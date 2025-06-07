#include "nix/util/idmaps.hh"
#include "nix/util/util.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"

#include <fstream>
#include <sys/types.h>
#include <sys/mount.h>
#include <grp.h>

namespace nix {

std::ostream & operator << (std::ostream & os, const IDMapType & t)
{
    return os << static_cast<char>(t);
}

std::string IDMapping::to_map_line() const {
    assert(range > 0);
    return fmt("%d %d %d", mapped_id, host_id, range);
}

std::ostream & operator << (std::ostream & os, const IDMapping & m)
{
    return os << fmt("%s=%d:%d:%d", m.type, m.mapped_id, m.host_id, m.range);
}

bool IDMapping::operator<(const IDMapping & other) const
{
    if (type != other.type) return type < other.type;
    if (mapped_id != other.mapped_id) return mapped_id < other.mapped_id;
    if (host_id != other.host_id) return host_id < other.host_id;
    return range < other.range;
}

bool IDMapping::overlaps_with(const IDMapping & other) const
{
    if (type != other.type)
        return false;
    return
        ((mapped_id < other.mapped_id + other.range) && (mapped_id + range > other.mapped_id))
        || ((host_id < other.host_id + other.range) && (host_id + range > other.host_id));
}

IDMapping parseIDMapping(const std::string & str)
{
    if (str.size() < 3 || str[1] != IDMapping::TypeSep)
        throw Error("Invalid ID mapping format: %s", str);

    auto parts = splitString<std::vector<std::string>>(str.substr(2), IDMapping::ValueSep);

    if (parts.size() > 3)
        throw Error("Invalid ID mapping format: %s", str);

    IDMapping mapping;
    switch (str[0]) {
        case static_cast<char>(IDMapType::GID): mapping.type = IDMapType::GID; break;
        case static_cast<char>(IDMapType::UID): mapping.type = IDMapType::UID; break;
        default: throw Error("Unknown ID mapping type: %1%", str[0]);
    };
    mapping.mapped_id = std::stoi(parts[0]);
    mapping.host_id = parts.size() >= 2 ? std::stoi(parts[1]) : mapping.mapped_id;
    mapping.range = parts.size() >= 3 ? std::stoi(parts[2]) : 1;
    return mapping;
}

/**
 * Parses arbitrary amount of mappings separated by commas. Only vaidates the
 * format and skips exact duplicates!! Results from this may not be accepted
 * for gid_map/uid_map depending on other factors (clashing map ranges,
 * missing mappings in caller namespace, missing permissions, ...)
 */
IDMappings parseIDMappingsList(const std::string & maps)
{
    IDMappings result;
    for (auto line : splitString<Strings>(maps, ","))
        result.insert(parseIDMapping(line));
    return result;
}

bool overlaps_with_any(const IDMapping & m1, auto maps)
{
    return std::find_if(maps.begin(), maps.end(),
        [&m1](const IDMapping & m2) { return m1.overlaps_with(m2); }) != maps.end();
}

IDMapper::IDMapper(const std::string & expl)
{
    add_explicit(expl);
}

IDMapper::IDMapper(const IDMappings & expl)
{
    for (auto m : expl) add_explicit(m);
}

void IDMapper::add_explicit(const IDMapping & map)
{
    if (overlaps_with_any(map, explicit_maps))
        throw Error("ID-mapping '%s' overlaps with another mapping", map);
    explicit_maps.insert(map);
}

void IDMapper::add_explicit(const std::string & maps)
{
    for (auto line : splitString<Strings>(maps, ","))
        add_explicit(parseIDMapping(line));
}

/* Mount idmap <id-from>:<id-to> only makes sense when there's a
   ".host_id = <id-to>" mapping in the sandbox user namespace. If in addition
   .mapped_id = <id-from> the ID's are just exactly the same inside the
   sandbox, which probably wasn't intended, so by default we add the mapping
   host_id == mapped_id instead. */
void IDMapper::add_fallback(const IDMapping & m)
{
    fallback_maps.insert({.type = m.type, .mapped_id = m.host_id, .host_id = m.host_id, .range = m.range});
}

void IDMapper::add_fallback(const std::string & maps)
{
    for (auto line : splitString<Strings>(maps, ","))
        add_fallback(parseIDMapping(line));
}

void IDMapper::transform(IDMapType type, id_t from, id_t to)
{
    for (auto m : explicit_maps)
        if (m.type == type && m.host_id == from) {
            explicit_maps.erase(m);
            m.host_id = to;
            add_explicit(m);
        }
    for (auto m : fallback_maps)
        if (m.type == type && m.host_id == from) {
            fallback_maps.erase(m);
            m.host_id = to;
            fallback_maps.insert(m);
        }
}

std::vector<IDMapping> IDMapper::collect(IDMapType type) const
{
    std::vector<IDMapping> result;
    for (const auto & m : explicit_maps)
        if (type == m.type)
            result.push_back(m);
    for (const auto & m : fallback_maps)
        if (type == m.type && !overlaps_with_any(m, result))
            result.push_back(m);
    if (result.empty()) // min. 1 map has to be defined
        result.push_back({.type = type, .mapped_id = 0, .host_id = 0, .range = 1});
    if (result.size() > IDMAP_LIMIT)
        throw Error("Too many mappings (>%d)", IDMAP_LIMIT);
    return result;
}

IDMappings IDMapper::collectBoth() const
{
    IDMappings res;
    for (const auto & m : collect(IDMapType::UID)) res.insert(m);
    for (const auto & m : collect(IDMapType::GID)) res.insert(m);
    return res;
}

/* ?id_map */
void writeIDMapFile(const std::string & filepath, const std::vector<IDMapping> & mappings, IDMapType type)
{
    std::ostringstream oss;
    for (const auto & mapping : mappings) {
        oss << mapping.to_map_line();
        oss << "\n";
    }

    std::string content = oss.str();
    if (content.size() > IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit for '%s'", filepath);

    debug("write %cid_map %s: %s", (char)type, filepath, replaceStrings(content, "\n", ";"));

    std::ofstream file(filepath);
    if (!file.is_open())
        throw SysError("open %s", filepath);
    file << content;
    if (!file)
        throw SysError("write %s", filepath);
}

/**
 * The ID-maps for a mount have to be defined by defining the maps to a (new)
 * user namespace, opening an FD to the NS and passing that FD to
 * mount_setattr. As long as the FD stays open the mapping can be used for
 * mounting. It's even okay to kill all processes in the NS (as we do here).
 **/
int createUsernamespaceWithMappings(const std::string & str, uid_t sandbox_uid, gid_t sandbox_gid)
{
    if (str.empty()) return -1;
    IDMapper mapper;
    try {
        mapper = IDMapper(str);
        mapper.transform(IDMapType::UID, 1000, sandbox_uid);
        mapper.transform(IDMapType::GID, 100, sandbox_gid);
    }
    catch (Error & e) {
        debug(e.message());
        throw;
    }
    return createUsernamespaceWithMappings(const_cast<IDMapper&>(mapper));
}

int createUsernamespaceWithMappings(const IDMapper & mapper)
{
    //debug("setting up user namespace for ID-mapping: '%s'", mapper);

    Pipe syncPipe, exitPipe;
    syncPipe.create();
    exitPipe.create();

    Pid pid(startProcess([&]() {
        syncPipe.readSide.close();
        exitPipe.writeSide.close();
        try {
            if (unshare(CLONE_NEWUSER) == -1)
                throw SysError("new user ns for idmap (is UID:GID 0:0 mapped in caller namespace?)");

            writeFull(syncPipe.writeSide.get(), "1\n");
            readLine(exitPipe.readSide.get(), true);
        }
        catch (Error & e) {
            writeFull(syncPipe.writeSide.get(), "0\n" + e.message());
            _exit(1);
        }
        _exit(0);
    }, { .cloneFlags = SIGCHLD }));
    syncPipe.writeSide.close();
    exitPipe.readSide = -1;

    if (readLine(syncPipe.readSide.get(), true) != "1")
        throw Error("Setting up user namespace failed: " + readFile(syncPipe.readSide.get()));

    /* Write setgroups (if necessary/possible).
     * In case of child ns, setgroups is inherited from parent ns and cannot be changed. */
    try { writeFile(fmt("/proc/%d/setgroups", (pid_t)pid), "deny"); }
    catch (SysError & e) { if (e.errNo != EACCES) throw; }

    // Write uid_map & gid_map
    writeIDMapFile(fmt("/proc/%d/uid_map", (pid_t)pid), mapper.collect(IDMapType::UID), IDMapType::UID);
    writeIDMapFile(fmt("/proc/%d/gid_map", (pid_t)pid), mapper.collect(IDMapType::GID), IDMapType::GID);

    // Open namespace fd
    int userFd = open(fmt("/proc/%d/ns/user", (pid_t)pid).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");

    writeLine(exitPipe.writeSide.get(), "X"); // Signal child to exit
    exitPipe.writeSide.close();

    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");

    return userFd;
}

/* Use slave propagation by default so that nested mounts from host are
 * propagated if added but nesting mounts in the sandbox namespace does not
 * propagate back. */
void bindMountWithIDMap(const Path & source, const Path & target, int userns_fd, bool optional, bool rdonly)
{
    static constexpr uint64_t open_tree_flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT |
                                                AT_RECURSIVE | AT_SYMLINK_NOFOLLOW |
                                                OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE;
    static constexpr uint64_t attr_rdonly_flags =   MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC |
                                                    MOUNT_ATTR_NOSUID | MOUNT_ATTR_RDONLY;
    static constexpr uint64_t propagation_default = MS_SLAVE; // .alt.: MS_PRIVATE,
    static constexpr uint64_t mount_setattr_flags = AT_EMPTY_PATH | AT_RECURSIVE;
    static constexpr uint64_t move_mount_flags = MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH /* | MOVE_MOUNT_T_SYMLINKS */;

    debug("bind mounting ID-mapped '%s' to '%s' with userns=%d", source, target, userns_fd);

    auto maybeSt = maybeLstat(source);
    if (!maybeSt) {
        if (optional) return;
        else throw SysError("stat path '%s'", source);
    }

    // Ensure that parent of target path is a directory
    createDirs(dirOf(target));

    // For a directory, ensure the whole path is a directory. Otherwise ensure
    // it's a file.
    if (S_ISDIR(maybeSt->st_mode)) createDirs(target);
    else writeFile(target, "");

    AutoCloseFD tfd = open_tree(-EBADF, source.c_str(), open_tree_flags);

    if (tfd.get() == -1)
        throw SysError("open_tree '%s'", source);

    mount_attr attr = { .attr_set = rdonly ? attr_rdonly_flags : 0, .propagation = propagation_default };

    if (userns_fd > 0) {
        attr.attr_set |= MOUNT_ATTR_IDMAP;
        // FD's are int, except when ABI compatibility requires otherwise
        attr.userns_fd = static_cast<uint64_t>(userns_fd);
    }

    if (mount_setattr(tfd.get(), "", mount_setattr_flags, &attr, sizeof(struct mount_attr)) == -1)
        throw SysError("mount_setattr '%s'", source);

    if (move_mount(tfd.get(), "", -EBADF, target.c_str(), move_mount_flags) == -1)
        throw SysError("move_mount '%s'", source);
}

inline static void mount_with_idmap(const Path & target, const Path & chrootRootDir,
        const Path & source, int idmapFd, bool optional, bool rdonly)
{
    bindMountWithIDMap(source, chrootRootDir + target, idmapFd, optional, rdonly);
}

/* This should be called from a child process! */
inline static void mount_with_idmap_wrapped(const Path & target, const Path & chrootRootDir,
        int mountNsFd, const IDMappedChrootPath & chrootpath, int idmapFd)
{
    try {
        // set mount namespace
        if (setns(mountNsFd, 0) == -1)
            throw SysError("idmap-mount: entering sandbox mount namespace");

        // TODO handle other attributes of IDMappedChrootPath as well.
        nix::mount_with_idmap(target, chrootRootDir, chrootpath.source,
                idmapFd, chrootpath.optional, chrootpath.rdonly);

    } catch (Error & e) {
        debug(e.message());
        _exit(1);
    }
    _exit(0);
}

/* ID-mapped bind mounts. Setup these from the parent (initial)
 * namespace, because here we still have all the needed capabilities and
 * are not constrained by the sandbox user ns. For every unique ID-map a
 * user namespace is created with the specified mappings. Various criteria
 * are required:
 *
 * - The caller needs to be owner of current user namespace.
 * - The caller UID/GID has to be mapped in the current namespace.
 * - The mapped user IDs (group IDs) must in turn have a mapping in the parent user namespace.
 * - Mapping UID 0 requires CAP_SETFCAP
 * - To write maps for other than effective UID/GID, CAP_SETUID/GID is needed.
 * - A child user namespace inherits the /proc/pid/setgroups setting from its parent and can't modify it.
 *
 * Mounts are performed in the sandbox's mount namespace.
 */
void UserMountNSHelper::setupSandboxPathHandlerSide(const Path & target)
{
    auto st(state_.lock());
    // Mount namespace fd
    int nsFd = st->mountNsFd;
    // Chroot root and target path
    auto _crdir = st->chrootRootDir;
    auto [iterChrootPath, inserted] = st->chrootPaths.try_emplace(target, IDMappedChrootPath{});
    auto chrootPath = iterChrootPath->second;
    // idmap user namespace fd; skip the work if there's no id-mapping
    // requested.
    auto idmapFd = -1;
    if (!chrootPath.idmap.empty()) {
        IDMapper mapper(chrootPath.idmap);
        /* Little convenience: if the target 1000:100 (either) is mapped in
           the mount, then modify it to match with the build user's host map
           instead. So that what mount's id-map maps into targets 1000:100
           becomes the mapping into the builder's *mapped* (=sandbox) IDs. (So
           you can have builders with a mapped UID 1000 and randomly
           changing host UID and filesystem) */
        mapper.transform(IDMapType::UID, 1000, st->builderPrimaryUID.host_id);
        mapper.transform(IDMapType::GID, 100, st->builderPrimaryGID.host_id);
        IDMappings maps = mapper.collectBoth();
        auto [iterNSFDs, _] = st->chrootPathNamespaceFds.try_emplace(maps, [&] {
            return createUsernamespaceWithMappings(mapper);
        }());
        idmapFd = iterNSFDs->second.get();
    }

    // make the mount in a sub-process because we have to change mount
    // namespace for the call.
    Pid child(startProcess([&]() {
        nix::mount_with_idmap_wrapped(target, _crdir, nsFd, chrootPath, idmapFd);
    }));
    int status = child.wait();
    if (status != 0) {
        throw Error("could not add id-mapped mounts to sandbox");
    }
}

void UserMountNSHelper::update(std::function<void(NS_State &)> modify)
{
    auto st(state_.lock());
    modify(*st);
}

std::vector<gid_t> UserMountNSHelper::getSupplementarySetGroups()
{
    auto st(state_.lock());
    std::vector<gid_t> ret;
    if (!st->useSupplementaryGroups)
        return ret;
    for (auto & [pgid, cgid] : st->supplementaryGIDs)
        ret.push_back(pgid);
    return ret;
}

void UserMountNSHelper::writeProcessIDMapFiles(pid_t pid) {
    auto st(state_.lock());
    auto idm = st->idmapper;
    // Make sure we include the build user primary maps.
    // Should overwrite any overlapping maps maybe?
    idm.add_explicit(st->builderPrimaryUID);
    idm.add_explicit(st->builderPrimaryGID);
    // Maps cynthesised from id-mapped mounts: added from fallbacks as far
    // there aren't conflicts.
    writeFile("/proc/" + std::to_string(pid) + "/setgroups", "deny");
    writeIDMapFile("/proc/" + std::to_string(pid) + "/uid_map", idm.collect(IDMapType::UID), IDMapType::UID);
    writeIDMapFile("/proc/" + std::to_string(pid) + "/gid_map", idm.collect(IDMapType::GID), IDMapType::GID);
}

void UserMountNSHelper::addChrootPathsWithIDMap(std::map<Path, IDMappedChrootPath> chrootPaths)
{
    auto st(state_.lock());
    st->chrootPaths = chrootPaths;
    for (const auto & [_, m] : chrootPaths)
        for (const auto & mm : m.idmap)
            st->idmapper.add_fallback(mm);
};

void UserMountNSHelper::createGroupsContent(const Path & out) {
    auto st(state_.lock());
    std::ostringstream oss;
    oss << fmt(
        "root:x:0:\n"
        "nogroup:x:65534:\n"
        "nixbld:!:%d:\n", st->builderPrimaryGID.mapped_id);

    for (auto [pgid, mgid] : st->supplementaryGIDs)
        oss << fmt("%s:x:%d:nixbld\n", st->supplementaryGroupNames.at(mgid), mgid);
    writeFile(out, oss.str());
};

void UserMountNSHelper::createUsersPasswdContent(const Path & out, const Path & sandboxBuildDir) {
    auto st(state_.lock());
    writeFile(out,
      fmt("root:x:0:0:Nix build user:%3%:/noshell\n"
          "nixbld:x:%1%:%2%:Nix build user:%3%:/noshell\n"
          "nobody:x:65534:65534:Nobody:/:/noshell\n",
          st->builderPrimaryUID.mapped_id,
          st->builderPrimaryGID.mapped_id,
          sandboxBuildDir));
};

/**
 * Keys are host/parent gid's (can't have duplicates obviously). Values
 * are the mapped/target (gid, name) pairs. Each mapped gid (name) may
 * only appear once in the result.
 *
 * Primary GID (sandboxGid) is always mapped and it would make no
 * sense to assign as a supplementary group as well.
 *
 * It would be technically harmless to allow mapping and assigning 0,
 * aside from some potential confusion. It's only disallowed here
 * because the root group is declared always anyway. Allowing it here
 * would result in a duplicate /etc/group entry.
 *
 * Allowing assigning nogroup 65534 would be very bad, especially if
 * root 0 wasn't mapped, as it's the fallback group to which all
 * unmapped GIDs get mapped to (including root).
 *
 * Use: settings.supplementaryGroups.get() */
void UserMountNSHelper::setupSupplementaryGroups(const StringSet supgrps)
{
    auto st(state_.lock());
    if (!st->useSupplementaryGroups)
        return;
    std::vector<gid_t> reserved_gids = {st->builderPrimaryUID.mapped_id, 0, 65534};
    std::vector<std::string> reserved_names = {"root", "nixbld", "nogroup"};

    // parent_gid -> (mapped_gid, mapped_name)
    std::map<gid_t, std::tuple<gid_t, std::string>> gid_map;

    struct group grp;
    struct group * gr = nullptr;
    long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer;

    for (const auto & group_entry : supgrps) {
        std::string group_name = group_entry;
        std::optional<gid_t> mapped_gid;

        // parse "name[:gid]"
        auto pos = group_entry.find(":");
        if (pos != std::string::npos) {
            std::string gid_str = group_entry.substr(pos + 1);
            group_name = group_entry.substr(0, pos);
            try {
                mapped_gid = static_cast<gid_t>(std::stoul(gid_str));
            } catch (...) {
                throw Error("Invalid GID number in '%s'", gid_str);
            }
        }

        while (true) {
            buffer.resize(bufsize);
            int ret = getgrnam_r(group_name.c_str(), &grp, buffer.data(), buffer.size(), &gr);
            if (ret == 0) {
                break;
            } else if (ret == ERANGE) { // buffer too small
                bufsize *= 2;
            } else if (ret != 0)
                throw Error("getgrnam_r failed for group '%s': %s", group_name, strerror(ret));
        }

        if (!gr) {
            debug("Supplementary group '%s' not found", group_name);
            continue;
        }

        // host GID sanity checks
        gid_t parent_gid = gr->gr_gid;
        if (parent_gid == 0)
            throw Error("Group '%s': mapping the root group (GID 0) is not a good idea", group_name);
        if (gid_map.contains(parent_gid))
            throw Error("Group '%s': parent GID %d is already mapped", group_name, parent_gid);

        /* Mapped GID sanity checks

           65535 is the special invalid/overflow GID distinct from
           nogroup. We don't want to allow that.

           2^16 and above are not allowed because it would seem impossible
           to assign them. In a quick test higher GIDs got truncated to
           65534. Might have something to do with how we're forced to call
           setgroups before setting up the namespace. */
        if (!mapped_gid)
            mapped_gid = parent_gid;
        if (mapped_gid > 65534)
            throw Error("Group '%s': mapped GID %d is too large (>65534)", group_name, mapped_gid.value());
        if (std::find(reserved_gids.begin(), reserved_gids.end(), mapped_gid.value()) != reserved_gids.end())
            throw Error("Group '%s': mapped GID %d conflicts with reserved GID", group_name, mapped_gid.value());

        // mapped name sanity checks
        std::string mapped_name = gr->gr_name;
        if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
            mapped_name += "-host";
            debug("Group '%s': name conflicts with reserved name; renaming to '%s'", group_name, mapped_name);
            if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
                warn("Group '%s': original and alternative name '%s' both conflict with reserved names; skipping this group", group_name, mapped_name);
                continue;
            }
        }

        gid_map[parent_gid] = std::make_tuple(mapped_gid.value(), std::move(mapped_name));
        reserved_gids.push_back(mapped_gid.value());
        reserved_names.push_back(std::get<1>(gid_map[parent_gid]));
    }

    // Populate supplementaryGIDs
    for (auto & [a, m] : gid_map) {
        st->supplementaryGIDs[a] = get<0>(m);
        st->supplementaryGroupNames[a] = get<1>(m);
        st->idmapper.add_explicit({.type = IDMapType::GID, .mapped_id = std::get<0>(m), .host_id = a });
    }
}
}
