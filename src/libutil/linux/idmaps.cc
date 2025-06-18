#include "nix/util/idmaps.hh"
#include "nix/util/util.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"

#include <fstream>
#include <sys/types.h>
#include <sys/mount.h>
#include <grp.h>

namespace nix {

/* ?id_map */
inline static void write_id_map(pid_t pid, const std::set<IDMapping> & mappings, IDMapping::Type type)
{
    if (type == IDMapping::Type::Both) {
        write_id_map(pid, mappings, IDMapping::Type::User);
        write_id_map(pid, mappings, IDMapping::Type::Group);
        return;
    }

    auto filepath = fmt("/proc/%d/%cid_map", pid, (char)type);

    std::ostringstream oss;
    for (const auto & mapping : mappings) {
        if (mapping.contains(type))
            oss << mapping.to_map_line();
    }

    std::string content = oss.str();
    if (content.size() > IDMapping::IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit for '%s'", filepath);

    debug("write %cid_map %s: %s", (char)type, filepath, replaceStrings(content, "\n", ";"));

    std::ofstream file(filepath);
    if (!file.is_open())
        throw SysError("open %s", filepath);
    file << content;
    if (!file)
        throw SysError("write %s", filepath);
}

/* Write setgroups (if necessary/possible).
 * In case of child ns, setgroups is inherited from parent ns and cannot be changed. */
inline static void write_setgroups(pid_t pid, bool deny = true)
{
    try {
        writeFile(fmt("/proc/%d/setgroups", pid), deny ? "deny" : "allow");
    } catch (SysError & e) {
        if (e.errNo != EACCES) throw;
    }
}

inline static int createUsernamespaceWithMappings(const IDMap & mapper)
{
    static const std::string SYNC_PARENT_NAMESPACE_READY = "1";
    static const std::string SYNC_PARENT_ERREXIT = "0";
    static const std::string SYNC_CHILD_EXIT = "X";

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

            writeFull(syncPipe.writeSide.get(), fmt("%s\n", SYNC_PARENT_NAMESPACE_READY));
            readLine(exitPipe.readSide.get(), true);
        }
        catch (Error & e) {
            writeFull(syncPipe.writeSide.get(), fmt("%s\n%s\n", SYNC_PARENT_ERREXIT, e.message()));
            _exit(1);
        }
        _exit(0);
    }, { .cloneFlags = SIGCHLD }));
    syncPipe.writeSide.close();
    exitPipe.readSide = -1;

    if (readLine(syncPipe.readSide.get(), true) != SYNC_PARENT_NAMESPACE_READY)
        throw Error("Setting up user namespace failed: " + readFile(syncPipe.readSide.get()));

    write_setgroups(pid);

    // Write uid_map & gid_map
    write_id_map(pid, mapper.collectBoth(), IDMapping::Type::Both);

    // Open namespace fd
    int userFd = open(fmt("/proc/%d/ns/user", (pid_t)pid).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");

    writeLine(exitPipe.writeSide.get(), SYNC_CHILD_EXIT);
    exitPipe.writeSide.close();

    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");

    return userFd;
}

/**
 * The ID-maps for a mount have to be defined by defining the maps to a (new)
 * user namespace, opening an FD to the NS and passing that FD to
 * mount_setattr. As long as the FD stays open the mapping can be used for
 * mounting. It's even okay to kill all processes in the NS (as we do here).
 *
 * Id maps are specified in syntax:
 *
 *      <type>=<mapped>[-<host>[-<range>]]
 *
 * - `type` is one of `u` for UID or `g` for GID.
 * - `mapped` is the beginning of the ID range inside the sandbox.
 * - `host` is start of outside IDs. Same as mapped if only one number is given.
 * - `range` is the number of IDs in the range. Default and min. is 1.
 */
inline static int createUsernamespaceWithMappings(const std::string & str, uid_t sandbox_uid, gid_t sandbox_gid)
{
    if (str.empty()) return -1;
    IDMap mapper;
    try {
        mapper = IDMap(str);
        mapper.transform(IDMapping::Type::User, 1000, sandbox_uid);
        mapper.transform(IDMapping::Type::Group, 100, sandbox_gid);
    }
    catch (Error & e) {
        debug(e.message());
        throw;
    }
    return mapper.createUsernamespace();
}

/* Use slave propagation by default so that nested mounts from host are
 * propagated if added but nesting mounts in the sandbox namespace does not
 * propagate back. */
void bindMountWithIDMap(const Path & source, const Path & target, int userns_fd, bool optional, bool rdonly)
{
    static constexpr uint64_t open_tree_flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE;
    static constexpr uint64_t attr_rdonly_flags = MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_RDONLY;
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

/* This should be called from a child process! */
inline static void mount_with_idmap_wrapped(const Path & target, const Path & chrootRootDir,
        int mountNsFd, const IDMappedChrootPath & chrootpath, int idmapFd)
{
    try {
        // set mount namespace
        if (setns(mountNsFd, 0) == -1)
            throw SysError("idmap-mount: entering sandbox mount namespace");

        // TODO handle other attributes of IDMappedChrootPath as well.
        bindMountWithIDMap(chrootpath.source, chrootRootDir + target, idmapFd, chrootpath.optional, chrootpath.readOnly);

    } catch (Error & e) {
        debug(e.message());
        _exit(1);
    }
    _exit(0);
}

// IDMapping::Type

std::ostream & operator << (std::ostream & os, const IDMapping::Type & t)
{
    return os << static_cast<char>(t);
}

bool IDMapping::contains(const Type t1, const Type t2)
{
    return t1 == t2 || t1 == Type::Both || t2 == Type::Both;
}
bool IDMapping::contains(const Type t2) const { return contains(type, t2); }

IDMapping::Type IDMapping::parse_type(const char ch)
{
    switch (ch) {
        case static_cast<char>(Type::Both): return Type::Both;
        case static_cast<char>(Type::User): return Type::User;
        case static_cast<char>(Type::Group): return Type::Group;
        default: throw Error("Unknown ID mapping type: %1%", ch);
    };
}

// IDMapping

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

std::string IDMapping::to_map_line() const {
    assert(range > 0);
    return fmt("%d %d %d\n", mapped_id, host_id, range);
}

IDMapping IDMapping::parse(const std::string & str)
{
    if (str.size() < 3 || str[1] != TypeSep)
        throw Error("Invalid ID mapping format: %s", str);

    auto parts = splitString<std::vector<std::string>>(str.substr(2), ValueSep);

    if (parts.size() > 3)
        throw Error("Invalid ID mapping format: %s", str);

    IDMapping mapping;
    mapping.type = parse_type(str[0]);
    mapping.mapped_id = std::stoi(parts[0]);
    mapping.host_id = parts.size() >= 2 ? std::stoi(parts[1]) : mapping.mapped_id;
    mapping.range = parts.size() >= 3 ? std::stoi(parts[2]) : 1;
    return mapping;
}

bool IDMapping::overlaps_with(const IDMapping & other) const
{
    if (!contains(other.type))
        return false;
    return
        ((mapped_id < other.mapped_id + other.range) && (mapped_id + range > other.mapped_id))
        || ((host_id < other.host_id + other.range) && (host_id + range > other.host_id));
}

bool IDMapping::overlaps_with_any(auto maps) const
{
    return std::find_if(maps.begin(), maps.end(),
        [&](const IDMapping & m2) { return this->overlaps_with(m2); }) != maps.end();
}

// IDMap

IDMap::IDMap(const IDMap::Set & expl)
{
    for (const auto & m : expl) add_explicit(m);
}

IDMap::IDMap(const std::string & expl) { add_explicit(expl); }

/**
 * Parses arbitrary amount of mappings separated by commas. Only vaidates the
 * format and skips exact duplicates!! Results from this may not be accepted
 * for gid_map/uid_map depending on other factors (clashing map ranges,
 * missing mappings in caller namespace, missing permissions, ...)
 */
IDMap::Set IDMap::parse_maps(const std::string & str)
{
    IDMap::Set res;
    for (auto line : splitString<Strings>(str, ","))
        res.insert(IDMapping::parse(std::move(line)));
    return res;
}

void IDMap::add_explicit(const IDMapping & map)
{
    if (map.overlaps_with_any(explicit_maps))
        throw Error("ID-mapping '%s' overlaps with another mapping", map);
    explicit_maps.insert(map);
}

void IDMap::add_explicit(const std::string & maps)
{
    for (const auto & map : parse_maps(maps)) add_explicit(map);
}

/* Mount idmap <id-from>:<id-to> only makes sense when there's a
   ".host_id = <id-to>" mapping in the sandbox user namespace. If in addition
   .mapped_id = <id-from> the ID's are just exactly the same inside the
   sandbox, which probably wasn't intended, so by default we add the mapping
   host_id == mapped_id instead. */
void IDMap::add_fallback(const IDMapping & m)
{
    fallback_maps.insert({.type = m.type, .mapped_id = m.host_id, .host_id = m.host_id, .range = m.range});
}

void IDMap::add_fallback(const std::string & maps)
{
    for (const auto & map : parse_maps(maps))
        add_fallback(map);
}

void IDMap::transform(const IDMapping::Type type, id_t from, id_t to)
{
    if(type == IDMapping::Type::Both) {
        transform(IDMapping::Type::Group, from, to);
        transform(IDMapping::Type::User, from, to);
        return;
    }
    for (auto m : explicit_maps)
        if (m.contains(type) && m.host_id == from) {
            explicit_maps.erase(m);
            m.host_id = to;
            add_explicit(m);
        }
    for (auto m : fallback_maps)
        if (m.contains(type) && m.host_id == from) {
            fallback_maps.erase(m);
            m.host_id = to;
            fallback_maps.insert(m);
        }
}

std::vector<IDMapping> IDMap::collect(const IDMapping::Type type) const
{
    std::vector<IDMapping> result;
    for (const auto & m : explicit_maps)
        if (m.contains(type))
            result.push_back(m);
    for (const auto & m : fallback_maps)
        if (m.contains(type) && !m.overlaps_with_any(result))
            result.push_back(m);
    if (result.empty()) // min. 1 map has to be defined
        result.push_back({.type = type, .mapped_id = 0, .host_id = 0, .range = 1});
    if (result.size() > IDMapping::IDMAP_LIMIT)
        throw Error("Too many mappings (>%d)", IDMapping::IDMAP_LIMIT);
    return result;
}

/**
 * Calculate both UID and GID maps (no overlapping).
 */
IDMap::Set IDMap::collectBoth() const
{
    Set res;
    for (const auto & m : collect(IDMapping::Type::User)) res.insert(m);
    for (const auto & m : collect(IDMapping::Type::Group)) res.insert(m);
    return res;
}

int IDMap::createUsernamespace() const
{
    return createUsernamespaceWithMappings(*this);
}

void SandboxIDMap::write_userns_map(pid_t pid) const
{
    // Maps cynthesised from id-mapped mounts: added from fallbacks as far
    // there aren't conflicts.
    write_setgroups(pid);
    write_id_map(pid, primaryIDMap.collectBoth(), IDMapping::Type::Both);
}

void SandboxIDMap::write_etc_passwd(const Path & out, const Path & sandboxBuildDir) const
{
    writeFile(out,
      fmt("root:x:0:0:Nix build user:%3%:/noshell\n"
          "nixbld:x:%1%:%2%:Nix build user:%3%:/noshell\n"
          "nobody:x:65534:65534:Nobody:/:/noshell\n",
          primaryUID.mapped_id,
          primaryGID.mapped_id,
          sandboxBuildDir));
};
void SandboxIDMap::write_etc_groups(const Path &file) const
{
    std::ostringstream oss;
    // Default groups
    for (auto gid : { (gid_t)0, primaryGID.mapped_id, (gid_t)65534 }) {
        if (!useSupplementaryGroups || !supplementaryGIDs.contains(gid)) {
            oss << fmt("%s:x:%d:\n", groupNames.at(gid), gid);
        }
    }
    // Supplementary groups
    for (auto [_, mappedID] : supplementaryGIDs)
        oss << fmt("%s:x:%d:nixbld\n", groupNames.at(mappedID), mappedID);
    writeFile(file, oss.str());
}

void SandboxIDMap::setPrimaryIDs(uid_t uid, gid_t gid, uid_t huid, gid_t hgid, id_t nrids) {
    primaryUID = { IDMapping::Type::User, uid, huid, nrids };
    primaryGID = { IDMapping::Type::Group, gid, hgid, nrids };
    primaryIDMap.add_explicit(primaryUID);
    primaryIDMap.add_explicit(primaryGID);
}


std::vector<gid_t> SandboxIDMap::supplementaryHostGIDs() const
{
    if (!useSupplementaryGroups) return {};
    std::vector<gid_t> res;
    for (auto [gid, _] : supplementaryGIDs)
        res.push_back(gid);
    return res;
}
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
void SandboxIDMap::addSupplementaryGroups(const StringSet supgrps)
{
    useSupplementaryGroups = true;

    //std::vector<gid_t> reserved_gids = {primaryUID.mapped_id, 0, 65534};
    //std::vector<std::string> reserved_names = {"root", "nixbld", "nogroup"};

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
        if (groupNames.contains(mapped_gid.value()))
            throw Error("Group '%s': mapped GID %d conflicts with reserved GID", group_name, mapped_gid.value());

        // mapped name sanity checks
        std::string mapped_name = gr->gr_name;
        if (std::find_if(groupNames.begin(), groupNames.end(), ([&](auto i) { return i.second == mapped_name; })) != groupNames.end()) {
            mapped_name += "-host";
            debug("Group '%s': name conflicts with reserved name; renaming to '%s'", group_name, mapped_name);
            if (std::find_if(groupNames.begin(), groupNames.end(), ([&](auto i) { return i.second == mapped_name; })) != groupNames.end()) {
                warn("Group '%s': original and alternative name '%s' both conflict with reserved names; skipping this group", group_name, mapped_name);
                continue;
            }
        }

        gid_map[parent_gid] = std::make_tuple(mapped_gid.value(), std::move(mapped_name));
        supplementaryGIDs[parent_gid] = std::get<0>(gid_map[parent_gid]);
        groupNames[mapped_gid.value()] = std::get<1>(gid_map[parent_gid]);
        primaryIDMap.add_explicit({
                .type = IDMapping::Type::Group,
                .mapped_id = std::get<0>(gid_map[parent_gid]),
                .host_id = parent_gid,
        });
    }
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
        IDMap mapper(chrootPath.idmap);
        /* Little convenience: if the target 1000:100 (either) is mapped in
           the mount, then modify it to match with the build user's host map
           instead. So that what mount's id-map maps into targets 1000:100
           becomes the mapping into the builder's *mapped* (=sandbox) IDs. (So
           you can have builders with a mapped UID 1000 and randomly
           changing host UID and filesystem) */
        mapper.transform(IDMapping::Type::User, 1000, st->builderPrimaryUID.host_id);
        mapper.transform(IDMapping::Type::Group, 100, st->builderPrimaryGID.host_id);
        // Create new user ns and get its fd, unless the same mapping already
        // has a stored fd in which case copy that.
        auto [fds, _] = st->userNamespaceFDs.try_emplace(mapper.collectBoth(), [&] { return mapper.createUsernamespace(); }());
        idmapFd = fds->second.get();
    }

    // make the mount in a sub-process because we have to change mount
    // namespace for the call.
    Pid child(startProcess([&]() {
        mount_with_idmap_wrapped(target, _crdir, nsFd, chrootPath, idmapFd);
    }));
    int status = child.wait();
    if (status != 0)
        throw Error("could not add id-mapped mounts to sandbox");
}

void SandboxIDMap::recordMountIDMap(IDMap::Set map)
{
    for (auto m : map)
        primaryIDMap.add_fallback(m);
}

// called from callback handler
void SandboxIDMap::add_sandbox_path_handler_side(const Path & target, const IDMappedChrootPath & chrootPath, const Path & chrootRootDir, int mountNsFd)
{
    idmappedChrootPaths.try_emplace(target, chrootPath);

    int idmapFd = -1;

    if (!chrootPath.idmap.empty()) {
        /* Little convenience: if the target 1000:100 (either) is mapped in
           the mount, then modify it to match with the build user's host map
           instead. So that what mount's id-map maps into targets 1000:100
           becomes the mapping into the builder's *mapped* (=sandbox) IDs. (So
           you can have builders with a mapped UID 1000 and randomly
           changing host UID and filesystem) */
        IDMap map(chrootPath.idmap);
        map.transform(IDMapping::Type::User, primaryUID.mapped_id, primaryUID.host_id);
        map.transform(IDMapping::Type::Group, primaryGID.mapped_id, primaryGID.host_id);

        // Create new user ns and get its fd, unless the same mapping already
        // has a stored fd in which case copy that.
        auto [fds, _] = userNamespaceFDs.try_emplace(map.collectBoth(), [&] { return map.createUsernamespace(); }());
        idmapFd = fds->second.get();
    }

    // make the mount in a sub-process because we have to change mount
    // namespace for the call.
    Pid child(startProcess([&]() {
        mount_with_idmap_wrapped(target, chrootRootDir, mountNsFd, chrootPath, idmapFd);
    }));
    int status = child.wait();
    if (status != 0)
        throw Error("could not add id-mapped mounts to sandbox");
}

void UserMountNSHelper::addChrootPathsWithIDMap(std::map<Path, IDMappedChrootPath> chrootPaths)
{
    auto st(state_.lock());
    st->chrootPaths = chrootPaths;
    for (const auto & [_, m] : chrootPaths)
        for (const auto & mm : m.idmap)
            st->idmapper.add_fallback(mm);
};

//void UserMountNSHelper::setupSupplementaryGroups(const StringSet supgrps)
//{
//    auto st(state_.lock());
//    if (!st->useSupplementaryGroups)
//        return;
//    std::vector<gid_t> reserved_gids = {st->builderPrimaryUID.mapped_id, 0, 65534};
//    std::vector<std::string> reserved_names = {"root", "nixbld", "nogroup"};
//
//    // parent_gid -> (mapped_gid, mapped_name)
//    std::map<gid_t, std::tuple<gid_t, std::string>> gid_map;
//
//    struct group grp;
//    struct group * gr = nullptr;
//    long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
//    if (bufsize == -1) bufsize = 16384;
//    std::vector<char> buffer;
//
//    for (const auto & group_entry : supgrps) {
//        std::string group_name = group_entry;
//        std::optional<gid_t> mapped_gid;
//
//        // parse "name[:gid]"
//        auto pos = group_entry.find(":");
//        if (pos != std::string::npos) {
//            std::string gid_str = group_entry.substr(pos + 1);
//            group_name = group_entry.substr(0, pos);
//            try {
//                mapped_gid = static_cast<gid_t>(std::stoul(gid_str));
//            } catch (...) {
//                throw Error("Invalid GID number in '%s'", gid_str);
//            }
//        }
//
//        while (true) {
//            buffer.resize(bufsize);
//            int ret = getgrnam_r(group_name.c_str(), &grp, buffer.data(), buffer.size(), &gr);
//            if (ret == 0) {
//                break;
//            } else if (ret == ERANGE) { // buffer too small
//                bufsize *= 2;
//            } else if (ret != 0)
//                throw Error("getgrnam_r failed for group '%s': %s", group_name, strerror(ret));
//        }
//
//        if (!gr) {
//            debug("Supplementary group '%s' not found", group_name);
//            continue;
//        }
//
//        // host GID sanity checks
//        gid_t parent_gid = gr->gr_gid;
//        if (parent_gid == 0)
//            throw Error("Group '%s': mapping the root group (GID 0) is not a good idea", group_name);
//        if (gid_map.contains(parent_gid))
//            throw Error("Group '%s': parent GID %d is already mapped", group_name, parent_gid);
//
//        /* Mapped GID sanity checks
//
//           65535 is the special invalid/overflow GID distinct from
//           nogroup. We don't want to allow that.
//
//           2^16 and above are not allowed because it would seem impossible
//           to assign them. In a quick test higher GIDs got truncated to
//           65534. Might have something to do with how we're forced to call
//           setgroups before setting up the namespace. */
//        if (!mapped_gid)
//            mapped_gid = parent_gid;
//        if (mapped_gid > 65534)
//            throw Error("Group '%s': mapped GID %d is too large (>65534)", group_name, mapped_gid.value());
//        if (std::find(reserved_gids.begin(), reserved_gids.end(), mapped_gid.value()) != reserved_gids.end())
//            throw Error("Group '%s': mapped GID %d conflicts with reserved GID", group_name, mapped_gid.value());
//
//        // mapped name sanity checks
//        std::string mapped_name = gr->gr_name;
//        if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
//            mapped_name += "-host";
//            debug("Group '%s': name conflicts with reserved name; renaming to '%s'", group_name, mapped_name);
//            if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
//                warn("Group '%s': original and alternative name '%s' both conflict with reserved names; skipping this group", group_name, mapped_name);
//                continue;
//            }
//        }
//
//        gid_map[parent_gid] = std::make_tuple(mapped_gid.value(), std::move(mapped_name));
//        reserved_gids.push_back(mapped_gid.value());
//        reserved_names.push_back(std::get<1>(gid_map[parent_gid]));
//    }
//
//    // Populate supplementaryGIDs
//    for (auto & [a, m] : gid_map) {
//        st->supplementaryGIDs[a] = get<0>(m);
//        st->supplementaryGroupNames[a] = get<1>(m);
//        st->idmapper.add_explicit({.type = IDMapping::Type::Group, .mapped_id = std::get<0>(m), .host_id = a });
//    }
//}
}
