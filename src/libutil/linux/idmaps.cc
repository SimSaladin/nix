#include "nix/util/idmaps.hh"
#include "nix/util/util.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"

#include <fstream>
#include <sys/types.h>
#include <sys/mount.h>
#include <grp.h>

namespace nix {

/**
 * Given a ProcessID, ID-map and ID-map type, writes the corresponding uid_map
 * and/or gid_map for the process (e.g. namespace)
 */
inline static void write_id_map(pid_t pid, const IDMap & map, IDMapping::Type type)
{
    if (type == IDMapping::Type::Both) {
        write_id_map(pid, map, IDMapping::Type::User);
        write_id_map(pid, map, IDMapping::Type::Group);
        return;
    }

    auto filepath = fmt("/proc/%d/%cid_map", pid, (char)type);

    std::ostringstream oss;
    for (const auto & m : map.collect(type))
        oss << m.to_map_line();

    std::string content = oss.str();
    if (content.size() > IDMapping::IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit for '%s': %s", filepath, map);

    debug("idmap write %s (%s)", filepath, replaceStrings(content, "\n", ";"));

    std::ofstream file(filepath);
    if (!file.is_open())
        throw SysError("open %s", filepath);
    file << content;
    if (!file)
        throw SysError("write %s", filepath);
}

/**
 * Writes setgroups if necessary/possible for PID (namespace).
 * In case of child ns, setgroups is inherited from parent ns and cannot be changed,
 * so no exception is raised if that seems to be the case.
 */
inline static void write_setgroups(pid_t pid, bool deny = true)
{
    try {
        writeFile(fmt("/proc/%d/setgroups", pid), deny ? "deny" : "allow");
    } catch (SysError & e) {
        if (e.errNo != EACCES) throw;
    }
}

// XXX move to the other location
inline static int createUsernamespaceWithMappings(const IDMap & mapper)
{
    static const std::string SYNC_PARENT_NAMESPACE_READY = "1";
    static const std::string SYNC_PARENT_ERREXIT = "0";
    static const std::string SYNC_CHILD_EXIT = "X";

    //debug("setting up user namespace for ID-mapping: '%s'", mapper);

    // child-to-parent / other way around
    Pipe pipeC2P, pipeP2C;
    pipeC2P.create();
    pipeP2C.create();

    auto syncProcWrite = [] (Pipe& pipe, std::string_view tkn, std::string_view msg = "", bool close = false) {
        auto fd = pipe.writeSide.get();
        writeLine(fd, std::string(tkn));
        if (!msg.empty())
            writeFull(fd, fmt("%s\n", msg));
        if (close)
            pipe.writeSide.close();
    };

    auto syncProcRead = [] (const Pipe& pipe, std::string_view tkn) {
        auto fd = pipe.readSide.get();
        auto ln = readLine(fd, true);
        if (ln != tkn)
            throw Error("Unexpected response from process: '%s' (%s)", readFile(fd));
    };

    Pid pid(startProcess([&]() {
        pipeC2P.readSide.close();
        pipeP2C.writeSide.close();
        try {
            if (unshare(CLONE_NEWUSER) == -1)
                throw SysError("new user ns for idmap (is UID:GID 0:0 mapped in caller namespace?)");
            syncProcWrite(pipeC2P, SYNC_PARENT_NAMESPACE_READY);
            syncProcRead(pipeP2C, SYNC_CHILD_EXIT);
        }
        catch (Error & e) {
            syncProcWrite(pipeC2P, SYNC_PARENT_ERREXIT, e.message(), true);
            _exit(1);
        }
        _exit(0);
    }, { .cloneFlags = SIGCHLD }));
    pipeC2P.writeSide.close();
    pipeP2C.readSide = -1;

    syncProcRead(pipeC2P, SYNC_PARENT_NAMESPACE_READY);

    // Write setgroups, uid_map & gid_map
    write_setgroups(pid);
    write_id_map(pid, mapper, IDMapping::Type::Both);

    // Open namespace fd
    int userFd = open(fmt("/proc/%d/ns/user", (pid_t)pid).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");

    syncProcWrite(pipeP2C, SYNC_CHILD_EXIT, "", true);

    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");

    return userFd;
}

// IDMapping::Type

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
        default: throw Error("Unknown ID mapping type: '%1%'", ch);
    };
}

std::ostream & operator << (std::ostream & os, const IDMapping::Type & t)
{
    return os << static_cast<char>(t);
}

// IDMapping

std::string IDMapping::to_map_line() const
{
    // NOTE: The "mapped" part is first in uid_map/gid_map.
    // In IDMapping it's the other way around, {Host,Mapped,Range}.
    assert(range > 0);
    return fmt("%d %d %d\n", mapped_id, host_id, range);
}

IDMapping IDMapping::parse(const std::string & str)
{
    // T=H:M:R
    if (str.size() < 3 || str[1] != TypeSep)
        throw Error("Invalid ID mapping format: '%s'", str);

    auto parts = splitString<std::vector<std::string>>(str.substr(2), ValueSep);

    if (parts.size() > 3)
        throw Error("Invalid ID mapping format: '%s'", str);

    debug("Parsing idmap string: %s", str);
    return {
        .type = parse_type(str[0]),
        .host_id = (id_t)std::stoi(parts[0]),
        .mapped_id = (id_t)std::stoi(parts[parts.size() >= 2 ? 1 : 0]),
        .range = parts.size() >= 3 ? (unsigned int)std::stoi(parts[2]) : 1
    };
}

bool IDMapping::overlaps_with(const IDMapping & m) const
{
    return contains(m.type) && (
        ((mapped_id < m.mapped_id + m.range) && (mapped_id + range > m.mapped_id)) ||
        ((host_id < m.host_id + m.range) && (host_id + range > m.host_id))
    );
}

bool IDMapping::overlaps_with_any(auto maps) const
{
    return std::find_if(maps.begin(), maps.end(), [&](const IDMapping & m) {
        return this->overlaps_with(m); }) != maps.end();
}

bool IDMapping::operator<(const IDMapping & m) const
{
    // Order significance: Type -> Host -> Mapped -> Range
    if (type != m.type)
        return type < m.type;
    if (host_id != m.host_id)
        return host_id < m.host_id;
    if (mapped_id != m.mapped_id)
        return mapped_id < m.mapped_id;
    return
        range < m.range;
}

std::ostream & operator << (std::ostream & os, const IDMapping & m)
{
    // Type=Host:Mapped:Range
    return os << fmt("%c=%d:%d:%d", (char)m.type, m.host_id, m.mapped_id, m.range);
}

// IDMap

IDMap::IDMap(const Set & expl) { for (const auto & m : expl) add_explicit(m); }
IDMap::IDMap(const std::string & expl) { add_explicit(expl); }

IDMap::Set IDMap::parse_maps(const std::string & str)
{
    Set res;
    for (auto i : splitString<Strings>(str, ",\n\t\r"))
        if (!i.empty()) res.insert(IDMapping::parse(std::move(i)));
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

void IDMap::add_fallback(const IDMapping & m)
{
    fallback_maps.insert({ m.type, m.host_id, m.host_id, m.range });
}

void IDMap::add_fallback(const std::string & maps)
{
    for (const auto & map : parse_maps(maps)) add_fallback(map);
}

void IDMap::transform(const IDMapping::Type type, id_t from, id_t to)
{
    debug("idmap transform: %s: %d -> %d", type, from, to);

    auto f = [&](auto m, bool isexp)
    {
        if ((m.type == type || m.type == IDMapping::Type::Both) && m.mapped_id == from) {
            isexp ? explicit_maps.erase(m) : fallback_maps.erase(m);
            m.host_id = to;
            isexp ? add_explicit(m) : [&]{ fallback_maps.insert(m); }();
        }
    };
    for (auto m : explicit_maps) f(m, true);
    for (auto m : fallback_maps) f(m, false);
}

std::vector<IDMapping> IDMap::collect(const IDMapping::Type type) const
{
    std::vector<IDMapping> res;
    for (const auto & m : explicit_maps)
        if (m.contains(type))
            res.push_back(m);
    for (const auto & m : fallback_maps)
        if (m.contains(type) && !m.overlaps_with_any(res))
            res.push_back(m);
    if (res.empty()) // min. 1 map has to be defined
        res.push_back({ type, 0, 0, 1 });
    if (res.size() > IDMapping::IDMAP_LIMIT)
        throw Error("Too many mappings (>%d)", IDMapping::IDMAP_LIMIT);
    return res;
}

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

std::ostream & operator << (std::ostream & os, const IDMap & map)
{
    auto sep = "";
    for (auto em : map.explicit_maps) {
        os << fmt("%s%s", sep, em);
        sep = ", ";
    }
    sep = "";
    for (auto fm : map.fallback_maps) {
        os << fmt("%s(%s)", sep, fm);
        sep = ", ";
    }
    return os;
}

//* SandboxIDMap

void SandboxIDMap::write_userns_map(pid_t pid) const
{
    write_setgroups(pid);
    write_id_map(pid, primaryIDMap, IDMapping::Type::Both);
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
    for (const gid_t gid : (gid_t[]){0, 65534, primaryGID.mapped_id})
        if (!useSupplementaryGroups || !supplementaryGIDs.contains(gid))
            oss << fmt("%s:x:%d:\n", groupNames.at(gid), gid);

    // Supplementary groups
    for (auto [_, mappedID] : supplementaryGIDs)
        oss << fmt("%s:x:%d:nixbld\n", groupNames.at(mappedID), mappedID);
    writeFile(file, oss.str());
}

void SandboxIDMap::setPrimaryIDs(const uid_t uid, const gid_t gid)
{
    primaryUID.mapped_id = uid;
    primaryGID.mapped_id = gid;
    groupNames.try_emplace(gid, groupNames.at(IDMapping::UNSET));
}

void SandboxIDMap::setPrimaryHostIDs(const uid_t huid, const gid_t hgid)
{
    primaryUID.host_id = huid;
    primaryGID.host_id = hgid;
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

void SandboxIDMap::addSupplementaryGroups(const StringSet supgrps)
{
    debug("Setting supplementary groups: '%s'", concatStringsSep(" ", supgrps));
    useSupplementaryGroups = true;

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
        if (supplementaryGIDs.contains(parent_gid))
            throw Error("Group '%s': parent GID %d is already mapped", group_name, parent_gid);
        if (primaryGID.host_id == parent_gid)
            throw Error("Group '%s': parent GID %d is the primary builder GID", group_name, parent_gid);

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

        // Ensure the mapped name is unique.
        std::string mapped_name = gr->gr_name;
        int counter = 1;
        while (std::find_if(groupNames.begin(), groupNames.end(), ([&](auto i) { return i.second == mapped_name; })) != groupNames.end()) {
            if (counter <= 1) mapped_name += "-host";
            else mapped_name = fmt("%s%d", gr->gr_name, ++counter);
            debug("Group '%s': name conflicts with reserved name; attempting rename to '%s'...", group_name, mapped_name);
        }

        // Set the supplementary group for later assignment
        supplementaryGIDs[parent_gid] = mapped_gid.value();
        // Remember assigned group name for later
        groupNames[mapped_gid.value()] = std::move(mapped_name);
        // Remember the mapping pair
        primaryIDMap.add_explicit({ IDMapping::Type::Group, parent_gid, mapped_gid.value() });
    }
}

void SandboxIDMap::recordMountIDMap(IDMap::Set map)
{
    for (auto m : map)
        primaryIDMap.add_fallback(m);
}

int SandboxIDMap::getIDMapUserNsFd(IDMap::Set idmap)
{
    if (idmap.empty())
        return -1;

    IDMap map(idmap);

    /* Little convenience: if the target 1000:100 (either) is mapped in
       the mount, then modify it to match with the build user's host map
       instead. So that what mount's id-map maps into targets 1000:100
       becomes the mapping into the builder's *mapped* (=sandbox) IDs. (So
       you can have builders with a mapped UID 1000 and randomly
       changing host UID and filesystem) */
    map.transform(IDMapping::Type::User, primaryUID.mapped_id, primaryUID.host_id);
    map.transform(IDMapping::Type::Group, primaryGID.mapped_id, primaryGID.host_id);

    // Create new user ns and get its fd, unless the same mapping already
    // has a stored fd in which case copy that.
    auto [fds, _] = userNamespaceFDs.try_emplace(map.collectBoth(), [&] { return map.createUsernamespace(); }());
    auto fd = fds->second.get();

    return fd;
}
}
