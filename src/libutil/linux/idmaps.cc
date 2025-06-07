#include "nix/util/idmaps.hh"
// #include "nix/util/types.hh"
#include "nix/util/util.hh"
// #include "nix/util/current-process.hh"
// #include "nix/util/finally.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"
// #include "nix/util/cgroup.hh"
// #include "nix/util/signals.hh"

#include <fstream>
// #include <mutex>
// #include <sys/resource.h>
// #include <sys/types.h>
#include <sys/mount.h>

namespace nix {

std::ostream & operator << (std::ostream & os, const IDMapType & t)
{
    return os << static_cast<char>(t);
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
    // shortest valid "u=0" e.g. "u=0-0-1"
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

bool overlaps_with_any(const IDMapping & mapping, auto maps)
{
    return std::find_if(maps.begin(), maps.end(), [&](const IDMapping & r) {
            return mapping.overlaps_with(r);
        }) != maps.end();
}

IDMapper::IDMapper(const std::string & expl)
{
    add_explicit(expl);
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

void IDMapper::add_fallback(const IDMapping & map) {
    /* mount idmap <id-from>:<id-to> only makes sense when there's a
       ".host_id = <id-to>" mapping in the sandbox user namespace. If in
       addition .mapped_id = <id-from> the ID's are just exactly the same
       inside the sandbox, which probably wasn't intended, so by default we
       add the mapping host_id == mapped_id instead.
     */
    fallback_maps.insert({.type = map.type, .mapped_id = map.host_id, .host_id
            = map.host_id, .range = map.range});
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

int createUsernamespaceWithMappings(const std::string & str, uid_t sandbox_uid, gid_t sandbox_gid)
{
    if (str.empty()) return -1;

    debug("setting up user namespace for ID-mapping: '%s' (%d:%d)", str, sandbox_uid, sandbox_gid);

    IDMapper mapper;
    try {
        mapper = IDMapper(str);
        mapper.transform(IDMapType::UID, 1000, sandbox_uid);
        mapper.transform(IDMapType::GID, 100, sandbox_gid);
    } catch (Error & e) {
        debug(e.message());
        throw;
    }

    Pipe syncPipe, exitPipe;
    syncPipe.create();
    exitPipe.create();
    Pid pid(startProcess([&]()
    {
        syncPipe.readSide.close();
        exitPipe.writeSide.close();
        try {
            if (unshare(CLONE_NEWUSER) == -1)
                throw SysError("new user ns for idmap (is UID:GID 0:0 mapped in caller namespace?)");
            writeFull(syncPipe.writeSide.get(), "1\n");
            readLine(exitPipe.readSide.get(), true);
        } catch (Error & e) {
            writeFull(syncPipe.writeSide.get(), "0\n" + e.message());
            _exit(1);
        }
        _exit(0);
    }, { .cloneFlags = SIGCHLD }));

    syncPipe.writeSide.close();
    exitPipe.readSide = -1;

    Finally cleanup([&]() { exitPipe.writeSide = -1; });

    if (readLine(syncPipe.readSide.get(), true) != "1")
        throw Error("Setting up user namespace failed: " + readFile(syncPipe.readSide.get()));

    try {
        writeFile(fmt("/proc/%d/setgroups", (pid_t)pid), "deny");
    } catch (SysError & e) {
        if (e.errNo != EACCES) throw; // in case of child ns, setgroups is inherited from parent ns and cannot be changed
    }
    writeIDMapFile(fmt("/proc/%d/uid_map", (pid_t)pid), mapper.collect(IDMapType::UID), IDMapType::UID);
    writeIDMapFile(fmt("/proc/%d/gid_map", (pid_t)pid), mapper.collect(IDMapType::GID), IDMapType::GID);

    int userFd = open(fmt("/proc/%d/ns/user", (pid_t)pid).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");
    debug("ID map USER namespace Fd=%d", userFd);

    writeLine(exitPipe.writeSide.get(), "X"); // Signal child to exit
    exitPipe.writeSide.close();
    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");
    if (fcntl(userFd, F_GETFD) == -1)
        throw SysError("fcntl(userFd)");
    return userFd;
}

void bindMountWithIDMap(const Path & source, const Path & target, int userns_fd, bool optional, bool rdonly)
{
    debug("bind mounting ID-mapped '%s' to '%s' with userns=%d", source, target, userns_fd);

    auto maybeSt = maybeLstat(source);
    if (!maybeSt) {
        if (optional) return;
        else throw SysError("stat path '%s'", source);
    }

    // TODO do we need to handle source is file/symlink differently?
    createDirs(target);

    int treefd = open_tree(-EBADF, source.c_str(), OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
            | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | AT_RECURSIVE);
    if (treefd == -1)
        throw SysError("open_tree '%s'", source);

    mount_attr attr = {
        .attr_set = rdonly ? (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC) : static_cast<uint64_t>(0),
        .propagation = MS_PRIVATE,
    };

    if (userns_fd > 0) {
        attr.attr_set |= MOUNT_ATTR_IDMAP;
        attr.userns_fd = static_cast<uint64_t>(userns_fd); // FD's are int, except when ABI compatibility requires otherwise
    }

    if (mount_setattr(treefd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(struct mount_attr)) == -1)
        throw SysError("mount_setattr '%s'", source);

    if (move_mount(treefd, "", -EBADF, target.c_str(), MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH | MOVE_MOUNT_T_SYMLINKS) == -1)
        throw SysError("move_mount '%s'", source);

    close(treefd);
}

}
