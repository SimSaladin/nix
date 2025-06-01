#include "nix/util/idmaps.hh"
#include "nix/util/util.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"

#include <fstream>
#include <ranges>
#include <sys/types.h>
#include <sys/mount.h>
#include <grp.h>

namespace nix {

static std::ofstream open_ofstream(const Path & fp)
{
    std::ofstream os(fp);
    if (!os.is_open())
        throw SysError("open %s", fp);
    return os;
}

int createUsernamespaceWithMappings(const IDMap & mapper)
{
    static const std::string SYNC_PARENT_NAMESPACE_READY = "1";
    static const std::string SYNC_PARENT_ERREXIT = "0";
    static const std::string SYNC_CHILD_EXIT = "X";

    // debug("setting up user namespace for ID-mapping: '%s'", mapper);

    // child-to-parent / other way around
    Pipe pipeC2P, pipeP2C;
    pipeC2P.create();
    pipeP2C.create();

    auto syncProcWrite = [](Pipe & pipe, std::string_view tkn, std::string_view msg = "", bool close = false) {
        auto fd = pipe.writeSide.get();
        writeLine(fd, std::string(tkn));
        if (!msg.empty())
            writeFull(fd, fmt("%s\n", msg));
        if (close)
            pipe.writeSide.close();
    };

    auto syncProcRead = [](const Pipe & pipe, std::string_view tkn) {
        auto fd = pipe.readSide.get();
        auto ln = readLine(fd, true);
        if (ln != tkn)
            throw Error("Unexpected response from process: '%s' (%s)", readFile(fd));
    };

    Pid pid(startProcess(
        [&]() {
            pipeC2P.readSide.close();
            pipeP2C.writeSide.close();
            try {
                if (unshare(CLONE_NEWUSER) == -1)
                    throw SysError("new user ns for idmap (is UID:GID 0:0 mapped in caller namespace?)");
                syncProcWrite(pipeC2P, SYNC_PARENT_NAMESPACE_READY);
                syncProcRead(pipeP2C, SYNC_CHILD_EXIT);
            } catch (Error & e) {
                syncProcWrite(pipeC2P, SYNC_PARENT_ERREXIT, e.message(), true);
                _exit(1);
            }
            _exit(0);
        },
        {.cloneFlags = SIGCHLD}));
    pipeC2P.writeSide.close();
    pipeP2C.readSide = -1;

    syncProcRead(pipeC2P, SYNC_PARENT_NAMESPACE_READY);

    // Write setgroups, uid_map & gid_map
    write_setgroups(pid);
    write_id_map(pid, mapper, IDMapping::T::Both);

    // Open namespace fd
    int userFd = open(fmt("/proc/%d/ns/user", (pid_t) pid).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");

    syncProcWrite(pipeP2C, SYNC_CHILD_EXIT, "", true);

    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");

    return userFd;
}

/**
 * Given a ProcessID, ID-map and ID-map type, writes the corresponding uid_map
 * and/or gid_map for the process (e.g. namespace)
 */
void write_id_map(const pid_t pid, const IDMap & map, const IDMapping::T type)
{
    if (type == IDMapping::T::Both) {
        write_id_map(pid, map, IDMapping::T::User);
        write_id_map(pid, map, IDMapping::T::Group);
        return;
    }

    auto filepath = fmt("/proc/%d/%cid_map", pid, static_cast<char>(type));

    std::ostringstream oss;
    for (const auto & m : map.collect(type))
        oss << m.to_string();

    std::string content = oss.str();
    if (content.size() > IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit for '%s': %s", filepath, map);

    debug("idmap write %s (%s)", filepath, replaceStrings(content, "\n", ";"));

    std::ofstream file = open_ofstream(filepath);
    file << content;
    if (!file)
        throw SysError("write %s", filepath);
    file.close();
}

/**
 * Writes setgroups if necessary/possible for PID (namespace).
 * In case of child ns, setgroups is inherited from parent ns and cannot be changed,
 * so no exception is raised if that seems to be the case.
 */
void write_setgroups(const pid_t pid, const bool deny)
{
    try {
        writeFile(fmt("/proc/%d/setgroups", pid), deny ? "deny" : "allow");
    } catch (SysError & e) {
        if (e.errNo != EACCES)
            throw;
    }
}

//+ IDMapping

bool operator==(const IDMapping & a, const IDMapping & b)
{
    return (a.type == b.type) && (a.host_id == b.host_id) && (a.mapped_id == b.mapped_id) && (a.range == b.range);
}
std::strong_ordering operator<=>(const IDMapping & a, const IDMapping & b)
{
    if (a.type != b.type)
        return a.type <=> b.type;
    if (a.host_id != b.host_id)
        return a.host_id <=> b.host_id;
    if (a.mapped_id != b.mapped_id)
        return a.mapped_id <=> b.mapped_id;
    return a.range <=> b.range;
}
std::ostream & operator<<(std::ostream & os, const IDMapping & m)
{
    return os << fmt("%c=%d:%d:%d", static_cast<char>(m.type), m.host_id, m.mapped_id, m.range);
}
std::ostream & operator<<(std::ostream & os, const IDMapping::T & t)
{
    return os << static_cast<char>(t);
}

bool IDMapping::contains(const T t2) const
{
    return type == t2 || type == T::Both || t2 == T::Both;
}
bool IDMapping::overlaps_with(const IDMapping & m) const
{
    return contains(m.type)
           && (((mapped_id < m.mapped_id + m.range) && (mapped_id + range > m.mapped_id))
               || ((host_id < m.host_id + m.range) && (host_id + range > m.host_id)));
}
bool IDMapping::overlaps_with_any(auto maps) const
{
    return std::find_if(maps.begin(), maps.end(), [&](const IDMapping & m) { return this->overlaps_with(m); })
           != maps.end();
}
std::string IDMapping::to_string() const
{
    assert(range > 0);
    return fmt("%d %d %d\n", mapped_id, host_id, range);
}
/**
 * Parsed format: T=H:M:R
 */
IDMapping IDMapping::parse(const std::string & str)
{
    if (str.size() < 3 || str[1] != '=')
        throw Error("Invalid ID mapping format: '%s'", str);
    IDMapping res(parse_type(str[0]));
    auto parts = splitString<Strings>(str.substr(2), "-:/");
    if (parts.size() > 3)
        throw Error("Invalid ID mapping format: '%s'", str);
    if (!parts.empty()) {
        res.host_id = *string2Int<id_t>(parts.front());
        parts.pop_front();
    }
    if (!parts.empty()) {
        res.mapped_id = *string2Int<id_t>(parts.front());
    }
    if (!parts.empty())
        res.range = *string2Int<uint>(parts.front());
    return res;
}

IDMapping::T IDMapping::parse_type(const char ch)
{
    switch (ch) {
    case static_cast<char>(T::Both):
        return T::Both;
    case static_cast<char>(T::User):
        return T::User;
    case static_cast<char>(T::Group):
        return T::Group;
    default:
        throw Error("Unknown ID mapping type: '%1%'", ch);
    };
}

// IDMap

IDMap::IDMap(const Vec & expl)
{
    for (const auto & m : expl)
        add_explicit(m);
}

IDMap::IDMap(const std::string & expl)
{
    add_explicit(expl);
}

IDMap::Vec IDMap::parse(const std::string & str)
{
    Vec res;
    for (auto items : splitString<Strings>(str, ",\n\t\r"))
        if (!items.empty())
            res.insert(IDMapping::parse(std::move(items)));
    return res;
}

void IDMap::add_explicit(IDMapping map)
{
    if (map.overlaps_with_any(explicit_maps))
        throw Error("ID-mapping '%s' overlaps with another mapping", map);
    explicit_maps.insert(map);
}

void IDMap::add_explicit(const std::string & maps)
{
    for (const auto & map : parse(maps))
        add_explicit(map);
}

void IDMap::add_fallback(const IDMapping & m)
{
    fallback_maps.insert({m.type, m.host_id, m.host_id, m.range});
}

void IDMap::transform(const IDMapping::T type, id_t from, id_t to)
{
    debug("idmap transform: %s: %d -> %d", type, from, to);
    auto erase = [&](auto & m, auto & ms) {
        for (auto it = ms.begin(); it != ms.end(); ++it)
            if (*it == m)
                ms.erase(it);
    };
    auto f = [&](auto m, bool isexp) {
        if ((m.type == type || m.type == IDMapping::T::Both) && m.mapped_id == from) {
            isexp ? erase(m, explicit_maps) : erase(m, fallback_maps);
            m.host_id = to;
            if (isexp)
                add_explicit(m);
            else
                fallback_maps.insert(m);
        }
    };
    for (auto m : explicit_maps)
        f(m, true);
    for (auto m : fallback_maps)
        f(m, false);
}

IDMap::Vec IDMap::collect(const IDMapping::T type) const
{
    Vec res;
    for (auto m : explicit_maps)
        if (m.contains(type)) {
            m.type = type;
            res.insert(m);
        }
    for (auto m : fallback_maps)
        if (m.contains(type) && !m.overlaps_with_any(res)) {
            m.type = type;
            res.insert(m);
        }
    if (res.empty()) // min. 1 map has to be defined
        res.insert({type, 0, 0, 1});
    if (res.size() > IDMAP_LIMIT)
        throw Error("Too many mappings (>%d)", IDMAP_LIMIT);
    return res;
}

IDMap::Vec IDMap::collectBoth() const
{
    Vec res = collect(IDMapping::T::User);
    Vec ms = collect(IDMapping::T::Group);
    res.insert(ms.begin(), ms.end());
    return res;
}

std::ostream & operator<<(std::ostream & os, const IDMap & map)
{
    auto go = [](const auto & xs) {
        return concatMapStringsSep(",", xs, [](const auto & x) { return x.to_string(); });
    };
    os << fmt("IDMap(explicit: %s; fallback: %s)", go(map.explicit_maps), go(map.fallback_maps));
    return os;
}

//* SandboxIDMap

void SandboxIDMap::addSandboxGroup(const gid_t gid, std::string name, const std::set<std::string> & members)
{
    sandboxGroups.insert_or_assign(gid, SandboxGroup{std::move(name), members});
}

void SandboxIDMap::addSupplementaryGroups(const SupplementaryGroups & supGrps, const std::vector<gid_t> & gids)
{
    if (!useSupplementaryGroups())
        return;

    debug("Resolving requested supplementary groups (%d)", supGrps.size());

    addSandboxGroup(sandboxGid(), sandboxGroup());

    struct group gr;
    struct group * grPtr = nullptr;
    std::vector<char> buf;
    long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1)
        bufsize = 16384;

    auto add = [&](const auto group, const auto use_gid, const std::string useName) {
        while (true) {
            buf.resize(bufsize);
            int ret;
            if constexpr (std::is_integral<decltype(group)>::value)
                ret = getgrgid_r(group, &gr, buf.data(), buf.size(), &grPtr);
            else
                ret = getgrnam_r(group.c_str(), &gr, buf.data(), buf.size(), &grPtr);
            if (ret == 0) {
                break;
            } else if (ret == ERANGE) { // buffer too small
                bufsize *= 2;
            } else if (ret != 0)
                throw Error("Getting group '%1%' failed: %2%", group, strerror(ret));
        }

        gid_t grGid;
        std::string nameBase;
        if (grPtr) {
            grGid = grPtr->gr_gid;
            nameBase = grPtr->gr_name;
        } else {
            debug("No such group: %1%", group);
            if (!use_gid.has_value())
                return;
            if constexpr (std::is_integral<decltype(group)>::value)
                grGid = group;
            else
                grGid = *use_gid;
            if constexpr (std::is_convertible_v<decltype(group), std::string>)
                nameBase = group;
            else
                nameBase = fmt("group%i", *use_gid);
        }

        // Host GID sanity checks
        if (grGid == 0)
            throw Error("Group '%1%': mapping the root group (GID 0) is not a good idea", group);
        if (hostGid() == grGid) {
            warn("Group '%1%': ignored (host GID %2% is the primary builder GID)", group, grGid);
            return;
        }
        if (supplementaryGIDs.contains(grGid))
            throw Error("Group '%1%': host GID %2% is already mapped", group, grGid);

        /* Mapped GID sanity checks

           65535 is the special invalid/overflow GID distinct from
           nogroup. We don't want to allow that.

           2^16 and above are not allowed because it would seem impossible
           to assign them. In a quick test higher GIDs got truncated to
           65534. Might have something to do with how we're forced to call
           setgroups before setting up the namespace. */
        gid_t gid = use_gid ? *use_gid : grGid;
        if (gid > 65534)
            throw Error("Group '%1%': mapped GID %2% is too large (>65534)", group, gid);
        if (sandboxGroups.contains(gid))
            throw Error("Group '%1%': mapped GID %2% conflicts with reserved GID", group, gid);

        // Ensure the mapped name is unique.
        std::string name = useName.empty() ? nameBase : useName;
        int counter = 1;
        while (std::find_if(sandboxGroups.begin(), sandboxGroups.end(), ([&](auto v) { return v.second.name == name; }))
               != sandboxGroups.end()) {
            if (!useName.empty())
                throw Error("Group '%1%': requested name '%2%' conflicts with another group", group, name);
            if (counter++ == 1)
                name += "-host";
            else
                name = fmt("%s-%i", &nameBase, counter);
            debug("Group '%1%': name conflicts with reserved name; attempting rename to '%2%'...", group, name);
        }

        // Set the supplementary group for later assignment
        supplementaryGIDs[grGid] = gid;

        // Remember assigned group name for later
        addSandboxGroup(gid, std::move(name), {sandboxUser()});

        // Remember the mapping pair
        primaryIDMap.add_explicit({IDMapping::T::Group, grGid, gid});
    };

    for (const auto & it : supGrps)
        if (!it.group.empty() && std::isdigit(it.group[0]))
            add(*string2Int<gid_t>(it.group), it.gid, it.name);
        else
            add(it.group, it.gid, it.name);
    for (const auto & gid : gids)
        if (gid != sandboxGid() && !supplementaryGIDs.contains(gid))
            add(gid, std::optional<gid_t>(gid), "");
}

std::vector<gid_t> SandboxIDMap::supplementaryHostGIDs() const
{
    if (!useSupplementaryGroups())
        return {};
    std::vector<gid_t> res = {};
    for (auto [x, _] : supplementaryGIDs)
        res.push_back(x);
    return res;
}

void SandboxIDMap::writeGroupsFile(const Path & file)
{
    addSandboxGroup(sandboxGid(), sandboxGroup());
    auto ofs = open_ofstream(file);
    for (const auto & [gid, gr] : sandboxGroups)
        ofs << fmt(
            "%s:x:%d:%s\n", gr.name, gid, concatStringsSep(",", std::vector(gr.members.begin(), gr.members.end())));
    ofs.close();
}

void SandboxIDMap::writePasswdFile(const Path & file, Path & homeDir) const
{
    auto ofs = open_ofstream(file);
    auto put = [&ofs](
                   const std::string & username,
                   const uid_t uid,
                   const gid_t gid,
                   const std::string & description,
                   const Path & homeDir) {
        ofs << fmt("%1%:x:%2%:%3%:%4%:%5%:/noshell\n", username, uid, gid, description, homeDir);
    };
    put("root", 0, 0, "Nix build user", homeDir);
    put(sandboxUser(), sandboxUid(), sandboxGid(), "Nix build user", homeDir);
    put("nobody", 65534, 65534, "Nobody", "/");
    ofs.close();
};

static void writeIDMap(const pid_t pid, const IDMap idmap, const IDMapping::T type)
{
    if (type == IDMapping::T::Both) {
        writeIDMap(pid, idmap, IDMapping::T::User);
        writeIDMap(pid, idmap, IDMapping::T::Group);
        return;
    }
    std::ostringstream oss;
    for (const auto & m : idmap.collect(type))
        oss << m.to_string();
    std::string content = oss.str();
    if (content.size() > IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit: '%s'", idmap);

    auto filepath = fmt("/proc/%d/%cid_map", pid, (char) type);
    auto ofs = open_ofstream(filepath);
    ofs << content;
    ofs.close();
}

void SandboxIDMap::writeIDMapFiles(const pid_t pid, const IDMapping::T type)
{
    primaryIDMap.add_explicit({IDMapping::T::User, hostUid(), sandboxUid(), nrUids()});
    primaryIDMap.add_explicit({IDMapping::T::Group, hostGid(), sandboxGid(), nrGids()});
    if (type != IDMapping::T::User)
        write_setgroups(pid, true);
    writeIDMap(pid, primaryIDMap, type);
}

//* Mount ID-mapping

void SandboxIDMap::recordMountIDMap(IDMap::Vec map)
{
    for (auto m : map)
        primaryIDMap.add_fallback(m);
}

int SandboxIDMap::getIDMapUserNsFd(IDMap::Vec idmap)
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
    map.transform(IDMapping::T::User, sandboxUid(), hostUid());
    map.transform(IDMapping::T::Group, sandboxGid(), hostGid());

    // Create new user ns and get its fd, unless the same mapping already
    // has a stored fd in which case copy that.
    auto [fds, _] =
        userNamespaceFDs.try_emplace(map.collectBoth(), [&] { return createUsernamespaceWithMappings(map); }());
    auto fd = fds->second.get();

    return fd;
}
}
