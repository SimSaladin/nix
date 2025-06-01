#include "nix/util/idmaps.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"

#include <fstream>

#include <grp.h>

namespace nix {

static std::ofstream open_ofstream(const Path & fp)
{
    std::ofstream os(fp);
    if (!os.is_open())
        throw SysError("open %s", fp);
    return os;
}

//+ SupplementaryGroup

bool SupplementaryGroup::isConflict(const SupplementaryGroup & other) const
{
    return group == other.group || (gid && gid == other.gid);
}
std::string SupplementaryGroup::to_string() const
{
    return nlohmann::json(*this).dump();
}
void to_json(nlohmann::json & j, const SupplementaryGroup & v)
{
    j.emplace("group", v.group);
    if (v.gid.has_value())
        j.emplace("gid", v.gid);
    if (!v.name.empty())
        j.emplace("name", v.name);
};
void from_json(const nlohmann::json & j, SupplementaryGroup & v)
{
    static auto getGroup = [](const auto & j) {
        if (j.is_string()) {
            auto s = j.template get<std::string>();
            if (s.empty())
                UsageError("supplementary-groups: group must not be empty");
            return s;
        } else if (j.is_number())
            return fmt("%i", j.template get<uint>());
        else
            throw UsageError("supplementary-groups: expected string or number: %1%", j.dump());
    };
    if (j.is_object()) {
        v.group = getGroup(j.at("group"));
        v.gid = j.value("gid", v.gid);
        v.name = j.value("name", v.name);
    } else
        v.group = getGroup(j);
};
SupplementaryGroups SupplementaryGroup::parseArray(const std::string str)
{
    if (str.starts_with("[")) // read json
        return nlohmann::json::parse(str, nullptr, false, true).template get<std::vector<SupplementaryGroup>>();

    // Read strings
    SupplementaryGroups items = {};
    for (auto & part : splitString<StringSet>(str, " ")) {
        auto parts = splitString<std::vector<std::string>>(part, ":");
        if (parts.size() == 2)
            items.emplace_back(parts[0], string2Int<gid_t>(parts[1]));
        else if (parts.size() == 1)
            items.emplace_back(parts[0]);
        else
            throw UsageError("unexpected item: %s", part);
    }
    return items;
}

//+ IDMapping::T

IDMapping::T IDMapping::parse_type(const std::string & s)
{
    if (s.empty())
        throw UsageError("ID-mapping: type must not be empty");
    switch (s[0]) {
    case static_cast<char>(T::Both):
        return T::Both;
    case static_cast<char>(T::User):
        return T::User;
    case static_cast<char>(T::Group):
        return T::Group;
    default:
        throw UsageError("Unknown ID-mapping type: '%1%' (%2%)", s[0], s);
    };
}
std::ostream & operator<<(std::ostream & os, const IDMapping::T & t)
{
    return os << static_cast<char>(t);
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
    return os << m.to_string();
}
std::ostream & operator<<(std::ostream & os, const std::vector<IDMapping> & xs)
{
    os << "IDMappings[";
    for (auto it = xs.begin(); it != xs.end(); ++it)
        os << it->to_string() << (it + 1 != xs.end() ? ", " : "");
    return os << "]";
};
std::string IDMapping::to_map_string(const bool inverse) const
{
    assert(range > 0);
    return inverse ? fmt("%d %d %d", host_id, mapped_id, range) : fmt("%d %d %d", mapped_id, host_id, range);
}
std::string IDMapping::to_string() const
{
    return fmt("%c:%d:%d:%d", static_cast<char>(type), mapped_id, host_id, range);
}
IDMapping IDMapping::parse(const std::string & str)
{
    auto parts = splitString<Strings>(str, "=-:/");

    if (parts.size() < 1 || parts.size() > 4)
        UsageError("Invalid ID-mapping format: '%s'", str);

    IDMapping res;

    if (!parts.front().empty() && !std::isdigit(parts.front()[0])) {
        res.type = parse_type(parts.front());
        parts.pop_front();
    } else
        res.type = T::Both;

    if (parts.empty()) {
        throw UsageError("Invalid ID-mapping: '%s'", str);
    }
    res.mapped_id = *string2Int<id_t>(parts.front());
    parts.pop_front();

    if (parts.empty()) {
        res.host_id = res.mapped_id;
        return res;
    }
    res.host_id = *string2Int<id_t>(parts.front());
    parts.pop_front();

    if (!parts.empty())
        res.range = *string2Int<uint>(parts.front());

    return res;
}
bool IDMapping::contains(const T ot) const
{
    return type == ot || type == T::Both || ot == T::Both;
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

//+ IDMap

IDMap::IDMap(const S & expl, const V & fallback)
{
    for (const auto & m : expl)
        add_explicit(m);
    fallback_maps = fallback;
}
IDMap::S IDMap::parse(const std::string & str)
{
    S res;
    for (auto items : splitString<Strings>(str, ",\n\t\r"))
        if (!items.empty())
            res.insert(IDMapping::parse(std::move(items)));
    return res;
}
void IDMap::add_explicit(IDMapping m)
{
    if (m.overlaps_with_any(explicit_maps))
        throw Error("ID-mapping '%s' overlaps with another mapping", m);
    explicit_maps.insert(m);
}
void IDMap::add_fallback(const IDMapping & m)
{
    fallback_maps.push_back({m.type, m.mapped_id, m.mapped_id, m.range});
}
void IDMap::transform(const IDMapping::T type, id_t from, id_t to)
{
    debug("idmap transform: type:%s mapped:[%d -> %d]", type, from, to);
    for (auto m : explicit_maps)
        if (m.contains(type) && m.mapped_id == from) {
            explicit_maps.erase(m);
            m.mapped_id = to;
            add_explicit(m);
        }
    for (auto * m = fallback_maps.data(); m != fallback_maps.data() + fallback_maps.size(); ++m)
        if (m->contains(type) && m->mapped_id == from)
            m->mapped_id = to;
}
IDMap::S IDMap::collect(const IDMapping::T type, const IDMap::V & filter) const
{
    auto matches = [](auto fis, auto q) {
        for (auto & fi : fis) {
            if (!fi.contains(q.type))
                continue;
            if ((fi.mapped_id <= q.host_id) && (q.host_id + q.range <= fi.mapped_id + fi.range))
                return true;
        }
        return false;
    };
    S res;
    for (auto m : explicit_maps)
        if (m.contains(type) && (filter.empty() || matches(filter, m))) {
            m.type = type;
            res.insert(m);
        }
    for (auto m : fallback_maps)
        if (m.contains(type) && (filter.empty() || matches(filter, m)) && !m.overlaps_with_any(res)) {
            m.type = type;
            res.insert(m);
        }
    if (res.empty()) { // min. 1 map has to be defined
        res.insert({type, 0, 0, 1});
        warn("Empty ID map - defaulting to 0:0:1 [%s] (filter: %s)", *this, filter);
    }
    if (res.size() > IDMAP_LIMIT)
        throw Error("Too many mappings (>%d)", IDMAP_LIMIT);
    return res;
}
IDMap::S IDMap::collectBoth() const
{
    S res = collect(IDMapping::T::User);
    S ms = collect(IDMapping::T::Group);
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

//+ SandboxIDMap

void SandboxIDMap::addSupplementaryGroups(const SupplementaryGroups & supGrps, const std::vector<gid_t> & gids)
{
    if (!useSupplementaryGroups())
        return;

    debug("Resolving requested supplementary groups (%d)", supGrps.size());

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
        if (grGid == sandboxGid()) {
            warn("Group '%1%': ignored (host GID %2% is the primary builder GID)", group, grGid);
            return;
        }
        if (std::find_if(sandboxGroups.begin(), sandboxGroups.end(), ([&](auto v) { return v.second.hostId == grGid; }))
            != sandboxGroups.end())
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

        sandboxGroups.emplace(gid, MappedGID(std::move(name), {sandboxUid()}, grGid));
    };

    for (const auto & it : supGrps)
        if (!it.group.empty() && std::isdigit(it.group[0]))
            add(*string2Int<gid_t>(it.group), it.gid, it.name);
        else
            add(it.group, it.gid, it.name);

    for (const auto & gid : gids)
        if (gid != sandboxGid())
            add(gid, std::optional<gid_t>(gid), "");
}
std::vector<gid_t> SandboxIDMap::supplementaryHostGIDs() const
{
    if (!useSupplementaryGroups())
        return {};
    std::vector<gid_t> res = {};
    for (const auto & [nsGid, g] : sandboxGroups)
        if (g.hostId != IDMapping::UNSET && nsGid != sandboxGid())
            for (auto gid = g.hostId; gid < g.hostId + g.nrIds; ++gid)
                res.push_back(gid);
    return res;
}
void SandboxIDMap::writeGroupsFile(const Path & file) const
{
    auto ofs = open_ofstream(file);
    for (const auto & [gid, gr] : sandboxGroups)
        ofs << fmt(
            "%s:x:%d:%s\n",
            gr.name,
            gid,
            concatMapStringsSep(",", std::vector(gr.members.begin(), gr.members.end()), [&](auto x) {
                return sandboxUsers.at(x).name;
            }));
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
    for (auto [uid, u] : sandboxUsers)
        put(u.name, uid, u.group != IDMapping::UNSET ? u.group : uid, u.desc, u.homeDir.empty() ? homeDir : u.homeDir);
    ofs.close();
};
void SandboxIDMap::writeIDMapFiles(const pid_t pid, const IDMapping::T type) const
{
    IDMap idmap;
    for (auto [uid, u] : sandboxUsers)
        if (u.hostId != IDMapping::UNSET)
            idmap.add_explicit({IDMapping::T::User, u.hostId, uid, u.nrIds});
    for (auto [gid, g] : sandboxGroups)
        if (g.hostId != IDMapping::UNSET)
            idmap.add_explicit({IDMapping::T::Group, g.hostId, gid, g.nrIds});
    for (auto m : mountIDMaps)
        idmap.add_fallback(m);
    debug("Writing IDMaps for UIDs and GIDs for PID %i using %s", pid, idmap);
    if (type != IDMapping::T::User)
        write_setgroups(pid, true);
    writeIDMap(pid, idmap, type);
}
void SandboxIDMap::recordMountIDMap(IDMap idmap)
{
    for (auto m : idmap.collectBoth())
        mountIDMaps.push_back(m);
}
int SandboxIDMap::getIDMapUserNsFd(IDMap idmap)
{
    if (idmap.empty())
        return -1;

    /* Little convenience: if the target 1000:100 (either) is mapped in
       the mount, then modify it to match with the build user's host map
       instead. So that what mount's id-map maps into targets 1000:100
       becomes the mapping into the builder's *mapped* (=sandbox) IDs. (So
       you can have builders with a mapped UID 1000 and randomly
       changing host UID and filesystem) */
    if (sandboxUsers.contains(sandboxUid()))
        idmap.transform(IDMapping::T::User, sandboxUid(), sandboxUsers.at(sandboxUid()).hostId);
    if (sandboxGroups.contains(sandboxGid()))
        idmap.transform(IDMapping::T::Group, sandboxGid(), sandboxGroups.at(sandboxGid()).hostId);

    // Create new user ns and get its fd, unless the same mapping already
    // has a stored fd in which case copy that.
    auto [fds, _] =
        userNamespaceFDs.try_emplace(idmap.collectBoth(), [&] { return createUsernamespaceWithMappings(idmap); }());
    return fds->second.get();
}

//+ Functions

IDMap::V readIDMapFileThis(const IDMapping::T type)
{
    return readIDMapFile(fmt("/proc/self/%cid_map", (char) type), type);
}
IDMap::V readIDMapFile(const pid_t pid, const IDMapping::T type)
{
    return readIDMapFile(fmt("/proc/%i/%cid_map", pid, type), type);
}
IDMap::V readIDMapFile(const Path & filepath, const IDMapping::T type)
{
    std::ifstream file(filepath);
    if (!file)
        throw SysError("Opening file for reading: %s", filepath);
    IDMap::V result;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty())
            continue;
        auto items = tokenizeString<std::vector<std::string>>(line, " \t\n");
        result.push_back({
            .type = type,
            .host_id = *string2Int<id_t>(items[1]),
            .mapped_id = *string2Int<id_t>(items[0]),
            .range = *string2Int<uint>(items[2]),
        });
    }
    if (result.empty())
        warn("Read an empty ID map from: '%s'", filepath);
    return result;
}

bool write_setgroups(const pid_t pid, const bool deny)
{
    auto filepath = fmt("/proc/%i/setgroups", pid);
    try {
        writeFile(filepath, deny ? "deny" : "allow");
        return true;
    } catch (SysError & e) {
        if (e.errNo != EACCES)
            throw;
    }
    warn("could not write to setgroups file: '%s'", filepath);
    return false;
}

void writeIDMap(
    const pid_t pid,
    const IDMap & idmap,
    const IDMapping::T type,
    const bool inverse,
    const std::optional<pid_t> parent)
{
    if (type == IDMapping::T::Both) {
        writeIDMap(pid, idmap, IDMapping::T::User, inverse, parent);
        writeIDMap(pid, idmap, IDMapping::T::Group, inverse, parent);
        return;
    }
    auto filter = parent ? readIDMapFile(*parent, type) : readIDMapFileThis(type);
    Path filepath = fmt("/proc/%d/%cid_map", pid, (char) type);
    writeIDMap(filepath, idmap.collect(type, filter), inverse);
}
void writeIDMap(const Path & filepath, const IDMap::S ids, const bool inverse)
{
    std::ostringstream oss;
    for (const auto & m : ids)
        oss << m.to_map_string(inverse) << "\n";
    std::string content = oss.str();
    if (content.size() > IDMAP_MAX_SIZE)
        throw Error("Size of ID map exceeds the 4K length limit: '%s'", ids);
    debug("Writing ID map [%s] to file: '%s'", IDMap(ids), filepath);
    writeFile(filepath, content); // this should be a single write()
}

int createUsernamespaceWithMappings(const IDMap & mapper)
{
    static const char SYNC_PARENT_NAMESPACE_READY = '1';
    static const char SYNC_PARENT_ERREXIT = '0';
    static const char SYNC_CHILD_EXIT = 'X';

    debug("new user namespace for ID-mapping: '%s'", mapper);

    // child-to-parent / other way around
    Pipe pipeC2P, pipeP2C;
    pipeC2P.create();
    pipeP2C.create();

    auto syncProcWrite = [](Pipe & pipe, char tkn, std::string_view msg = "", bool close = false) {
        auto fd = pipe.writeSide.get();
        writeLine(fd, fmt("%c", tkn));
        if (!msg.empty())
            writeFull(fd, fmt("%s\n", msg));
        if (close)
            pipe.writeSide.close();
    };

    auto syncProcRead = [](const Pipe & pipe, char tkn) {
        auto fd = pipe.readSide.get();
        auto ln = readLine(fd, true);
        if (ln.empty() || ln[0] != tkn)
            throw Error("Unexpected response from process: %s (%s)", ln, readFile(fd));
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
    writeIDMap(pid, mapper, IDMapping::T::Both, true);

    // Open namespace fd
    int userFd = open(fmt("/proc/%d/ns/user", (pid_t) pid).c_str(), O_RDONLY /*| O_CLOEXEC*/ | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");

    syncProcWrite(pipeP2C, SYNC_CHILD_EXIT, "", true);

    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");

    return userFd;
}

}
