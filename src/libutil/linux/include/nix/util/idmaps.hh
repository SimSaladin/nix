#pragma once

#include "nix/util/util.hh"
#include "nix/util/linux-namespaces.hh"

#include <sys/mount.h>

namespace nix {

/* kernel only takes up to 4k in size or 340 in number of entries written
 * into uid_map/gid_map */
inline constexpr size_t IDMAP_MAX_SIZE = 4096;
inline constexpr uint64_t IDMAP_LIMIT = 340;

/**
 * Single contiguous ID map range of UIDs, GIDs or both.
 *
 * { Type, HostId, MappedId, Range }
 *
 * In configs this is typically parsed from something such as:
 *
 *    "Type=HostID:ContainerID:Range"
 *
 * E.g. u=1000:0:1, g=100:0:1, etc.
 */
struct IDMapping
{
    enum class T : char { User = 'u', Group = 'g', Both = 'b' };

    // 0 is as valid ID as any but not the safest default
    inline static constexpr id_t UNSET = static_cast<id_t>(-1);

    T type;                 // 1
    id_t host_id = UNSET;   // 2
    id_t mapped_id = UNSET; // 3
    unsigned int range = 1; // 4

    friend bool operator==(const IDMapping &, const IDMapping &);
    friend std::strong_ordering operator<=>(const IDMapping &, const IDMapping &);

    bool overlaps_with(const IDMapping & other) const;
    bool overlaps_with_any(auto maps) const;
    bool contains(const T) const;
    std::string to_string() const;
    friend std::ostream & operator<<(std::ostream &, const T &);
    friend std::ostream & operator<<(std::ostream &, const IDMapping &);

    static IDMapping parse(const std::string &);
    static T parse_type(const char);
};

/**
 * Container for sets of ID-mappings. Second set of IDMapping's
 * denotes "fallback" mappings that are created unless any other mappings are
 * defined that would conflict with them.
 *
 * This is to allow some heuristic defaults be applied when more specific
 * settings are not configured.
 */
class IDMap
{
public:
    using Vec = std::set<IDMapping>;

private:
    Vec explicit_maps, fallback_maps;

public:
    IDMap(const Vec & explicit_maps);
    IDMap(const std::string & explicit_maps = "");

    void add_explicit(IDMapping map);
    void add_explicit(const std::string & map);

    /**
     * Mount idmap <id-from>:<id-to> only makes sense when there's a
     * ".host_id = <id-to>" mapping in the sandbox user namespace. If in addition
     * .mapped_id = <id-from> the ID's are just exactly the same inside the
     * sandbox, which probably wasn't intended, so by default we add the mapping
     * host_id == mapped_id instead. */
    void add_fallback(const IDMapping & map);

    /**
     * Calculate both UID and GID maps (no overlapping).
     */
    Vec collectBoth() const;
    Vec collect(const IDMapping::T type) const;

    friend std::ostream & operator<<(std::ostream &, const IDMap &);

    /**
     * Transform maps of given type: any "from" mapped id is remapped to "to"
     * host id(s). Used to override host-side id for the mapped id when the
     * mapped id is auto-allocated/randomly changes. This way the fresh
     * primary uid corresponds to a stationary host id.
     */
    void transform(const IDMapping::T type, id_t from, id_t to);

    /**
     * Parses arbitrary amount of mappings separated by commas. Only vaidates the
     * format and skips exact duplicates!! Results from this may not be accepted
     * for gid_map/uid_map depending on other factors (clashing map ranges,
     * missing mappings in caller namespace, missing permissions, ...)
     */
    static Vec parse(const std::string &);
};

/**
 * This tracks all of the ID mappings in a chroot/namespace sandbox: the
 * process-level UID/GID maps, user's primary IDs and supplementary
 * groups, as well as any mappings for ID-mapped mounts (binds).
 */
class SandboxIDMap
{
    struct SandboxGroup
    {
        std::string name;
        std::set<std::string> members = {};
    };

private:
    /**
     * Builder namespace ID maps.
     */
    IDMap primaryIDMap;

    /**
     * Groups (GIDs and names) that we will define inside the sandbox's group
     * database. Indexed by the mapped GID.
     */
    std::map<gid_t, SandboxGroup> sandboxGroups = {{0, {"root"}}, {65534, {"nogroup"}}};

    /**
     * Host GID -> Sandbox GID.
     */
    std::map<gid_t, gid_t> supplementaryGIDs;

public:
    /**
     * Build user's UID/GID within the sandbox.
     */
    virtual uid_t sandboxUid() const = 0;
    virtual gid_t sandboxGid() const = 0;

    /**
     * Mapped username.
     */
    virtual std::string sandboxUser() const
    {
        return "nixbld";
    };

    /**
     * Mapped primary group's name.
     */
    virtual std::string sandboxGroup() const
    {
        return "nixbld";
    };

    /* Host primary UID and GID. */
    virtual uid_t hostUid() const = 0;
    virtual gid_t hostGid() const = 0;
    virtual uint nrUids() const = 0;
    virtual uint nrGids() const = 0;

    /* Whether or not supplementary groups should be set. If false sup groups
     * are emptied. */
    virtual bool useSupplementaryGroups() const
    {
        return false;
    };

    /**
     * Define groups for the sandbox.
     */
    void addSandboxGroup(const gid_t, std::string, const std::set<std::string> & members = {});

    /**
     * Add and enable supplemantary groups based on given configuration.
     *
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
     * unmapped GIDs get mapped to (including root).) */
    void addSupplementaryGroups(const SupplementaryGroups &, const std::vector<gid_t> &);

    /**
     * Get the host-side GIDs that should be assigned with setgroups().
     */
    std::vector<gid_t> supplementaryHostGIDs() const;

    /**
     * Format minimal /etc/groups for the sandbox
     */
    void writeGroupsFile(const Path &);

    /**
     * Writes the process uid_map, gid_map and setgroups files.
     */
    void writeIDMapFiles(const pid_t, const IDMapping::T = IDMapping::T::Both);

    /**
     * Write the user database for the sandbox.
     */
    void writePasswdFile(const Path &, Path & homeDir) const;

private:
    /**
     * Recover or create usernamespace fd for idmapping.
     */
    int getIDMapUserNsFd(IDMap::Vec);

    /**
     * IDMapped mounts' ID maps are separate from the build sandbox's
     * usernamespace by default. But for convenience the maps of id-mapped
     * mounts are recreated in the builder process namespace when it does not
     * overlap with any explicitly declared mapping. */
    void recordMountIDMap(IDMap::Vec map);

    /**
     * User namespace FDs for idmapped mounts. We store each unique map
     * definition for re-use (creating an idmapping fd requires us to
     * setup a whole new user namespace).
     */
    std::map<IDMap::Vec, AutoCloseFD> userNamespaceFDs = {};
};

void write_setgroups(const pid_t, const bool = true);
void write_id_map(const pid_t, const IDMap &, const IDMapping::T = IDMapping::T::Both);
int createUsernamespaceWithMappings(const IDMap & mapper);
}
