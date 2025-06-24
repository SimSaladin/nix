#pragma once
#include "nix/util/util.hh"
#include "nix/util/sync.hh"
#include <sys/mount.h>

namespace nix {

struct IDMapping
{
    enum class Type : char {
        User = 'u',
        Group = 'g',
        Both = 'b',
    };

    Type type; // 1
    id_t host_id = UNSET; // 2
    id_t mapped_id = UNSET; // 3
    unsigned int range = 1; // 4

    // 0 is as valid ID as any but not the safest default
    static inline constexpr id_t UNSET = static_cast<id_t>(-1);
    static inline constexpr char TypeSep = '=';
    static inline constexpr char ValueSep[] = "-";
    /* kernel only takes up to 4k in size or 340 in number of entries written
     * into uid_map/gid_map */
    static inline constexpr size_t IDMAP_MAX_SIZE = 4096;
    static inline constexpr uint64_t IDMAP_LIMIT = 340;

    static Type parse_type(const char);
    static IDMapping parse(const std::string&);
    static bool contains(const Type, const Type);

    bool operator<(const IDMapping & other) const;
    bool overlaps_with(const IDMapping & other) const;
    bool overlaps_with_any(auto maps) const;
    bool contains(const Type) const;
    std::string to_map_line() const;

    friend std::ostream & operator<<(std::ostream&, const Type&);
    friend std::ostream & operator<<(std::ostream&, const IDMapping&);
};

class IDMap
{
public:
    typedef std::set<IDMapping> Set;
private:
    Set explicit_maps, fallback_maps;

public:
    IDMap(const Set& explicit_maps);
    IDMap(const std::string & explicit_maps = "");

    /**
     * Parses arbitrary amount of mappings separated by commas. Only vaidates the
     * format and skips exact duplicates!! Results from this may not be accepted
     * for gid_map/uid_map depending on other factors (clashing map ranges,
     * missing mappings in caller namespace, missing permissions, ...)
     */
    static Set parse_maps(const std::string&);

    void add_explicit(const IDMapping & map);
    void add_explicit(const std::string & map);

    /**
     * Mount idmap <id-from>:<id-to> only makes sense when there's a
     * ".host_id = <id-to>" mapping in the sandbox user namespace. If in addition
     * .mapped_id = <id-from> the ID's are just exactly the same inside the
     * sandbox, which probably wasn't intended, so by default we add the mapping
     * host_id == mapped_id instead. */
    void add_fallback(const IDMapping & map);
    void add_fallback(const std::string & map);

    std::vector<IDMapping> collect(const IDMapping::Type type) const;

    /**
     * Calculate both UID and GID maps (no overlapping).
     */
    Set collectBoth() const;

    /**
     * Transform maps of given type: any "from" mapped id is remapped to "to"
     * host id(s). Used to override host-side id for the mapped id when the
     * mapped id is auto-allocated/randomly changes. This way the fresh
     * primary uid corresponds to a stationary host id.
     */
    void transform(const IDMapping::Type type, id_t from, id_t to);

    int createUsernamespace() const;

    friend std::ostream & operator<<(std::ostream&, const IDMap&);
};


class SandboxIDMap
{
private:
    // builder user's primary UID and GID.
    IDMapping primaryUID = { .type = IDMapping::Type::User };
    IDMapping primaryGID = { .type = IDMapping::Type::Group };

    // Builder namespace ID maps.
    IDMap primaryIDMap;

    // Whether or not supplementary groups should be set. If false sup groups
    // are emptied.
    bool useSupplementaryGroups = false;

    // Host GID -> Sandbox GID
    std::map<gid_t, gid_t> supplementaryGIDs = {};

    // group names inside sandbox
    std::map<gid_t, std::string> groupNames = {
        { 0, "root" },
        { IDMapping::UNSET, "nixbld" }, // Substituted with primaryGID
        { 65534, "nogroup" },
    };

    /**
     * User namespace FDs for idmapped mounts. We store each unique map
     * definition for re-use (creating an idmapping fd requires us to
     * setup a whole new user namespace).
     */
    std::map<IDMap::Set, AutoCloseFD> userNamespaceFDs = {};
public:
    /**
     * Set the primary UID/GID mapping.
     */
    void setPrimaryIDs(const uid_t, const gid_t);
    void setPrimaryHostIDs(const uid_t, const gid_t);

    /** Format minimal /etc/groups for the sandbox */
    void write_etc_groups(const Path &) const;
    void write_etc_passwd(const Path &, const Path & sandboxBuildDir) const;
    void write_userns_map(pid_t) const;

    /** Get the host-side GIDs that should be assigned with setgroups() */
    std::vector<gid_t> supplementaryHostGIDs() const;

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
     * unmapped GIDs get mapped to (including root).
     *
     * Use: settings.supplementaryGroups.get() */
    void addSupplementaryGroups(const StringSet);

    /**
     * IDMapped mounts' ID maps are separate from the build sandbox's
     * usernamespace by default. But for convenience the maps of id-mapped
     * mounts are recreated in the builder process namespace when it does not
     * overlap with any explicitly declared mapping. */
    void recordMountIDMap(IDMap::Set map);

    /**
     * Recover or create usernamespace fd for idmapping.
     */
    int getIDMapUserNsFd(IDMap::Set);

};
}
