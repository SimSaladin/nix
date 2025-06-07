#pragma once
///@file

#include "nix/util/util.hh"
// #include "nix/util/types.hh"

// #include <sys/types.h>

/* kernel only takes up to 4k in size or 340 in number of entries written
 * into uid_map/gid_map */
#define IDMAP_MAX_SIZE 4096
#define IDMAP_LIMIT 340

namespace nix {

enum class IDMapType : char
{
    UID = 'u',
    GID = 'g'
};

std::ostream & operator << (std::ostream & os, const IDMapType & t);

struct IDMapping
{
    IDMapType type;
    id_t mapped_id = UNSET, host_id = UNSET;
    unsigned int range = 1;

    // 0 is as valid ID as any but not the safest default
    static constexpr id_t UNSET = static_cast<id_t>(-1);
    static constexpr char TypeSep = '=';
    static constexpr char ValueSep[] = "-";

    std::string to_map_line() const {
        assert(range > 0);
        return fmt("%d %d %d", mapped_id, host_id, range);
    }

    bool operator<(const IDMapping & other) const;

    bool overlaps_with(const IDMapping & other) const;

    friend std::ostream & operator << (std::ostream & os, const IDMapping & m);
};

typedef std::set<IDMapping> IDMappings;

class IDMapper
{
    IDMappings explicit_maps, fallback_maps;
public:
    IDMapper() {};
    IDMapper(const std::string & expl);

    void add_explicit(const IDMapping & map);
    void add_explicit(const std::string & map);

    void add_fallback(const IDMapping & map);
    void add_fallback(const std::string & map);

    std::vector<IDMapping> collect(IDMapType type) const;

    void transform(IDMapType type, id_t from, id_t to);
};

/**
 * Makes an ID-mapping bind mount.
 *
 * mount(2) does not support ID mapping. We need to use the new
 * mount_setattr(2) syscall API and also open_tree() and move_mount().
 * None of those have wrappers, yet.
 **/
void bindMountWithIDMap(const Path & source, const Path & target,
        int userns_fd = -1, bool optional = false, bool rdonly = false);

/**
 * Id maps are specified in syntax:
 *
 *      <type>=<mapped>[-<host>[-<range>]]
 *
 * - `type` is one of `u` for UID or `g` for GID.
 * - `mapped` is the beginning of the ID range inside the sandbox.
 * - `host` is start of outside IDs. Same as mapped if only one number is given.
 * - `range` is the number of IDs in the range. Default and min. is 1.
 */
int createUsernamespaceWithMappings(const std::string & mappings_str, uid_t suid, gid_t sgid);

void writeIDMapFile(const Path & filepath, const std::vector<IDMapping> & mappings, IDMapType type);

}
