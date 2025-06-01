#pragma once
///@file

#include <optional>

#include "nix/util/types.hh"
#include "nix/util/error.hh"

namespace nix {

/* kernel only takes up to 4k in size or 340 in number of entries written
 * into uid_map/gid_map */
#define IDMAP_MAX_SIZE 4096
#define IDMAP_LIMIT 340

enum class IDMapType : char {
    UID = 'u',
    GID = 'g'
};

struct IDMapping {
    IDMapType type;
    unsigned int mapped_id = UNSET;
    unsigned int host_id = UNSET;
    unsigned int range = 1;

    // 0 is as valid ID as any but not the safest default
    static constexpr unsigned int UNSET = static_cast<unsigned int>(-1);
    static constexpr char TypeSep = '=';
    static constexpr char ValueSep[] = "-";
    std::string to_map_line() const {
        return fmt("%d %d %d\n", mapped_id, host_id, range);
    }
};

/**
 * Save the current mount namespace. Ignored if called more than
 * once.
 */
void saveMountNamespace();

/**
 * Restore the mount namespace saved by saveMountNamespace(). Ignored
 * if saveMountNamespace() was never called.
 */
void restoreMountNamespace();

/**
 * Cause this thread to try to not share any FS attributes with the main
 * thread, because this causes setns() in restoreMountNamespace() to
 * fail.
 *
 * This is best effort -- EPERM and ENOSYS failures are just ignored.
 */
void tryUnshareFilesystem();

bool userNamespacesSupported();

bool mountAndPidNamespacesSupported();

/**
 * Makes an ID-mapping bind mount.
 *
 * mount(2) does not support ID mapping. We need to use the new
 * mount_setattr(2) syscall API and also open_tree() and move_mount().
 * None of those have wrappers, yet.
 **/
void bindMountWithIDMap( const Path & source, const Path & target,
        int idmap_fd = -1, bool rdonly = false);

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
int createUsernamespaceWithMappings(const std::string & mappings_str);

}
