#pragma once
#include "nix/util/util.hh"
#include "nix/util/sync.hh"
#include <sys/mount.h>

namespace nix {

/* kernel only takes up to 4k in size or 340 in number of entries written
 * into uid_map/gid_map */
static inline constexpr size_t IDMAP_MAX_SIZE = 4096;
static inline constexpr uint64_t IDMAP_LIMIT = 340;

enum class IDMapType : char { UID = 'u', GID = 'g' };
std::ostream & operator<<(std::ostream & os, const IDMapType & t);

struct IDMapping
{
    IDMapType type;
    id_t mapped_id = UNSET, host_id = UNSET;
    unsigned int range = 1;

    // 0 is as valid ID as any but not the safest default
    static constexpr id_t UNSET = static_cast<id_t>(-1);
    static constexpr char TypeSep = '=';
    static constexpr char ValueSep[] = "-";

    std::string to_map_line() const;
    bool operator<(const IDMapping & other) const;
    bool overlaps_with(const IDMapping & other) const;
    friend std::ostream & operator<<(std::ostream & os, const IDMapping & m);
};

typedef std::set<IDMapping> IDMappings;

IDMappings parseIDMappingsList(const std::string & maps);

class IDMapper
{
    IDMappings explicit_maps, fallback_maps;
public:
    IDMapper() {};
    IDMapper(const IDMappings & expl);
    IDMapper(const std::string & expl);
    void add_explicit(const IDMapping & map);
    void add_explicit(const std::string & map);
    void add_fallback(const IDMapping & map);
    void add_fallback(const std::string & map);
    void transform(IDMapType type, id_t from, id_t to);
    std::vector<IDMapping> collect(IDMapType type) const;
    IDMappings collectBoth() const;
};

/**
 * Like ChrootPath in nixstore but with additional fields.
 * TODO: replace with SandboxPath
 */
struct IDMappedChrootPath
{
    Path source = "";
    bool optional = false;
    bool rdonly = false;
    IDMappings idmap = {};
    /* Mount-point flags:
     * - MS_NODEV
     * - MS_NOEXEC
     * - MS_NOSUID
     * - one of: MS_NOATIME | MS_NODIRATIME | MS_RELATIME
     * - MS_RDONLY (technically mountpoint and superblock option) */
    unsigned int mpflags = 0;
    /* SHARED | PRIVATE | SLAVE UNBINDABLE */
    unsigned int propagation = MS_SLAVE;
};

/**
 * When namespaces are used as a privileged user, setting up some features
 * of the build sandbox use this utility context to make changes to the
 * sandbox by manipulating it from the outside after having entered
 * the restricted namespaces already. (ID-mapped mounts in particular
 * almost require this escape hatch.) Should only ever be available during
 * the scaffolding before a build is started!
 */
class UserMountNSHelper
{
public:
    struct NS_State
    {
        /**
         * build user's primary UID and GID (container + host).
         *
         * Note: ought to take precedence over any other preference set in
         * "idmap".
         */
        IDMapping builderPrimaryUID, builderPrimaryGID;

        /**
         * Whether supplementary groups are to be used. If false we try to
         * drop any existing groups instead.
         */
        bool useSupplementaryGroups = false;

        /**
         * Build user's supplementary GIDs (sandbox - host)
         */
        std::map<gid_t, gid_t> supplementaryGIDs;

        std::map<gid_t, std::string> supplementaryGroupNames;

        /**
         * FD for the main sandbox mount namespace.
         */
        int mountNsFd = -1;

        /**
         * Sandbox default uid & gid maps
         */
        IDMapper idmapper;

        /**
         * ID-mapped chroot paths. Keyed by the target path.
         */
        std::map<Path, IDMappedChrootPath> chrootPaths;

        /**
         * User namespace FDs for idmapped mounts. We store each unique map
         * definition for re-use (creating an idmapping fd requires us to
         * setup a whole new user namespace).
         */
        std::map<IDMappings, AutoCloseFD> chrootPathNamespaceFds;

        /**
         * Chroot root directory outside the sandbox
         */
        Path chrootRootDir;
    };

    Sync<NS_State> state_;

    void update(std::function<void(NS_State &)>);

    /**
     * Mount the specified sandbox path in the build sandbox.
     * Supports ID-mapping.
     */
    void setupSandboxPathHandlerSide(const Path & target);

    /**
     * Interprets the supplementary-groups option from a config.
     */
    void setupSupplementaryGroups(const StringSet);

    /**
     * The groups that should be assigned via setgroups()
     */
    std::vector<gid_t> getSupplementarySetGroups();

    /** Write setgroups, uid_map and gid_map from parent process for a child
     * (pid) */
    void writeProcessIDMapFiles(pid_t);

    void addChrootPathsWithIDMap(std::map<Path, IDMappedChrootPath>);

    /** Format minimal /etc/passwd for the sandbox */
    void createUsersPasswdContent(const Path &, const Path &);

    /** Format minimal /etc/groups for the sandbox */
    void createGroupsContent(const Path &);
};

/**
 * Makes an ID-mapping bind mount.
 *
 * mount(2) does not support ID mapping. We need to use the new
 * mount_setattr(2) syscall API and also open_tree() and move_mount().
 * None of those have wrappers, yet.
 **/
void bindMountWithIDMap(
    const Path & source, const Path & target, int userns_fd = -1, bool optional = false, bool rdonly = false);

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

int createUsernamespaceWithMappings(const IDMapper & maps);

void writeIDMapFile(const Path & filepath, const std::vector<IDMapping> & mappings, IDMapType type);

}
