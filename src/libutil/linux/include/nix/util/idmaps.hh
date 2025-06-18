#pragma once
#include "nix/util/util.hh"
#include "nix/util/sync.hh"
#include <sys/mount.h>

namespace nix {

/**
 * Makes an ID-mapping bind mount.
 *
 * mount(2) does not support ID mapping. We need to use the new
 * mount_setattr(2) syscall API and also open_tree() and move_mount().
 * None of those have wrappers, yet.
 **/
// XXX take SandboxPath instead
void bindMountWithIDMap(
    const Path & source,
    const Path & target,
    int userns_fd = -1,
    bool optional = false,
    bool readOnly = false);

struct IDMapping
{
    enum class Type : char {
        User = 'u',
        Group = 'g',
        Both = 'b',
    };

    Type type;
    id_t mapped_id = UNSET, host_id = UNSET;
    unsigned int range = 1;

    // 0 is as valid ID as any but not the safest default
    static inline constexpr id_t UNSET = static_cast<id_t>(-1);
    static inline constexpr char TypeSep = '=';
    static inline constexpr char ValueSep[] = "-";

    /* kernel only takes up to 4k in size or 340 in number of entries written
     * into uid_map/gid_map */
    static inline constexpr size_t IDMAP_MAX_SIZE = 4096;
    static inline constexpr uint64_t IDMAP_LIMIT = 340;

    std::string to_map_line() const;
    bool operator<(const IDMapping & other) const;
    bool overlaps_with(const IDMapping & other) const;
    bool overlaps_with_any(auto maps) const;

    friend std::ostream & operator<<(std::ostream&, const Type&);
    friend std::ostream & operator<<(std::ostream&, const IDMapping&);

    static Type parse_type(const char);
    static IDMapping parse(const std::string&);

    static bool contains(const Type, const Type);

    bool contains(const Type) const;
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

    static Set parse_maps(const std::string&);

    void add_explicit(const IDMapping & map);
    void add_explicit(const std::string & map);

    void add_fallback(const IDMapping & map);
    void add_fallback(const std::string & map);

    std::vector<IDMapping> collect(const IDMapping::Type type) const;
    Set collectBoth() const;

    void transform(const IDMapping::Type type, id_t from, id_t to);

    int createUsernamespace() const;
};

/**
 * Like ChrootPath in nixstore but with additional fields.
 * TODO: replace with SandboxPath
 */
struct IDMappedChrootPath
{
    Path source = "";
    bool optional = false;
    bool readOnly = false;
    IDMap::Set idmap = {};
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

class SandboxIDMap
{
private:
    // builder user's primary UID and GID.
    IDMapping primaryUID, primaryGID;

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

    std::map<Path,IDMappedChrootPath> idmappedChrootPaths = {};

    /**
     * User namespace FDs for idmapped mounts. We store each unique map
     * definition for re-use (creating an idmapping fd requires us to
     * setup a whole new user namespace).
     */
    std::map<IDMap::Set, AutoCloseFD> userNamespaceFDs = {};
public:

    void setPrimaryIDs(uid_t uid, gid_t gid, uid_t, gid_t, id_t nrids = 1);

    /** Format minimal /etc/groups for the sandbox */
    void write_etc_groups(const Path &) const;
    void write_etc_passwd(const Path & out, const Path & sandboxBuildDir) const;
    void write_userns_map(pid_t pid) const;

    /** Get the host-side GIDs that should be assigned with setgroups() */
    std::vector<gid_t> supplementaryHostGIDs() const;

    void addSupplementaryGroups(const StringSet);

    void add_sandbox_path_handler_side(const Path &, const IDMappedChrootPath &, const Path &, int mountNsFd);

    void recordMountIDMap(IDMap::Set map);
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
        // XXX moved
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
        IDMap idmapper;

        /**
         * User namespace FDs for idmapped mounts. We store each unique map
         * definition for re-use (creating an idmapping fd requires us to
         * setup a whole new user namespace).
         */
        std::map<IDMap::Set, AutoCloseFD> userNamespaceFDs = {};

        /**
         * ID-mapped chroot paths. Keyed by the target path.
         */
        std::map<Path, IDMappedChrootPath> chrootPaths;

        /**
         * Chroot root directory outside the sandbox
         */
        Path chrootRootDir;
    };

    Sync<NS_State> state_;

    //void update(std::function<void(NS_State &)>);

    /**
     * Mount the specified sandbox path in the build sandbox.
     * Supports ID-mapping.
     */
    void setupSandboxPathHandlerSide(const Path & target);

    void addChrootPathsWithIDMap(std::map<Path, IDMappedChrootPath>);

    /** Format minimal /etc/passwd for the sandbox */
    //void createUsersPasswdContent(const Path &, const Path &);

    /**
     * Interprets the supplementary-groups option from a config.
     */
    //void setupSupplementaryGroups(const StringSet);

    /**
     * The groups that should be assigned via setgroups()
     */
    //std::vector<gid_t> getSupplementarySetGroups();

    /** Write setgroups, uid_map and gid_map from parent process for a child
     * (pid) */
    //void writeProcessIDMapFiles(pid_t);

    /** Format minimal /etc/groups for the sandbox */
    //void createGroupsContent(const Path &);
};
}
