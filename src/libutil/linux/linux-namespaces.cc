#include "nix/util/linux-namespaces.hh"
#include "nix/util/current-process.hh"
#include "nix/util/util.hh"
#include "nix/util/finally.hh"
#include "nix/util/file-system.hh"
#include "nix/util/processes.hh"
#include "nix/util/signals.hh"

#include <mutex>
#include <sys/resource.h>
#include "nix/util/cgroup.hh"

#include <sys/mount.h>
#include <fstream>

namespace nix {

bool userNamespacesSupported()
{
    static auto res = [&]() -> bool
    {
        if (!pathExists("/proc/self/ns/user")) {
            debug("'/proc/self/ns/user' does not exist; your kernel was likely built without CONFIG_USER_NS=y");
            return false;
        }

        Path maxUserNamespaces = "/proc/sys/user/max_user_namespaces";
        if (!pathExists(maxUserNamespaces) ||
            trim(readFile(maxUserNamespaces)) == "0")
        {
            debug("user namespaces appear to be disabled; check '/proc/sys/user/max_user_namespaces'");
            return false;
        }

        Path procSysKernelUnprivilegedUsernsClone = "/proc/sys/kernel/unprivileged_userns_clone";
        if (pathExists(procSysKernelUnprivilegedUsernsClone)
            && trim(readFile(procSysKernelUnprivilegedUsernsClone)) == "0")
        {
            debug("user namespaces appear to be disabled; check '/proc/sys/kernel/unprivileged_userns_clone'");
            return false;
        }

        try {
            Pid pid = startProcess([&]()
            {
                _exit(0);
            }, {
                .cloneFlags = CLONE_NEWUSER
            });

            auto r = pid.wait();
            assert(!r);
        } catch (SysError & e) {
            debug("user namespaces do not work on this system: %s", e.msg());
            return false;
        }

        return true;
    }();
    return res;
}

bool mountAndPidNamespacesSupported()
{
    static auto res = [&]() -> bool
    {
        try {

            Pid pid = startProcess([&]()
            {
                /* Make sure we don't remount the parent's /proc. */
                if (mount(0, "/", 0, MS_PRIVATE | MS_REC, 0) == -1)
                    _exit(1);

                /* Test whether we can remount /proc. The kernel disallows
                   this if /proc is not fully visible, i.e. if there are
                   filesystems mounted on top of files inside /proc.  See
                   https://lore.kernel.org/lkml/87tvsrjai0.fsf@xmission.com/T/. */
                if (mount("none", "/proc", "proc", 0, 0) == -1)
                    _exit(2);

                _exit(0);
            }, {
                .cloneFlags = CLONE_NEWNS | CLONE_NEWPID | (userNamespacesSupported() ? CLONE_NEWUSER : 0)
            });

            if (pid.wait()) {
                debug("PID namespaces do not work on this system: cannot remount /proc");
                return false;
            }

        } catch (SysError & e) {
            debug("mount namespaces do not work on this system: %s", e.msg());
            return false;
        }

        return true;
    }();
    return res;
}


//////////////////////////////////////////////////////////////////////

static AutoCloseFD fdSavedMountNamespace;
static AutoCloseFD fdSavedRoot;

void saveMountNamespace()
{
    static std::once_flag done;
    std::call_once(done, []() {
        fdSavedMountNamespace = open("/proc/self/ns/mnt", O_RDONLY);
        if (!fdSavedMountNamespace)
            throw SysError("saving parent mount namespace");

        fdSavedRoot = open("/proc/self/root", O_RDONLY);
    });
}

void restoreMountNamespace()
{
    try {
        auto savedCwd = std::filesystem::current_path();

        if (fdSavedMountNamespace && setns(fdSavedMountNamespace.get(), CLONE_NEWNS) == -1)
            throw SysError("restoring parent mount namespace");

        if (fdSavedRoot) {
            if (fchdir(fdSavedRoot.get()))
                throw SysError("chdir into saved root");
            if (chroot("."))
                throw SysError("chroot into saved root");
        }

        if (chdir(savedCwd.c_str()) == -1)
            throw SysError("restoring cwd");
    } catch (Error & e) {
        debug(e.msg());
    }
}

void tryUnshareFilesystem()
{
    if (unshare(CLONE_FS) != 0 && errno != EPERM && errno != ENOSYS)
        throw SysError("unsharing filesystem state");
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
        case 'g': mapping.type = IDMapType::GID; break;
        case 'u': mapping.type = IDMapType::UID; break;
        default: throw Error("Unknown ID mapping type: " + str[0]);
    };

    mapping.mapped_id = std::stoi(parts[0]);
    mapping.host_id = parts.size() >= 2 ? std::stoi(parts[1]) : mapping.mapped_id;
    mapping.range = parts.size() >= 3 ? std::stoi(parts[2]) : 1;

    return mapping;
}

void writeIDMapFile(const std::string & filepath, const std::vector<IDMapping> & mappings, IDMapType type)
{
    int entries = 0;
    std::ostringstream oss;
    for (const auto & mapping : mappings)
        if (mapping.type == type) {
            oss << mapping.to_map_line();
            ++entries;
        }
    if (entries > MAX_IDMAP_LINES)
        throw Error("Too many mappings (>%d)", MAX_IDMAP_LINES);

    /* TODO does there need to be defaults?
    if (entries == 0) oss << "100000 0 65534"; */

    std::string content = oss.str();
    if (content.size() > MAX_IDMAP_LEN)
        throw Error("Size of ID map exceeds the 4K length limit for '%s'", filepath);

    std::ofstream file(filepath);
    if (!file.is_open())
        throw SysError("open %s", filepath);
    file << content;
    if (!file)
        throw SysError("write %s", filepath);
}

int createUsernamespaceWithMappings(const std::string & str)
{
    if (str.empty()) return -1;

    debug("setting up user namespace for ID-mapping: '%s'", str);

    std::vector<IDMapping> mappings;
    for (auto line : splitString<Strings>(str, ","))
        mappings.push_back(parseIDMapping(line));

    Pipe syncPipe, exitPipe;
    syncPipe.create();
    exitPipe.create();
    Pid pid(startProcess([&]()
    {
        try {
            syncPipe.readSide.close();
            if (unshare(CLONE_NEWUSER) == -1)
                throw SysError("unshare(CLONE_NEWUSER): new user ns for idmap");
            writeLine(syncPipe.writeSide.get(), "1");
            debug("unshare(CLONE_NEWUSER) was successful, waiting for parent to write ID maps");
            readLine(exitPipe.readSide.get(), true);
        } catch (...) {
            writeLine(syncPipe.writeSide.get(), "0");
            syncPipe.writeSide.close();
            _exit(1);
        }
        _exit(0);
    }, { .cloneFlags = SIGCHLD }));

    syncPipe.writeSide.close();
    exitPipe.readSide = -1;

    Finally cleanup([&]() { exitPipe.writeSide = -1; });

    if (readLine(syncPipe.readSide.get(), true) != "1")
        throw Error("Unexpected response from child process");

    writeFile(fmt("/proc/%d/setgroups", (pid_t)pid), "deny");
    writeIDMapFile(fmt("/proc/%d/uid_map", (pid_t)pid), mappings, IDMapType::UID);
    writeIDMapFile(fmt("/proc/%d/gid_map", (pid_t)pid), mappings, IDMapType::GID);

    debug("Wrote ID maps, opening USER ns of PID=%d", (pid_t)pid);

    int userFd = open(fmt("/proc/%d/ns/user", (pid_t)pid), O_RDONLY | O_NOCTTY);
    if (userFd < 0)
        throw SysError("open(userFd)");
    debug("ID map USER namespace Fd=%d", userFd);

    writeFull(exitPipe.writeSide.get(), "X\n"); // Signal child to exit
    exitPipe.writeSide.close();
    if (pid.wait() != 0)
        throw Error("idmap: process did not exit gracefully");
    if (fcntl(userFd, F_GETFD) == -1)
        throw SysError("fcntl(userFd)");
    return userFd;
}

void bindMountWithIDMap(const Path & source, const Path & target,
        int idmap_fd, bool rdonly)
{
    debug("bind mounting ID-mapped '%s' to '%s' with userns=%d",
            source, target, idmap_fd);

    // TODO do we need to handle source is file/symlink differently?
    createDirs(target);

    int treefd = open_tree(-1, source.c_str(), OPEN_TREE_CLONE |
            OPEN_TREE_CLOEXEC | AT_RECURSIVE);
    if (treefd == -1)
        throw SysError("open_tree: %s", source);

    mount_attr attr = {
        .attr_set = rdonly ? MOUNT_ATTR_RDONLY : static_cast<uint64_t>(0),
        .propagation = MS_PRIVATE,
    };

    if (idmap_fd > 0) {
        attr.attr_set |= MOUNT_ATTR_IDMAP;
        attr.userns_fd = static_cast<uint64_t>(idmap_fd); // FD's are int, except when ABI compatibility requires otherwise
    }

    if (mount_setattr(treefd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(struct mount_attr)) == -1)
        throw SysError("mount_setattr: '%s'", source);

    /* TODO the same namespace fd might be used for multiple mappings
    if (attr.userns_fd >= 0)
        close(attr.userns_fd); */

    if (move_mount(treefd, "", -1, target.c_str(), MOVE_MOUNT_F_EMPTY_PATH) == -1)
        throw SysError("move_mount: '%s'", source);

    close(treefd);
}

/*
 * Syscall wrappers for new mount features in Linux 5.2+.
 */
static inline int open_tree(int dfd, char * path, unsigned int flags = 0)
{
    return syscall(SYS_open_tree, dfd, path, flags);
}

static inline int mount_setattr(int dfd, char * path, unsigned int flags = 0,
        struct mount_attr * uattr = &(struct mount_attr){},
        size_t usize = sizeof(struct mount_attr))
{
    return syscall(SYS_mount_setattr, dfd, path, flags, uattr, usize);
}

static inline int move_mount(int dfd_from, const char * path_from,
        int dfd_to, const char * path_to, unsigned int flags = 0)
{
    return syscall(SYS_move_mount, dfd_from, path_from, dfd_to, path_to, flags);
}
}
