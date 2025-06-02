#ifdef __linux__

#  include "nix/store/personality.hh"
#  include "nix/util/cgroup.hh"
#  include "nix/util/linux-namespaces.hh"
#  include "linux/fchmodat2-compat.hh"

#  include <sys/ioctl.h>
#  include <net/if.h>
#  include <netinet/ip.h>
#  include <sys/mman.h>
#  include <sched.h>
#  include <sys/param.h>
#  include <sys/mount.h>
#  include <sys/syscall.h>

#  if HAVE_SECCOMP
#    include <seccomp.h>
#  endif

#  define pivot_root(new_root, put_old) (syscall(SYS_pivot_root, new_root, put_old))

namespace nix {

static void setupSeccomp()
{
    if (!settings.filterSyscalls)
        return;

#  if HAVE_SECCOMP
    scmp_filter_ctx ctx;

    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)))
        throw SysError("unable to initialize seccomp mode 2");

    Finally cleanup([&]() { seccomp_release(ctx); });

    constexpr std::string_view nativeSystem = NIX_LOCAL_SYSTEM;

    if (nativeSystem == "x86_64-linux" && seccomp_arch_add(ctx, SCMP_ARCH_X86) != 0)
        throw SysError("unable to add 32-bit seccomp architecture");

    if (nativeSystem == "x86_64-linux" && seccomp_arch_add(ctx, SCMP_ARCH_X32) != 0)
        throw SysError("unable to add X32 seccomp architecture");

    if (nativeSystem == "aarch64-linux" && seccomp_arch_add(ctx, SCMP_ARCH_ARM) != 0)
        printError(
            "unable to add ARM seccomp architecture; this may result in spurious build failures if running 32-bit ARM processes");

    if (nativeSystem == "mips64-linux" && seccomp_arch_add(ctx, SCMP_ARCH_MIPS) != 0)
        printError("unable to add mips seccomp architecture");

    if (nativeSystem == "mips64-linux" && seccomp_arch_add(ctx, SCMP_ARCH_MIPS64N32) != 0)
        printError("unable to add mips64-*abin32 seccomp architecture");

    if (nativeSystem == "mips64el-linux" && seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL) != 0)
        printError("unable to add mipsel seccomp architecture");

    if (nativeSystem == "mips64el-linux" && seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL64N32) != 0)
        printError("unable to add mips64el-*abin32 seccomp architecture");

    /* Prevent builders from creating setuid/setgid binaries. */
    for (int perm : {S_ISUID, S_ISGID}) {
        if (seccomp_rule_add(
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                SCMP_SYS(chmod),
                1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, (scmp_datum_t) perm, (scmp_datum_t) perm))
            != 0)
            throw SysError("unable to add seccomp rule");

        if (seccomp_rule_add(
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                SCMP_SYS(fchmod),
                1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, (scmp_datum_t) perm, (scmp_datum_t) perm))
            != 0)
            throw SysError("unable to add seccomp rule");

        if (seccomp_rule_add(
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                SCMP_SYS(fchmodat),
                1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, (scmp_datum_t) perm, (scmp_datum_t) perm))
            != 0)
            throw SysError("unable to add seccomp rule");

        if (seccomp_rule_add(
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                NIX_SYSCALL_FCHMODAT2,
                1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, (scmp_datum_t) perm, (scmp_datum_t) perm))
            != 0)
            throw SysError("unable to add seccomp rule");
    }

    /* Prevent builders from using EAs or ACLs. Not all filesystems
       support these, and they're not allowed in the Nix store because
       they're not representable in the NAR serialisation. */
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(getxattr), 0) != 0
        || seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(lgetxattr), 0) != 0
        || seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fgetxattr), 0) != 0
        || seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(setxattr), 0) != 0
        || seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(lsetxattr), 0) != 0
        || seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fsetxattr), 0) != 0)
        throw SysError("unable to add seccomp rule");

    if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, settings.allowNewPrivileges ? 0 : 1) != 0)
        throw SysError("unable to set 'no new privileges' seccomp attribute");

    if (seccomp_load(ctx) != 0)
        throw SysError("unable to load seccomp BPF program");
#  else
    throw Error(
        "seccomp is not supported on this platform; "
        "you can bypass this error by setting the option 'filter-syscalls' to false, but note that untrusted builds can then create setuid binaries!");
#  endif
}

static void doBind(const Path & source, const Path & target, bool optional = false, bool rdonly = false)
{
    debug("bind mounting '%1%' to '%2%'", source, target);

    auto bindMount = [&]() {
        if (mount(source.c_str(), target.c_str(), "", MS_BIND | MS_REC, 0) == -1)
            throw SysError("bind mount from '%1%' to '%2%' failed", source, target);

        if (rdonly)
            // initial mount wouldn't respect MS_RDONLY, must remount
            if (mount("", target.c_str(), "", MS_REMOUNT | MS_BIND | MS_RDONLY, 0) == -1)
                throw (SysError("making bind mount '%s' read-only failed", target));
    };

    auto maybeSt = maybeLstat(source);
    if (!maybeSt) {
        if (optional)
            return;
        else
            throw SysError("getting attributes of path '%1%'", source);
    }
    auto st = *maybeSt;

    if (S_ISDIR(st.st_mode)) {
        createDirs(target);
        bindMount();
    } else if (S_ISLNK(st.st_mode)) {
        // Symlinks can (apparently) not be bind-mounted, so just copy it
        createDirs(dirOf(target));
        copyFile(std::filesystem::path(source), std::filesystem::path(target), false);
    } else {
        createDirs(dirOf(target));
        writeFile(target, "");
        bindMount();
    }
}

struct LinuxDerivationBuilder : DerivationBuilderImpl
{
    using DerivationBuilderImpl::DerivationBuilderImpl;

    void enterChroot() override
    {
        setupSeccomp();

        linux::setPersonality(drv.platform);
    }
};

struct ChrootLinuxDerivationBuilder : LinuxDerivationBuilder
{
    /**
     * Pipe for synchronising updates to the builder namespaces / from the
     * namespace.
     */
    Pipe userNamespaceSync;
    Pipe builderSync;

    /**
     * The mount namespace and user namespace of the builder, used to add additional
     * paths to the sandbox as a result of recursive Nix calls.
     */
    AutoCloseFD sandboxMountNamespace;
    AutoCloseFD sandboxUserNamespace;

    /**
     * On Linux, whether we're doing the build in its own user
     * namespace.
     */
    bool usingUserNamespace = true;

    /**
     * The root of the chroot environment.
     */
    Path chrootRootDir;

    /**
     * RAII object to delete the chroot directory.
     */
    std::shared_ptr<AutoDelete> autoDelChroot;

    PathsInChroot pathsInChroot;

    std::unordered_map<std::string, int> mountIDMapNamespaces;

    /**
     * The cgroup of the builder, if any.
     */
    std::optional<Path> cgroup;

    using LinuxDerivationBuilder::LinuxDerivationBuilder;

    void deleteTmpDir(bool force) override
    {
        autoDelChroot.reset(); /* this runs the destructor */

        DerivationBuilderImpl::deleteTmpDir(force);
    }

    uid_t sandboxUid()
    {
        return usingUserNamespace ? (!buildUser || buildUser->getUIDCount() == 1 ? 1000 : 0) : buildUser->getUID();
    }

    gid_t sandboxGid()
    {
        return usingUserNamespace ? (!buildUser || buildUser->getUIDCount() == 1 ? 100 : 0) : buildUser->getGID();
    }

    bool setSupplementaryGroups;

    /**
     * Return parent_gid -> (mapped_gid, mapped_name)
     *
     * Keys are host/parent gid's (can't have duplicates obviously). Values
     * are the mapped/target (gid, name) pairs. Each mapped gid (name) may
     * only appear once in the result.
     *
     * TODO this should interact with ID-mapped mounts, because ID-mapped
     * mounts aren't really useful unless the IDs that are mapped by ID-mapped
     * mounts are also mapped in the user namespace.
     */
    std::map<gid_t, std::tuple<gid_t, std::string>> getSupplementaryGIDMap()
    {
        // Primary GID (sandboxGid) is always mapped and it would make no
        // sense to assign as a supplementary group as well.
        //
        // It would be technically harmless to allow mapping and assigning 0,
        // aside from some potential confusion. It's only disallowed here
        // because the root group is declared always anyway. Allowing it here
        // would result in a duplicate /etc/group entry.
        //
        // Allowing assigning nogroup 65534 would be very bad, especially if
        // root 0 wasn't mapped, as it's the fallback group to which all
        // unmapped GIDs get mapped to (including root).
        std::vector<gid_t> reserved_gids = {sandboxGid(), 0, 65534};
        std::vector<std::string> reserved_names = {"root", "nixbld", "nogroup"};

        std::map<gid_t, std::tuple<gid_t, std::string>> gid_map;

        struct group grp;
        struct group * gr = nullptr;
        long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize == -1) bufsize = 16384;
        std::vector<char> buffer(bufsize);

        for (const auto & group_entry : settings.supplementaryGroups.get()) {
            std::string group_name = group_entry;
            std::optional<gid_t> mapped_gid;

            // parse "name[:gid]"
            auto pos = group_entry.find(":");
            if (pos != std::string::npos) {
                std::string gid_str = group_entry.substr(pos + 1);
                group_name = group_entry.substr(0, pos);
                try {
                    mapped_gid = static_cast<gid_t>(std::stoul(gid_str));
                } catch (...) {
                    throw Error("Invalid GID number in '%s'", gid_str);
                }
            }

            int ret = getgrnam_r(group_name.c_str(), &grp, buffer.data(), buffer.size(), &gr);
            if (ret != 0)
                throw Error("getgrnam_r failed for group '%s': %s", group_name, strerror(ret));
            if (!gr) {
                debug("Supplementary group '%s' not found", group_name);
                continue;
            }

            // host GID sanity checks
            gid_t parent_gid = gr->gr_gid;
            if (parent_gid == 0)
                throw Error("Group '%s': mapping the root group (GID 0) is not a good idea", group_name);
            if (gid_map.contains(parent_gid))
                throw Error("Group '%s': parent GID %d is already mapped", group_name, parent_gid);

            /* Mapped GID sanity checks

               65535 is the special invalid/overflow GID distinct from
               nogroup. We don't want to allow that.

               2^16 and above are not allowed because it would seem impossible
               to assign them. In a quick test higher GIDs got truncated to
               65534. Might have something to do with how we're forced to call
               setgroups before setting up the namespace. */
            if (!mapped_gid)
                mapped_gid = parent_gid;
            if (mapped_gid > 65534)
                throw Error("Group '%s': mapped GID %d is too large (>65534)", group_name, mapped_gid.value());
            if (std::find(reserved_gids.begin(), reserved_gids.end(), mapped_gid.value()) != reserved_gids.end())
                throw Error("Group '%s': mapped GID %d conflicts with reserved GID", group_name, mapped_gid.value());

            // mapped name sanity checks
            std::string mapped_name = gr->gr_name;
            if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
                mapped_name += "-host";
                debug("Group '%s': name conflicts with reserved name; renaming to '%s'", group_name, mapped_name);
                if (std::find(reserved_names.begin(), reserved_names.end(), mapped_name) != reserved_names.end()) {
                    warn("Group '%s': original and alternative name '%s' both conflict with reserved names; skipping this group", group_name, mapped_name);
                    continue;
                }
            }

            gid_map[parent_gid] = std::make_tuple(mapped_gid.value(), std::move(mapped_name));
            reserved_gids.push_back(mapped_gid.value());
            reserved_names.push_back(std::get<1>(gid_map[parent_gid]));
        }

        return gid_map;
    }

    bool needsHashRewrite() override
    {
        return false;
    }

    std::unique_ptr<UserLock> getBuildUser() override
    {
        return acquireUserLock(drvOptions.useUidRange(drv) ? 65536 : 1, true);
    }

    void setBuildTmpDir() override
    {
        /* If sandboxing is enabled, put the actual TMPDIR underneath
           an inaccessible root-owned directory, to prevent outside
           access.

           On macOS, we don't use an actual chroot, so this isn't
           possible. Any mitigation along these lines would have to be
           done directly in the sandbox profile. */
        tmpDir = topTmpDir + "/build";
        createDir(tmpDir, 0700);
    }

    Path tmpDirInSandbox() override
    {
        /* In a sandbox, for determinism, always use the same temporary
           directory. */
        return settings.sandboxBuildDir;
    }

    void prepareUser() override
    {
        if ((buildUser && buildUser->getUIDCount() != 1) || settings.useCgroups) {
            experimentalFeatureSettings.require(Xp::Cgroups);

            /* If we're running from the daemon, then this will return the
               root cgroup of the service. Otherwise, it will return the
               current cgroup. */
            auto rootCgroup = getRootCgroup();
            auto cgroupFS = getCgroupFS();
            if (!cgroupFS)
                throw Error("cannot determine the cgroups file system");
            auto rootCgroupPath = canonPath(*cgroupFS + "/" + rootCgroup);
            if (!pathExists(rootCgroupPath))
                throw Error("expected cgroup directory '%s'", rootCgroupPath);

            static std::atomic<unsigned int> counter{0};

            cgroup = buildUser ? fmt("%s/nix-build-uid-%d", rootCgroupPath, buildUser->getUID())
                               : fmt("%s/nix-build-pid-%d-%d", rootCgroupPath, getpid(), counter++);

            debug("using cgroup '%s'", *cgroup);

            /* When using a build user, record the cgroup we used for that
               user so that if we got interrupted previously, we can kill
               any left-over cgroup first. */
            if (buildUser) {
                auto cgroupsDir = settings.nixStateDir + "/cgroups";
                createDirs(cgroupsDir);

                auto cgroupFile = fmt("%s/%d", cgroupsDir, buildUser->getUID());

                if (pathExists(cgroupFile)) {
                    auto prevCgroup = readFile(cgroupFile);
                    destroyCgroup(prevCgroup);
                }

                writeFile(cgroupFile, *cgroup);
            }
        }

        setSupplementaryGroups = settings.autoAllocateUids && getuid() == 0;

        // Kill any processes left in the cgroup or build user.
        DerivationBuilderImpl::prepareUser();
    }

    void prepareSandbox() override
    {
        /* Create a temporary directory in which we set up the chroot
           environment using bind-mounts.  We put it in the Nix store
           so that the build outputs can be moved efficiently from the
           chroot to their final location. */
        auto chrootParentDir = store.Store::toRealPath(drvPath) + ".chroot";
        deletePath(chrootParentDir);

        /* Clean up the chroot directory automatically. */
        autoDelChroot = std::make_shared<AutoDelete>(chrootParentDir);

        printMsg(lvlChatty, "setting up chroot environment in '%1%'", chrootParentDir);

        if (mkdir(chrootParentDir.c_str(), 0700) == -1)
            throw SysError("cannot create '%s'", chrootRootDir);

        chrootRootDir = chrootParentDir + "/root";

        if (mkdir(chrootRootDir.c_str(), buildUser && buildUser->getUIDCount() != 1 ? 0755 : 0750) == -1)
            throw SysError("cannot create '%1%'", chrootRootDir);

        if (buildUser
            && chown(
                   chrootRootDir.c_str(), buildUser->getUIDCount() != 1 ? buildUser->getUID() : 0, buildUser->getGID())
                   == -1)
            throw SysError("cannot change ownership of '%1%'", chrootRootDir);

        /* Create a writable /tmp in the chroot.  Many builders need
           this.  (Of course they should really respect $TMPDIR
           instead.) */
        Path chrootTmpDir = chrootRootDir + "/tmp";
        createDirs(chrootTmpDir);
        chmod_(chrootTmpDir, 01777);

        /* Create a /etc/passwd with entries for the build user and the
           nobody account.  The latter is kind of a hack to support
           Samba-in-QEMU. */
        createDirs(chrootRootDir + "/etc");
        if (drvOptions.useUidRange(drv))
            chownToBuilder(chrootRootDir + "/etc");

        if (drvOptions.useUidRange(drv) && (!buildUser || buildUser->getUIDCount() < 65536))
            throw Error("feature 'uid-range' requires the setting '%s' to be enabled", settings.autoAllocateUids.name);

        /* Declare the build user's group so that programs get a consistent
           view of the system (e.g., "id -gn"). */
        std::ostringstream oss;
        oss << fmt(
            "root:x:0:\n"
            "nogroup:x:65534:\n"
            "nixbld:!:%d:\n", sandboxGid());

        if (setSupplementaryGroups)
            for (const auto & [parent_gid, mapped] : getSupplementaryGIDMap())
                oss << fmt("%s:x:%d:nixbld\n", std::get<1>(mapped), std::get<0>(mapped));

        writeFile(chrootRootDir + "/etc/group", oss.str());

        /* Create /etc/hosts with localhost entry. */
        if (derivationType.isSandboxed())
            writeFile(chrootRootDir + "/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n");

        /* Make the closure of the inputs available in the chroot,
           rather than the whole Nix store.  This prevents any access
           to undeclared dependencies.  Directories are bind-mounted,
           while other inputs are hard-linked (since only directories
           can be bind-mounted).  !!! As an extra security
           precaution, make the fake Nix store only writable by the
           build user. */
        Path chrootStoreDir = chrootRootDir + store.storeDir;
        createDirs(chrootStoreDir);
        chmod_(chrootStoreDir, 01775);

        if (buildUser && chown(chrootStoreDir.c_str(), 0, buildUser->getGID()) == -1)
            throw SysError("cannot change ownership of '%1%'", chrootStoreDir);

        /* If we're repairing, checking or rebuilding part of a
           multiple-outputs derivation, it's possible that we're
           rebuilding a path that is in settings.sandbox-paths
           (typically the dependencies of /bin/sh).  Throw them
           out. */
        for (auto & i : drv.outputsAndOptPaths(store)) {
            /* If the name isn't known a priori (i.e. floating
               content-addressing derivation), the temporary location we use
               should be fresh.  Freshness means it is impossible that the path
               is already in the sandbox, so we don't need to worry about
               removing it.  */
            if (i.second.second)
                pathsInChroot.erase(store.printStorePath(*i.second.second));
        }

        if (cgroup) {
            if (mkdir(cgroup->c_str(), 0755) != 0)
                throw SysError("creating cgroup '%s'", *cgroup);
            chownToBuilder(*cgroup);
            chownToBuilder(*cgroup + "/cgroup.procs");
            chownToBuilder(*cgroup + "/cgroup.threads");
            // chownToBuilder(*cgroup + "/cgroup.subtree_control");
        }

        pathsInChroot = getPathsInSandbox();

        for (auto & i : inputPaths) {
            auto p = store.printStorePath(i);
            pathsInChroot.insert_or_assign(p, store.toRealPath(p));
        }

        createMountIDMapNamespaces();
    }

    void createMountIDMapNamespaces()
    {
        for (auto & p : pathsInChroot) {
            if (p.second.idmap.empty())
                continue;
            if (mountIDMapNamespaces.find(p.second.idmap) == mountIDMapNamespaces.end()) {
                mountIDMapNamespaces[p.second.idmap] = createUsernamespaceWithMappings(p.second.idmap);
            }
        }
    }

    void mountIDMapPaths()
    {
       /* The kernel has (too) many small & significant security rules as to
        * what's okay under which conditions when CLONE_(USER|NS|PID) et al.
        * are involved. There is a very reasonable explanation why
        * mount_setattr(2) gives EPERM if it goes inside the sandbox's user
        * namespace (for sure). I'd be upset too, being compared to some
        * mount(2) all the time!
        *
        * Successful mounting is really a secondary concern, though. Only just
        * producing ID-maps for mount_setattr has as many gotchas as user
        * namespaces in general. :) */
        Pid child(startProcess([&]()
        {
         /* if (usingUserNamespace && (setns(sandboxUserNamespace.get(), 0) == -1))
                throw SysError("idmap-mount: entering sandbox user namespace"); */

            if (setns(sandboxMountNamespace.get(), 0) == -1)
                throw SysError("idmap-mount: entering sandbox mount namespace");

            for (auto & p : pathsInChroot) {
                if (p.second.idmap.empty())
                    continue;
                auto fd = mountIDMapNamespaces[p.second.idmap];
                if (fcntl(fd, F_GETFD) == -1)
                    throw SysError("fd-send: %d: invalid at init-parent: '%s'", fd, p.second.source);

                bindMountWithIDMap(p.second.source, chrootRootDir + p.first, fd, p.second.rdonly);
            }
            _exit(0);
        }));
        int status = child.wait();
        if (status != 0)
            throw Error("could not add id-mapped mounts to sandbox");
    }

    Strings getPreBuildHookArgs() override
    {
        assert(!chrootRootDir.empty());
        return Strings({store.printStorePath(drvPath), chrootRootDir});
    }

    Path realPathInSandbox(const Path & p) override
    {
        // FIXME: why the needsHashRewrite() conditional?
        return !needsHashRewrite() ? chrootRootDir + p : store.toRealPath(p);
    }

    void startChild() override
    {
        /* Set up private namespaces for the build:

           - The PID namespace causes the build to start as PID 1.
             Processes outside of the chroot are not visible to those
             on the inside, but processes inside the chroot are
             visible from the outside (though with different PIDs).

           - The private mount namespace ensures that all the bind
             mounts we do will only show up in this process and its
             children, and will disappear automatically when we're
             done.

           - The private network namespace ensures that the builder
             cannot talk to the outside world (or vice versa).  It
             only has a private loopback interface. (Fixed-output
             derivations are not run in a private network namespace
             to allow functions like fetchurl to work.)

           - The IPC namespace prevents the builder from communicating
             with outside processes using SysV IPC mechanisms (shared
             memory, message queues, semaphores).  It also ensures
             that all IPC objects are destroyed when the builder
             exits.

           - The UTS namespace ensures that builders see a hostname of
             localhost rather than the actual hostname.

           We use a helper process to do the clone() to work around
           clone() being broken in multi-threaded programs due to
           at-fork handlers not being run. Note that we use
           CLONE_PARENT to ensure that the real builder is parented to
           us.
        */

        userNamespaceSync.create();
        builderSync.create();

        usingUserNamespace = userNamespacesSupported();

        // NOTE: setting supplementary groups like this only only works in
        // certain conditions (root permissions).
        std::vector<gid_t> supplementaryGroups;
        if (setSupplementaryGroups)
            for (const auto & [parent_gid, mapped] : getSupplementaryGIDMap())
                supplementaryGroups.push_back(std::get<0>(mapped));

        Pipe sendPid;
        sendPid.create();

        Pid helper = startProcess([&]() {
            sendPid.readSide.close();
            builderSync.readSide.close();

            /* We need to open the slave early, before
               CLONE_NEWUSER. Otherwise we get EPERM when running as
               root. */
            openSlave();

            try {
                /* Drop and/or set additional groups here because we can't do it
                   after we've created the new user namespace. */
                if (setgroups(supplementaryGroups.size(), supplementaryGroups.data()) == -1) {
                    if (errno != EPERM)
                        throw SysError("setgroups failed");
                    if (settings.requireDropSupplementaryGroups)
                        throw Error(
                            "setgroups failed. Set the require-drop-supplementary-groups option to false to skip this step.");
                }

                ProcessOptions options;
                options.cloneFlags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_PARENT | SIGCHLD;
                if (derivationType.isSandboxed())
                    options.cloneFlags |= CLONE_NEWNET;
                if (usingUserNamespace)
                    options.cloneFlags |= CLONE_NEWUSER;

                pid_t child = startProcess([&]() { runChild(); }, options);

                writeFull(sendPid.writeSide.get(), fmt("%d\n", child));
                _exit(0);
            } catch (...) {
                handleChildException(true);
                _exit(1);
            }
        });

        sendPid.writeSide.close();

        if (helper.wait() != 0) {
            processSandboxSetupMessages();
            // Only reached if the child process didn't send an exception.
            throw Error("unable to start build process");
        }

        userNamespaceSync.readSide = -1;

        /* Close the write side to prevent runChild() from hanging
           reading from this. */
        Finally cleanup([&]() { userNamespaceSync.writeSide = -1; });

        auto ss = tokenizeString<std::vector<std::string>>(readLine(sendPid.readSide.get()));
        assert(ss.size() == 1);
        pid = string2Int<pid_t>(ss[0]).value();

        if (usingUserNamespace) {
            /* Set the UID/GID mapping of the builder's user namespace
               such that the sandbox user maps to the build user, or to
               the calling user (if build users are disabled). */
            uid_t hostUid = buildUser ? buildUser->getUID() : getuid();
            uid_t hostGid = buildUser ? buildUser->getGID() : getgid();
            uid_t nrIds = buildUser ? buildUser->getUIDCount() : 1;

            writeFile("/proc/" + std::to_string(pid) + "/uid_map", fmt("%d %d %d", sandboxUid(), hostUid, nrIds));

            if (!buildUser || buildUser->getUIDCount() == 1)
                writeFile("/proc/" + std::to_string(pid) + "/setgroups", "deny");

            std::ostringstream oss;

            // Primary GID mapping
            oss << fmt("%d %d %d", sandboxGid(), hostGid, nrIds);

            if (setSupplementaryGroups)
                // Supplementary GIDs one by one
                for (const auto & [parent_gid, mapped] : getSupplementaryGIDMap())
                    oss << fmt("\n%d %d 1", std::get<0>(mapped), parent_gid);

            writeFile("/proc/" + std::to_string(pid) + "/gid_map", oss.str());
        } else {
            debug("note: not using a user namespace");
            if (!buildUser)
                throw Error(
                    "cannot perform a sandboxed build because user namespaces are not enabled; check /proc/sys/user/max_user_namespaces");
        }

        /* Now that we now the sandbox uid, we can write
           /etc/passwd. */
        writeFile(
            chrootRootDir + "/etc/passwd",
            fmt("root:x:0:0:Nix build user:%3%:/noshell\n"
                "nixbld:x:%1%:%2%:Nix build user:%3%:/noshell\n"
                "nobody:x:65534:65534:Nobody:/:/noshell\n",
                sandboxUid(),
                sandboxGid(),
                settings.sandboxBuildDir));

        /* Save the mount- and user namespace of the child. We have to do this
         *before* the child does a chroot. */
        sandboxMountNamespace = open(fmt("/proc/%d/ns/mnt", (pid_t) pid).c_str(), O_RDONLY);
        if (sandboxMountNamespace.get() == -1)
            throw SysError("getting sandbox mount namespace");

        if (usingUserNamespace) {
            sandboxUserNamespace = open(fmt("/proc/%d/ns/user", (pid_t) pid).c_str(), O_RDONLY);
            if (sandboxUserNamespace.get() == -1)
                throw SysError("getting sandbox user namespace");
        }

        /* Move the child into its own cgroup. */
        if (cgroup)
            writeFile(*cgroup + "/cgroup.procs", fmt("%d", (pid_t) pid));

        /* Signal the builder that we've updated its user namespace. */
        writeLine(userNamespaceSync.writeSide.get(), "1");

        if (readLine(builderSync.readSide.get(), true) != "C")
            throw Error("builder chroot preparation failed");

        /* Mount paths that need ID-mapping */
        mountIDMapPaths();
        /* Signal the builder to proceed with chroot and build. */
        writeLine(userNamespaceSync.writeSide.get(), "1");
    }

    void enterChroot() override
    {
        userNamespaceSync.writeSide = -1;

        if (readLine(userNamespaceSync.readSide.get(), true) != "1")
            throw Error("user namespace initialisation failed");


        if (derivationType.isSandboxed()) {

            /* Initialise the loopback interface. */
            AutoCloseFD fd(socket(PF_INET, SOCK_DGRAM, IPPROTO_IP));
            if (!fd)
                throw SysError("cannot open IP socket");

            struct ifreq ifr;
            strcpy(ifr.ifr_name, "lo");
            ifr.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
            if (ioctl(fd.get(), SIOCSIFFLAGS, &ifr) == -1)
                throw SysError("cannot set loopback interface flags");
        }

        /* Set the hostname etc. to fixed values. */
        char hostname[] = "localhost";
        if (sethostname(hostname, sizeof(hostname)) == -1)
            throw SysError("cannot set host name");
        char domainname[] = "(none)"; // kernel default
        if (setdomainname(domainname, sizeof(domainname)) == -1)
            throw SysError("cannot set domain name");

        /* Make all filesystems private.  This is necessary
           because subtrees may have been mounted as "shared"
           (MS_SHARED).  (Systemd does this, for instance.)  Even
           though we have a private mount namespace, mounting
           filesystems on top of a shared subtree still propagates
           outside of the namespace.  Making a subtree private is
           local to the namespace, though, so setting MS_PRIVATE
           does not affect the outside world. */
        if (mount(0, "/", 0, MS_PRIVATE | MS_REC, 0) == -1)
            throw SysError("unable to make '/' private");

        /* Bind-mount chroot directory to itself, to treat it as a
           different filesystem from /, as needed for pivot_root. */
        if (mount(chrootRootDir.c_str(), chrootRootDir.c_str(), 0, MS_BIND, 0) == -1)
            throw SysError("unable to bind mount '%1%'", chrootRootDir);

        /* Bind-mount the sandbox's Nix store onto itself so that
           we can mark it as a "shared" subtree, allowing bind
           mounts made in *this* mount namespace to be propagated
           into the child namespace created by the
           unshare(CLONE_NEWNS) call below.

           Marking chrootRootDir as MS_SHARED causes pivot_root()
           to fail with EINVAL. Don't know why. */
        Path chrootStoreDir = chrootRootDir + store.storeDir;

        if (mount(chrootStoreDir.c_str(), chrootStoreDir.c_str(), 0, MS_BIND, 0) == -1)
            throw SysError("unable to bind mount the Nix store", chrootStoreDir);

        if (mount(0, chrootStoreDir.c_str(), 0, MS_SHARED, 0) == -1)
            throw SysError("unable to make '%s' shared", chrootStoreDir);

        /* Set up a nearly empty /dev, unless the user asked to
           bind-mount the host /dev. */
        Strings ss;
        if (pathsInChroot.find("/dev") == pathsInChroot.end()) {
            createDirs(chrootRootDir + "/dev/shm");
            createDirs(chrootRootDir + "/dev/pts");
            ss.push_back("/dev/full");
            if (store.config.systemFeatures.get().count("kvm") && pathExists("/dev/kvm"))
                ss.push_back("/dev/kvm");
            ss.push_back("/dev/null");
            ss.push_back("/dev/random");
            ss.push_back("/dev/tty");
            ss.push_back("/dev/urandom");
            ss.push_back("/dev/zero");
            createSymlink("/proc/self/fd", chrootRootDir + "/dev/fd");
            createSymlink("/proc/self/fd/0", chrootRootDir + "/dev/stdin");
            createSymlink("/proc/self/fd/1", chrootRootDir + "/dev/stdout");
            createSymlink("/proc/self/fd/2", chrootRootDir + "/dev/stderr");
        }

        /* Fixed-output derivations typically need to access the
           network, so give them access to /etc/resolv.conf and so
           on. */
        if (!derivationType.isSandboxed()) {
            // Only use nss functions to resolve hosts and
            // services. Don’t use it for anything else that may
            // be configured for this system. This limits the
            // potential impurities introduced in fixed-outputs.
            writeFile(chrootRootDir + "/etc/nsswitch.conf", "hosts: files dns\nservices: files\n");

            /* N.B. it is realistic that these paths might not exist. It
               happens when testing Nix building fixed-output derivations
               within a pure derivation. */
            for (auto & path : {"/etc/resolv.conf", "/etc/services", "/etc/hosts"})
                if (pathExists(path))
                    ss.push_back(path);

            if (settings.caFile != "") {
                Path caFile = settings.caFile;
                if (pathExists(caFile))
                    pathsInChroot.try_emplace("/etc/ssl/certs/ca-certificates.crt", canonPath(caFile, true), true);
            }
        }

        for (auto & i : ss) {
            // For backwards-compatibility, resolve all the symlinks in the
            // chroot paths.
            auto canonicalPath = canonPath(i, true);
            pathsInChroot.emplace(i, canonicalPath);
        }

        /* Bind-mount all the directories from the "host"
           filesystem that we want in the chroot
           environment. */
        for (auto & i : pathsInChroot) {
            if (i.second.source == "/proc")
                continue; // backwards compatibility

#  if HAVE_EMBEDDED_SANDBOX_SHELL
            if (i.second.source == "__embedded_sandbox_shell__") {
                static unsigned char sh[] = {
#    include "embedded-sandbox-shell.gen.hh"
                };
                auto dst = chrootRootDir + i.first;
                createDirs(dirOf(dst));
                writeFile(dst, std::string_view((const char *) sh, sizeof(sh)));
                chmod_(dst, 0555);
            } else
#  endif
            if (i.second.idmap == "") {
                doBind(i.second.source, chrootRootDir + i.first, i.second.optional, i.second.rdonly);
            }
        }

        /* Bind a new instance of procfs on /proc. */
        createDirs(chrootRootDir + "/proc");
        if (mount("none", (chrootRootDir + "/proc").c_str(), "proc", 0, 0) == -1)
            throw SysError("mounting /proc");

        /* Mount sysfs on /sys. */
        if (buildUser && buildUser->getUIDCount() != 1) {
            createDirs(chrootRootDir + "/sys");
            if (mount("none", (chrootRootDir + "/sys").c_str(), "sysfs", 0, 0) == -1)
                throw SysError("mounting /sys");
        }

        /* Mount a new tmpfs on /dev/shm to ensure that whatever
           the builder puts in /dev/shm is cleaned up automatically. */
        if (pathExists("/dev/shm")
            && mount(
                   "none",
                   (chrootRootDir + "/dev/shm").c_str(),
                   "tmpfs",
                   0,
                   fmt("size=%s", settings.sandboxShmSize).c_str())
                   == -1)
            throw SysError("mounting /dev/shm");

        /* Mount a new devpts on /dev/pts.  Note that this
           requires the kernel to be compiled with
           CONFIG_DEVPTS_MULTIPLE_INSTANCES=y (which is the case
           if /dev/ptx/ptmx exists). */
        if (pathExists("/dev/pts/ptmx") && !pathExists(chrootRootDir + "/dev/ptmx")
            && !pathsInChroot.count("/dev/pts")) {
            if (mount("none", (chrootRootDir + "/dev/pts").c_str(), "devpts", 0, "newinstance,mode=0620") == 0) {
                createSymlink("/dev/pts/ptmx", chrootRootDir + "/dev/ptmx");

                /* Make sure /dev/pts/ptmx is world-writable.  With some
                   Linux versions, it is created with permissions 0.  */
                chmod_(chrootRootDir + "/dev/pts/ptmx", 0666);
            } else {
                if (errno != EINVAL)
                    throw SysError("mounting /dev/pts");
                doBind("/dev/pts", chrootRootDir + "/dev/pts");
                doBind("/dev/ptmx", chrootRootDir + "/dev/ptmx");
            }
        }

        /* Make /etc unwritable */
        if (!drvOptions.useUidRange(drv))
            chmod_(chrootRootDir + "/etc", 0555);

        /* Signal parent just prior to chroot. */
        writeLine(builderSync.writeSide.get(), "C");

        /* Wait for parent before continuing to unshare mount and cgroup namespaces. */
        if (readLine(userNamespaceSync.readSide.get(), true) != "1")
            throw Error("preparing chroot failed");

        /* Unshare this mount namespace. This is necessary because
           pivot_root() below changes the root of the mount
           namespace. This means that the call to setns() in
           addDependency() would hide the host's filesystem,
           making it impossible to bind-mount paths from the host
           Nix store into the sandbox. Therefore, we save the
           pre-pivot_root namespace in
           sandboxMountNamespace. Since we made /nix/store a
           shared subtree above, this allows addDependency() to
           make paths appear in the sandbox. */
        if (unshare(CLONE_NEWNS) == -1)
            throw SysError("unsharing mount namespace");

        /* Unshare the cgroup namespace. This means
           /proc/self/cgroup will show the child's cgroup as '/'
           rather than whatever it is in the parent. */
        if (cgroup && unshare(CLONE_NEWCGROUP) == -1)
            throw SysError("unsharing cgroup namespace");

        /* Do the chroot(). */
        if (chdir(chrootRootDir.c_str()) == -1)
            throw SysError("cannot change directory to '%1%'", chrootRootDir);

        if (mkdir("real-root", 0500) == -1)
            throw SysError("cannot create real-root directory");

        if (pivot_root(".", "real-root") == -1)
            throw SysError("cannot pivot old root directory onto '%1%'", (chrootRootDir + "/real-root"));

        if (chroot(".") == -1)
            throw SysError("cannot change root directory to '%1%'", chrootRootDir);

        if (umount2("real-root", MNT_DETACH) == -1)
            throw SysError("cannot unmount real root filesystem");

        if (rmdir("real-root") == -1)
            throw SysError("cannot remove real-root directory");

        LinuxDerivationBuilder::enterChroot();
    }

    void setUser() override
    {
        /* Switch to the sandbox uid/gid in the user namespace,
           which corresponds to the build user or calling user in
           the parent namespace. */
        if (setgid(sandboxGid()) == -1)
            throw SysError("setgid failed");
        if (setuid(sandboxUid()) == -1)
            throw SysError("setuid failed");
    }

    std::variant<std::pair<BuildResult::Status, Error>, SingleDrvOutputs> unprepareBuild() override
    {
        sandboxMountNamespace = -1;
        sandboxUserNamespace = -1;

        return DerivationBuilderImpl::unprepareBuild();
    }

    void killSandbox(bool getStats) override
    {
        if (cgroup) {
            auto stats = destroyCgroup(*cgroup);
            if (getStats) {
                buildResult.cpuUser = stats.cpuUser;
                buildResult.cpuSystem = stats.cpuSystem;
            }
            return;
        }

        DerivationBuilderImpl::killSandbox(getStats);
    }

    void cleanupBuild() override
    {
        DerivationBuilderImpl::cleanupBuild();

        /* Move paths out of the chroot for easier debugging of
           build failures. */
        if (buildMode == bmNormal)
            for (auto & [_, status] : initialOutputs) {
                if (!status.known)
                    continue;
                if (buildMode != bmCheck && status.known->isValid())
                    continue;
                auto p = store.toRealPath(status.known->path);
                if (pathExists(chrootRootDir + p))
                    std::filesystem::rename((chrootRootDir + p), p);
            }
    }

    void addDependency(const StorePath & path) override
    {
        if (isAllowed(path))
            return;

        addedPaths.insert(path);

        debug("materialising '%s' in the sandbox", store.printStorePath(path));

        Path source = store.Store::toRealPath(path);
        Path target = chrootRootDir + store.printStorePath(path);

        if (pathExists(target)) {
            // There is a similar debug message in doBind, so only run it in this block to not have double messages.
            debug("bind-mounting %s -> %s", target, source);
            throw Error("store path '%s' already exists in the sandbox", store.printStorePath(path));
        }

        /* Bind-mount the path into the sandbox. This requires
           entering its mount namespace, which is not possible
           in multithreaded programs. So we do this in a
           child process.*/
        Pid child(startProcess([&]() {
            if (usingUserNamespace && (setns(sandboxUserNamespace.get(), 0) == -1))
                throw SysError("entering sandbox user namespace");

            if (setns(sandboxMountNamespace.get(), 0) == -1)
                throw SysError("entering sandbox mount namespace");

            doBind(source, target);

            _exit(0);
        }));

        int status = child.wait();
        if (status != 0)
            throw Error("could not add path '%s' to sandbox", store.printStorePath(path));
    }
};

}

#endif
