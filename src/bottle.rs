use crate::environment;
use crate::error;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;

static RUNTIME_DIR: &str = "/run/subsystemctl";
static PID_FILE: &str = "/run/subsystemctl/systemd.pid";
static HOSTNAME_FILE: &str = "/run/subsystemctl/hostname";
static ORIG_HOSTNAME_FILE: &str = "/run/subsystemctl/hostname.orig";

const OS_NONE: Option<&'static [u8]> = None;

pub fn get_systemd_pid() -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let result = std::fs::read(PID_FILE);
    match result {
        Ok(buf) => {
            let pid: i32 = String::from_utf8(buf)?.trim().parse()?;
            Ok(Some(pid))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Box::new(e))
            }
        }
    }
}

fn put_systemd_pid(pid: i32) -> std::io::Result<()> {
    std::fs::create_dir_all(RUNTIME_DIR)?;
    std::fs::write(PID_FILE, format!("{}\n", pid))
}

fn zap_systemd_pid() -> std::io::Result<()> {
    if std::fs::metadata(PID_FILE).is_ok() {
        std::fs::remove_file(PID_FILE)?;
    }
    Ok(())
}

pub fn get_original_hostname() -> std::io::Result<String> {
    let buf = if std::fs::metadata(ORIG_HOSTNAME_FILE).is_ok() {
        std::fs::read(ORIG_HOSTNAME_FILE)
    } else {
        std::fs::read("/etc/hostname")
    }?;
    Ok(String::from_utf8(buf).unwrap().trim().to_owned())
}

pub fn put_hostname(name: String) -> std::io::Result<()> {
    std::fs::create_dir_all(RUNTIME_DIR)?;
    if std::fs::metadata(ORIG_HOSTNAME_FILE).is_err() {
        let orig_hostname = std::fs::read("/etc/hostname")?;
        std::fs::write(ORIG_HOSTNAME_FILE, orig_hostname)?
    }
    std::fs::write(HOSTNAME_FILE, format!("{}\n", name))
}

pub fn is_running() -> bool {
    if environment::is_pid1_systemd() {
        return true;
    }
    if let Ok(pid_o) = get_systemd_pid() {
        if let Some(pid) = pid_o {
            if let Ok(meta) = std::fs::metadata(std::format!("/proc/{}", pid)) {
                return meta.is_dir();
            }
        }
    }
    false
}

pub fn is_inside() -> bool {
    environment::is_pid1_systemd()
}

pub fn start(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(hostname) = name {
        ensure_hostname(hostname)?;
    }
    exec_systemd_ensure_dropin()?;
    Ok(exec_systemd()?)
}

fn exec_systemd_ensure_dropin() -> std::io::Result<()> {
    std::fs::create_dir_all("/run/systemd/system.conf.d")?;

    let envs = vec!["WSL_INTEROP", "WSL_DISTRO_NAME", "WSL_NAME", "WT_SESSION", "WT_PROFILE_ID"];

    let envvar_strs: Vec<String> = envs
        .into_iter()
        .filter_map(|name| {
            let e = std::env::var(name);
            if let Ok(env) = e {
                if env.contains("\"") {
                    None // XXX:
                } else {
                    Some(format!("\"{}={}\"", name, env))
                }
            } else {
                None
            }
        })
        .collect();

    let dropin = format!(
        "[Manager]\nDefaultEnvironment=INSIDE_GENIE=1 INSIDE_SUBSYSTEMCTL=1 {}\n",
        envvar_strs.join(" ")
    );
    std::fs::write("/run/systemd/system.conf.d/10-subsystemctl-env.conf", dropin)
}

fn ensure_hostname(name: String) -> Result<(), Box<dyn std::error::Error>> {
    let needs_bind = std::fs::metadata(HOSTNAME_FILE).is_err();
    put_hostname(name)?;
    if !needs_bind {
        return Ok(());
    }
    nix::mount::mount(
        Some(OsStr::new(HOSTNAME_FILE)),
        OsStr::new("/etc/hostname"),
        OS_NONE,
        nix::mount::MsFlags::MS_BIND,
        OS_NONE,
    )?;
    Ok(())
}

fn exec_systemd() -> Result<(), error::Error> {
    use nix::unistd::ForkResult;

    let systemd_bin = CString::new(environment::systemd_bin().unwrap()).unwrap();

    match nix::unistd::fork() {
        Ok(ForkResult::Child) => exec_systemd0_handle_child_failure(exec_systemd1_child(systemd_bin)),
        Ok(ForkResult::Parent { child, .. }) => exec_systemd1_parent(child),
        Err(e) => panic!("{}",e),
    }
}

fn exec_systemd0_handle_child_failure(r: Result<(), error::Error>) -> Result<(), error::Error> {
    match r {
        Ok(_) => {} // do nothing
        Err(error::Error::StartFailed(exitstatus)) => {
            log::error!("Something went wrong while starting");
            std::process::exit(exitstatus);
        }
        Err(e) => panic!("{}",e),
    }
    std::process::exit(0);
}

fn exec_systemd1_parent(child: nix::unistd::Pid) -> Result<(), error::Error> {
    use nix::sys::wait::WaitStatus;

    // TODO: monitor systemd status instead of pid file
    loop {
        match get_systemd_pid() {
            Ok(Some(pid)) => {
                log::debug!("Watching pid: child_pid={}, pid={}", child, pid);
                let pidns_path = format!("/proc/{}/ns/pid", pid);
                let mntns_path = format!("/proc/{}/ns/mnt", pid);
                if std::fs::metadata(pidns_path).is_ok() && std::fs::metadata(mntns_path).is_ok() {
                    break;
                }
            }
            Ok(None) => {
                log::debug!("Watching pid: none");
            }
            Err(e) => {
                log::debug!("Watching pid: e={:?}", e);
            }
        }
        match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOWAIT)) {
            Ok(WaitStatus::Exited(_pid, status)) => {
                return Err(error::Error::StartFailed(status));
            }
            Ok(WaitStatus::Signaled(_pid, signal, _)) => {
                return Err(error::Error::StartFailed(128 + (signal as i32)));
            }
            Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => {
                return Err(error::Error::StartFailed(128));
            }
            _ => {} // ignore,
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // TODO:
    Ok(())
}

fn exec_systemd1_child(systemd_bin: CString) -> Result<(), error::Error> {
    use nix::sched::CloneFlags;
    use nix::unistd::ForkResult;

    nix::sched::unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID).unwrap();
    nix::unistd::setsid().unwrap();

    match nix::unistd::fork() {
        Ok(ForkResult::Child) => exec_systemd0_handle_child_failure(exec_systemd2_child(systemd_bin)),
        Ok(ForkResult::Parent { child, .. }) => exec_systemd2_parent(child),
        Err(e) => panic!("{}",e),
    }
}

fn exec_systemd2_parent(child: nix::unistd::Pid) -> Result<(), error::Error> {
    put_systemd_pid(child.as_raw()).unwrap();
    std::process::exit(0);
}

fn exec_systemd2_child(systemd_bin: CString) -> Result<(), error::Error> {
    use nix::fcntl::OFlag;
    use nix::mount::MsFlags;
    use std::os::unix::io::RawFd;

    nix::mount::mount(
        Some(OsStr::new("none")),
        OsStr::new("/"),
        OS_NONE,
        MsFlags::MS_REC | MsFlags::MS_SHARED,
        OS_NONE,
    )
    .expect("set_propagation mount failure");

    nix::mount::mount(
        Some(OsStr::new("none")),
        OsStr::new("/proc"),
        OS_NONE,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        OS_NONE,
    )
    .expect("proc propagation mount failure");

    nix::mount::mount(
        Some(OsStr::new("proc")),
        OsStr::new("/proc"),
        Some(OsStr::new("proc")),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        OS_NONE,
    )
    .expect("proc mount failure");

    nix::unistd::chdir("/").unwrap();
    nix::unistd::setgid(nix::unistd::Gid::from_raw(0)).unwrap();
    nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).unwrap();

    match nix::unistd::close(0 as RawFd) {
        Ok(_) => {}
        Err(nix::Error::Sys(nix::errno::Errno::EBADF)) => {}
        Err(e) => panic!("{}",e),
    }
    match nix::unistd::close(1 as RawFd) {
        Ok(_) => {}
        Err(nix::Error::Sys(nix::errno::Errno::EBADF)) => {}
        Err(e) => panic!("{}",e),
    }
    match nix::unistd::close(2 as RawFd) {
        Ok(_) => {}
        Err(nix::Error::Sys(nix::errno::Errno::EBADF)) => {}
        Err(e) => panic!("{}",e),
    }

    nix::fcntl::open(OsStr::new("/dev/null"), OFlag::O_RDONLY, nix::sys::stat::Mode::empty()).unwrap();
    nix::fcntl::open(OsStr::new("/dev/null"), OFlag::O_WRONLY, nix::sys::stat::Mode::empty()).unwrap();
    nix::fcntl::open(OsStr::new("/dev/null"), OFlag::O_WRONLY, nix::sys::stat::Mode::empty()).unwrap();

    nix::unistd::execve(systemd_bin.as_c_str(), &[systemd_bin.as_c_str()], &[]).unwrap();
    panic!("should unreach");
}

pub fn stop() -> Result<(), Box<dyn std::error::Error>> {
    let systemd_pid = get_systemd_pid().unwrap().unwrap();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(systemd_pid), Some(SIGRTMIN_plus_4()))?;
    zap_systemd_pid().unwrap();
    Ok(())
}

extern "C" {
    fn __libc_current_sigrtmin() -> libc::c_int;
}

#[allow(non_snake_case)]
fn SIGRTMIN_plus_4() -> nix::sys::signal::Signal {
    unsafe { std::mem::transmute(__libc_current_sigrtmin() + 4) }
}

pub fn wait() -> Result<(), Box<dyn std::error::Error>> {
    use nix::sys::wait::WaitStatus;
    use nix::unistd::ForkResult;

    log::debug!("Waiting systemd-machined to start");
    let machinectl = environment::machinectl_bin()?;

    match nix::unistd::fork() {
        Ok(ForkResult::Child) => {
            wait_internal(machinectl);
            std::process::exit(0);
        }
        Ok(ForkResult::Parent { child, .. }) => {
            loop {
                match nix::sys::wait::waitpid(child, None) {
                    Ok(WaitStatus::Exited(_pid, status)) => {
                        if status == 0 {
                            log::debug!("machined is now up");
                            return Ok(());
                        } else {
                            return Err(Box::new(error::Error::WaitFailed));
                        }
                    }
                    Ok(WaitStatus::Signaled(_pid, _signal, _)) => {
                        return Err(Box::new(error::Error::WaitFailed));
                    }
                    Ok(_) => {}                                                       // ignore
                    Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => return Ok(()), // ???
                    Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => {}              // ignore
                    Err(e) => panic!("{}",e),
                }
            }
        }

        Err(e) => panic!("{}",e),
    }
}

fn wait_internal(machinectl: String) {
    setns_systemd();
    loop {
        let cmd = std::process::Command::new(&machinectl)
            .arg("list")
            .output()
            .expect("failed to execute machinectl list");
        if cmd.status.success() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(600));
        log::debug!("Still waiting systemd-machined to start");
    }
    log::debug!("systemd-machined is up (internal)");
}

pub fn exec(cmdline: Vec<String>, uid: nix::unistd::Uid, gid: nix::unistd::Gid) -> Result<i32, error::Error> {
    let args_string: Vec<CString> = cmdline.into_iter().map(|a| CString::new(a).unwrap()).collect();
    let args: Vec<&CStr> = args_string.iter().map(|s| s.as_c_str()).collect();

    enter(args[0], args.as_slice(), uid, gid)
}

pub fn shell(uid: Option<nix::unistd::Uid>, quiet: bool) -> Result<i32, error::Error> {
    let machinectl = CString::new(environment::machinectl_bin()?).unwrap();
    let mut args = vec![CString::new("machinectl").unwrap(), CString::new("shell").unwrap()];

    if let Some(u) = uid {
        args.push(CString::new("--uid").unwrap());
        args.push(CString::new(format!("{}", u)).unwrap());
    }
    if quiet {
        args.push(CString::new("--quiet").unwrap());
    }

    args.push(CString::new("--setenv").unwrap());
    args.push(CString::new(format!("SUBSYSTEMCTL_PATH={}", std::env::current_dir().unwrap().display())).unwrap());

    args.push(CString::new(".host").unwrap());

    args.push(CString::new("/bin/sh").unwrap());
    args.push(CString::new("-c").unwrap());
    args.push(CString::new("cd \"${SUBSYSTEMCTL_PATH}\"; exec ${SHELL:-sh}").unwrap());

    let args_c: Vec<&CStr> = args.iter().map(|s| s.as_c_str()).collect();
    enter(
        machinectl.as_c_str(),
        &args_c.as_slice(),
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
    )
}

fn setns_systemd() {
    use nix::fcntl::OFlag;
    use nix::sched::CloneFlags;

    let sd_pid = get_systemd_pid().unwrap().unwrap();
    let pidns_path = format!("/proc/{}/ns/pid", sd_pid);
    let mntns_path = format!("/proc/{}/ns/mnt", sd_pid);

    {
        let pidns_fd =
            nix::fcntl::open(OsStr::new(&pidns_path), OFlag::O_RDONLY, nix::sys::stat::Mode::empty())
                .unwrap();
        nix::sched::setns(pidns_fd, CloneFlags::CLONE_NEWPID).unwrap();
        nix::unistd::close(pidns_fd).unwrap();
    }

    {
        let mntns_fd =
            nix::fcntl::open(OsStr::new(&mntns_path), OFlag::O_RDONLY, nix::sys::stat::Mode::empty())
                .unwrap();
        nix::sched::setns(mntns_fd, CloneFlags::CLONE_NEWNS).unwrap();
        nix::unistd::close(mntns_fd).unwrap();
    }
}

fn enter(
    path: &CStr,
    args: &[&CStr],
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> Result<i32, error::Error> {
    use nix::sys::wait::WaitStatus;
    use nix::unistd::ForkResult;

    setns_systemd();

    match nix::unistd::fork() {
        Ok(ForkResult::Child) => {
            log::debug!("enter(child): uid={}, gid={}", uid, gid);

            nix::unistd::setgroups(&[]).unwrap();

            unsafe {
                let ent = libc::getpwuid(uid.as_raw() as libc::uid_t);
                if !ent.is_null() {
                    let username = CString::from_raw((*ent).pw_name);
                    nix::unistd::initgroups(&username, gid).unwrap();
                }
            }

            nix::unistd::setgid(gid).unwrap();
            nix::unistd::setuid(uid).unwrap();

            log::debug!("execvp {:?}, {:?}", path, args);
            match nix::unistd::execvp(path, args) {
                Err(nix::Error::Sys(errno)) => {
                    log::error!("exec failed: {}", errno.desc());
                    return Ok(128);
                }
                Err(e) => panic!("{}",e),
                Ok(_) => {}
            }
            panic!("should unreach");
        }
        Ok(ForkResult::Parent { child, .. }) => {
            loop {
                match nix::sys::wait::waitpid(child, None) {
                    Ok(WaitStatus::Exited(_pid, status)) => {
                        return Ok(status);
                    }
                    Ok(WaitStatus::Signaled(_pid, signal, _)) => {
                        return Ok(128 + (signal as i32));
                    }
                    Ok(_) => {}                                                        // ignore
                    Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => return Ok(128), // ???
                    Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => {}               // ignore
                    Err(e) => panic!("{}",e),
                }
            }
        }

        Err(e) => panic!("{}",e),
    }
}
