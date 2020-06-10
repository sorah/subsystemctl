use crate::error::Error;
static PROC_MOUNTS: &'static str = "/proc/self/mounts";

static OSRELEASE_FILE: &'static str = "/proc/sys/kernel/osrelease";
static WSL_OSRELEASE: &'static str = "microsoft";

pub fn is_wsl() -> Result<bool, Box<dyn std::error::Error>> {
    let osrelease = String::from_utf8(std::fs::read(OSRELEASE_FILE)?)?;
    Ok(osrelease.contains(WSL_OSRELEASE))
}

pub fn is_wsl1() -> Result<bool, Box<dyn std::error::Error>> {
    log::debug!("Checking is_wsl1");
    // Assume we're in WSL 1 or 2.
    // Find rootfs is lxfs or not. If it's lxfs, then it's WSL1, otherwise considered 2.

    let mounts_buf = String::from_utf8(std::fs::read(PROC_MOUNTS)?)?;
    let mut mounts_lines = mounts_buf.lines();

    while let Some(mount) = mounts_lines.next() {
        let mut iter = mount.split_ascii_whitespace();
        iter.next();
        let mountpoint_o = iter.next();
        let fstype_o = iter.next();
        if let (Some(mountpoint), Some(fstype)) = (mountpoint_o, fstype_o) {
            log::debug!("Checking is_wsl1: mountpoint={}, fstype={}", mountpoint, fstype);
            if mountpoint != "/" {
                continue;
            }
            return Ok(fstype == "lxfs" || fstype == "wslfs");
        } else {
            return Err(Box::new(Error::InvalidProcMounts));
        }
    }

    Ok(false)
}

pub fn systemd_bin() -> Result<String, Error> {
    //if let Ok(bin) = std::env::var("SUBSYSTEMCTL_SYSTEMD_BIN") {
    //    return Ok(bin);
    //}
    if std::fs::metadata("/lib/systemd/systemd").is_ok() {
        return Ok("/lib/systemd/systemd".to_string());
    }
    if std::fs::metadata("/usr/lib/systemd/systemd").is_ok() {
        return Ok("/usr/lib/systemd/systemd".to_string());
    }
    Err(Error::NoSystemdFound)
}

pub fn machinectl_bin() -> Result<String, Error> {
    // if let Ok(bin) = std::env::var("SUBSYSTEMCTL_MACHINECTL_BIN") {
    //   return Ok(bin)
    // }
    if std::fs::metadata("/usr/bin/machinectl").is_ok() {
        return Ok("/usr/bin/machinectl".to_string());
    }
    if std::fs::metadata("/bin/machinectl").is_ok() {
        return Ok("/bin/machinectl".to_string());
    }
    Err(Error::NoSystemdFound)
}

pub fn is_pid1_systemd() -> bool {
    if let Ok(cmdline_vec) = std::fs::read("/proc/1/cmdline") {
        let cmdline = String::from_utf8(cmdline_vec).unwrap();
        let binpath = cmdline.split('\0').next().unwrap();

        binpath == systemd_bin().unwrap()
    } else {
        false
    }
}
