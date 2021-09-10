use subsystemctl::bottle;
use subsystemctl::environment;

fn main() -> anyhow::Result<()> {
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let app = clap::App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .setting(clap::AppSettings::SubcommandRequired)
        .subcommand(
            clap::SubCommand::with_name("start")
                .about("Start systemd in a Linux namespace (mount, pid)")
                .arg(
                    clap::Arg::with_name("hostname")
                        .help("Change hostname during start up")
                        .takes_value(true)
                        .short("n")
                        .long("hostname"),
                )
                .arg(
                    clap::Arg::with_name("hostname-suffix")
                        .help("Append a suffix to hostname during startup")
                        .takes_value(true)
                        .short("N")
                        .long("hostname-suffix"),
                )
                .arg(
                    clap::Arg::with_name("wait")
                        .help("Wait systemd-machined to start up")
                        .short("w")
                        .long("wait"),
                ),
        )
        .subcommand(clap::SubCommand::with_name("stop").about("stop"))
        .subcommand(
            clap::SubCommand::with_name("shell")
                .about("Start a shell in a systemd namespace using machinectl-shell")
                .arg(
                    clap::Arg::with_name("start")
                        .help("Start systemd when necessary")
                        .short("s")
                        .long("start"),
                )
                .arg(
                    clap::Arg::with_name("quiet")
                        .help("Suppress machinectl-shell output")
                        .short("q")
                        .long("quiet"),
                )
                .arg(clap::Arg::with_name("uid").takes_value(true).short("u").long("uid")),
        )
        .subcommand(
            clap::SubCommand::with_name("exec")
                .about("Execute a command in a systemd namespace")
                .arg(
                    clap::Arg::with_name("start")
                        .help("Start systemd when necessary")
                        .short("s")
                        .long("start"),
                )
                .arg(
                    clap::Arg::with_name("uid")
                        .help("setuid(2) on exec. Only available for root, default to current uid (getuid(2)")
                        .takes_value(true)
                        .short("u")
                        .long("uid"),
                )
                .arg(
                    clap::Arg::with_name("gid")
                        .help("setgid(2) on exec. Only available for root, default to current gid (getgid(2)")
                        .takes_value(true)
                        .short("g")
                        .long("gid"),
                )
                .arg(clap::Arg::with_name("command").takes_value(true).multiple(true)
                .allow_hyphen_values(true)
                .last(true)),
        )
        .subcommand(
            clap::SubCommand::with_name("is-running")
                .about("Return 0 if a systemd namespace is running, otherwise 1"),
        )
        .subcommand(
            clap::SubCommand::with_name("is-inside")
                .about("Return 0 if invoked from inside of a systemd namespace, otherwise 1"),
        );
    let matches = app.get_matches();
    run_subcommand(matches.subcommand())
}

fn run_subcommand(subcommand: (&str, Option<&clap::ArgMatches>)) -> anyhow::Result<()> {
    match subcommand {
        ("start", Some(m)) => cmd_start(m),
        ("stop", Some(m)) => cmd_stop(m),
        ("exec", Some(m)) => cmd_exec(m),
        ("shell", Some(m)) => cmd_shell(m),
        ("is-running", Some(m)) => cmd_is_running(m),
        ("is-inside", Some(m)) => cmd_is_inside(m),
        _ => panic!("?"),
    }
}

fn cmd_start(m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_root()?;
    check_prereq()?;
    if bottle::is_running() {
        log::warn!("systemd is running, not starting again");
        return Ok(());
    }
    let hostname = if m.is_present("hostname") {
        Some(m.value_of_lossy("hostname").unwrap().to_string())
    } else if m.is_present("hostname-suffix") {
        let suffix = m.value_of_lossy("hostname-suffix").unwrap();
        Some(std::format!("{}{}", bottle::get_original_hostname()?, suffix))
    } else {
        None
    };

    // TODO: resolv.conf
    autostart(m.is_present("wait"), hostname)?;

    Ok(())
}

fn cmd_stop(_m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_root()?;
    check_prereq()?;
    if !bottle::is_running() {
        log::warn!("systemd is already stopped or not running");
        return Ok(());
    }
    if bottle::is_inside() {
        return Err(anyhow::anyhow!("Cannot stop from inside of systemd environment"));
    }

    let r = bottle::stop();
    if let Err(e) = r {
        return Err(anyhow::anyhow!("Failed to stop: {}", e));
    }
    Ok(())
}

fn cmd_exec(m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_prereq()?;
    if !bottle::is_running() {
        if m.is_present("start") {
            log::info!("Starting systemd");
            autostart(true, None)?;
        } else {
            return Err(anyhow::anyhow!("systemd is not running. Try start it first: subsystemctl start"));
        }
    }

    let cmd = m.values_of_lossy("command");
    if cmd.is_none() {
        return Err(anyhow::anyhow!("command not given"));
    }
    let (uid, gid) = extract_uid_gid(m)?;
    let r = bottle::exec(cmd.unwrap(), uid, gid);
    match r {
        Ok(retval) => std::process::exit(retval),
        Err(e) => return Err(anyhow::anyhow!("Failed to start: {}", e)),
    }
}

fn cmd_shell(m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_prereq()?;
    if !bottle::is_running() {
        if m.is_present("start") {
            log::info!("Starting systemd");
            autostart(true, None)?;
        } else {
            return Err(anyhow::anyhow!("systemd is not running. Try start it first: subsystemctl start"));
        }
    }

    let (uid, _gid) = extract_uid_gid(m)?;
    let quiet = m.is_present("quiet");
    let r = bottle::shell(Some(uid), quiet);
    match r {
        Ok(retval) => std::process::exit(retval),
        Err(e) => return Err(anyhow::anyhow!("Failed to start: {}", e)),
    }
}

fn cmd_is_running(_m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_prereq()?;
    if !bottle::is_running() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_is_inside(_m: &clap::ArgMatches) -> anyhow::Result<()> {
    check_prereq()?;
    if !bottle::is_inside() {
        std::process::exit(1);
    }
    Ok(())
}

fn check_prereq() -> anyhow::Result<()> {
    if std::env::var("SUBSYSTEMCTL_IGNORE_WSL_CHECK").is_err() {
        if !environment::is_wsl().expect("Cannot check WSL1/2 status") {
            return Err(anyhow::anyhow!("not running in WSL1/2; This tool only runs in WSL2"));
        }
        if environment::is_wsl1().expect("Cannot check WSL1") {
            return Err(anyhow::anyhow!("not running in WSL2; This tool only runs in WSL2"));
        }
    }
    Ok(())
}

fn check_root() -> anyhow::Result<()> {
    if !nix::unistd::getuid().is_root() {
        return Err(anyhow::anyhow!("This subcommand is only available for root"));
    }
    Ok(())
}

fn extract_uid_gid(m: &clap::ArgMatches) -> anyhow::Result<(nix::unistd::Uid, nix::unistd::Gid)> {
    if !nix::unistd::getuid().is_root() {
        if m.is_present("uid") || m.is_present("gid") {
            return Err(anyhow::anyhow!("uid,gid flags are only available for root"));
        }
        log::debug!(
            "extract_uid_gid: non-root, uid={}, gid={}",
            nix::unistd::getuid(),
            nix::unistd::getgid()
        );
        return Ok((nix::unistd::getuid(), nix::unistd::getgid()));
    }

    let uid = if let Some(id) = m.value_of("uid") {
        log::debug!("uid flag: {}", &id);
        nix::unistd::Uid::from_raw(id.parse()?)
    } else {
        nix::unistd::Uid::from_raw(0)
    };
    let gid = if let Some(id) = m.value_of("gid") {
        log::debug!("gid flag: {}", &id);
        nix::unistd::Gid::from_raw(id.parse()?)
    } else {
        if !uid.is_root() {
            nix::unistd::Gid::from_raw(uid.as_raw())
        } else {
            nix::unistd::getgid()
        }
    };
    Ok((uid, gid))
}

fn autostart(wait: bool, hostname: Option<String>) -> anyhow::Result<()> {
    environment::machinectl_bin()?;
    let r = bottle::start(hostname);
    if let Err(e) = r {
        return Err(anyhow::anyhow!("Failed to start: {}", e));
    }
    if wait {
        if let Err(e) = bottle::wait() {
            return Err(anyhow::anyhow!("Failed to wait machined: {}", e));
        }
    }

    Ok(())
}
