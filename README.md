# subsystemd: Run systemd in WSL2

Run systemd under Linux namespace in WSL2. Heavily inspired by [arkane-systems/genie][genie], but written in Rust.

## Difference with arkane-systems/genie

Slightly following [genie]'s behavior, but noted below...

- Interface
  - Command line interface is not compatible.
- Behavior
  - Hostname altertion is optional with `--hostname`, `--hostname-suffix`
    - `/etc/hosts` are not updated. Users are encouraged to use `nss-myhostname`.
  - Uses `machinectl shell` to launch a user shell; this allows running systemd user session
- Internal
  - Removed dependency to `unshare`, `daemonize`, `nsenter` command line tools
  - systemd-wide environment variables are set via `systemd.conf` drop-in, using `DefaultEnvironment=`
  - systemd PID from root namespace is stored at `/run/subsystemctl/systemd.pid`

## Install

### Arch Linux

PKGBUILD: https://github.com/sorah/arch.sorah.jp/tree/master/aur-sorah/PKGBUILDs/subsystemctl

_(PKGBUILD originally submitted to AUR (https://aur.archlinux.org/packages/subsystemctl) was deleted as [they unwelcomes WSL-exclusive packages](https://lists.archlinux.org/pipermail/aur-requests/2020-June/041193.html).)_

### Debian/Ubuntu

Refer to https://github.com/nkmideb/subsystemctl for debian source.

Pre-built package binaries available at https://github.com/nkmideb/subsystemctl/releases for your convenient.

### Self build

```
cargo install subsystemctl
```

or from git source:

```bash
cargo build --release
install -m6755 -oroot -groot ./target/release/subsystemctl /usr/local/bin/subsystemctl
```

## Usage

### `subsystemctl start`: Start `systemd` environment

```ps1
PS> wsl -u root -- subsystemctl start
```

### `subsystemctl shell`: shell login to systemd-enabled environment

```ps1
PS> wsl subsystemctl shell
Connected to the local host. Press ^] three times within 1s to exit session.
someone@hostname$ ...
```

#### Specifying uid to login

```ps1
PS> wsl -u root -- subsystemctl --uid=1000 shell
Connected to the local host. Press ^] three times within 1s to exit session.
someone@hostname$ ...
```

### `subsystemctl exec`: Raw `nsenter` like interface

```ps1
PS> wsl subsystemctl exec id
uid=1000(sorah) gid=1000(sorah) groups=1000(sorah),116(admin)
```

#### Specifying uid (and gid)

```ps1
PS> wsl -u root -- subsystemctl exec id
uid=0(root) gid=0(root) groups=0(root)

PS> wsl -u root -- subsystemctl exec --uid=1000 id
uid=1000(sorah) gid=1000(sorah) groups=1000(sorah),116(admin)

PS> wsl -u root -- subsystemctl exec --uid=1000 --gid=116 id
uid=1000(sorah) gid=116(admin) groups=116(admin)
```

### `subsystemctl is-running`

```bash
#!/bin/bash
if subsystemctl is-running; then
  echo "running"
else
  echo "not-running"
fi
```

### `subsystemctl is-inside`

```bash
#!/bin/bash
if subsystemctl is-inside; then
  echo "inside"
else
  echo "outside"
fi
```

## Tips

### systemd-resolved, networkd are recommended to be disabled

otherwise `/etc/resolv.conf` might get overwritten to resolved stub-resolver.

## Author

Sorah Fukumori https://sorah.jp/

## License

MIT


[genie]: https://github.com/arkane-systems/genie
