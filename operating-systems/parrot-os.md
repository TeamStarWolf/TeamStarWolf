<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Parrot OS

> A Debian-based security distribution with a rolling update model and its own repository on top of Debian's packages.

Part of [Operating systems](/operating-systems/README.md) (Security testing distributions). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 7.x (7.4) | echo | Not applicable | 7.4 | Not applicable | Not applicable | Not applicable | Rolling release |

- 7.x (7.4): Rolling updates within the 7 "Echo" line; Parrot publishes no end-of-life dates.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 7.x (7.4) | Not checked | amd64, arm64 | Debian 13 (Parrot 7 "Echo") | echo branch (deb.parrot.sh) |

## Where its advisories live

Parrot publishes no numbered security advisories. Parrot 7 is based on Debian 13, whose own advisories are on the [Debian](/operating-systems/debian.md) page; Parrot's packages come from its repository at deb.parrot.sh.

## How it patches

Package manager: `apt` and `dpkg`.

Parrot's documentation recommends `parrot-upgrade` (or the graphical `parrot-updater`) over a bare `apt` upgrade.

```sh
sudo apt update
sudo parrot-upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `dpkg-query -W 'linux-image-*'` | Installed kernel image packages and their versions |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 7.x (7.4) | `ID=parrot` | Not checked on a running system |

## Hardening

- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)

## On the Intelligence Hub

The library's vocabulary id for Parrot OS is `product:parrot-os`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Parrot documentation](https://parrotsec.org/docs/)
- [Parrot download](https://parrotsec.org/download/)
- [Parrot 7.4 release notes](https://parrotsec.org/blog/2026-10-03-parrot-7.4-release-notes/)
- [Upgrade to Parrot 7 from Parrot 6](https://parrotsec.org/docs/configuration/upgrade-from-lorykeet/)

<!-- os-pages:end -->
