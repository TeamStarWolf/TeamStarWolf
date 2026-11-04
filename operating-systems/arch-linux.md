<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Arch Linux

> An independently developed x86-64 distribution that follows a rolling release model and installs a minimal base the user builds up.

Part of [Operating systems](/operating-systems/README.md) (Independent distributions). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Rolling | None | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Rolling release |

- Rolling: There are no numbered versions to reach end of life; staying current is the support model.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Rolling | Latest stable upstream (`linux` 7.2.14 in core on the fetch date) | x86_64 | Independent | Official repositories (core, extra) |

## Where its advisories live

- [Arch Linux Security Advisories (ASA)](https://security.archlinux.org/advisory): IDs take the form `ASA-YYYYMM-N` (for example `ASA-202506-10`). Machine-readable: [Atom](https://security.archlinux.org/advisory/feed.atom).

The tracker also groups CVEs into issues with AVG ids (for example `AVG-2905`). On 2026-11-03 the newest advisory in the list was ASA-202506-10, dated 22 June 2025, so the issue pages are the more current view.

## How it patches

Package manager: `pacman`.

Upgrade the whole system with `pacman -Syu`; partial upgrades (refreshing the package lists without upgrading) are unsupported (ArchWiki, pacman).

```sh
sudo pacman -Syu
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `pacman -Q linux` | Installed `linux` kernel package version |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Rolling | `ID=arch`, `BUILD_ID=rolling` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Arch Linux:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)

## On the Intelligence Hub

The library's vocabulary id for Arch Linux is `product:arch-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [About Arch Linux](https://archlinux.org/about/)
- [ArchWiki: Arch Linux](https://wiki.archlinux.org/title/Arch_Linux)
- [ArchWiki: pacman](https://wiki.archlinux.org/title/Pacman)
- [Arch Linux security tracker advisories](https://security.archlinux.org/advisory)
- [linux package in core](https://archlinux.org/packages/core/x86_64/linux/)

<!-- os-pages:end -->
