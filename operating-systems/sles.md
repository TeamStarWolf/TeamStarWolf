<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# SUSE Linux Enterprise Server

> SUSE's commercial distribution, sold by subscription, with service packs inside each major version.

Part of [Operating systems](/operating-systems/README.md) (SUSE family). Support dates come from the [endoflife.date](https://endoflife.date/sles) API (`https://endoflife.date/api/sles.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 16.0 | None | 2025-11-04 | Not published | Not published | 2027-11-30 | 2030-11-30 | Supported |
| 15 SP7 | None | 2025-06-17 | Not published | Not published | 2031-07-31 | 2034-07-31 | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 16.0 | Not checked | x86_64, aarch64, ppc64le, s390x | Independent (SUSE) | SUSE-SU patches |
| 15 SP7 | Linux 6.4 | x86_64, aarch64, ppc64le, s390x | Independent (SUSE) | SUSE-SU patches |

## Where its advisories live

- [SUSE security updates (SUSE-SU)](https://www.suse.com/support/update/): IDs take the form `SUSE-SU-YYYY:NNNN-N` (for example `SUSE-SU-2026:5086-1`). Machine-readable: [CSAF 2.0](https://ftp.suse.com/pub/projects/security/csaf/), [OVAL](https://ftp.suse.com/pub/projects/security/oval/).

## How it patches

Package manager: `zypper` and `rpm`.

`zypper patch` installs the patches published as advisories; `zypper list-patches --category security` lists the pending security ones.

```sh
sudo zypper refresh
sudo zypper patch
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel-default` | Installed default kernel packages |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 16.0 | `ID=sles`, `VERSION_ID=16.0` | Not checked on a running system |
| 15 SP7 | `ID=sles`, `VERSION_ID=15.7` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss SUSE Linux Enterprise Server:

- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for SUSE Linux Enterprise Server is `product:suse-linux-enterprise-server`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Commercial distribution sold by subscription; the packages are open-source licensed.

Vendor and project pages read for this page (2026-11-03):

- [SUSE Linux Enterprise Server 16.0 release notes](https://documentation.suse.com/releasenotes/sles/html/releasenotes_sles_16.0/index.html)
- [SUSE product support lifecycle](https://www.suse.com/lifecycle/)
- [SUSE update advisories](https://www.suse.com/support/update/)
- [SUSE Linux Enterprise Server 15 SP7 release notes](https://www.suse.com/releasenotes/x86_64/SUSE-SLES/15-SP7/index.html)

<!-- os-pages:end -->
