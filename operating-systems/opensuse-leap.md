<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# openSUSE Leap

> The openSUSE community's regular-release distribution, built on the SUSE Linux Enterprise core.

Part of [Operating systems](/operating-systems/README.md) (SUSE family). Support dates come from the [endoflife.date](https://endoflife.date/opensuse) API (`https://endoflife.date/api/opensuse.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 16.0 | None | 2025-10-01 | Not published | Not published | 2027-10-31 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 16.0 | Not checked | x86_64, aarch64, ppc64le, s390x | SUSE Linux Enterprise 16.0 | openSUSE and SUSE maintenance updates |

## Where its advisories live

- [openSUSE security updates (openSUSE-SU)](https://www.suse.com/support/update/): IDs take the form `openSUSE-SU-YYYY:NNNNN-N` (for example `openSUSE-SU-2026:22207-1`). Machine-readable: [CSAF 2.0](https://ftp.suse.com/pub/projects/security/csaf/), [OVAL](https://ftp.suse.com/pub/projects/security/oval/).
- [SUSE security updates (SUSE-SU)](https://www.suse.com/support/update/): IDs take the form `SUSE-SU-YYYY:NNNN-N` (for example `SUSE-SU-2026:5086-1`). Machine-readable: [CSAF 2.0](https://ftp.suse.com/pub/projects/security/csaf/), [OVAL](https://ftp.suse.com/pub/projects/security/oval/).

Leap 16.0 fixes appear as openSUSE-SU advisories and in SUSE-SU advisories for the shared SUSE Linux Enterprise packages; each CSAF file lists the products it applies to.

## How it patches

Package manager: `zypper` and `rpm`.

Each Leap minor release gets 24 months of community maintenance (Leap 16.0 release notes).

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
| 16.0 | `ID=opensuse-leap`, `VERSION_ID=16.0` | Not checked on a running system |

## Security relevance

openSUSE Leap is a stable SUSE-family server and workstation base, so it is usually a host reached after initial access rather than the entry point. The surface is the standard Linux one of SSH, sudo, SUID, and kernel escalation, with the zypper and RPM supply chain and AppArmor enforcing by default. Measure it against the CIS Benchmark and audit with OpenSCAP; the hardening references below cover the baseline.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for openSUSE Leap is `product:opensuse-leap`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [openSUSE Leap 16.0 release notes (text)](https://doc.opensuse.org/release-notes/x86_64/openSUSE/Leap/16.0/release-notes-leap-160.txt)
- [Get openSUSE Leap 16.0](https://get.opensuse.org/leap/16.0/)
- [SUSE CSAF advisories](https://ftp.suse.com/pub/projects/security/csaf/)

<!-- os-pages:end -->
