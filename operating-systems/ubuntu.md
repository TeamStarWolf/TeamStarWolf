<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Ubuntu

> Canonical's distribution, with interim releases every six months and a long-term support (LTS) release every two years; the catalog tracks the LTS releases.

Part of [Operating systems](/operating-systems/README.md) (Debian family). Support dates come from the [endoflife.date](https://endoflife.date/ubuntu) API (`https://endoflife.date/api/ubuntu.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 26.04 LTS | resolute | 2026-04-23 | 26.04.1 | 2031-05-29 | 2031-05-29 | 2036-04-23 | Supported |
| 24.04 LTS | noble | 2024-04-25 | 24.04.5 | 2029-05-31 | 2029-05-31 | 2034-04-25 | Supported |
| 22.04 LTS | jammy | 2022-04-21 | 22.04.5 | 2024-09-30 | 2027-06-01 | 2032-04-21 | Security support only |
| 20.04 LTS | focal | 2020-04-23 | 20.04.6 | 2022-10-01 | 2025-05-31 | 2030-04-23 | Extended support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 26.04 LTS | Linux 7.0 (GA kernel) | amd64, arm64, armhf, ppc64el, riscv64, s390x | Debian (the Universe archive draws on Debian and the Ubuntu community) | Standard security maintenance |
| 24.04 LTS | Linux 6.8 (GA kernel) | amd64, arm64, armhf, ppc64el, riscv64, s390x | Debian (the Universe archive draws on Debian and the Ubuntu community) | Standard security maintenance |
| 22.04 LTS | Linux 5.15 (GA kernel) | amd64, arm64, armhf, ppc64el, riscv64, s390x | Debian (the Universe archive draws on Debian and the Ubuntu community) | Standard security maintenance |
| 20.04 LTS | Linux 5.4 (GA kernel) | amd64, arm64, armhf, ppc64el, riscv64, s390x | Debian (the Universe archive draws on Debian and the Ubuntu community) | Expanded Security Maintenance (Ubuntu Pro) |

## Where its advisories live

- [Ubuntu Security Notices (USN)](https://ubuntu.com/security/notices): IDs take the form `USN-NNNN-N` (for example `USN-8994-1`). Machine-readable: [RSS](https://ubuntu.com/security/notices/rss.xml), [OVAL](https://security-metadata.canonical.com/oval/).

## How it patches

Package manager: `apt` and `dpkg`.

When standard security maintenance ends, an LTS release keeps getting fixes through Expanded Security Maintenance (ESM), which needs an Ubuntu Pro subscription (Ubuntu release cycle page). The kernel version column is the release's GA kernel; hardware enablement (HWE) kernels move later point releases to newer series.

```sh
sudo apt update
sudo apt upgrade
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
| 26.04 LTS | `ID=ubuntu`, `VERSION_ID=26.04` | Not checked on a running system |
| 24.04 LTS | `ID=ubuntu`, `VERSION_ID=24.04` | Not checked on a running system |
| 22.04 LTS | `ID=ubuntu`, `VERSION_ID=22.04` | Not checked on a running system |
| 20.04 LTS | `ID=ubuntu`, `VERSION_ID=20.04` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Ubuntu:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Ubuntu is `product:ubuntu`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free to download; Expanded Security Maintenance past the standard window needs an Ubuntu Pro subscription.

Vendor and project pages read for this page (2026-11-03):

- [Ubuntu release cycle](https://ubuntu.com/about/release-cycle)
- [Ubuntu kernel lifecycle and enablement stack](https://ubuntu.com/kernel/lifecycle)
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)
- [Expanded Security Maintenance](https://ubuntu.com/security/esm)
- [Ubuntu 26.04 LTS release notes](https://documentation.ubuntu.com/release-notes/26.04/)

<!-- os-pages:end -->
