<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Debian

> A distribution built and maintained by the volunteers of the Debian Project, and the base that Kali Linux and Parrot OS build on.

Part of [Operating systems](/operating-systems/README.md) (Debian family). Support dates come from the [endoflife.date](https://endoflife.date/debian) API (`https://endoflife.date/api/debian.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 13 | trixie | 2025-08-09 | 13.7 | 2028-08-09 | 2030-06-30 | 2035-06-30 | Supported |
| 12 | bookworm | 2023-06-10 | 12.15 | 2026-07-11 | 2028-06-30 | 2033-06-30 | Security support only |
| 11 | bullseye | 2021-08-14 | 11.11 | 2024-08-14 | 2026-08-31 | 2031-06-30 | Extended support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 13 | Linux 6.12 series | amd64, arm64, armhf, ppc64el, riscv64, s390x | Independent | Debian security team (DSA) |
| 12 | Linux 6.1 series | amd64, arm64, armel, armhf, i386, mipsel, mips64el, ppc64el, s390x | Independent | Debian security team (DSA), then the LTS team (DLA) |
| 11 | Linux 5.10 series | amd64, i386, arm64, armhf | Independent | Third-party extended LTS only |

## Where its advisories live

- [Debian Security Advisories (DSA)](https://www.debian.org/security/): IDs take the form `DSA-NNNN-N` (for example `DSA-6606-1`). Machine-readable: [RDF feed](https://www.debian.org/security/dsa.rdf).
- [Debian LTS Advisories (DLA)](https://www.debian.org/lts/security/): IDs take the form `DLA-NNNN-N` (for example `DLA-4879-1`). Machine-readable: [RDF feed](https://www.debian.org/lts/security/dla.rdf).
- [Debian Security Tracker](https://security-tracker.debian.org/tracker/): IDs take the form `CVE-YYYY-NNNN`. Machine-readable: [JSON export](https://security-tracker.debian.org/tracker/data/json).

The tracker lists each CVE's status per suite: stable, testing, unstable, and backports.

## How it patches

Package manager: `apt` and `dpkg`.

A release gets security fixes from the Debian security team during its regular support years, then from the LTS team during its Long Term Support years; paid extended LTS from third parties runs after that (Debian release pages).

```sh
sudo apt update
sudo apt upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/debian_version` | Point release, for example `12.15` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `dpkg-query -W 'linux-image-*'` | Installed kernel image packages and their versions |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 13 | `ID=debian`, `VERSION_ID=13` | Not checked on a running system |
| 12 | `ID=debian`, `VERSION_ID=12` | Not checked on a running system |
| 11 | `ID=debian`, `VERSION_ID=11` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Debian:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Debian is `product:debian`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Debian releases](https://www.debian.org/releases/)
- [Debian security information](https://www.debian.org/security/)
- [Debian LTS security advisories](https://www.debian.org/lts/security/)
- [Debian 13 (trixie) release information](https://www.debian.org/releases/trixie/)
- [Debian 13 release notes: what's new](https://www.debian.org/releases/trixie/release-notes/whats-new.en.html)
- [Debian 12 (bookworm) release information](https://www.debian.org/releases/bookworm/)
- [Debian 12 release notes: what's new](https://www.debian.org/releases/bookworm/amd64/release-notes/ch-whats-new.en.html)
- [Debian 11 (bullseye) release information](https://www.debian.org/releases/bullseye/)

<!-- os-pages:end -->
