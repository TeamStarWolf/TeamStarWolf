<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# AlmaLinux

> A community distribution that follows Red Hat Enterprise Linux's major and minor releases, with the same kernel builds at each GA.

Part of [Operating systems](/operating-systems/README.md) (Red Hat Enterprise Linux family). Support dates come from the [endoflife.date](https://endoflife.date/almalinux) API (`https://endoflife.date/api/almalinux.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 10 | Purple Lion | 2025-05-27 | 10.2 | 2030-05-31 | 2035-05-31 | Not published | Supported |
| 9 | Emerald Puma | 2022-05-26 | 9.8 | 2027-05-31 | 2032-05-31 | Not published | Supported |
| 8 | Cerulean Leopard (8.10) | 2021-03-30 | 8.10 | 2024-05-31 | 2029-05-31 | Not published | Security support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 10 | Linux 6.12 (6.12.0-55 at 10.0) | x86_64, x86_64_v2, aarch64, ppc64le, s390x | Red Hat Enterprise Linux 10 | ALSA errata |
| 9 | Linux 5.14 (5.14.0-70 at 9.0) | x86_64, aarch64, ppc64le, s390x | Red Hat Enterprise Linux 9 | ALSA errata |
| 8 | Linux 4.18 (4.18.0-553 at 8.10) | x86_64, aarch64, ppc64le, s390x | Red Hat Enterprise Linux 8 | ALSA errata |

## Where its advisories live

- [AlmaLinux Security Advisories (ALSA)](https://errata.almalinux.org/): IDs take the form `ALSA-YYYY:NNNNN` (for example `ALSA-2023:5091`). Machine-readable: [OVAL](https://security.almalinux.org/oval/), [Errata JSON (AlmaLinux 9)](https://errata.almalinux.org/9/errata.full.json).

## How it patches

Package manager: `dnf` and `rpm`.

`dnf upgrade --security` applies only the updates that carry a security advisory.

```sh
sudo dnf check-update
sudo dnf upgrade --security
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/redhat-release` | Release name and minor version |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel` | Installed kernel packages; more than one means a reboot may be pending |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 10 | `ID=almalinux`, `VERSION_ID=10.x` | Not checked on a running system |
| 9 | `ID=almalinux`, `VERSION_ID=9.x` | Not checked on a running system |
| 8 | `ID=almalinux`, `VERSION_ID=8.x` | Not checked on a running system |

## Security relevance

AlmaLinux is a production server base, so it is most often met as a host an operator has already reached rather than an initial target. The security-relevant surface is the RHEL family one: SSH and sudo configuration, SUID binaries, and kernel local-privilege-escalation paths, plus the dnf and rpm supply chain. Knowing it tells a defender to measure the host against the CIS Benchmark or the matching DISA STIG and to audit it with OpenSCAP and Lynis. The hardening references below cover the baseline.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss AlmaLinux:

- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for AlmaLinux is `product:almalinux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [AlmaLinux release notes](https://wiki.almalinux.org/release-notes/)
- [AlmaLinux errata](https://errata.almalinux.org/)
- [AlmaLinux OVAL data](https://security.almalinux.org/oval/)
- [AlmaLinux 10.0 release notes](https://wiki.almalinux.org/release-notes/10.0.html)
- [AlmaLinux 9.0 release notes](https://wiki.almalinux.org/release-notes/9.0.html)
- [AlmaLinux 8.10 release notes](https://wiki.almalinux.org/release-notes/8.10.html)

<!-- os-pages:end -->
