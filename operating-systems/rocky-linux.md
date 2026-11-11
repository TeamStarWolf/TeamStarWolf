<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Rocky Linux

> A community distribution that follows Red Hat Enterprise Linux's major and minor releases.

Part of [Operating systems](/operating-systems/README.md) (Red Hat Enterprise Linux family). Support dates come from the [endoflife.date](https://endoflife.date/rocky-linux) API (`https://endoflife.date/api/rocky-linux.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 10 | None | 2025-06-11 | 10.2 | 2030-05-31 | 2035-05-31 | Not published | Supported |
| 9 | None | 2022-07-14 | 9.8 | 2027-05-31 | 2032-05-31 | Not published | Supported |
| 8 | None | 2021-05-01 | 8.10 | 2024-05-31 | 2029-05-31 | Not published | Security support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 10 | Linux 6.12 | x86_64 (x86-64-v3), aarch64, ppc64le, riscv64, s390x | Red Hat Enterprise Linux 10 | RLSA errata |
| 9 | Linux 5.14 | x86_64 (x86-64-v2), aarch64, ppc64le, s390x | Red Hat Enterprise Linux 9 | RLSA errata |
| 8 | Linux 4.18 | x86_64, aarch64 | Red Hat Enterprise Linux 8 | RLSA errata |

## Where its advisories live

- [Rocky Linux Security Advisories (RLSA)](https://errata.rockylinux.org/): IDs take the form `RLSA-YYYY:NNNNN` (for example `RLSA-2026:93442`). Machine-readable: [Apollo errata service](https://apollo.build.resf.org/).

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
| 10 | `ID=rocky`, `VERSION_ID=10.x` | Not checked on a running system |
| 9 | `ID=rocky`, `VERSION_ID=9.x` | Not checked on a running system |
| 8 | `ID=rocky`, `VERSION_ID=8.x` | Not checked on a running system |

## Security relevance

Rocky Linux is a RHEL rebuild used as a production server base, so its foothold surface is identical to RHEL: SSH and sudo, SUID binaries, kernel escalation, the dnf and rpm supply chain, and SELinux enforcing by default. It is typically a host reached on the way to a service rather than the entry point. Measure it against the CIS Benchmark and audit with OpenSCAP; the hardening references below cover the baseline.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Rocky Linux:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Rocky Linux is `product:rocky-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Rocky Linux errata](https://errata.rockylinux.org/)
- [Rocky Linux documentation](https://docs.rockylinux.org/)
- [Rocky Linux 10.0 release notes](https://docs.rockylinux.org/releases/release_notes/10_0/)
- [Rocky Linux 10 BaseOS repository](https://dl.rockylinux.org/pub/rocky/10/BaseOS/)
- [Rocky Linux 9.0 release notes](https://docs.rockylinux.org/releases/release_notes/9_0/)
- [Rocky Linux 9 BaseOS repository](https://dl.rockylinux.org/pub/rocky/9/BaseOS/)
- [Rocky Linux 8.10 release notes](https://docs.rockylinux.org/releases/release_notes/8_10/)
- [Rocky Linux 8 BaseOS repository](https://dl.rockylinux.org/pub/rocky/8/BaseOS/)

<!-- os-pages:end -->
