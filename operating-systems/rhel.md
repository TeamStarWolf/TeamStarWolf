<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Red Hat Enterprise Linux

> Red Hat's commercial distribution, sold by subscription; AlmaLinux, Rocky Linux, and Oracle Linux follow its major and minor releases.

Part of [Operating systems](/operating-systems/README.md) (Red Hat Enterprise Linux family). Support dates come from the [endoflife.date](https://endoflife.date/rhel) API (`https://endoflife.date/api/rhel.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 10 | None | 2025-05-20 | 10.2 | 2030-05-31 | 2035-05-31 | 2039-05-31 | Supported |
| 9 | None | 2022-05-18 | 9.8 | 2027-05-31 | 2032-05-31 | 2036-05-31 | Supported |
| 8 | Ootpa | 2019-05-07 | 8.10 | 2024-05-31 | 2029-05-31 | 2033-05-31 | Security support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 10 | Linux 6.12 (6.12.0-55 at 10.0 GA) | x86_64, aarch64, ppc64le, s390x | Independent (Red Hat) | Full support (RHSA) |
| 9 | Linux 5.14 (5.14.0-70 at 9.0 GA) | x86_64, aarch64, ppc64le, s390x | Independent (Red Hat) | Full support (RHSA) |
| 8 | Linux 4.18 (4.18.0-80 at 8.0 GA) | x86_64, aarch64, ppc64le, s390x | Fedora 28 | Maintenance support (RHSA) |

## Where its advisories live

- [Red Hat Security Advisories (RHSA)](https://access.redhat.com/errata-search/): IDs take the form `RHSA-YYYY:NNNNN` (for example `RHSA-2026:94749`). Machine-readable: [CSAF 2.0 advisories](https://security.access.redhat.com/data/csaf/v2/advisories/), [Security Data API](https://access.redhat.com/security/data).

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
| 10 | `ID=rhel`, `VERSION_ID=10.x` | Not checked on a running system |
| 9 | `ID=rhel`, `VERSION_ID=9.x` | Not checked on a running system |
| 8 | `ID=rhel`, `VERSION_ID=8.x` | Not checked on a running system |

## Security relevance

Red Hat Enterprise Linux is the enterprise Linux standard and the common reference target for Linux hardening, so it is usually a host reached after initial access. The surface is SSH and sudo, SUID binaries, and kernel local-privilege-escalation paths, with the subscription and Satellite supply chain and SELinux enforcing by default. Measure it against the CIS Benchmark or the DISA STIG and audit with OpenSCAP; the hardening references below cover the baseline.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Red Hat Enterprise Linux:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Red Hat Enterprise Linux is `product:red-hat-enterprise-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Commercial distribution sold by subscription; the packages are open-source licensed.

Vendor and project pages read for this page (2026-11-03):

- [Red Hat Enterprise Linux release dates](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates)
- [Red Hat Enterprise Linux technology capabilities and limits](https://access.redhat.com/articles/rhel-limits)
- [Red Hat Enterprise Linux life cycle](https://access.redhat.com/support/policy/updates/errata)
- [Red Hat CSAF advisories](https://security.access.redhat.com/data/csaf/v2/advisories/)

<!-- os-pages:end -->
