<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Oracle Linux

> Oracle's distribution, free to download, that follows Red Hat Enterprise Linux releases and ships Oracle's Unbreakable Enterprise Kernel (UEK) beside the Red Hat Compatible Kernel (RHCK).

Part of [Operating systems](/operating-systems/README.md) (Red Hat Enterprise Linux family). Support dates come from the [endoflife.date](https://endoflife.date/oracle-linux) API (`https://endoflife.date/api/oracle-linux.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 10 | None | 2025-06-26 | 10.1 | Not published | 2035-06-30 | 2038-06-30 | Supported |
| 9 | None | 2022-07-06 | 9.8 | Not published | 2032-06-30 | 2035-06-30 | Supported |
| 8 | None | 2019-07-19 | 8.10 | Not published | 2029-07-31 | 2032-07-31 | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 10 | UEK 8 (6.12) by default; RHCK 6.12.0-55 | x86_64 (x86-64-v3), aarch64 | Red Hat Enterprise Linux 10 | ELSA errata |
| 9 | UEK R7 (5.15) by default; RHCK 5.14.0-70 | x86_64 (x86-64-v2), aarch64 | Red Hat Enterprise Linux 9 | ELSA errata |
| 8 | RHCK 4.18.0-80 at 8.0 | x86_64, aarch64 | Red Hat Enterprise Linux 8 | ELSA errata |

## Where its advisories live

- [Oracle Linux Security Advisories (ELSA)](https://linux.oracle.com/security/): IDs take the form `ELSA-YYYY-NNNNN` (for example `ELSA-2026-93975`). Machine-readable: [OVAL](https://linux.oracle.com/security/oval/).

## How it patches

Package manager: `dnf` and `rpm`.

New installations boot UEK by default on x86_64, and the aarch64 platform runs UEK only (Oracle Linux 9 and 10 release notes). Check which one is running with `uname -r`: UEK releases carry `uek` in the name.

```sh
sudo dnf check-update
sudo dnf upgrade --security
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/oracle-release` | Release name and minor version |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel kernel-uek` | Installed RHCK and UEK kernel packages |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 10 | `ID=ol`, `VERSION_ID=10.x` | Not checked on a running system |
| 9 | `ID=ol`, `VERSION_ID=9.x` | Not checked on a running system |
| 8 | `ID=ol`, `VERSION_ID=8.x` | Not checked on a running system |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

Case studies that discuss Oracle Linux:

- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Oracle Linux is `product:oracle-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Available to download for free from the Oracle Linux yum server; the packages are open-source licensed.

Vendor and project pages read for this page (2026-11-03):

- [Oracle Linux security](https://linux.oracle.com/security/)
- [Oracle Linux OVAL definitions](https://linux.oracle.com/security/oval/)
- [Oracle Linux yum server](https://yum.oracle.com/)
- [Oracle Linux 10 release notes (PDF)](https://docs.oracle.com/en/operating-systems/oracle-linux/10/relnotes10.0/OL10-RELNOTES-10-0.pdf)
- [Oracle lifetime support policy (PDF)](https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf)
- [Oracle Linux 9 release notes (PDF)](https://docs.oracle.com/en/operating-systems/oracle-linux/9/relnotes9.0/OL9-RELNOTES-9-0.pdf)
- [Oracle Linux 8 release notes (PDF)](https://docs.oracle.com/en/operating-systems/oracle-linux/8/relnotes8.0/OL8-RELNOTES8-0.pdf)
- [Oracle Linux 8 repositories](https://yum.oracle.com/oracle-linux-8.html)

<!-- os-pages:end -->
