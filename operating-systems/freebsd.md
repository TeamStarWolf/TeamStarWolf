<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# FreeBSD

> A BSD operating system developed as one base system, kernel and userland together, with third-party software from the Ports Collection and binary packages.

Part of [Operating systems](/operating-systems/README.md) (BSD family). Support dates come from the [endoflife.date](https://endoflife.date/freebsd) API (`https://endoflife.date/api/freebsd.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 15 | None | 2025-12-02 | Not published | Not published | 2029-12-31 | Not published | Supported |
| 14 | None | 2023-11-20 | Not published | Not published | 2028-11-30 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 15 | FreeBSD 15 | amd64, aarch64, armv7, powerpc64, powerpc64le, riscv64 | Independent | stable/15 branch; releng/15.1 security branch |
| 14 | FreeBSD 14 | amd64, i386, aarch64, armv7, powerpc, powerpcspe, powerpc64, powerpc64le, riscv64 | Independent | stable/14 branch; releng/14.5 and releng/14.4 security branches |

## Where its advisories live

- [FreeBSD Security Advisories](https://www.freebsd.org/security/advisories/): IDs take the form `FreeBSD-SA-YY:NN.name` (for example `FreeBSD-SA-26:73.caroot`). Machine-readable: [RSS feed (advisories and errata notices)](https://www.freebsd.org/security/feed.xml).
- [FreeBSD Errata Notices](https://www.freebsd.org/security/notices/): IDs take the form `FreeBSD-EN-YY:NN.name` (for example `FreeBSD-EN-26:27.tcp`).
- [FreeBSD VuXML (Ports Collection)](https://vuxml.freebsd.org/freebsd/).

Advisories cover the base system and errata notices cover base-system fixes that are not security issues; problems in the Ports Collection are tracked in VuXML. No advisories are issued for the -CURRENT development branch.

## How it patches

Package manager: `freebsd-update` (base system) and `pkg` (packages).

The security page gives `freebsd-update fetch` and `freebsd-update install` for systems installed from a binary release; systems built from source update their source tree instead. Each minor release is supported for three months after the next minor release in the same branch, and each stable branch has its own end date (FreeBSD security page).

```sh
freebsd-update fetch
freebsd-update install
pkg upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `freebsd-version -kru` | Installed kernel, running kernel, and installed userland versions with patch level (a new kernel shows before the reboot) |
| `uname -r` | Release of the running kernel |
| `cat /etc/os-release` | The os-release file; on FreeBSD 13.0 and later it is a link to /var/run/os-release, generated for the running system |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Hardening

- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Vulnerability management (learning path)](/disciplines/vulnerability-management.md)

## On the Intelligence Hub

The library's vocabulary id for FreeBSD is `product:freebsd`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; the FreeBSD Project publishes the base system under BSD-style licences.

Vendor and project pages read for this page (2026-11-03):

- [FreeBSD security information](https://www.freebsd.org/security/)
- [FreeBSD security advisories](https://www.freebsd.org/security/advisories/)
- [FreeBSD errata notices](https://www.freebsd.org/security/notices/)
- [FreeBSD supported platforms](https://www.freebsd.org/platforms/)
- [freebsd-version(1)](https://man.freebsd.org/cgi/man.cgi?query=freebsd-version)
- [os-release(5)](https://man.freebsd.org/cgi/man.cgi?query=os-release)
- [uname(1)](https://man.freebsd.org/cgi/man.cgi?query=uname)
- [FreeBSD Handbook: updating and upgrading](https://docs.freebsd.org/en/books/handbook/cutting-edge/)
- [endoflife.date API](https://endoflife.date/api/freebsd.json)
- [FreeBSD 15.1-RELEASE announcement](https://www.freebsd.org/releases/15.1R/announce/)
- [FreeBSD 14.5-RELEASE announcement](https://www.freebsd.org/releases/14.5R/announce/)

<!-- os-pages:end -->
