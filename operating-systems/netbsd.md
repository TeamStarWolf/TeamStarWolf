<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# NetBSD

> A BSD operating system built to run on many hardware platforms, with third-party software from pkgsrc.

Part of [Operating systems](/operating-systems/README.md) (BSD family). Support dates come from the [endoflife.date](https://endoflife.date/netbsd) API (`https://endoflife.date/api/netbsd.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 11 | None | 2026-07-30 | 11.1 | Not published | Not published | Not published | No date published |
| 10 | None | 2024-03-28 | 10.2 | 2026-07-30 | Not published | Not published | No date published |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 11 | Not checked | amd64, evbarm, evbmips, evbppc, hpcarm, i386, sparc64, xen | Independent | NetBSD 11.x series |
| 10 | Not checked | amd64, evbarm, evbmips, evbppc, hpcarm, i386, sparc64, xen | Independent | NetBSD 10.x series |

## Where its advisories live

- [NetBSD Security Advisories](https://www.netbsd.org/support/security/): IDs take the form `NetBSD-SAYYYY-NNN` (for example `NetBSD-SA2024-002`). Machine-readable: [Advisory archive (signed text files)](https://ftp.netbsd.org/pub/NetBSD/security/advisories/).
- [pkgsrc vulnerabilities list](https://cdn.netbsd.org/pub/NetBSD/packages/vulns/pkg-vulnerabilities.gz).

Supported releases are the 11.x and 10.x series; fixes to them appear in the next release of the same series. Advisories for releases that are no longer supported stay in the release archive.

## How it patches

Package manager: `sysinst` or `sysupgrade` (base system) and pkgsrc packages.

The NetBSD Guide upgrades the base system with `sysinst` from release media, or with `sysupgrade` (from pkgsrc/sysutils/sysupgrade), which fetches the new kernel and distribution sets; it warns that the running kernel must never be older than userland.

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `uname -r` | Operating system release |
| `uname -p` | Machine processor architecture name |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Hardening

- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Vulnerability management (learning path)](/disciplines/vulnerability-management.md)

## On the Intelligence Hub

The library's vocabulary id for NetBSD is `product:netbsd`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; The NetBSD Foundation publishes the base system under a BSD licence.

Vendor and project pages read for this page (2026-11-03):

- [NetBSD releases](https://www.netbsd.org/releases/)
- [NetBSD security](https://www.netbsd.org/support/security/)
- [Platforms supported by NetBSD](https://www.netbsd.org/ports/)
- [The NetBSD Guide: upgrading NetBSD](https://www.netbsd.org/docs/guide/en/chap-upgrading.html)
- [uname(1)](https://man.netbsd.org/uname.1)
- [endoflife.date API](https://endoflife.date/api/netbsd.json)

<!-- os-pages:end -->
