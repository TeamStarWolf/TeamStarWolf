<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# OpenBSD

> A BSD operating system that ships a new release about every six months and backports security fixes to the two most recent releases.

Part of [Operating systems](/operating-systems/README.md) (BSD family). Support dates come from the [endoflife.date](https://endoflife.date/openbsd) API (`https://endoflife.date/api/openbsd.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 8.0 | None | 2026-10-20 | Not published | Not published | 2027-11-01 | Not published | Supported |
| 7.9 | None | 2026-05-19 | Not published | Not published | 2027-06-01 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 8.0 | Not checked | alpha, amd64, arm64, armv7, hppa, i386, landisk, luna88k, macppc, octeon, powerpc64, riscv64, sparc64 | Independent | syspatch binary patches |
| 7.9 | Not checked | alpha, amd64, arm64, armv7, hppa, i386, landisk, luna88k, macppc, octeon, powerpc64, riscv64, sparc64 | Independent | syspatch binary patches |

## Where its advisories live

- [OpenBSD errata](https://www.openbsd.org/errata.html): IDs take the form `NNN_name` (for example `005_dbupdate`).

Each release has its own errata page (for example errata80.html for 8.0); each erratum is numbered and named after the patch it ships. OpenBSD publishes no machine-readable feed; fixes are also announced on the announce mailing list.

## How it patches

Package manager: `syspatch` (base system) and `pkg_add` (packages).

`syspatch` fetches, verifies and installs the binary patches for the base system and keeps a rollback tarball; binary patches exist for amd64, arm64 and i386, and other platforms follow -stable from source. `pkg_add -u` updates installed packages (OpenBSD FAQ).

```sh
syspatch
pkg_add -u
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `uname -r` | Operating system release, in the form digit.digit |
| `syspatch -l` | Installed binary patches |
| `syspatch -c` | Available patches not yet installed |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Security relevance

OpenBSD is built around proactive security and ships hardened defaults, pledge and unveil, and the origin of OpenSSH, so it commonly runs firewalls, VPN endpoints, and other exposed roles. Its value as a reference is the design stance: reduce privilege and surface before a flaw is found rather than after. It is still a host with SSH and privilege boundaries, but the platform assumes far less about the trustworthiness of the code it runs.

## Hardening

- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Vulnerability management (learning path)](/disciplines/vulnerability-management.md)

## On the Intelligence Hub

The library's vocabulary id for OpenBSD is `product:openbsd`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; the OpenBSD Project prefers ISC and BSD-style licences for the base system.

Vendor and project pages read for this page (2026-11-03):

- [OpenBSD errata and patches](https://www.openbsd.org/errata.html)
- [OpenBSD security](https://www.openbsd.org/security.html)
- [OpenBSD platforms](https://www.openbsd.org/plat.html)
- [syspatch(8)](https://man.openbsd.org/syspatch)
- [uname(1)](https://man.openbsd.org/uname)
- [OpenBSD FAQ: system management](https://www.openbsd.org/faq/faq10.html)
- [OpenBSD FAQ: packages and ports](https://www.openbsd.org/faq/faq15.html)
- [endoflife.date API](https://endoflife.date/api/openbsd.json)
- [OpenBSD 8.0](https://www.openbsd.org/80.html)
- [OpenBSD 8.0 errata](https://www.openbsd.org/errata80.html)
- [OpenBSD 7.9](https://www.openbsd.org/79.html)
- [OpenBSD 7.9 errata](https://www.openbsd.org/errata79.html)

<!-- os-pages:end -->
