<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# OpenWrt

> An open-source Linux distribution for routers and other embedded network devices.

Part of [Operating systems](/operating-systems/README.md) (Embedded and real-time systems). Support dates come from the [endoflife.date](https://endoflife.date/openwrt) API (`https://endoflife.date/api/openwrt.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 25.12 | None | 2026-03-06 | 25.12.6 | Not published | Not published | Not published | No date published |
| 24.10 | None | 2025-02-06 | 24.10.8 | 2026-03-05 | 2026-09-30 | Not published | Ended |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 25.12 | Not checked | Not checked | Linux | OpenWrt release series |
| 24.10 | Not checked | Not checked | Linux | OpenWrt release series |

## Where its advisories live

- [OpenWrt security advisories](https://openwrt.org/advisory/start).
- [OpenWrt security policy (GitHub)](https://github.com/openwrt/openwrt/security).

openwrt.org answered automated requests with a bot check when this page was built, so open the advisory list in a browser; the GitHub security policy and the release downloads were reachable.

## How it patches

Package manager: `apk` or `opkg` (both packages are in the 24.10 and 25.12 source trees).

OpenWrt's security policy says a release series stops getting security fixes once it reaches end of life, recommends the latest minor release or a recent snapshot, and notes that not every security fix gets a CVE or advisory. Firmware upgrades use sysupgrade images from downloads.openwrt.org.

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/openwrt_release` | DISTRIB_RELEASE, DISTRIB_TARGET, and DISTRIB_ARCH for the running firmware |
| `cat /usr/lib/os-release` | os-release fields plus OPENWRT_BOARD, OPENWRT_ARCH, and OPENWRT_RELEASE |

From the OpenWrt source tree (package/base-files templates for both files); not run on a device for this page.

## Hardening

- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md)
- [Security Gadgets Reference](/SECURITY_GADGETS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for OpenWrt is `product:openwrt`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; see the LICENSE file in the OpenWrt repository.

Vendor and project pages read for this page (2026-11-04):

- [OpenWrt security policy](https://github.com/openwrt/openwrt/security)
- [OpenWrt release downloads](https://downloads.openwrt.org/releases/)
- [OpenWrt latest release (v25.12.6)](https://github.com/openwrt/openwrt/releases/tag/v25.12.6)
- [base-files: os-release template (25.12)](https://raw.githubusercontent.com/openwrt/openwrt/openwrt-25.12/package/base-files/files/usr/lib/os-release)
- [base-files: openwrt_release template (25.12)](https://raw.githubusercontent.com/openwrt/openwrt/openwrt-25.12/package/base-files/files/etc/openwrt_release)
- [endoflife.date API](https://endoflife.date/api/openwrt.json)

<!-- os-pages:end -->
