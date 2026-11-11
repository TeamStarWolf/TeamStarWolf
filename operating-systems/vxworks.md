<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Wind River VxWorks

> Wind River's real-time operating system, with certification editions such as VxWorks Cert and VxWorks 653, built into embedded products by device makers.

Part of [Operating systems](/operating-systems/README.md) (Embedded and real-time systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| VxWorks | None | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Not confirmed (see note) |

- VxWorks: Wind River's lifecycle pages are on its support network and were not checked for this page.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| VxWorks | Not checked | Not checked | Wind River | Device maker's firmware updates |

## Where its advisories live

- [Wind River Security Center](https://www.windriver.com/security).
- [Wind River safety and security notices](https://support2.windriver.com/index.php?page=security-notices).

The Security Center lists alerts and links an alerts RSS feed on support2.windriver.com, which answered an automated request with a script challenge, so open it in a browser. A VxWorks fix reaches a product only through its maker's firmware.

## How it patches

Package manager: None; the device maker builds VxWorks into its firmware.

## Identify the version

No identify command is listed: Wind River's pages opened for this page describe the product, not a version command. On a product, the maker's firmware version is what to track.

## Hardening

- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Wind River VxWorks is `product:vxworks`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Wind River.

Vendor and project pages read for this page (2026-11-04):

- [VxWorks](https://www.windriver.com/products/embedded/vxworks)
- [Wind River Security Center](https://www.windriver.com/security)
- [Wind River safety and security notices](https://support2.windriver.com/index.php?page=security-notices)

<!-- os-pages:end -->
