<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# QNX

> BlackBerry's microkernel real-time operating system, sold as the QNX Software Development Platform (SDP) and built into embedded products by device makers.

Part of [Operating systems](/operating-systems/README.md) (Embedded and real-time systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| SDP 8.0 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |

- SDP 8.0: BlackBerry QNX lifecycle dates were not published on the pages opened for this page.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| SDP 8.0 | Not checked | Not checked | QNX microkernel | Device maker's firmware updates |

## Where its advisories live

- [BlackBerry and QNX security advisories](https://support.blackberry.com/pkb/s/topic/0TO2J000000QZxzWAG/security-advisories).

The advisory list is rendered in the browser (it now redirects through myaccount.blackberry.com), so open it in a browser. A QNX fix reaches a product only through its maker's firmware.

## How it patches

Package manager: None; the device maker builds QNX into its firmware.

## Identify the version

No identify command is listed: the QNX documentation page tried was not found (HTTP 404). On a product, the maker's firmware version is what to track.

## Security relevance

QNX is a commercial real-time operating system in vehicles, medical devices, and industrial control, so it runs in safety-critical settings where availability and integrity are paramount. It is largely C with limited isolation, which makes memory-safety flaws and firmware integrity the central concerns, and the devices are hard to patch in the field. The work is secure development, update signing, and supply-chain assurance; see the firmware and IoT reference below.

## Hardening

- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md)
- [Automotive Security Reference](/AUTOMOTIVE_SECURITY_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for QNX is `product:qnx`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by BlackBerry QNX.

Vendor and project pages read for this page (2026-11-04):

- [QNX](https://qnx.software/en)
- [QNX cybersecurity](https://qnx.software/en/services/cybersecurity)
- [BlackBerry security advisories](https://support.blackberry.com/pkb/s/topic/0TO2J000000QZxzWAG/security-advisories)

<!-- os-pages:end -->
