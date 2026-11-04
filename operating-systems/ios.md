<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# iOS

> Apple's operating system for iPhone (with iPadOS for iPad), released once a year and updated over the air.

Part of [Operating systems](/operating-systems/README.md) (Mobile operating systems). Support dates come from the [endoflife.date](https://endoflife.date/ios) API (`https://endoflife.date/api/ios.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 27 | None | 2026-09-14 | 27.2 | Not published | Not published | Not published | No date published |
| 26 | None | 2025-09-15 | 26.7.2 | 2026-09-14 | Not published | Not published | No date published |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 27 | Not checked | Not checked | Independent | Software Update (over the air) |
| 26 | Not checked | Not checked | Independent | Software Update (over the air) |

## Where its advisories live

- [Apple security releases](https://support.apple.com/en-us/100100): IDs take the form `CVE-YYYY-NNNNN`.

The security releases page links one security-content note per update. Apple keeps shipping security updates to some earlier releases: the 2026-10-26 list included iOS 27.2, iOS 26.7.2, and iOS 18.7.11. Apple publishes no end-of-life dates and no machine-readable feed.

## How it patches

Package manager: Software Update (Settings > General > Software Update).

Apple Support's update steps: back up, connect to power and Wi-Fi, then Settings > General > Software Update > Download and Install. Supervised devices can be held back with time-based deferrals and required to meet a minimum version at enrolment.

## Identify the version

| Where to look | What it shows |
|---|---|
| Settings > General > Software Update | The installed iOS or iPadOS version and whether an update is available |

From Apple Support's Update your iPhone or iPad.

## Hardening

- [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md)
- [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md)
- [Cloud, SaaS and Mobile Forensics](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for iOS is `product:ios`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Apple.

Vendor and project pages read for this page (2026-11-03):

- [Apple security releases](https://support.apple.com/en-us/100100)
- [Update your iPhone or iPad](https://support.apple.com/en-us/118575)
- [Install and enforce software updates for Apple devices](https://support.apple.com/guide/deployment/install-and-enforce-software-updates-depd30715cbb/web)
- [endoflife.date API](https://endoflife.date/api/ios.json)

<!-- os-pages:end -->
