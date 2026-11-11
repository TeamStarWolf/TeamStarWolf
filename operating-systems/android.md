<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Android

> Google's open-source mobile operating system (AOSP), shipped on devices by many manufacturers, whose security fixes are published in a monthly bulletin and delivered as security patch levels.

Part of [Operating systems](/operating-systems/README.md) (Mobile operating systems). Support dates come from the [endoflife.date](https://endoflife.date/android) API (`https://endoflife.date/api/android.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 17 (API level 37) | Cinnamon Bun | 2026-06-16 | Not published | Not published | Not published | Not published | No date published |
| 16 (API level 36) | Baklava | 2025-06-10 | Not published | Not published | Not published | Not published | No date published |
| 15 (API level 35) | Vanilla Ice Cream | 2024-09-03 | Not published | Not published | Not published | Not published | No date published |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 17 (API level 37) | Not checked | Not checked | AOSP | Device maker's system updates |
| 16 (API level 36) | Not checked | Not checked | AOSP | Device maker's system updates |
| 15 (API level 35) | Not checked | Not checked | AOSP | Device maker's system updates |

## Where its advisories live

- [Android Security Bulletins](https://source.android.com/docs/security/bulletin/asb-overview): IDs take the form `A-NNNNNNNNN` (for example `A-486464711`).
- [Pixel Update Bulletins](https://source.android.com/docs/security/bulletin/pixel).

Bulletins are published on the first Monday of each month (the next work day when that Monday is a holiday), each with two patch levels, YYYY-MM-01 and YYYY-MM-05. Each issue carries a CVE and an Android bug ID (A-) and lists the updated AOSP versions; the November 2026 bulletin listed 14, 15, 16, 16-qpr2, and 17. Device and chipset makers publish their own bulletins too.

## How it patches

Package manager: System updates from the device maker; Google Play system updates.

Fixes listed in the bulletin come from AOSP, the upstream Linux kernel, and chipset makers. A device is covered once its security patch level is at or after the bulletin's level (for example 2026-11-05 for the November 2026 bulletin); when and whether a device gets that level is up to its manufacturer.

## Identify the version

| Where to look | What it shows |
|---|---|
| Settings > About phone (or About tablet) > Android version | Android version, Android security update (the patch level), Google Play system update, and build number |

From Google's Check and update your Android version help page.

## Security relevance

Android is reached as the device and the application rather than a server, so the surface is the app sandbox, the APK, and the permissions it requests. Attackers repackage apps, abuse over-broad permissions, and deliver mobile malware, while rooting removes the platform's own isolation. A reviewer pulls the APK and inspects it the way the mobile security reference below describes; managed deployments add an MDM and Play Protect.

## Hardening

- [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md)
- [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md)
- [Cloud, SaaS and Mobile Forensics](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Android is `product:android`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

The Android Open Source Project is open source; device builds add the maker's own components.

Vendor and project pages read for this page (2026-11-03):

- [Android Security Bulletins](https://source.android.com/docs/security/bulletin/asb-overview)
- [Android Security Bulletin, November 2026](https://source.android.com/docs/security/bulletin/2026/2026-11-01)
- [Android security and update bulletins](https://source.android.com/docs/security/bulletin)
- [Codenames, tags, and build numbers](https://source.android.com/docs/setup/reference/build-numbers)
- [Check and update your Android version](https://support.google.com/android/answer/7680439)
- [endoflife.date API](https://endoflife.date/api/android.json)

<!-- os-pages:end -->
