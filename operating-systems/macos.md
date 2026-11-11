<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# macOS

> Apple's desktop operating system, released once a year; Apple publishes security content for the current release and selected earlier ones but no end-of-life dates.

Part of [Operating systems](/operating-systems/README.md) (macOS). Support dates come from the [endoflife.date](https://endoflife.date/macos) API (`https://endoflife.date/api/macos.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 27 | Golden Gate | 2026-09-14 | 27.2 | Not published | Not published | Not published | No date published |
| 26 | Tahoe | 2025-09-15 | 26.7.2 | Not published | Not published | Not published | No date published |
| 15 | Sequoia | 2024-09-16 | 15.8.2 | Not published | Not published | Not published | No date published |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 27 | Not checked | Not checked | Independent | Software Update |
| 26 | Not checked | Not checked | Independent | Software Update |
| 15 | Not checked | Not checked | Independent | Software Update |

## Where its advisories live

- [Apple security releases](https://support.apple.com/en-us/100100): IDs take the form `CVE-YYYY-NNNNN`.

Apple does not disclose, discuss, or confirm security issues until a fix is available. The security releases page links one security-content note per update, each listing CVE IDs; the 2026-10-26 entries covered macOS Golden Gate 27.2, Tahoe 26.7.2, and Sequoia 15.8.2. Apple publishes no machine-readable feed.

## How it patches

Package manager: Software Update (System Settings > General > Software Update).

Apple recommends the latest macOS that is compatible with the Mac. Software Update finds, downloads and installs updates; organisations can enforce and defer updates through declarative device management. Apple separates minor updates, major upgrades, and Background Security Improvements.

## Identify the version

| Where to look | What it shows |
|---|---|
| Apple menu > About This Mac | Name and version of macOS; click the version number to see the build number |

From Apple Support's Find out which macOS your Mac is using; Apple's support pages opened for this page describe the menus, not command-line tools.

## Security relevance

macOS is a high-value enterprise and targeted-attack endpoint, so the surface is the user session and the platform controls around it: TCC privacy prompts, Gatekeeper, notarization, and the launch agent and daemon paths used for persistence. Attackers work around these with consent tricks, unsigned or notarization-abusing code, and persistence in user and system launch points. The Endpoint Security framework and an MDM are the main defensive hooks.

## Hardening

- [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md)
- [macOS Command Reference](/commands/macos-commands.md)

## On the Intelligence Hub

The library's vocabulary id for macOS is `product:macos`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Apple.

Vendor and project pages read for this page (2026-11-03):

- [Apple security releases](https://support.apple.com/en-us/100100)
- [Find out which macOS your Mac is using](https://support.apple.com/en-us/109033)
- [Update macOS on Mac](https://support.apple.com/en-us/108382)
- [About software updates for Apple devices](https://support.apple.com/guide/deployment/about-software-updates-depc4c80847a/web)
- [Install and enforce software updates for Apple devices](https://support.apple.com/guide/deployment/install-and-enforce-software-updates-depd30715cbb/web)
- [endoflife.date API](https://endoflife.date/api/macos.json)

<!-- os-pages:end -->
