<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Cisco IOS XE

> Cisco's operating system for Catalyst switches and other enterprise platforms; Cisco publishes its advisories alongside periodic security hardening releases.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). Support dates come from the [endoflife.date](https://endoflife.date/cisco-ios-xe) API (`https://endoflife.date/api/cisco-ios-xe.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 26.1 | None | 2026-06-03 | Not published | Not published | Not published | Not published | No date published |
| 17.18 | None | 2025-08-08 | Not published | 2028-02-08 | 2029-08-08 | Not published | Supported |
| 17.15 | None | 2024-08-09 | Not published | 2027-03-30 | 2028-09-30 | Not published | Supported |
| 17.12 | None | 2023-07-28 | Not published | 2026-03-30 | 2027-09-30 | Not published | Security support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 26.1 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| 17.18 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| 17.15 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| 17.12 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |

## Where its advisories live

- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x): IDs take the form `cisco-sa-<name>-<suffix>` (for example `cisco-sa-napi-rce-r2shwu2j`). Machine-readable: [RSS feed](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml), [PSIRT openVuln API (needs a Cisco API key)](https://developer.cisco.com/docs/psirt/).

Cisco's vulnerability policy lists RSS and CSAF as the machine-readable formats and the openVuln API for programmatic queries; the Cisco Software Checker returns the advisories that affect a given release. Cisco's product, end-of-life and command-reference pages on www.cisco.com refused automated requests (HTTP 403) when this page was built, as did the CSAF provider metadata, so open those in a browser.

## How it patches

Package manager: None; upgrades install a new IOS XE software image.

IOS XE has no package manager for security fixes: each advisory names the first fixed release per train, and the device is upgraded to an image at or after it.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `show version` | The system banner with the IOS XE release and the installed image name |

From Cisco security advisories, which tell administrators to log in and use show version to find the running release; the IOS XE command reference refused automated requests (HTTP 403).

## Security relevance

IOS XE runs enterprise and carrier routing and switching, so it is infrastructure that sits in the middle of the network rather than an endpoint. Internet-reachable management has a history of pre-authentication exploitation in the wild, and a foothold there yields configuration, credentials, and a persistent implant on a device few teams monitor. The control is to keep the management plane off untrusted networks and patch promptly; see the network protocols reference below.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)

## On the Intelligence Hub

The library's vocabulary id for Cisco IOS XE is `product:cisco-ios-xe`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Cisco.

Vendor and project pages read for this page (2026-11-04):

- [Cisco Security Vulnerability Policy](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html)
- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/)
- [Cisco Software Checker](https://sec.cloudapps.cisco.com/security/center/softwarechecker.x)
- [Cisco IOS and IOS XE Software Smart Install advisory (show version)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2)
- [Cisco IOS XE Software Security Hardening Release: August 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ)
- [endoflife.date API](https://endoflife.date/api/cisco-ios-xe.json)

<!-- os-pages:end -->
