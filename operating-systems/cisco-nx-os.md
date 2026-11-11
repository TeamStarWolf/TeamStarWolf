<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Cisco NX-OS

> Cisco's operating system for Nexus data-centre switches and MDS storage switches, in standalone and ACI modes.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 10.x (standalone) | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |

- 10.x (standalone): Cisco publishes end-of-sale and end-of-life bulletins on www.cisco.com, which refused automated requests (HTTP 403) when this page was built; open Cisco's End-of-Life Policy page on www.cisco.com in a browser.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 10.x (standalone) | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |

## Where its advisories live

- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x): IDs take the form `cisco-sa-<name>-<suffix>` (for example `cisco-sa-napi-rce-r2shwu2j`). Machine-readable: [RSS feed](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml), [PSIRT openVuln API (needs a Cisco API key)](https://developer.cisco.com/docs/psirt/).

Cisco's vulnerability policy lists RSS and CSAF as the machine-readable formats and the openVuln API for programmatic queries; the Cisco Software Checker returns the advisories that affect a given release. Cisco's product, end-of-life and command-reference pages on www.cisco.com refused automated requests (HTTP 403) when this page was built, as did the CSAF provider metadata, so open those in a browser.

## How it patches

Package manager: None; upgrades install a new NX-OS software image.

Each advisory points to the Cisco Software Checker for the first fixed release; releases are written like 10.4(4) for Nexus 3000 standalone and 16.0(8e) for ACI mode.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `show version` | Software and BIOS versions of the switch (advisories filter it, for example show version \| include BIOS) |

From Cisco security advisories for NX-OS; the NX-OS command reference refused automated requests (HTTP 403).

## Security relevance

NX-OS runs Nexus data-center switching, so it is core infrastructure whose compromise affects every workload behind it. The exposed surface is the management plane and the device software itself, where a foothold gives configuration theft and a durable implant on gear that is rarely re-imaged. Restricting management access and tracking the device like any other patchable asset are the main controls; see the network protocols reference below.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)

## On the Intelligence Hub

The library's vocabulary id for Cisco NX-OS is `product:cisco-nx-os`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Cisco.

Vendor and project pages read for this page (2026-11-04):

- [Cisco Security Vulnerability Policy](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html)
- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/)
- [Cisco Software Checker](https://sec.cloudapps.cisco.com/security/center/softwarechecker.x)
- [Cisco NX-OS Software NX-API Remote Code Execution Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-napi-rce-r2shwu2j)
- [Cisco NX-OS Software image signature advisory (show version)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-image-sig-bypas-pQDRQvjL)

<!-- os-pages:end -->
