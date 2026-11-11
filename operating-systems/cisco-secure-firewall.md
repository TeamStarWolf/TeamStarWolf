<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Cisco Secure Firewall ASA and FTD

> Cisco's firewall software: Adaptive Security Appliance (ASA) Software and Secure Firewall Threat Defense (FTD), which Cisco covers in joint advisories.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| ASA 9.24 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| ASA 9.22 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| ASA 9.20 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| FTD 10.1 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| FTD 7.7 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| FTD 7.6 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |
| FTD 7.4 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |

- All versions: Cisco publishes end-of-sale and end-of-life bulletins on www.cisco.com, which refused automated requests (HTTP 403) when this page was built; open Cisco's End-of-Life Policy page on www.cisco.com in a browser.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| ASA 9.24 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| ASA 9.22 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| ASA 9.20 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| FTD 10.1 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| FTD 7.7 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| FTD 7.6 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |
| FTD 7.4 | Not checked | Not checked | Independent | Cisco software downloads (image upgrade) |

## Where its advisories live

- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x): IDs take the form `cisco-sa-<name>-<suffix>` (for example `cisco-sa-napi-rce-r2shwu2j`). Machine-readable: [RSS feed](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml), [PSIRT openVuln API (needs a Cisco API key)](https://developer.cisco.com/docs/psirt/).

Cisco's vulnerability policy lists RSS and CSAF as the machine-readable formats and the openVuln API for programmatic queries; the Cisco Software Checker returns the advisories that affect a given release. Cisco's product, end-of-life and command-reference pages on www.cisco.com refused automated requests (HTTP 403) when this page was built, as did the CSAF provider metadata, so open those in a browser.

## How it patches

Package manager: None; upgrades install a new ASA or FTD image (FTD through the Firewall Management Center or Device Manager).

Advisories give a first fixed release per train for ASA and for FTD; the October 2026 advisories listed ASA trains 9.16 through 9.24 and FTD trains 7.0 through 10.1.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `show version` | ASA software and Device Manager versions (advisories filter it with show version \| include Version) |

The ASA command is from Cisco security advisories. No FTD command is listed: the FTD command reference refused automated requests (HTTP 403), so check the release in the Firewall Management Center or open that reference in a browser.

## Security relevance

Cisco Secure Firewall (ASA and FTD) is the perimeter and the remote-access VPN, which makes it a top initial-access target. Remote-access VPN endpoints have repeatedly been hit with pre-authentication flaws and with credential spraying against exposed portals. Treating the appliance as a monitored, promptly patched asset rather than only a control is the lesson; see the network protocols reference below.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)

## On the Intelligence Hub

The library's vocabulary id for Cisco Secure Firewall ASA and FTD is `product:cisco-secure-firewall`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Cisco.

Vendor and project pages read for this page (2026-11-04):

- [Cisco Security Vulnerability Policy](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html)
- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/)
- [Cisco Software Checker](https://sec.cloudapps.cisco.com/security/center/softwarechecker.x)
- [Cisco ASA Software advisory, 2018 (show version)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180129-asa1)
- [Cisco Secure Firewall ASA and FTD Software Remote Access SSL VPN Tunnel Denial of Service Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75)

<!-- os-pages:end -->
