<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Palo Alto Networks PAN-OS

> The operating system of Palo Alto Networks next-generation firewalls and Panorama.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). Support dates come from the [endoflife.date](https://endoflife.date/panos) API (`https://endoflife.date/api/panos.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 12.2 | None | 2026-07-30 | 12.2.4-h1 | Not published | 2029-07-30 | Not published | Supported |
| 12.1 | None | 2025-08-28 | 12.1.10-h3 | Not published | 2028-08-28 | Not published | Supported |
| 11.2 | None | 2024-05-02 | 11.2.16-h1 | Not published | 2027-05-02 | Not published | Supported |
| 11.1 | None | 2023-11-03 | 11.1.16-h4 | Not published | 2027-05-03 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 12.2 | Not checked | Not checked | Independent | Palo Alto Networks software updates (image upgrade) |
| 12.1 | Not checked | Not checked | Independent | Palo Alto Networks software updates (image upgrade) |
| 11.2 | Not checked | Not checked | Independent | Palo Alto Networks software updates (image upgrade) |
| 11.1 | Not checked | Not checked | Independent | Palo Alto Networks software updates (image upgrade) |

## Where its advisories live

- [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/): IDs take the form `CVE-YYYY-NNNN or PAN-SA-YYYY-NNNN`. Machine-readable: [RSS feed](https://security.paloaltonetworks.com/rss.xml), [JSON feed](https://security.paloaltonetworks.com/json/).

Each advisory page lists the affected PAN-OS trains and CPE names; the JSON feed carries the same records with severity and product fields.

## How it patches

Package manager: None; upgrades install a new PAN-OS software image (with hotfix releases such as -h1).

Advisories name the fixed maintenance or hotfix release per train, for example 11.1.2-h3.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `show system info` | Device details, including model, serial, and the sw-version field with the PAN-OS release |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Security relevance

PAN-OS runs Palo Alto Networks firewalls, so it sits on the perimeter and its GlobalProtect VPN portal and management interface are high-value targets with pre-authentication flaws exploited in the wild. A foothold on the firewall yields policy, credentials, and a vantage point over all traffic it inspects. Keep the management interface off untrusted networks and patch urgently; see the network protocols reference below.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)
- [Palo Alto Networks](/platforms/palo-alto-networks.md)

## On the Intelligence Hub

The library's vocabulary id for Palo Alto Networks PAN-OS is `product:pan-os`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Palo Alto Networks.

Vendor and project pages read for this page (2026-11-04):

- [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/)
- [CVE-2024-3400 advisory](https://security.paloaltonetworks.com/CVE-2024-3400)
- [PAN-OS CLI quick start: view settings and statistics](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/view-settings-and-statistics)
- [endoflife.date API](https://endoflife.date/api/panos.json)

<!-- os-pages:end -->
