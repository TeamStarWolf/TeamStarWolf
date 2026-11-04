<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Fortinet FortiOS

> The operating system of Fortinet FortiGate firewalls.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). Support dates come from the [endoflife.date](https://endoflife.date/fortios) API (`https://endoflife.date/api/fortios.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 8.0 | None | 2026-04-21 | Not published | 2029-04-21 | 2030-10-21 | Not published | Supported |
| 7.6 | None | 2024-07-25 | Not published | 2028-07-25 | 2030-01-25 | Not published | Supported |
| 7.4 | None | 2023-05-11 | Not published | 2027-05-11 | 2028-11-11 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 8.0 | Not checked | Not checked | Independent | FortiGuard firmware updates (image upgrade) |
| 7.6 | Not checked | Not checked | Independent | FortiGuard firmware updates (image upgrade) |
| 7.4 | Not checked | Not checked | Independent | FortiGuard firmware updates (image upgrade) |

## Where its advisories live

- [FortiGuard PSIRT advisories](https://www.fortiguard.com/psirt): IDs take the form `FG-IR-YY-NNN` (for example `FG-IR-26-182`). Machine-readable: [RSS feed](https://filestore.fortinet.com/fortiguard/rss/ir.xml).

The PSIRT list covers all Fortinet products; filter it to FortiOS. The RSS feed declares CSAF and CVRF namespaces for the machine-readable copies.

## How it patches

Package manager: None; upgrades install a new FortiOS firmware image.

From FortiOS 7.2.0 each image carries a maturity tag, Feature or Mature, shown next to the version in the GUI and CLI; FortiOS can also upgrade itself automatically from FortiGuard.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `get system status` | System status, including the firmware version and build |
| `Dashboard > Status (GUI)` | The Firmware field of the System Information widget, with build number and the Mature or Feature tag |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)
- [Fortinet](/platforms/fortinet.md)

## On the Intelligence Hub

The library's vocabulary id for Fortinet FortiOS is `product:fortios`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Fortinet.

Vendor and project pages read for this page (2026-11-04):

- [FortiGuard PSIRT advisories](https://www.fortiguard.com/psirt)
- [FortiOS 7.6 administration guide: firmware maturity levels](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/173707/firmware-maturity-levels)
- [FortiOS 7.6 administration guide: enabling automatic firmware upgrades](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/369092/enabling-automatic-firmware-upgrades)
- [endoflife.date API](https://endoflife.date/api/fortios.json)

<!-- os-pages:end -->
