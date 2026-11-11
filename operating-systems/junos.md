<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Juniper Junos OS

> Juniper Networks' operating system for its MX routers, EX and QFX switches, and SRX firewalls.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 24.4 | None | Not checked | Not checked | Not checked | Not checked | Not checked | Not confirmed (see note) |

- 24.4: Juniper's dates and milestones page loads its table with scripts and showed no dates to an automated request; open it in a browser. ([source](https://support.juniper.net/support/eol/software/junos/))

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 24.4 | Not checked | Not checked | Independent | Juniper software downloads (image upgrade) |

## Where its advisories live

- [Juniper Security Advisories (JSA)](https://supportportal.juniper.net/s/global-search/%40uri): IDs take the form `JSANNNNN` (for example `JSA75729`).

Each advisory has a short link of the form https://supportportal.juniper.net/JSA75729, and Juniper publishes them in monthly Security Bulletins (titled YYYY-MM Security Bulletin). The support portal is rendered in the browser, so open it in a browser; its CSAF provider metadata answered HTTP 401, and the Junos dates and milestones page loads its table with scripts.

## How it patches

Package manager: None; upgrades install a new Junos OS software package.

Advisories list the fixed releases per train; releases are written like 24.4R1.

## Identify it from the device CLI

| Command | What it shows |
|---|---|
| `show version` | Hostname, model, and the Junos release (for example Junos: 24.4R1.9) |
| `show version detail` | The same with component versions |

From the Junos OS CLI reference (show version), now hosted on HPE networking docs.

## Security relevance

Junos runs Juniper routers and firewalls, so it is network infrastructure whose compromise affects everything behind it. The exposed surface is the management plane and the J-Web interface, where flaws have given a foothold that yields configuration, credentials, and persistence on long-lived gear. Restricting management access and patching promptly are the main controls; see the network protocols reference below.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)

## On the Intelligence Hub

The library's vocabulary id for Juniper Junos OS is `product:junos-os`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Juniper Networks.

Vendor and project pages read for this page (2026-11-04):

- [show version (Junos OS)](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-version.html)
- [Junos OS dates and milestones](https://support.juniper.net/support/eol/software/junos/)
- [CVE-2024-21591 record (JSA75729)](https://cveawg.mitre.org/api/cve/CVE-2024-21591)

<!-- os-pages:end -->
