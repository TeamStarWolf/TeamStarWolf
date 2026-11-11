<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Proxmox VE

> A Debian-based virtualisation platform for KVM virtual machines and containers, managed from a web interface or the command line.

Part of [Operating systems](/operating-systems/README.md) (Hypervisors and Kubernetes node images). Support dates come from the [endoflife.date](https://endoflife.date/proxmox-ve) API (`https://endoflife.date/api/proxmox-ve.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 9 | None | 2025-08-05 | 9.2 | Not published | Not published | Not published | No date published |
| 8 | None | 2023-06-22 | 8.4 | Not published | 2026-08-31 | Not published | Ended |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 9 | Not checked | x86_64, aarch64 (NVIDIA Grace Hopper and Vera platforms) | Debian 13 (trixie) | Proxmox VE package repositories |
| 8 | Not checked | x86_64, aarch64 (NVIDIA Grace Hopper and Vera platforms) | Debian 12 (bookworm) | Proxmox VE package repositories |

## Where its advisories live

- [Proxmox VE security advisories (forum)](https://forum.proxmox.com/forums/security-advisories.26/). Machine-readable: [RSS feed](https://forum.proxmox.com/forums/security-advisories.26/index.rss).

Proxmox publishes advisories in its forum and does not normally assign CVEs itself. The Debian base gets its fixes from the Debian security team, listed on the [Debian](/operating-systems/debian.md) page.

## How it patches

Package manager: `apt` and `dpkg`.

Proxmox VE uses a rolling release model on top of Debian; use `apt full-upgrade` (or the web interface), because a plain `apt upgrade` can leave a partly upgraded system.

```sh
apt update
apt full-upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `pveversion` | Installed Proxmox VE version (the 8 to 9 upgrade guide expects 8.4.1 or newer before upgrading) |
| `egrep '(vmx\|svm)' /proc/cpuinfo` | Whether an x86 CPU has the virtualisation extensions KVM needs |

From the vendor documentation cited at the foot of this page; not run on a host for this page.

## Security relevance

Proxmox VE is an open virtualization and container platform managed through a web interface and API, so it is both a hypervisor boundary and an exposed management surface. The risks combine a guest-to-host escape through QEMU with web and API exposure that, if reached, grants root over the whole cluster. Keep the management network isolated, patch QEMU and the kernel, and scope administrative access tightly.

## Hardening

- [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Homelab Setup](/HOMELAB_SETUP.md)

## On the Intelligence Hub

The library's vocabulary id for Proxmox VE is `product:proxmox-ve`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source under the GNU Affero General Public License, version 3.

Vendor and project pages read for this page (2026-11-04):

- [Proxmox VE FAQ](https://pve.proxmox.com/wiki/FAQ)
- [System software updates](https://pve.proxmox.com/wiki/System_Software_Updates)
- [Proxmox VE security reporting](https://pve.proxmox.com/wiki/Security_Reporting)
- [Upgrade from 8 to 9](https://pve.proxmox.com/wiki/Upgrade_from_8_to_9)
- [endoflife.date API](https://endoflife.date/api/proxmox-ve.json)

<!-- os-pages:end -->
