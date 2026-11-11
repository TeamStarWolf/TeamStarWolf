<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# KVM hosts on RHEL and Ubuntu

> The Linux kernel's KVM hypervisor with QEMU and libvirt, run on a general-purpose distribution and patched with that distribution's packages.

Part of [Operating systems](/operating-systems/README.md) (Hypervisors and Kubernetes node images). Support dates come from the [endoflife.date](https://endoflife.date/) API (`https://endoflife.date/api/rhel.json`, `https://endoflife.date/api/ubuntu.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| On RHEL 10 | None | 2025-05-20 | 10.2 | 2030-05-31 | 2035-05-31 | 2039-05-31 | Supported |
| On RHEL 9 | None | 2022-05-18 | 9.8 | 2027-05-31 | 2032-05-31 | 2036-05-31 | Supported |
| On Ubuntu 24.04 LTS | None | 2024-04-25 | 24.04.5 | 2029-05-31 | 2029-05-31 | 2034-04-25 | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| On RHEL 10 | Not checked | Not checked | Red Hat Enterprise Linux 10 | Host distribution security updates |
| On RHEL 9 | Not checked | Not checked | Red Hat Enterprise Linux 9 | Host distribution security updates |
| On Ubuntu 24.04 LTS | Not checked | Not checked | Ubuntu 24.04 LTS | Host distribution security updates |

## Where its advisories live

- [Red Hat Security Advisories (RHSA)](https://access.redhat.com/errata-search/): IDs take the form `RHSA-YYYY:NNNN`.
- [Ubuntu Security Notices (USN)](https://ubuntu.com/security/notices): IDs take the form `USN-NNNN-N`. Machine-readable: [RSS](https://ubuntu.com/security/notices/rss.xml).

Search the host's advisories for the kernel, qemu, and libvirt packages.

## How it patches

Package manager: The host distribution's (`dnf` on RHEL, `apt` on Ubuntu).

KVM is part of the host kernel, and QEMU and libvirt are ordinary packages, so the host's own security advisories cover them; see the [Red Hat Enterprise Linux](/operating-systems/rhel.md) and [Ubuntu](/operating-systems/ubuntu.md) pages for the patch commands and support dates.

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `kvm-ok` | Whether the CPU supports the virtualisation extensions KVM needs (Ubuntu; from the cpu-checker package) |
| `virsh version` | libvirt, the hypervisor, and their versions (virsh is libvirt's command line) |

From Ubuntu Server's libvirt documentation (kvm-ok) and the libvirt virsh manual (virsh version); Red Hat's virtualisation guides refused automated requests (HTTP 403) when this page was built.

## Security relevance

KVM is the Linux kernel hypervisor, usually driven through QEMU and libvirt, so it is the virtualization boundary rather than an application host. The key risk is a guest-to-host escape through emulated device code in QEMU, which breaks the boundary between tenants. The host is the trust anchor, so patching QEMU and the kernel and constraining the management path are the core controls.

## Hardening

- [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for KVM hosts on RHEL and Ubuntu is `product:kvm`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; KVM is part of the Linux kernel (GPL-2.0), and QEMU and libvirt carry their own open-source licences.

Vendor and project pages read for this page (2026-11-04):

- [Ubuntu Server: libvirt](https://documentation.ubuntu.com/server/how-to/virtualisation/libvirt/)
- [virsh(1) manual (libvirt)](https://www.libvirt.org/manpages/virsh.html)
- [endoflife.date API (RHEL)](https://endoflife.date/api/rhel.json)
- [endoflife.date API (Ubuntu)](https://endoflife.date/api/ubuntu.json)

<!-- os-pages:end -->
