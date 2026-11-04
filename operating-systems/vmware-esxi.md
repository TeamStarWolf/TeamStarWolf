<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# VMware ESXi

> Broadcom's bare-metal hypervisor (VMware vSphere), whose advisories moved to the Broadcom support portal.

Part of [Operating systems](/operating-systems/README.md) (Hypervisors and Kubernetes node images). Support dates come from the [endoflife.date](https://endoflife.date/esxi) API (`https://endoflife.date/api/esxi.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 9.1 | None | 2026-05-12 | 9.1.1.0 | Not published | 2028-08-12 | Not published | Supported |
| 9.0 | None | 2025-06-17 | 9.0.2.0100 | Not published | 2027-09-17 | Not published | Supported |
| 8.0 | None | 2022-10-11 | 8.0 Update 3k | Not published | 2027-10-11 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 9.1 | Not checked | Not checked | Independent | Broadcom support portal downloads |
| 9.0 | Not checked | Not checked | Independent | Broadcom support portal downloads |
| 8.0 | Not checked | Not checked | Independent | Broadcom support portal downloads |

## Where its advisories live

- [VMware Security Advisories (Broadcom)](https://support.broadcom.com/web/ecx/security-advisory?segment=VC).

Broadcom's advisory list and each advisory are rendered in the browser, so open them in a browser; CVE records link each advisory by a numeric content ID (for example 25390 for CVE-2025-22224). The older www.vmware.com advisories page now redirects to Broadcom.

## How it patches

Package manager: None; patches install ESXi image profiles or updates (managed through vCenter).

Fixes ship as ESXi updates and patches named by release and build, for example ESXi80U3d-24585383 (from the CVE-2025-22224 record).

## Identify it from the device CLI

No identify command is listed: the Broadcom ESXi command reference was not reachable at the address tried (HTTP 404) when this page was built.

## Hardening

- [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)

## On the Intelligence Hub

The library's vocabulary id for VMware ESXi is `product:vmware-esxi`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Broadcom.

Vendor and project pages read for this page (2026-11-04):

- [Broadcom VMware security advisories](https://support.broadcom.com/web/ecx/security-advisory?segment=VC)
- [VMware Security Advisories (redirect)](https://www.broadcom.com/support/vmware-security-advisories)
- [CVE-2025-22224 record](https://cveawg.mitre.org/api/cve/CVE-2025-22224)
- [endoflife.date API](https://endoflife.date/api/esxi.json)

<!-- os-pages:end -->
