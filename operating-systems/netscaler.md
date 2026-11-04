<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# NetScaler ADC and Gateway

> The application delivery controller and remote-access gateway firmware formerly sold as Citrix ADC and Citrix Gateway.

Part of [Operating systems](/operating-systems/README.md) (Network operating systems). endoflife.date does not track this system, so the support column below quotes the vendor's own statement.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 14.1 | None | 2023-08-08 | Not published | 2029-08-08 | 2030-08-08 | Not published | Supported |
| 13.1 | None | 2021-09-15 | Not published | 2026-09-15 | 2027-09-15 | Not published | Security support only |

- All versions: Citrix product matrix: End of Maintenance (EOM) is in the full support column and End of Life (EOL) in the security support column. ([source](https://www.citrix.com/support/product-lifecycle/product-matrix.html))

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 14.1 | Not checked | Not checked | Independent | NetScaler firmware builds |
| 13.1 | Not checked | Not checked | Independent | NetScaler firmware builds |

## Where its advisories live

- [Citrix and NetScaler security bulletins](https://support.citrix.com/securitybulletins): IDs take the form `CTXNNNNNN` (for example `CTX693420`).

The bulletin site is rendered in the browser, so open it in a browser; CVE records link each bulletin as a support.citrix.com article by its CTX number.

## How it patches

Package manager: None; upgrades install a new NetScaler firmware build.

Fixes ship as firmware builds written as release and build, for example 14.1 47.46.

## Identify it from the device CLI

No identify command is listed: the NetScaler command reference redirected automated requests to its home page when this page was built. Compare the release and build the appliance reports with the fixed builds in each bulletin.

## Hardening

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)
- [Citrix NetScaler](/platforms/citrix-netscaler.md)

## On the Intelligence Hub

The library's vocabulary id for NetScaler ADC and Gateway is `product:citrix-netscaler`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by NetScaler (formerly part of Citrix).

Vendor and project pages read for this page (2026-11-04):

- [Citrix product matrix](https://www.citrix.com/support/product-lifecycle/product-matrix.html)
- [NetScaler security updates for CVE-2025-6543 and CVE-2025-5777](https://www.netscaler.com/blogs/2025-06/netscaler-critical-security-updates-for-cve-2025-6543-and-cve-2025-5777)
- [CVE-2025-5777 record (CTX693420)](https://cveawg.mitre.org/api/cve/CVE-2025-5777)

<!-- os-pages:end -->
