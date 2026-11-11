<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Zephyr RTOS

> An open-source real-time operating system for microcontrollers, with releases every six months and a long-term support (LTS) release for products.

Part of [Operating systems](/operating-systems/README.md) (Embedded and real-time systems). endoflife.date does not track this system, so the support column below quotes the vendor's own statement.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 4.5 | None | 2026-10-28 | 4.5.0 | Not published | 2027-10-28 | Not published | Supported |
| 4.4 | None | 2026-04-14 | 4.4.0 | Not published | 2027-04-12 | Not published | Supported |
| 3.7 LTS | LTS3 | 2024-07-26 | 3.7.0 | Not published | 2029-07-27 | Not published | Supported |

- All versions: Release and end-of-life dates from the Zephyr releases page; Zephyr publishes no separate full-support date. ([source](https://docs.zephyrproject.org/latest/releases/index.html))

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 4.5 | Not checked | Not checked | Independent | Zephyr releases |
| 4.4 | Not checked | Not checked | Independent | Zephyr releases |
| 3.7 LTS | Not checked | Not checked | Independent | Zephyr releases |

## Where its advisories live

- [Zephyr vulnerabilities](https://docs.zephyrproject.org/latest/security/vulnerabilities.html): IDs take the form `CVE-YYYY-NNNN`.
- [Zephyr GitHub security advisories](https://github.com/zephyrproject-rtos/zephyr/security): IDs take the form `GHSA-xxxx-xxxx-xxxx`.

The vulnerabilities page lists each CVE by year, and details can follow once an embargo lifts.

## How it patches

Package manager: None; Zephyr is source code built into the firmware with West.

Major releases come every six months (April and October) and stable releases are supported for two release cycles, about a year; LTS releases are maintained for at least five years.

## Identify the version

No identify command is listed: the Zephyr version is set at build time in the firmware's source tree (West manifest).

## Security relevance

Zephyr is a modern real-time operating system for microcontrollers and connected devices, so it runs in constrained hardware that is network-reachable. Its security posture is stronger than legacy embedded kernels, with memory-protection and update features, but the network stack and the firmware update path remain the surfaces that matter. The work is secure development, signed updates, and reducing network exposure; see the firmware and IoT reference below.

## Hardening

- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Zephyr RTOS is `product:zephyr-rtos`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; see the LICENSE file in the Zephyr repository.

Vendor and project pages read for this page (2026-11-04):

- [Zephyr releases](https://docs.zephyrproject.org/latest/releases/index.html)
- [Zephyr release process](https://docs.zephyrproject.org/latest/project/release_process.html)
- [Zephyr vulnerabilities](https://docs.zephyrproject.org/latest/security/vulnerabilities.html)
- [Zephyr GitHub security](https://github.com/zephyrproject-rtos/zephyr/security)

<!-- os-pages:end -->
