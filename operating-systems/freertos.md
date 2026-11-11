<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# FreeRTOS

> An open-source real-time kernel for microcontrollers, maintained with Amazon Web Services, with long-term support (LTS) libraries.

Part of [Operating systems](/operating-systems/README.md) (Embedded and real-time systems). endoflife.date does not track this system and no vendor page confirmed an end-of-life date, so the support columns say so; the notes under the table say where to look.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Kernel V11 | None | Not applicable | V11.3.3 | Not applicable | Not applicable | Not applicable | Not confirmed (see note) |

- Kernel V11: The FreeRTOS LTS page loads its support periods with scripts, so no dates were confirmed; open it in a browser. ([source](https://www.freertos.org/Documentation/03-Libraries/01-Library-overview/03-LTS-libraries/01-LTS-libraries))

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Kernel V11 | Not checked | Not checked | Independent | FreeRTOS-Kernel releases on GitHub |

## Where its advisories live

- [FreeRTOS-Kernel security advisories](https://github.com/FreeRTOS/FreeRTOS-Kernel/security): IDs take the form `GHSA-xxxx-xxxx-xxxx` (for example `GHSA-56j9-g43f-8g6v`).

Advisories are published as GitHub Security Advisories on the kernel repository; reports go to the AWS vulnerability reporting page or aws-security@amazon.com.

## How it patches

Package manager: None; the kernel is compiled into the device firmware.

Firmware picks up a fix by moving to a fixed FreeRTOS-Kernel release and rebuilding; the latest release when this page was built was V11.3.3.

## Identify the version

No identify command is listed: FreeRTOS has no shell. The kernel version is set at build time in the firmware's source tree.

## Hardening

- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Reverse Engineering Reference](/REVERSE_ENGINEERING_REFERENCE.md)
- [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for FreeRTOS is `product:freertos`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Free and open source; see the LICENSE file in the FreeRTOS-Kernel repository.

Vendor and project pages read for this page (2026-11-04):

- [FreeRTOS-Kernel security](https://github.com/FreeRTOS/FreeRTOS-Kernel/security)
- [FreeRTOS-Kernel releases](https://github.com/FreeRTOS/FreeRTOS-Kernel/releases)
- [FreeRTOS LTS libraries](https://www.freertos.org/Documentation/03-Libraries/01-Library-overview/03-LTS-libraries/01-LTS-libraries)

<!-- os-pages:end -->
