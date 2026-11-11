<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Microsoft Hyper-V

> Microsoft's hypervisor, a role of Windows Server and a feature of Windows 10 and 11, patched with the host operating system.

Part of [Operating systems](/operating-systems/README.md) (Hypervisors and Kubernetes node images). Support dates come from the [endoflife.date](https://endoflife.date/windows-server) API (`https://endoflife.date/api/windows-server.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| On Windows Server 2025 | None | 2024-11-01 | 10.0.26100 | 2029-11-13 | 2034-11-14 | Not published | Supported |
| On Windows Server 2022 | None | 2021-08-18 | 10.0.20348 | 2026-10-13 | 2031-10-14 | Not published | Security support only |
| On Windows Server 2019 | None | 2018-11-13 | 10.0.17763 | 2024-01-09 | 2029-01-09 | Not published | Security support only |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| On Windows Server 2025 | NT, build 26100 | x64 | Windows Server 2025 | Windows Update |
| On Windows Server 2022 | NT, build 20348 | x64 | Windows Server 2022 | Windows Update |
| On Windows Server 2019 | NT, build 17763 | x64 | Windows Server 2019 | Windows Update |

## Where its advisories live

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide): IDs take the form `CVE-YYYY-NNNNN`. Machine-readable: [CVRF API, one document per monthly release](https://api.msrc.microsoft.com/cvrf/v3.0/updates), [CSAF provider metadata](https://msrc.microsoft.com/csaf/provider-metadata.json), [CSAF advisories directory](https://msrc.microsoft.com/csaf/advisories/).

The Update Guide is a page rendered in the browser, so open it in a browser; the CVRF API names each monthly release YYYY-Mon (for example 2026-Oct), and the CSAF provider metadata points at the advisory and VEX directories. Updates themselves are identified by KB article number.

## How it patches

Package manager: Windows Update (as part of the host's cumulative updates).

Microsoft publishes a cumulative monthly security update on the second Tuesday of each month (about 10:00 AM Pacific Time), an optional non-security preview in the fourth week, and out-of-band updates as needed. Devices take them from Windows Update, configured by Group Policy or mobile device management (MDM).

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `Systeminfo.exe` | The Hyper-V requirements section: every item Yes means the host can run the Hyper-V role |
| `winver` | Version and OS build dialog |
| `systeminfo \| findstr /B /C:"OS Name" /B /C:"OS Version"` | OS Name and OS Version lines |

From Microsoft documentation (Hyper-V host hardware requirements and What version of Windows am I running?); not run on a Windows host for this page.

## Hardening

- [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure](/ENTERPRISE_INFRASTRUCTURE.md)
- [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Microsoft Hyper-V is `product:hyper-v`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; part of Windows and Windows Server, licensed by Microsoft.

Vendor and project pages read for this page (2026-11-04):

- [Hyper-V virtualization in Windows Server and Windows](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/overview)
- [Hyper-V host hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)
- [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
- [Update release cycle for Windows clients](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle)
- [Manage additional Windows Update settings](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings)
- [What version of Windows am I running?](https://learn.microsoft.com/en-us/windows/client-management/client-tools/windows-version-search)
- [Upgrade Windows Server in place](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-in-place)
- [Get-ComputerInfo](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerinfo)
- [Get-HotFix](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix)
- [systeminfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)
- [MSRC CSAF provider metadata](https://msrc.microsoft.com/csaf/provider-metadata.json)
- [endoflife.date API](https://endoflife.date/api/windows-server.json)

<!-- os-pages:end -->
