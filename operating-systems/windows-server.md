<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Windows Server

> Microsoft's server operating system, released in the Long-Term Servicing Channel every two to three years with five years of mainstream and five of extended support, plus a faster Annual Channel aimed at containers and microservices.

Part of [Operating systems](/operating-systems/README.md) (Windows). Support dates come from the [endoflife.date](https://endoflife.date/windows-server) API (`https://endoflife.date/api/windows-server.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 2025 | None | 2024-11-01 | 10.0.26100 | 2029-11-13 | 2034-11-14 | Not published | Supported |
| 2022 | None | 2021-08-18 | 10.0.20348 | 2026-10-13 | 2031-10-14 | Not published | Security support only |
| 2019 (1809) | None | 2018-11-13 | 10.0.17763 | 2024-01-09 | 2029-01-09 | Not published | Security support only |
| 2016 (1607) | None | 2016-10-15 | 10.0.14393 | 2022-01-11 | 2027-01-12 | 2030-01-12 | Security support only |
| 23H2 (Annual Channel) | None | 2023-10-24 | 10.0.25398 | 2026-05-12 | 2026-05-12 | Not applicable | Ended |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 2025 | NT, build 26100 | x64 | Independent | Long-Term Servicing Channel |
| 2022 | NT, build 20348 | x64 | Independent | Long-Term Servicing Channel |
| 2019 (1809) | NT, build 17763 | x64 | Independent | Long-Term Servicing Channel |
| 2016 (1607) | NT, build 14393 | x64 | Independent | Long-Term Servicing Branch |
| 23H2 (Annual Channel) | NT, build 25398 | x64 | Independent | Annual Channel |

## Where its advisories live

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide): IDs take the form `CVE-YYYY-NNNNN`. Machine-readable: [CVRF API, one document per monthly release](https://api.msrc.microsoft.com/cvrf/v3.0/updates), [CSAF provider metadata](https://msrc.microsoft.com/csaf/provider-metadata.json), [CSAF advisories directory](https://msrc.microsoft.com/csaf/advisories/).

The Update Guide is a page rendered in the browser, so open it in a browser; the CVRF API names each monthly release YYYY-Mon (for example 2026-Oct), and the CSAF provider metadata points at the advisory and VEX directories. Updates themselves are identified by KB article number.

## How it patches

Package manager: Windows Update (cumulative updates, identified by KB number).

Microsoft publishes a cumulative monthly security update on the second Tuesday of each month (about 10:00 AM Pacific Time), an optional non-security preview in the fourth week, and out-of-band updates as needed. Devices take them from Windows Update, configured by Group Policy or mobile device management (MDM).

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `winver` | Version and OS build dialog |
| `systeminfo \| findstr /B /C:"OS Name" /B /C:"OS Version"` | OS Name and OS Version lines |
| `slmgr /dlv` | Detailed licensing information; an LTSC build shows an edition such as EnterpriseS |
| `Get-ComputerInfo -Property WindowsBuildLabEx,WindowsEditionID` | Build lab string and edition ID |
| `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' \| Select-Object BuildLabEx,EditionID` | The BuildLabEx and EditionID registry values under the key Microsoft's in-place upgrade guide names |
| `Get-HotFix` | Installed updates (hotfixes) by KB number |

From Microsoft documentation (What version of Windows am I running?, the in-place upgrade guide, and the Get-ComputerInfo and Get-HotFix references); not run on a Windows host for this page. The registry command reads the key that the upgrade guide tells you to open in Registry Editor.

## Hardening

- [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md)
- [Windows Hardening](/WINDOWS_HARDENING.md)
- [Windows Hardening with Group Policy](/WINDOWS_HARDENING_GPO.md)
- [PowerShell Command Reference](/commands/powershell-commands.md)
- [Windows Command Prompt Reference](/commands/windows-cmd.md)
- [Microsoft Defender](/platforms/microsoft-defender.md)
- [Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Windows Server is `product:windows-server`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Microsoft.

Vendor and project pages read for this page (2026-11-03):

- [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
- [Windows Server servicing channels](https://learn.microsoft.com/en-us/windows-server/get-started/servicing-channels-comparison)
- [Windows Server hardware requirements](https://learn.microsoft.com/en-us/windows-server/get-started/hardware-requirements)
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
