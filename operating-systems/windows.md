<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Windows

> Microsoft's client operating system: Windows 11 in the General Availability and Long-Term Servicing channels, and Windows 10, whose support has ended outside the paid Extended Security Updates program and the LTSC editions.

Part of [Operating systems](/operating-systems/README.md) (Windows). Support dates come from the [endoflife.date](https://endoflife.date/windows) API (`https://endoflife.date/api/windows.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 11 26H2 (Home and Pro) | None | 2026-09-29 | 10.0.26300 | 2028-10-10 | 2028-10-10 | Not published | Supported |
| 11 26H2 (Enterprise and Education) | None | 2026-09-29 | 10.0.26300 | 2029-10-09 | 2029-10-09 | Not published | Supported |
| 11 25H2 (Home and Pro) | None | 2025-09-30 | 10.0.26200 | 2027-10-12 | 2027-10-12 | Not published | Supported |
| 11 25H2 (Enterprise and Education) | None | 2025-09-30 | 10.0.26200 | 2028-10-10 | 2028-10-10 | Not published | Supported |
| 11 24H2 (Enterprise and Education) | None | 2024-10-01 | 10.0.26100 | 2027-10-12 | 2027-10-12 | Not published | Supported |
| 11 Enterprise LTSC 2024 (24H2) | None | 2024-10-01 | 10.0.26100 | 2029-10-09 | 2029-10-09 | Not published | Supported |
| 10 22H2 | None | 2022-10-18 | 10.0.19045 | 2025-10-14 | 2025-10-14 | 2028-10-10 | Extended support only |
| 10 Enterprise LTSC 2021 (21H2) | None | 2021-11-16 | 10.0.19044 | 2027-01-12 | 2027-01-12 | 2030-01-12 | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 11 26H2 (Home and Pro) | NT, build 26300 | x64, Arm64 | Independent | General Availability Channel |
| 11 26H2 (Enterprise and Education) | NT, build 26300 | x64, Arm64 | Independent | General Availability Channel |
| 11 25H2 (Home and Pro) | NT, build 26200 | x64, Arm64 | Independent | General Availability Channel |
| 11 25H2 (Enterprise and Education) | NT, build 26200 | x64, Arm64 | Independent | General Availability Channel |
| 11 24H2 (Enterprise and Education) | NT, build 26100 | x64, Arm64 | Independent | General Availability Channel |
| 11 Enterprise LTSC 2024 (24H2) | NT, build 26100 | x64, Arm64 | Independent | Long-Term Servicing Channel |
| 10 22H2 | NT, build 19045 | Not checked | Independent | Extended Security Updates (paid) after 2025-10-14 |
| 10 Enterprise LTSC 2021 (21H2) | NT, build 19044 | Not checked | Independent | Long-Term Servicing Channel |

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

## Security relevance

Windows is the dominant enterprise endpoint and the center of most intrusions, so it is where credential theft, lateral movement, and persistence usually play out. The surface is Active Directory domain membership, LSASS credential extraction, living-off-the-land binaries, and token and Kerberos abuse, with endpoint detection as the main control. Harden with the DISA STIG, attack surface reduction rules, LAPS, and Credential Guard; see the Windows hardening reference below.

## Hardening

- [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md)
- [Windows Hardening](/WINDOWS_HARDENING.md)
- [Windows Hardening with Group Policy](/WINDOWS_HARDENING_GPO.md)
- [PowerShell Command Reference](/commands/powershell-commands.md)
- [Windows Command Prompt Reference](/commands/windows-cmd.md)
- [Microsoft Defender](/platforms/microsoft-defender.md)

## On the Intelligence Hub

The library's vocabulary id for Windows is `product:windows`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Proprietary; licensed by Microsoft.

Vendor and project pages read for this page (2026-11-03):

- [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information)
- [Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information)
- [Extended Security Updates program for Windows 10](https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates)
- [Windows 11 specifications](https://www.microsoft.com/en-us/windows/windows-11-specifications)
- [Update release cycle for Windows clients](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle)
- [Manage additional Windows Update settings](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings)
- [What version of Windows am I running?](https://learn.microsoft.com/en-us/windows/client-management/client-tools/windows-version-search)
- [Upgrade Windows Server in place](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-in-place)
- [Get-ComputerInfo](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerinfo)
- [Get-HotFix](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix)
- [systeminfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)
- [MSRC CSAF provider metadata](https://msrc.microsoft.com/csaf/provider-metadata.json)
- [endoflife.date API](https://endoflife.date/api/windows.json)

<!-- os-pages:end -->
