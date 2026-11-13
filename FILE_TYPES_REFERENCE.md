# File Types and Extensions Reference

A file extension is a hint, not a fact. It is the last part of a name that the sender chose, and Windows uses it to look up a handler in the registry, Outlook and Gmail use it to decide what to block, and people use it to decide what to trust. The bytes inside decide what the file actually is: a magic number at a fixed offset tells a parser that a file is a ZIP archive, an ELF executable or a SQLite database whatever it is called. The handler decides what happens when the file is opened, and the same `.xml` text is inert in an editor and runs script in an XSLT host. Provenance decides how much the operating system trusts it: Windows records where a download came from in the Mark of the Web, macOS in a quarantine attribute, and both drop that signal more often than most defenders expect. Every abuse on this page sits in the gap between those four answers, and every control on this page closes part of that gap.

> Scope: How operating systems, mail gateways, browsers and web servers decide what a file is; a catalog of common and uncommon extensions across Windows, macOS, Linux, mobile, firmware, web, cloud, machine learning, email and databases, with the dated record of abuse for each; the evidence formats responders collect; and the controls and detections that act on file type. Written at advisory level: names, identifiers, dates, products and versions, never payloads or crafted-file recipes.
> Mapped to MITRE ATT&CK T1204.002 (Malicious File), T1566.001 (Spearphishing Attachment), T1553.005 (Mark-of-the-Web Bypass), T1036.007 (Double File Extension), T1036.008 (Masquerade File Type), T1027.006 (HTML Smuggling), CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-646 (Reliance on File Name or Extension of Externally-Supplied File) and D3FEND D3-FFV (File Format Verification).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

SOC analysts, incident responders, email and endpoint administrators, and detection engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 104 min (23,896 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are deciding whether an attachment or download type should be blocked, inspected or allowed, you are triaging a file by its extension, magic number or handler, or you are writing a detection or a mail and endpoint policy for a rarely seen file type

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[How a file type is decided](#how-a-file-type-is-decided), [The catalog](#the-catalog) for the family tables, [Uncommon and dangerous](#uncommon-and-dangerous) for the rarely seen types with an exploitation record

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Email Security Reference](EMAIL_SECURITY_REFERENCE.md), [Endpoint Security Reference](ENDPOINT_SECURITY_REFERENCE.md), [Malware Analysis Reference](MALWARE_ANALYSIS_REFERENCE.md), [Digital Forensics Reference](DIGITAL_FORENSICS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

---

## Table of Contents

- [How a file type is decided](#how-a-file-type-is-decided)
- [The catalog](#the-catalog)
  - [Windows executables and libraries](#windows-executables-and-libraries)
  - [Scripts and script hosts](#scripts-and-script-hosts)
  - [Shortcuts and shell items](#shortcuts-and-shell-items)
  - [Installers and packages](#installers-and-packages)
  - [Office and document formats](#office-and-document-formats)
  - [Archives and compression](#archives-and-compression)
  - [Disk images and containers](#disk-images-and-containers)
  - [Web and server-side code](#web-and-server-side-code)
  - [Configuration, secrets and keys](#configuration-secrets-and-keys)
  - [Data and interchange formats](#data-and-interchange-formats)
  - [Media, fonts and images with an exploit record](#media-fonts-and-images-with-an-exploit-record)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Mobile](#mobile)
  - [Firmware and embedded](#firmware-and-embedded)
  - [Virtualization, cloud and infrastructure as code](#virtualization-cloud-and-infrastructure-as-code)
  - [Machine learning and data science](#machine-learning-and-data-science)
  - [Email and messaging](#email-and-messaging)
  - [Databases](#databases)
- [Uncommon and dangerous](#uncommon-and-dangerous)
- [Evidence and operations formats](#evidence-and-operations-formats)
- [Controls](#controls)
- [Detections](#detections)
- [MITRE mappings](#mitre-mappings)
- [What the record overstates and understates](#what-the-record-overstates-and-understates)
- [Sources](#sources)
- [Related references](#related-references)

---

## How a file type is decided

Four mechanisms answer the question "what is this file?", and they often disagree. Read each catalog row with all four in mind.

| Mechanism | What it reads | Who uses it | How it fails |
|---|---|---|---|
| Extension | The characters after the last dot in the name | Windows shell handler lookup, mail and browser blocklists, people | The sender picks it; Explorer hides known extensions by default |
| Magic number | Fixed bytes at a known offset, often the first bytes | Loaders, parsers, libmagic, gateway true-type matching | Polyglots satisfy two signatures; some formats have no signature at byte 0 |
| Handler | The program registered or configured for the type | Windows ProgIDs, web server handler maps, Linux `execve` | A handler that runs script turns a data-looking file into code |
| Provenance mark | Mark of the Web on Windows, `com.apple.quarantine` on macOS | SmartScreen, Office macro blocking, Gatekeeper | Lost on FAT32, inside containers, through some archivers, and on files that never came from a browser |

### The extension

On Windows a file name extension is a subkey under `HKEY_CLASSES_ROOT` whose default value names a programmatic identifier (ProgID), and the ProgID names the program that opens the file [184]. Nothing in that lookup inspects the content. Explorer's default "hide extensions for known file types" setting lets `invoice.pdf.exe` display as `invoice.pdf`, and ATT&CK's mitigation for Double File Extension ([T1036.007](/mitre/techniques/T1036-007.md)) is to turn that setting off and train users to spot the trick [37]. Extension blocklists also fail by design when a file is wrapped: Microsoft's own Outlook page says that compressing a file produces an extension Outlook does not recognize as a threat, so the archive is not blocked [5].

Extensions are still worth enforcing. They are cheap, they are the only signal some layers have, and the published lists (Outlook, Gmail, the Microsoft 365 common attachments filter, Chromium's download policy) are the first line most mail and web traffic meets. The [Controls](#controls) section compares those lists.

### Magic numbers and libmagic

The `file` command (version 5.46) classifies a file with three sets of tests in order: filesystem tests, magic tests and language tests. Its manual describes a magic number as an invariant identifier at a small fixed offset, first used for executables and later applied to data formats; the library behind it is libmagic [183]. A parser that checks the signature is answering a different question from a blocklist that checks the name.

| Format | Signature (hex unless quoted) | Where | Source |
|---|---|---|---|
| ZIP (and JAR, APK, DOCX, XPI, WHL, NUPKG) | Local header `50 4B 03 04`; end of central directory record `50 4B 05 06` | Entries at the start, directory at the end; readers locate entries from the end record | [51] |
| gzip | `1F 8B`, compression method 8 for deflate | Byte 0 | [52] |
| Zstandard | `28 B5 2F FD` (the little-endian value `0xFD2FB528`) | Byte 0 | [53] |
| xz | `FD 37 7A 58 5A 00`; `0xFD` chosen so the file is never mistaken for text | Byte 0 | [54] |
| 7z | `37 7A BC AF 27 1C` ("7z" then four bytes) | Byte 0 | [50] |
| RAR 5.0 | `52 61 72 21 1A 07 01 00` (RAR 4.x uses a 7-byte form) | Searched from the start up to the maximum SFX module size, currently 1 MB | [49] |
| tar (POSIX ustar) | "ustar" in the `magic` field | Offset 257, not byte 0 | [55] |
| Debian package | "!&lt;arch&gt;" (an `ar` archive) | Byte 0 | [56] |
| RPM package | 96-byte lead with magic, then signature, header and payload | Byte 0 | [57] |
| Chrome extension (CRX3) | "Cr24", version 3, header length, signed header, then the ZIP | Byte 0 | [64] |
| ELF | `7F 45 4C 46` ("\x7fELF") with a type field (relocatable, executable, shared object, core) | Byte 0 | [78] |
| SQLite 3 | "SQLite format 3" and a nul byte (16 bytes) | Byte 0 | [165] |
| Apache Parquet | "PAR1" | First and last four bytes | [162] |
| Windows hibernation file | "hibr" | Byte 0 | [142] |
| JPEG | `FF D8` | Byte 0; ATT&CK's own example for [T1036.008](/mitre/techniques/T1036-008.md) | [37] |

Two consequences follow. A format with no signature at byte 0 (tar) or one that is found by searching (RAR after an SFX stub) needs a parser that knows the format, not a four-byte prefix check. And a check that looks only at the first bytes can be satisfied by one format while a different parser reads another format from the end of the same file (see [Polyglots](#polyglots)). The Microsoft 365 common attachments filter applies best-effort true type matching to leading and trailing bytes, so an `.exe` renamed to `.txt` is still caught as an executable, and it falls back to the extension when true typing fails or the type is unsupported [6]. OWASP's upload guidance says the same thing from the server side: the `Content-Type` an uploader sends is trivially spoofed, and signature checks belong alongside an extension allowlist, never alone [87]. The weakness behind trusting the name is [CWE-646](/CWE_REFERENCE.md) Reliance on File Name or Extension of Externally-Supplied File [38].

### Handlers and the Windows registry

The handler is where a file type turns into behavior. The same ProgID mechanism that lets Word open `.docx` lets `mshta.exe` run `.hta`, `hh.exe` render `.chm`, `mmc.exe` load `.msc` and `msiexec.exe` install `.msi`, and ATT&CK tracks each of those hosts as a System Binary Proxy Execution sub-technique ([T1218.005](/mitre/techniques/T1218-005.md), [T1218.001](/mitre/techniques/T1218-001.md), [T1218.014](/mitre/techniques/T1218-014.md), [T1218.007](/mitre/techniques/T1218-007.md)) [37]. Changing the association itself is persistence: CAPEC-556 Replace File Extension Handlers maps to [T1546.001](/mitre/techniques/T1546-001.md) Change Default File Association [39][41]. The weakness class for a request reaching the wrong handler is CWE-430 Deployment of Wrong Handler, which the library links to CAPEC-11 Cause Web Server Misclassification [38][41].

Web servers make the same decision with configuration instead of the registry. Apache `mod_mime` lets one file carry several extensions, and when a multi-extension file maps to both a media type and a handler the request usually goes to the handler [90]. IIS binds handlers to extensions in the `<handlers>` element, including in a per-directory `web.config` [26].

Handlers also disappear, which changes risk in both directions. WordPad is removed from Windows 11 24H2 and Windows Server 2025, so `.rtf` now opens in Word where Word is installed [18]. VBScript is deprecated and becomes a feature on demand before retirement [18]. XPS Viewer has been a feature on demand since Windows 10 1803 [16]. WinHlp32 for `.hlp` is not supported in Windows 10 [17]. Publisher is not included in Microsoft 365 from October 2026, and Baseline Security Mode can stop it launching [10].

### Mark of the Web and the Zone.Identifier stream

When a browser or mail client saves a file from the internet, Windows writes a `Zone.Identifier` NTFS alternate data stream holding a `ZoneId` under `[ZoneTransfer]`: 0 My Computer, 1 Local intranet, 2 Trusted sites, 3 Internet, 4 Restricted sites. By default the mark is added only for the Internet and Restricted sites zones [9]. SmartScreen runs its reputation check when the stream reads `ZoneId=3`, so a file that arrives without the stream skips that prompt [2]. Office blocks VBA macros by default in files marked `ZoneId=3`; selecting Unblock in the file's Properties or running `Unblock-File` removes the mark and lets macros run [9].

The mark is easy to lose:

- **File system.** Mark of the Web applies only to files saved on NTFS, not FAT32, so a file copied to a FAT32 USB stick loses it [9].
- **Containers.** ATT&CK records that archives (`.arj`, `.gzip`) and disk images (`.iso`, `.vhd`) are marked on download while the files inside may not inherit the mark after extraction or mounting, and cites APT29 and APT38 for ISO, VHD and VHDX delivery [37].
- **Archivers.** 7-Zip first offered propagation in 22.00 (2022-06-15) as an option, so earlier builds never carried the mark to extracted files [47]. WinRAR added a "Propagate Mark of the Web" option in 7.00; console RAR does not propagate it whatever the option says, and `unrar.dll` leaves it to the calling application [48].
- **Sync and trusted paths.** Files opened from OneDrive or SharePoint with Open in Desktop App, files pulled down by the OneDrive sync client, synced known folders and anything in a Trusted Location arrive without the mark or skip the check [9].
- **Network shares.** SmartScreen does not protect against malicious files on internal locations or UNC and SMB shares [21].

The record shows how often this chain is attacked. Across 2022 to 2026 the KEV catalog lists at least ten exploited Windows Mark of the Web, SmartScreen or Shell prompt bypasses (CVE-2022-41091, CVE-2022-41049, CVE-2022-44698, CVE-2023-24880, CVE-2023-36584, CVE-2023-36025, CVE-2024-21412, CVE-2024-38213, CVE-2024-38217, CVE-2026-21510) and five exploited WinRAR or UnRAR flaws (CVE-2018-20250, CVE-2022-30333, CVE-2023-38831, CVE-2025-6218, CVE-2025-8088) [1]. CISA's KEV entry for CVE-2024-29988 notes it can be chained with WinRAR CVE-2023-38831 and Internet Shortcut CVE-2024-21412, so archiver and Windows flaws are used together [1]. ATT&CK v20.0 places [T1553.005](/mitre/techniques/T1553-005.md) Mark-of-the-Web Bypass under the Defense Impairment tactic [41].

### The macOS quarantine attribute

Gatekeeper is built on File Quarantine, introduced in Mac OS X 10.6 in 2009. The downloading application can set an extended attribute named `com.apple.quarantine`, and for a first-run app with the flag set Gatekeeper prompts the user to allow or deny it [37]. Quarantine is opt-in by the downloading program, so files arriving from a USB drive, optical or external disk, network share or command-line download tool may not carry it, and malware families have been documented removing the attribute ([T1553.001](/mitre/techniques/T1553-001.md)) [37]. The quarantine properties Apple exposes record the agent's bundle identifier and name, the origin URL, the time and a reason type, which makes the attribute a provenance record for responders [72].

When an app, plug-in or installer package from outside the App Store is opened, Gatekeeper checks that it comes from an identified developer, is notarized by Apple and has not been altered, and asks for approval at first open [69]. Since macOS Catalina, software from outside the App Store must be notarized by default, and a user can still use Open Anyway in System Settings [70]. On macOS 15 or later the Endpoint Security API emits an event when a user bypasses Gatekeeper, visible in `eslogger` [69]. Gatekeeper bypasses are in the record: CVE-2021-30657 (KEV since 2021-11-03) [1], CVE-2022-22616 through a crafted ZIP [4] and CVE-2022-42821, where an extended attribute applied during extraction set restrictive ACLs that stopped the quarantine attribute being added [32].

### Linux permissions and shebangs

Linux does not use extensions to decide execution. An ELF file starts with `7F 45 4C 46` and declares a type in its header, and that header, not the name, decides how the kernel treats it [78]. `execve` accepts a binary or a script that begins with `#!` and an interpreter path, so any file with execute permission and a shebang runs, whatever its extension [78]. The text after `#!` is limited to 127 characters before Linux 5.1 and 255 since [78]. Linux ignores set-user-ID and set-group-ID bits on interpreter scripts, so setuid ELF binaries are the review target ([T1548.001](/mitre/techniques/T1548-001.md)) [78].

Mount options are a file-type control. `execve` fails with `EACCES` on a filesystem mounted `noexec`. For `nosuid`, the `execve(2)` manual says the set-user-ID and set-group-ID bits (and file capabilities) are ignored, and its error list also gives `EPERM` for a non-superuser running a set-user-ID file on such a mount. Either way, `noexec` and `nosuid` on upload and temporary directories remove whole classes of file from play [78].

### Polyglots

A polyglot is one file that is valid as two types. ZIP is located from its end record, so other data can sit before the ZIP structure, which is how self-extracting archives work and the structural basis for ZIP polyglots (Inferred from the specification) [51]. RAR readers search for the signature up to the maximum SFX module size, so a RAR can legitimately follow an executable stub [49]. Android's CVE-2017-13156, fixed in the 2017-12-01 bulletin as a High elevation of privilege in ART affecting Android 5.1.1 to 8.0, is the APK and DEX polyglot flaw publicly called Janus; the name and the description of a DEX file prepended to a valid APK come from the researcher disclosure and press, and the bulletin lists only the CVE and severity (Reported) [66][4]. ATT&CK tracks payloads hidden inside another file as [T1027.009](/mitre/techniques/T1027-009.md) Embedded Payloads [37]. SigmaHQ's rule `cc7abbd0-762b-41e3-8a26-57ad50d2eea3` looks for `mshta.exe` given `.png`, `.jpg`, `.zip` or `.pdf` files, which its description calls frequent polyglots [42].

Type confusion also happens inside one container. In CVE-2023-38831, WinRAR before 6.23 processed the contents of a folder that shared its name with a benign file inside a ZIP when the user tried to view the benign file [4]. CISA assigned it CWE-351 Insufficient Type Distinction and added it to KEV on 2023-08-24 with known ransomware use [1].

### Double extensions and the right-to-left override

Double extensions such as `invoice.pdf.exe` depend on hidden known extensions, and the dangerous types are the runnable ones: `.exe`, `.scr`, `.com`, `.pif`, `.lnk`, `.js`, `.hta` [37]. CAPEC-635 Alternative Execution Due to Deceptive Filenames links to CWE-162 and [T1036.007](/mitre/techniques/T1036-007.md); CAPEC-649 Adding a Space to a File Extension links to [T1036.006](/mitre/techniques/T1036-006.md) Space after Filename [39].

U+202E RIGHT-TO-LEFT OVERRIDE forces the characters after it to display right to left under the Unicode Bidirectional Algorithm (UAX #9, revision 52, Unicode 18.0.0) [77], and ATT&CK records its use to make a file name look benign ([T1036.002](/mitre/techniques/T1036-002.md)) [37]. CVE-2021-42574 (Trojan Source) records the same gap between displayed text and the logical order a program processes, in source code rather than file names [4]. Look-alike characters are a related trick: Trend Micro reported homoglyphs used to spoof document extensions on a nested archive in the CVE-2025-0411 campaign [115]. The library's ATT&CK data also carries [T1027.018](/mitre/techniques/T1027-018.md) Invisible Unicode [41]. WinRAR 7.30 beta 2 added console output filtering against special characters that hide information in file names [48].

On upload paths the same family of tricks appears as double extensions, null-byte truncation, case changes and NTFS alternate data streams marked by a colon; OWASP advises rejecting any file name that contains a colon [87].

## The catalog

One table per family. Columns:

- **Extension**: the name suffix as it is usually written. A file name with no extension (`Dockerfile`, `kubeconfig`) is shown in code font without a leading dot.
- **What it is**: the format in one phrase.
- **Opens with**: the default handler or the program that parses it.
- **Why it matters**: what the type can do that makes it a delivery, persistence or exposure risk.
- **Record**: an identifier or a dated primary for that type: a CVE, a KEV addition date, a vendor list as published, a specification, or a registered media type. Grades follow the sources table: vendor research reports are graded Confirmed for what the researcher observed and Reported for attribution and counts; anything marked (Inferred) is reasoning from the cited source, not a statement in it.
- **Library and MITRE**: the ATT&CK v20.0 technique (or CWE, CAPEC, D3FEND id) and the library page that goes deeper.

KEV dates are the `dateAdded` values in catalog version 2026.11.10 [1]. "Outlook blocks" means the type is on Microsoft's published blocked-attachments list [5]; "EOP default" and "EOP optional" refer to the Microsoft 365 common attachments filter's default list and its additional selectable types [6]; "Gmail blocks" means Google's published list [34]; "Chromium" refers to the download file-type policy, version_id 70 [36].

### Windows executables and libraries

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.exe` | Portable Executable program | Windows loader | Runs code with the user's rights; SmartScreen, Smart App Control and ASR gate it on provenance, prevalence and signing | CVE-2024-38213, a Mark of the Web bypass that skipped the SmartScreen experience, KEV 2024-08-13 [2][1]; CVE-2013-3900 (Authenticode padding in WinVerifyTrust), KEV 2022-01-10, a reminder that a valid-looking signature is not proof of integrity [1] | [T1204.002](/mitre/techniques/T1204-002.md), [T1553.002](/mitre/techniques/T1553-002.md); [Endpoint Security](/ENDPOINT_SECURITY_REFERENCE.md) |
| `.dll` | PE library | Any process that loads it; `rundll32.exe`, `regsvr32.exe` | Loaded by search order; Chromium rates `.dll` DANGEROUS because it can take over a co-located executable [36] | CVE-2012-1854, VBA loading a planted DLL from the working directory next to a document, KEV 2026-04-13, fourteen years after its 2012 fix [4][1]; DLL side-loading (T1574.002) is revoked into T1574.001 in the library data [41] | [T1574.001](/mitre/techniques/T1574-001.md), [T1218.011](/mitre/techniques/T1218-011.md) |
| `.lib` | Static or import library | Linkers and build tools | Rare in mail and a build-chain artifact; Gmail still lists it | Gmail blocks [34] | [T1195.002](/mitre/techniques/T1195-002.md) |
| `.sys` | Kernel-mode driver | Service Control Manager and the kernel | A vulnerable signed driver gives kernel access | Vulnerable driver blocklist on by default for all devices since the Windows 11 2022 update, also enforced with HVCI, Smart App Control or S mode [13]; ASR rule `56a863a9-875e-4185-98a7-b882c64b5ce5` stops a vulnerable driver being written but not a present one loading [8] | [T1068](/mitre/techniques/T1068.md), [T1014](/mitre/techniques/T1014.md); [Windows Hardening](/WINDOWS_HARDENING_REFERENCE.md) |
| `.drv` | Legacy driver file | Kernel or legacy loader | Falls through mail filtering and depends on code integrity (Inferred) | Absent from Outlook's list and from the EOP default and optional lists [5][6] | [T1068](/mitre/techniques/T1068.md) |
| `.vxd` | Windows 9x virtual device driver | No loader on current Windows (Inferred) | A legacy type that still appears on vendor lists | EOP default; Gmail blocks [6][34] | [T1068](/mitre/techniques/T1068.md) |
| `.efi` | UEFI executable (boot manager, loader) | Platform firmware at boot | Runs before the operating system and its controls | CVE-2023-24932, the Secure Boot bypass used by the BlackLotus bootkit; its boot manager revocations are not on by default and cannot be reverted once applied with Secure Boot on; not in KEV as of 2026.11.10 [14][1]. KB5025885 phases ran from 2023-05-09 with the enforcement date still to be announced [14] | [T1542.003](/mitre/techniques/T1542-003.md); [Firmware and IoT Security](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| `.scr` | Screensaver, a PE file | Windows screensaver host; runs on double-click | A full executable with a harmless-sounding name | [T1546.002](/mitre/techniques/T1546-002.md) records `SCRNSAVE.exe` registry abuse and advises blocking `.scr` from non-standard paths [37]; Outlook blocks [5]; covered by the ASR prevalence rule `01443614-cd74-433a-b99e-2ecdc07bfc25` [8] | [T1546.002](/mitre/techniques/T1546-002.md) |
| `.com` | DOS-era command program | Windows runs it directly (Inferred) | A lure renamed to `.com` runs on double-click | Outlook blocks; EOP default [5][6] | [T1204.002](/mitre/techniques/T1204-002.md), [T1036.008](/mitre/techniques/T1036-008.md) |
| `.pif` | Program information file | Windows runs it as a program (Inferred) | Same as `.com`; the true-type filter recognises `pif` content [6] | Outlook blocks; EOP default [5][6] | [T1204.002](/mitre/techniques/T1204-002.md), [T1036.008](/mitre/techniques/T1036-008.md) |
| `.cpl` | Control Panel item, a renamed DLL exporting `CPlApplet` | Control Panel; runs on double-click | Renamed DLLs registered under the Control Panel `Cpls` key load even without `CPlApplet` [37] | Outlook blocks; EOP optional only [5][6]; Chromium requires a user gesture and disallows auto-open [36] | [T1218.002](/mitre/techniques/T1218-002.md) |
| `.msc` | Microsoft Management Console saved console (XML) | `mmc.exe` | A console file can carry script that runs inside a trusted signed host | CVE-2024-43572, KEV 2024-10-08: the fix stops untrusted `.msc` files opening [2][1]; CVE-2025-26633, KEV 2025-03-11, known ransomware use [2][1]; Elastic's GrimResource (June 2024) [124] and Trend's MSC EvilTwin attribution to Water Gamayun (2025-03-25) are Reported [126] | [T1218.014](/mitre/techniques/T1218-014.md) |
| `.ocx` | ActiveX control | Office and legacy browser components | A classic exploit carrier loaded by documents | CVE-2012-0158 (MSCOMCTL.OCX), KEV 2021-11-03, known ransomware use [1]; Microsoft 365 apps block ActiveX in documents by default and Baseline Security Mode stops users overriding it [10]; AppLocker DLL rules govern `.ocx` but are off by default [19] | [T1203](/mitre/techniques/T1203.md) |
| `.local` | DLL redirection marker | Windows loader | Changes DLL search order for a same-named `.exe` | Chromium rates it DANGEROUS on Windows [36] | [T1574.001](/mitre/techniques/T1574-001.md) |
| `.manifest` | Side-by-side application manifest | Windows loader | Same effect as `.local` when placed beside an executable | Chromium rates it DANGEROUS on Windows [36] | [T1574.001](/mitre/techniques/T1574-001.md) |

### Scripts and script hosts

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.ps1` | PowerShell script | `powershell.exe`, `pwsh` | Full scripting access to Windows and .NET | Default execution policy on Windows clients is RemoteSigned, so downloaded scripts need a trusted signature unless unblocked; with every scope Undefined the effective policy is Restricted on clients and RemoteSigned on servers [15]. Windows PowerShell 2.0, a downgrade target, removed from Windows 11 24H2 as of August 2025 and from Windows Server 2025 as of September 2025 [16] | [T1059.001](/mitre/techniques/T1059-001.md); [PowerShell](/languages/powershell.md) |
| `.psm1` | PowerShell script module | PowerShell | Can arrive by mail where a `.ps1` is stopped | Not on Outlook's list [5]; the Restricted policy blocks it [15]; under App Control unallowed modules run only in Constrained Language Mode [20] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.psd1` | PowerShell data file or module manifest | PowerShell | Module manifests control what a module loads | Outlook blocks [5]; App Control applies Constrained Language Mode [20] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.psdm1` | PowerShell data module | PowerShell | Uncommon PowerShell type on the block list | Outlook blocks [5] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.pssc` | PowerShell session configuration | PowerShell remoting | Defines what a remote session may run | Outlook blocks [5] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.ps1xml` | PowerShell formatting and type configuration | PowerShell | Configuration that PowerShell loads as code-adjacent data | Outlook blocks; the Restricted policy blocks it [5][15] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.ps2` | Legacy PowerShell script type | PowerShell | Old type kept on the list | Outlook blocks [5] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.psc1` | PowerShell console file | PowerShell | Loads snap-ins at console start | Outlook blocks [5] | [T1059.001](/mitre/techniques/T1059-001.md) |
| `.bat` | Batch file | `cmd.exe`; runs on double-click | Runs commands directly | Outlook blocks; EOP default [5][6]; App Control does not directly control `.bat` run by `cmd.exe` [20], while the AppLocker script collection includes it [19] | [T1059.003](/mitre/techniques/T1059-003.md); [Windows command line](/commands/windows-cmd.md) |
| `.cmd` | Batch file (NT form) | `cmd.exe` | Same as `.bat` | Outlook blocks; EOP default [5][6]; same App Control gap [20] | [T1059.003](/mitre/techniques/T1059-003.md) |
| `.vbs` | VBScript | Windows Script Host (`wscript.exe`, `cscript.exe`) | Script downloaders and droppers | VBScript is deprecated and becomes a feature on demand before retirement [18]. Script engine flaws in KEV: CVE-2018-8174 (2022-02-15, known ransomware use), CVE-2024-38178 (2024-08-13), CVE-2025-30397 (2025-05-13) [1]. ASR rule `d3e037e1-3eb8-44c8-a917-57927947596d` targets JavaScript and VBScript downloaders [8] | [T1059.005](/mitre/techniques/T1059-005.md) |
| `.vbe` | Encoded VBScript | Windows Script Host | Encoding hides the script from casual review | Outlook blocks; EOP default [5][6] | [T1059.005](/mitre/techniques/T1059-005.md), [T1027](/mitre/techniques/T1027.md) |
| `.js` | JScript (when opened by Windows Script Host) | Windows Script Host by default on Windows | A text file that runs as a program on double-click | Google TAG reported Magniber delivered as `.js` with a malformed Authenticode signature that made SmartScreen skip its warning from September 2022, fixed as CVE-2022-44698, KEV 2022-12-13 with known ransomware use (Reported for the campaign) [134][2][1]; Chromium requires a user gesture [36] | [T1059.007](/mitre/techniques/T1059-007.md), [T1553.005](/mitre/techniques/T1553-005.md) |
| `.jse` | Encoded JScript | Windows Script Host | Encoded form of `.js` | Outlook blocks; EOP optional only, while `.vbe` is a default [5][6] | [T1059.007](/mitre/techniques/T1059-007.md), [T1027](/mitre/techniques/T1027.md) |
| `.mjs` | JavaScript module | Node.js and other runtimes | A script type that the Outlook list does not name | Gmail blocks [34] | [T1059.007](/mitre/techniques/T1059-007.md) |
| `.wsf` | Windows Script File (XML wrapper for mixed script) | Windows Script Host | Mixes VBScript and JScript in one file | Outlook blocks; EOP default [5][6]; App Control blocks Windows Script Host scripts unless the policy allows them [20] | [T1059.005](/mitre/techniques/T1059-005.md), [T1059.007](/mitre/techniques/T1059-007.md) |
| `.wsh` | Windows Script Host settings file | Windows Script Host | Points the host at a script | Outlook blocks; EOP default [5][6] | [T1059.005](/mitre/techniques/T1059-005.md) |
| `.wsc` | Windows Script Component | Windows Script Host and COM | Script registered as a COM object | EOP default [6] | [T1559.001](/mitre/techniques/T1559-001.md) |
| `.hta` | HTML Application | `mshta.exe`, outside the browser sandbox | HTML plus script with full user rights | [T1218.005](/mitre/techniques/T1218-005.md) [37]; all MSHTA execution is blocked when any App Control policy with script enforcement is active, even in audit mode [20]; Check Point reported `.url` files hiding an `.hta` behind a PDF-like icon (samples from January 2023), fixed as CVE-2024-38112, KEV 2024-07-09 (Reported for the campaign) [130][1] | [T1218.005](/mitre/techniques/T1218-005.md) |
| `.sct` | COM scriptlet | `regsvr32.exe`, `scrobj.dll` | Can be fetched by URL and run without registration | [T1218.010](/mitre/techniques/T1218-010.md) records the variation and RogueRobin's use [37]; Outlook blocks [5]; EOP default [6] | [T1218.010](/mitre/techniques/T1218-010.md) |
| `.xsl` | XSL stylesheet | XSLT processors such as `msxsl.exe` | A stylesheet can embed script that runs when processed | [T1220](/mitre/techniques/T1220.md) cites Cobalt Group and Higaisa [37]; WMIC is removed and no longer a feature on demand on Windows 11 24H2 and later as of the August 2026 update, which closes the WMIC formatting route [17] | [T1220](/mitre/techniques/T1220.md) |
| `.reg` | Registry export | `regedit.exe`, after a prompt | Merges keys, including persistence keys | Outlook blocks; EOP default [5][6] | [T1112](/mitre/techniques/T1112.md) |
| `.inf` | Setup information file | Setup API, `cmstp.exe` | A malicious INF can make CMSTP load DLLs or scriptlets and bypass UAC | [T1218.003](/mitre/techniques/T1218-003.md) [37]; Outlook blocks [5] | [T1218.003](/mitre/techniques/T1218-003.md) |
| `.py` | Python source | The Python interpreter, if installed | Runs with no application control where the interpreter is allowed | Outlook blocks the Python family [5]; App Control does not govern unenlightened third-party script hosts, so allowing the host allows every script it runs [20] | [T1059.006](/mitre/techniques/T1059-006.md); [Python](/languages/python.md) |
| `.pyc` | Compiled Python bytecode | Python interpreter | Not human-readable | Outlook blocks [5] | [T1059.006](/mitre/techniques/T1059-006.md) |
| `.pyo` | Optimized Python bytecode (legacy) | Python interpreter | Same as `.pyc` | Outlook blocks [5] | [T1059.006](/mitre/techniques/T1059-006.md) |
| `.pyw` | Python script run without a console | `pythonw.exe` | Runs with no visible window | Outlook blocks [5] | [T1059.006](/mitre/techniques/T1059-006.md) |
| `.pyz` | Zipped Python application | Python interpreter | A ZIP that runs as a program | Outlook blocks [5] | [T1059.006](/mitre/techniques/T1059-006.md) |
| `.pyzw` | Zipped Python application, windowless | `pythonw.exe` | Same as `.pyz`, no console | Outlook blocks [5] | [T1059.006](/mitre/techniques/T1059-006.md) |
| `.nsh` | NSIS installer script include | NSIS build tools | A build input that rarely belongs in mail | Gmail blocks [34] | [T1059](/mitre/techniques/T1059.md) |
| `.vba` | Exported VBA module | Office VBA editor, Windows Script Host | Macro source outside a document | SigmaHQ rule `1e33157c-53b1-41ad-bbcc-780b80b58288` lists `.vba` among Windows Script Host extensions it hunts for [42] | [T1059.005](/mitre/techniques/T1059-005.md) |

### Shortcuts and shell items

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.lnk` | Shell Link (shortcut), specified in [MS-SHLLINK] [136] | Explorer | Points at any target with arguments and an icon path; parsed when merely displayed | CVE-2010-2568 (code ran when Explorer displayed the icon), KEV 2022-09-15 [1]; CVE-2017-8464 (crafted `.LNK`), KEV 2022-02-10 [1]; ZDI-25-148 (ZDI-CAN-25373), later CVE-2025-9491, hides command-line content from the Windows UI, reported to Microsoft 2024-09-20, not serviced and not in KEV as of 2026.11.10 [128][1]; Trend counted nearly 1,000 abusing samples back to 2017 (Reported) [127]; CVE-2026-21510 and CVE-2026-21513, exploited, KEV 2026-02-10 [2][1] | [T1204.002](/mitre/techniques/T1204-002.md), [T1547.009](/mitre/techniques/T1547-009.md), [T1027.012](/mitre/techniques/T1027-012.md) |
| `.url` | Internet Shortcut (INI-style text) | Explorer, then the URL's handler | Can point at WebDAV, a protocol handler or a remote working directory | CVE-2023-36025, KEV 2023-11-14 [2][1]; CVE-2024-21412, KEV 2024-02-13, known ransomware use [2][1]; CVE-2025-33053 (`WorkingDirectory` aimed at a remote WebDAV location), KEV 2025-06-10 [1]; CVE-2022-41091, whose FAQ names a crafted `.url` file, KEV 2022-11-08 [2]; Water Hydra and Stealth Falcon attributions are Reported [129][131] | [T1204.002](/mitre/techniques/T1204-002.md), [T1553.005](/mitre/techniques/T1553-005.md) |
| `.website` | Pinned site shortcut | Explorer and the browser | An internet-shortcut-style file; the `.url` record is the closest guide (Inferred) | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.scf` | Shell Command File | Explorer | Explorer loads its icon path when the folder is shown, which can send an NTLM hash to a remote share | [T1187](/mitre/techniques/T1187.md) cites Dragonfly and advises blocking outbound TCP 139 and 445 and UDP 137 [37]; Chromium rates `.scf` DANGEROUS [36]; EOP default [6] | [T1187](/mitre/techniques/T1187.md) |
| `.library-ms` | Windows library description (XML) | Explorer | Minimal interaction (a click or right-click) can leak NTLMv2 | CVE-2025-24054, fixed 2025-03-11, KEV 2025-04-17 [2][1]; Check Point reported exploitation from 2025-03-19 through `.library-ms` files often inside a ZIP (Reported) [132] | [T1187](/mitre/techniques/T1187.md) |
| `.search-ms` | Saved search for the `search-ms` protocol | Explorer and Windows Search | Opens a search view that can point at remote locations | Protocol documented by Microsoft [23]; Outlook blocks [5]; Chromium requires a user gesture [36] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.settingcontent-ms` | Windows 10 settings shortcut (XML) | Settings host | Its `DeepLink` element could run any binary and slipped past Office 2016's OLE extension block | SpecterOps, 2018-06-11 (Reported) [133]; fixed as CVE-2018-8414, KEV 2022-03-25 [1]; Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.appref-ms` | ClickOnce application reference | ClickOnce runtime (`dfsvc`) | Launches a ClickOnce install of a hosted app (Inferred) | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.application` | ClickOnce deployment manifest | ClickOnce runtime | Same as `.appref-ms` (Inferred) | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.appcontent-ms` | Windows shell content descriptor (XML) | Explorer | A shell descriptor rather than a classic executable | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.theme` | Windows theme | Personalization settings | Theme files reference resources that can live on SMB shares | CVE-2023-38146 (Themes RCE, TOCTOU), not exploited, not in KEV [2]; CVE-2024-21320 (NTLM leak on merely handling a theme file; NTLM-disabled systems unaffected) [2]; Outlook blocks [5] | [T1187](/mitre/techniques/T1187.md), [T1204.002](/mitre/techniques/T1204-002.md) |
| `.themepack` | Cabinet holding a `.theme` and its resources | Personalization settings | Packaged themes escape the `.theme` block (Inferred) | On neither Outlook's list nor the EOP default or optional lists [5][6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.diagcab` | Troubleshooting package (cabinet) | Microsoft Support Diagnostic Tool (MSDT) | A diagnostic package that runs bundled scripts | CVE-2022-34713 (DogWalk), KEV 2022-08-09 [2][1]; MSDT is deprecated and custom packages were kept as a feature on demand until retirement in 2025 [18]; Outlook blocks [5] | [T1218](/mitre/techniques/T1218.md) |
| `.diagcfg` | MSDT troubleshooting configuration | MSDT | Same family as `.diagcab` | Gmail blocks [34] | [T1218](/mitre/techniques/T1218.md) |
| `.diagpkg` | MSDT troubleshooting package | MSDT | Same family as `.diagcab` | Gmail blocks [34] | [T1218](/mitre/techniques/T1218.md) |
| `.wsb` | Windows Sandbox configuration (XML) | Windows Sandbox | Can map host folders and run a `LogonCommand`; networking and clipboard redirection are on by default [22] | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.rdp` | Remote Desktop connection file | `mstsc.exe` | Connects to whatever server it names and can redirect drives, clipboard, printers and smart cards | Midnight Blizzard emailed signed `.rdp` files to thousands of targets in over 100 organizations from 2024-10-22 [30]; on neither Outlook's list nor the EOP default or optional lists [5][6] | [T1566.001](/mitre/techniques/T1566-001.md), [T1021.001](/mitre/techniques/T1021-001.md) |
| `.ica` | Citrix connection launch file | Citrix Workspace | A connection profile like `.rdp` (Inferred) | On neither Outlook's list nor the EOP default or optional lists [5][6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.jnlp` | Java Web Start launch file | `javaws` where a legacy runtime remains | Removed from Oracle JDK 11, so it launches only where Java 8 or a third-party replacement is installed [44] | Outlook blocks; EOP default [5][6] | [T1204.002](/mitre/techniques/T1204-002.md) |

### Installers and packages

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.msi` | Windows Installer package | `msiexec.exe` | Signed host that can install from a URL and run custom actions | Google TAG reported Magniber `.msi` files with a crafted invalid signature bypassing SmartScreen (CVE-2023-24880, KEV 2023-03-14, known ransomware use), with over 100,000 downloads since January 2023 (Reported for counts) [134][2]; CVE-2024-38014 (Windows Installer privilege escalation to SYSTEM), KEV 2024-09-10 [2][1] | [T1218.007](/mitre/techniques/T1218-007.md) |
| `.msp` | Windows Installer patch | `msiexec.exe` | Same host as `.msi` | Outlook blocks; EOP default [5][6]; AppLocker Windows Installer collection [19] | [T1218.007](/mitre/techniques/T1218-007.md) |
| `.mst` | Windows Installer transform | `msiexec.exe` | Modifies what an `.msi` installs | EOP default [6]; AppLocker Windows Installer collection [19] | [T1218.007](/mitre/techniques/T1218-007.md) |
| `.msix` | MSIX app package | App Installer | Signed packages abused through the `ms-appinstaller` handler | Microsoft disabled the `ms-appinstaller` protocol handler by default on 2023-12-28 after four actor groups used it from mid-November 2023 [29]; CVE-2021-43890 (AppX Installer spoofing, Emotet, TrickBot and BazaLoader packages), KEV 2021-12-15, known ransomware use [2][1]; EOP default; not on Outlook's list [6][5] | [T1204.002](/mitre/techniques/T1204-002.md), [T1553.002](/mitre/techniques/T1553-002.md) |
| `.msixbundle` | Bundle of MSIX packages | App Installer | Same as `.msix` | Not on Outlook's list; EOP optional only [5][6]; Gmail blocks [34] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.appx` | AppX package | App Installer | Same family as `.msix` | Outlook blocks; EOP default [5][6]; AppLocker packaged-app collection [19] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.appxbundle` | Bundle of AppX packages | App Installer | Same family | EOP optional only [6]; Gmail blocks [34] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.appinstaller` | App Installer descriptor (XML pointing at a package URL) | App Installer | The descriptor in the 2023 `ms-appinstaller` campaigns | Not on Outlook's list [5]; not listed in Chromium's policy at all [36] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.cab` | Microsoft Cabinet archive | Windows Expand, Setup API, archivers | Wraps other files; also the LVFS firmware container | IANA `application/vnd.ms-cab-compressed` [177]; 7-Zip extracts multivolume CAB [47]; LVFS asks vendors to declare whether payloads are verified on device [85] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.chm` | Compiled HTML Help | `hh.exe` with legacy browser components | Bundles HTML, script and ActiveX; can bypass application control that ignores `hh.exe` | [T1218.001](/mitre/techniques/T1218-001.md) [37]; Outlook blocks, EOP optional only [5][6]; SigmaHQ `f57c58b3-ee69-4ef5-9041-455bf39aaa89` watches `hh.exe` opening remote `.chm` [42] | [T1218.001](/mitre/techniques/T1218-001.md) |
| `.hlp` | Legacy WinHelp file | WinHlp32, not supported in Windows 10 | A dead handler; block it | Deprecated features entry [17]; Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.jar` | Java archive (ZIP with `META-INF/MANIFEST.MF` and optional signature files) | Java runtime | Executable code in a ZIP container | JAR specification [45]; CVE-2012-4681 (KEV 2022-03-03, known ransomware use) and CVE-2013-0422 (KEV 2022-05-25, known ransomware use) [1]; Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.war` | Java web application archive | Servlet containers such as Tomcat | Tomcat deploys any `.war` copied into `appBase` at startup when `deployOnStartup` is true and while running when `autoDeploy` is true [91] | Tomcat deployer documentation [91] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.ear` | Java enterprise application archive | Java EE application servers | A ZIP of executable code built on JAR | JAR specification [45] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.nupkg` | NuGet package (a ZIP of compiled DLLs and a manifest) | NuGet and .NET tooling | A dependency that runs in builds and applications | Microsoft Learn, NuGet introduction [27] | [T1195.002](/mitre/techniques/T1195-002.md); [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md) |
| `.whl` | Python wheel (ZIP with a formatted file name) | `pip` | A dependency installed into environments | PyPA binary distribution format [61] | [T1195.002](/mitre/techniques/T1195-002.md) |
| `.egg` | Legacy Python distribution | `easy_install` era tooling | PyPI rejects egg uploads from 2023-08-01 (PEP 715), so a `.egg` today is legacy or out-of-band | PyPI blog, 2023-06-26 [62] | [T1195.001](/mitre/techniques/T1195-001.md) |
| `.xpi` | Firefox extension (a renamed ZIP) | Firefox | A browser extension with access to browsing data | Firefox Extension Workshop [63] | [T1176.001](/mitre/techniques/T1176-001.md); [Browser Security](/BROWSER_SECURITY_REFERENCE.md) |
| `.crx` | Chrome extension (CRX3: `Cr24` header, signed header, ZIP) | Chromium browsers | Same as `.xpi` | Chromium `crx3.proto` [64] | [T1176.001](/mitre/techniques/T1176-001.md) |
| `.deb` | Debian package (an `ar` archive) | `dpkg`, `apt` | Maintainer scripts (`preinst`, `postinst`, `prerm`, `postrm`) run as root | deb(5) [56]; Debian Policy chapter 6 [80]; [T1546.016](/mitre/techniques/T1546-016.md) [37] | [T1546.016](/mitre/techniques/T1546-016.md); [Linux Hardening](/LINUX_HARDENING_REFERENCE.md) |
| `.rpm` | RPM package (lead, signature, header, compressed payload) | `rpm`, `dnf` | Scriptlets run with installer privileges | RPM v4 format [57]; [T1546.016](/mitre/techniques/T1546-016.md) [37] | [T1546.016](/mitre/techniques/T1546-016.md) |
| `.snap` | Snap package (a SquashFS image with metadata) | `snapd`, mounted read-only under `/snap` | A whole application image | Snapcraft documentation [58] | [T1195.002](/mitre/techniques/T1195-002.md) |
| `.AppImage` | Runtime plus SquashFS image, run as one executable | The file itself, once marked executable | One file equals one app; it bypasses the distribution package manager's signature checks (Inferred) | AppImage architecture and concepts [59] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.flatpak` | Flatpak single-file bundle | `flatpak` | Built on OSTree, a Git-like system for versioned file trees, rather than one archive | Flatpak documentation [60] | [T1195.002](/mitre/techniques/T1195-002.md) |
| `.flatpakref` | Flatpak application reference | `flatpak` | Points the installer at a remote | Flatpak documentation [60] | [T1195.002](/mitre/techniques/T1195-002.md) |

### Office and document formats

Office on Windows blocks VBA macros in files from the internet by default in Access, Excel, PowerPoint, Visio and Word. The rollout reached Current Channel (Preview) 2203 on 2022-04-12, Current Channel 2206 on 2022-07-27, Monthly Enterprise Channel 2208 on 2022-10-11 and Semi-Annual Enterprise Channel 2208 on 2023-01-10; Publisher followed in Current Channel 2301 on 2023-02-14 and Project in Current Channel 2407 on 2024-08-13. The block does not affect Office on Mac, Android, iOS or the web, and Mark of the Web is the deciding signal [9].

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.doc` | Word 97-2003 binary document | Word | Legacy parser with a long exploit history | CVE-2017-11882 (Equation Editor), KEV 2021-11-03, known ransomware use [1]; CVE-2022-30190 (Follina, MSDT called from Word), KEV 2022-06-14, known ransomware use [4][1]; Storm-0978 used CVE-2023-36884 in Word lures in June 2023, KEV 2023-07-17, known ransomware use [31][1] | [T1203](/mitre/techniques/T1203.md), [T1566.001](/mitre/techniques/T1566-001.md) |
| `.docx` | Word Open XML document (ZIP of XML parts) | Word | No VBA, but can load remote templates and OLE objects | CVE-2021-40444 (MSHTML through ActiveX in a document), KEV 2021-11-03 with known ransomware use [2][1]; CVE-2026-21509 (Office OLE mitigation bypass), out of band 2026-01-26, KEV the same day [2][1]; CVE-2026-21514, KEV 2026-02-10 [2][1]; remote template loading triggers SMB or WebDAV authentication ([T1221](/mitre/techniques/T1221.md) with [T1187](/mitre/techniques/T1187.md)) [37] | [T1221](/mitre/techniques/T1221.md), [T1559.001](/mitre/techniques/T1559-001.md) |
| `.docm` | Macro-enabled Word document | Word | Carries VBA | IANA `application/vnd.ms-word.document.macroEnabled.12` [177]; EOP default [6]; not on Outlook's list [5]; Gmail refuses documents with malicious macros [34] | [T1204.002](/mitre/techniques/T1204-002.md), [T1059.005](/mitre/techniques/T1059-005.md) |
| `.dot` | Word 97-2003 template | Word | Templates load at document open | Downloaded macro-enabled templates keep the mark and their macros are blocked [9] | [T1137.001](/mitre/techniques/T1137-001.md) |
| `.dotm` | Macro-enabled Word template | Word | A `Normal.dotm` loaded from a remote host is the template-injection path | Macro block covers templates [9]; EOP optional only [6] | [T1137.001](/mitre/techniques/T1137-001.md), [T1221](/mitre/techniques/T1221.md) |
| `.xls` | Excel 97-2003 binary workbook | Excel | Legacy parser; CISA keeps adding old bugs | CVE-2007-0671 (KEV 2025-08-12) and CVE-2009-0238 (KEV 2026-04-14) [1]; Baseline Security Mode can open old formats in Protected View and block Excel DDE server launches [10] | [T1203](/mitre/techniques/T1203.md), [T1559](/mitre/techniques/T1559.md) |
| `.xlsx` | Excel Open XML workbook | Excel | No VBA; external links and DDE remain | IANA `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` [177]; one of the Office true types Safe Attachments can exclude [7] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.xlsm` | Macro-enabled Excel workbook | Excel | Carries VBA | IANA `application/vnd.ms-excel.sheet.macroEnabled.12` [177]; EOP optional only [6]; files from OneDrive sync or Trusted Locations arrive without the mark [9] | [T1204.002](/mitre/techniques/T1204-002.md), [T1059.005](/mitre/techniques/T1059-005.md) |
| `.xlsb` | Excel binary workbook, can hold macros | Excel | Macro-capable but less familiar than `.xlsm` | IANA `application/vnd.ms-excel.sheet.binary.macroEnabled.12` [177]; EOP optional only, so it passes the default filter [6] | [T1566.001](/mitre/techniques/T1566-001.md) |
| `.xlt` | Excel 97-2003 template | Excel | Template with macros | Macro block covers templates [9] | [T1137.001](/mitre/techniques/T1137-001.md) |
| `.xltm` | Macro-enabled Excel template | Excel | Same | Macro block covers templates [9] | [T1137.001](/mitre/techniques/T1137-001.md) |
| `.xla` | Excel 97-2003 add-in | Excel | Loads into every workbook | Macro-enabled add-ins from the internet load disabled; for Excel add-ins with the mark, signing and trusting the publisher does not unblock them (behavior since MS16-088 in 2016) [9] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.xlam` | Macro-enabled Excel add-in | Excel | Same | Macro-enabled add-ins from the internet load disabled; signing does not unblock marked Excel add-ins (since MS16-088) [9] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.xll` | Native-code Excel add-in (a DLL) | Excel | Native code loaded by Excel | Excel blocks untrusted XLL add-ins from the internet by default in Microsoft 365, 2024, 2021, 2019 and 2016; the support page gives no rollout date [12]; Outlook blocks, EOP default [5][6]; SigmaHQ `af4c4609-5755-42fe-8075-4effb49f5d44` and `36fbec91-fa1b-4d5d-8df1-8d8edcb632ad` [42] | [T1137.006](/mitre/techniques/T1137-006.md), [T1204.002](/mitre/techniques/T1204-002.md) |
| `.wll` | Word add-in (a DLL) | Word | Native code loaded by Word | SigmaHQ `8e1cb247-6cf6-42fa-b440-3f27d57e9936` describes `.wll` and `.xll` as DLLs for Word and Excel [42] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.ppt` | PowerPoint 97-2003 binary presentation | PowerPoint | Legacy parser | CVE-2009-0556 (OutlineTextRefAtom memory corruption), KEV 2026-01-07 [1] | [T1203](/mitre/techniques/T1203.md) |
| `.pptx` | PowerPoint Open XML presentation | PowerPoint | No VBA; OLE objects remain | IANA `application/vnd.openxmlformats-officedocument.presentationml.presentation` [177] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.pptm` | Macro-enabled presentation | PowerPoint | Carries VBA | IANA `application/vnd.ms-powerpoint.presentation.macroEnabled.12` [177]; EOP optional only [6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.pot` | PowerPoint 97-2003 template | PowerPoint | Template with macros | Macro block covers templates [9] | [T1137.001](/mitre/techniques/T1137-001.md) |
| `.potm` | Macro-enabled PowerPoint template | PowerPoint | Same | Macro block covers templates [9] | [T1137.001](/mitre/techniques/T1137-001.md) |
| `.ppa` | PowerPoint 97-2003 add-in | PowerPoint | Loads with the application | Add-ins from the internet load disabled [9]; EOP default [6] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.ppam` | Macro-enabled PowerPoint add-in | PowerPoint | Same; PowerPoint can also trust a signature | Macro-enabled add-ins from the internet load disabled; the user must remove the mark, use a Trusted Location or, for PowerPoint, trust the signature [9]; EOP default [6] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.rtf` | Rich Text Format | Word (WordPad is removed from Windows 11 24H2 [18]) | Embeds OLE objects; previewed in mail | CVE-2017-0199 (Office and WordPad), KEV 2021-11-03, known ransomware use [4][1]; CVE-2015-1641 and CVE-2010-3333 (RTF handling), KEV [1]; CVE-2023-21716 (RTF parsing, Preview Pane vector), not in KEV, workaround is the File Block policy for RTF [2]; CVE-2025-21298 (OLE, preview in Outlook) [2] | [T1203](/mitre/techniques/T1203.md) |
| `.one` | OneNote section | OneNote | Embedded files run from inside a note | OneNote for Microsoft 365 blocks embedded files with dangerous extensions from Version 2304 (Current Channel 2023-05-01; Semi-Annual Enterprise 2308 on 2024-01-09) [11]; absent from Outlook, Gmail and the EOP default lists and not listed by Chromium [5][34][6][36]; the ASR child-process rule covers OneNote [8] | [T1566.001](/mitre/techniques/T1566-001.md), [T1027.009](/mitre/techniques/T1027-009.md) |
| `.onepkg` | OneNote package | OneNote | Same family as `.one` | SigmaHQ `fcc6d700-68d9-4241-9a1a-06874d621b06` watches files written by OneNote from `.one` and `.onepkg` [42] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.pub` | Publisher document | Publisher | A large attack surface in a product leaving Microsoft 365 | CVE-2023-21715 (macro policy bypass), KEV 2023-02-14 [2][1]; Publisher not included in Microsoft 365 from October 2026, and Baseline Security Mode can block it [10] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.mpp` | Project file | Project | Macro-capable | Macro block reached Project in Current Channel 2407 on 2024-08-13 [9] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.accdb` | Access database | Access | Macros and VBA in a database file | Not on Outlook's list; EOP optional only [5][6]; the internet macro block covers Access [9] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.accde` | Compiled Access database | Access | Same | Not on Outlook's list; EOP optional only [5][6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.mdb` | Access 97-2003 database | Access | Legacy database with code | Outlook blocks; EOP optional only [5][6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.mde` | Compiled legacy Access database | Access | Same | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.mda` | Access add-in | Access | Same | Outlook blocks [5] | [T1137.006](/mitre/techniques/T1137-006.md) |
| `.ade` | Access project extension | Access | Same | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.adp` | Access project | Access | Same | Outlook blocks [5] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.odt` | OpenDocument text | LibreOffice Writer | Linked content and frames | CVE-2023-2255: floating frames fetched linked remote content without prompting; fixed in 7.4.7 and 7.5.3 (announced 2023-05-24) [135] | [T1221](/mitre/techniques/T1221.md) |
| `.ods` | OpenDocument spreadsheet | LibreOffice Calc | Data links fetched on load | CVE-2026-63267: a `calcext:data-mappings` link was fetched on load, letting a document read a local file into the sheet or request a host it chose; fixed in 26.2.5 and 26.8.0 (announced 2026-10-05) [135] | [T1221](/mitre/techniques/T1221.md) |
| `.pdf` | Portable Document Format | Acrobat Reader, browsers, Preview | Script, forms, embedded files and image codecs | CVE-2026-34621 (Acrobat Reader prototype pollution, APSB26-43), KEV 2026-04-13 [4][1]; CVE-2010-2883 (KEV 2022-06-08) and CVE-2010-0188 (KEV 2022-03-03, known ransomware use) [1]; CVE-2021-30860 (FORCEDENTRY, a crafted PDF in Apple CoreGraphics), KEV 2021-11-03 [1]; ASR `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` blocks Reader child processes [8] | [T1203](/mitre/techniques/T1203.md) |
| `.xps` | XML Paper Specification document | XPS Viewer (a feature on demand since Windows 10 1803) | Often has no handler on current machines | Removed-features entry [16]; EOP true-type matching recognises `xps` [6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.oxps` | OpenXPS document | XPS Viewer | Same | IANA `application/oxps` [177]; removed-features entry [16] | [T1204.002](/mitre/techniques/T1204-002.md) |

### Archives and compression

Every format an archiver can open is parser attack surface: 7-Zip 26.01 (2026-04-27) alone fixed eight CVEs in individual format handlers, including UDF, WIM, SquashFS, NTFS, UEFI and Ar [47]. Windows' own archive support is in scope too: CVE-2024-20696 and CVE-2024-20697 are heap overflows in the built-in libarchive, fixed 2024-01-09 [3].

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.zip` | ZIP archive | Explorer, archivers, every language runtime | The wrapper that defeats extension blocklists; path traversal on extraction | CVE-2023-38831 (WinRAR type confusion inside a ZIP), KEV 2023-08-24, CWE-351, known ransomware use [4][1]; Group-IB reported exploitation since April 2023 on trading forums [116]; Zip Slip disclosed by Snyk on 2018-06-05 [120]; CVE-2025-11001 (7-Zip symlink traversal) fixed in 25.00 [4][47]; CVE-2024-8811 (WinZip dropped the mark on open) [4]; CVE-2024-48510 (DotNetZip 1.16.0 and earlier, unmaintained, Zip Slip) [4] | [T1027.015](/mitre/techniques/T1027-015.md), CWE-22; [Malware Analysis](/MALWARE_ANALYSIS_REFERENCE.md) |
| `.7z` | 7-Zip archive | 7-Zip | Mark of the Web propagation depends on the archiver | CVE-2025-0411 (nested-archive MotW bypass), KEV 2025-02-06 [4][1]; Trend reported exploitation from September 2024 against Ukrainian organizations (attribution Reported) [115]; 7-Zip 24.09 fixed nested-archive propagation [47] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.rar` | RAR archive | WinRAR, UnRAR, other archivers | Path traversal and MotW handling in widely deployed tools | CVE-2025-8088 (path traversal using alternate data streams), WinRAR 7.13 released 2025-07-30, KEV 2025-08-12 with known ransomware use [4][1]; ESET found RomCom exploiting it [117]; GTIG reported continued use by state and criminal actors dropping files into the Startup folder (2026-01-27) [118]; CVE-2025-6218, KEV 2025-12-09 [4][1]; CVE-2022-30333 (UnRAR on Linux and Unix), KEV 2022-08-09 [4]; CVE-2026-58052 (7-Zip through 26.01 lost the mark on a crafted RAR5 through an alternate stream-name spelling), fixed in 26.03 (2026-09-03) [4][47]; CVE-2018-10115 (7-Zip RAR decoder, fixed in 18.05) [4] | [T1553.005](/mitre/techniques/T1553-005.md), [T1204.002](/mitre/techniques/T1204-002.md) |
| `.rev` | RAR recovery volume | WinRAR and RAR | A rarely inspected companion file | WinRAR 7.23 fixed a heap overflow in RAR5 recovery volume reconstruction [48]; WinRAR 6.23 (2023-08-02) fixed CVE-2023-40477 in RAR4 recovery volumes [48] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.ace` | ACE archive | Formerly WinRAR through `UNACEV2.dll` | A 2006-compiled library without exploit protections, unnoticed for over 19 years | CVE-2018-20250 (absolute path traversal), KEV 2022-02-15, known ransomware use [4][1]; Check Point found it by fuzzing, and WinRAR dropped ACE support (2019-02-20) [119]; EOP default [6] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.tar` | POSIX tape archive | `tar`, archivers | No signature at byte 0; file names inside are attacker-controlled | CVE-2023-2868 (Barracuda ESG command injection through `.tar` file names), KEV 2023-05-26 [4][1]; CVE-2020-36193 (PEAR Archive_Tar symlink traversal), KEV 2022-08-25 [1]; CVE-2025-55188 (7-Zip symlinks) fixed in 25.01 [4] | [T1566.001](/mitre/techniques/T1566-001.md), CWE-22, CWE-59 |
| `.gz` | gzip stream | `gzip`, archivers | Compression layer that hides the inner type | RFC 1952 [52]; Gmail inspects listed types in compressed form [34]; ATT&CK names `.gzip` as a MotW-bypass container [37] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.tgz` | gzip-compressed tar | `tar`, archivers | Two layers before the content | Gmail inspects inside `.tgz` [34] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.bz2` | bzip2 stream | `bzip2`, archivers | Compression layer | Gmail inspects compressed forms such as `.bz2` [34] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.xz` | xz stream | `xz`, archivers | The release format in the 2024 xz backdoor | CVE-2024-3094: malicious code in upstream xz tarballs from 5.6.0, extracted from a disguised test file at build time (CWE-506) [4]; CVE-2026-14266 (7-Zip XZ heap overflow), fixed in 26.02 [4][47]; EOP default [6] | [T1195.002](/mitre/techniques/T1195-002.md); [XZ Utils case study](/case-studies/XZ_UTILS_BACKDOOR_2024.md) |
| `.zst` | Zstandard frame | `zstd`, archivers | Newer compression in packages and logs | RFC 8878 [53]; CVE-2024-11477 (7-Zip Zstandard integer underflow, CWE-191) fixed in 24.07 [4][47] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.z` | Unix `compress` output | `uncompress`, archivers | Legacy compression | EOP default [6] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.lzh` | LHA/LZH archive | Archivers (7-Zip extraction only) | Legacy type still reached through general archivers | 7-Zip history [47]; EOP default [6] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.lha` | LHA archive | Archivers | Same | EOP default [6] | [T1027.015](/mitre/techniques/T1027-015.md) |
| `.arj` | ARJ archive | Archivers | Named by ATT&CK as a MotW-bypass container | [T1553.005](/mitre/techniques/T1553-005.md) [37]; 7-Zip extracts it [47]; EOP default [6] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.ar` | Unix `ar` archive (the `.deb` container) | `ar`, archivers | Parser surface in archivers | 7-Zip 26.01 fixed an Ar handler CVE [47] | [T1204.002](/mitre/techniques/T1204-002.md) |

Two limits apply to every row. A password-protected archive cannot be inspected by a gateway without the password [51]; ATT&CK lists encrypted documents and SFX archives under [T1027.013](/mitre/techniques/T1027-013.md) [37]; Safe Attachments cannot fully detonate one unless the recipient supplies the password [7]; and Gmail refuses password-protected archives that contain archived content [34]. Decompression itself can be the attack: David Fifield's non-recursive zip bomb reaches a ratio over 28 million (10 MB to 281 TB) with DEFLATE alone, the weakness CWE-409 [121].

### Disk images and containers

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.iso` | Optical disc image (ISO 9660 or UDF) | Windows mounts it on double-click | Files inside appear as local disk content | CVE-2022-41091 (MotW bypass), KEV 2022-11-08, known ransomware use [3][1]; the November 2022 update made the mark propagate into downloaded ISO contents, a detail from press reporting, not the advisory (Reported) [122]; Kaspersky reported BlueNoroff adopting `.iso` and `.vhd` in late 2022 to evade the mark [123]; Outlook blocks; EOP default [5][6]; Chromium gives `.iso` no danger level [36] | [T1553.005](/mitre/techniques/T1553-005.md), [T1566.001](/mitre/techniques/T1566-001.md) |
| `.img` | Raw disk image | Windows mounts it | Same as `.iso` | Outlook blocks; EOP default [5][6]; Chromium requires a user gesture on Windows and macOS [36] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.vhd` | Virtual Hard Disk | Windows mounts it (`Mount-DiskImage` is also the double-click action) [24] | A whole volume delivered as one attachment | Outlook blocks; EOP optional only; Gmail blocks [5][6][34]; SigmaHQ `8468111a-ef07-4654-903b-b863a80bbc95` watches browsers writing `.vhd` and `.vhdx` [42] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.vhdx` | Virtual Hard Disk v2 | Windows mounts it | Same | Outlook blocks [5]; Gmail names `.vhd` but not `.vhdx` [34]; 7-Zip opens VHDX since 21.07 [47] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.vmdk` | VMware virtual disk | Hypervisors; 7-Zip since 15.07 [47] | Extracting it with an archiver bypasses the Windows mount fix, so the mark depends on the archiver (Inferred) [47] | The Sleuth Kit reads VMDK images [150] | [T1553.005](/mitre/techniques/T1553-005.md); [Hypervisor Security](/HYPERVISOR_SECURITY_REFERENCE.md) |
| `.qcow2` | QEMU copy-on-write disk | QEMU and KVM; 7-Zip since 15.07 | Same | 7-Zip history [47] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.vdi` | VirtualBox disk image | VirtualBox; 7-Zip since 15.07 | Same | 7-Zip history [47] | [T1553.005](/mitre/techniques/T1553-005.md) |
| `.udf` | Universal Disk Format image | Archivers; 7-Zip since 4.59 beta (2008) | Parser surface | CVE-2026-48102 (7-Zip UDF handler), fixed in 26.01 [47] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.wim` | Windows Imaging Format (file-based, several compression types) | DISM, archivers | Can carry a whole Windows installation | WIM vs VHD vs FFU comparison [25]; CVE-2026-48103 (7-Zip WIM handler) fixed in 26.01 [47] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.ffu` | Full Flash Update image (sector-based) | Windows imaging tools | A full device image | WIM vs VHD vs FFU comparison [25] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.squashfs` | Compressed read-only Linux file system | Linux kernel, archivers | The container inside snaps and AppImages | CVE-2026-48092 and CVE-2026-48104 (7-Zip SquashFS handler), fixed in 26.01 [47] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.xar` | eXtensible ARchive (the macOS flat-package container) | macOS Installer, archivers; 7-Zip since 4.59 beta | Container under macOS `.pkg` files (Inferred) | 7-Zip history [47] | [T1204.002](/mitre/techniques/T1204-002.md) |

### Web and server-side code

A server-side type is dangerous because of where it lands, not what it is. CWE-434 describes code execution when an uploaded file is interpreted as code, especially for extensions such as `.asp` and `.php` that are often treated as executable regardless of file permissions [38]. ATT&CK defines a web shell as a web script placed on an accessible server to use it as a gateway into the network ([T1505.003](/mitre/techniques/T1505-003.md)) [37], and CAPEC-650 Upload a Web Shell to a Web Server links to it [39].

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.php` | PHP script | PHP interpreter via the web server's handler map | Executes when requested from a mapped directory | CVE-2026-48356 (Adobe Commerce and Magento dangerous-type upload), KEV 2026-10-27 [1]; CVE-2024-4577 (PHP-CGI on Windows through Best-Fit character mapping, a bypass of CVE-2012-1823), KEV 2024-06-12, known ransomware use [4][1]; CISA AA23-158A records the DEWMODE PHP web shell on Accellion FTA in 2020 and 2021 [93] | [T1505.003](/mitre/techniques/T1505-003.md), CWE-434; [PHP](/languages/php.md) |
| `.phtml` | PHP template | PHP, where mapped | Alternative extension that a main-extension blocklist misses | OWASP lists `.phtml`, `.php5` and `.pht` as extensions a server may map to PHP [87] | CWE-434 |
| `.php5` | PHP 5 script | PHP, where mapped | Same | OWASP [87] | CWE-434 |
| `.pht` | PHP script variant | PHP, where mapped | Same | OWASP [87] | CWE-434 |
| `.phar` | PHP archive | `phar://` stream wrapper; PHP if the server maps `.phar` | A packaged PHP application | PHP 8.0 stopped automatically unserializing phar metadata, to fix vulnerabilities caused by object instantiation and autoloading [92]; to run one from a browser the server must map `.phar` to PHP, so that mapping should not apply to upload directories [92] | CWE-502, [CAPEC-586](/mitre/capec/CAPEC-586.md) |
| `.asp` | Classic ASP page | IIS | Executes server-side | CWE-434 names `.asp` [38] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.aspx` | ASP.NET page | IIS and ASP.NET | Executes server-side; the type in recent mass exploitation | July 2025 SharePoint attacks dropped `spinstall0.aspx` to read MachineKey data [33]; CVE-2025-53770, KEV 2025-07-20, known ransomware use [1]; LEMURLOOT on MOVEit (CVE-2023-34362) from 2023-05-27 per CISA AA23-158A [93]; ASR `a8f5898e-1dc8-49a9-9878-85004b8a61e6` blocks web shell creation on Exchange servers [8] | [T1505.003](/mitre/techniques/T1505-003.md), [T1190](/mitre/techniques/T1190.md); [SharePoint ToolShell case study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [CL0P file transfer case study](/case-studies/CL0P_FILE_TRANSFER_2023.md) |
| `.ashx` | ASP.NET generic handler | IIS | Executes if the handler map allows | IIS `<handlers>` binds handlers to extensions [26] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.asmx` | ASP.NET web service | IIS | Same | IIS `<handlers>` [26] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.jsp` | JavaServer Page | Servlet containers | Executes server-side | CVE-2017-12615 (Tomcat PUT upload of a JSP on Windows), KEV 2022-03-25, known ransomware use [4][1]; CVE-2025-24813 (Tomcat partial PUT), KEV 2025-04-01 [4][1]; CVE-2025-31324 (SAP NetWeaver Visual Composer upload), KEV 2025-04-29, known ransomware use [4][1] | [T1505.003](/mitre/techniques/T1505-003.md), CWE-434 |
| `.jspx` | JSP in XML syntax | Servlet containers | Alternative extension | OWASP [87] | CWE-434 |
| `.cfm` | ColdFusion markup page | Adobe ColdFusion | A repeat file-type risk on one server product | CVE-2018-15961 (unrestricted upload), KEV 2021-11-03, and CVE-2023-26360 (deserialization), KEV 2023-03-15 [1] | CWE-434, CWE-502 |
| `.cgi` | Common Gateway Interface program | Web server, where `ExecCGI` is enabled | Any script becomes an executable in a CGI directory | Apache restricts CGI to `ScriptAlias` directories or `Options ExecCGI` [90] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.pl` | Perl script | Perl, or the web server as CGI | Same | Apache CGI documentation [90] | [T1059](/mitre/techniques/T1059.md) |
| `.rb` | Ruby script | Ruby, or the web server as CGI | Same | Apache CGI documentation [90] | [T1059](/mitre/techniques/T1059.md) |
| `.htaccess` | Apache per-directory configuration | Apache, where `AllowOverride` permits | A writable upload directory that honours it can be remapped to execute uploads | Apache warns that `.htaccess` lets users change configuration the administrator cannot control [90] | [T1505.003](/mitre/techniques/T1505-003.md), CWE-434 |
| `web.config` | IIS and ASP.NET configuration | IIS | Write access in an upload path equals choosing which extensions execute (Inferred) | IIS `<handlers>` documentation [26] | [T1505.003](/mitre/techniques/T1505-003.md) |
| `.html` | HTML document | Browser | HTML smuggling builds the payload in the browser, so gateways that inspect EXE, ZIP or DOCX attachments see nothing | Microsoft documented HTML smuggling with NOBELIUM (May 2021), Mekotio, AsyncRAT and Trickbot (2021-11-11) [28]; CVE-2026-21513 (MSHTML bypass through a crafted HTML or `.lnk` file), KEV 2026-02-10 [2][1]; not on Outlook's or Gmail's lists; EOP optional only; Chromium no danger level [5][34][6][36] | [T1027.006](/mitre/techniques/T1027-006.md); [HTML](/formats/html.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md) |
| `.htm` | HTML document | Browser | Same | Same lists as `.html` [5][6] | [T1027.006](/mitre/techniques/T1027-006.md) |
| `.mht` | MHTML web archive | The `mhtml` handler | The handler that reopened retired Internet Explorer | Check Point reported `.url` files using the `mhtml` handler to open Internet Explorer (Reported) [130]; CVE-2024-38112, KEV 2024-07-09 [1]; CVE-2024-43461 (MSHTML spoofing in the same chain), KEV 2024-09-16 [2] | [T1218.005](/mitre/techniques/T1218-005.md), [T1036.008](/mitre/techniques/T1036-008.md) |
| `.mhtml` | MHTML web archive | The `mhtml` handler | The same web archive format as `.mht`, opened by the handler that reopened retired Internet Explorer | Handled by the `mhtml` protocol handler as in CVE-2024-38112, KEV 2024-07-09 [130][1] | [T1036.008](/mitre/techniques/T1036-008.md) |

### Configuration, secrets and keys

ATT&CK lists the private key and certificate extensions adversaries search for (`.key`, `.pgp`, `.gpg`, `.ppk`, `.p12`, `.pem`, `.pfx`, `.cer`, `.p7b`, `.asc`) and directories such as `~/.ssh` ([T1552.004](/mitre/techniques/T1552-004.md)) [37]. Credentials in files ([T1552.001](/mitre/techniques/T1552-001.md)) cover password files, shared stores, service configuration and cloud credential files [37]. GitHub secret scanning checks the entire Git history on all branches and reports partner-type secrets to the issuer for revocation [103]; OWASP recommends detection before commit and immediate rotation, noting that rewriting Git history has side effects [88].

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.key` | Private key | TLS servers, SSH and crypto tooling | Direct credential material | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md); [Secrets Management](/SECRETS_MANAGEMENT_REFERENCE.md) |
| `.pem` | PEM-encoded key or certificate | TLS and crypto tooling | May hold a private key as well as certificates | [T1552.004](/mitre/techniques/T1552-004.md) [37]; IANA `application/pem-certificate-chain` [177] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.pfx` | PKCS #12 key and certificate bundle | Windows certificate import | A private key protected by one password | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md); [Cryptography](/CRYPTOGRAPHY_REFERENCE.md) |
| `.p12` | PKCS #12 bundle | Crypto tooling; the JDK keytool default store type [46] | Same as `.pfx` | IANA `application/pkcs12` [177]; [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.cer` | X.509 certificate | Certificate viewers | Certificates are trust decisions; validation bugs spoof them | CVE-2020-0601 (CryptoAPI spoofing), KEV 2021-11-03 [1] | [T1553.004](/mitre/techniques/T1553-004.md) |
| `.p7b` | PKCS #7 certificate bundle | Certificate import | Installs chains | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1553.004](/mitre/techniques/T1553-004.md) |
| `.ppk` | PuTTY private key | PuTTY tools | SSH credential | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.gpg` | OpenPGP data or keyring | GnuPG | May hold secret keys | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.pgp` | OpenPGP data | PGP tooling | Same | [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.asc` | ASCII-armored OpenPGP data | GnuPG | Same | IANA `application/pgp-keys` [177]; [T1552.004](/mitre/techniques/T1552-004.md) [37] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.jks` | Java KeyStore (the older Java-specific type) | JDK `keytool`, Java applications | Private keys protected only by the store password | Oracle keytool (JDK 21) [46] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.keystore` | Java keystore by convention | Java applications | Same | Oracle keytool [46] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.kdbx` | KeePass database | KeePass and compatibles | The whole file is encrypted with a key derived by AES-KDF or Argon2; a stolen copy is an offline guessing target (Inferred) | KeePass security help [101] | [T1555.005](/mitre/techniques/T1555-005.md) |
| `.ovpn` | OpenVPN profile | OpenVPN clients | Inline sections allow one file to carry the CA, client certificate, private key and TLS auth key (Inferred from the inline-file support); `--script-security` defaults to level 1 | OpenVPN 2.6 manual [102] | [T1552.004](/mitre/techniques/T1552-004.md) |
| `.env` | Key-value file loaded into environment variables | Application frameworks | Plain text with no access control of its own (Inferred) | OWASP Secrets Management Cheat Sheet [88] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-538 |
| `.netrc` | Auto-login credentials | `ftp`, `curl` and others | Stores passwords; GNU ftp refuses auto-login if the file with a password is readable by others | GNU Inetutils manual [95] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-256 |
| `.npmrc` | npm configuration | `npm` | Can hold `_auth` and `_authToken`; must be scoped to a registry | npm v10 documentation [96] | [T1552.001](/mitre/techniques/T1552-001.md), [T1195.001](/mitre/techniques/T1195-001.md); [npm case study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) |
| `.pypirc` | PyPI upload configuration | `twine` and packaging tools | A `password` field is plain text | PyPA specification [97] | [T1552.001](/mitre/techniques/T1552-001.md) |
| `.git-credentials` | Git store-helper credentials | Git | Passwords written unencrypted, protected only by file permissions | git-credential-store [94] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-256 |
| `kubeconfig` | Kubernetes client configuration (no fixed extension) | `kubectl` and client libraries | A crafted kubeconfig can execute code through exec credential plugins, on top of the cluster credentials it holds | Kubernetes documentation [98] | [T1552.001](/mitre/techniques/T1552-001.md); [Kubernetes Security](/KUBERNETES_SECURITY_REFERENCE.md) |

### Data and interchange formats

Data formats are "safe" only when the loader is. The library's [formats](/formats/README.md) pages carry the parser-level detail for each.

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.txt` | Plain text | Text editors | The extension attackers rename executables to | EOP true-type matching still detects an `.exe` renamed to `.txt` [6] | [T1036.008](/mitre/techniques/T1036-008.md) |
| `.json` | JavaScript Object Notation | Parsers in every language | Interchange for APIs, logs and threat intelligence; type confusion in loaders | RFC 8259 (December 2017) registers `.json` [178]; STIX 2.1 serializes as JSON [168] | No technique bound; [JSON](/formats/json.md) |
| `.jsonl` | JSON Lines (one JSON value per line, UTF-8, no BOM) | Log and data tooling | A truncated last line loses one record, not the file | JSON Lines specification [159] | No technique bound; [JSON](/formats/json.md) |
| `.ndjson` | Newline-delimited JSON | Stream and log tooling | Interchangeable with JSON Lines for exports | NDJSON 1.0.0 (last updated 2014-10-19) [159] | No technique bound; [JSON](/formats/json.md) |
| `.yaml` | YAML document | YAML loaders | Tag resolution can trigger code execution in unsafe loaders, and anchors allow exponential expansion | RFC 9512 (February 2024) section 4 on arbitrary code execution and resource exhaustion [179]; PyYAML warns that `yaml.load` on untrusted data carries the same risk as `pickle.load` and may call any Python function, and points to `yaml.safe_load` [104] | CWE-502, CWE-776; [YAML](/formats/yaml.md) |
| `.yml` | YAML document (alternative extension) | YAML loaders | Same | RFC 9512 lists `yaml` (preferred) and `yml` [179] | CWE-502; [YAML](/formats/yaml.md) |
| `.xml` | XML document | XML parsers | External entities, DTDs and stylesheets extend trust to every referenced document | RFC 7303 (July 2014) security considerations [180]; CVE-2026-125350 (Chromium XML component use-after-free), KEV 2026-11-10 [1]; CWE-611 [41] | [T1220](/mitre/techniques/T1220.md), CWE-611; [XML](/formats/xml.md) |
| `.dtd` | XML document type definition | XML parsers | External DTDs and parameter entities redefine defaults | RFC 7303 registers `.dtd` [180] | CWE-611, CWE-776 |
| `.ent` | XML external entity file | XML parsers | Entity declarations loaded from outside the document | RFC 7303 registers `.ent` [180] | CWE-611 |
| `.csv` | Comma-separated values | Spreadsheets, text tools | Cells beginning with `=` are evaluated as formulas when opened in a spreadsheet | RFC 4180 (October 2005, Informational) [160]; OWASP CSV injection [89] | CWE-1236; [CSV](/formats/csv.md) |
| `.toml` | Tom's Obvious, Minimal Language | Configuration loaders | Configuration that holds secrets in many projects (Inferred) | TOML v1.0.0, published 2021-01-11, extension `.toml`, media type `application/toml` [182]; IANA registration [177] | No technique bound; [TOML](/formats/toml.md) |
| `.md` | Markdown | Renderers, editors | Rendered to HTML, so raw HTML in Markdown reaches the browser where the renderer allows it (Inferred) | RFC 7763 (March 2016) registers `text/markdown` with `.md` and `.markdown` [181] | CWE-79; [Markdown](/formats/markdown.md) |
| `.markdown` | Markdown | Same | Same | RFC 7763 [181] | CWE-79; [Markdown](/formats/markdown.md) |
| `.parquet` | Apache Parquet columnar file | Data tooling | Footer-indexed: a truncated file is unreadable as a whole | "PAR1" magic at both ends, metadata in the footer [162]; IANA `application/vnd.apache.parquet` [177] | No technique bound; [Security Data Engineering](/SECURITY_DATA_ENGINEERING_REFERENCE.md) |

### Media, fonts and images with an exploit record

Image, font and media parsers run automatically: in previews, message apps, thumbnails and font rendering. The KEV catalog records exploited decoders across every major platform.

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.png` | Portable Network Graphics | Image decoders everywhere | Decoded inside Office documents and fonts as well as viewers | CVE-2013-1331 (crafted PNG data in an Office document), KEV 2022-06-08 [1]; CVE-2020-15999 (FreeType, PNG embedded in fonts, in Chrome), KEV 2021-11-03 [1] | [T1203](/mitre/techniques/T1203.md), [T1027.003](/mitre/techniques/T1027-003.md) |
| `.jpg` | JPEG image | Image decoders | The canonical masquerade example | [T1036.008](/mitre/techniques/T1036-008.md) uses the JPEG header `FF D8` as its example [37]; SigmaHQ `cc7abbd0-762b-41e3-8a26-57ad50d2eea3` flags `mshta.exe` given a `.jpg` [42] | [T1036.008](/mitre/techniques/T1036-008.md), [T1027.003](/mitre/techniques/T1027-003.md) |
| `.jpeg` | JPEG image | Image decoders | Same | IANA `image/jpeg` [177]; [T1036.008](/mitre/techniques/T1036-008.md) [37] | [T1036.008](/mitre/techniques/T1036-008.md) |
| `.webp` | WebP image | Browsers, messaging apps, OS image libraries | A zero-click decoder reached by any page or message | CVE-2023-4863 (WebP heap overflow), KEV 2023-09-13 [1] | [T1203](/mitre/techniques/T1203.md); [Browser Security](/BROWSER_SECURITY_REFERENCE.md) |
| `.svg` | Scalable Vector Graphics (XML that can carry script) | Browsers, webmail, image viewers | Script and HTML in an "image"; used for smuggling | CVE-2025-68461 (Roundcube XSS through an SVG `animate` tag), KEV 2026-02-20 [1]; CVE-2024-37383 (Roundcube SVG animate attributes), KEV 2024-10-24 [1]; CVE-2016-9079 (Firefox SVG Animation), KEV 2023-06-22 [1]; absent from Outlook, Gmail and both EOP lists; Chromium no danger level [5][34][6][36]; the library's ATT&CK data carries T1027.017 SVG Smuggling [41] | [T1027.017](/mitre/techniques/T1027-017.md), [CAPEC-209](/mitre/capec/CAPEC-209.md) |
| `.djvu` | DjVu document image | ExifTool and document viewers | Metadata parsers run on uploads | CVE-2021-22204 (ExifTool DjVu code execution), KEV 2021-11-17 [1]; CVE-2021-22205 (GitLab image uploads passed to ExifTool), KEV 2021-11-03, known ransomware use [1] | [T1190](/mitre/techniques/T1190.md) |
| `.mvg` | Magick Vector Graphics | ImageMagick | An image coder that could reach a shell | CVE-2016-3714 (ImageMagick EPHEMERAL, HTTPS, MVG, MSL and other coders), KEV 2024-09-09 [1] | [T1190](/mitre/techniques/T1190.md) |
| `.msl` | Magick Scripting Language | ImageMagick | Same | CVE-2016-3714, KEV 2024-09-09 [1] | [T1190](/mitre/techniques/T1190.md) |
| `.eps` | Encapsulated PostScript | Office graphics filters, PostScript interpreters | A programming language inside an image | CVE-2015-2545 (crafted EPS image in Office), KEV 2022-03-03 [1] | [T1203](/mitre/techniques/T1203.md) |
| `.ttf` | TrueType font | Font engines in kernels, browsers and Office | Fonts parse in privileged code | CVE-2011-3402 (TrueType parsing in `win32k.sys`), KEV 2025-10-06 [1]; CVE-2014-4148 and CVE-2015-1671 (TrueType), KEV 2022-05-25 [1]; CVE-2025-27363 (FreeType, TrueType GX and variable fonts), KEV 2025-05-06 [1]; CVE-2023-41990 (Apple, code execution processing a font file), KEV 2024-01-08 [1] | [T1203](/mitre/techniques/T1203.md), [T1068](/mitre/techniques/T1068.md) |
| `.otf` | OpenType font | Font engines | Same | CVE-2015-2426 (Adobe Type Manager Library, crafted OpenType fonts), KEV 2022-03-28 [1]; CVE-2020-27930 (Apple FontParser), KEV 2021-11-03 [1] | [T1203](/mitre/techniques/T1203.md) |
| `.pfb` | Adobe Type 1 font (binary) | Windows Adobe Font Manager Library | Multi-master Type 1 fonts reached Windows font parsing | CVE-2020-0938 and CVE-2020-1020 (Adobe Type 1 PostScript multi-master fonts), KEV 2021-11-03 [1] | [T1203](/mitre/techniques/T1203.md) |
| `.pfm` | Adobe Type 1 font metrics | Windows font loader | Companion file to `.pfb` | CVE-2020-0938 and CVE-2020-1020, KEV 2021-11-03 [1] | [T1203](/mitre/techniques/T1203.md) |
| `.swf` | Adobe Flash movie | Flash Player (end of life) | A retired plugin with a long exploited record | CVE-2018-4878 (KEV 2021-11-03, known ransomware use), CVE-2015-5119 (KEV 2022-03-03) and CVE-2016-4117 (KEV 2022-03-03, known ransomware use) [1]; IANA `application/vnd.adobe.flash.movie` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.mp4` | MPEG-4 media | OS media frameworks, players | Media is parsed on receipt and preview | CVE-2025-31200 (Apple, audio stream in a crafted media file), KEV 2025-04-17; the entry names no extension [1]; IANA `video/mp4` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.mov` | QuickTime movie | Apple media frameworks | Same | CVE-2025-43200 (Apple, crafted photo or video shared through an iCloud Link), KEV 2025-06-16; no extension named [1]; IANA `video/quicktime` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.m4a` | MPEG-4 audio | OS media frameworks | Same | CVE-2025-31200, KEV 2025-04-17 (audio stream in a media file) [1]; IANA `audio/mp4` [177] | [T1203](/mitre/techniques/T1203.md) |

Several KEV entries for image decoders name the library rather than a file extension: CVE-2023-41064 (Apple ImageIO, crafted image, chained with CVE-2023-41061; KEV 2023-09-11), CVE-2025-43300 (Apple Image I/O out-of-bounds write; KEV 2025-08-21) and CVE-2025-21043 (Samsung `libimagecodec.quram.so`; KEV 2025-10-02) [1]. Treat any image type those libraries decode as in scope.

Common types with a registered media type and no exploited-vulnerability entry in the sources used here:

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.gif` | GIF image | Image decoders | A routine decoder target; also a steganography carrier (Inferred) | IANA `image/gif` [177] | [T1027.003](/mitre/techniques/T1027-003.md) |
| `.bmp` | Bitmap image | Image decoders | Uncompressed pixels hide data easily (Inferred) | IANA `image/bmp` [177] | [T1027.003](/mitre/techniques/T1027-003.md) |
| `.tif` | TIFF image | Image decoders, Office | A complex container format | IANA `image/tiff` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.tiff` | TIFF image | Same | Same | IANA `image/tiff` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.heic` | HEIF image (HEVC) | Apple and Android image stacks | Decoded by the same OS image libraries named above (Inferred) | IANA `image/heic` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.heif` | HEIF image | Same | Same | IANA `image/heif` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.avif` | AV1 image | Browsers | Newer decoder | IANA `image/avif` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.jxl` | JPEG XL image | Browsers and viewers that support it | Newer decoder | IANA `image/jxl` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.ico` | Windows icon | Explorer and browsers | Parsed when a folder or page is displayed | IANA `image/vnd.microsoft.icon` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.emf` | Enhanced Metafile | Windows GDI, Office | A record-based drawing format replayed by the renderer | IANA `image/emf` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.wmf` | Windows Metafile | Windows GDI, Office | Same family as `.emf` | IANA `image/wmf` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.mp3` | MPEG audio | Players, OS media frameworks | Routine media parser | IANA `audio/mpeg` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.flac` | FLAC audio | Players | Routine media parser | IANA `audio/flac` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.ogg` | Ogg container | Browsers, players | Routine media parser | IANA `audio/ogg` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.woff` | Web Open Font Format | Browsers | Fonts downloaded by any page | IANA `font/woff` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.woff2` | WOFF 2.0 | Browsers | Same | IANA `font/woff2` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.eot` | Embedded OpenType | Legacy browsers | Legacy web font | IANA `application/vnd.ms-fontobject` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.ttc` | TrueType collection | Font engines | Several fonts in one file | IANA `font/collection` [177] | [T1203](/mitre/techniques/T1203.md) |
| `.epub` | EPUB e-book (a ZIP of XHTML) | E-readers, browsers | HTML and script inside a ZIP (Inferred) | IANA `application/epub+zip` [177] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.stl` | Stereolithography 3D model | 3D tools | Uncommon mail type parsed by niche software | IANA `model/stl` [177] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.obj` | Wavefront 3D model | 3D tools | Same | IANA `model/obj` [177] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.glb` | Binary glTF 3D model | Browsers, 3D viewers | Same | IANA `model/gltf-binary` [177] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.dcm` | DICOM medical image | PACS and medical viewers | Medical images carry patient data and a preamble ahead of the DICOM header (Inferred) | IANA `application/dicom` [177] | [T1027.009](/mitre/techniques/T1027-009.md) |
| `.wasm` | WebAssembly module | Browsers and runtimes | Compiled code delivered as a web asset | IANA `application/wasm` [177] | [T1059.007](/mitre/techniques/T1059-007.md) |

### macOS

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.app` | Application bundle | Finder and LaunchServices | Gatekeeper checks signing and notarization at first open | CVE-2021-30657 (Gatekeeper bypass, CWE-862), fixed in Big Sur 11.3, KEV 2021-11-03 [1][4]; CVE-2022-42821 fixed in Monterey 12.6.2, Big Sur 11.7.2 and Ventura 13 [4]; Developer ID, Hardened Runtime and a secure timestamp are notarization prerequisites [71] | [T1553.001](/mitre/techniques/T1553-001.md), [T1553.002](/mitre/techniques/T1553-002.md); [macOS Security](/MACOS_SECURITY_REFERENCE.md) |
| `.pkg` | Installer package (flat package) | macOS Installer | `preinstall` and `postinstall` scripts run with the installer's elevated rights | [T1546.016](/mitre/techniques/T1546-016.md) [37]; notarization accepts flat installer packages [71]; IANA `application/vnd.apple.installer+xml` [177] | [T1546.016](/mitre/techniques/T1546-016.md) |
| `.dmg` | Apple disk image (UDIF) | DiskImageMounter | Delivery wrapper for apps; propagation of quarantine depends on the tool | Notarization accepts UDIF disk images [71]; Gmail blocks [34]; 7-Zip opens DMG since 4.59 beta and APFS inside DMG since 22.00 [47] | [T1553.001](/mitre/techniques/T1553-001.md) |
| `.kext` | Kernel extension bundle | Kernel | Full access to the operating system | On macOS 11, kexts need administrator approval, a restart and Reduced Security; Apple points developers to system extensions [73]; EOP default lists `kext` [6] | [T1547.006](/mitre/techniques/T1547-006.md) |
| `.dylib` | Dynamic library | `dyld` | A library with an expected name in a searched path loads with the app's privileges and entitlements | [T1574.004](/mitre/techniques/T1574-004.md) [37]; `DYLD_INSERT_LIBRARIES` ([T1574.006](/mitre/techniques/T1574-006.md)) [37] | [T1574.004](/mitre/techniques/T1574-004.md) |
| `.plist` | Property list (XML or binary) | macOS frameworks, `launchd` | Launch agent plists with `RunAtLoad` or `KeepAlive` run at every login | [T1647](/mitre/techniques/T1647.md) [37]; [T1543.001](/mitre/techniques/T1543-001.md) lists the LaunchAgents directories [37]; binary plists need conversion before reading [76] | [T1647](/mitre/techniques/T1647.md), [T1543.001](/mitre/techniques/T1543-001.md), [T1543.004](/mitre/techniques/T1543-004.md) |
| `.mobileconfig` | Configuration profile (XML) | System Settings profile installer | Installs certificates, accounts and network settings; treat as an installer that changes trust, not a document (Inferred) | Apple Platform Deployment, device management profiles (2026-09-17): distributed by mail or web, opening it prompts installation [74] | [T1553.004](/mitre/techniques/T1553-004.md) |
| `.command` | Shell script that Finder opens in Terminal | Terminal | Looks like a document, runs as a script (Inferred; no Apple page documents it) | No Apple page documents the type; what the Gatekeeper page says: it checks apps, plug-ins and installer packages and names no scripts [69] | [T1059.004](/mitre/techniques/T1059-004.md) |
| `.terminal` | Terminal settings document | Terminal | Can specify a command to run (Inferred) | Terminal User Guide: exported profiles end in `.terminal` and are imported from Finder [186] | [T1059.004](/mitre/techniques/T1059-004.md) |
| `.webloc` | Web location (a plist holding a URL) | Finder, default browser | Leads to navigation like `.url` on Windows (Inferred) | No Apple page documents the type; what the Gatekeeper page says: it checks apps, plug-ins and installer packages and names no documents [69] | [T1204.002](/mitre/techniques/T1204-002.md) |

### Linux

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| (none) ELF | Executable and Linkable Format binary | The kernel loader | The header, not a name, decides how the kernel treats it | elf(5) [78]; EOP default lists `elf` as a true type [6] | [T1036.008](/mitre/techniques/T1036-008.md) |
| `.so` | Shared object | `ld.so` | Preloaded through `LD_PRELOAD`, `--preload` or `/etc/ld.so.preload`; ignored or restricted in secure-execution mode | ld.so(8) [78]; [T1574.006](/mitre/techniques/T1574-006.md) [37] | [T1574.006](/mitre/techniques/T1574-006.md); [Linux Hardening](/LINUX_HARDENING_REFERENCE.md) |
| `.ko` | Loadable kernel module | Kernel module loader | Ring 0 code; rootkits hide files, processes and connections | With `CONFIG_MODULE_SIG_FORCE` unsigned or unknown-key modules are refused; otherwise they load and taint the kernel with flag E [81]; [T1547.006](/mitre/techniques/T1547-006.md) [37] | [T1547.006](/mitre/techniques/T1547-006.md) |
| `.sh` | Shell script | Any shell; runs directly with a shebang and execute bit | Extension is irrelevant to execution | execve(2) [78] | [T1059.004](/mitre/techniques/T1059-004.md) |
| `.bash` | Bash script | Bash | Same | execve(2) [78] | [T1059.004](/mitre/techniques/T1059-004.md) |
| `.desktop` | Desktop Entry launcher | Desktop environment | Runs its `Exec` key; entries in XDG autostart directories run at session start | Desktop Entry Specification 1.5 (2020-04-27) [79]; [T1547.013](/mitre/techniques/T1547-013.md) [37] | [T1547.013](/mitre/techniques/T1547-013.md) |
| `.service` | systemd service unit | systemd | `ExecStart=` and `User=` define what runs at boot | systemd.service(5) [79] | [T1543.002](/mitre/techniques/T1543-002.md) |
| `.timer` | systemd timer unit | systemd | Activates the same-named `.service` on a schedule | systemd.timer(5) [79] | [T1053.006](/mitre/techniques/T1053-006.md) |
| `.run` | Self-extracting installer | The file itself | Runs with the user's rights and skips package-manager signature checks (Inferred) | AppImage concepts and execve(2) [59][78] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.bin` | Self-extracting installer or raw binary image | The file itself, or a flasher | Same as `.run` (Inferred); also a raw firmware encoding with no signature of its own [84] | GNU objcopy [84] | [T1204.002](/mitre/techniques/T1204-002.md), [T1542.001](/mitre/techniques/T1542-001.md) |
| `.bashrc` | Bash per-user startup file | Bash at every interactive start | Persistence without root | [T1546.004](/mitre/techniques/T1546-004.md) [37] | [T1546.004](/mitre/techniques/T1546-004.md) |
| `.profile` | Login shell startup file | Login shells | Same; `/etc/profile` and `/etc/profile.d` need root | [T1546.004](/mitre/techniques/T1546-004.md) [37] | [T1546.004](/mitre/techniques/T1546-004.md) |
| `.zshrc` | Zsh per-user startup file | Zsh (the macOS default shell) | Same | [T1546.004](/mitre/techniques/T1546-004.md) [37] | [T1546.004](/mitre/techniques/T1546-004.md) |

### Mobile

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.apk` | Android package (a ZIP with signatures) | Package installer | Sideloading bypasses store review | Signature schemes v1 to v4; Android 7.0 and later verify v2 and later; v1 leaves ZIP metadata unprotected [65]; installs from outside Google Play require the Install unknown apps opt-in [67]; Play Protect scans at install and periodically [68]; CVE-2017-13156 (Janus) [66]; Mobile T1476 and T1577 are in the library's Mobile ATT&CK data, which has no generated pages for them [41] | Mobile T1476 Deliver Malicious Application via Other Means, Mobile T1577 Compromise Application Executable; [Mobile Security](/MOBILE_SECURITY_REFERENCE.md), [Android](/operating-systems/android.md) |
| `.aab` | Android App Bundle | Google Play (publishing format, not installable) | Signing and APK generation move to Google Play | New apps must publish as AAB since August 2021 [67] | No technique bound; [Mobile Security](/MOBILE_SECURITY_REFERENCE.md) |
| `.xapk` | Third-party bundle of an APK with split APKs or OBB data | A separate installer app | Not an Android platform format; adds an unvetted installer (Inferred; no Google page defines it) | No Google page defines the type; what the alternative distribution page says about sideloading: Android blocks installs from sources other than Google Play until the user opts in through Install unknown apps [67]; Mobile T1476 is in the library's Mobile ATT&CK data [41] | Mobile T1476 |
| `.obb` | Android expansion file | The app that owns it | Large assets shipped beside an APK, often inside XAPK (Inferred) | APK expansion files: named `main` or `patch` with a version and package name, any format, saved in shared storage where the user and other apps can read them [187]; Mobile T1476 is in the library's Mobile ATT&CK data [41] | Mobile T1476 |
| `.dex` | Dalvik executable | Android Runtime | The code inside an APK; the Janus polyglot prepended one to an APK (Reported) | Android Security Bulletin, 2017-12-01 [66][4] | [T1027.009](/mitre/techniques/T1027-009.md) |
| `.ipa` | iOS app archive | iOS installer, MDM | All executable code must be Apple-signed; enterprise-signed apps bypass App Review | Apple Platform Security, app code signing [69]; Mobile T1476 is in the library's Mobile ATT&CK data [41] | Mobile T1476; [iOS](/operating-systems/ios.md) |
| `.ab` | Android `adb backup` archive | `adb` | From Android 12, apps targeting API 31 or higher are excluded unless they opt in | Android 12 behavior changes [67] | No technique bound; [Cloud, SaaS and Mobile Forensics](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md) |

### Firmware and embedded

NIST SP 800-193 (May 2018) sets platform firmware resiliency guidelines because a successful firmware attack can leave a system inoperable, perhaps permanently [86].

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.uf2` | USB Flashing Format (512-byte blocks with magic numbers and target addresses) | Microcontroller bootloaders over USB mass storage | The block layout defines no signature field, so authenticity is up to the bootloader (Inferred) | Microsoft UF2 specification [82] | [T1542.001](/mitre/techniques/T1542-001.md), [T1495](/mitre/techniques/T1495.md); [Firmware and IoT Security](/FIRMWARE_IOT_SECURITY_REFERENCE.md) |
| `.dfu` | USB Device Firmware Upgrade image with a DFU suffix | DFU tools | The suffix carries a CRC of the whole file, which detects corruption, not tampering (Inferred) | USB-IF DFU 1.1 (2004-08-05) [83] | [T1542.001](/mitre/techniques/T1542-001.md) |
| `.srec` | Motorola S-record | Programmers and bootloaders | An encoding of machine code with no signature of its own | GNU objcopy [84] | [T1542.001](/mitre/techniques/T1542-001.md) |
| `.fw` | Vendor firmware image | Vendor updaters, LVFS clients | Integrity depends on whether the device verifies a signature | LVFS asks vendors to declare signed or unsigned payloads [85] | [T1542.001](/mitre/techniques/T1542-001.md), [D3-FV](/mitre/d3fend/firmware-verification.md) |

### Virtualization, cloud and infrastructure as code

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.ovf` | Open Virtualization Format descriptor | Hypervisor import | Imports a whole guest, often with VMDK disks | DMTF Open Virtualization Format standard [185] | [T1204.002](/mitre/techniques/T1204-002.md); [Hypervisor Security](/HYPERVISOR_SECURITY_REFERENCE.md) |
| `.ova` | Single-file OVF appliance | Hypervisor import | Same, in one file | DMTF Open Virtualization Format standard [185] | [T1204.002](/mitre/techniques/T1204-002.md) |
| `.vmem` | VMware guest memory paging file | VMware Workstation | Holds guest RAM while running or for a powered-on snapshot | VMware Workstation Pro 25H2 documentation [146] | [T1005](/mitre/techniques/T1005.md) |
| `.vmsn` | VMware snapshot state | VMware Workstation | Running state at snapshot time | VMware documentation [146] | [T1005](/mitre/techniques/T1005.md) |
| `.vmss` | VMware suspended state | VMware Workstation | Memory of a suspended VM | VMware documentation [146] | [T1005](/mitre/techniques/T1005.md) |
| `.vmsd` | VMware snapshot metadata | VMware Workstation | Index of snapshots | VMware documentation [146] | [T1005](/mitre/techniques/T1005.md) |
| `.std` | Suspended state in some earlier VMware products | VMware | Same as `.vmss` | VMware documentation [146] | [T1005](/mitre/techniques/T1005.md) |
| `.tfstate` | Terraform state (plain text locally) | Terraform | Resource attributes can include initial database passwords and API tokens; keep it out of Git | HashiCorp Terraform sensitive data page [99] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-312; [Terraform](/commands/terraform.md) |
| `.tfplan` | Terraform plan | Terraform | Values marked sensitive are still written to state and plan; only ephemeral values are omitted | HashiCorp Terraform [99] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-532 |
| `.tfvars` | Terraform variables | Terraform (auto-loads `terraform.tfvars`, `*.auto.tfvars`) | A committed variables file becomes both a repository secret and a state secret | HashiCorp Terraform input variables [99] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-798 |
| `Dockerfile` | Container build instructions (no extension) | Docker and BuildKit | Build arguments and environment variables persist in the final image | Docker build secrets documentation [100] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-538; [Container Security](/CONTAINER_SECURITY_REFERENCE.md), [Docker](/commands/docker.md) |
| `compose.yaml` | Docker Compose file | Docker Compose | Passwords in environment variables can be exposed to all processes and printed in logs; secrets mount as files | Docker Compose secrets documentation [100] | [T1552.001](/mitre/techniques/T1552-001.md), CWE-532 |
| Kubernetes Secret manifest (`.yaml`) | Secret object definition | `kubectl` | Base64, not encryption; Secrets are stored unencrypted in etcd by default | Kubernetes Secrets (2026-07-23) [98] | [T1552.007](/mitre/techniques/T1552-007.md), CWE-312 |

### Machine learning and data science

Model files are code more often than their names suggest. The library's [Hugging Face supply chain case study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) covers malicious models on the Hub (Part 3), loaders and scanners (Part 4) and the defender view (Part 8), and [ModelScan](/ai-tooling/tools/MODELSCAN.md) is one scanner.

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.pkl` | Python pickle | `pickle`, `joblib`, ML loaders | Unpickling can execute arbitrary code | The Python documentation says never to load pickle data from an untrusted or tampered source [108]; CVE-2025-1716 (picklescan before 0.0.21 missed `pip` as an unsafe global) [4] | CWE-502, CWE-184, [T1195.002](/mitre/techniques/T1195-002.md); [AI Security](/AI_SECURITY_REFERENCE.md) |
| `.pickle` | Python pickle | Same | Same | Python documentation [108] | CWE-502 |
| `.pt` | PyTorch file (a ZIP64 archive whose object data is a pickle since 1.6) | `torch.load` | `torch.load` defaults to `weights_only=True` from 2.6, which restricts the unpickler to an allowlist | PyTorch 2.15 serialization notes [109]; CVE-2025-32434 (code execution even with `weights_only=True` in 2.5.1 and earlier, fixed in 2.6.0) [4] | CWE-502, [T1195.002](/mitre/techniques/T1195-002.md) |
| `.pth` | PyTorch file (same format by convention) | `torch.load` | Same | `torch.load` defaults to `weights_only=True` from 2.6; CVE-2025-32434 [109][4] | CWE-502 |
| `.bin` (model weights) | Pickled PyTorch weights on model hubs | `transformers`, `torch.load` | Pickle is the default PyTorch weight format; Hub scanning shows imports but ClamAV does not cover pickle exploits | Hugging Face pickle scanning [110]; files of 2 GB or more are not malware-scanned [110] | CWE-502, [T1195.002](/mitre/techniques/T1195-002.md) |
| `.safetensors` | Tensors plus a header, no executable objects | `safetensors` loaders | The format built to replace pickle for weights | Hugging Face safetensors documentation [111] | [D3-FFV](/mitre/d3fend/file-format-verification.md) |
| `.npy` | NumPy array | `numpy.load` | Object arrays are pickled; `allow_pickle` is `False` by default | NumPy 2.5 documentation [112] | CWE-502 |
| `.npz` | Zipped NumPy arrays | `numpy.load` | Same | NumPy 2.5 documentation [112] | CWE-502 |
| `.h5` | HDF5 (legacy Keras model format) | Keras | Loading a model could run code | CVE-2024-3660 (Keras before 2.13), CERT/CC [4] | CWE-94, [T1195.002](/mitre/techniques/T1195-002.md) |
| `.keras` | Keras v3 model archive | `keras.Model.load_model` | `safe_mode=True` was not enough | CVE-2025-1550: a hand-built archive's `config.json` could name arbitrary modules and functions [4] | CWE-94, [T1195.002](/mitre/techniques/T1195-002.md) |
| `.gguf` | GGML inference model | llama.cpp and bindings | Metadata can carry a Jinja chat template | GGUF specification [113]; CVE-2024-34359 (llama-cpp-python rendered the template unsandboxed) [4] | CWE-1336, [T1195.002](/mitre/techniques/T1195-002.md) |
| `.onnx` | ONNX model graph | ONNX Runtime | Safer than pickle only while it uses built-in operators (Inferred) | ONNX Runtime custom operators [114] | [T1195.002](/mitre/techniques/T1195-002.md) |
| `.ipynb` | Jupyter notebook (JSON) | Jupyter | Output HTML and JavaScript is trusted only with a stored signature; code cells still run when the user runs them | Jupyter Server security [107] | [T1059.006](/mitre/techniques/T1059-006.md), [T1204.002](/mitre/techniques/T1204-002.md) |

### Email and messaging

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.eml` | Internet Message Format message | Mail clients | Received headers added before the receiving organization's own servers can be forged | RFC 5322 (October 2008) trace fields are informational [164] | [T1566.001](/mitre/techniques/T1566-001.md); [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Investigate a phishing email](/guides/INVESTIGATE_A_PHISHING_EMAIL.md) |
| `.msg` | Outlook item ([MS-OXMSG]): mail, appointment, contact or task | Outlook | Opening a crafted message can trigger outbound authentication | CVE-2026-124194 (Outlook spoofing, NTLMv2 disclosure on opening a crafted message file, Preview Pane not a vector), KEV 2026-11-10, due 2026-11-24 [2][1]; CVE-2023-23397 (Outlook NTLM relay), KEV 2023-03-14 [1]; [MS-OXMSG] [136] | [T1187](/mitre/techniques/T1187.md) |
| `.pst` | Outlook Personal Folders file | Outlook | A full offline mailbox | [MS-PST] [136] | [T1114.001](/mitre/techniques/T1114-001.md) |
| `.ost` | Outlook offline cache | Outlook | Cached copy of a server mailbox, up to 50 GB in Outlook 2010 and later (Reported) | [T1114.001](/mitre/techniques/T1114-001.md) [37] | [T1114.001](/mitre/techniques/T1114-001.md) |
| `.mbox` | Mailbox (concatenated messages) | Unix mail tools | Parsers disagree on message boundaries | RFC 4155 (September 2005) [164] | [T1114.001](/mitre/techniques/T1114-001.md) |
| `.ics` | iCalendar | Calendar and webmail clients | Invites are acted on automatically | RFC 5545 (September 2009) [164]; CVE-2024-27443 (Zimbra calendar invite XSS), KEV 2025-05-19, and CVE-2022-24682 (Zimbra Calendar XSS), KEV 2022-02-25 [1] | [T1566.001](/mitre/techniques/T1566-001.md) |
| `.vcf` | vCard contact | Contact apps | Personal data that falls under mailbox handling rules | RFC 6350 (August 2011) [164] | [T1114.001](/mitre/techniques/T1114-001.md) |

### Databases

| Extension | What it is | Opens with | Why it matters | Record | Library and MITRE |
|---|---|---|---|---|---|
| `.sqlite` | SQLite 3 database | SQLite and every app that embeds it | Deleted rows persist in free pages unless `secure_delete` is on, which it normally is not | SQLite file format and pragma documentation [165] | [T1005](/mitre/techniques/T1005.md); [SQLite](/databases/sqlite.md) |
| `.db` | Database file, often SQLite | Owning application | Identify by the 16-byte "SQLite format 3" header, not the name | SQLite file format [165]; IANA `application/vnd.sqlite3` [177] | [T1005](/mitre/techniques/T1005.md) |
| `.sql` | SQL script or plain-text dump | Database clients | Readable text that reproduces schema and data | pg_dump default output [166]; IANA `application/sql` [177] | [T1005](/mitre/techniques/T1005.md); [PostgreSQL](/databases/postgresql.md) |
| `.dump` | PostgreSQL custom-format archive (by convention) | `pg_restore` | A full binary data copy | pg_dump documentation [166] | [T1005](/mitre/techniques/T1005.md) |
| `.bak` | SQL Server backup | SQL Server | Integrity and confidentiality depend on `CHECKSUM` and `ENCRYPTION` chosen at backup time; the default is `NO_CHECKSUM` | SQL Server `BACKUP` [167] | [T1005](/mitre/techniques/T1005.md); [SQL Server](/databases/sql-server.md) |

SQLite in WAL mode keeps recent commits in a `-wal` file beside a `-shm` file, so copying only the `.db` loses data [165]. The Access types (`.accdb`, `.mdb`) are in the [Office table](#office-and-document-formats).

## Uncommon and dangerous

These are the rarely seen types the record shows being abused; the `.one` row gives the dated vendor response instead, since no abuse report is cited here. Most are absent from at least one default blocklist, which is likely part of why they appear in the record (Inferred).

| Extension | Dated example | What makes it work | Control that stops it |
|---|---|---|---|
| `.settingcontent-ms` | SpecterOps, 2018-06-11; CVE-2018-8414, KEV 2022-03-25 [133][1] | A settings shortcut whose `DeepLink` ran any binary | Outlook block [5]; SigmaHQ `24de4f3b-804c-4165-b442-5a06a2302c7e` [42] |
| `.library-ms` | CVE-2025-24054 exploited from 2025-03-19 (Reported), KEV 2025-04-17 [132][1] | Explorer touches the remote location on minimal interaction | Patch; Outlook block [5]; block outbound SMB [37]; SigmaHQ `5a7132c0-86db-4e6b-95c0-f0e9d7f461aa` [42] |
| `.msc` | CVE-2024-43572, KEV 2024-10-08; CVE-2025-26633, KEV 2025-03-11 [2][1] | Script inside a signed console host | Patch (untrusted `.msc` no longer opens) [2]; EOP default [6]; executable rules that govern `mmc.exe` [19] |
| `.appinstaller` | Abused from mid-November 2023; handler disabled 2023-12-28 [29] | A descriptor that bypassed SmartScreen and browser warnings | Keep `ms-appinstaller` off; `EnableMSAppInstallerProtocol` set to Disabled [2]; custom block (not on Outlook's list) [5] |
| `.rdp` | Midnight Blizzard from 2024-10-22 [30] | A signed file that maps local resources to an actor server | Custom transport rule or file-type policy, since no default list names it [5][6]; block outbound RDP |
| `.one` | Vendor response, not an abuse example: OneNote embedded-file block from Version 2304 (2023-05-01) [11] | Embedded files inside a note | OneNote extension block [11]; ASR child-process rule [8]; custom gateway block, since no default list names it [5][6][34] |
| `.diagcab` | CVE-2022-34713, KEV 2022-08-09 [1] | MSDT runs bundled troubleshooting scripts | MSDT retirement [18]; Outlook block [5] |
| `.ace` | CVE-2018-20250, KEV 2022-02-15 [1] | A 2006 library without exploit protections | Remove the handler (WinRAR dropped ACE) [119]; EOP default [6] |
| `.mht` | CVE-2024-38112, KEV 2024-07-09 (samples from January 2023, Reported) [1][130] | The `mhtml` handler reopening Internet Explorer | July and September 2024 updates together [2] |
| `.svg` | CVE-2025-68461, KEV 2026-02-20 [1] | Script inside an image type | Custom block or sanitization; no default list names it [5][34][6] |

Also watch (rarely seen and risky, but the sources here give no dated abuse example):

- `.theme` and `.themepack`: remote resource paths trigger SMB authentication; CVE-2023-38146 (2023-09-12), which MSRC marks as not exploited, and CVE-2024-21320 (2024-01-09) were disclosed and fixed, and neither is in KEV [2][1]; patch, disable NTLM where possible [2]; custom block for `.themepack` [5][6].
- `.rev`: RAR recovery volume reconstruction; CVE-2023-40477 in RAR4 recovery volumes was fixed in WinRAR 6.23 (2023-08-02) with no KEV entry [48][1]; keep WinRAR current [48].
- `.gguf`, `.keras`, `.pt`: model loaders that execute templates or code; CVE-2024-34359 (published 2024-05-10), CVE-2025-1550 (published 2025-03-11) and CVE-2025-32434 (published 2025-04-18) are disclosure dates, not exploitation dates [4]; load only trusted models, prefer `.safetensors` [111] and scan with the caveats in [110].
- `.wsb`: a sandbox pre-configured by the sender, networking on by default [22]; Outlook block [5]; disable Windows Sandbox where not needed.
- `.xll`: native code loaded by Excel; Excel default block [12]; EOP default [6]; SigmaHQ XLL rules [42].
- `.chm`: help viewer with script and ActiveX, tracked as [T1218.001](/mitre/techniques/T1218-001.md) [37]; Outlook block [5]; executable rules that govern `hh.exe` (Inferred from the documented collections) [19].
- `.scf`: icon path loaded on folder view, tracked as [T1187](/mitre/techniques/T1187.md) with Dragonfly [37]; block outbound TCP 139 and 445 [37]; Chromium DANGEROUS rating [36].
- `.ica`: a remote-session profile like `.rdp` (Inferred), absent from Microsoft lists [5][6]; custom block.
- `.jnlp`: launches where legacy Java remains, since Web Start was removed in JDK 11 [44]; remove legacy runtimes; Outlook and EOP blocks [5][6].
- `.ppk`, `.kdbx`, `.ovpn`: credential material in a single file, listed by [T1552.004](/mitre/techniques/T1552-004.md) and [T1555.005](/mitre/techniques/T1555-005.md) [37]; secret scanning [103]; file-access auditing; no secrets in shared folders.
- `.tfstate`: plaintext state with live secrets [99]; remote encrypted state; keep out of Git [99].
- `.phar`: PHP 8.0 stopped unserializing phar metadata automatically, to fix issues caused by object instantiation and autoloading [92]; current PHP; no `.phar` handler on upload paths [92].
- `.mobileconfig`: installs certificates and network settings [74]; MDM-only profile installation; user training (Inferred).

## Evidence and operations formats

Responders, detection engineers and intelligence teams work with their own file types. Each one records some things and not others, and each has a handling rule that decides whether it stands up later. The [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md), [Network Forensics Reference](/NETWORK_FORENSICS_REFERENCE.md) and [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) cover the procedures; this section covers the formats.

### Windows event and trace logs

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| Legacy Event Log | `.evt` | Fixed-size circular buffer of records (XP and Server 2003; unused from Vista) | Holds only the most recent window; gaps are overwrites, not proof of deletion | [137] |
| Windows XML Event Log | `.evtx` | Events written through ETW by providers declared in manifests | Message text depends on the provider manifest, so an export moved to another host can render incompletely; a dirty header is normal on a log copied while running | [137][142] |
| Security event 1102 | Inside `Security.evtx` | "The audit log was cleared," with provider `Microsoft-Windows-Eventlog` and an `EventRecordID` | Microsoft says it should not normally appear; log clearing is [T1685.005](/mitre/techniques/T1685-005.md) in ATT&CK v20.0, revoked from T1070.001 [41] | [137][37] |
| Archived logs | `.evtx` backups | `wevtutil` exports and the optional backup written when a log is cleared, plus auto-backup at maximum size | Look for archives beside the live log before treating a cleared log as gone | [137] |
| Log retention and access | `Eventlog` registry key | `Retention` (0 overwrites) and a `CustomSD` whose Clear right is `0x0004` | Configuration belongs in the evidence set with the log; turning logging off is [T1685.001](/mitre/techniques/T1685-001.md) | [137][37] |
| Event trace log | `.etl` | Kernel or application ETW events | Sessions count lost events and buffers; read the loss counters before reasoning from absence. WPP content may not decode without the provider's format data | [138] |
| Common Log File System | CLFS base logs | Kernel-managed transactional logs | The CLFS driver is itself attack surface: CVE-2025-29824 (KEV 2025-04-08, known ransomware use), CVE-2023-28252 (KEV 2023-04-11, known ransomware use) and CVE-2022-24521 (KEV 2022-04-13) [1] | [1] |

### Execution and NTFS artifacts

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| Prefetch | `.pf` | Run count and one to eight last-run times, named `<exe>-<hash>.pf` | Windows 10 and later compress it (MAM, XPRESS Huffman); a failed parse is not tampering. A name containing a colon points to execution from an alternate data stream ([T1564.004](/mitre/techniques/T1564-004.md)) | [142][37] |
| Shell Link | `.lnk` | A target that existed at some point, with metadata | Parse collected shortcuts; do not open them in Explorer on an analysis host, given CVE-2010-2568 and CVE-2017-8464 | [136][1] |
| Jump lists | `.automaticDestinations-ms`, `.customDestinations-ms` | Per-application recent and frequent files, in a Compound File Binary container with a `DestList` stream | Tools must walk the internal streams [MS-CFB] | [142][136][143] |
| Master File Table | `$MFT` | An entry for every file, including deleted ones until reuse | Compare `$STANDARD_INFORMATION` and `$FILE_NAME` times to spot timestomping ([T1070.006](/mitre/techniques/T1070-006.md)) | [139][37] |
| Change journal | `$UsnJrnl` (`$Max` and sparse `$J`) | Create, rename and delete history | Copy `$J` at its logical content; a missing or fresh journal on a volume that should have one is an integrity question | [139][142] |
| Transaction log | `$LogFile` | Short-lived metadata history replayed after a crash | Mounting read-write before imaging can replay and change it | [139] |
| Raw volume reads | All locked metafiles | The method collection tools use to copy them | The same method is [T1006](/mitre/techniques/T1006.md) Direct Volume Access, so document collection activity | [37] |
| Alternate data streams | `file:stream` | Hidden content sharing the host file's timestamps | Use tools that enumerate streams explicitly | [147] |

### Registry hives

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| System hives | `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT` in `System32\Config`, with `.log`, `.alt` and `.sav` companions | Machine configuration and local accounts | A REGF hive whose sequence numbers differ needs its `.LOG1` and `.LOG2` transaction logs applied | [140][142] |
| User hive | `NTUSER.DAT` | Per-user settings and Run-key persistence ([T1547.001](/mitre/techniques/T1547-001.md)) | Collect every profile separately | [140][37] |
| Class hive | `UsrClass.dat` | ShellBags folder-view history (Inferred; the Plaso page confirms only the `bagmru` parser) | Collect beside `NTUSER.DAT` | [143] |
| RegBack copies | `RegBack` folder | Formerly a second historical copy | Not written automatically since Windows 10 1803 | [140] |
| SAM plus SYSTEM | Hive copies | Enough for offline hash extraction ([T1003.002](/mitre/techniques/T1003-002.md)) | Treat as credential material: encrypted storage, restricted access (Inferred) | [37] |

### Memory, crash dumps and virtual machine state

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| Hibernation file | `hiberfil.sys` | A compressed copy of RAM at hibernation | Must be decompressed before memory tools read it; the public format specification dates from 2014 | [141][142] |
| Page file | `pagefile.sys` | Paged-out process memory | Collect with the RAM image; Volatility 3 can layer a LiME image and a page file together | [141][144] |
| Kernel dumps | `.dmp` | Complete, Kernel, Small, Automatic or Active memory dump | A Small or Kernel dump cannot answer user-process questions; record the dump type | [141] |
| User-mode dumps | `.dmp`, `.mdmp` | A process's memory, written by `MiniDumpWriteDump` or ProcDump (v12.02, 2026-10-15) | Legitimate dumps look the same as credential theft ([T1003.001](/mitre/techniques/T1003-001.md)); record who made it and why | [141][37] |
| Raw memory images | `.raw`, `.mem`, `.lime`, `.vmem` | Physical memory | Volatility 3 does not acquire memory and needs symbol files (often downloaded) for Windows analysis; LiME's raw output loses physical offsets, so its `lime` or `padded` formats are the defensible choice | [144][145] |
| VMware state | `.vmem`, `.vmsn`, `.vmss`, `.vmsd`, `vmware.log` | Guest RAM, snapshot and suspend state | Snapshotting or suspending a VM captures RAM without running anything in the guest | [146] |
| Volatile sources in general | Swap, dump and hibernation files | Usernames, password hashes and contact data among others | A graceful shutdown can clear swap; decide shutdown order deliberately | [147] |

### Disk images and chain of custody

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| Raw bit-stream image | `.dd`, `.raw` | Every sector, including free and slack space | NIST SP 800-86 advises bit-stream imaging where evidence may reach legal or disciplinary action | [147] |
| Expert Witness Format | `.E01` to `.E99`, then `.EAA`; EWF2 `.Ex01`, `.Lx01` | Image segments plus case metadata, MD5 and (since EnCase 6.19) SHA-1 of the source | One image is a set of files; the embedded metadata does not replace the external custody log | [142] |
| AFF4 | `.aff4` | Advanced Forensic Format v4 | Test tool claims against the AFF4 Canonical Reference Images | [151] |
| Analysis compatibility | `.dd`, `.E01`, `.vhd`, `.vmdk`, `.aff` | Image formats The Sleuth Kit and Autopsy read | They read NTFS, FAT, exFAT, APFS, ext2/3/4, HFS, ISO 9660 and YAFFS2 regardless of host OS | [150] |
| Integrity routine | All images | Hash the original, hash the copy, compare, re-hash the original | SP 800-86 (2006) named MD5 and SHA-1; record SHA-256 today and keep the older digests only for compatibility | [147] |
| Write blocking | All media | Protection of the source | Test blockers routinely; a blocker cannot stop the OS caching changed MAC times in RAM | [147] |
| Logical collections | `.zip`, copied folders | Files without unallocated space | A copied file takes the copy time as its creation time and some logical tools alter creation times, so record the tool and settings, and image when file times matter | [147] |
| Mobile acquisitions | Vendor formats | Device state at a moment | Back-to-back acquisitions differ, so per-file hashes are the stable check; isolate the device from networks | [149] |

### Packet captures, flows and network logs

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| pcap | `.pcap` | Packets with one link type and one timestamp resolution | IETF draft-ietf-opsawg-pcap-04 (2024-08-04) describes it | [152] |
| pcapng | `.pcapng` | Blocks for multiple interfaces, comments and a Decryption Secrets Block | A capture with a DSB holds key material; handle it like the plaintext it unlocks | [152] |
| Capture editing | `.pcap`, `.pcapng` | `editcap` can shift timestamps, split, deduplicate and add or discard secrets and comments | The collection-time hash is what proves a working copy unaltered; `capinfos -H` prints SHA-256 | [153] |
| Endace ERF | `.erf` | Records with a loss counter between card and buffer | ERF can document its own capture loss | [153] |
| NetFlow v9 | Exporter stream | Template-based flow records, possibly sampled | Metadata, not payload | [154] |
| IPFIX | Exporter stream | Data records described by templates, with IANA information elements | Unreadable without its templates | [154] |
| Zeek | `conn.log` and related logs (TSV or JSON) | Protocol summaries linked by `uid` | Nonzero `missed_bytes` flags capture gaps; payload questions need the pcap (Inferred) | [155] |
| Sniffing on endpoints | Capture files or drivers on non-sensor hosts | Adversary collection ([T1040](/mitre/techniques/T1040.md)) | An indicator, not only a defender artifact | [37] |

### Text and structured logs

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| syslog | RFC 5424 messages (RFC 3164 for BSD syslog over UDP 514) | Host and application events | RFC 5424 warns messages can be altered in transit and have no confidentiality; use a secure transport | [156] |
| Any archived log | `.log` | Text events | Hash each archived file and store the digest securely; logs may capture passwords; rootkits alter logs | [148] |
| Time | All logs | Each host's own clock | Synchronize with NTP, normalize time zones and record both with every export | [148] |
| ArcSight CEF | Syslog payload | Pipe-delimited header and key-value extension (Version 26, October 2023) | Unescaped attacker-controlled values shift fields ([CWE-117](/CWE_REFERENCE.md)) | [157] |
| IBM LEEF | Syslog or file import | QRadar event format, UTF-8 | New sources need about 25 events before auto-identification | [158] |
| JSON Lines and NDJSON | `.jsonl`, `.ndjson` | One JSON value per line | A truncated last line loses one record | [159] |
| CSV exports | `.csv` | Tabular exports with varying quoting and encoding | Record the exporting tool; open in a text viewer or import with formulas off ([CWE-1236](/CWE_REFERENCE.md)) | [160][89] |
| Microsoft Purview audit export | `.csv` with an `AuditData` JSON column | Microsoft 365 audit events | Capped at 50,000 rows (Standard) or 1,000,000 (Premium) per search; a capped export is silently partial | [161] |
| Parquet | `.parquet` | Columnar data with a footer index | Truncation loses the whole file | [162] |
| Current logging baseline | All | The 2024-08-21 joint guidance led by ASD's ACSC with CISA and partners | Cite it next to the 2006 NIST SP 800-92 | [163] |

Plaso (log2timeline, documentation 20261027) ships parsers for EVT, EVTX, Prefetch, LNK, `$MFT`, `$UsnJrnl:$J`, REGF, plist, SQLite, PE, jump lists, JSON-L logs, Apple Unified Logging and the Microsoft 365 audit log, so most of these formats can merge into one timeline, each limited to what its format records [143].

### Apple and mobile evidence

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| Property lists | `.plist` (XML or binary) | App and system configuration; persistence ([T1647](/mitre/techniques/T1647.md)) | Convert binary plists before reading; changed plists are integrity-monitoring targets | [76][37] |
| iOS local backups | Backup folder | Device data; encrypted backups add passwords, Wi-Fi settings, history, Health and call history | Not encrypted by default; encrypted backups hold more and need the backup password | [75] |
| Android `adb backup` | `.ab` | App data, now mostly excluded for apps targeting API 31 | Not a substitute for full acquisition | [67] |
| Android Auto Backup | Google Drive | App data up to 25 MB per app, end-to-end encrypted on Android 9 and later | Some data may exist only in the user's cloud account | [67] |

### Threat intelligence, detection content and exports

| Format | Extension or name | What it records | Handling notes | Source |
|---|---|---|---|---|
| STIX 2.1 | `.json` | Objects, relationships and indicators (OASIS Standard, 2021-06-10) | A bundle carries no meaning by itself; indicators need `pattern`, `pattern_type` and `valid_from`; keep data markings intact when converting | [168] |
| TAXII 2.1 | HTTPS API | API Roots, Collections and Channels | The transport, not a file type | [168] |
| MISP | `.json` | Events and attributes with `distribution` and `to_ids` | Attributes with `to_ids` false should not drive blocking | [169] |
| OpenIOC 1.1 | `.ioc` (XML) | Indicator logic (2013 Mandiant draft) | Predates STIX 2.x | [170] |
| YARA | `.yar`, `.yara` | Matching rules: `rule`, optional `strings`, required `condition` | A miss can reflect a format guard in the rule, such as a `pe` module condition, not absence of content | [171] |
| Sigma | `.yml` | Detection rules: YAML, UTF-8, LF, 4-space indentation, lowercase keys. Required: `title`, `logsource`, and `detection` with a `condition`. Optional but recommended: `id`, a random UUID v4, with a new id preferred after a major logic change. Optional: `falsepositives`, `level`, `tags` and the `logsource` `category`, `product` and `service` (specification 2.1.0, 2025-08-02) | Converted queries depend on backends and field mappings; test them on the target SIEM | [43][172] |
| Snort 3 and Suricata | `.rules` | Header (action, protocol, addresses, ports, direction) and options | Similar but not fully interchangeable; validate per engine ([D3-NTSA](/mitre/d3fend/network-traffic-signature-analysis.md)) | [173] |
| ATT&CK Navigator layer | `.json` (format 4.5) | Scores, colors and comments per technique | An annotated view, not proof of coverage; check old layers for v20 renames such as T1070.001 to T1685.005 | [174] |
| Nessus v2 | `.nessus` (XML) | Targets, policy and results (format revised 2016-11-18) | Passwords are not stored, but the file maps hosts to open vulnerabilities | [175] |
| SARIF 2.1.0 | `.sarif` | Static analysis results with fingerprints, suppressions and baseline state (OASIS Standard, 2020-03-27) | Review suppressions; they are findings too | [176] |
| SPDX | `.spdx`, `.spdx.json` | Software bill of materials; 2.2.1 is ISO/IEC 5962:2021, current Linux Foundation version 3.0.1 | Check the major version; 2.x and 3.x models differ | [106] |
| CycloneDX | `bom.json`, `bom.xml`, `*.cdx.json`, `*.cdx.xml` | BOMs, vulnerability disclosure and VEX; ECMA-424 2nd edition (December 2025) standardizes v1.7 | XML and JSON media types are IANA-registered; the protobuf type is unregistered. A CycloneDX file may be an exploitability statement, not a component list | [105] |

The D3FEND countermeasures that fit this section are File Carving ([D3-FC](/mitre/d3fend/file-carving.md)), File Analysis ([D3-FA](/mitre/d3fend/file-analysis.md)) and File Integrity Monitoring ([D3-FIM](/mitre/d3fend/file-integrity-monitoring.md)), all present in the library's D3FEND data [41].

## Controls

No single file-type control is sufficient, and each fails on a documented axis: extension blocklists miss archives (Outlook's own page says so), detonation misses encrypted containers, Mark of the Web misses FAT32 media, and SmartScreen misses network shares [5][7][9][21]. Layer them. The [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md) and [Windows Hardening GPO](/WINDOWS_HARDENING_GPO.md) carry deployment detail.

### Attachment blocklists as published

| Type | Outlook blocked list [5] | Gmail [34] | Microsoft 365 common attachments filter [6] | Chromium download policy [36] |
|---|---|---|---|---|
| `.exe`, `.scr`, `.com`, `.pif` | Blocked | Blocked | Default | User gesture, no auto-open (Windows) |
| `.dll` | Not listed | Blocked | Default | DANGEROUS |
| `.lnk` | Blocked | Blocked | Default | User gesture |
| `.url` | Blocked | Not listed | Optional | User gesture |
| `.library-ms`, `.search-ms`, `.settingcontent-ms` | Blocked | Not listed | Neither list | User gesture |
| `.iso` | Blocked | Blocked | Default | No danger level; inspected with the DMG parser |
| `.img` | Blocked | Blocked | Default | User gesture (Windows and macOS) |
| `.vhd` | Blocked | Blocked | Optional | No danger level |
| `.vhdx` | Blocked | Not listed | Neither list | No danger level |
| `.xll` | Blocked | Blocked | Default | User gesture |
| `.docm` | Not listed | Malicious macros refused | Default | No danger level |
| `.xlsm`, `.xlsb`, `.pptm`, `.dotm` | Not listed | Malicious macros refused | Optional | No danger level |
| `.one` | Not listed | Not listed | Optional | Not listed |
| `.html`, `.htm` | Not listed | Not listed | Optional | No danger level |
| `.svg` | Not listed | Not listed | Neither list | No danger level |
| `.zip`, `.7z`, `.rar` | Not listed | Listed types refused inside archives | Optional | Inspected as archives |
| `.rdp`, `.themepack` | Not listed | Not listed | Neither list | Not listed |
| `.ica` | Not listed | Not listed | Neither list | No danger level |
| `.msix` | Not listed | Blocked | Default | User gesture |
| `.appinstaller` | Not listed | Not listed | Neither list | Not listed |

"Neither list" means the type is in neither the filter's default list nor its additional selectable types. The Gmail entries come from Google's published page, which is undated [34]. Two behaviors matter more than any single cell. The Microsoft 365 filter rejects matches with an NDR by default, and because the block is administrator policy those messages get no malware verdict [6]. For Exchange accounts the administrator can unblock Outlook types, so the list is a default, not a fixed control [5].

Across the four lists, no default list blocks or flags `.one` or `.svg`, while `.iso` and `.xll` are covered by all three mail lists (Inferred from the cross-read) [5][34][6][36].

### Attack surface reduction rules

| Rule | GUID | File types it acts on | Source |
|---|---|---|---|
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Executables (`.exe`, `.dll`, `.scr`), scripts (`.ps1`, `.vbs`, `.js`) and archives (`.zip`) from Outlook and webmail | [8] |
| Block executable files unless they meet a prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` | `.exe`, `.dll`, `.scr`; needs cloud-delivered protection | [8] |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` | `.js`, `.vbs` downloaders; needs Defender Antivirus and AMSI | [8] |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | PowerShell and other scripts; needs Defender Antivirus, AMSI and Cloud Protection | [8] |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Word, Excel, PowerPoint, OneNote, Access documents; enforced only when Office is under Program Files | [8] |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` | Code that Office or macros write to disk | [8] |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | VBA in `.docm`, `.xlsm`, `.dotm` | [8] |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` | `.pdf` | [8] |
| Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | `.exe`, `.dll`, `.scr` on removable drives ([T1091](/mitre/techniques/T1091.md)) | [8] |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` | `.sys` written to disk (not loading of drivers already present) | [8] |
| Block Webshell creation for Servers | `a8f5898e-1dc8-49a9-9878-85004b8a61e6` | Server web scripts on Exchange servers; Intune only | [8] |

Tampering with these controls is [T1685](/mitre/techniques/T1685.md) Disable or Modify Tools in ATT&CK v20.0; T1562.001 is revoked to it in the library data [41].

### AppLocker and App Control for Business

AppLocker enforces five rule collections by extension: executables (`.exe`, `.com`), Windows Installer (`.msi`, `.mst`, `.msp`), scripts (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`), DLLs (`.dll`, `.ocx`) and packaged apps (`.appx`) [19]. The DLL collection is off by default for performance and compatibility, and the script collection does not name `.hta`, `.wsf`, `.jse`, `.vbe` or `.chm`, so those depend on executable rules for their hosts (Inferred from the documented collections) [19].

App Control for Business (WDAC) enforces scripts by default unless policy option 11 disables it [20]. Unallowed `.ps1`, `.psm1` and `.psd1` still run but only in Constrained Language Mode; Windows Script Host scripts are blocked unless allowed; MSHTA and MSXML execution is blocked whenever a policy with script enforcement is active, even in audit mode [20]. It does not directly control `.bat` and `.cmd` run by `cmd.exe` or scripts run by unenlightened third-party hosts, so allowing such a host allows every script it runs [20]. Decisions are logged as events 8028, 8029, 8037 and 8038 [20]. D3FEND names these countermeasures Executable Allowlisting ([D3-EAL](/mitre/d3fend/executable-allowlisting.md)) and Executable Denylisting ([D3-EDL](/mitre/d3fend/executable-denylisting.md)) [40].

### Mark of the Web, SmartScreen and archiver settings

SmartScreen checks downloaded files and their signing certificates for reputation and treats an item with no established reputation as higher risk; it checks files that any app downloads, including third-party browsers and mail clients [21]. It does not cover UNC paths or SMB shares [21]. On the archive side, set 7-Zip to propagate `Zone.Identifier` (available since 22.00) and WinRAR's "Propagate Mark of the Web" option (7.00 and later; 7.10 also marks nested archives unless set to Never) [47][48]. WinRAR 7.10 added a "Zone value only" option because full mark fields such as the download URL can be a privacy concern when files are shared [48]. Keep archivers current: the KEV record above shows WinRAR, 7-Zip and WinZip each losing the mark in some version [1][4].

### Office defaults with dates

| Default | Date | Source |
|---|---|---|
| VBA macros from the internet blocked (Access, Excel, PowerPoint, Visio, Word) | Current Channel 2206 on 2022-07-27; Monthly Enterprise 2208 on 2022-10-11; Semi-Annual Enterprise 2208 on 2023-01-10 | [9] |
| Same block for Publisher, then Project | 2023-02-14; 2024-08-13 | [9] |
| Excel add-ins with Mark of the Web stay blocked even when signed | Since MS16-088 (2016) | [9] |
| OneNote blocks embedded files with dangerous extensions | Version 2304, Current Channel 2023-05-01; Semi-Annual Enterprise 2308 on 2024-01-09 | [11] |
| Untrusted XLL add-ins blocked by default | Not dated; the support page (2025-04-04) gives no rollout date | [12] |
| ActiveX in documents blocked by default; Baseline Security Mode stops overrides, opens legacy formats in Protected View, blocks DDE server launches and Publisher | Baseline Security Mode settings page, 2026-11-12 | [10] |
| `ms-appinstaller` protocol handler disabled by default | 2023-12-28 | [29] |

A file whose user chose Enable content before the block arrived stays a Trusted Document and keeps running macros [9].

### Browser download protection

Chrome blocks dangerous downloads automatically, can send suspicious files for deeper Safe Browsing scanning under Enhanced protection, and warns on password-protected files that may be dangerous [35]. Chromium's policy file treats any unlisted extension as NOT_DANGEROUS with auto-open allowed, so absence from the list means no extension-based warning [36]. It marks `.dll`, `.local`, `.manifest` and `.scf` DANGEROUS on Windows, requires a user gesture for `.exe`, `.lnk`, `.hta`, `.js`, `.ps1`, `.msi`, `.scr`, `.reg`, `.cpl`, `.wsf`, `.url`, `.xll`, `.search-ms`, `.library-ms` and `.settingcontent-ms`, inspects `.zip` and `.rar` as archives, and does not list `.one` or `.appinstaller` [36].

### Upload validation

For any service that accepts files, OWASP's guidance reduces to six rules [87]:

1. Allow only the extensions the business needs, checked after decoding the file name; treat blocklists as weak on their own.
2. Validate the file signature as well as the extension, never the client's `Content-Type` alone.
3. Rename uploads to an application-generated name such as a UUID.
4. Store uploads outside the web root or on a separate host so the server never interprets them.
5. Pass PDF and DOCX uploads through content disarm and reconstruction, and plan for ZIP and XML bombs; avoid accepting ZIP at all where possible.
6. Reject file names containing a colon (NTFS streams) and normalize case.

On the server, remove script handlers from upload directories: no `ExecCGI` or `.htaccess` overrides on Apache, no handler overrides in an upload path's `web.config` on IIS, no `.phar` mapping, and `noexec` and `nosuid` mounts on Linux [90][26][92][78]. The KEV record shows what happens otherwise: Versa Director's favicon upload expected a `.png` and accepted a dangerous type (CVE-2024-39717, KEV 2024-08-23) [1], and Cleo Harmony, VLTrader and LexiCom before 5.8.0.21 allowed unrestricted upload and download (CVE-2024-50623, KEV 2024-12-13, known ransomware use) [4][1]. D3FEND's [D3-FFV](/mitre/d3fend/file-format-verification.md) File Format Verification is the matching countermeasure [40].

### Sandboxing and detonation

Safe Attachments in Microsoft Defender for Office 365 detonates attachments in a virtual environment after anti-malware scanning, usually within 15 minutes [7]. Dynamic Delivery sends the body with placeholders until scanning finishes and works only for Exchange Online mailboxes [7]. Password-protected attachments cannot be fully detonated without the password; administrators can quarantine them and recipients can submit the password once for a rescan, and exclusions are by true type in three groups (PDF; archives; Office documents) [7]. D3FEND calls this Dynamic Analysis ([D3-DA](/mitre/d3fend/dynamic-analysis.md)), mapped to [T1204.002](/mitre/techniques/T1204-002.md) and [T1566.001](/mitre/techniques/T1566-001.md) in both the library data and the live API [40][41].

Windows Sandbox is a local option for opening a suspicious file, with the caveat in the catalog: a `.wsb` from someone else carries the sender's configuration, not the recipient's [22].

## Detections

Detection by file type works on three signals: a type appearing where it should not (a disk image in a mail temp folder), a handler doing what it should not (Office spawning a script host), and provenance being removed. The rules below are from SigmaHQ at master `54967d64e6`; each entry names what the rule looks for, not its body [42]. The [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md), [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) and [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) carry more.

| Rule (SigmaHQ) | Id | What it looks for | File types |
|---|---|---|---|
| ISO Image Mounted | `0248a7bc-8a9a-4cd8-a57e-3ae8e073a073` | An ISO mount in the Windows Security log | `.iso` |
| ISO File Created Within Temp Folders | `2f9356ae-bf43-41b8-b858-4496d83b2acb` | `.iso` written to Outlook or AppData temp folders (cites Qakbot, late July 2022) | `.iso` |
| Phishing Pattern ISO in Archive | `fcdf69e5-a3d3-452a-9724-26f2308bf2b1` | An ISO opened from inside 7-Zip or WinRAR | `.iso` in `.zip`, `.rar` |
| VHD Image Download Via Browser | `8468111a-ef07-4654-903b-b863a80bbc95` | Browsers writing `.vhd` or `.vhdx` | `.vhd`, `.vhdx` |
| Office Macro File Download | `0e29e3a7-1ad8-40aa-b691-9f82ecd33d66` | Browsers or mail clients creating macro-enabled Office files | `.docm`, `.xlsm`, `.pptm` |
| File With Uncommon Extension Created By An Office Application | `c7a74c80-ba5a-486e-9974-ab9e682bc5e4` | Office writing executable or script extensions | Script and executable types |
| Suspicious File Created Via OneNote Application | `fcc6d700-68d9-4241-9a1a-06874d621b06` | Files dropped by OneNote | `.one`, `.onepkg` |
| OneNote.EXE Execution of Malicious Embedded Scripts | `84b1706c-932a-44c4-ae28-892b28a25b94` | Script hosts launched from OneNote | `.one` |
| Microsoft Excel Add-In Loaded From Uncommon Location | `af4c4609-5755-42fe-8075-4effb49f5d44` | XLL loads outside normal paths | `.xll` |
| Code Executed Via Office Add-in XLL File | `36fbec91-fa1b-4d5d-8df1-8d8edcb632ad` | XLL registration through PowerShell COM | `.xll` |
| Potential Persistence Via Microsoft Office Add-In | `8e1cb247-6cf6-42fa-b440-3f27d57e9936` | Add-ins placed for persistence | `.wll`, `.xll` |
| MSHTA Execution with Suspicious File Extensions | `cc7abbd0-762b-41e3-8a26-57ad50d2eea3` | `mshta.exe` given non-HTA types | `.png`, `.jpg`, `.zip`, `.pdf` polyglots |
| Remote CHM File Download/Execution Via HH.EXE | `f57c58b3-ee69-4ef5-9041-455bf39aaa89` | `hh.exe` opening remote help files | `.chm` |
| Suspicious Double Extension Files | `b4926b47-a9d7-434c-b3a0-adc3fa0bd13e` | Names with a document extension before an executable one | Double extensions |
| Suspicious LNK Double Extension File Created | `3215aa19-f060-4332-86d5-5602511f3ca8` | Shortcuts named like documents | `.lnk` |
| Potential File Extension Spoofing Using Right-to-Left Override | `979baf41-ca44-4540-9d0c-4fcef3b5a3a4` | U+202E in file names | Any |
| ADS Zone.Identifier Deleted By Uncommon Application | `3109530e-ab47-4cc6-a953-cac5ebcc93ae` | Unusual processes removing the mark | Any downloaded file |
| Suspicious Creation of .library-ms File (CVE-2025-24054) | `5a7132c0-86db-4e6b-95c0-f0e9d7f461aa` | `.library-ms` creation | `.library-ms` |
| Arbitrary Shell Command Execution Via Settingcontent-Ms | `24de4f3b-804c-4165-b442-5a06a2302c7e` | Settings shortcuts launching processes | `.settingcontent-ms` |
| Potential Webshell Creation On Static Website | `39f1f9f2-9636-45de-98f6-a4046aa8e4b9` | Server-script extensions written into a static web root | `.aspx`, `.php`, `.jsp` |
| WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript | `1e33157c-53b1-41ad-bbcc-780b80b58288` | Windows Script Host running script files (threat hunting) | `.js`, `.jse`, `.vba`, `.vbe`, `.vbs`, `.wsf`, `.wsh` |
| Rundll32 Execution With Uncommon DLL Extension | `c3a99af4-35a9-4668-879e-c09aeb4f2bdf` | DLLs renamed to other extensions | Renamed `.dll` |
| Regsvr32 DLL Execution With Suspicious File Extension | `089fc3d2-71e8-4763-a8a5-c97fbb0a403e` | Same for `regsvr32.exe` | Renamed `.dll` |
| CVE-2023-38331 Exploitation Attempt: Suspicious Double Extension File | `e4556676-fc5c-4e95-8c39-5ef27791541f` | Double extension with a space written by WinRAR | `.zip` |
| Suspicious Explorer Process with Whitespace Padding: ClickFix/FileFix | `3ae9974a-eb09-4044-8e70-8980a50c12c8` | The paste-to-run lure ([T1204.004](/mitre/techniques/T1204-004.md)), which uses no file | None |

Three cautions apply to these rules. The WinRAR rule is titled and tagged CVE-2023-38331, while the KEV entry is CVE-2023-38831, so a search by the correct CVE misses it [42][1]. SigmaHQ's ATT&CK tags are not authoritative bindings: the VHD rule is tagged [T1587.001](/mitre/techniques/T1587-001.md) Malware (Resource Development) and the OneNote script rule [T1218.001](/mitre/techniques/T1218-001.md) Compiled HTML File, so take technique ids from ATT&CK and the library data [42][41]. Current SigmaHQ rules tag former defense-evasion behavior with `attack.stealth`, matching ATT&CK v20.0; older third-party tag maps may still say defense-evasion [42].

Other file-type signals worth alerting on, from the sources above:

- Security event 1102 (audit log cleared) and missing collection from a source that should report ([T1685.005](/mitre/techniques/T1685-005.md), [T1685.001](/mitre/techniques/T1685-001.md)) [137][37].
- App Control script events 8028, 8029, 8037 and 8038 [20].
- The macOS Endpoint Security event for a Gatekeeper bypass on macOS 15 or later [69].
- A Prefetch name containing a colon, which points to execution from an alternate data stream [142].
- `.save` or `.dmp` files created after sequential access to `HKLM\SAM` and `HKLM\SYSTEM`, the pattern ATT&CK's detection guidance flags for [T1003.002](/mitre/techniques/T1003-002.md) [37].
- New `.service`, `.timer`, `.desktop` (autostart) or launch-agent `.plist` files, each a persistence location in the catalog [79][37].

## MITRE mappings

Every identifier below was checked against the library's data files at `origin/main` (`data/attack/technique_profiles.jsonl`, `data/attack/mobile/technique_profiles.jsonl`, `data/attack/superseded_by.jsonl`, `data/weaknesses/cwe.jsonl`, `data/weaknesses/capec.jsonl`, `data/attack/d3fend_countermeasures.jsonl` and `data/attack/technique_to_d3fend.jsonl`) [41].

### ATT&CK Enterprise techniques

Tactic names follow ATT&CK v20.0. Since v19, ATT&CK splits the former Defense Evasion tactic into Stealth and Defense Impairment: masquerading, obfuscation and proxy execution sit under Stealth, while subverting trust controls, modifying registry and disabling tools sit under Defense Impairment. Revoked ids are shown under their successors: T1070.001 is now [T1685.005](/mitre/techniques/T1685-005.md), T1562.001 is now [T1685](/mitre/techniques/T1685.md), and T1574.002 DLL Side-Loading now folds into [T1574.001](/mitre/techniques/T1574-001.md) DLL [41].

| Id | Name | Tactic (v20.0) | File types on this page | Source |
|---|---|---|---|---|
| [T1566.001](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | Initial Access | Every attachment type; `.rdp`, `.library-ms`, `.iso`, `.7z` campaigns | [37][30][132][115] |
| [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | `.aspx`, `.jsp`, `.php`, `.djvu`, `.mvg` upload and parsing paths | [33][93][1] |
| [T1195.001](/mitre/techniques/T1195-001.md) | Compromise Software Dependencies and Development Tools | Initial Access | `.npmrc`, `.pypirc`, `.egg` | [96][97][62] |
| [T1195.002](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | Initial Access | `.tar.xz` release tarballs, `.whl`, `.nupkg`, model files | [4][61][27][110] |
| [T1091](/mitre/techniques/T1091.md) | Replication Through Removable Media | Lateral Movement, Initial Access | Unsigned `.exe`, `.dll`, `.scr` on USB | [8] |
| [T1204.002](/mitre/techniques/T1204-002.md) | Malicious File | Execution | Most of the catalog | [37] |
| [T1204.004](/mitre/techniques/T1204-004.md) | Malicious Copy and Paste | Execution | The fileless paste-to-run lure | [42] |
| [T1203](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | `.doc`, `.rtf`, `.pdf`, `.ocx`, `.ttf`, `.otf`, `.webp`, `.png`, `.eps`, `.swf` | [1] |
| [T1059.001](/mitre/techniques/T1059-001.md) | PowerShell | Execution | `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.pssc` | [15][20] |
| [T1059.003](/mitre/techniques/T1059-003.md) | Windows Command Shell | Execution | `.bat`, `.cmd` | [6][20] |
| [T1059.004](/mitre/techniques/T1059-004.md) | Unix Shell | Execution | `.sh`, `.bash`, `.command` | [78] |
| [T1059.005](/mitre/techniques/T1059-005.md) | Visual Basic | Execution | `.vbs`, `.vbe`, `.wsf`, `.vba`, VBA in Office files | [18][9] |
| [T1059.006](/mitre/techniques/T1059-006.md) | Python | Execution | `.py` family, `.pkl`, `.ipynb` | [5][108][107] |
| [T1059.007](/mitre/techniques/T1059-007.md) | JavaScript | Execution | `.js`, `.jse`, `.mjs` | [134][34] |
| [T1559.001](/mitre/techniques/T1559-001.md) | Component Object Model | Execution | OLE in `.docx`; `.wsc` | [2] |
| [T1053.006](/mitre/techniques/T1053-006.md) | Systemd Timers | Execution, Persistence, Privilege Escalation | `.timer` | [79] |
| [T1137.001](/mitre/techniques/T1137-001.md) | Office Template Macros | Persistence | `.dot`, `.dotm`, `.xlt`, `.xltm`, `.pot`, `.potm` | [9] |
| [T1137.006](/mitre/techniques/T1137-006.md) | Add-ins | Persistence | `.xll`, `.wll`, `.xla`, `.xlam`, `.ppa`, `.ppam` | [12][9][42] |
| [T1505.003](/mitre/techniques/T1505-003.md) | Web Shell | Persistence | `.aspx`, `.php`, `.jsp`, `.war`, `.htaccess`, `web.config` | [37][93][33] |
| [T1176.001](/mitre/techniques/T1176-001.md) | Browser Extensions | Persistence | `.crx`, `.xpi` | [63][64] |
| [T1546.001](/mitre/techniques/T1546-001.md) | Change Default File Association | Privilege Escalation, Persistence | Handler registration | [39][41] |
| [T1546.002](/mitre/techniques/T1546-002.md) | Screensaver | Privilege Escalation, Persistence | `.scr` | [37] |
| [T1546.004](/mitre/techniques/T1546-004.md) | Unix Shell Configuration Modification | Privilege Escalation, Persistence | `.bashrc`, `.profile`, `.zshrc` | [37] |
| [T1546.016](/mitre/techniques/T1546-016.md) | Installer Packages | Privilege Escalation, Persistence | `.pkg`, `.deb`, `.rpm` | [37][80] |
| [T1547.001](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | Files dropped to Startup through `.rar` traversal; `NTUSER.DAT` | [118][140] |
| [T1547.006](/mitre/techniques/T1547-006.md) | Kernel Modules and Extensions | Persistence, Privilege Escalation | `.ko`, `.kext` | [81][73] |
| [T1547.009](/mitre/techniques/T1547-009.md) | Shortcut Modification | Persistence, Privilege Escalation | `.lnk` | [37] |
| [T1547.013](/mitre/techniques/T1547-013.md) | XDG Autostart Entries | Persistence, Privilege Escalation | `.desktop` | [37][79] |
| [T1543.001](/mitre/techniques/T1543-001.md) | Launch Agent | Persistence, Privilege Escalation | `.plist` | [37] |
| [T1543.002](/mitre/techniques/T1543-002.md) | Systemd Service | Persistence, Privilege Escalation | `.service` | [79] |
| [T1543.004](/mitre/techniques/T1543-004.md) | Launch Daemon | Persistence, Privilege Escalation | `.plist` | [37] |
| [T1542.001](/mitre/techniques/T1542-001.md) | System Firmware | Stealth, Persistence | `.uf2`, `.dfu`, `.fw`, `.bin`, `.srec` | [82][83][85] |
| [T1542.003](/mitre/techniques/T1542-003.md) | Bootkit | Stealth, Persistence | `.efi` | [14] |
| [T1068](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | `.sys`, `.msi` (CVE-2024-38014), fonts | [13][2][1] |
| [T1548.001](/mitre/techniques/T1548-001.md) | Setuid and Setgid | Privilege Escalation | Setuid ELF; `nosuid` mounts | [78] |
| [T1218](/mitre/techniques/T1218.md) | System Binary Proxy Execution | Stealth | `.diagcab`, `.url` working directory | [18][1] |
| [T1218.001](/mitre/techniques/T1218-001.md) | Compiled HTML File | Stealth | `.chm` | [37] |
| [T1218.002](/mitre/techniques/T1218-002.md) | Control Panel | Stealth | `.cpl` | [37] |
| [T1218.003](/mitre/techniques/T1218-003.md) | CMSTP | Stealth | `.inf` | [37] |
| [T1218.005](/mitre/techniques/T1218-005.md) | Mshta | Stealth | `.hta`, `.mht` | [37][130] |
| [T1218.007](/mitre/techniques/T1218-007.md) | Msiexec | Stealth | `.msi`, `.msp`, `.mst` | [37] |
| [T1218.010](/mitre/techniques/T1218-010.md) | Regsvr32 | Stealth | `.sct`, renamed `.dll` | [37][42] |
| [T1218.011](/mitre/techniques/T1218-011.md) | Rundll32 | Stealth | Renamed `.dll` | [42] |
| [T1218.014](/mitre/techniques/T1218-014.md) | MMC | Stealth | `.msc` | [37][2] |
| [T1220](/mitre/techniques/T1220.md) | XSL Script Processing | Stealth | `.xsl` | [37] |
| [T1221](/mitre/techniques/T1221.md) | Template Injection | Stealth | `.docx`, `.dotm`, `.odt`, `.ods` | [37][135] |
| [T1036.002](/mitre/techniques/T1036-002.md) | Right-to-Left Override | Stealth | Any file name | [37][77] |
| [T1036.006](/mitre/techniques/T1036-006.md) | Space after Filename | Stealth | Any file name | [39] |
| [T1036.007](/mitre/techniques/T1036-007.md) | Double File Extension | Stealth | Runnable types behind document extensions | [37] |
| [T1036.008](/mitre/techniques/T1036-008.md) | Masquerade File Type | Stealth | Renamed executables, `.jpg` header example | [37][6] |
| [T1027.003](/mitre/techniques/T1027-003.md) | Steganography | Stealth | Image types | [41] |
| [T1027.006](/mitre/techniques/T1027-006.md) | HTML Smuggling | Stealth | `.html`, `.htm` | [28] |
| [T1027.009](/mitre/techniques/T1027-009.md) | Embedded Payloads | Stealth | Polyglots, `.one`, `.dex` in `.apk` | [37][11][66] |
| [T1027.012](/mitre/techniques/T1027-012.md) | LNK Icon Smuggling | Stealth | `.lnk` | [37] |
| [T1027.013](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | Stealth | Password-protected archives, SFX | [37] |
| [T1027.015](/mitre/techniques/T1027-015.md) | Compression | Stealth | `.zip`, `.gz`, `.7z` and other archives | [37] |
| [T1027.017](/mitre/techniques/T1027-017.md) | SVG Smuggling | Stealth | `.svg` | [41] |
| [T1027.018](/mitre/techniques/T1027-018.md) | Invisible Unicode | Stealth | File names and text | [41] |
| [T1564.004](/mitre/techniques/T1564-004.md) | NTFS File Attributes | Stealth | Alternate data streams; Prefetch names with a colon | [142][147] |
| [T1070.006](/mitre/techniques/T1070-006.md) | Timestomp | Stealth | `$MFT` times | [37] |
| [T1006](/mitre/techniques/T1006.md) | Direct Volume Access | Stealth | Locked metafiles and hives | [37] |
| [T1014](/mitre/techniques/T1014.md) | Rootkit | Stealth | `.sys`, `.ko` | [13][37] |
| [T1553.001](/mitre/techniques/T1553-001.md) | Gatekeeper Bypass | Defense Impairment | `.app`, `.dmg`, `.zip` on macOS | [37][1][32] |
| [T1553.002](/mitre/techniques/T1553-002.md) | Code Signing | Defense Impairment | Signed `.exe`, `.msix`, `.rdp` | [1][29][30] |
| [T1553.004](/mitre/techniques/T1553-004.md) | Install Root Certificate | Defense Impairment | `.mobileconfig`, `.cer` | [74][1] |
| [T1553.005](/mitre/techniques/T1553-005.md) | Mark-of-the-Web Bypass | Defense Impairment | `.iso`, `.vhd`, `.7z`, `.rar`, `.url`, `.lnk`, `.js`, `.msi` | [37][1][2] |
| [T1647](/mitre/techniques/T1647.md) | Plist File Modification | Defense Impairment | `.plist` | [37] |
| [T1112](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | `.reg` | [6] |
| [T1685](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | Tampering with ASR and AV | [41] |
| [T1685.001](/mitre/techniques/T1685-001.md) | Disable or Modify Windows Event Log | Defense Impairment | `.evtx` collection gaps | [37][137] |
| [T1685.005](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs | Defense Impairment | `.evtx`, event 1102 | [37][137] |
| [T1187](/mitre/techniques/T1187.md) | Forced Authentication | Credential Access | `.scf`, `.lnk`, `.library-ms`, `.theme`, `.msg`, remote templates | [37][2] |
| [T1552.001](/mitre/techniques/T1552-001.md) | Credentials In Files | Credential Access | `.env`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `kubeconfig`, `.tfstate` | [37][99] |
| [T1552.004](/mitre/techniques/T1552-004.md) | Private Keys | Credential Access | `.key`, `.pem`, `.pfx`, `.p12`, `.ppk`, `.gpg`, `.asc`, `.jks`, `.ovpn` | [37] |
| [T1552.007](/mitre/techniques/T1552-007.md) | Container API | Credential Access | Kubernetes Secret manifests | [98] |
| [T1555.005](/mitre/techniques/T1555-005.md) | Password Managers | Credential Access | `.kdbx` | [101] |
| [T1003.001](/mitre/techniques/T1003-001.md) | LSASS Memory | Credential Access | Process `.dmp` files | [141] |
| [T1003.002](/mitre/techniques/T1003-002.md) | Security Account Manager | Credential Access | `SAM` and `SYSTEM` hive copies | [37] |
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | `.pcap`, `.pcapng` on non-sensor hosts | [37] |
| [T1114.001](/mitre/techniques/T1114-001.md) | Local Email Collection | Collection | `.pst`, `.ost`, `.mbox` | [37][136] |
| [T1005](/mitre/techniques/T1005.md) | Data from Local System | Collection | Database dumps, VM state files | [166][146] |
| [T1021.001](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | Lateral Movement | `.rdp` | [30] |
| [T1495](/mitre/techniques/T1495.md) | Firmware Corruption | Impact | `.uf2`, `.dfu` | [86] |
| [T1587.001](/mitre/techniques/T1587-001.md) | Malware | Resource Development | Only as a SigmaHQ tag on the VHD rule, not a binding this page uses | [42] |

ATT&CK for Mobile: T1476 Deliver Malicious Application via Other Means (Initial Access) and T1577 Compromise Application Executable (Persistence) apply to `.apk`, `.xapk` and enterprise-signed `.ipa`; both are in `data/attack/mobile/technique_profiles.jsonl`, and the library has no generated pages for them [41]. The [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md) covers the matrix.

### CWE and CAPEC

| Weakness | Name | Where it appears | CAPEC in the library | Source |
|---|---|---|---|---|
| CWE-646 | Reliance on File Name or Extension of Externally-Supplied File | Extension-only checks anywhere | [CAPEC-209](/mitre/capec/CAPEC-209.md) XSS Using MIME Type Mismatch | [38][41] |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | `.php`, `.aspx`, `.jsp`, `.cfm` uploads; CVE-2017-12615, CVE-2025-31324, CVE-2024-50623, CVE-2024-39717, CVE-2026-48356 | [CAPEC-1](/mitre/capec/CAPEC-1.md) | [38][1][39] |
| CWE-430 | Deployment of Wrong Handler | Handler maps on servers and desktops | [CAPEC-11](/mitre/capec/CAPEC-11.md) Cause Web Server Misclassification | [38][41] |
| CWE-351 | Insufficient Type Distinction | CVE-2023-38831 (assigned in KEV) | None in the library | [1][41] |
| CWE-693 | Protection Mechanism Failure | Mark of the Web and SmartScreen bypasses; CVE-2025-0411, CVE-2024-38217, CVE-2024-21412 | [CAPEC-17](/mitre/capec/CAPEC-17.md) Using Malicious Files, among others | [1][39][41] |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") | Zip Slip, CVE-2025-6218, CVE-2025-11001, CVE-2020-36193 | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal, among others | [120][1][4] |
| CWE-59 | Improper Link Resolution Before File Access | Symlinks in `.tar` and `.zip` (CVE-2025-55188, CVE-2020-36193) | [CAPEC-35](/mitre/capec/CAPEC-35.md) among others | [4][1][41] |
| CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | Zip bombs | None in the library | [121][41] |
| CWE-502 | Deserialization of Untrusted Data | `.pkl`, `.pt`, `.npy`, `.yaml`, `.phar`; CVE-2025-53770 | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection | [108][1][41] |
| CWE-94 | Improper Control of Generation of Code | `.h5`, `.keras` model loading | [CAPEC-35](/mitre/capec/CAPEC-35.md) | [4][41] |
| CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | `.gguf` chat templates (this page's mapping; the CVE record lists CWE-76) | None in the library | [4][41] |
| CWE-611 | Improper Restriction of XML External Entity Reference | `.xml`, `.ent`, `.dtd`, `.svg` | [CAPEC-221](/mitre/capec/CAPEC-221.md) Data Serialization External Entities Blowup | [180][41] |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs | XML and YAML expansion | [CAPEC-197](/mitre/capec/CAPEC-197.md) Exponential Data Expansion | [179][41] |
| CWE-1236 | Improper Neutralization of Formula Elements in a CSV File | `.csv` exports | None in the library | [89][41] |
| CWE-73 | External Control of File Name or Path | CVE-2025-33053 (`.url`), CVE-2025-24054 (`.library-ms`) | [CAPEC-13](/mitre/capec/CAPEC-13.md) Subverting Environment Variable Values, among others | [1][2] |
| CWE-451 | User Interface (UI) Misrepresentation of Critical Information | CVE-2024-43461 and CVE-2024-38112 | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing, among others | [2][1][41] |
| CWE-162 | Improper Neutralization of Trailing Special Elements | Deceptive file names | [CAPEC-635](/mitre/capec/CAPEC-635.md) | [39][41] |
| CWE-117 | Improper Output Neutralization for Logs | CEF fields; syslog tampering | [CAPEC-93](/mitre/capec/CAPEC-93.md), [CAPEC-268](/mitre/capec/CAPEC-268.md) | [157][156][41] |
| CWE-506 | Embedded Malicious Code | CVE-2024-3094 xz tarballs | None used here | [4] |
| CWE-184 | Incomplete List of Disallowed Inputs | CVE-2025-1716 picklescan; every extension blocklist | None used here | [4][41] |

Other CAPEC entries on this page: [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server (T1505.003), [CAPEC-556](/mitre/capec/CAPEC-556.md) Replace File Extension Handlers (T1546.001), [CAPEC-649](/mitre/capec/CAPEC-649.md) Adding a Space to a File Extension (T1036.006) and [CAPEC-636](/mitre/capec/CAPEC-636.md) Hiding Malicious Data or Code within Files (T1027.003, T1218.001, T1221) [39][41]. The library has no generated CWE pages; the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md) cover the classes.

### D3FEND countermeasures

| Countermeasure | Id | Library mappings to this page's techniques in `d3fend_countermeasures.jsonl` | Control it matches | Source |
|---|---|---|---|---|
| [File Format Verification](/mitre/d3fend/file-format-verification.md) | D3-FFV | Only T1564.009 in the library; the live D3FEND API maps it to about 100 techniques, including T1204.002 and T1566.001 | True-type matching, upload signature checks | [41][40] |
| [File Analysis](/mitre/d3fend/file-analysis.md) | D3-FA | T1204.002, T1566.001, T1187, T1218.005, T1218.011, T1220, T1505.003, T1547.009, T1574.001, T1114.001 and others | Static scanning; evidence parsing | [41] |
| [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md) | D3-EFA | T1204.002, T1566.001, T1218.005, T1220, T1137.001 | Emulation in gateways | [41] |
| [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) | D3-DA | T1204.002, T1566.001, T1218.005, T1220, T1505.003 | Safe Attachments detonation | [41][40][7] |
| [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) | D3-EAL | T1204.002, T1218.001, T1218.002, T1218.003, T1218.005, T1218.011, T1220, T1505.003, T1546.002, T1547.009 | AppLocker, App Control | [41][19][20] |
| [Executable Denylisting](/mitre/d3fend/executable-denylisting.md) | D3-EDL | Same set as D3-EAL | Driver blocklist, hash blocks | [41][13] |
| [Email Filtering](/mitre/d3fend/email-filtering.md) | D3-EF | T1566.001, T1114.001 | Attachment blocklists | [41][5][6] |
| [Content Filtering](/mitre/d3fend/content-filtering.md) | D3-CF | T1204.002, T1566.001 and others | Gateway and proxy content rules | [41] |
| [Content Quarantine](/mitre/d3fend/content-quarantine.md) | D3-CQ | T1204.002, T1566.001, T1546.001 and others | Quarantine of encrypted or blocked attachments | [41][7] |
| [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) | D3-FIM | T1543.001, T1543.002, T1546.004, T1547.006 and others | Watching persistence files and archived logs | [41][148] |
| [Local File Permissions](/mitre/d3fend/local-file-permissions.md) | D3-LFP | T1552.001, T1505.003 and others | Protecting secret files; upload directories | [41] |
| [File Carving](/mitre/d3fend/file-carving.md) | D3-FC | T1071.002, T1570 only | Recovering deleted records from freelists and unallocated space | [41][165] |
| [Firmware Verification](/mitre/d3fend/firmware-verification.md) | D3-FV | T1014, T1542.001 | Bootloader signature checks for `.uf2`, `.dfu`, `.fw` | [41][85] |
| [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md) | D3-SFV | T1542.001 | Platform firmware resiliency | [41][86] |
| [Software Update](/mitre/d3fend/software-update.md) | D3-SU | T1137.006, T1218.014, T1542.003, T1195.001, T1195.002 | Archiver, Office and boot manager updates | [41][14] |
| [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) | D3-NTSA | T1566.001, T1021.001, T1105 | Snort and Suricata `.rules` | [41][173] |

No countermeasure in the library's `technique_to_d3fend.jsonl`, and none in the live D3FEND entries checked for D3-FFV, D3-DA, D3-EF and D3-EAL, binds [T1553.005](/mitre/techniques/T1553-005.md), [T1036.007](/mitre/techniques/T1036-007.md), [T1036.008](/mitre/techniques/T1036-008.md) or [T1027.006](/mitre/techniques/T1027-006.md), so Mark of the Web propagation, true-type matching and HTML attachment policy are described above without a D3FEND id [41][40]. D3-FH and D3-FCR are not in the library data and are not used [41].

## What the record overstates and understates

- **Overstated: the ISO and macro era as today's exposure.** The three mail lists now cover `.iso` and `.xll`, and Office blocks internet macros by default, while no default list blocks or flags `.one` or `.svg` and `.html` sits only on optional lists (Inferred from the cross-read) [5][34][6][36][9]. Public attention trails the lists.
- **Overstated: a signature as proof.** CVE-2013-3900 kept a padded Authenticode file looking validly signed (KEV 2022-01-10) [1]; Magniber used malformed signatures to make SmartScreen skip its warning (Reported) [134]; Midnight Blizzard's `.rdp` files and the 2023 MSIX packages were signed [30][29].
- **Overstated: any one control.** Each fails on a documented axis: archives for Outlook's list, encrypted containers for detonation, FAT32 for Mark of the Web, network shares for SmartScreen (Inferred from the cited pages) [5][7][9][21]. Elastic also reports that reputation-based controls can be bypassed by signing, reputation hijacking, seeding and tampering, and described a shortcut rewrite ("LNK stomping") that dropped the mark before checks ran (Reported) [125]. CVE-2024-38217, fixed 2024-09-10, matches that behavior, but the Elastic post does not name the CVE, so the link is Inferred [2][125].
- **Overstated: SigmaHQ tags as ATT&CK bindings.** The VHD download rule carries a Resource Development tag and the OneNote script rule a Compiled HTML File tag [42].
- **Overstated: disputed records.** CVE-2022-29072, a claimed 7-Zip privilege escalation through a `.7z` dragged into Help, is disputed in its own record, which notes third parties reported that no escalation can occur [4].
- **Understated: old formats.** CISA keeps adding very old file-format bugs to KEV: CVE-2007-0671 (Excel, added 2025-08-12), CVE-2011-3402 (TrueType, 2025-10-06), CVE-2009-0556 (PowerPoint, 2026-01-07), CVE-2012-1854 (VBA DLL loading, 2026-04-13), CVE-2009-0238 (Excel, 2026-04-14) and CVE-2009-3459 (PDF, 2026-05-20) [1]. Retiring a legacy handler is a control, not housekeeping.
- **Understated: which file carried the exploit.** KEV entries for 2026 Windows Shell bypasses (CVE-2026-21510, CVE-2026-32202, CVE-2026-96951) name a component and weakness but no extension, and image-decoder entries name a library rather than a format [1]. A file-type view cannot be built from KEV alone (Inferred). The CVE-2026-96951 entry also carries an unusual three-day due date (added 2026-10-13, due 2026-10-16), quoted as the feed shows it [1].
- **Understated: exploitation that never reaches KEV.** ZDI-CAN-25373 (later CVE-2025-9491) was not serviced and is not in KEV as of 2026.11.10, yet Trend counted nearly 1,000 abusing `.lnk` samples and 11 state-sponsored groups (Reported) [128][127][1]. Exploitation status also changes after release: CVE-2023-36584 was marked not exploited on 2023-10-10 and added to KEV on 2023-11-16 [3][1].
- **Understated: archivers in the trust chain.** WinRAR, 7-Zip and WinZip each have a record of losing Mark of the Web, and KEV lists exploited flaws in both WinRAR and 7-Zip [1][4][47][48].
- **Understated: model files as programs.** `.pkl`, `.pt`, `.keras`, `.h5` and `.gguf` each have a code-execution record, and Hub scanning is best-effort with a 2 GB ceiling [4][108][110].
- **Understated: the library's own D3FEND data.** The library lists one ATT&CK technique for D3-FFV while the live API lists about 100; the difference is a lag in the library's copy of the D3FEND mappings (Inferred) [41][40].

## Sources

All sources were opened on 13 November 2026. "Confirmed" means the publisher is the primary for the fact as used here; "Reported" means a secondary account or a vendor's attribution, count or assessment; a source can be Confirmed for one use and Reported for another, as noted.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CISA Known Exploited Vulnerabilities catalog, JSON feed, catalog version 2026.11.10 (1,779 entries) | [cisa.gov/.../known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-13 | Confirmed |
| 2 | MSRC Security Update Guide entries: CVE-2021-40444, CVE-2021-43890, CVE-2022-34713, CVE-2022-41091, CVE-2022-44698, CVE-2023-21715, CVE-2023-21716, CVE-2023-24880, CVE-2023-36025, CVE-2023-38146, CVE-2024-21320, CVE-2024-21412, CVE-2024-38014, CVE-2024-38213, CVE-2024-38217, CVE-2024-43461, CVE-2024-43572, CVE-2025-21298, CVE-2025-24054, CVE-2025-26633, CVE-2026-21509, CVE-2026-21510, CVE-2026-21513, CVE-2026-21514, CVE-2026-124194 | [msrc.microsoft.com/update-guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38217) | 2026-11-13 | Confirmed |
| 3 | MSRC CVRF monthly security update documents: 2022-Nov, 2022-Dec, 2023-Mar, 2023-Oct, 2024-Jan, 2024-Sep, 2025-Mar, 2026-Feb | [api.msrc.microsoft.com/cvrf/v3.0/cvrf/2022-Nov](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2022-Nov) | 2026-11-13 | Confirmed |
| 4 | CVE records through the CVE Services API, including CVE-2012-1854, CVE-2017-0199, CVE-2017-13156, CVE-2018-10115, CVE-2021-42574, CVE-2022-22616, CVE-2022-29072, CVE-2022-30190, CVE-2022-30333, CVE-2022-42821, CVE-2023-2868, CVE-2023-38831, CVE-2024-3094, CVE-2024-3660, CVE-2024-8811, CVE-2024-11477, CVE-2024-34359, CVE-2024-48510, CVE-2024-50623, CVE-2025-0411, CVE-2025-1550, CVE-2025-1716, CVE-2025-6218, CVE-2025-8088, CVE-2025-11001, CVE-2025-24813, CVE-2025-31324, CVE-2025-32434, CVE-2025-55188, CVE-2026-14266, CVE-2026-34621, CVE-2026-58052, CVE-2017-12615, CVE-2021-30657, CVE-2024-4577 | [cveawg.mitre.org/api/cve/CVE-2025-0411](https://cveawg.mitre.org/api/cve/CVE-2025-0411) | 2026-11-13 | Confirmed |
| 5 | Microsoft Support, Blocked attachments in Outlook | [support.microsoft.com/.../blocked-attachments-in-outlook](https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519) | 2026-11-13 | Confirmed |
| 6 | Microsoft Learn, Anti-malware protection in EOP (common attachments filter, true type matching), 2026-06-09 | [learn.microsoft.com/.../anti-malware-protection-about](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about) | 2026-11-13 | Confirmed |
| 7 | Microsoft Learn, Safe Attachments in Microsoft Defender for Office 365, 2026-07-17 | [learn.microsoft.com/.../safe-attachments-about](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about) | 2026-11-13 | Confirmed |
| 8 | Microsoft Learn, Attack surface reduction rules reference, 2026-09-09 | [learn.microsoft.com/.../attack-surface-reduction-rules-reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) | 2026-11-13 | Confirmed |
| 9 | Microsoft Learn, Macros from the internet are blocked by default in Office, 2026-07-17 | [learn.microsoft.com/.../internet-macros-blocked](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked) | 2026-11-13 | Confirmed |
| 10 | Microsoft Learn, Baseline security mode settings, 2026-11-12 | [learn.microsoft.com/.../baseline-security-mode-settings](https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings) | 2026-11-13 | Confirmed |
| 11 | Microsoft Learn, OneNote blocks embedded files that have dangerous extensions, 2025-05-30 | [learn.microsoft.com/.../onenote-extension-block](https://learn.microsoft.com/en-us/microsoft-365-apps/security/onenote-extension-block) | 2026-11-13 | Confirmed |
| 12 | Microsoft Support, Excel is blocking untrusted XLL add-ins by default, 2025-04-04 | [support.microsoft.com/.../excel-is-blocking-untrusted-xll-add-ins](https://support.microsoft.com/en-us/office/excel-is-blocking-untrusted-xll-add-ins-by-default-1e3752e2-1177-4444-a807-7b700266a6fb) | 2026-11-13 | Confirmed |
| 13 | Microsoft Learn, Microsoft recommended driver block rules, 2026-05-01 | [learn.microsoft.com/.../microsoft-recommended-driver-block-rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | 2026-11-13 | Confirmed |
| 14 | Microsoft Support, KB5025885: Windows Boot Manager revocations for CVE-2023-24932, 2026-06-02 | [support.microsoft.com/.../kb5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) | 2026-11-13 | Confirmed |
| 15 | Microsoft Learn, about_Execution_Policies, 2026-08-31 | [learn.microsoft.com/.../about_execution_policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) | 2026-11-13 | Confirmed |
| 16 | Microsoft Learn, Features and functionality removed in Windows client, 2026-08-25 | [learn.microsoft.com/.../removed-features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features) | 2026-11-13 | Confirmed |
| 17 | Microsoft Learn, Deprecated features in the Windows client, 2026-11-11 | [learn.microsoft.com/.../deprecated-features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features) | 2026-11-13 | Confirmed |
| 18 | Microsoft Learn, Resources for deprecated features in the Windows client, 2026-09-23 | [learn.microsoft.com/.../deprecated-features-resources](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources) | 2026-11-13 | Confirmed |
| 19 | Microsoft Learn, Understanding AppLocker rule collections, 2024-09-11 | [learn.microsoft.com/.../understanding-applocker-rule-collections](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-rule-collections) | 2026-11-13 | Confirmed |
| 20 | Microsoft Learn, Script enforcement with App Control for Business, 2026-11-02 | [learn.microsoft.com/.../script-enforcement](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement) | 2026-11-13 | Confirmed |
| 21 | Microsoft Learn, Microsoft Defender SmartScreen overview, 2026-04-23 | [learn.microsoft.com/.../microsoft-defender-smartscreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/) | 2026-11-13 | Confirmed |
| 22 | Microsoft Learn, Use and configure Windows Sandbox (`.wsb` files), 2026-03-29 | [learn.microsoft.com/.../windows-sandbox-configure-using-wsb-file](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) | 2026-11-13 | Confirmed |
| 23 | Microsoft Learn, Querying the index with the search-ms protocol, 2018-05-31 | [learn.microsoft.com/.../-search-3x-wds-qryidx-searchms](https://learn.microsoft.com/en-us/windows/win32/search/-search-3x-wds-qryidx-searchms) | 2026-11-13 | Confirmed |
| 24 | Microsoft Learn, Mount-DiskImage | [learn.microsoft.com/.../mount-diskimage](https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage) | 2026-11-13 | Confirmed |
| 25 | Microsoft Learn, WIM vs. VHD vs. FFU: comparing image file formats (last updated 2020-08-27) | [learn.microsoft.com/.../wim-vs-ffu-image-file-formats](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim-vs-ffu-image-file-formats) | 2026-11-13 | Confirmed |
| 26 | Microsoft Learn, IIS Handlers `<handlers>`, 2026-05-19 | [learn.microsoft.com/.../handlers](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/) | 2026-11-13 | Confirmed |
| 27 | Microsoft Learn, An introduction to NuGet, 2025-03-03 | [learn.microsoft.com/.../what-is-nuget](https://learn.microsoft.com/en-us/nuget/what-is-nuget) | 2026-11-13 | Confirmed |
| 28 | Microsoft Security Blog, HTML smuggling surges, 2021-11-11 | [microsoft.com/.../html-smuggling-surges](https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-targeted-attacks/) | 2026-11-13 | Confirmed (observations); Reported (actor attribution) |
| 29 | Microsoft Security Blog, Financially motivated threat actors misusing App Installer, 2023-12-28 | [microsoft.com/.../misusing-app-installer](https://www.microsoft.com/en-us/security/blog/2023/12/28/financially-motivated-threat-actors-misusing-app-installer/) | 2026-11-13 | Confirmed (observations); Reported (actor attribution) |
| 30 | Microsoft Security Blog, Midnight Blizzard spear-phishing campaign using RDP files, 2024-10-29 | [microsoft.com/.../using-rdp-files](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/) | 2026-11-13 | Confirmed (observations); Reported (actor attribution) |
| 31 | Microsoft Security Blog, Storm-0978 attacks, 2023-07-11 | [microsoft.com/.../storm-0978](https://www.microsoft.com/en-us/security/blog/2023/07/11/storm-0978-attacks-reveal-financial-and-espionage-motives/) | 2026-11-13 | Confirmed (observations); Reported (actor attribution) |
| 32 | Microsoft Security Blog, Gatekeeper's Achilles heel (CVE-2022-42821), 2022-12-19 | [microsoft.com/.../gatekeepers-achilles-heel](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) | 2026-11-13 | Confirmed |
| 33 | Microsoft Security Blog, Disrupting active exploitation of on-premises SharePoint vulnerabilities, 2025-07-22 (updated 2025-07-29) | [microsoft.com/.../sharepoint-vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/) | 2026-11-13 | Confirmed |
| 34 | Gmail Help, File types blocked in Gmail (undated) | [support.google.com/mail/answer/6590](https://support.google.com/mail/answer/6590?hl=en) | 2026-11-13 | Confirmed |
| 35 | Chrome Help, Google Chrome blocks some downloads (undated) | [support.google.com/chrome/answer/6261569](https://support.google.com/chrome/answer/6261569?hl=en) | 2026-11-13 | Confirmed |
| 36 | Chromium `download_file_types.asciipb`, version_id 70 | [github.com/chromium/chromium/.../download_file_types.asciipb](https://github.com/chromium/chromium/blob/main/components/safe_browsing/content/resources/download_file_types/download_file_types.asciipb) | 2026-11-13 | Confirmed |
| 37 | MITRE ATT&CK v20 technique pages: T1003.001, T1003.002, T1006, T1014, T1027.009, T1027.012, T1027.013, T1027.015, T1036.002, T1036.007, T1036.008, T1040, T1070.006, T1114.001, T1187, T1204.002, T1218.001, T1218.002, T1218.003, T1218.005, T1218.007, T1218.010, T1218.014, T1220, T1221, T1505.003, T1543.001, T1543.004, T1546.002, T1546.004, T1546.016, T1547.001, T1547.006, T1547.009, T1547.013, T1552.001, T1552.004, T1553.001, T1553.005, T1555.005, T1564.004, T1566.001, T1574.004, T1574.006, T1647, T1685.001, T1685.005 | [attack.mitre.org/techniques](https://attack.mitre.org/techniques/enterprise/) | 2026-11-13 | Confirmed (Reported for Outlook size facts on T1114.001) |
| 38 | MITRE CWE definitions: CWE-434, CWE-646, CWE-430 | [cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html) | 2026-11-13 | Confirmed |
| 39 | MITRE CAPEC 3.9 entries: CAPEC-11, 17, 35, 209, 556, 635, 636, 649, 650 | [capec.mitre.org/data/definitions/650.html](https://capec.mitre.org/data/definitions/650.html) | 2026-11-13 | Confirmed |
| 40 | MITRE D3FEND API entries: D3-FFV, D3-DA, D3-EF, D3-EAL | [d3fend.mitre.org/api/technique/d3f:FileFormatVerification.json](https://d3fend.mitre.org/api/technique/d3f:FileFormatVerification.json) | 2026-11-13 | Confirmed |
| 41 | Library data files at `origin/main`: ATT&CK technique profiles (Enterprise and Mobile), `superseded_by.jsonl`, CWE, CAPEC, D3FEND countermeasures and technique-to-D3FEND mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-13 | Confirmed |
| 42 | SigmaHQ rule repository, master `54967d64e6` (rule metadata only) | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | 2026-11-13 | Confirmed |
| 43 | Sigma Rules Specification v2.1.0, released 2025-08-02 | [github.com/SigmaHQ/sigma-specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) | 2026-11-13 | Confirmed |
| 44 | Oracle, JDK 11 Migration Guide (removal of the deployment stack) | [docs.oracle.com/en/java/javase/11/migrate](https://docs.oracle.com/en/java/javase/11/migrate/index.html) | 2026-11-13 | Confirmed |
| 45 | Oracle, Java SE 21 JAR File Specification | [docs.oracle.com/.../jar.html](https://docs.oracle.com/en/java/javase/21/docs/specs/jar/jar.html) | 2026-11-13 | Confirmed |
| 46 | Oracle, JDK 21 `keytool` | [docs.oracle.com/.../keytool.html](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html) | 2026-11-13 | Confirmed |
| 47 | 7-Zip `history.txt` (latest entry 26.06, 2026-11-06) | [7-zip.org/history.txt](https://www.7-zip.org/history.txt) | 2026-11-13 | Confirmed |
| 48 | RARLAB, WinRAR What's new (latest entry 7.30 beta 2), with win-rar.com release news | [rarlab.com/rarnew.htm](https://www.rarlab.com/rarnew.htm) | 2026-11-13 | Confirmed |
| 49 | RARLAB, RAR 5.0 archive format technical note | [rarlab.com/technote.htm](https://www.rarlab.com/technote.htm) | 2026-11-13 | Confirmed |
| 50 | 7-Zip `DOC/7zFormat.txt` | [github.com/ip7z/7zip/.../7zFormat.txt](https://raw.githubusercontent.com/ip7z/7zip/main/DOC/7zFormat.txt) | 2026-11-13 | Confirmed |
| 51 | PKWARE, APPNOTE.TXT .ZIP File Format Specification | [pkware.cachefly.net/.../APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | 2026-11-13 | Confirmed |
| 52 | RFC 1952, GZIP file format specification 4.3, May 1996 | [rfc-editor.org/rfc/rfc1952](https://www.rfc-editor.org/rfc/rfc1952.txt) | 2026-11-13 | Confirmed |
| 53 | RFC 8878, Zstandard Compression and the application/zstd Media Type, February 2021 | [rfc-editor.org/rfc/rfc8878](https://www.rfc-editor.org/rfc/rfc8878.txt) | 2026-11-13 | Confirmed |
| 54 | The .xz File Format | [tukaani.org/xz/xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | 2026-11-13 | Confirmed |
| 55 | The Open Group Base Specifications (POSIX.1-2024), pax utility, ustar header | [pubs.opengroup.org/.../pax.html](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html) | 2026-11-13 | Confirmed |
| 56 | deb(5), Debian bookworm | [manpages.debian.org/.../deb.5](https://manpages.debian.org/bookworm/dpkg-dev/deb.5.en.html) | 2026-11-13 | Confirmed |
| 57 | RPM documentation, RPM v4 package format | [rpm-software-management.github.io/rpm/manual/format_v4.html](https://rpm-software-management.github.io/rpm/manual/format_v4.html) | 2026-11-13 | Confirmed |
| 58 | Snapcraft documentation, The snap format | [snapcraft.io/docs/.../the-snap-format](https://snapcraft.io/docs/reference/development/yaml-schemas/the-snap-format/) | 2026-11-13 | Confirmed |
| 59 | AppImage documentation, Architecture and Concepts | [docs.appimage.org/reference/architecture.html](https://docs.appimage.org/reference/architecture.html) | 2026-11-13 | Confirmed |
| 60 | Flatpak documentation, Under the Hood | [docs.flatpak.org/en/latest/under-the-hood.html](https://docs.flatpak.org/en/latest/under-the-hood.html) | 2026-11-13 | Confirmed |
| 61 | Python Packaging User Guide, Binary distribution format | [packaging.python.org/.../binary-distribution-format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/) | 2026-11-13 | Confirmed |
| 62 | PyPI Blog, Deprecation of bdist_egg uploads to PyPI, 2023-06-26 | [blog.pypi.org/posts/2023-06-26-deprecate-egg-uploads](https://blog.pypi.org/posts/2023-06-26-deprecate-egg-uploads/) | 2026-11-13 | Confirmed |
| 63 | Firefox Extension Workshop, Package your extension | [extensionworkshop.com/.../package-your-extension](https://extensionworkshop.com/documentation/publish/package-your-extension/) | 2026-11-13 | Confirmed |
| 64 | Chromium `components/crx_file/crx3.proto` | [github.com/chromium/chromium/.../crx3.proto](https://raw.githubusercontent.com/chromium/chromium/main/components/crx_file/crx3.proto) | 2026-11-13 | Confirmed |
| 65 | Android Open Source Project, Application signing (2026-09-30) and APK signature scheme v2 | [source.android.com/docs/security/features/apksigning](https://source.android.com/docs/security/features/apksigning) | 2026-11-13 | Confirmed |
| 66 | Android Security Bulletin, December 2017 | [source.android.com/docs/security/bulletin/2017-12-01](https://source.android.com/docs/security/bulletin/2017-12-01) | 2026-11-13 | Confirmed (bulletin); Reported (the Janus name and mechanism) |
| 67 | Android Developers: About Android App Bundles (2026-06-24), Alternative distribution options (2026-02-26), Behavior changes for apps targeting Android 12 (2026-10-28), Auto Backup (2026-10-26) | [developer.android.com/guide/app-bundle](https://developer.android.com/guide/app-bundle) | 2026-11-13 | Confirmed |
| 68 | Google Play Help, Google Play Protect | [support.google.com/googleplay/answer/2812853](https://support.google.com/googleplay/answer/2812853) | 2026-11-13 | Confirmed |
| 69 | Apple Platform Security: Gatekeeper and runtime protection; Protecting against malware; App code signing in macOS and in iOS (2021-02-18 to 2024-12-19) | [support.apple.com/guide/security/sec5599b66df](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web) | 2026-11-13 | Confirmed |
| 70 | Apple Support 102445, Safely open apps on your Mac, 2026-05-27 | [support.apple.com/en-us/102445](https://support.apple.com/en-us/102445) | 2026-11-13 | Confirmed |
| 71 | Apple Developer, Notarizing macOS software before distribution | [developer.apple.com/.../notarizing-macos-software-before-distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) | 2026-11-13 | Confirmed |
| 72 | Apple Developer, `URLResourceKey.quarantinePropertiesKey` | [developer.apple.com/.../quarantinepropertieskey](https://developer.apple.com/documentation/foundation/urlresourcekey/quarantinepropertieskey) | 2026-11-13 | Confirmed |
| 73 | Apple Platform Deployment, System and kernel extensions in macOS, 2021-10-27 | [support.apple.com/guide/deployment/depa5fb8376f](https://support.apple.com/guide/deployment/system-and-kernel-extensions-in-macos-depa5fb8376f/web) | 2026-11-13 | Confirmed |
| 74 | Apple Platform Deployment, Intro to device management profiles, 2026-09-17 | [support.apple.com/guide/deployment/depc0aadd3fe](https://support.apple.com/guide/deployment/intro-to-mdm-profiles-depc0aadd3fe/web) | 2026-11-13 | Confirmed |
| 75 | Apple Support 108353, About encrypted backups, 2026-09-21 | [support.apple.com/en-us/108353](https://support.apple.com/en-us/108353) | 2026-11-13 | Confirmed |
| 76 | Apple Developer Documentation Archive, About Property Lists | [developer.apple.com/library/archive/.../AboutPropertyLists.html](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/PropertyLists/AboutPropertyLists/AboutPropertyLists.html) | 2026-11-13 | Confirmed |
| 77 | Unicode Standard Annex #9, Unicode Bidirectional Algorithm, revision 52 (Unicode 18.0.0), 2026-09-01 | [unicode.org/reports/tr9](https://www.unicode.org/reports/tr9/) | 2026-11-13 | Confirmed |
| 78 | Linux man-pages 6.19: elf(5), execve(2), ld.so(8) | [man7.org/linux/man-pages/man2/execve.2.html](https://man7.org/linux/man-pages/man2/execve.2.html) | 2026-11-13 | Confirmed |
| 79 | freedesktop.org: systemd.service(5), systemd.timer(5), Desktop Entry Specification 1.5 | [freedesktop.org/.../systemd.service.html](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) | 2026-11-13 | Confirmed |
| 80 | Debian Policy Manual 4.7.4.1, chapter 6, Package maintainer scripts | [debian.org/doc/debian-policy/ch-maintainerscripts.html](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) | 2026-11-13 | Confirmed |
| 81 | Linux kernel documentation, Kernel module signing facility | [kernel.org/doc/html/latest/admin-guide/module-signing.html](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html) | 2026-11-13 | Confirmed |
| 82 | Microsoft UF2 specification README | [github.com/microsoft/uf2](https://github.com/microsoft/uf2/blob/master/README.md) | 2026-11-13 | Confirmed |
| 83 | USB-IF, Device Firmware Upgrade Specification 1.1, 2004-08-05 | [usb.org/.../DFU_1.1.pdf](https://www.usb.org/sites/default/files/DFU_1.1.pdf) | 2026-11-13 | Confirmed |
| 84 | GNU Binutils documentation, objcopy | [sourceware.org/binutils/docs/binutils/objcopy.html](https://sourceware.org/binutils/docs/binutils/objcopy.html) | 2026-11-13 | Confirmed |
| 85 | LVFS documentation, Metadata (metainfo) | [lvfs.readthedocs.io/en/latest/metainfo.html](https://lvfs.readthedocs.io/en/latest/metainfo.html) | 2026-11-13 | Confirmed |
| 86 | NIST SP 800-193, Platform Firmware Resiliency Guidelines, May 2018 | [csrc.nist.gov/pubs/sp/800/193/final](https://csrc.nist.gov/pubs/sp/800/193/final) | 2026-11-13 | Confirmed |
| 87 | OWASP File Upload Cheat Sheet (undated) | [cheatsheetseries.owasp.org/.../File_Upload_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | 2026-11-13 | Confirmed |
| 88 | OWASP Secrets Management Cheat Sheet (undated) | [cheatsheetseries.owasp.org/.../Secrets_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | 2026-11-13 | Confirmed |
| 89 | OWASP, CSV Injection | [owasp.org/www-community/attacks/CSV_Injection](https://owasp.org/www-community/attacks/CSV_Injection) | 2026-11-13 | Confirmed |
| 90 | Apache HTTP Server 2.4 documentation: mod_mime, .htaccess files, Dynamic Content with CGI | [httpd.apache.org/docs/2.4/mod/mod_mime.html](https://httpd.apache.org/docs/2.4/mod/mod_mime.html) | 2026-11-13 | Confirmed |
| 91 | Apache Tomcat 10.1, Tomcat Web Application Deployment | [tomcat.apache.org/tomcat-10.1-doc/deployer-howto.html](https://tomcat.apache.org/tomcat-10.1-doc/deployer-howto.html) | 2026-11-13 | Confirmed |
| 92 | PHP Manual: Backward incompatible changes in PHP 8.0; Using Phar Archives | [php.net/manual/en/migration80.incompatible.php](https://www.php.net/manual/en/migration80.incompatible.php) | 2026-11-13 | Confirmed |
| 93 | CISA Advisory AA23-158A, CL0P exploits MOVEit vulnerability, 2023-06-07 (updated 2023-06-16) | [cisa.gov/.../aa23-158a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) | 2026-11-13 | Confirmed |
| 94 | Git documentation, git-credential-store | [git-scm.com/docs/git-credential-store](https://git-scm.com/docs/git-credential-store) | 2026-11-13 | Confirmed |
| 95 | GNU Inetutils manual, The .netrc file | [gnu.org/.../The-_002enetrc-file.html](https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html) | 2026-11-13 | Confirmed |
| 96 | npm Docs v10, npmrc | [docs.npmjs.com/cli/v10/configuring-npm/npmrc](https://docs.npmjs.com/cli/v10/configuring-npm/npmrc) | 2026-11-13 | Confirmed |
| 97 | Python Packaging User Guide, The .pypirc file | [packaging.python.org/en/latest/specifications/pypirc](https://packaging.python.org/en/latest/specifications/pypirc/) | 2026-11-13 | Confirmed |
| 98 | Kubernetes documentation: Organizing Cluster Access Using kubeconfig Files; Secrets (2026-07-23) | [kubernetes.io/docs/concepts/configuration/secret](https://kubernetes.io/docs/concepts/configuration/secret/) | 2026-11-13 | Confirmed |
| 99 | HashiCorp Terraform: Manage sensitive data; Input variables | [developer.hashicorp.com/terraform/language/state/sensitive-data](https://developer.hashicorp.com/terraform/language/state/sensitive-data) | 2026-11-13 | Confirmed |
| 100 | Docker Docs: Build secrets; Secrets in Compose | [docs.docker.com/build/building/secrets](https://docs.docker.com/build/building/secrets/) | 2026-11-13 | Confirmed |
| 101 | KeePass Help, Security | [keepass.info/help/base/security.html](https://keepass.info/help/base/security.html) | 2026-11-13 | Confirmed |
| 102 | OpenVPN 2.6 reference manual | [openvpn.net/community-docs/.../openvpn-2-6-manual.html](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html) | 2026-11-13 | Confirmed |
| 103 | GitHub Docs, About secret scanning | [docs.github.com/.../about-secret-scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) | 2026-11-13 | Confirmed |
| 104 | PyYAML Documentation (undated wiki; the loader warning) | [pyyaml.org/wiki/PyYAMLDocumentation](https://pyyaml.org/wiki/PyYAMLDocumentation) | 2026-11-13 | Confirmed |
| 105 | CycloneDX Specification Overview; Ecma International, ECMA-424 2nd edition, December 2025 | [ecma-international.org/.../ecma-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/) | 2026-11-13 | Confirmed |
| 106 | SPDX overview; ISO/IEC 5962:2021 | [iso.org/standard/81870.html](https://www.iso.org/standard/81870.html) | 2026-11-13 | Confirmed |
| 107 | Jupyter Server documentation, Security in the Jupyter Server | [jupyter-server.readthedocs.io/.../security.html](https://jupyter-server.readthedocs.io/en/latest/operators/security.html) | 2026-11-13 | Confirmed |
| 108 | Python 3 documentation, `pickle` | [docs.python.org/3/library/pickle.html](https://docs.python.org/3/library/pickle.html) | 2026-11-13 | Confirmed |
| 109 | PyTorch 2.15 documentation, Serialization semantics | [docs.pytorch.org/docs/2.15/notes/serialization.html](https://docs.pytorch.org/docs/2.15/notes/serialization.html) | 2026-11-13 | Confirmed |
| 110 | Hugging Face Hub documentation: Pickle Scanning; Malware Scanning | [huggingface.co/docs/hub/security-pickle](https://huggingface.co/docs/hub/security-pickle) | 2026-11-13 | Confirmed |
| 111 | Hugging Face, Safetensors documentation | [huggingface.co/docs/safetensors](https://huggingface.co/docs/safetensors/index) | 2026-11-13 | Confirmed |
| 112 | NumPy 2.5 documentation, `numpy.load` | [numpy.org/doc/stable/.../numpy.load.html](https://numpy.org/doc/stable/reference/generated/numpy.load.html) | 2026-11-13 | Confirmed |
| 113 | ggml repository, GGUF specification | [github.com/ggml-org/ggml/.../gguf.md](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md) | 2026-11-13 | Confirmed |
| 114 | ONNX Runtime documentation, Custom operators | [onnxruntime.ai/docs/reference/operators/add-custom-op.html](https://onnxruntime.ai/docs/reference/operators/add-custom-op.html) | 2026-11-13 | Confirmed |
| 115 | Trend Micro (Peter Girnus), CVE-2025-0411: Ukrainian Organizations Targeted in Zero-Day Campaign and Homoglyph Attacks, 2025-02-04 | [trendmicro.com/.../cve-2025-0411](https://www.trendmicro.com/en_us/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html) | 2026-11-13 | Confirmed (findings); Reported (attribution) |
| 116 | Group-IB (Andrey Polovinkin), CVE-2023-38831 zero-day in WinRAR, 2023-08-23 | [group-ib.com/blog/cve-2023-38831-winrar-zero-day](https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/) | 2026-11-13 | Confirmed (findings) |
| 117 | ESET, RomCom and others exploiting a WinRAR zero-day, 2025-08-11 | [welivesecurity.com/.../update-winrar-tools-now](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/) | 2026-11-13 | Confirmed (findings); Reported (attribution) |
| 118 | Google Threat Intelligence Group, Exploiting critical WinRAR vulnerability, 2026-01-27 | [cloud.google.com/.../exploiting-critical-winrar-vulnerability](https://cloud.google.com/blog/topics/threat-intelligence/exploiting-critical-winrar-vulnerability) | 2026-11-13 | Confirmed (findings); Reported (attribution) |
| 119 | Check Point Research, Extracting a 19 Year Old Code Execution from WinRAR, 2019-02-20 | [research.checkpoint.com/2019/extracting-code-execution-from-winrar](https://research.checkpoint.com/2019/extracting-code-execution-from-winrar/) | 2026-11-13 | Confirmed |
| 120 | Snyk, Zip Slip Vulnerability, 2018-06-05 | [security.snyk.io/research/zip-slip-vulnerability](https://security.snyk.io/research/zip-slip-vulnerability) | 2026-11-13 | Confirmed |
| 121 | David Fifield, A better zip bomb | [bamsoftware.com/hacks/zipbomb](https://www.bamsoftware.com/hacks/zipbomb/) | 2026-11-13 | Confirmed |
| 122 | BleepingComputer, Microsoft fixes Windows zero-day bug exploited to push malware, 2022-11-10 | [bleepingcomputer.com/.../microsoft-fixes-windows-zero-day](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-windows-zero-day-bug-exploited-to-push-malware/) | 2026-11-13 | Reported |
| 123 | Kaspersky Securelist (Seongsu Park), BlueNoroff introduces new methods bypassing MoTW, 2022-12-27 | [securelist.com/bluenoroff-methods-bypass-motw/108383](https://securelist.com/bluenoroff-methods-bypass-motw/108383/) | 2026-11-13 | Confirmed (findings); Reported (attribution) |
| 124 | Elastic Security Labs, GrimResource, June 2024 | [elastic.co/security-labs/grimresource](https://www.elastic.co/security-labs/grimresource) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 125 | Elastic Security Labs, Dismantling Smart App Control, 2024-08-06 | [elastic.co/security-labs/dismantling-smart-app-control](https://www.elastic.co/security-labs/dismantling-smart-app-control) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 126 | Trend Micro, CVE-2025-26633: How Water Gamayun Weaponizes MUIPath using MSC EvilTwin, 2025-03-25 | [trendmicro.com/.../cve-2025-26633-water-gamayun](https://www.trendmicro.com/en_us/research/25/c/cve-2025-26633-water-gamayun.html) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 127 | Trend Micro, ZDI-CAN-25373 Windows Shortcut Exploit Abused as Zero-Day in Widespread APT Campaigns, March 2025 | [trendmicro.com/.../windows-shortcut-zero-day-exploit](https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 128 | Zero Day Initiative, advisory ZDI-25-148, 2025-03-18 | [zerodayinitiative.com/advisories/ZDI-25-148](https://www.zerodayinitiative.com/advisories/ZDI-25-148/) | 2026-11-13 | Confirmed |
| 129 | Trend Micro, CVE-2024-21412: Water Hydra Targets Traders, 2024-02-13 | [trendmicro.com/.../cve202421412-water-hydra](https://www.trendmicro.com/en_us/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.html) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 130 | Check Point Research (Haifei Li), Resurrecting Internet Explorer (CVE-2024-38112), 2024-07-09 | [research.checkpoint.com/2024/resurrecting-internet-explorer](https://research.checkpoint.com/2024/resurrecting-internet-explorer-threat-actors-using-zero-day-tricks-in-internet-shortcut-file-to-lure-victims-cve-2024-38112/) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 131 | Check Point Research, CVE-2025-33053, Stealth Falcon and Horus, 2025-06-10 | [research.checkpoint.com/2025/stealth-falcon-zero-day](https://research.checkpoint.com/2025/stealth-falcon-zero-day/) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 132 | Check Point Research, CVE-2025-24054, NTLM Exploit in the Wild, 2025-04-16 | [research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 133 | SpecterOps, The Tale of SettingContent-ms Files, 2018-06-11 | [posts.specterops.io/the-tale-of-settingcontent-ms-files](https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 134 | Google TAG, Magniber ransomware actors used a variant of Microsoft SmartScreen bypass, 2023-03-14 | [blog.google/threat-analysis-group/magniber-ransomware](https://blog.google/threat-analysis-group/magniber-ransomware-actors-used-a-variant-of-microsoft-smartscreen-bypass/) | 2026-11-13 | Confirmed (findings); Reported (attribution, counts) |
| 135 | LibreOffice Security Advisories (CVE-2023-2255, CVE-2026-63267) | [libreoffice.org/about-us/security/advisories](https://www.libreoffice.org/about-us/security/advisories/) | 2026-11-13 | Confirmed |
| 136 | Microsoft Open Specifications: [MS-SHLLINK], [MS-CFB], [MS-OXMSG], [MS-PST] | [learn.microsoft.com/.../ms-shllink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) | 2026-11-13 | Confirmed |
| 137 | Microsoft Learn event logging: Event Log File Format; Windows Event Log; 1102(S) The audit log was cleared; wevtutil; Eventlog Key | [learn.microsoft.com/.../event-1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) | 2026-11-13 | Confirmed |
| 138 | Microsoft Learn: About Event Tracing; Tracelog | [learn.microsoft.com/.../about-event-tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing) | 2026-11-13 | Confirmed |
| 139 | Microsoft Learn: Master File Table; Change Journals; fsutil usn; NTFS overview | [learn.microsoft.com/.../master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table) | 2026-11-13 | Confirmed |
| 140 | Microsoft Learn: Registry Hives; system registry no longer backed up to RegBack | [learn.microsoft.com/.../registry-hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) | 2026-11-13 | Confirmed |
| 141 | Microsoft Learn: hibernation; Introduction to the page file; Varieties of Kernel-Mode Dump Files; Minidump Files; ProcDump v12.02 | [learn.microsoft.com/sysinternals/downloads/procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) | 2026-11-13 | Confirmed |
| 142 | libyal format specifications: EVTX, Prefetch (libscca), NTFS (libfsntfs), REGF, hibernation (libhibr, 2014), EWF, jump lists (dtformats) | [github.com/libyal](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc) | 2026-11-13 | Confirmed (researcher specifications) |
| 143 | Plaso (log2timeline) 20261027, Parsers and plugins | [plaso.readthedocs.io/.../Parsers-and-plugins.html](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html) | 2026-11-13 | Confirmed |
| 144 | Volatility 3 documentation 2.28.3 | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html) | 2026-11-13 | Confirmed |
| 145 | LiME, Linux Memory Extractor README | [github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME) | 2026-11-13 | Confirmed |
| 146 | Broadcom TechDocs, VMware Workstation Pro 25H2, Virtual Machine Files, 2026-03-06 | [techdocs.broadcom.com/.../virtual-machine-files.html](https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/workstation-pro/25H2/using-vmware-workstation-pro/creating-virtual-machines-in-workstation-user-guide/virtual-machine-files.html) | 2026-11-13 | Confirmed |
| 147 | NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response, August 2006 | [nvlpubs.nist.gov/.../nistspecialpublication800-86.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf) | 2026-11-13 | Confirmed |
| 148 | NIST SP 800-92, Guide to Computer Security Log Management, September 2006 | [nvlpubs.nist.gov/.../nistspecialpublication800-92.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf) | 2026-11-13 | Confirmed |
| 149 | NIST SP 800-101 Rev. 1, Guidelines on Mobile Device Forensics, May 2014 | [nvlpubs.nist.gov/.../NIST.SP.800-101r1.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf) | 2026-11-13 | Confirmed |
| 150 | The Sleuth Kit, File and Volume System Analysis | [sleuthkit.org/sleuthkit/desc.php](https://www.sleuthkit.org/sleuthkit/desc.php) | 2026-11-13 | Confirmed |
| 151 | AFF4 Standard documents | [github.com/aff4/Standard](https://github.com/aff4/Standard) | 2026-11-13 | Confirmed |
| 152 | IETF drafts: draft-ietf-opsawg-pcap-04 (2024-08-04) and draft-ietf-opsawg-pcapng-04 (2025-08-30) | [ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html) | 2026-11-13 | Confirmed (drafts, not RFCs) |
| 153 | Wireshark 4.6.9: editcap(1), capinfos(1); Wireshark Wiki, ERF | [wireshark.org/docs/man-pages/editcap.html](https://www.wireshark.org/docs/man-pages/editcap.html) | 2026-11-13 | Confirmed |
| 154 | RFC 3954 (NetFlow v9, October 2004) and RFC 7011 (IPFIX, September 2013) | [rfc-editor.org/rfc/rfc7011](https://www.rfc-editor.org/rfc/rfc7011.txt) | 2026-11-13 | Confirmed |
| 155 | Book of Zeek, conn.log | [docs.zeek.org/en/master/logs/conn.html](https://docs.zeek.org/en/master/logs/conn.html) | 2026-11-13 | Confirmed |
| 156 | RFC 5424, The Syslog Protocol, March 2009 | [rfc-editor.org/rfc/rfc5424](https://www.rfc-editor.org/rfc/rfc5424.txt) | 2026-11-13 | Confirmed |
| 157 | OpenText, Implementing ArcSight Common Event Format, Version 26, October 2023 | [microfocus.com/.../cef-implementation-standard.pdf](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf) | 2026-11-13 | Confirmed |
| 158 | IBM Documentation, LEEF overview, 2026-04-03 | [ibm.com/docs/en/dsm?topic=leef-overview](https://www.ibm.com/docs/en/dsm?topic=leef-overview) | 2026-11-13 | Confirmed |
| 159 | JSON Lines; NDJSON specification 1.0.0 | [jsonlines.org](https://jsonlines.org/) | 2026-11-13 | Confirmed |
| 160 | RFC 4180, Common Format and MIME Type for CSV Files, October 2005 | [rfc-editor.org/rfc/rfc4180](https://www.rfc-editor.org/rfc/rfc4180.txt) | 2026-11-13 | Confirmed |
| 161 | Microsoft Learn, Export, configure, and view audit log records, 2026-06-24 | [learn.microsoft.com/.../audit-log-export-records](https://learn.microsoft.com/en-us/purview/audit-log-export-records) | 2026-11-13 | Confirmed |
| 162 | Apache Parquet, File Format | [parquet.apache.org/docs/file-format](https://parquet.apache.org/docs/file-format/) | 2026-11-13 | Confirmed |
| 163 | CISA, Best Practices for Event Logging and Threat Detection, 2024-08-21 | [cisa.gov/.../best-practices-event-logging-and-threat-detection](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection) | 2026-11-13 | Confirmed |
| 164 | RFC 5322 (October 2008), RFC 4155 (September 2005), RFC 5545 (September 2009), RFC 6350 (August 2011) | [rfc-editor.org/rfc/rfc5545](https://www.rfc-editor.org/rfc/rfc5545.txt) | 2026-11-13 | Confirmed |
| 165 | SQLite documentation: Database File Format; Pragma statements; Write-Ahead Logging | [sqlite.org/fileformat2.html](https://www.sqlite.org/fileformat2.html) | 2026-11-13 | Confirmed |
| 166 | PostgreSQL documentation, pg_dump | [postgresql.org/docs/current/app-pgdump.html](https://www.postgresql.org/docs/current/app-pgdump.html) | 2026-11-13 | Confirmed |
| 167 | Microsoft Learn, BACKUP (Transact-SQL), 2026-10-19 | [learn.microsoft.com/.../backup-transact-sql](https://learn.microsoft.com/en-us/sql/t-sql/statements/backup-transact-sql) | 2026-11-13 | Confirmed |
| 168 | OASIS, STIX Version 2.1 and TAXII Version 2.1, OASIS Standards, 2021-06-10 | [docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) | 2026-11-13 | Confirmed |
| 169 | MISP core format, draft-dulaunoy-misp-core-format | [github.com/MISP/misp-rfc](https://raw.githubusercontent.com/MISP/misp-rfc/master/misp-core-format/raw.md) | 2026-11-13 | Confirmed |
| 170 | Mandiant, OpenIOC 1.1 draft README (2013) | [github.com/mandiant/OpenIOC_1.1](https://github.com/mandiant/OpenIOC_1.1) | 2026-11-13 | Confirmed |
| 171 | YARA 4.4.0 documentation, Writing YARA rules | [yara.readthedocs.io/en/stable/writingrules.html](https://yara.readthedocs.io/en/stable/writingrules.html) | 2026-11-13 | Confirmed |
| 172 | Sigma documentation, Backends | [sigmahq.io/docs/digging-deeper/backends.html](https://sigmahq.io/docs/digging-deeper/backends.html) | 2026-11-13 | Confirmed |
| 173 | Snort 3 Rule Writing Guide; Suricata 9.0.0-dev rules format | [docs.snort.org/rules](https://docs.snort.org/rules/) | 2026-11-13 | Confirmed |
| 174 | ATT&CK Navigator Layer File Format, version 4.5 | [github.com/mitre-attack/attack-navigator/.../layerformat.md](https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/spec/v4.5/layerformat.md) | 2026-11-13 | Confirmed |
| 175 | Tenable, Nessus v2 File Format (revised 2016-11-18) | [static.tenable.com/documentation/nessus_v2_file_format.pdf](https://static.tenable.com/documentation/nessus_v2_file_format.pdf) | 2026-11-13 | Confirmed |
| 176 | OASIS, SARIF Version 2.1.0, OASIS Standard, 2020-03-27 | [docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) | 2026-11-13 | Confirmed |
| 177 | IANA, Media Types registry (updated 2026-11-10) | [iana.org/assignments/media-types](https://www.iana.org/assignments/media-types/media-types.xhtml) | 2026-11-13 | Confirmed |
| 178 | RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format, December 2017 | [rfc-editor.org/rfc/rfc8259](https://www.rfc-editor.org/rfc/rfc8259.txt) | 2026-11-13 | Confirmed |
| 179 | RFC 9512, YAML Media Type, February 2024 | [rfc-editor.org/rfc/rfc9512](https://www.rfc-editor.org/rfc/rfc9512.txt) | 2026-11-13 | Confirmed |
| 180 | RFC 7303, XML Media Types, July 2014 | [rfc-editor.org/rfc/rfc7303](https://www.rfc-editor.org/rfc/rfc7303.txt) | 2026-11-13 | Confirmed |
| 181 | RFC 7763, The text/markdown Media Type, March 2016 | [rfc-editor.org/rfc/rfc7763](https://www.rfc-editor.org/rfc/rfc7763.txt) | 2026-11-13 | Confirmed |
| 182 | TOML v1.0.0, published 2021-01-11 | [toml.io/en/v1.0.0](https://toml.io/en/v1.0.0) | 2026-11-13 | Confirmed |
| 183 | file(1), version 5.46, and libmagic(3) manual pages | [man7.org/linux/man-pages/man1/file.1.html](https://man7.org/linux/man-pages/man1/file.1.html) | 2026-11-13 | Confirmed |
| 184 | Microsoft Learn, File Types (Win32 shell, file associations), last updated 2021-11-19 | [learn.microsoft.com/.../fa-file-types](https://learn.microsoft.com/en-us/windows/win32/shell/fa-file-types) | 2026-11-13 | Confirmed |
| 185 | DMTF, Open Virtualization Format | [dmtf.org/standards/ovf](https://www.dmtf.org/standards/ovf) | 2026-11-13 | Confirmed |
| 186 | Apple Support, Terminal User Guide: Import and export Terminal profiles on Mac | [support.apple.com/guide/terminal/trml4299c696](https://support.apple.com/guide/terminal/import-and-export-terminal-profiles-trml4299c696/mac) | 2026-11-13 | Confirmed |
| 187 | Android Developers, APK Expansion Files | [developer.android.com/google/play/expansion-files](https://developer.android.com/google/play/expansion-files) | 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), the Common Attack Pattern Enumeration and Classification (CAPEC™) and MITRE D3FEND™, used under their terms of use. https://cwe.mitre.org/ https://capec.mitre.org/ https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- Formats: [JSON](/formats/json.md), [YAML](/formats/yaml.md), [XML](/formats/xml.md), [CSV](/formats/csv.md), [TOML](/formats/toml.md), [INI](/formats/ini.md), [HTML](/formats/html.md), [Markdown](/formats/markdown.md), and the [formats index](/formats/README.md)
- Delivery and users: [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md), [Investigate a phishing email](/guides/INVESTIGATE_A_PHISHING_EMAIL.md)
- Analysis and response: [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Malware Families](/MALWARE_FAMILIES.md), [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md), [Network Forensics Reference](/NETWORK_FORENSICS_REFERENCE.md), [Cloud, SaaS and Mobile Forensics Reference](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- Platforms: [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md), [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md), [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- Build and supply chain: [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Package Managers Reference](/PACKAGE_MANAGERS_REFERENCE.md), [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)
- Web: [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- AI: [Hugging Face supply chain case study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [ModelScan](/ai-tooling/tools/MODELSCAN.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- Case studies: [XZ Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [SharePoint ToolShell](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [CL0P file transfer](/case-studies/CL0P_FILE_TRANSFER_2023.md), [npm supply chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- Detection: [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md), [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md), [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md)
- Frameworks: [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md), [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md)

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Detection and response](/hubs/detection-and-response.md)
- [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md)

<!-- related:end -->
