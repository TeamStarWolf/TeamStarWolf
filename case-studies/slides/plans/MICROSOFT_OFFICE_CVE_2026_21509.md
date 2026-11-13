# Slide plan: The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study

- Study: case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md
- Cover title: The Microsoft Office / Security Feature Bypass of 2026 / CVE-2026-21509 and APT28
- Subtitle: One mailed document, one open, and a campaign that outran the fix
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An Office fix shipped while the flaw was already in use

- On 26 January 2026 Microsoft shipped an out-of-band Office fix.
- The flaw let a mailed document get past the COM/OLE control protections.
- Microsoft marked it exploited on the day it published.
- Within three days mail posing as a weather bulletin reached 60+ addresses.
- CERT-UA attributed the attacks to UAC-0001 (APT28).
Caption: Evidence grade: Confirmed from Microsoft's advisory and CERT-UA#19542; the attribution is CERT-UA's assessment.
Notes: Fix and exploited flag [1]. Mailings [9]. Attribution [9]. Targets [9][10].

## KEY FACTS | Important, local and already exploited

Stat: 7.8 | CVSS 3.1 score, Microsoft severity Important
Stat: 21 | Days KEV allowed federal agencies to fix
Stat: 60+ | Addresses in one mailing
Stat: 0 | Victims named in any source
- Affected: Office 2016, 2019, LTSC 2021 and 2024, Microsoft 365 Apps.
- Weakness: CWE-807, reliance on untrusted inputs in a security decision.
- Credited: MSTIC with MSRC, and Google Threat Intelligence Group.
Notes: Score and severity [1]. KEV [6]. Mailing [9]. Victims [6][9][10]. Affected [4][5]. CWE [1][4]. Credits [2][3].

## PART 1 | From disclosure to attribution in six days

| Date (2026) | Event |
|---|---|
| 12 Jan | Two domains later used in the chain registered |
| 26 Jan | MSRC out-of-band advisory, Exploited = Yes; KEV entry |
| 27 Jan | COREPER-themed lure created, per its metadata |
| 29 Jan | Mail posing as Ukraine's weather service reported |
| 1 Feb | CERT-UA#19542 names UAC-0001 (APT28) |
| 2 Feb | Zscaler publishes Operation Neusploit |
Caption: Rows from Microsoft, KEV and CERT-UA are Confirmed; Zscaler's report is graded Reported.
Notes: Domains [9]. Advisory [1][2]. KEV [6][7]. Lure and mailings [9]. Attribution [9]. Zscaler [10].

## PART 1 | The record disagrees with itself

- **Two mitigation texts.** One gives a registry block for 2016 and 2019; another says it does not apply.
- **Word or Office.** The CVE says Office; KB5002713 says Word.
- **DOC or RTF.** CERT-UA describes DOC files; Zscaler describes RTF attachments.
- **Seven revisions.** The advisory changed seven times in four days.
Caption: Re-read an out-of-band advisory before acting on it (Inferred).
Notes: Mitigation texts [1]. Word or Office [1][8]. DOC or RTF [9][10]. Revisions [1].

## PART 2 | The flaw and the fix, at advisory level

- A bypass of the OLE mitigations that block vulnerable COM/OLE controls.
- The user must open the file; the Preview Pane is not a vector.
- Microsoft 365 and Office 2021+: a service-side fix, live after a restart.
- Office 2016: build 16.0.5539.1001 (KB5002713). Office 2019: 16.0.10417.20095.
- An interim registry COM compatibility block, for use only until patched.
Caption: Take the registry values from Microsoft's page, not from secondary copies.
Notes: Flaw and vector [1]. Fix by version [1][2][8]. Interim block [1][6].

## PART 2 | From one open to a Covenant implant

Left: CERT-UA's chain
- A WebDAV fetch of a shortcut-format file.
- An executable drops a DLL posing as a shell extension.
- A COM hijack and a task named OneDriveHealth.
- Covenant talks to the Filen cloud storage service.
Right: Zscaler's two paths
- MiniDoor: an Outlook VBA mail forwarder.
- PixyNetLoader: shellcode hidden in a PNG.
- A Covenant Grunt over HTTPS through Filen.
- Next stage only for targeted regions.
Caption: CERT-UA's chain is Confirmed; Zscaler's analysis is graded Reported.
Notes: Chain [9]. Payload paths and geofencing [10].

## PART 3 | Three sources, one actor

| Source | Date | Standing |
|---|---|---|
| CERT-UA | 1 Feb 2026 | UAC-0001 (APT28), the agency's assessment |
| Zscaler | 2 Feb 2026 | APT28 "with high confidence" |
| ESET | 10 Mar 2026 | Sednit, its name for APT28 |
Caption: Sekoia's 2025 Phantom Net Voxel used the same building blocks: COM hijack, PNG shellcode, Covenant, cloud C2.
Notes: CERT-UA [9]. Zscaler [10]. ESET [11]. Sekoia lineage [12]. ATT&CK G0007 and C0051 [13][14].

## PART 4 | Targeted, not mass, and no victims named

- Targets: Ukrainian central executive bodies and EU organizations.
- Zscaler saw exploitation in Ukraine, Slovakia and Romania.
- CERT-UA counts one COREPER lure and three more EU-aimed documents.
- No source names a victim or counts compromises.
- CERT-UA forecast more attacks because many users patch Office slowly.
Caption: The known targets are a floor, not a count (Inferred).
Notes: Targets [9][10]. Documents [9]. No victims [6][9]. Forecast [9].

## PART 5 | Office documents keep returning to KEV

- Follina, CVE-2022-30190, reached through Word documents (KEV, June 2022).
- Outlook CVE-2023-23397, tied to Unit 26165 (KEV, March 2023).
- CVE-2026-21514, a Word flaw with the same CWE-807 (KEV, 10 Feb 2026).
- "Local" (AV:L) still means one mailed file and one open.
Caption: Rank Office bugs by KEV status and delivery path, not the AV:L label (Inferred).
Notes: KEV entries [6]. Vector [1].

## DEFENDER VIEW | Patch by build, then hunt the chain

Left: Close the flaw
- Restart every Microsoft 365 and Office 2021+ session.
- Patch 2016 and 2019 by build number.
- Use the registry block only as a bridge.
- Sandbox attachments.
Right: Hunt the chain
- Block or monitor Filen; restrict outbound WebDAV.
- Hunt COM hijacks of shell-extension CLSIDs.
- Look for a task named OneDriveHealth.
- Watch Outlook VBA projects and forwarding.
Notes: Restart and builds [1][2][8]. Interim block [1][6]. Sandbox [10]. Filen [9]. Hunting [9][10].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- Mass exploitation: the record shows targeted spearphishing.
- Zero-click: the Preview Pane is not a vector.
Right: Understated
- The AV:L label, when delivery is one mailed document.
- New lures one day after the out-of-band fix.
- Unnamed victims: the known targets are a floor.
Notes: Overstated [9][10][1]. Understated [1][9]. Readings Inferred from the cited records.

## MITRE MAPPINGS | Nineteen techniques from two analyses

| Id | Technique | Tie to the record |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Weather-bulletin mailing |
| T1203 | Exploitation for Client Execution | CVE-2026-21509 |
| T1546.015 | Component Object Model Hijacking | Shell-extension CLSID |
| T1053.005 | Scheduled Task | OneDriveHealth |
| T1027.003 | Steganography | Shellcode in an image |
| T1102.002 | Bidirectional Communication | Filen as C2 |
Caption: ATT&CK v20.0; the other thirteen techniques are in the study's table and its Navigator layer. CWE-807.
Notes: Techniques [1][9][10] with library data [14]. CWE [1][4]. Group G0007 APT28; software S1155 Covenant; campaign C0051 for lineage only. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | A protection layer became the way in

- **Disclosure did not slow the actor.** A lure was built the day after the fix.
- **Cloud storage is the command channel.** Filen here, Koofr and icedrive in 2025.
- **Security features are attack surface.** A bypass rated Important opened the door.
- **Advisories are living documents.** Seven revisions in four days.
Notes: Lure timing [1][9]. Cloud C2 [9][12]. Severity [1]. Revisions [1]. The lessons are Inferred.
