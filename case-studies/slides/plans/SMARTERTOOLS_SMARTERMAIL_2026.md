# Slide plan: SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691): A Case Study

- Study: case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md
- Cover title: SmarterTools SmarterMail / Exploitation and Ransomware, 2026
- Subtitle: CVE-2026-23760, CVE-2026-24423 and CVE-2025-52691: two days from patch to attack, and a vendor breached through its own mail server
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/SMARTERTOOLS_SMARTERMAIL_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Admins heard it from researchers, not the vendor

- SmarterMail is a mail server its customers host themselves.
- Build 9511 fixed two critical flaws on 15 January 2026.
- A forum post two days later described a successful attack.
- All three SmarterMail flaws were in KEV by 5 February.
- The vendor was breached through its own unpatched server.
Caption: Evidence grades: Confirmed from the CVE, KEV and vendor records; the forum post is Reported.
Notes: Fix [4][6][13]. Forum post, Reported [15]. KEV [9]. Vendor breach, the vendor's statement [14]. Who heard first, Inferred from [13][15][18].

## KEY FACTS | Three critical flaws, one ransomware flag

Stat: 3 | SmarterMail CVEs in KEV
Stat: 2 | Days from fix to reported attack
Stat: 12 | Vendor servers that appeared compromised
Stat: 6,000 | Likely vulnerable IPs, Shadowserver
- CVE-2025-52691: file upload (CWE-434), CVSS 10.0.
- CVE-2026-23760: password-reset bypass (CWE-288), 9.8.
- CVE-2026-24423: ConnectToHub command execution (CWE-306), 9.8.
- KEV marks known ransomware campaign use for all three.
Notes: Flaws and scores [2][4][5][6][7]. Two days [13][15]. Twelve servers [14]. Shadowserver, about 6,000 by version check, Demonstrated [19]. KEV [9].

## PART 1 | From patch to KEV in eleven days

| Date | Event |
|---|---|
| 9 Oct 2025 | Build 9413: "Critical security fixes." |
| 29 Dec 2025 | CSA alert and CVE-2025-52691 |
| 15 Jan 2026 | Build 9511 fixes both 2026 flaws |
| 17 Jan 2026 | Forum post describes an attack |
| 22 to 23 Jan 2026 | Both 2026 CVEs published |
| 26 Jan 2026 | KEV adds two flaws |
| 29 Jan 2026 | Vendor breached via its own VM |
| 5 Feb 2026 | KEV adds CVE-2026-24423 |
Caption: Rows Confirmed from the records; the 17 January post is Reported.
Notes: Builds [13]. CSA [1][3]. CVEs [4][6]. Forum post [15]. KEV [9][11][12]. Vendor breach [14].

## PART 1 | Where the record disagrees

- The CVE and NVD records put the fix in Build 9511.
- The vendor's breach post credits Build 9518 with all the fixes.
- The release notes date 9518 to 22 January, not 15 January.
- F5 Labs gives 2 February for the KEV entry; the catalog says 5 February.
Caption: The study follows the release notes and NVD (Inferred).
Notes: Fixed build [4][6][13][14][17]. KEV date [9][12][21].

## PART 2 | The flaws, at advisory level

- Password reset accepted anonymous requests for system administrators.
- It checked neither the old password nor a reset token.
- ConnectToHub let an unauthenticated caller point the server at an attacker host.
- CVE-2025-52691 allowed file upload to any location.
Caption: No exploit request, payload or command is reproduced.
Notes: CVE-2026-23760 [4]. CVE-2026-24423 [6]. CVE-2025-52691 [1].

## PART 2 | An admin password is a shell

Left: Why the bypass mattered
- System administrator rights run operating system commands.
- NVD: that amounts to SYSTEM or root on the host.
- Huntress saw the System Events feature used this way.
Right: How fast it was armed
- watchTowr's title points to patch diffing.
- Flare reports PoC material traded in Telegram channels.
- A further flaw, CVE-2026-40514, is not in KEV.
Caption: Bypass to remote code execution in two steps (Inferred).
Notes: Admin rights [4][5]. Huntress, Demonstrated and Reported [18]. Patch diffing reading Inferred [15]. Flare, Reported [25]. CVE-2026-40514 [9][17].

## PART 3 | Two attributions, neither from a government

| Who says | What they say |
|---|---|
| SmarterTools | "Warlock Group" behind its own breach |
| ReliaQuest | Storm-2603, moderate-to-high confidence |
| Huntress | 28 source IPs, no attribution |
| F5 Labs | One source in ASN 200593, no attribution |
Caption: The vendor's claim is its own statement; ReliaQuest is Reported.
Notes: Vendor [14]. ReliaQuest [20]. Huntress [18]. F5 Labs [21]. Storm-2603 and Warlock in ToolShell 2025 [27].

## PART 4 | One named victim: the vendor

- About 12 Windows servers appeared compromised, linked through Active Directory.
- SentinelOne stopped the encryption.
- Segmentation kept the website, cart and account portal online.
- The way in was one forgotten server out of about 30.
- No other victim, sector or regulator filing in any source opened.
Caption: Confirmed as the vendor's statement.
Notes: Vendor breach [14]. ReliaQuest's unnamed victim, caught at staging [20]. Regulator filings not checked.

## PART 4 | Exposure counts differ by method

Stat: 6,000 | Likely vulnerable, version check
Stat: 8,550 | Vulnerable instances, one researcher
Stat: 30,000 | SmarterMail instances on Shodan
Stat: 1,185 | Of 17,754 servers exposed, Flare
- Only the Shadowserver figure comes from a scan the study opened.
- The Shodan count is instances, not vulnerable ones.
Notes: Shadowserver, Demonstrated [19]. Macnica researcher via news [22], F5 [21], Flare [25], all Reported.

## PART 5 | Patched is not clean

- "Critical security fixes." hid three KEV flaws: check the build number.
- Count the clock from the fix: 15 Jan fix, 17 Jan attack, 26 Jan KEV.
- Planted files waited 6 to 7 days, so some updated servers were still hit.
- The KEV ransomware flag changed about 30 and 85 days after addition.
Caption: Triage readings Inferred from Confirmed facts.
Notes: Release notes [13]. Clock [4][9][13][15]. Planted files, vendor statement [14]. Flag history [10].

## DEFENDER VIEW | Update, then hunt as if compromised

Left: Fix and contain
- Run the current build; hardening ran to Build 9805.
- Inventory every instance, including forgotten ones.
- Keep mail servers in a DMZ, away from domain controllers.
- Allow only mail protocols outbound.
Right: Hunt what the vendor lists
- Velociraptor, JWRapper and SimpleHelp.
- Random-named .ps1 and .aspx files.
- Unusual local admins and startup items.
- Unexpected scheduled tasks.
Notes: Build 9805 [13]. Inventory and hunting list [14]. DMZ and egress, Reported [20][21].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- "Nation-state ransomware": no government attribution.
- "Ransomware deployed": encryption stopped or never started.
- 30,000 Shodan instances read as 30,000 vulnerable.
Right: Understated
- Release notes never said exploited; KEV flags all three.
- Compromise after updating makes patch counts flattering.
- No victim count exists, which is not evidence of few.
Notes: Overstated [14][20][21]. Understated [9][13][14]. Readings Inferred.

## MITRE MAPPINGS | Thirteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | All three CVEs, KEV |
| T1098 | Account Manipulation | Forced admin password reset |
| T1059 | Command and Scripting Interpreter | Commands via admin features |
| T1219 | Remote Access Tools | Velociraptor for C2 |
| T1486 | Data Encrypted for Impact | Encryption attempted, stopped |
Caption: ATT&CK v20.0; CWE-434, CWE-288, CWE-306; eight more techniques and the layer in the study.
Notes: Techniques [4][9][14][18][20] with library data [27]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Self-hosted mail is still a front door

- **Mail servers stay exposed.** As with Exchange in 2021, admins learned from researchers.
- **Patched is not clean.** As with ToolShell's machine keys, planted files outlived the fix.
- **The same crew, a new door.** Storm-2603 and Warlock appear in ToolShell and here.
- **Silent release notes cost time.** No CVE, no "exploited", three KEV flaws.
Notes: Exchange comparison Inferred. ToolShell [27]. Storm-2603 [20][27]. Release notes [13].
