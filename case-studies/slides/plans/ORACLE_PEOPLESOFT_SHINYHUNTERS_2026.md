# Slide plan: Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study

- Study: case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md
- Cover title: Oracle PeopleSoft / CVE-2026-35273 and / ShinyHunters, 2026
- Subtitle: A zero-day in the system of record for students, staff and applicants, and a WAF rule that was not a patch
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/ORACLE_PEOPLESOFT_SHINYHUNTERS_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Student records, then the FBI's job site

- From 27 May to 9 June 2026 ShinyHunters exploited a PeopleSoft zero-day.
- Oracle's out-of-band alert came on 10 June; KEV listed it on 12 June.
- The University of Nottingham told students their records were accessed.
- In September the actor returned against hosts guarded only by WAF rules.
- The FBI's recruitment site was defaced and its data claimed (Reported).
Caption: Evidence grade: Confirmed for the GTIG, Oracle, CISA and Nottingham records; the FBI story is Reported.
Notes: Zero-day window [7]. Alert [1]. KEV [4][5]. Nottingham [10]. September [8]. FBI [15][16].

## KEY FACTS | One CVE, two waves

Stat: 9.8 | CVSS 3.1, unauthenticated, over HTTP
Stat: 100+ | Organizations GTIG notified in June
Stat: 68% | Of them in higher education
Stat: 3 days | KEV deadline, 12 to 15 June
- Product: PeopleSoft Enterprise PeopleTools 8.61 and 8.62.
- Actor: UNC6240, tracked by GTIG as ShinyHunters (ATT&CK G1057).
- KEV flags known ransomware campaign use.
Notes: Severity [1]. Notified, not confirmed compromised [7]. KEV [4]. Actor [7][12].

## KEY FINDINGS | Four lessons from the record

- **The vendor page was the quietest record.** Oracle's alert never mentions exploitation.
- **The exploit predates the fix.** Data was on the leak site a day before the alert.
- **A stopgap became the attack surface.** WAF-only hosts fell in September.
- **One CVE id hides three flaws.** SSRF, file-path control and deserialization.
Notes: Vendor silence [1]; SSVC [3]; KEV [4]. Leak site [7]. September [8]. Three flaws [9].

## PART 1 | The dated record

| Date (2026) | Event |
|---|---|
| 15 May | FBI PSA warns about ShinyHunters |
| 27 May | Staging set up; zero-day use begins |
| 9 Jun | Stolen data on the leak site |
| 10 Jun | Oracle Security Alert; Nottingham notice |
| 11 Jun | CVE published; SSVC: exploitation active |
| 12 Jun | CISA adds the CVE to KEV |
| September | WAF rules bypassed; web shells planted |
| 22 Sep | FBI jobs site defaced (Reported) |
| 25 Sep | GTIG renewed-campaign report |
Caption: The zero-day window closed a day before the vendor's alert.
Notes: PSA [6]. Window [7]. Alert [1]. Nottingham [10]. CVE and SSVC [2][3]. KEV [4][5]. September [8]. FBI [15].

## PART 2 | The flaw and the September bypass

Left: What the records say
- Oracle: Updates Environment Management, no auth, may yield RCE.
- NVD and KEV: CWE-306 only.
- ZDI: one fix for three issues, SSRF, path control, deserialization.
Right: How the stopgap failed
- WAFs and proxies matched the literal path before decoding.
- The application server decoded it and served the request.
- GTIG: path blocking is "not a substitute for patching".
Caption: Advisory level only: flaw classes are named, request formats are not.
Notes: Oracle [1]. NVD and KEV [3][4]. ZDI [9]. Bypass and quote [8].

## PART 2 | What the actor did after access

- June: MeshCentral agents in disguise, acme-client certificates, sshpass over SSH.
- June: zstd archives before exfiltration, a marker file for victims.
- September: JSP web shells in PSEMHUB, or commands with no file written.
- September: SIDEEYE in an EV-signed installer, Neo-reGeorg tunnels.
- About a quarter of observed commands ran as root or SYSTEM.
Caption: A separate May breach adds pass-the-hash, Chisel and Rclone (Reported, Sekoia and Beazley).
Notes: June tools [7]. September tools [8]. Beazley case [21].

## PART 3 | Who and why

| Who | What the record says |
|---|---|
| Mandiant and GTIG | UNC6240, tracked as ShinyHunters |
| ATT&CK G1057 | Maps the CVE use to T1190 and T1587.004 |
| GTIG | A "pattern of data theft extortion" |
| FBI, via 404 Media | A PeopleSoft zero-day hit its jobs site |
| Police, Sep and Oct | Arrests in the Netherlands, Jordan, US |
Caption: No opened source shows an arrested person ran the PeopleSoft exploitation (Inferred).
Notes: GTIG [7][8]. ATT&CK [12]. FBI [15][16], Reported. Arrests [16][19][20], Reported.

## PART 4 | Impact and response

- Higher education first: 68% of the June notification list.
- Nottingham: student and alumni data; HIBP loaded 454,635 addresses.
- September reached technology, healthcare, transport and government.
- FBI: more than 5,000 personnel exposed, a contractor dropped (Reported).
- CISA: KEV with a three-day deadline under BOD 26-04.
Notes: Notification list [7]. Nottingham [10]; HIBP [11]. September sectors [8]. FBI [17][20]. KEV [4][5].

## PART 4 | The government record, and what is not this campaign

| Record | What it shows |
|---|---|
| KEV, 12 Jun | Due 15 Jun; known ransomware use |
| KEV, 10 Nov | Still the only PeopleSoft entry |
| Other Oracle KEV rows | EBS, HTTP Server plug-in, WebLogic |
| Nottingham | Working with Action Fraud and the ICO |
| Not counted | Boeing/Jeppesen, Harvard 2025 |
Caption: Neither GTIG post ties the PeopleSoft wave to Cl0p or the E-Business Suite campaign (Inferred).
Notes: KEV [4][5]. Other Oracle rows [4]. Nottingham [10]. Not this campaign [17][22], Reported.

## DEFENDER VIEW | What the record argues for

Left: Patch and close
- Patch PeopleTools from Oracle's alert.
- Disable or remove PSEMHUB where allowed.
- Give every WAF exception an expiry date.
Right: Hunt and assume access
- WebLogic logs, unexpected JSP, JSPX and EXE files.
- MeshCentral agents, Java-spawned shells, outbound SMB.
- Rotate credentials the PeopleSoft tier can read.
Caption: The zero-day window closed before the fix shipped, so every exposed host needed a hunt (Inferred).
Notes: Patch [1]. PSEMHUB [7][8]. WAF lesson [8], Inferred. Hunt guidance [7][8].

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "PeopleSoft zero-days", plural: one CVE.
- "100+ victims": organizations notified.
- "FBI hacked": the jobs site and a pivot.
Right: Understated
- Oracle's alert is silent on exploitation.
- CWE-306 alone hides a three-flaw chain.
- The WAF-only mitigation was bypassed.
Notes: One CVE [1][9]. Notified [7]. FBI [15][17][20]. Vendor silence [1][3][4][7]. Chain [9]. Bypass [8].

## MITRE MAPPINGS | The techniques GTIG and ATT&CK record

| Id | Technique | Tie to the campaign |
|---|---|---|
| T1595.002 | Vulnerability Scanning | 5 to 15 probes per host |
| T1587.004 | Exploits | ATT&CK G1057 entry |
| T1190 | Exploit Public-Facing Application | CVE-2026-35273 |
| T1505.003 | Web Shell | JSP shells in PSEMHUB |
| T1027 | Obfuscated Files or Information | Listed by GTIG |
| T1219 | Remote Access Tools | MeshCentral and MeshAgent |
| T1090 | Proxy | Neo-reGeorg |
| T1657 | Financial Theft | Leak-site extortion |
Caption: ATT&CK v20.0. CWE-306; CAPEC-36, 664, 76, 586, 72, 267. G1057; S1189, S1040.
Notes: Techniques [7][8][12] with [23]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | A familiar arc

- **Mass exploitation, then a leak site.** The Cl0p MOVEit pattern, by method, not actor.
- **Zero-day before the alert, KEV within days.** As with SharePoint ToolShell.
- **Education as a soft target.** The May PSA and June list both point at schools.
- **Careful attribution.** ATT&CK warns overlaps are not operational ties.
Notes: Cl0p and ToolShell comparisons, Inferred. PSA [6]; list [7]. Attribution [12]; Change Healthcare, Inferred.
