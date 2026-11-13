# Slide plan: The Stryker Device-Wipe Attack of March 2026: A Case Study

- Study: case-studies/STRYKER_HANDALA_WIPER_2026.md
- Cover title: The Stryker Device-Wipe / Attack of March 2026 / A Case Study
- Subtitle: A built-in wipe command, a persona that claimed it, and three weeks to rebuild
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/STRYKER_HANDALA_WIPER_2026.md, published 12 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The admin console was the weapon

- On 11 March 2026 Stryker reported a global disruption to its Microsoft environment.
- Staff in four countries reported managed devices, personal phones included, wiped remotely.
- Reporting points to a compromised administrator and the built-in Intune wipe.
- DOJ ties the Handala persona's claim domains to Iran's MOIS and seized four on 19 March.
- No CVE or KEV entry applies: the exposure was privilege and configuration.
Caption: Evidence grade: Confirmed from Stryker's filings, CISA and DOJ; the wipe mechanism is Reported.
Notes: Disruption [1]. Wiped devices [22]. Mechanism [21][23]. DOJ [14]. No CVE or KEV [12][13].

## KEY FACTS | Claims are large, filings are careful

Stat: 21 | Days from disclosure to full operations
Stat: 200,000+ | Devices the persona claimed (Reported)
Stat: 4 | Persona domains seized by DOJ
Stat: 0 | CVEs or KEV entries tied to the attack
- Victim: Stryker Corporation, a medical technology manufacturer in Portage, Michigan.
- Unit 42 names Entra ID, servers and workstations as affected.
- Stryker declared the incident material to first-quarter 2026 results.
Notes: 11 March to 1 April [1][11]. Persona claim [21][22]. Domains [14]. KEV [13]. Victim [1]. Unit 42 letter [4]. Materiality [6].

## PART 1 | From wipe to materiality

| Date (2026) | Event |
|---|---|
| 11 Mar | Devices wiped in four countries; 8-K reports a global disruption |
| 12 Mar | 8-K: order processing, manufacturing and shipping disrupted |
| 18 Mar | CISA alert on endpoint management names the Stryker attack |
| 19 Mar | DOJ announces seizure of four MOIS persona domains |
| 23 Mar | 8-K revises the no-malware view: a malicious file hid activity |
| 1 Apr | Fully operational across global manufacturing |
| 9 Apr | 8-K/A Item 1.05: material to first-quarter results |
| 20 Apr | ATT&CK creates G1055 VOID MANTICORE |
Caption: The wipe itself is known from staff and press reports, graded Reported.
Notes: Wipe [22]. Filings [1][2][3][6]. CISA [12]. DOJ [14]. Operations [11]. ATT&CK [19].

## PART 2 | The primaries fix the outline, not the mechanism

Left: What the primaries say
- Unit 42: a compromise affecting Entra ID, servers and workstations.
- No persistent access found and no unauthorized activity after 11 March.
- 23 March 8-K: a malicious file ran commands to hide activity; it could not spread.
Right: What reporting adds
- An administrator account was compromised.
- A new Global Administrator account was created.
- The built-in Intune wipe command was used.
Caption: Neither primary names the file, the commands or the initial access route.
Notes: Unit 42 letter [4]. 8-K [3]. Reporting [21][23]. Gaps [3][4].

## DISCREPANCIES | The figures do not agree

| Figure | Who gives it, and its status |
|---|---|
| 200,000+ devices | The persona, at the time of the attack (claim) |
| Nearly 80,000 devices | The persona later, per BleepingComputer (claim) |
| Tens of thousands | TechCrunch (Reported) |
| 50 TB stolen | The persona; no primary confirms exfiltration |
| No device count | Stryker's filings and customer pages |
| No PII found | Stryker's motion to dismiss, as reported |
Caption: None of these counts is confirmed by a primary opened for the study.
Notes: Persona [21][22][23]. TechCrunch [24]. Filings [1] to [11]. Motion [28].

## PART 3 | Four statements carry the attribution

| Who | What they say |
|---|---|
| DOJ, 19 Mar | MOIS used four seized domains, two for the Handala persona |
| Check Point | Handala Hack is a persona of MOIS-affiliated Void Manticore |
| Unit 42 | A state-directed MOIS front, as currently assessed |
| ATT&CK G1055 | VOID MANTICORE; its description names the Stryker attack |
| ESET | A pro-Iranian hacktivist group, not state-aligned (Reported) |
Caption: DOJ attributes the claim domains, not the intrusion forensics; Stryker speaks only of purported actors.
Notes: DOJ [14]. Check Point [17]. Unit 42 [16]. ATT&CK [19]. ESET via the 2026 chronicle [31]. Stryker [10].

## PART 4 | Three weeks and a rebuild

- Some staff could not reach IT systems; ordering ran on manual workarounds.
- Electronic ordering was returning on 15 March; manufacturing was ramping by 23 March.
- Systems were rebuilt or restored from backups predating the compromise window.
- Microsoft was engaged to recover the identity infrastructure.
- Some personalized-implant cases were rescheduled for the week of 16 March.
Caption: Idle production time still weighed on gross margin in the third-quarter 10-Q.
Notes: Workarounds [8]. Ordering and ramp [10][5]. Rebuild and Microsoft [4]. Implant cases [10][11]. Margin [8][9].

## PART 4 | Courts, government and hospitals

Left: Government
- CISA's 18 March alert, with Microsoft and Stryker contributing.
- DOJ's domain seizures the next day.
- Health-ISAC: require a second approver for destructive Intune commands.
Right: Courts and hospitals
- A former employee filed a class action on 13 March.
- Plaintiffs dismissed without prejudice on 29 June (Reported).
- A Maryland EMS notice on LifeNet, which Stryker disputed (Reported).
Notes: CISA [12]. DOJ [14]. Health-ISAC [18]. Complaint [27]. Dismissal [28]. LifeNet [26].

## DEFENDER VIEW | Treat device management as tier zero

Left: Limit the blast radius
- Require a second administrator for wipe and other high-impact actions.
- Scope Intune administrators by role and scope tags.
- Decide in BYOD policy what an administrator can do to a personal phone.
Right: Detect and recover
- Phishing-resistant MFA and privileged identity management for admin roles.
- Alert on any new Global Administrator and on mass wipes.
- Plan an Entra ID rebuild path and manual ordering workarounds.
Caption: A program that ranks work only by CVE and KEV would have seen nothing here (Inferred).
Notes: Multi Admin Approval and RBAC [12][15][18]. MFA and PIM [12][15]. Alerts [16][23]. Recovery [4][8][10]. BYOD [22]. Inferred readings are the study's own.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- The 200,000-device, 80,000-device and 50 TB figures are persona claims.
- Stryker's filings give no device count and do not confirm exfiltration.
- The attribution as settled: vendor and ATT&CK views are assessments.
Right: Understated
- The day-one "no malware" framing was revised on 23 March.
- Unit 42 describes a compromise of Entra ID, servers and workstations.
- Together they show more than a device-management misuse.
Notes: Claims [21][22][23]. Filings [1] to [11]. Attribution [14][16][17][19]. Revision [1][3]. Unit 42 [4]. The assessments are Inferred.

## MITRE MAPPINGS | Eleven techniques, one bound group

| Id | Technique | Tie to Stryker |
|---|---|---|
| T1583.001 | Domains | Four MOIS persona domains |
| T1078.004 | Cloud Accounts | Entra ID and admin compromise |
| T1136.003 | Cloud Account | New Global Administrator (Reported) |
| T1651 | Cloud Administration Command | Built-in remote wipe |
| T1072 | Software Deployment Tools | Wipe through Intune |
| T1561.001 | Disk Content Wipe | Managed devices wiped |
| T1485 | Data Destruction | Destructive attack claimed |
Caption: ATT&CK v20.0; also T1585.001, T1566, T1098 and T1491.001. Group G1055 VOID MANTICORE. CAPEC-560, CAPEC-98, CAPEC-148.
Notes: Techniques [3][4][14][19][22][23] with [29]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Administrative tools are destructive tools

- **A built-in wipe needs no malware.** The admin console reached every managed device.
- **Personas are a delivery mechanism.** DOJ calls the playbook "faketivist."
- **Treat persona numbers as claims.** Confirm counts against filings before repeating them.
- **The lineage is long.** The same persona family hit Albania's government in 2022.
Notes: Wipe [12][23]. Faketivist [14]. Claims [21][22]. Albania, HomeLand Justice [20][29]. The themes are Inferred from the record.
