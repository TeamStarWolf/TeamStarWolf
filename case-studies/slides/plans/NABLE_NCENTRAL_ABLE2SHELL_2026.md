# Slide plan: Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026

- Study: case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md
- Cover title: Able2Shell and / the RMM Attack Surface / N-able N-central, November 2026
- Subtitle: One server per MSP, every customer behind it, and a disclosure with no notice
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The vendor treated it as critical before any CVE existed

- An RMM server holds an agent on every managed laptop, server and domain controller.
- On 9 November 2026 (UTC) a researcher's GitHub folder published 33 alleged N-central flaws with proof-of-concept scripts.
- Within hours N-able took hosted N-central offline in every region and told on-premises customers to disconnect.
- On 10 November it shipped 2026.4 Hotfix 2 and published seven CVE records.
- By 11 November every hosted server was upgraded; no source confirms a customer compromise.
Caption: Evidence grade: Confirmed for the vendor and CVE record; Reported for the researcher's claims and the press.
Notes: RMM role [44][45]. Publication [14][15]. Takedown [1]. HF2 and CVEs [2][4][5]. Hosted upgrade [1]. No compromise, Inferred from [3][17][18][19][23].

## KEY FACTS | A big headline, a smaller vendor record

Stat: 33 | Findings the researcher claims (Reported)
Stat: 7 | CVE records N-able published on 10 November
Stat: 9.3 | Top CVSS v4.0 score, no privileges needed
Stat: 0 | Of the seven in KEV, catalog 2026.11.10
- Fixed build: N-central 2026.4 Hotfix 2, build 2026.4.1.26.
- HF2 also removes legacy MDM and temporarily disables built-in remote control.
- Five earlier N-central CVEs are in KEV, three of them from August and September 2026.
Notes: README count [14][16]. CVE records [4] to [10]. Scores [4][5]. KEV [12]. HF2 [2]. Earlier KEV entries [12].

## PART 1 | Four chains, named only by class and privilege

| Chain | Class and result (researcher's claim) |
|---|---|
| 1 | Anonymous XXE in service import, code execution as the service account |
| 2 | Anonymous stored XSS in patch metadata, OGNL execution once an admin views it |
| 3 | The same stored XSS, code execution as root through Audit Export |
| 4 | Authenticated path traversal, then local privilege escalation to root |
Caption: No proof-of-concept script was opened, downloaded, quoted or run for this study.
Notes: Chains as the README names them, Reported [14]. Tenable's reading [16]. Handling rule from the study's Scope and method.

## PART 1 | The findings cross the boundaries an RMM exists to enforce

- Cross-customer appliance disclosure and Technician account creation.
- Registration-token and credential disclosure, including asset-discovery and agent credentials.
- A view-only role able to write configuration.
- MDM device impersonation and remote-control session termination.
- Every one of these is the researcher's claim until the vendor maps it.
Caption: The spread of classes matters more than any single entry (Inferred).
Notes: README index, Reported [14]. The boundary reading is Inferred from [14].

## PART 2 | Seven CVE records, two critical, one mislabelled

| CVE | Class | CVSS v4.0 |
|---|---|---|
| CVE-2026-125883 | XXE, CWE-611 | 9.3 |
| CVE-2026-125881 | SSRF, CWE-918 | 9.3 |
| CVE-2026-125878 | Titled OGNL, recorded CWE-79 | 8.7 |
| CVE-2026-125879 | Local privilege escalation, CWE-266 | 8.6 |
| CVE-2026-125882 | Path traversal upload, CWE-23 | 8.6 |
| CVE-2026-91000 | Insecure IPC, CWE-306 | 8.4 |
| CVE-2026-125880 | Stored XSS, CWE-644 | 8.3 |
Caption: CVE-2026-91000 was reserved in September; CVE-2026-125882 is credited to a different researcher.
Notes: Records [4] to [10]. NVD [11]. Reservation [10]. Credit [8].

## PART 3 | Under two days from publication to a fixed build

| Date (UTC) | Event |
|---|---|
| 9 Nov 04:14 | Commit "N-Able 0-Days" publishes the folder |
| 9 Nov 14:00 | Status incident 202584 starts, three regions |
| 9 to 10 Nov | Honeypot and decoy attempts reported |
| 10 Nov | HF2 notes posted; seven CVEs published |
| 11 Nov 01:04 | All hosted servers upgraded |
| 11 Nov | N-able blog: unauthenticated paths closed |
Caption: The status dashboard carries no time zone; its times are given as dashboard time.
Notes: Commit [14][15]. Status [1]. Attempts [18][19]. HF2 and CVEs [2][4] to [10]. Blog [3].

## PART 4 | Attempts on decoys, not compromise of customers

Left: What was seen
- N-able: scanning tied to the published code.
- watchTowr via Beazley: attempts against honeypots (Reported).
- Previdian: 68 events from one address on its decoy (Demonstrated).
Right: What was not
- Huntress: no Able2Shell exploitation in partner environments.
- H-ISAC relays N-able: no active exploitation, no data access.
- CISA: none of the seven in KEV; SSVC "poc" for one CVE.
Caption: Treat any server reachable between the drop and the upgrade as possibly compromised (Inferred).
Notes: Vendor [1][3]. watchTowr [18][30]. Previdian [19]. Huntress [17]. H-ISAC [23]. KEV and SSVC [12][4].

## PART 5 | The RMM server is one point of compromise for every customer

| Year | Landmark | What it showed |
|---|---|---|
| 2021 | Kaseya VSA | Ransomware pushed to managed endpoints |
| 2024 | ScreenConnect CVE-2024-1709 | Auth bypass to an admin account |
| 2025 | SimpleHelp CVE-2024-57727 | Downstream customers hit through a vendor |
| 2025 to 2026 | N-central KEV entries | Take Control used to reach endpoints |
| 2026 | Able2Shell | Hosted service offline worldwide |
Caption: Kaseya's home study in this library is Chronicle 2021.
Notes: Kaseya [44][45][47][48][59]. ScreenConnect [49][50][12]. SimpleHelp [51][52][53][54]. N-central [34][35][36][37][38][12]. Able2Shell [1][2][14].

## PART 6 | A disclosure dispute on the record

- The researcher says he gave no advance notice to N-able.
- His stated reason: earlier reports on a different N-able product went unpatched for months.
- N-able calls claims that it ignored responsible disclosure inaccurate.
- N-able says the 9 November findings did not come through its reporting channels.
- The study does not judge the dispute.
Caption: Plan for both failure modes: slow vendor fixes and zero-notice publication (Inferred).
Notes: No notice, Reported [25]. Earlier reports, Reported [26][25]. Vendor statement [3]. Alert wording, Reported [28].

## PART 7 | The vendor's behavior is the priority signal

- Scores run 8.3 to 9.3; only two of the seven need no privileges.
- A hosted fleet taken offline in three regions says "emergency change now".
- SSVC moved before KEV, and KEV may never move.
- The 33 findings do not map to the seven CVEs: track the latest hotfix, not a CVE list.
- HF2 is a fleet change: Agents first, then Probes.
Caption: Overstated: "33 zero-days" and "customers compromised". Understated: the blast radius and the missing KEV entry.
Notes: Scores [4] to [10]. Takedown [1]. SSVC and KEV [4][12][60]. Mapping [3][14]. Upgrade order [2]. Overstated and understated, the study's Part 7.

## DEFENDER VIEW | Contain, upgrade, then hunt from 8 November

Left: Contain and reduce exposure
- Keep self-hosted servers offline until 2026.4.1.26 or later.
- Upgrade Agents first, then Probes, for every customer.
- Restrict the console to an admin VLAN or VPN.
Right: Hunt and recover
- New administrators, deployed scripts, remote-control sessions.
- Unexpected child processes and silent installs on endpoints.
- Preserve logs, then rotate admin, technician and agent credentials.
Caption: Assess every client network the server manages, not just the server.
Notes: Contain [1][2][23]. Exposure [21][23][20]. Hunt [17][23][20]. Recover [32][23][20].

## DEFENDER VIEW | For the customers of an MSP

- Require MFA on privileged, administrative and remote-access accounts.
- Keep MSP accounts out of customer administrator groups.
- Allowlist the approved RMM and block others at the boundary.
- Ask every software supplier whether an RMM is embedded in its product.
- Keep backups the RMM cannot reach.
Caption: CISA's Kaseya-era guidance still reads as current.
Notes: Kaseya guidance [46][45]. RMM guidance [56]. Embedded RMM [53].

## MITRE MAPPINGS | Thirteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1595.002 | Vulnerability Scanning | Scanning seen by N-able |
| T1190 | Exploit Public-Facing Application | Two unauthenticated CVEs |
| T1068 | Exploitation for Privilege Escalation | Two local CVEs |
| T1219 | Remote Access Tools | Take Control in 2026 |
| T1072 | Software Deployment Tools | Kaseya VSA, 2021 |
| T1199 | Trusted Relationship | MSP to customer |
Caption: ATT&CK v20.0; also T1059, T1136, T1572, T1543.003, T1078, T1486, T1552.001. Context objects G0115, S0496, S0591.
Notes: Techniques and objects [57][58][59] with [1][4][5][7][10][36][37][45][53]. CWE and CAPEC [4] to [10][58]. D3FEND [58]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | One server, every customer

- **Hosted gets fixed first.** Self-hosted servers are the long tail.
- **Vendors now switch features off.** Removing a feature removes its surface.
- **Counts are claims.** "33" and "seven" describe different things.
- **Evidence thresholds are not safety thresholds.** No KEV entry is not safety.
- **AI-assisted discovery raises the volume.** The researcher says AI helped.
Notes: Hosted [49][44][1][26]. Features [2]. Counts [3][14][16]. Thresholds [1][18][17][4][12]. AI, Reported [25]. The lessons are Inferred.
