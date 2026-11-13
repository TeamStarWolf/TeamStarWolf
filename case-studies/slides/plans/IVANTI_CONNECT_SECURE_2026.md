# Slide plan: The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study

- Study: case-studies/IVANTI_CONNECT_SECURE_2026.md
- Cover title: The Ivanti Connect Secure / Zero-Day Chain / of October 2026
- Subtitle: A fully patched VPN appliance, two rounds of fixes, and an integrity check that came back clean
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/IVANTI_CONNECT_SECURE_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Patch twice, and do not trust a clean check

- Volexity found the chain on a customer appliance fully patched at 22.8R2.4; exploitation began on 3 October.
- Ivanti disclosed CVE-2026-104935 on 13 October as under limited exploitation.
- The root escalation, CVE-2026-111357, was published on 15 October and fixed only on 29 October.
- The actor left no implant, and Ivanti's Integrity Checker Tool missed the in-memory patching.
- KEV gave two of the three CVEs a three-day deadline with forensic triage.
Caption: Evidence grade: Confirmed for the record; the exposed-host counts and the 1 October start are Reported.
Notes: Discovery and start [12]. Disclosure [1]. Escalation [4][7][12]. No implant [10][12]. KEV [9].

## KEY FACTS | Three CVEs, two fix dates, one described victim

Stat: 3 | CVEs in the chain
Stat: 16 | Days the root escalation stayed unpatched
Stat: 3 | Days KEV allowed for the two forensic-triage entries
Stat: 5,000+ | Internet-facing hosts in early November (Reported)
- Product: Ivanti Connect Secure, branches 22.8, 25.1.1 and 25.1.2.
- Full-chain fixes: 25.1.1.3, 25.1.3.1 or 22.8R2.6.
- Actor: UTA0576, previously unknown; low-confidence criminal motive.
Notes: Product [3][10][15]. Sixteen days [12]. KEV [9]. Host counts via the press [19][20]. Fixes [14][15]. Actor [12].

## PART 1 | From first exploitation to the second fix

| Date (2026) | Event |
|---|---|
| 3 Oct | Exploitation of a 22.8R2.4 appliance begins |
| 13 Oct | Ivanti discloses; KEV lists CVE-2026-104935, due 16 Oct |
| 15 Oct | CVE-2026-111357 published as exploited; no fix |
| 29 Oct | Ivanti ships 25.1.1.3 and 22.8R2.6 |
| 30 Oct | KEV adds the two later CVEs; CISA revises its alert |
| 3 Nov | CVE-2026-118527 record published |
Caption: Defused, quoted in the press, puts first activity on 1 October; its telemetry was not opened (Reported).
Notes: Start [12]. Disclosure and KEV [1][9][10]. Escalation record [4][7]. Fixes [5][12][22]. KEV and alert [9][10]. Record [5][8]. Defused [19][21].

## PART 1 | The record disagrees with itself

- **Versions.** CISA, the CVE records and NVD give different affected-version cutoffs.
- **Weakness.** The CVE record and NVD give CWE-829; KEV gives CWE-306, CWE-862 and CWE-345.
- **Score.** MITRE's CVSS for CVE-2026-111357 is 7.0; the press cites 8.8.
- **KEV before CVE.** CVE-2026-118527 was KEV-listed four days before its record was published.
Caption: Read together, the 13 October builds closed the bypass and code execution but not the full chain (Inferred).
Notes: Versions [3][4][7][10]. Weakness [4][7][9]. Score [7] and, Reported, [23]. KEV before CVE [5][9].

## PART 2 | Three links in the chain, at advisory level

| CVE | Class | CVSS 3.1 |
|---|---|---|
| CVE-2026-104935 | Auth bypass by spoofing; remote command execution | 8.6 |
| CVE-2026-111357 | Root via the dsinvoked broker trusting DSCache data | 7.0 |
| CVE-2026-118527 | Predictable filenames; authenticated upload | 4.3 |
Caption: Mapping the upload handler's predictable path to CVE-2026-118527 is the study's own; Volexity does not name that CVE (Inferred).
Notes: Classes and scores [3][4][5][6][7][8]. Chain as Volexity describes it [12]. KEV says each can be chained with the other two [9].

## PART 2 | No implant to find

Left: What the actor did with root
- Extracted stored LDAP credentials.
- Queried LDAP for LAPS passwords and BitLocker recovery keys.
- Sprayed passwords and reviewed logs for valid usernames.
- Ran a renamed packet-capture tool for credentials and NTLM hashes.
Right: Why it was hard to see
- Commands and data rode the exploit's own HTTPS traffic.
- Library code was patched only in memory, then restored.
- The Ivanti debug log and the Linux audit log were tampered with.
- Memory and core-dump analysis found the chain and the sniffer.
Caption: Volexity assesses with high confidence that the activity was preparation for lateral movement.
Notes: Post-exploitation and evasion [12]. Integrity Checker miss [10][12]. Kerberoast function present but not used [12].

## PART 3 | A new actor, not the 2024 story again

- Volexity tracks UTA0576 as a previously unknown group.
- Low confidence: a criminal rather than espionage motive.
- Medium confidence: the actor uses large language models for exploits and post-exploitation.
- No government advisory opened names an actor, victim or agency.
- The 2024 Cutting Edge campaign used web shells and custom malware; this chain left none.
Caption: The 2026 chain should not be attached to UNC5221 on the strength of the product alone (Inferred).
Notes: Actor and assessments [12]. Advisories [10][14][15][16][17]. Cutting Edge C0029 [24]. China record [25].

## PART 4 | One described appliance is a floor, not a total

- Volexity describes one compromised appliance, with no sector, geography or count.
- Ivanti said it was working directly with affected organizations.
- Shadowserver counted over 5,500 exposed instances at disclosure (Reported).
- Ivanti said it chose not to delay the first fix once the escalation was found (Reported).
Caption: Ivanti's November Security Update did not mention Connect Secure.
Notes: Victims [12]. Vendor [1]. Counts via the press [19][20]. Fix decision, Reported [20][23]. November update [2].

## PART 4 | KEV and BOD 26-04 set a three-day clock

Stat: 3 | Days for the forensic-triage entries
Stat: 14 | Days for CVE-2026-118527
Stat: 17 | Connect Secure and Pulse entries in KEV since 2021
Stat: 38 | Ivanti entries in KEV
- BOD 26-04 requires remediation within three days where a KEV timeline includes forensic triage.
- KEV marks known ransomware use as Unknown for all three.
- Canada, INCIBE-CERT, HKCERT and Singapore's CSA all issued advisories.
Notes: KEV entries and counts from catalog 2026.11.10 [9]. BOD 26-04 [11]. National CERTs [14][15][16][17]. The 14-day reading is Inferred from the dates [9].

## PART 5 | A version scan would have said fixed

- On 14 October, a scanner reading version strings would mark 22.8R2.5 as fixed.
- The root escalation was still open on that build.
- The patch level that closes the known chain is 25.1.1.3, 25.1.3.1 or 22.8R2.6.
- 22.8 reaches end of life on 31 January 2027.
Caption: Use SSVC and the KEV forensic-triage flag to order the work, not the version string alone (Inferred).
Notes: Scanner reading Inferred from [4][15]. Fixed builds [14][15]. End of life [10]. SSVC [6]. Forensic triage [9][11].

## DEFENDER VIEW | Patch, hunt in memory, reset and rotate

Left: Patch and hunt
- Move to the full-chain builds, then off 22.8.
- Treat any appliance exposed from 1 October on an affected build as possibly compromised.
- Use memory and network forensics; an Integrity Checker pass is not proof.
- Watch for bursts of welcome.cgi requests and path and routing-header mismatches.
Right: Recover
- Factory reset and upgrade, by CISA's sequence.
- Reset every password, certificate and API key.
- Rotate LDAP bind, LAPS and BitLocker secrets the appliance could read.
- Alert on auth failures from the appliance's internal interface (Reported).
Notes: Patch [10][15]. Exposure window Inferred from [12][19]. Forensics [10][12]. Detection [12]. Recovery [10]. Directory secrets Inferred from [12]. Internal interface, Reported [21].

## OVERSTATED AND UNDERSTATED | What the headlines got wrong in both directions

Left: Overstated
- All three CVEs as internet entry points: only CVE-2026-104935 is remote and unauthenticated.
- The 1 October start date rests on unopened telemetry.
- An AI-built chain goes further than Volexity's assessment.
Right: Understated
- The chain was first seen on a fully patched appliance.
- The escalation stayed unpatched for 16 days while exploited.
- The 13 October builds did not close the chain.
- The integrity check gave a false clean.
Notes: Overstated [3][4][5][10][21][12], Inferred where labelled. Understated [12][15], Confirmed.

## MITRE MAPPINGS | Fourteen techniques, all the study's own reading

| Id | Technique | Tie to the chain |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Auth bypass and code execution |
| T1068 | Exploitation for Privilege Escalation | Root via dsinvoked |
| T1601.001 | Patch System Image | In-memory library patching |
| T1552 | Unsecured Credentials | LDAP, LAPS and BitLocker secrets |
| T1040 | Network Sniffing | Renamed packet capture |
| T1041 | Exfiltration Over C2 Channel | Data in exploit responses |
Caption: ATT&CK v20.0; also T1587.004, T1588.007, T1070, T1685.006, T1036.003, T1110.003, T1654, T1071.001. CWE-290, 829, 306, 862, 345, 340.
Notes: Techniques and fit notes [12][3][4][10] with library data [24]. CWE [3][4][5][7][8][9]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The VPN edge is a standing exposure

- **Edge appliances keep failing the same way.** Seventeen KEV entries since 2021.
- **Patch first, fix second.** The trade-off is defensible but leaves a window.
- **Integrity checks are not forensics.** Recovery means a reset and full rotation.
- **The record is a moving target.** Two CNAs, three CWE sets and two scores.
- **One assessment, not a trend.** The LLM finding is a single data point.
Notes: KEV count [9]. Fix timing [12][23]. False clean [10][12]. Record [4][5][7][9][23]. LLM assessment [12]. The lessons are Inferred.
