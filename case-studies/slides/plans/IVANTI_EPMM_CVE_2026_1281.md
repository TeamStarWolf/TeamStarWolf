# Slide plan: Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340): A Case Study

- Study: case-studies/IVANTI_EPMM_CVE_2026_1281.md
- Cover title: Ivanti EPMM / Code Injection / (CVE-2026-1281 and CVE-2026-1340)
- Subtitle: Two unauthenticated flaws in a mobile device management server, and the identity data behind it
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/IVANTI_EPMM_CVE_2026_1281.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An MDM server is an identity store

- EPMM is Ivanti's on-premises mobile device management server.
- Two code injection flaws let an attacker run code without logging in.
- Ivanti disclosed them on 29 January 2026 with customers already exploited.
- NCSC-NL saw the database copied: device data, directory users, Office365 tokens.
- Dutch ministers named six public bodies and a municipality.
Caption: Evidence grade: Confirmed from Ivanti, the CVE records, KEV, NCSC-NL and the Dutch government.
Notes: Product and disclosure [1]. Flaws [2][3]. Database theft [12]. Named bodies [13][14].

## KEY FACTS | Every risk signal at its maximum

Stat: 9.8 | CVSS 3.1 base score, both CVEs
Stat: 3 | Days each KEV listing allowed
Stat: 7 | Dutch bodies with misuse found or not ruled out
Stat: 0 | Actors named by any source
- Weakness: CWE-94, code injection; CAPEC-242 from the CNA.
- SSVC: exploitation active, automatable, technical impact total.
- Fix: hotfix RPMs that do not survive a version upgrade; 12.8.0.0 planned.
Notes: Score, CWE and CAPEC [2][3][4][5]. KEV [6]. Bodies [14]. Actor silence [25], Inferred. SSVC [2][3]. Fix [2][10].

## PART 1 | From disclosure to a named victim list

| Date | Event |
|---|---|
| 29 Jan 2026 | Ivanti discloses; KEV adds CVE-2026-1281 |
| 30 Jan 2026 | CERT-EU: one flaw exploited; Rapid7 and watchTowr publish |
| 2 Feb 2026 | NCSC-NL: assume breach, report even after patching |
| 9 Feb 2026 | NCSC-NL: database copied, multiple actors plausible |
| 17 Feb 2026 | Unit 42: widespread, mostly automated attempts |
| 20 Feb 2026 | NCSC-NL: a compromised EPMM can reach Sentry |
| 27 Feb 2026 | Dutch letter lists six bodies and a municipality |
| 8 Apr 2026 | KEV adds CVE-2026-1340; Canada relays both exploited |
Caption: Rows Confirmed from the vendor, CISA, CERT-EU, NCSC-NL and the Dutch government; Rapid7 and Unit 42 Reported.
Notes: Disclosure and KEV [1][6][7]. CERT-EU [10]. Research [21][22]. NCSC-NL [11][12]. Unit 42 [20]. Dutch letter [14]. April [6][8][9].

## PART 1 | Where the record disagrees

- Affected version lists differ between Canada, CERT-EU and NVD.
- One flaw first, then both: CVE-2026-1340 reached KEV only on 8 April.
- Its SSVC stamp says 29 January in a record updated on 9 April.
- Public PoC by 30 January per Rapid7; 4 February per NCSC-NL.
- NOS reports five months of access at DJI; the government record does not.
Caption: Every list covers release lines up to 12.7.0.0; none lists 12.8.0.0 (Inferred).
Notes: Versions [4][5][9][10]. KEV and SSVC [3][6][10]. PoC [11][21]. DJI [14][15][16][19].

## PART 2 | The flaw, at advisory level

- Ivanti: code injection that allows unauthenticated remote code execution.
- watchTowr: in the web tier's app store and file transfer handling.
- The fix is an RPM hotfix, not a new version, until 12.8.0.0.
- KEV notes cite two RPM builds, 1.0.0 in January and 1.1.0 in April.
Caption: No request format, endpoint or exploit step is reproduced.
Notes: Description [2][3]. Root cause [22], Demonstrated. Fix [2][10]. Builds [6]; the reissue reading is Inferred.

## PART 2 | What attackers did after getting in

Left: Seen by national CERTs
- The MIFS database copied and exfiltrated.
- Device data, LDAP users, Office365 tokens and credentials.
- At least one actor wiped its traces.
- EPMM keystore can open a path to Sentry.
Right: Seen by Unit 42
- Reverse-shell attempts.
- Nezha monitoring agent downloads.
- JSP web shells and second-stage scripts.
- Cryptominers and dormant backdoors.
Caption: The mix of data theft and mining fits more than one actor (Inferred).
Notes: NCSC-NL [11][12], Confirmed. Unit 42 [20], Reported.

## PART 3 | Silence on attribution is the finding

| Question | What the record says |
|---|---|
| Actor in 2026 | Not named by any source opened |
| NCSC-NL | Multiple actors plausible |
| Same as earlier Ivanti rounds? | NCSC-NL: not clear |
| 2023 EPMM round | APT actors, AA23-213A |
| 2025 EPMM round | China-nexus, per EclecticIQ |
| Lineage only | C0029 Cutting Edge (Connect Secure) |
Caption: Carrying the 2025 attribution over to 2026 is unsupported (Inferred).
Notes: Silence [25]. NCSC-NL [12]. 2023 [23]. 2025 [24], Reported. Lineage [27].

## PART 4 | Who was hit

- Dutch Data Protection Authority and Council for the Judiciary.
- Prison service DJI: staff names, emails, phones, location data.
- Four more bodies and one municipality where misuse was not ruled out.
- European Commission MDM attack on 30 January, contained in 9 hours.
- Unit 42: victims in five sectors across four countries.
Caption: The Commission release does not name Ivanti or EPMM; any link rests on timing (Inferred).
Notes: Dutch record [13][14][15][16]. Commission [18]. Unit 42 [20], Reported.

## PART 5 | Patching did not close the case

- NCSC-NL: patching does not remove earlier compromise.
- Reinstall rather than clean in place.
- Treat configuration backups as taken too.
- A clean detection RPM is no guarantee.
- Recheck the RPM after every version upgrade.
Caption: A version-only scanner can be wrong in both directions here (Inferred).
Notes: NCSC-NL [12]. RPM and upgrades [10]. Scanner reading Inferred from [2][10].

## DEFENDER VIEW | Treat it as an identity incident

Left: Contain and rebuild
- Preserve evidence first, as CERT-EU advises.
- Report to the national CERT, even after patching.
- Reinstall EPMM; treat backups as exposed.
- Confirm the hotfix RPM after each upgrade.
Right: Rotate and hunt
- Rotate LDAP credentials, Office365 tokens, keys and certificates.
- Check Ivanti Sentry for access from EPMM.
- Hunt for web shells, miners and unknown agents.
- Order work by SSVC and KEV together.
Notes: Evidence [10]. Report and reinstall [12]. RPM [10]. Rotation [12][16]. Sentry [11]. Hunt [20]. SSVC and KEV [2][3][6].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- Both CVEs as confirmed January zero-days.
- The Commission incident as an EPMM case.
- The 2025 China-nexus actor as the 2026 actor.
Right: Understated
- "A very limited number of customers."
- An RPM fix that an upgrade removes.
- The EPMM-to-Sentry path that outlasts the patch.
Notes: Overstated [3][6][10][18][21][24][25]. Understated [1][10][11][12][14][20]. Readings Inferred.

## MITRE MAPPINGS | Thirteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated code injection |
| T1505.003 | Web Shell | JSP web shells |
| T1105 | Ingress Tool Transfer | Second-stage scripts, Nezha |
| T1219 | Remote Access Tools | Nezha agent attempts |
| T1496.001 | Compute Hijacking | Cryptominers |
| T1005 | Data from Local System | MIFS database copied |
| T1528 | Steal Application Access Token | Office365 tokens |
| T1552.004 | Private Keys | DJI certificates leaked |
Caption: Also T1587.004, T1588.005, T1059, T1070, T1552; CWE-94; CAPEC-242; layer in the study.
Notes: Techniques [2][3][6][11][12][16][20][21] with library data [26]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The same product keeps returning

- **MDM is identity infrastructure.** Rotate and rebuild, not just patch.
- **Hotfixes that do not persist.** Version-based programs cannot see them.
- **Government records measured scale best.** Better than vendor statements.
- **Eight EPMM entries in KEV since 2023.** A standing exposure, not a one-off.
Notes: MDM [12][14][16]. Hotfix [10]. Scale [12][14]. KEV line [6]. All readings Inferred.
