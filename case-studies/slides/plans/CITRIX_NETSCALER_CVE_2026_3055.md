# Slide plan: The Citrix NetScaler SAML IdP Memory Overread (CVE-2026-3055): A Case Study

- Study: case-studies/CITRIX_NETSCALER_CVE_2026_3055.md
- Cover title: Citrix NetScaler / SAML IdP Memory Overread / (CVE-2026-3055)
- Subtitle: A single sign-on front door that leaked memory, and why the patch is not the end
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CITRIX_NETSCALER_CVE_2026_3055.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The login front door leaked memory

- NetScaler ADC and Gateway can act as a SAML identity provider.
- CVE-2026-3055 lets an unauthenticated request read memory it should not.
- Citrix disclosed it on 23 March 2026 and said it found it internally.
- watchTowr saw exploitation on 27 March; KEV listed it on 30 March.
- In testing, the overread returned an administrative session ID.
Caption: Evidence grade: Confirmed from Citrix, the CVE record, NVD, KEV and CERT-EU; exploitation date Reported.
Notes: Bulletin [1]. Honeypots [11], Reported. KEV [4][6]. Session ID [11], Demonstrated.

## KEY FACTS | Critical, exploited, and narrowly scoped

Stat: 9.3 | CVSS v4.0 base score
Stat: 3 | Days the KEV listing allowed
Stat: 2 | Leak sites shown under one CVE
Stat: 0 | Actors or victims named by any source
- Weakness: CWE-125, out-of-bounds read.
- Precondition: a SAML IdP profile in the running configuration.
- Fixed: 14.1-60.58, 14.1-66.59, 13.1-62.23, FIPS and NDcPP 13.1-37.262.
Notes: Score and CWE [1][3]. KEV [4][5]. Leak sites [10][11]. Silence [1] to [15], Inferred. Builds [1].

## PART 1 | Seven days from bulletin to KEV

| Date (2026) | Event |
|---|---|
| 23 Feb | The NetScaler CNA reserves the CVE |
| 23 Mar | CTX696300; same-day revision adds 14.1-60.58 |
| 23 Mar | CERT-EU 2026-003: no public evidence of exploitation |
| 27 Mar | watchTowr honeypots see exploitation |
| 30 Mar | KEV adds CVE-2026-3055, due 2 April |
| 31 Mar | CISA ADP: exploitation active, automatable |
| 30 Jun | CTX696604 fixes the follow-on CVE-2026-8451 |
Caption: Rows Confirmed from Citrix, the CVE record, KEV and CERT-EU; watchTowr Reported.
Notes: Reservation [2]. Bulletin [1]. CERT-EU [8]. Honeypots [11]. KEV [4][6]. ADP [2]. Follow-on [13].

## PART 1 | Where the record disagrees

- The bulletin and NVD say 14.1 before 60.58; the CNA says before 66.59.
- watchTowr tested 14.1-66.54 as unpatched and 66.59 as patched.
- An SSVC stamp of 23 March is not evidence of exploitation that day.
- "Identified internally," yet outside research found a second leak site in six days.
Caption: This study reads 14.1-66.x builds before 66.59 as affected (Inferred).
Notes: Range [1][2][3][8][15]. Test builds [10], Demonstrated. SSVC [2]. Discovery [1][11].

## PART 2 | The flaw, at advisory level

- An unauthenticated request reads past its buffer in the SAML IdP login flow.
- Part 1 (28 March): a small overread on the SAML login path.
- Part 2 (29 March): a WS-Federation overread leaks kilobytes per request.
- Traces show in ns.log only with DEBUG logging; the bulletin gives no detection guidance.
- A Metasploit scanner module was proposed on 30 March and merged on 20 May.
Caption: No request format, parameter or exploit step is reproduced.
Notes: Class [1]. Research [10][11], Demonstrated. Logging [10], Reported. Module [16].

## PART 2 | Three CVEs, two bulletins

| CVE | Class | Precondition | Record |
|---|---|---|---|
| CVE-2026-3055 | Overread, CWE-125 | SAML IdP | KEV 30 Mar 2026 |
| CVE-2026-4368 | Race condition, CWE-362 | Gateway or AAA, 14.1-66.54 | Not in KEV |
| CVE-2026-8451 | Overread, CWE-125 | SAML IdP | Not in KEV |
Caption: CVSS v4.0 scores 9.3, 7.7 and 8.8; KEV as of catalog 2026.11.10.
Notes: CVE-2026-3055 [1][2][4]. CVE-2026-4368 [1][7]. CVE-2026-8451 [13][14]. KEV [4].

## PART 3 | No actor, no victim, no ransomware on record

| Question | What the record says |
|---|---|
| Actor | Not named by any source opened |
| Victims or sectors | None named |
| KEV ransomware use | Unknown |
| CitrixBleed (2023) | Known ransomware use; LockBit 3.0 affiliates |
| CitrixBleed 2 (2025) | Known ransomware use |
Caption: The CitrixBleed lineage is not evidence about who exploited CVE-2026-3055 (Inferred).
Notes: Silence [1] to [8], Inferred. watchTowr names no actor [11]. KEV [4]. AA23-325A [17].

## PART 4 | One CVE, then another

- Citrix updated its managed cloud services itself.
- The bulletin still has no exploitation note or session-kill step.
- watchTowr reported a further overread on 28 March.
- It became CVE-2026-8451, fixed in CTX696604 on 30 June.
- KEV has since listed four more exploited NetScaler flaws.
Caption: The current fixed build, not the March one, is the target (Inferred from version order).
Notes: Response [1]. Follow-on [12], Reported; fix [13]. KEV lineage [4].

## PART 4 | The KEV lineage since 2023

| Added | NetScaler ADC and Gateway entries |
|---|---|
| 2023 | CVE-2023-3519 and CitrixBleed, ransomware use Known |
| Jan 2024 | CVE-2023-6548 and CVE-2023-6549 |
| 2025 | CVE-2025-6543, CitrixBleed 2 (Known), CVE-2025-7775 |
| 30 Mar 2026 | CVE-2026-3055, ransomware use Unknown |
| Aug to Oct 2026 | CVE-2026-8452, CVE-2026-19490 and three zero-days |
Caption: The three zero-days of September and October have their own study.
Notes: KEV catalog 2026.11.10 [4]. CitrixBleed advisory [17].

## DEFENDER VIEW | A patch does not recall what leaked

Left: Scope and fix
- Find every appliance with a SAML IdP profile.
- Check both 14.1 fixed branches, not only 60.58.
- Move to the current fixed build in the latest bulletins.
- Restrict access to Gateway and AAA virtual servers.
Right: Preserve and evict
- Snapshot an internet-facing appliance before patching.
- After updating, end all active and persistent sessions.
- Treat a leaked session ID as reusable until ended.
- Patch internet-facing SAML IdP appliances first.
Notes: Inventory [1]. Builds [1][3][10][13]. Access, snapshot and sessions [8], CERT-EU guidance. Session reuse [11][17].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- Every NetScaler as exposed.
- "CitrixBleed" as a vendor or government label.
- A ransomware link the record does not show.
Right: Understated
- No session-kill step in the vendor bulletin.
- One CVE that covered at least two leak sites.
- A third leak that arrived under a new number.
Notes: Overstated [1][4][11][15]. Understated [1][8][11][13][17]. Readings Inferred.

## MITRE MAPPINGS | Four techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Honeypot exploitation; KEV listing |
| T1212 | Exploitation for Credential Access | Overread returns a session ID |
| T1539 | Steal Web Session Cookie | Session ID in leaked memory |
| T1550.004 | Web Session Cookie | Capability only; session-kill advice |
Caption: CWE-125 and CWE-362; CAPEC-540 and CAPEC-60; D3FEND pairings and the Navigator layer are in the study.
Notes: Techniques [4][6][8][11][17] with library data [19]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The same class keeps returning

- **Memory disclosure on the edge recurs.** CitrixBleed, CitrixBleed 2, then two in 2026.
- **The identity provider is a high-value target.** It fronts every app it signs users into.
- **Found internally and found by others.** Both can be true at once.
Notes: Class [4][12][13]. IdP [1]. Discovery [11][12][13]. Groupings Inferred.
