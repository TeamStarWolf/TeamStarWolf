# Slide plan: The FireEye Mandiant Intrusion of 2020: The Public Record

- Study: case-studies/MANDIANT_INTRUSION_2020.md
- Cover title: The FireEye Mandiant / Intrusion of 2020 / The Public Record
- Subtitle: A second phone, stolen red team tools, and the first public thread of SUNBURST
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/MANDIANT_INTRUSION_2020.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An identity alert caught a state operator inside a security firm

- Late November 2020: an employee's account registered a second phone for two-factor codes.
- 8 December 2020: FireEye disclosed the attack and the theft of Red Team tools.
- The tools held no zero-days, and FireEye shipped free countermeasures the same day.
- Decompiling its own Orion server, FireEye found SUNBURST and told SolarWinds on 12 December.
- The US named Russia's SVR in April 2021; Mandiant merged UNC2452 into APT29 in 2022.
Caption: Evidence grade: Confirmed from filings, testimony and advisories; Demonstrated for repository counts.
Notes: Detection [11]. Disclosure [1][2][3]. No zero-days [1][3]. Countermeasures [4]. SUNBURST [11][13][15]. Attribution [26][31].

## KEY FACTS | A limited theft with a fast defensive answer

Stat: 0 | Zero-day exploits in the stolen tools
Stat: 16 | CVEs FireEye ranked for patching, all now in KEV
Stat: 324 | Rules in the final countermeasures table
Stat: 100+ | Staff on the investigation around the clock
- No attacker use of the tools seen by FireEye through 23 February 2021.
- No exfiltration seen from FireEye's primary customer-data systems.
- No material effect on Q4 or fiscal 2020 revenue, per the 10-K.
Notes: Zero-days [1][3][10]. CVEs [8][9]. Rules [6]. Staff [11]. Use [11]. Customer data [1]. Financial [25].

## PART 1 | Caught through the identity plane

- The first signal: a second phone enrolled for an employee's two-factor codes.
- The employee had not registered a new device.
- Senator Blunt called the extra verifier the tip-off, and Mandia agreed.
- The attackers went for credentials and tokens first, then bypassed two-factor authentication.
- They moved into Office 365 to target email and documents.
Caption: Mandia called FireEye a "stage two" victim, entered through the SolarWinds implant.
Notes: Alert [11]. Hearing [12]. Stage two [12][13]. Access path [25].

## PART 1 | What the attacker sought, and what was not seen taken

Left: Sought or taken
- Certain Red Team assessment tools.
- Information on certain government customers.
- Access to some internal systems.
Right: Not seen taken
- Incident-response customer data.
- Consulting customer data.
- Product threat-intelligence metadata.
Caption: The tools were the visible loss; the 8-K's stated objective was government-customer information (Inferred).
Notes: Form 8-K Item 8.01 [1]. 10-K access path through trojanized Orion updates [25].

## PART 2 | Three weeks from alert to SUNBURST

| Date | Event |
|---|---|
| Late Nov 2020 | Second-phone alert |
| 3 Dec 2020 | Countermeasures repository created |
| 8 Dec 2020 | 8-K, two blog posts, 311 rules, CVE list |
| 12 Dec 2020 | FireEye tells SolarWinds |
| 13 Dec 2020 | SUNBURST report; ED 21-01 |
| 5 Jan 2021 | US: "likely Russian in origin" |
| 15 Apr 2021 | US names the SVR; sanctions |
Caption: The repository existed five days before the disclosure (Demonstrated from its metadata).
Notes: Alert [11]. Repository [4][5]. Disclosure [1][2][3][8]. SolarWinds notice [11][13]. SUNBURST [15][21]. Joint statement [22]. April 2021 [26][27].

## PART 3 | The tools were mostly public, and the rules shipped on day one

- The kit ranged from reconnaissance scripts to frameworks like Cobalt Strike and Metasploit.
- Many tools were already public, some through CommandoVM; some were lightly modified.
- Rules came in Yara, Snort, ClamAV and HXIOC formats, labelled Production or Supplemental.
- Malwarebytes and IBM QRadar put the content into products within two days.
- No FireEye statement itemizes which tools were taken.
Caption: Rule families such as BEACON, RUBEUS and IMPACKETOBF show what FireEye wanted to detect, not what left the building.
Notes: Tools [3]. Formats [3][4]. Downstream use [55][56]. Families [6][7]; the reading is Inferred.

## PART 3 | Four counts, four different sets

| Point in the record | Count |
|---|---|
| 8-K, 8 Dec 2020 | More than 300 |
| Blog, 8 Dec 2020 | Hundreds |
| First table, 8 Dec 2020 | 311 rules, 60 families |
| Final table, 30 Dec 2020 | 324 rules, 61 families |
| Testimony, 23 Feb 2021 | More than 500 |
Caption: The 500 figure most likely also counts the SUNBURST rules and later updates (Inferred).
Notes: Counts [1][3][5][6][11]. SUNBURST rules [16].

## PART 4 | The victim became the first responder

- Out of other leads, FireEye decompiled one of its own SolarWinds servers.
- Over 18,000 files, 3,500 of them executables, yielded the implant.
- FireEye told SolarWinds on 12 December and published SUNBURST on 13 December.
- With GoDaddy and Microsoft it triggered a kill switch that disabled the backdoor.
- The kill switch did not remove intruders already inside networks.
Caption: The Orion build compromise and campaign C0024 have their home in the SolarWinds and SUNBURST study.
Notes: Decompilation [11][13]. Notice [11][13]. Publication [15]. Kill switch [11][17].

## PART 5 | Attribution was a ladder, not a jump

| Date | Who | Words used |
|---|---|---|
| 8 Dec 2020 | FireEye | Top-tier nation; no country |
| 5 Jan 2021 | FBI, CISA, ODNI, NSA | Likely Russian in origin |
| 15 Apr 2021 | White House | SVR, high confidence |
| 15 Apr 2021 | UK NCSC | SVR highly likely |
| 27 Apr 2022 | Mandiant | UNC2452 merged into APT29 |
Caption: Each phrase is a different claim made months apart; this deck keeps each source's words.
Notes: Ladder [1][22][26][29][31]. C0024 records the April 2021 attribution [32].

## PART 6 | The company changed shape, but not because of the breach

- 29 May 2021: FireEye agreed to sell its products business for $1.2 billion.
- 4 October 2021: FireEye, Inc. became Mandiant, Inc.; the sale closed on 8 October.
- 7 March 2022: Google agreed to acquire Mandiant; the merger closed 12 September 2022.
- The merger proxy dates the divestment idea to 2019.
- No opened filing ties the split to the intrusion.
Caption: Reading the sale as fallout of the breach is not supported by the opened record (Inferred).
Notes: Sale [48]. Rename and close [49][50]. Google [52][53]. Proxy [51]. 10-K [25].

## PART 8 | Patching sixteen known CVEs was the main mitigation

- Every CVE on FireEye's list had a vendor fix before 8 December 2020.
- Fifteen entered KEV on its first day; CVE-2018-8581 followed in March 2022.
- KEV marks known ransomware use for 11 of the 16.
- The top three: Pulse Secure, Netlogon and FortiOS SSL VPN.
- Three of the 16 also appear in the April 2021 SVR advisory.
Caption: FireEye's list is what its stolen tools could exploit; the SVR advisory is what the actor was seen exploiting.
Notes: List [8]. KEV [9]. NVD [54]. SVR advisory [28]. The comparison is Inferred.

## DEFENDER VIEW | Guard the identity plane as tier zero

Left: Detect
- New MFA devices on existing accounts.
- New or changed domain federation.
- Credentials added to service principals.
- Access to the AD FS key container.
Right: Recover
- Rotate token-signing certificates with care.
- Reset krbtgt twice.
- Audit service-principal credentials.
- Give every active account an MFA device.
Caption: Device registration, app credentials and federation changes recur in the same actor's record through 2024.
Notes: Detections [23][24][37]. Recovery [41]. MFA [45]. Recurrence [32][45][46][47].

## MITRE MAPPINGS | Identity techniques carried the campaign

| Id | Technique | Where it appears |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | Orion updates (10-K) |
| T1098.005 | Device Registration | Second-phone alert (Inferred) |
| T1606.002 | SAML Tokens | Campaign-level forgery |
| T1552.004 | Private Keys | AD FS signing key theft |
| T1098.001 | Additional Cloud Credentials | OAuth apps and principals |
| T1484.002 | Trust Modification | Added identity provider |
Caption: ATT&CK v20.0; 41 Enterprise techniques in the layer. G0016 APT29, campaign C0024, S0559 SUNBURST, S0560 TEARDROP.
Notes: Techniques [11][15][20][23][25][32][36][37][46]. Objects [32][33][67][68]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Security vendors hold trust material

- **Vendors are targets.** RSA, Bit9, Kaspersky and FireEye each disclosed a breach.
- **Trust material matters.** SecurID data, a signing key and token-signing certificates.
- **Tooling is mostly public.** The main fix was patching known CVEs.
- **Identity is the perimeter.** It caught the intrusion and carried the campaign.
- **Disclosure can ship defenses.** Same-day filing, blog and free rules.
Notes: Vendors [61][64][66][1]. Trust material [61][65][23]. Tooling [3][8]. Identity [11][23][36]. Disclosure [1][3][4]. The lessons are Inferred.
