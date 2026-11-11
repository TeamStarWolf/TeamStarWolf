# Slide plan: The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record

- Study: case-studies/CHANGE_HEALTHCARE_2024.md
- Cover title: The Change Healthcare / Attack of 2024 / The Largest Healthcare Breach on Record
- Subtitle: A password, no second factor, and a national claims and payments outage
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHANGE_HEALTHCARE_2024.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One password on a portal without MFA stopped U.S. claims

- Change Healthcare, a claims and payments clearinghouse owned by UnitedHealth Group, was encrypted by ransomware on the morning of 21 February 2024.
- The way in was a 12 February login with compromised credentials to a Citrix portal that did not require a second factor.
- Pharmacists could not run insurance claims, and practices stopped receiving the payments they lived on.
- UHG paid a $22 million ransom; a second group, RansomHub, still posted Change data in April.
- About 192.7 million people were affected, the largest entry on the HHS breach portal.
Caption: Grades: UHG filings, testimony, court and agency records are Confirmed; the payment trail and the affiliate story are Reported.
Notes: Encryption and ownership [14][17]. Entry [14][17]. Pharmacy and practice effects [60][55][58]. Ransom [17]; second extortion Reported [64][65][67], screenshots Confirmed [6]. Count [20][22].

## KEY FACTS | Nine days inside, $22 million paid, 192.7 million people

Stat: 192.7M | people affected, the largest HHS portal entry
Stat: 9 days | from the 12 Feb login to ransomware on 21 Feb
Stat: $22M | ransom UHG paid in Bitcoin
Stat: ~$3.07B | 2024 response and disruption costs
- Exfiltration window: 17 to 20 February 2024; no CVE, because the record describes stolen credentials, not a software flaw.
- Claimed by an actor calling itself ALPHV or BlackCat; ATT&CK records it as software S1068 with no group object.
- Next-largest portal entries: Anthem, 78.8 million in 2015, and Conduent, 62.2 million in 2025.
Notes: Count, OCR notice of 31 July 2025 [20][22]. Dwell [14][17]. Ransom [17]. $2.2 billion plus $867 million [11]; the sum is this study's arithmetic. Exfiltration [17][19]. No CVE, Confirmed [14][17], Inferred that none applies. ALPHV [14][28]; S1068 [30][33]. Rank [22].

## PART 1 | An ordinary entry, and backups inside the blast radius

Left: A password and no second factor
- 12 Feb 2024: criminals used compromised credentials on a Citrix remote-desktop portal.
- Witty: "The portal did not have multi-factor authentication."
- UHG policy required MFA; the legacy Change server had not been brought up to it.
- Nebraska alleges the credentials were posted in a Telegram group about 11 Feb.
Right: Why recovery took so long
- The attack reached both the primary and the backup environments.
- Witty called the locked-up backups, built before the acquisition, the root cause.
- Services came back from pre-incident backups into newly built environments.
- About 11,000 clean devices were reissued, most within two weeks.
Caption: The record names no exploit, malware build, lateral movement method, exfiltration channel or affiliate.
Notes: Entry [14][17]. Policy and legacy server [17]. Telegram posting, Confirmed as an allegation [46]. Backups and root cause [17]; Nebraska alleges no isolation or segmentation [46]. Rebuild: credential rotation, two-vendor scanning and testing before reconnection [14][17]. Gaps Inferred from [14][17][18][46].

## PART 2 | Nine quiet days came before the loud one

| Date (2024) | Event |
|---|---|
| About 11 Feb | Support employee's Citrix credentials allegedly posted in a Telegram group |
| 12 Feb | Login to the Citrix portal with compromised credentials; no MFA |
| 12 to 21 Feb | Lateral movement; privileged accounts allegedly created on the SelectRX server |
| 17 to 20 Feb | Exfiltration of protected health information |
| 21 Feb | Ransomware deployed; connectivity severed; FBI contacted within hours |
| 22 Feb | Form 8-K names a "suspected nation-state associated" actor |
| 7 Mar | E-prescribing working; 99 percent of pharmacy network services restored |
Caption: Encryption on 21 February was the point at which the attack was actually detected.
Notes: Telegram allegation and SelectRX accounts [46]. Login [14][17]. Lateral movement [14]. Exfiltration [17][19]. 21 February [14][17][60]. 8-K [1]. Pharmacy restoration [3][4][5]. Detection point [17].

## PART 3 | The first filing said nation-state; the record says cybercrime

- 22 February: "suspected nation-state associated" actor; 8 March: "cybercrime threat actors", and the wording never returned.
- Later statements describe self-identification: the actor "represented itself to us as ALPHV/Blackcat".
- AA23-353A: after the December 2023 disruption an ALPHV administrator urged affiliates to target hospitals.
- Not supported: China (unvalidated claim), Scattered Spider (structural link only) or a state hand behind ALPHV in this case.
Caption: This study found no public FBI or CISA statement attributing the Change attack specifically; the search was not exhaustive.
Notes: Filings [1][2]; later 10-Q and 10-K [9][11]. Status page [28]; Witty [15]; House memo "has been reported" [18]. AA23-353A, update of 27 February 2024 [23]. China, Reported [73]. Scattered Spider [25][26][27], Inferred. Rewards for Justice framing [29], Inferred.

## PART 4 | Paying $22 million did not buy the data back

| Date (2024) | Event | Grade |
|---|---|---|
| 1 Mar | 350 BTC, about $22 million, reaches an ALPHV-linked address | Reported |
| 3 Mar | Affiliate "notchy" says ALPHV kept the payment and the affiliate kept the data | Reported |
| 5 Mar | ALPHV shuts down behind a seizure banner researchers judge fake | Reported |
| 7 to 8 Apr | RansomHub lists Change, claims 4 TB and sets a sale deadline | Reported |
| 22 Apr | UHG: an unnamed actor posted 22 screenshots for about a week | Confirmed |
Caption: The House committee staff could not confirm whether UHG paid RansomHub; UHG has not said it did.
Notes: UHG answer to Senator Warren: "UHG paid the demanded $22 million ransom in Bitcoin" [17]. Transfer [65][64]; Nebraska alleges payment about 3 March [46]. notchy and the exit [64][62]. RansomHub [61][67][68]. Screenshots [6][7]. House staff [18]. Volumes are actors' claims: ALPHV about 6 TB, affiliate and RansomHub about 4 TB [63][64][67].

## PART 5 | A clearinghouse outage became a cash crisis for care

Stat: 94% | of AHA-surveyed hospitals reported a financial hit
Stat: 74% | reported an effect on direct patient care
Stat: 55% | of AMA practices used personal funds for expenses
Stat: 31% | of AMA practices could not make payroll
- Change carries about 6 percent of all U.S. health care payments by UHG's count; roughly 15 billion transactions a year by the Senate Finance chairman's.
- Two-thirds of surveyed hospitals found switching clearinghouses difficult or very difficult.
- Military pharmacies fell back to manual checks until full operations returned on 25 April.
Notes: AHA survey of nearly 1,000 hospitals, 9 to 12 March 2024 [55][56]. AMA survey of more than 1,400 practices, 26 March to 3 April 2024 [58]. 6 percent [6]; 15 billion is the senator's figure [17]. Switching [56]. Defense Health Agency [60].

## PART 5 | Pharmacy came back first; full volume took months

| Function | Restored |
|---|---|
| Pharmacy claims and e-prescribing | 7 Mar 2024; 99 percent of pharmacies processing |
| Electronic payments platform | Open for connection from 15 Mar 2024 |
| Medical claims network | Testing and reconnection from 18 Mar 2024 |
| Payment processing volume | About 86 percent of pre-incident levels, 22 Apr 2024 |
| Military pharmacies (TRICARE) | Full operations announced 25 Apr 2024 |
Caption: Relief: UHG advanced more than $9 billion; CMS paid more than $2.55 billion to Part A providers and $717.18 million to Part B suppliers.
Notes: Restoration [3][4][5][6][7][17][60]. "Restored the majority" by the Q2 2024 10-Q [9][11]. UHG funding through 30 June 2024 [8][9][10][11]. CHOPD payments by 17 June 2024 [51][53]; about $3.27 billion together is this study's sum.

## PART 6 | The count grew from 500 to 192.7 million over a year

| Date | Figure |
|---|---|
| 19 Jul 2024 | 500 individuals, a placeholder report to OCR |
| 22 Oct 2024 | About 100 million individual notices sent |
| 6 Jan 2025 | HIPAA proposal cites an earlier estimate of about 112 million |
| 24 Jan 2025 | About 130 million notices; about 190 million affected |
| 31 Jul 2025 | About 192.7 million affected |
| 3 Nov 2026 | Portal row: 192,700,000; no later revision |
Caption: Cite the date with the number: early figures in policy documents are superseded.
Notes: Count history [20][69][37][11][21][22][12]. Data types: contact, insurance, health, billing, Social Security, driver's license and passport numbers [19]. No known misuse per the FY2024 10-K [11]. The Change row is about two-thirds of the 290.1 million in 2024 reports [22]; the share is Inferred.

## PART 7 | The cost outran the incident year

Stat: $2.2B | direct response costs, 2024
Stat: $867M | Optum Insight business disruption, 2024
Stat: >$9B | in provider loans and accelerated funding
Stat: $799M | reserve increase, fourth quarter of 2025
- $9,033 million lent in 2024; $6,476 million repaid through 30 September 2026 by this study's sum.
- Suspended care management added $340 million to first-quarter 2024 medical costs.
- The Q3 2026 10-Q shows $282 million repaid in nine months and no new cyberattack cost line.
Notes: FY2024 10-K [11]. Funding [11][12]. Reserve [12]. Lent and repaid [11][12][13]; the sum is Inferred, and the difference is not a reported balance. Q1 medical costs [8]. Q3 2026 [13]. The Notable Incidents range of $872 million to $2.7 billion is superseded [11].

## PART 8 | Proposals and lawsuits followed; final rules did not

Left: Regulation and Congress
- The January 2025 HIPAA Security Rule proposal cites this breach.
- It would require MFA, segmentation and 72-hour restoration procedures.
- No final rule; the agenda now targets July 2027.
- S.3315 passed the Senate on 30 Sep 2026 and is held at the House desk.
Right: The courts
- MDL No. 3108 centralized in the District of Minnesota on 7 Jun 2024.
- Dec 2025: motions to dismiss granted in part and denied in part.
- Nebraska's suit survived a motion to dismiss on 10 Nov 2025.
- No settlement or class certification shown as of October 2026.
Caption: OCR opened investigations of Change Healthcare and UHG; the portal now lists the case in its archive, not under investigation.
Notes: HIPAA proposal, RIN 0945-AA22, 90 FR 898 [37]; agenda [38][39]; AHA asked for withdrawal [40]. S.5218 and S.5390 died in committee [42][43]; S.3315 [44]. MDL [48][49][50]. Nebraska [45][46][47]. OCR [20][57]; archive placement [22], what it means is Inferred.

## PART 9 | Which attack? Conduent and DentaQuest lead the later years

| Year | Largest entry | Individuals | What happened |
|---|---|---|---|
| 2024 | Change Healthcare | 192,700,000 | This study |
| 2024 | Kaiser Foundation Health Plan | 13,400,000 | Third-party tracking technologies, not a hack |
| 2025 | Conduent Business Services | 62,224,658 | Intrusion on 13 Jan 2025; client files exfiltrated |
| 2025 | Aflac | 13,924,906 | Network access found 12 Jun 2025; no ransomware |
| 2026 | DentaQuest | 15,000,000 | One employee tricked into credentials and an MFA code |
| 2026 | Aesto | 9,540,683 | Access to AWS infrastructure in Dec 2025 |
Caption: If it stopped pharmacies and claims nationwide for weeks, it is Change; later cases are mostly vendor data theft by social engineering.
Notes: HHS OCR breach portal export of 3 November 2026 [22]. Conduent [74]. Aflac [75]. DentaQuest [79]. Aesto [80]. Year totals: 2024, 741 reports and 290.1 million; 2025, 810 and 141.2 million; 2026 to 3 November, 618 and 87.7 million [22]. The pattern is Inferred from [22][74][79][81][83].

## MITRE MAPPINGS | Five techniques: the testimony names steps, not methods

| Id | Technique | Where it appears in the record |
|---|---|---|
| T1078 | Valid Accounts | Compromised credentials used to log in, 12 Feb 2024 |
| T1133 | External Remote Services | Citrix remote-desktop portal without MFA |
| T1136 | Create Account | Privileged accounts on the SelectRX server (an allegation) |
| T1486 | Data Encrypted for Impact | Ransomware deployed and systems encrypted, 21 Feb 2024 |
| T1657 | Financial Theft | The $22 million ransom paid in Bitcoin |
Caption: Lateral movement and exfiltration have no stated method, so no technique is bound. MITRE notice in the notes.
Notes: Rows [14][17][46]. Software S1068 BlackCat and S1212 RansomHub; no group or campaign object for ALPHV or the attack [30][31][33]. CAPEC-560 and CAPEC-555; CWE-308 Inferred [33][14]. Mitigations M1032, M1030, M1026, M1053 [33]. Navigator layer: 30 techniques, scores 100, 75 and 40. D3FEND Multi-factor Authentication is not mapped to T1078 or T1133 in the library data [33]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Close the single-factor doors and watch the quiet days

Left: Before the encryption
- Find every internet-facing remote-access service and require phishing-resistant MFA.
- Bring an acquired company's estate into the inventory on day one.
- Alert on new privileged accounts outside change control.
- Baseline egress volume and internal remote sessions.
Right: For the recovery
- Keep backups on separate credentials and networks.
- Rebuild into clean environments; do not clean in place.
- Keep a tested second clearinghouse or payments path.
- Assume a ransom payment does not end data exposure.
Caption: There is no CVE in this story: a CVE-driven scanning program would not surface a single-factor portal.
Notes: AA23-353A phishing-resistant MFA and detection guidance [23]. HICP practices [34]. HPH goals [35][36]. Acquisition point Inferred from [17]. Accounts [46]. Backups [17][37][46]. Rebuild [17]. Second path [17][56]. Extortion planning Inferred from [6][17][67]. Vulnerability-management view [14][17][35][37].

## CROSS-CUTTING THEMES | The perimeter was a policy, not a fact

- **Measure controls where they apply.** MFA was required on paper and missing on the one server that mattered.
- **Mergers inherit attack surface.** The server came with the late-2022 acquisition and was still in transition 14 to 16 months later.
- **Concentration turns one breach into a national outage.** Exclusivity clauses made switching hard for two-thirds of surveyed hospitals.
- **Ransomware as a service splits the actor in two.** The operator took the money and the affiliate kept the data.
- **Counts are moving targets.** 500 became 192.7 million over a year of filings.
Notes: Policy and MFA [17]. Mergers [17]; the month count is Inferred. Concentration [17][56]. RaaS split Reported [64][67]. Counts [20]. Overstated: a nation-state attack, 6 TB stolen, Scattered Spider [1][2][63][25]. Understated: the providers' cash crisis, the long tail and the backups [58][53][11][12][50][17].
