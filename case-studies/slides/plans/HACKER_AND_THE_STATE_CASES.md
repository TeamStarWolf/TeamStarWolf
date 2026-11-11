# Slide plan: Cyber Operations as Statecraft: The Cases in The Hacker and the State

- Study: case-studies/HACKER_AND_THE_STATE_CASES.md
- Cover title: Cyber Operations as Statecraft / The Cases in / The Hacker and the State
- Subtitle: Espionage, attack, destabilization and theft, read against indictments, advisories and vendor reports
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/HACKER_AND_THE_STATE_CASES.md. The book itself was not opened; its frame is known from the author's interview [48] and reviews [49][50][51], graded Reported. Facts from complaints and indictments are allegations not tested at trial. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | States hacked to shape, and the victims did the signaling

- **The book's frame** (Reported): states hack less to send messages than to shift power, daily, in peacetime.
- **Espionage at scale:** OPM lost 21.5 million background investigations; APT1 hit 141 organizations.
- **One set of operators,** per an FBI affidavit: Sony in 2014, Bangladesh Bank in 2016, WannaCry in 2017.
- **The GRU** is charged with the 2016 DNC theft and the 2017 French campaign operation.
- **Where the story runs ahead:** Belgacom rests on journalism, and Shamoon has no ATT&CK group.
Caption: Grades: intrusions, dates and government responses Confirmed; the book's thesis and Belgacom Reported.
Notes: Executive summary. OPM [2][3]; APT1 [5]; Park Jin Hyok complaint [12][14]; GRU indictments [28][32]. Belgacom [9][10], Reported; Shamoon in ATT&CK [21]. The defenders-signaled reading [7][16][44] is the study's inference.

## KEY FACTS | 21.5 million records, $81 million and at least 80 NHS trusts

Stat: 21.5M | background investigations taken from OPM
Stat: 356 days | APT1's average access; the longest 1,764
Stat: ~$81M | lost by Bangladesh Bank, of nearly $1 billion tried
Stat: 80 of 236 | NHS trusts hit by WannaCry, 12 May 2017
- First state actors charged for hacking: five PLA Unit 61398 officers, indicted 1 May 2014.
- OPM also lost personnel files of 4.2 million people and fingerprints of 5.6 million.
- 72 ATT&CK v20.0 Enterprise techniques and six groups in the study's layer.
Notes: OPM totals [2]. APT1 dwell [5]. Bangladesh Bank [14]; BAE put the attempt at $951 million [35]. WannaCry and the NHS [14]. PLA indictment [7]. Groups G0006, G0007, G0016, G0032, G0034 and G0082 [52][53].

## PART 1 | The book says hacking shapes well and signals badly

Left: The frame (Reported)
- Shaping, not signaling: changing the balance of power.
- Hacking needs secrecy, so it makes a poor signal.
- Three categories: espionage, attack, destabilization.
- The contest is near-continuous, not kept for war.
Right: How the record tests it
- Shaping fits: OPM, APT1 and the SWIFT thefts.
- The clear signals came from the victim states.
- A 2014 indictment, 2015 sanctions, a 2017 coalition.
- Critics: Parker and a 2025 review by Lorci.
Caption: Two reviews name three of the book's cases: Sony, the 2016 election and the Shadow Brokers leak.
Notes: Part 1. The Diplomat interview [48]; Uren's review [49]; Parker's review [50]; Lorci's abstract [51], all Reported. The test of the frame against the record [7][12][16][44] is the study's reading, Inferred.

## PART 2 | OPM's intruder was inside for nearly three years before notice

| Date | Event |
|---|---|
| Jul 2012 | First known adversarial access, dated from malware found in 2015 |
| 20 Mar 2014 | US-CERT tells OPM a third party reported exfiltration |
| Jun 2014 | Remote desktop session to background-investigation servers |
| Jul to Aug 2014 | Background-investigation files taken |
| Dec 2014 | Personnel records taken through the Interior data center |
| ~26 Mar 2015 | Fingerprint data taken |
| 4 Jun and 9 Jul 2015 | Public notices |
Caption: A contractor's credential, then domain admin; only 1 percent of OPM accounts required PIV cards at the end of FY2014.
Notes: House Oversight report [1][2] and its timeline [3], Confirmed. OPM watched "Hacker X1" for about two months in 2014 [2]. The opmsecurity.org domain was reported to US-CERT on 15 April 2015 [3]. Pages i to vii name no attributed actor, so no ATT&CK group is linked to OPM.

## PART 2 | APT1 ran a state espionage program on public credential tools

- **141 organizations in 20 industries since 2006;** Mandiant assessed PLA Unit 61398 in February 2013.
- **Entry by spear phishing** with attached or linked ZIP files; WEBC2 backdoors read commands from web pages.
- **Credential tools:** cachedump, fgdump, gsecdump, mimikatz, pwdump7 and a pass-the-hash kit.
- **Scale:** up to 6.5 TB from one organization in ten months; HTRAN seen relaying 767 times.
- **1 May 2014:** five Unit 61398 officers indicted on 31 counts, the first such charges against state actors.
Caption: On 25 September 2015 the US and China committed not to conduct or knowingly support cyber-enabled trade secret theft.
Notes: Mandiant APT1 report [5], Confirmed as Mandiant's observation and assessment. FBI on the indictment [7], Confirmed; linking the officers to APT1 runs through the unit number, Inferred. White House fact sheet [6], Confirmed.

## PART 2 | Belgacom rests on leaked documents; Regin on vendor analysis

Left: Belgacom (Reported)
- "Operation Socialist", per The Intercept.
- Quantum Insert sent three engineers to a fake LinkedIn page.
- Targets: roaming hub, GPRS links, VPN tunnels.
- Malware found in June 2013; no charges expected.
Right: Regin (Confirmed for Regin)
- Kaspersky, 24 November 2014.
- Stages in NTFS attributes or the registry.
- ICMP, HTTP and SMB pipe command channels.
- Internal relay drones; a 2008 GSM log of 136 cells.
Caption: Also in Part 2: the 2013 Section 215 and 702 disclosures, and NIST's removal of Dual_EC_DRBG on 21 April 2014.
Notes: The Intercept [9] and the 2018 Belgian findings [10], Reported. Kaspersky's Regin analysis [11], Confirmed for Regin; tying its techniques to Belgacom rests on [9]. PCLOB Section 702 report [4] and NIST [8], Confirmed; the NSA link to Dual_EC is not checked.

## PART 3 | Sony was phished in September and wiped in November 2014

| Date | Step |
|---|---|
| 22 Sep 2014 | A North Korean IP address scans an SPE web server |
| 25 Sep 2014 | Spear-phishing link from "Nathan Gonsalez" reaches an SPE user |
| 24 Nov 2014 | "Hacked By #GOP"; the wiper overwrites the MFT and MBR |
| 19 Dec 2014 | The FBI and the President attribute the attack to North Korea |
| 2 Jan 2015 | Treasury designates the RGB, KOMID, KOTC and ten officials |
| 8 Jun 2018 | Complaint against Park Jin Hyok signed |
Caption: Initial access is the affiant's assessment; TA14-353A describes the toolkit without naming Sony.
Notes: Park Jin Hyok complaint, paras 63 to 121 [14], Confirmed. FBI statement [12]; the President [15]; Treasury [16], Confirmed. TA14-353A [13]; reading it as Sony's toolkit is Inferred. Lazarus Group G0032 is reportedly responsible, per ATT&CK [22]; RawDisk is S0364 [52].

## PART 3 | Shamoon and Sony shared a wiper recipe, not an attribution

Left: Shamoon, 2012 and 2016
- 30,000+ systems at a Saudi energy company (Reported).
- An EldoS-signed raw-disk driver wipes the MBR.
- Shamoon 2 was set to wipe at 20:45 on 17 November 2016.
- Stolen admin credentials hard-coded in advance.
Right: The common recipe
- Raw-disk drivers overwrite the MBR.
- Systems stopped or rebooted.
- Spread over Windows admin shares.
- ATT&CK lists no group for Shamoon.
Caption: Stuxnet, the Ukrainian grid and NotPetya appear in summary only; their home studies carry the record.
Notes: Kaspersky 2012 [18]; Unit 42 on Shamoon 2 [19], with the 30,000 figure from its recap, Reported; Kaspersky 2017 on StoneDrill and false flags [20]; ATT&CK S0140 [21]. Sony's driver and wiper [13][14]. Ukraine and NotPetya [27][28][29][45].

## PART 4 | The GRU phished, leaked, and then did it again in France

Left: The 2016 US election
- 19 March: a spoofed Google notice; 50,000+ e-mails taken.
- X-Agent on ten or more DCCC computers.
- DNC entered 18 April with DCCC credentials.
- A Linux X-Agent survived to about October.
- 22 July: more than 20,000 e-mails released.
Right: The 2017 French campaign
- 3 April to 3 May: seven phishing campaigns.
- More than 100 members of Macron's movement targeted.
- A fake press-secretary account mailed about 30 staff.
- Leaks on 3 and 5 May are not attributed to them.
- Six Unit 74455 officers indicted, 15 October 2020.
Caption: The 2018 indictment does not allege the conduct changed the vote count or the outcome.
Notes: Indictment of twelve GRU officers [31][32]; JAR-16-20296A on APT29 from summer 2015 and APT28 from spring 2016 [46]; APT28 G0007 [24]. French campaign in the 2020 indictment [28] and the Andrienko notice [42]. All Confirmed as the charging documents state them.

## PART 5 | Forged SWIFT messages cost Bangladesh Bank $81 million

- **7 to 8 October 2014:** reconnaissance of Bangladeshi banks begins.
- **From 29 January 2015:** resume-themed phishing likely gives initial access.
- **29 January 2016:** the intruders reach the SWIFTLIVE system by lateral movement.
- **February 2016:** forged SWIFT messages to the New York Fed; about $81 million lost, $20 million stopped.
- **Hiding it:** a tool patched two bytes of liboradb.dll and altered printed confirmations, per BAE.
Caption: ATT&CK credits APT38 (G0082) with the heist; DYEPACK has no ATT&CK software id.
Notes: Park Jin Hyok complaint [14], Confirmed. BAE Systems, "Two bytes to $951m", 25 April 2016 [35], Confirmed as BAE's analysis. APT38 page [23] and the library's v20.0 data [52].

## PART 5 | WannaCry struck 59 days after its patch, then came attribution

| Date | Event |
|---|---|
| 14 Mar 2017 | MS17-010 fixes the SMBv1 flaws |
| 15 Apr 2017 | The Shadow Brokers release an exploit for CVE-2017-0144 |
| 12 May 2017 | WannaCry begins spreading |
| 14 May 2017 | Microsoft says the exploits came from tools stolen from the NSA |
| 19 Dec 2017 | The UK, the US and four partners attribute WannaCry to North Korea |
Caption: The US briefing did not confirm the NSA source; that provenance rests on Microsoft's statement.
Notes: MS17-010 [36]; release and spread [14][37][38]; Microsoft [43]; attribution [39][44], Confirmed. The full leak and outbreak record lives in the Zero-Day Trade study; WannaCry's government record in the North Korea study. KEV added CVE-2017-0144 on 10 February 2022 [41].

## PART 7 | Attribution moved from vendors to governments to courts

| Operation | Who said so | When | Instrument |
|---|---|---|---|
| APT1 | Mandiant | Feb 2013 | Vendor report |
| Unit 61398 | US grand jury | May 2014 | Indictment of five officers |
| Sony Pictures | FBI; the President | Dec 2014 | Public attribution |
| WannaCry | UK, US and partners | Dec 2017 | Coalition attribution |
| NotPetya | White House | Feb 2018 | Public attribution |
| 2016 election | US grand jury | Jul 2018 | Indictment of twelve officers |
| Shamoon; Belgacom | No government among sources | 2012 to 2024; 2014, 2018 | Vendor text; press |
Caption: Attribution came in weeks for Sony, months for WannaCry and years for quiet espionage (Inferred).
Notes: Part 7 table [5][7][9][10][12][15][20][21][29][31][32][39][44]. The three patterns, faster attribution for public impact, charges as the main instrument from 2018 and unacknowledged operations known only through leaks, are the study's reading, Inferred.

## MITRE MAPPINGS | 72 techniques, and the same few carry every category

| Id | Technique | Cases |
|---|---|---|
| T1566.002 | Spearphishing Link | APT1, Sony, APT29, Bangladesh Bank |
| T1078.002 | Domain Accounts | OPM, Shamoon 2 |
| T1021.002 | SMB/Windows Admin Shares | Sony, Shamoon 2, Regin |
| T1543.003 | Windows Service | Sony, Shamoon 2, Bangladesh Bank, WannaCry |
| T1561.002 | Disk Structure Wipe | Sony, Shamoon |
| T1565.001 | Stored Data Manipulation | Bangladesh Bank |
| T1685.005 | Clear Windows Event Logs | DNC, 13 May 2016 |
Caption: Layer scores: 100 primary record, 60 ATT&CK record only, 40 Reported, 30 Inferred.
Notes: Part 9, ATT&CK v20.0; revoked T1070.001 maps to T1685.005 [52]. Groups G0006, G0007, G0016, G0032, G0034, G0082; software including S0019, S0140, S0364, S0366, S0368; campaigns C0025 and C0028 [52][53]. CAPEC-163, CAPEC-561, CAPEC-644; D3FEND from the library's data. Not an official MITRE mapping. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The advice of 2014 still reads like the advice of 2022

Left: What the advisories asked
- Offline, tested backups.
- Least privilege; limit credential caching.
- Segment and isolate critical networks.
- MFA for privileged and remote access.
- Patch MS17-010; disable SMBv1.
Right: Lessons by case
- OPM: MFA for every privileged account.
- OPM: review contractor access too.
- DNC: remediation is not removal.
- Bangladesh: isolate payment systems.
- WannaCry: do not wait for KEV.
Caption: AA22-057A, written for the 2022 wipers, closely matches the advice of TA14-353A in 2014 (Inferred).
Notes: Advisories [13][38][45][47]; AA22-057A does not mention NotPetya [47]. Lessons by case [2][14][32][35][36][41]. The match between the 2014 and 2022 advice is the study's observation, Inferred. Library corrections in Part 8.3: the Regin proxy mapping, Shamoon's group links and a book cross-reference, with the Aurora line flagged for a primary check.

## CROSS-CUTTING THEMES | Shaping is quiet and long; the failures were ordinary

- **Shaping is quiet and long:** nearly three years at OPM, 356 days on average for APT1.
- **Signals came from the defenders:** indictments, sanctions and coalition attributions.
- **The same few techniques** carried espionage, attack, destabilization and theft.
- **Destruction became statecraft:** Sony, the Ukrainian grid, NotPetya and WannaCry.
- **Overstated:** some attributions. **Understated:** missing MFA, an unpatched flaw, a surviving implant.
Notes: Cross-cutting themes [2][3][5][7][12][14][16][21][27][28][29][32][36][44][48]. All five are the study's reading, graded Inferred. Shamoon fits the destruction pattern but no government source opened attributes it [20][21].
