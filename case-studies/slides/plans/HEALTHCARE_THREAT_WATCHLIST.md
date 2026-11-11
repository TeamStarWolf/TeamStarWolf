# Slide plan: Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says

- Study: case-studies/HEALTHCARE_THREAT_WATCHLIST.md
- Cover title: Healthcare Threat / Actor Watchlist / 2023 to 2026
- Subtitle: Who hits hospitals, how they get in, and what the record says
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/HEALTHCARE_THREAT_WATCHLIST.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Hospitals became a stated target, and identity is the front door

- **Four hard years:** 745, 741, 810 and 618 HHS breach reports of 500 or more people, 2023 to 9 October 2026.
- **Chosen, not just hit:** after December 2023 an ALPHV administrator urged affiliates to target hospitals.
- **The way in is rarely new malware:** phished credentials, VPNs without MFA, help-desk calls and edge devices.
- **State and crime overlap:** North Korea's Andariel funds espionage with ransomware against US healthcare.
- **Regulation trails:** the HHS goals are voluntary and the HIPAA Security Rule update slipped to July 2027.
Caption: Grades: counts, advisories and filings Confirmed; survey figures relayed by a vendor Reported; patterns Inferred.
Notes: Breach counts derived from the HHS OCR portal exports [1]. ALPHV advisory update of 27 February 2024 [13]. Initial access pattern across the advisories [14][18][20][22], the pattern Inferred. Andariel [24][31]. HPH goals [50]; Unified Agenda [56].

## KEY FACTS | One vendor breach can carry two thirds of a year

Stat: 192.7M | individuals in the Change Healthcare entry, 2024
Stat: 11 | healthcare-relevant joint advisories bound here
Stat: 130 | ATT&CK v20 techniques those advisories name
Stat: 61 of 76 | advisory CVEs in the KEV catalog
- About 702 million individual records across the four years, summed per report, so one person can count twice.
- Change Healthcare is about 66% of 2024; Conduent about 44% of 2025; DentaQuest about 17% of 2026.
- The FBI logged 238 ransomware and 206 data breach complaints from the sector in 2024.
Notes: HHS portal exports, per-year sums and shares are the study's arithmetic [1]. Advisories [13] to [20][23] to [25]. Technique count from Part 6. KEV join at catalog 2026.11.03, the 76 CVEs include the Play advisory [82]. FBI IC3 2024 [37].

## PART 1 | The yearly totals turn on one or two vendor entries

| Year | Reports (500+) | Individuals | Largest entry |
|---|---|---|---|
| 2023 | 745 | 183,256,225 | Welltok 14,782,887 |
| 2024 | 741 | 290,052,596 | Change Healthcare 192,700,000 |
| 2025 | 810 | 141,248,514 | Conduent 62,224,658 |
| 2026 to 9 Oct | 618 | 87,693,355 | DentaQuest 15,000,000 |
Caption: Counts are this study's derivation from the HHS exports, as of 3 November 2026; OCR updates entries over time.
Notes: All rows from the HHS OCR breach portal Under Investigation and Archive CSV exports, bucketed by submission year [1]. Conduent is the current OCR figure on 3 November 2026 [1][10]; DentaQuest [1][11]. The same person can be counted more than once (Inferred).

## PART 1 | Provider outages stop care; vendor breaches carry the counts

Left: Provider outages
- Kettering Health cancelled elective procedures and diverted emergency patients for about a week.
- Synnovis lost almost all its IT systems; pathology was disrupted.
- Ascension reported a ransomware attack: 5,466,931 people.
- DaVita: certain network elements encrypted; patient care continued.
Right: Vendor breaches
- Conduent, a back-office business associate: 62,224,658 people.
- Aesto 9.5 million and Episource 6.7 million.
- Lumexa Imaging: 5.8 million, taken from a vendor's system.
- TriZetto and CareCloud above 3 million each.
Caption: Of the provider notices opened, only Kettering Health names its attacker (Interlock).
Notes: Kettering [6][7][84]. Synnovis [4]. Ascension [3][1]. DaVita 8-K [8][1]. Vendor counts [1][9][10][12]. The two-kinds reading is Inferred from Confirmed entries. Victims rarely name the group [3][4][5][8].

## PART 1 | Advisories, outages and charges, from 2023 to 2026

| Date | Event |
|---|---|
| 14 Jun 2023 | LockBit advisory: about 1,700 US attacks since 2020 |
| 19 Dec 2023 | ALPHV advisory; February update says hospitals were targeted |
| Feb 2024 | Change Healthcare, the largest HHS entry on record |
| 7 May 2024 | NCA names LockBitSupp as Dmitry Khoroshev |
| 3 Jun 2024 | Synnovis ransomware disrupts London pathology |
| 24 Jul 2024 | Federal warrant for Rim Jong Hyok of Andariel |
| 30 Jan 2025 | CISA finds a backdoor in Contec CMS8000 monitors |
| 20 May 2025 | Kettering Health system-wide outage begins |
| 22 Jul 2025 | Interlock advisory, with HPH guidance appended |
Notes: LockBit [19]. ALPHV [13]. Change [1][34][69]. NCA [33]. Synnovis [4]. Rim Jong Hyok [31][32]. Contec [38][39]. Kettering [84][6][7]. Interlock [17]. Medusa's 2026-08-18 update added HHS as co-sealer [16].

## PART 2 | Twenty-one names on the list, and the brands keep changing

| Actor | Model | Healthcare evidence |
|---|---|---|
| ALPHV / BlackCat | RaaS since Nov 2021 | Most victimized sector after the call to target hospitals |
| LockBit | RaaS since Jan 2020 | Over 100 hospitals and healthcare companies, per the NCA |
| Black Basta | RaaS since Apr 2022 | Advisory calls healthcare an attractive target |
| RansomHub | RaaS since Feb 2024 | HPH among at least 210 victims |
| Medusa | Affiliates by early 2023 | HPH a frequent victim; over 500 victims |
| Akira | Since Mar 2023 | HPH among preferred sectors |
| Interlock | Double extortion | Kettering Health names it |
| Rhysida | RaaS since May 2023 | Healthcare among targets of opportunity |
Caption: Rhysida, Interlock, BlackSuit, Maui and others have no ATT&CK object in the library's v20.0 data.
Notes: Rows [13][40][19][33][14][42][15][41][16][46][20][17][6][18]. The full list adds Qilin, Royal/BlackSuit, Play, INC Ransom, Storm-0501, Phobos, Ghost, Scattered Spider, CL0P, Andariel, Moonstone Sleet, Pioneer Kitten and Orangeworm [21][26] to [29][35][43] to [49]. Objects missing from ATT&CK [83].

## PART 2 | North Korea funds spying with hospital ransom; Iran sells access

Left: North Korea
- Maui ransomware against HPH since at least May 2021.
- It encrypted servers for health records, diagnostics and imaging.
- Andariel of the RGB 3rd Bureau funds espionage this way.
- Rim Jong Hyok: Kansas warrant, reward up to $10 million.
- Moonstone Sleet has deployed Qilin.
Right: Iran
- Pioneer Kitten is associated with the Iranian government.
- The FBI judges its ransomware side likely not sanctioned.
- It partnered with ALPHV, NoEscape and RansomHouse affiliates.
- US healthcare facilities were among its victims.
- Entry through PAN-OS, BIG-IP, NetScaler, Ivanti and Check Point.
Notes: Maui advisory [23]. Andariel advisory of 25 July 2024 [24]. Warrant and Rewards for Justice [31][32]. Moonstone Sleet and Qilin [43]. Pioneer Kitten advisory AA24-241A [25]. Orangeworm is the espionage baseline since 2015 [49].

## PART 3 | The help desk and the password-only VPN are the front door

- **VPNs without MFA** are a stated way in for Rhysida, Akira, Daixin Team and Microsoft's hospital cases.
- **ALPHV affiliates and Scattered Spider** call the help desk posing as IT to reset passwords and move MFA.
- **Black Basta's November 2024 update** added Teams calls after email bombing.
- **Microsoft found phishing** behind 93% of malicious activity in its review of 13 hospital systems.
- **Interlock is the newcomer:** drive-by downloads and fake CAPTCHA pages (ClickFix, T1204.004).
Notes: VPN without MFA [18][20][30][36]. Help desk [13][22]. Black Basta [14]. Microsoft's own figure [36]. Interlock [17]. That initial access converges on identity and edge exploitation is Inferred.

## PART 3 | Edge devices, remote tools and the hypervisor are the side doors

Stat: 24 h | Medusa often exploits new flaws within a day of disclosure
Stat: 61 of 76 | advisory CVEs in KEV, mostly edge and remote access
Stat: $244.17M | about this much claimed by Akira by late September 2025
- Black Basta exploited ScreenConnect CVE-2024-1709 in February 2024, the month it was disclosed.
- ScreenConnect, AnyDesk, Quick Assist and Splashtop are abused to hold access.
- ALPHV, Akira and DragonForce encrypt VMware, ESXi and Nutanix AHV hosts.
Notes: Medusa [16]. KEV join [82], the edge reading Inferred. Akira [20]. Black Basta [14]. Remote tools [13][14]. Hypervisor [13][20][22]; that one encrypted host takes down every clinical system on it is Inferred.

## PART 3 | Extortion no longer needs encryption, and devices leak data

- **Double extortion is the norm:** eight advisory groups steal before they encrypt.
- **Data alone:** some ALPHV affiliates and Scattered Spider extort without deploying ransomware.
- **A second demand:** a separate actor told one Medusa victim the negotiator stole the payment.
- **Publication:** Synnovis data posted 20 June 2024; DentaQuest data posted online.
- **Contec CMS8000:** CISA found a backdoor in all three firmware versions; the FDA says unplug the network.
Notes: Double extortion [14] to [21]. Without encryption [13][22]. Medusa [16]. Publication [4][11][34]. Contec CVE-2025-0626 and CVE-2025-0683 [38]; FDA [39]. None of the initial access routes in Part 3.1 is a medical device (Inferred).

## PART 4 | The HIPAA Security Rule update has slipped to July 2027

| Date | Step |
|---|---|
| Dec 2023 | HHS concept paper promises a Security Rule update |
| 27 Dec 2024 | OCR issues the notice of proposed rulemaking |
| 6 Jan 2025 | Published at 90 FR 898 |
| 7 Mar 2025 | Comments close; 4,747 counted |
| Spring 2025 | Unified Agenda: final action May 2026 |
| Agenda 202510 | Moved to Long-Term Actions, final action July 2027 |
- The proposal would require MFA, encryption, asset inventories and 72-hour restoration plans.
Caption: The HPH goals stay voluntary; none of the four healthcare cyber bills opened was found enacted.
Notes: Concept paper as HHS states it [54]. NPRM [53]. Agenda [55][56]. Proposal contents [54]. That no final rule existed by 3 November 2026 is Inferred from the agenda stage. HPH goals [50]. Bills S.5218, S.5390, S.3315, S.1851 [77] to [81]; later actions on the 2025 bills not checked.

## PART 4 | OCR keeps finding the same missing risk analysis

| Date | Entity | What happened | Outcome |
|---|---|---|---|
| 20 Feb 2025 | Warby Parker | Credential stuffing, 197,986 people | $1,500,000 penalty |
| 30 May 2025 | Comstar | Ransomware, 585,621 people | $75,000 |
| 29 Jul 2026 | OSF HealthCare | Nephilim ransomware, 53,907 patients | $552,250 |
| 17 Sep 2026 | Ambry Genetics | Phishing, 225,370 people | $700,000 |
| 9 Oct 2026 | Lehigh Valley Health Network | Ransomware in acquired Delta Medix | $800,000 |
Caption: 44 attorneys general settled with Labcorp in September 2026, with vendor risk management terms.
Notes: OCR resolution agreements [63][64][65][66][67][68]. The common finding is Inferred from the cases opened. Labcorp settlement over the 2019 AMCA breach [76]. Inmediata, 33 attorneys general, $1.4M [75]. New York 10 NYCRR 405.46 [72]. Nebraska v. Change [73][74].

## MITRE MAPPINGS | Encryption for impact leads 130 advisory techniques

| Id | Technique | Advisories (of 11) |
|---|---|---|
| T1486 | Data Encrypted for Impact | 8 |
| T1059.001 | PowerShell | 7 |
| T1190 | Exploit Public-Facing Application | 7 |
| T1219 | Remote Access Tools | 7 |
| T1021.001 | Remote Desktop Protocol | 6 |
| T1685 | Disable or Modify Tools | 6 |
| T1078 | Valid Accounts | 5 |
| T1490 | Inhibit System Recovery | 5 |
Caption: ATT&CK v20.0; 12 groups and 15 software objects; 95 of the 130 fall inside their ATT&CK mappings.
Notes: Counts are this study's, Part 6.2 and 5.6, from each advisory's own mapping table [13] to [20][23] to [25][83]. Revoked ids mapped through superseded_by.jsonl, e.g. T1562.001 to T1685 [83]. Comparison with the objects' mappings: 213 techniques, 95 overlap, rerun 4 November 2026 (Inferred). Navigator layer: 130 techniques, scores 1 to 8. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Phishing-resistant MFA and a verified help desk come first

Left: What to do first
- Put phishing-resistant MFA on every remote path.
- Make the help desk verify callers out of band.
- Patch internet-facing KEV entries in days, not monthly.
- Allowlist remote access software.
- Keep offline, immutable, tested backups; guard hypervisors.
Right: What the record warns
- Patching an exploited edge device does not evict an intruder.
- Business associates carry the largest counts; hold them to the bar.
- Segment medical devices; run the CMS8000 unplugged.
- Use the HPH Cybersecurity Performance Goals as the baseline.
- Map coverage from advisory tables; ATT&CK objects miss many.
Notes: Recommendations [13][16][18][20][22][23][25][30][36][39][50][76][82][83]; the help-desk control and the patch tempo are Inferred from the advisories. Rhysida logging kept 180 days [18]; LockBit Credential Guard and LAPS [19]. HPH Mitigation Guide scan figures [61].

## CROSS-CUTTING THEMES | Names change faster than methods, and disclosure trails

- **Healthcare is chosen:** the ALPHV call and Andariel's funding model show deliberate selection.
- **The record runs through intermediaries:** access brokers, affiliates and business associates.
- **Names change faster than methods:** Royal became BlackSuit, Knight became RansomHub.
- **Disclosure lags:** Change Healthcare's count took more than a year to settle.
- **Overstated:** breach totals as a threat gauge, and devices or states as the main way in.
Notes: Selection [13][24][33], Inferred. Intermediaries [16][25][1]. Rebrands [21][15][35][48]. Disclosure [69][4]. Overstated and understated, Part 5.8 [1][36][38][39][24][43]. The baseline stays voluntary [50][54][56][77] to [81].
