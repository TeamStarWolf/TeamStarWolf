# Slide plan: Iran-Attributed Threat Actors: The Public Record

- Study: case-studies/THREAT_ACTORS_IRAN.md
- Cover title: Iran-Attributed / Threat Actors / The Public Record
- Subtitle: Two services, their contractors and the personas they use, 2011 to 2026
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/THREAT_ACTORS_IRAN.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Two services and their contractors get in through ordinary doors

- Governments tie named clusters to MOIS and the IRGC, including its Cyber-Electronic Command, and name the fronts.
- Eight joint advisories, 2020 to 2024: patched edge flaws, password spraying, MFA fatigue and default-password controllers.
- 19 of the 20 advisory IT CVEs are in KEV, each flagged for known ransomware use.
- The purpose widened from espionage to access brokering to OT disruption, with wipers from 2012 to 2026 (Inferred).
- In March 2026 the MOIS-tied Handala persona claimed a wiper attack on Stryker (attribution Reported).
Caption: Grades: advisories, sanctions, FBI records and ATT&CK are Confirmed; 2026 DOJ, Treasury and Stryker press items are Reported.
Notes: Services and fronts [18][36][44][39][37][41]. Entry points [15][17][19][21][24][25]. KEV catalog 2026.11.03 [33]. Era reading Inferred from Part 2. Stryker: 8-K [59], Check Point [76], press [93][90].

## KEY FACTS | 21 ATT&CK groups, eight advisories and 260 techniques

Stat: 21 | ATT&CK groups attributed to Iran
Stat: 8 | joint advisories, 2020 to 2024
Stat: 19 of 20 | advisory IT CVEs in KEV
Stat: 260 | Enterprise techniques, plus 24 ICS
- Largest ATT&CK records: Magic Hound 78 techniques, OilRig 76, MuddyWater 68.
- Earliest dated record: the 2011 to 2013 DDoS campaign on US banks; Ajax Security Team from 2010.
- US legal action: indictments in 2016, 2018, 2019, 2022, 2024 and 2026.
- Latest: PLC tampering since March 2026 (AA26-097A); NIMBUS MANTICORE added to ATT&CK on 1 October 2026.
Notes: Groups: 19 Enterprise, CyberAv3ngers (ICS only) and UNC788 (Mobile only) [1]. Advisories AA20-259A, AA21-321A, AA22-055A, AA22-257A, AA22-320A, AA23-335A, AA24-241A, AA24-290A. KEV [33]. 260 techniques: 237 from groups, 23 only in advisories [1]. ICS: 24 across CyberAv3ngers, OilRig and APT33 [1]. Earliest [43][1]. Latest [29][5].

## PART 1 | ATT&CK names a service for only nine of the 21 groups

| Sponsor in ATT&CK | Groups |
|---|---|
| IRGC (four) | Magic Hound (likely), Silent Librarian, NIMBUS MANTICORE, CyberAv3ngers (suspected) |
| MOIS (five) | MuddyWater, APT39, VOID MANTICORE, Agrius (public reporting), POLONIUM (coordinating) |
| Iran, no service named (twelve) | OilRig, APT33, Fox Kitten, APT42, CURIUM, Leafminer, Moses Staff, CopyKittens, Ajax Security Team, Cleaver, Group5, UNC788 |
Caption: Vendors go further: Mandiant ties APT42 to the IRGC Intelligence Organization at moderate confidence.
Notes: ATT&CK v20.0 sponsor wording [1], live pages [2] to [12]. Mandiant [64], Check Point on Educated Manticore [77], Microsoft on EUROPIUM [60], Google TAG [74]. The library's Threat Actors page labels OilRig with MOIS and APT33 with the IRGC, which ATT&CK v20.0 does not do [14].

## PART 1 | Indictments and sanctions put names on the fronts and contractors

| Organization | Service | What the record says |
|---|---|---|
| ITSecTeam and Mersad | IRGC and government | Bank DDoS, 2011 to 2013; seven indicted |
| Mabna Institute | IRGC | Theft from about 144 US universities (2018 figures) |
| Rana Intelligence Computing | MOIS | APT39 front; designated with 45 people in 2020 |
| Emennet Pasargad | IRGC | 2020 voter intimidation; 2024 Olympics displays |
| Najee Technology, Afkar System Yazd | IRGC | Ransomware and BitLocker extortion |
| Danesh Novin Sahand | Government of Iran (FBI) | Cover company for Pioneer Kitten |
| IRGC Cyber-Electronic Command | IRGC | Six officials designated over PLC defacements |
Caption: None is an ATT&CK object; the Najee and Afkar link to Magic Hound runs through the APT35 alias (Inferred).
Notes: ITSecTeam and Mersad [43]. Mabna [44][34]. Rana [36]. Emennet Pasargad, designated in 2019 as Net Peygard [37][70][30]. Najee and Afkar [19][39]. Danesh Novin Sahand [24]. IRGC-CEC [40][51]; its fronts Mehrsam Andisheh Saz Nik and Dadeh Afzar Arman [41].

## PART 2 | Fifteen years of operations, from bank DDoS to PLC tampering

| Date | Event |
|---|---|
| 2011 to 2013 | DDoS campaign on the US financial sector |
| 2012 | Shamoon wiper first used, against a Saudi energy company |
| Mar 2018 | Nine Mabna Institute members indicted; Treasury sanctions |
| Sep 2020 | AA20-259A: Pulse Secure, Citrix and F5 exploitation |
| Jun 2021 | Children's hospital reached through a Fortigate appliance |
| Jul 2022 | Albania government attack; HomeLand Justice claims it |
| Nov 2023 | 75+ Unitronics PLCs compromised, 34 in US water |
| Aug 2024 | AA24-241A: Pioneer Kitten brokers access for ransomware |
| Mar 2026 | Stryker disruption; Handala claims a wiper (Reported) |
| Mar 2026 on | Rockwell, Schneider and Siemens PLC tampering |
Caption: Eras (Inferred): espionage and contractor theft to 2020, access brokering 2020 to 2024, then OT and wipers.
Notes: Rows [43][1][67][44][34][15][17][39][20][52][60][23][72][24][59][76][93][29]. ATT&CK records Shamoon's 2012 use by Cutting Sword of Justice; Unit 42 describes the target [1][67]. The PLC tampering is AA26-097A, revised 22 July 2026 [29].

## PART 2 | Personas deliver the destruction; governments name the service

Left: HomeLand Justice and Albania
- The attack began 15 July 2022: an encryptor, then the ZeroCleare wiper.
- Initial access came about 14 months earlier, through SharePoint CVE-2019-0604.
- The US, UK and Microsoft attribute it to Iranian state actors; Treasury names MOIS.
- The EU condemned it without naming Iran; Albania cut ties (Reported).
Right: Handala and Stryker
- 11 March 2026: Stryker reports a global disruption to its Microsoft environment.
- Its filing found no indication of ransomware or malware.
- Check Point ties Handala to Void Manticore; reporting says DOJ ties it to MOIS.
- Handala claimed 200,000+ devices wiped; TechCrunch reports tens of thousands.
Caption: A source told KrebsOnSecurity the attackers appear to have used Microsoft Intune's remote wipe (Reported).
Notes: Albania [20][13][52][53][60][38][54][94]. Stryker 8-K [59]; Check Point [76]; DOJ seizure warrant and reporting [49][90][91][92]; claims and press [93][91]. ATT&CK's VOID MANTICORE page names the Stryker attack [6].

## PART 3 | Commodity tools, a wiper lineage and remote access in plain sight

Stat: 111 | ATT&CK software entries across 19 groups
Stat: 8 | groups using Mimikatz
Stat: 7 | groups using PsExec
- Wiper line: Shamoon (2012), ZeroCleare (Albania, 2022), Agrius's MultiLayer Wiper and Apostle.
- Check Point: Scarred Manticore hands victims to Void Manticore for the destructive phase.
- AA24-241A names AnyDesk, MeshCentral, Ligolo and ngrok; MuddyWater uses ConnectWise and RemoteUtilities.
- Unit 42: state actors moved C2 to Starlink during the 2026 internet outage (high confidence).
Notes: Software counts [1]. Wipers [1][20][13]; Check Point on CI Wiper and the hand-off [75]. Remote access [24][21][1]. Starlink [68][4].

## PART 4 | 19 of 20 advisory CVEs are in KEV, all with known ransomware use

| Vendor | CVEs | Named in |
|---|---|---|
| Pulse Secure | CVE-2019-11510, CVE-2019-11539 | AA20-259A |
| Citrix | CVE-2019-19781, CVE-2023-3519 | AA20-259A, AA24-241A |
| F5 BIG-IP | CVE-2020-5902, CVE-2022-1388 | AA20-259A, AA24-241A |
| Fortinet FortiOS | CVE-2018-13379 and two more | AA21-321A, AA22-257A |
| Microsoft Exchange | ProxyShell (three), CVE-2020-0688 | AA21-321A, AA22-257A, AA22-055A |
| Apache Log4j | CVE-2021-44228, -45046, -45105 | AA22-257A, AA22-320A |
| Ivanti, PAN-OS, Check Point | CVE-2024-21887, -3400, -24919 | AA24-241A |
Caption: Netlogon CVE-2020-1472 completes the 20; CVE-2021-45105 is the one not in KEV.
Notes: Advisories [15][17][18][19][21][24]; KEV catalog 2026.11.03 [33]. Unitronics CVE-2023-6448 added 11 December 2023, ransomware use unknown; its link to CyberAv3ngers is Inferred [33]. Fastest case: Mandiant's APT34 used CVE-2017-11882 less than a week after the patch [62].

## PART 5 | Targets: watched people, strategic industry and anything exposed

| Theme | Sectors |
|---|---|
| People the state watches | Dissidents, journalists, academics, officials, campaigns, travel and telecom data |
| Strategic industry and research | Aviation, aerospace, defense, satellite, energy, pharmaceutical research, universities |
| Whatever is exposed | IT, government, municipalities, transport, police, education, finance, healthcare |
| Operational technology | Water, energy, government facilities, food and beverage, healthcare as a PLC user |
Caption: After 7 October 2023, 43 percent of the Iranian activity Microsoft tracked targeted Israel.
Notes: The grouping is Inferred; each listing is Confirmed [2][7][36][64][69][74][42][10][61][5][71][79][44][15][17][19][24][25][23][27][29][51]. Israel [72]. The US and Israel were about 60 percent of APT42's known targeting over six months in 2024 [74].

## PART 6 | Hospitals sit in the blast radius more than in the crosshairs

Left: Through shared infrastructure
- June 2021: a children's hospital's environmental controls, via a Fortigate appliance.
- Summer 2021: an attempt on Boston Children's thwarted after an FBI warning.
- US healthcare facilities among Pioneer Kitten's victims (AA24-241A).
- Healthcare among the AA24-290A brute-force and MFA push victims.
Right: Research and suppliers
- TA453 phished fewer than 25 senior medical researchers in December 2020.
- APT42 targeted pharmaceuticals at the onset of COVID-19.
- Pay2Key ransomware at a US healthcare organization, February 2026.
- Stryker 2026: prosecutors say Maryland hospitals and EMS were affected (Reported).
Caption: AA21-321A's authors assess the actors exploit known vulnerabilities rather than choose sectors.
Notes: Children's hospital [17][39]; Boston Children's [50][95]; neither primary says the two are the same event. Pioneer Kitten [24]; AA24-290A [25]. TA453 [79]; APT42 [64]; Pay2Key [80]; Stryker [59][90][93]. Israeli hospitals as Israel records them [57][58]. HC3 brief not opened [81].

## PART 7 | Courts and Treasury name people and fronts, yet the work goes on

| Date | Action | Target |
|---|---|---|
| 21 Jan 2016 | SDNY indictment | Seven ITSecTeam and Mersad staff |
| 23 Mar 2018 | Indictment and sanctions | Mabna Institute (IRGC) |
| 17 Sep 2020 | Treasury | APT39, Rana and 45 individuals (MOIS) |
| 9 Sep 2022 | Treasury | MOIS and its minister, over Albania |
| 14 Sep 2022 | Treasury with DOJ | Najee, Afkar and ten individuals |
| 2 Feb 2024 | Treasury | Six IRGC-CEC officials |
| 27 Sep 2024 | D.D.C. and Treasury | Jalili and others, campaign hack-and-leak |
| 18 Aug 2026 | Superseding indictment | 17 Mabna members (Reported) |
Caption: The UK and Microsoft also attributed Albania; Israel records hospital targeting as a party to the conflict.
Notes: Indictments and sanctions [43][44][34][36][38][39][47][40][41][48][42][89][87][88]; August 2026 sanctions [86]. Rewards up to 10 million dollars for Ahmadi and co-defendants and for CyberAv3ngers [47][51]. UK, EU and Israel [52][53][54][57][58].

## MITRE MAPPINGS | 260 techniques, led by tools, PowerShell and LSASS theft

| Id | Technique | Groups | Advisories |
|---|---|---|---|
| T1588.002 | Obtain Capabilities: Tool | 14 | 4 |
| T1059.001 | PowerShell | 11 | 5 |
| T1105 | Ingress Tool Transfer | 10 | 4 |
| T1003.001 | LSASS Memory | 10 | 3 |
| T1053.005 | Scheduled Task | 8 | 5 |
| T1190 | Exploit Public-Facing Application | 7 | 5 |
Caption: Layer score is groups plus advisories naming a technique (maximum 18); the ICS layer holds 24. MITRE notice in notes.
Notes: 260 techniques: 237 from the groups, 23 only in the advisories, 96 in both. Tactic tally Stealth 38, Credential Access 33, Persistence 31 [1]. ICS: CyberAv3ngers 17, OilRig 6, APT33 3 [1]. Revoked T1574.002, T1562.001 and T1562.010 are shown as T1574.001, T1685 and T1689 [1]. D3FEND gaps: D3-MFA maps neither T1621 nor T1133, and T1059.001 has no mapping [1]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patch the edge, then hunt, and treat identity noise as intrusion

Left: Harden
- Patch KEV-listed edge devices first; rebuild compromised NetScaler devices.
- Phishing-resistant MFA; review help-desk resets; disable RC4 for Kerberos.
- Take PLCs and building systems off the internet and off default passwords.
- Back up BitLocker recovery keys offline, and PLC logic too.
Right: Watch
- Password spraying, impossible travel and MFA push floods.
- New MFA devices, new domain admins and new scheduled tasks.
- AnyDesk, MeshCentral, Ligolo and ngrok where none should be.
- Bulk wipe or reset actions in device-management consoles.
Caption: AA24-241A: patching alone may not be enough on a vulnerable device; AA22-320A: assume compromise.
Notes: Hardening [18][15][21][25][23][27][19]. Hunting [25][21][24][15]. Device-management consoles, Inferred from [59][93]. Hospitals: inventory internet-facing HVAC, water, life-safety and building systems (AHA, Reported) [82].

## CROSS-CUTTING THEMES | Personas speak to an audience, and old flaws keep working

- **Attribution has layers.** Carry the layer and the confidence, not just the name.
- **Contractors blur state and crime.** The FBI judges Pioneer Kitten's ransomware side work likely not sanctioned.
- **Personas are a delivery mechanism.** Device counts and victim lists stay claims until confirmed.
- **Legal action has not stopped the work.** Indictments and sanctions sit beside activity through 2026.
- **Understated: PLC tampering and console abuse.** Changed ladder logic, disabled alarms, a fleet wiped by its console.
Notes: Layers [64][18][36]. Contractors [24][19][45]. Personas [20][75][76][23][70][24]. Legal action, Inferred from the timeline [87][88]. Old flaws [33][23]. PLC tampering [40][23][29]; console abuse [59][93]. Overstated: persona device counts and the hospital cases read as a hospital campaign [93][91][17].
