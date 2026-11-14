# Slide plan: The Year 2015 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2015.md
- Cover title: The Year 2015 / in Intrusions / A Dated Record
- Subtitle: OPM, Anthem, implants below the operating system and the first grid blackout
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2015.md, told from the House Oversight timeline on OPM, Anthem's SEC filings and the FBI's wanted notice, ICS-CERT's alert on the Ukrainian blackout, US-CERT alerts in CISA's archive, CERT/CC vulnerability notes, NVD and KEV records, Microsoft, Oracle and Google bulletins, Kaspersky's, FireEye's, Mandiant's, Unit 42's and Citizen Lab's reports, the privacy commissioners' Ashley Madison report and the ICO's TalkTalk account, FBI, DOJ, SEC and court records, and US, UN, EU, IETF and NIST records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year the intrusion became a public number

- **OPM:** 4.2 million personnel records, then more than 20 million background records.
- **Anthem:** data on about 78.8 million persons, as a 2019 indictment charges.
- **Ukraine:** about 225,000 customers lost power on 23 December.
- **Below the OS:** disk firmware, UEFI, router images and firewall code.
- **Instruments:** sanctions, an information-sharing law and a US-China commitment.
Caption: Grades: vendor, government and court records Confirmed; Carbanak's USD 1 billion Reported.
Notes: OPM [26]. Anthem [1][3]. Ukraine [78][79]. Below the operating system [8][102][62][63][75]. Instruments [5][18][105][66]. Carbanak's estimate [10].

## KEY FACTS | Four numbers from the primary record

Stat: 48 | CVE-2015 entries in CISA's KEV catalog today
Stat: 20M+ | people in OPM's background records
Stat: 225,000 | Ukrainian customers without power
Stat: 96 | techniques in ATT&CK's first public release
- Four of the 48 KEV entries are flagged for known ransomware use.
- IC3 counted 288,012 complaints and about USD 1.07 billion in losses.
- No 2015 record carries an ATT&CK id; every binding is later.
Notes: KEV [99]. OPM [26]. Ukraine [78]. ATT&CK public in May 2015 [126]. IC3 [82].

## PART 1 | The year in date order, from sanctions to a blackout

| Date | Event |
|---|---|
| 2 Jan | Sanctions on North Korea over Sony |
| 16 Feb | Kaspersky names the Equation group |
| 17 Feb | Carbanak announced |
| 24 Feb | Anthem's 10-K describes the attack |
| 14 Apr | MS15-034 fixes HTTP.sys |
| 4 Jun | OPM: 4.2 million personnel records |
| 5 Jul | Hacking Team's trove published |
| 9 Jul | OPM: more than 20 million people |
| 18 Aug | Ashley Madison data published |
| 25 Sep | US-China commitment on IP theft |
| 17 Dec | Unauthorized code in ScreenOS |
| 23 Dec | Ukrainian power cut |
Notes: Sanctions [5]. Equation [8]. Carbanak [10]. Anthem [1]. MS15-034 [30]. OPM [26]. Hacking Team [42], graded Reported. Ashley Madison [46]. US-China [66]. ScreenOS [75]. Ukraine [78].

## PART 2 | The state record was named years later

| Date | Event | Grade |
|---|---|---|
| 8 Apr | TV5Monde's 12 channels off air | Reported |
| Apr and May | Bundestag attacked; data stolen | Confirmed |
| 4 Jun, 9 Jul | OPM's two public notices | Confirmed |
| Summer | APT29 in a US political party | Confirmed |
| 9 Sep | Kaspersky's Satellite Turla | Confirmed (vendor's finding) |
| 23 Dec | Three Ukrainian distributors cut | Confirmed |
Notes: Part 2. TV5Monde [21], with the GRU attribution in the UK profile and France's 2025 statement [22][23]. Bundestag [22]. OPM [26], which names no actor. APT29 [56][24][57]. Turla [83]. Ukraine [78]; the alert named Russian actors only in its 2021 update, and the indictment came in 2020 [81]. Homes: The Hacker and the State, Fancy Bear Goes Phishing and Sandworm Operations [135].

## PART 3 | The branded bugs were not the exploited bugs

Left: The branded bugs
- GHOST, Jan.
- FREAK, Mar.
- VENOM, May.
- Logjam, May.
- Stagefright, Jul.
- None in KEV.
Right: Exploited at the time
- Win32k, Apr.
- Flash pair, Jul.
- IE CVE-2015-2502, Aug.
- 48 KEV entries.
- Four ransomware flags.
Caption: Juniper's ScreenOS CVE-2015-7755 entered KEV only on 2 October 2025.
Notes: Part 3. GHOST [6][7]. FREAK [14][13]. VENOM [35]. Logjam [37][36]. Stagefright [52][53]. Win32k CVE-2015-1701 [31]. Flash CVE-2015-5119 and CVE-2015-5122 [43][44]. MS15-093 [98]. KEV [99].

## PART 4 | Implants moved below the operating system

- **Disk firmware:** Equation could reprogram drives of over a dozen brands.
- **System firmware:** ATT&CK's Hacking Team UEFI Rootkit cites July 2015.
- **Router images:** malicious ROMMON images on Cisco IOS, 12 Aug.
- **Router implant:** SYNful Knock in four countries, 15 Sep.
- **Firewall code:** unauthorized code in Juniper ScreenOS, 17 Dec.
- **Developer tools:** XcodeGhost rode Xcode into the App Store.
Caption: How the ScreenOS code entered is not established in any record the study opened.
Notes: Part 4. Disk firmware [8][9]. UEFI [102]. ROMMON [62]. SYNful Knock [63][64]. ScreenOS [75][76]. XcodeGhost [65].

## PART 5 | Crime was charged and botnets were taken down

| Date | Event | Grade |
|---|---|---|
| 17 Feb | Carbanak: up to 100 institutions | Confirmed |
| 15 Apr | Simda: more than 770,000 computers | Confirmed |
| 29 May | Ulbricht sentenced to life | Confirmed |
| 15 Jul | Darkode forum taken down | Confirmed |
| 11 Aug | SEC charges 32 in newswire scheme | Confirmed (as charged) |
| 13 Oct | TA15-286A on Dridex | Confirmed |
| 3 Dec | Dorkbot disrupted | Confirmed |
Notes: Part 5. Carbanak [10], its USD 1 billion Reported. Simda [25]. Ulbricht [93]. Darkode [94]. Newswire scheme [61]. Dridex [67]. Dorkbot [74].

## PART 5 | The breaches were counted in millions

| Date | Event | Grade |
|---|---|---|
| Feb | Anthem: about 78.8 million persons | Confirmed (as charged) |
| 26 May | IRS: about 100,000 accounts | Confirmed |
| 9 Jul | OPM: more than 20 million people | Confirmed |
| 18 and 20 Aug | Ashley Madison: about 36 million accounts | Confirmed |
| 15 to 21 Oct | TalkTalk: 156,959 customers | Confirmed |
| Nov | VTech: about 2.25 million parents | Reported |
Notes: Parts 2 and 5. Anthem [3][1]. IRS [110]. OPM [26]. Ashley Madison [46]. TalkTalk [69]. VTech [111], not reopened on 13 November 2026.

## PART 6 | Cars and phones were reached remotely

Left: The Jeep
- Remote control shown.
- Recall of 1,416,903.
- Carrier closed the port.
- USB software remedy.
Right: Stagefright
- Reached by a message.
- Android 2.2 onward.
- Carriers set the pace.
- Not in KEV.
Caption: Wired's account of the Jeep demonstration is graded Reported; NHTSA's recall is Confirmed.
Notes: Part 6. Jeep [49][50][48]. Stagefright [52][51][53].

## PART 7 | Governments answered with instruments

| Date | Event | Grade |
|---|---|---|
| 2 Jan | Sanctions order on North Korea | Confirmed |
| 13 Feb | Executive Order 13691 | Confirmed |
| 1 Apr | Executive Order 13694 | Confirmed |
| 12 Jun | Federal Cybersecurity Sprint | Confirmed |
| 22 Jul | UN GGE report A/70/174 | Confirmed |
| 24 Aug | Third Circuit, FTC v. Wyndham | Confirmed |
| 6 Oct | CJEU invalidates Safe Harbour | Confirmed |
| 18 Dec | Cybersecurity Act of 2015 | Confirmed |
Notes: Part 7. Sanctions [5]. EO 13691 [19][20]. EO 13694 [17][18]. Sprint [113]. UN GGE [109]. Wyndham [108]. Schrems [107]. Cybersecurity Act [105]. The US-China commitment of 25 September is on the Part 1 slide [66].

## PART 7 | The defender's toolkit became institutional

- **ATT&CK:** released publicly in May with 96 techniques.
- **TLS:** RFC 7465, 7525 and 7568 retired RC4, SSLv2 and SSLv3.
- **Certificates:** Let's Encrypt issued its first certificate on 14 September.
- **Logging:** PowerShell v5 added script block logging.
- **NIST:** SP 800-161, SP 800-82 Rev. 2 and SP 800-171.
Caption: CWE 2.9 and CAPEC 2.7 and 2.8 were the year's MITRE catalog releases.
Notes: Part 7. ATT&CK [126]. TLS [121][122][123]. Let's Encrypt [124][125]. PowerShell [119]. NIST [114][115][116]. CWE and CAPEC [129][130].

## CROSS-CUTTING THEMES | What the year's record shows

- **Scale:** the data thefts ran to tens of millions of people.
- **Remote access:** VPN and stolen credentials carried the worst intrusions.
- **Below the OS:** firmware, router images and firewall code in one year.
- **Late names:** attributions arrived in 2016, 2020, 2021 and 2025.
- **Email money:** IC3's BEC losses dwarfed its ransomware losses.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Scale [26][3][46]. Remote access [78][46][26]. Below the OS [8][102][62][63][75]. Late names [56][81][78][23]. Email money [82].

## MITRE MAPPINGS | 57 Enterprise and 20 ICS techniques, all later mappings

| Id | Technique | 2015 use |
|---|---|---|
| T1133 | External Remote Services | Ukraine, Ashley Madison |
| T1078 | Valid Accounts | Ukraine, OPM |
| T1566.001 | Spearphishing Attachment | Carbanak, Dridex |
| T1542.002 | Component Firmware | Equation |
| T1601.001 | Patch System Image | SYNful Knock |
| T1561.002 | Disk Structure Wipe | KillDisk |
| T0831 | Manipulation of Control (ICS) | Ukraine |
Caption: ATT&CK v20.0 ids; 45 Enterprise techniques are listed by ATT&CK for an object tied to 2015.
Notes: Part 9. Rows [79][78][46][26][10][67][9][8][64][63][131]. Basis scores in the layers: 100 Listed, 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2015 lessons still apply

Left: What 2015 taught
- MFA on every VPN.
- Plan for the wiper.
- Verify firmware images.
- Vendor code is a path.
Right: What still applies
- Patch Java middleware.
- Retire export crypto.
- Turn on script logging.
- Unique admin passwords.
Notes: Top recommendations and Part 8. MFA [78][46]. Wiper [78]. Firmware [8][62][63]. Vendor code [75][65]. Middleware [72][69]. Cryptography [13][37][122][123]. Logging [119]. LAPS [120].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Branded protocol bugs.
- Carbanak's USD 1 billion.
- The first TV5Monde claim.
- IC3 totals as crime.
Right: Understated
- The ordinary exploited bugs.
- The KEV long tail.
- Router and firmware implants.
- Business email compromise.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [14][36][7][35][53][30][37][10][21][22][23][82]. Understated [99][31][101][62][63][75][133][82]. Cross-cutting themes and the overstated and understated passage.
