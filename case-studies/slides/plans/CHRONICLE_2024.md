# Slide plan: The Year 2024 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2024.md
- Cover title: The Year 2024 / in Intrusions / A Dated Record
- Subtitle: Two doors, the edge and the missing second factor, and one long shadow
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2024.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The edge and the missing second factor opened 2024

- **The edge kept falling:** Ivanti, PAN-OS, Cisco ASA, FortiManager and ScreenConnect were exploited at or before disclosure.
- **A password with no MFA:** Microsoft's legacy test account, the Snowflake customer accounts and Akira's VPN entries.
- **The long shadow:** Volt Typhoon held footholds of at least five years; telecom companies were compromised.
- **Ransomware was hit hard:** Operation Cronos took LockBit's administration environment and leak site.
- **The worst outage was self-inflicted:** a faulty security update, not an attack.
Caption: Grades: agencies, victims, vendors, CVE, NVD and KEV records Confirmed; vendor estimates Reported; data checks Demonstrated.
Notes: Edge [2][32][91][69][20]. MFA [132][42][36]; the pattern is the study's reading (Inferred). Volt Typhoon [13]; telecom [75]. Cronos [93][16]. Outage [50][51][52].

## KEY FACTS | 186 KEV additions, 8.5 million devices, two emergency directives

Stat: 186 | KEV entries added in 2024, 44 ransomware-flagged
Stat: 8.5M | Windows devices crashed by the 19 July update
Stat: 5+ yrs | Volt Typhoon footholds in some US networks
Stat: -35% | ransomware payments, Chainalysis estimate
- Emergency directives: ED 24-01 on Ivanti (19 Jan) and ED 24-02 on Microsoft corporate email (11 Apr).
- Policy landmarks: CSF 2.0, EO 14117, the CIRCIA proposed rule, FIPS 203 to 205, NIS2 and the UN cybercrime convention.
- MITRE binding: 68 Enterprise technique rows, 47 objects with library pages, one Navigator layer.
Notes: KEV counts computed from catalog version 2026.11.10; the ransomware flag is current, not as listed [3]. Outage, Microsoft's estimate [52]. Volt Typhoon [13]. Chainalysis, about US$813.55 million (Reported [99]). Directives [4][10]. Policy [126][123][124][127][129][131]. MITRE counts from Part 13 of the study.

## PART 1 | The year in date order, from Ivanti to the UN convention

| Date | Event |
|---|---|
| 19 Jan | ED 24-01 on Ivanti Connect Secure |
| 7 Feb | AA24-038A on Volt Typhoon pre-positioning |
| 20 Feb | Operation Cronos against LockBit |
| 21 Feb | Change Healthcare systems isolated |
| 29 Mar | Backdoored xz 5.6.0 and 5.6.1 reported |
| 11 Apr | ED 24-02 on Microsoft corporate email |
| 10 Jun | Mandiant on UNC5537 and Snowflake customers |
| 19 Jul | The CrowdStrike content update outage |
| 13 Nov | FBI and CISA on the telecom campaign |
| 24 Dec | UN adopts the Convention against Cybercrime |
Notes: Ivanti [4][102]. Volt Typhoon [13]. Cronos [93][16][17]. Change Healthcare, home study [21][22]. XZ Utils, home study [29][30]. ED 24-02 [10]. UNC5537 [42]. Outage [50][51]. Telecom [75]. UN [131].

## PART 2 | The edge appliances fell, and their own checks missed it

Left: The appliances
- Ivanti: zero-days from December 2023, chained with a SAML SSRF.
- PAN-OS: test exploitation from 26 March, a zero-day on 10 April.
- Cisco ASA: ArcaneDoor's Line Runner and Line Dancer backdoors.
- FortiManager: exploited from 27 June, disclosed 23 October.
Right: What AA24-060B found
- Ivanti's integrity checker did not detect compromise.
- Root-level persistence survived a factory reset in CISA's lab.
- Patch within 24 to 48 hours and limit outbound traffic.
- Reset credentials stored on the appliance.
Notes: Ivanti [2][84][101][145][4]. PAN-OS [32][33][111]. ArcaneDoor, no state named by Talos [91]. FortiManager, UNC5820 [69][70]. AA24-060B [5]. ScreenConnect [20][133]. regreSSHion in summary, home study SSHole [48][137].

## PART 2 | The KEV record put edge and file-transfer flaws first

| CVE | Product | What happened | KEV added |
|---|---|---|---|
| CVE-2024-21887 | Ivanti Connect Secure | Command injection, zero-day | 2024-01-10 |
| CVE-2024-1709 | ScreenConnect | Authentication bypass, CVSS 10.0 | 2024-02-22 |
| CVE-2024-3400 | PAN-OS GlobalProtect | Command injection, CVSS 10.0 | 2024-04-12 |
| CVE-2024-37085 | VMware ESXi | Authentication bypass | 2024-07-30 |
| CVE-2024-40711 | Veeam B&R | Deserialization, CVSS 9.8 | 2024-10-17 |
| CVE-2024-47575 | FortiManager | Missing authentication | 2024-10-23 |
| CVE-2024-55956 | Cleo | Command injection | 2024-12-17 |
Caption: XZ Utils CVE-2024-3094 and regreSSHion CVE-2024-6387 are not in KEV.
Notes: Rows [144][3][20][133][33][134][109][110][70][135][112]. Six of the seven carry the known-ransomware flag in catalog 2026.11.10; FortiManager CVE-2024-47575 does not [3]. AA24-317A on the top exploited flaws of 2023 [74].

## PART 3 | China held long footholds and reached the telecoms

- **Volt Typhoon:** pre-positioning on IT networks to move to OT, with footholds of at least five years (AA24-038A).
- **The telecom campaign:** call records, the communications of a limited number of people, and law enforcement request data.
- **APT31 and APT40:** UK and US actions on 25 March; AA24-190A on 8 July.
- **A 260,000-device botnet** run by Integrity Technology Group, consistent with Flax Typhoon per the FBI.
- **Velvet Ant and UNC3886** persisted on load balancers and hypervisors.
Caption: The 2024 statements do not use the name Salt Typhoon; the G1045 binding is the study's reading (Inferred).
Notes: Volt Typhoon, high confidence [13]. Telecom [75][76][77]; Salt Typhoon binding Inferred [83]. APT31 [27][28]. APT40 [49]. Botnet [82][62]; Lumen's counts Reported [120]. Velvet Ant [85]. UNC3886 [86]. Sichuan Silence [79].

## PART 4 | Russia sprayed passwords, read mail and was renamed

Left: Midnight Blizzard
- A legacy test account without MFA was sprayed.
- OAuth applications were abused to read corporate mail.
- Stolen email led to some source code repositories.
- HPE's mailboxes were reached from May 2023.
Right: Military intelligence and others
- Mandiant graduated Sandworm to APT44 on 17 April.
- AA24-249A named GRU Unit 29155 and WhisperGate.
- APT28 reached a target through nearby Wi-Fi.
- Microsoft seized 66 Star Blizzard domains.
Notes: Microsoft [7][132][8][9]; ED 24-02 [10]. HPE [6]. AA24-057A, SVR in the cloud [87][24]. APT44 [35]. Unit 29155, Ember Bear [61]. Nearest Neighbor [88]. Star Blizzard [66]. Secret Blizzard and Storm-0156 [78]. CARR sanctions [53].

## PART 5 | Iran sold access; North Korea funded spying with ransomware

- **Fox Kitten** sold access to US organizations and worked with ransomware affiliates for a share (AA24-241A).
- **Iranian actors** used password spraying and MFA push bombing, likely to sell access (AA24-290A).
- **APT42** targeted accounts linked to the US presidential election.
- **Andariel** funded espionage with ransomware against US healthcare (AA24-207A).
- **Moonstone Sleet** deployed its first ransomware, FakePenny.
Caption: Crime and state blurred in both programs (Inferred).
Notes: Fox Kitten [59]. AA24-290A [68]. APT42 [89]; election designations [64]. IRGC-CEC sanctions after the Unitronics defacements [12][37]. Andariel [55]. APT45 [56]. Moonstone Sleet [90].

## PART 6 | Infostealer logs and no MFA emptied cloud data platforms

- **UNC5537** used stolen credentials against Snowflake customer instances; about 165 organizations were notified.
- **At least 79.7 percent** of the accounts used had prior credential exposure, the earliest from November 2020.
- **No MFA,** credentials unrotated for up to four years and no network allow lists.
- **AT&T and Live Nation** filed 8-Ks naming only a third-party cloud platform.
- **Storm-0501** carried ransomware into hybrid cloud environments.
Caption: Mandiant found no evidence of a breach of Snowflake's enterprise environment.
Notes: Snowflake notice [41]. UNC5537 [42]. AT&T [44]. Live Nation [43]. Storm-0501 [63]. Cloudflare's Thanksgiving intrusion [1]. Sisense [31]. Dropbox Sign [38]. AA24-046A [15]. CSRB on Storm-0558 [117].

## PART 7 | Police took LockBit's servers and payments fell

Left: Enforcement
- Cronos: LockBit's admin environment, leak site and over 1,000 keys.
- LockBitSupp named and sanctioned on 7 May.
- Evil Corp designated by the US, UK and Australia on 1 October.
- Endgame hit droppers; Magnus hit RedLine and META.
Right: The advisories and the money
- Black Basta: over 500 organizations by May 2024.
- RansomHub: at least 210 victims since February.
- IC3: 3,156 ransomware complaints in 2024.
- Coveware: 25% of victims paid in Q4.
Notes: Cronos [93][16][17][94]. Khoroshev [18][19]. Evil Corp [65][96]. Endgame [40]. Magnus [72]. 911 S5 [95]. Black Basta [39]. Akira [36]. RansomHub [60]. IC3 [98]. Chainalysis (Reported [99]). Coveware (Reported [100]). Change Healthcare home study [21]. Home study for the ransomware record: The Ransomware Ecosystem.

## PART 8 | Trust failed three ways: a maintainer, a domain, an update

- **XZ Utils:** upstream releases 5.6.0 and 5.6.1 carried a backdoor that reached sshd.
- **polyfill.io:** Cloudflare rewrote links after reports that the domain served malicious JavaScript.
- **19 July:** Channel File 291 passed CrowdStrike's Content Validator because of a bug and crashed Windows hosts.
- **Kaspersky:** Commerce barred new US agreements from 20 July and updates from 29 September.
Caption: The outage belongs in this chronicle as an outage, not an intrusion (Inferred).
Notes: XZ Utils, home study [29][113][30]. polyfill.io, Cloudflare's action Confirmed, the injection Reported [47]. CrowdStrike [50][138]; CISA [51]; Microsoft's estimate [52]. Kaspersky [121].

## PART 11 | Governments used directives, sanctions, standards and treaties

- **Two emergency directives:** ED 24-01 on Ivanti and ED 24-02 on Microsoft corporate email.
- **Sanctions:** IRGC-CEC, LockBit, Intellexa, APT31, 911 S5, CARR, Evil Corp and Sichuan Silence.
- **US rules:** EO 14117 on bulk data, the CIRCIA proposed rule, NSM-22 and the Secure by Design pledge.
- **Standards:** NIST CSF 2.0 and the first post-quantum standards, FIPS 203, 204 and 205.
- **Abroad:** UK PSTI, the NIS2 deadline, Australia's Cyber Security Act and the UN cybercrime convention.
Notes: Directives [4][102][10][116]. Sanctions [12][37][17][26][28][19][95][53][64][65][79]. US rules [123][124][125][139]. Standards [126][127]. Abroad [128][129][130][131]. SEC v. SolarWinds [122]. Industrial events, home study ICS attacks and advisories [54][34][118][119].

## MITRE MAPPINGS | 68 Enterprise rows, entry and credentials at the centre

| Id | Technique | 2024 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Ivanti, PAN-OS, FortiManager |
| T1078.004 | Cloud Accounts | Microsoft's test tenant account |
| T1110.003 | Password Spraying | Midnight Blizzard, AA24-290A |
| T1528 | Steal Application Access Token | AA24-057A, OAuth abuse |
| T1584.005 | Botnet | KV Botnet on SOHO routers |
| T1505.003 | Web Shell | Ivanti, APT40, Andariel |
| T1486 | Data Encrypted for Impact | Black Basta, Akira, RansomHub |
Caption: ATT&CK v20.0 ids; revoked advisory ids mapped through superseded_by.jsonl; one Navigator layer. MITRE notice in the notes.
Notes: Rows [13][5][32][69][132][7][68][87][49][55][39][36][60]. Basis scores in the layer: 100 Source, 70 Behavior, 40 Inferred [146]. T1562.001 maps to T1685, T1562.004 to T1686 and T1070.001 to T1685.005 [140]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Phishing-resistant MFA and the KEV clock mattered most

Left: What 2024 taught
- Put phishing-resistant MFA on test and legacy accounts too.
- Patch edge appliances on the KEV clock.
- Treat infostealer exposure as a breach and rotate.
- Stage every update, security agents included.
Right: Where to look
- Web shells and configuration exports on appliances.
- New OAuth apps and full mailbox access roles.
- Sign-ins with no MFA to cloud data platforms.
- Email bombing followed by help-desk calls.
Caption: AA24-060B says a vendor's integrity tool is not enough to rule out compromise.
Notes: Recommendations [39][36][60][132][42][5][13][138], with the generalizations Inferred. Hunting cues [5][32][69][132][42][87][13][39][60]; the cues are the study's reading. Telecom hardening guidance [77].

## CROSS-CUTTING THEMES | First headlines overstated some breaches and understated dwell

- **Overstated:** "Snowflake was breached"; the record describes customer accounts without MFA.
- **Overstated:** the outage as an attack, and firm national labels for Ivanti, ArcaneDoor and the telecoms.
- **Understated:** intrusions nobody detected; five-year dwell makes the public record a floor.
- **Understated:** ransomware losses; IC3's adjusted figure leaves out downtime and remediation.
- **Understated:** routine OT tampering, common enough for a May fact sheet and a September alert.
Notes: Snowflake [42][44][43]. Outage [50][51][52]. Attribution [84][2][91][27][75][77]. Dwell [13][5]. Losses [98]; Chainalysis Reported [99]. OT [118][119][12]. The themes are the study's reading (Inferred).
