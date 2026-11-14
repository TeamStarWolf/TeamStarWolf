# Slide plan: The Year 2014 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2014.md
- Cover title: The Year 2014 / in Intrusions / A Dated Record
- Subtitle: Heartbleed, Shellshock, POODLE, the card breaches and the first state indictment
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2014.md, told from OpenSSL, Google, Mozilla, Drupal and Microsoft advisories and bulletins, US-CERT and ICS-CERT alerts in CISA's archive, CERT/CC vulnerability notes, CVE, NVD and KEV records, company SEC filings, FBI releases and court records, Kaspersky's, Symantec's, CrowdStrike's, F-Secure's and Cisco Talos's reports, BSI's 2014 report, and NIST, IETF, EU, NATO, UK and US government records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year the shared code broke in public

- **Shared code:** Heartbleed in April, CCS injection in June, Shellshock in September, POODLE in October.
- **Card theft:** seven retailers' filings describe card-data intrusions in 2013 or 2014.
- **Indictment:** five PLA Unit 61398 officers charged on 31 counts, announced 19 May.
- **Sony:** destructive malware in late November; the FBI named North Korea on 19 December.
- **Industrial systems:** Havex, BlackEnergy on HMIs and a damaged German blast furnace.
Caption: Grades: vendor, government and court records Confirmed; the Senate report's vendor detail Reported.
Notes: Shared code [11][37][28][31]. Card theft [1][82][83][81][78][80][84]. Indictment [42][43]. Sony [70][71]. Industrial [51][54][94].

## KEY FACTS | Four numbers from the primary record

Stat: 34 | CVE-2014 entries in CISA's KEV catalog today
Stat: 56M | payment cards at risk at Home Depot
Stat: 31 | counts in the Unit 61398 indictment
Stat: 245 | ICS-CERT incidents in fiscal year 2014
- Every CVE-2014 KEV entry was added on 3 November 2021 or later.
- CVE-2014-1812, the GPP flaw, is the only one flagged for ransomware use.
- No 2014 record carries an ATT&CK id; every binding is later.
Notes: KEV [27][19]. Home Depot [78]. Indictment [43][42]. ICS-CERT [95]. ATT&CK public in May 2015 [117].

## PART 1 | The year in date order, from NTP floods to Sony

| Date | Event |
|---|---|
| 13 Jan | NTP amplification alert |
| 12 Feb | NIST Cybersecurity Framework 1.0 |
| 7 Apr | OpenSSL discloses Heartbleed |
| 19 May | Unit 61398 indictment announced |
| 2 Jun | GameOver Zeus and CryptoLocker disrupted |
| 25 Jun | ICS-CERT alert on Havex |
| 31 Jul | US-CERT TA14-212A on Backoff |
| 18 Sep | Home Depot: about 56 million cards |
| 24 Sep | NVD publishes Shellshock |
| 14 Oct | Google discloses POODLE |
| 24 Nov | Regin reports published |
| 19 Dec | FBI attributes Sony to North Korea |
Notes: NTP [4]. CSF [96]. Heartbleed [11]. Indictment [42]. GameOver Zeus [88]. Havex [50]. Backoff [85]. Home Depot [78]. Shellshock [28]. POODLE [31]. Regin [63][64]. Sony [70].

## PART 2 | OpenSSL, Bash and SSL 3.0 failed within six months

- **Heartbleed:** up to 64k of server memory per request, keys and credentials exposed.
- **CCS injection:** a man-in-the-middle could force weak keying material.
- **Shellshock:** six CVEs in Bash, reachable through CGI, ForceCommand and DHCP.
- **POODLE:** a design flaw no patch could repair; browsers removed SSL 3.0.
- **Response:** Project Zero, LibreSSL, Let's Encrypt and RFC 7258.
Caption: US-CERT told Heartbleed victims to regenerate keys, not only to patch.
Notes: Part 2. Heartbleed [11][12][14]. CCS injection [37]. Shellshock [28][29]. POODLE [31][32][33][34]. Response [112][113][111][109].

## PART 3 | The exploited bugs were not the branded bugs

Left: Exploited at or before the fix
- IE CVE-2014-0322, Feb.
- IE CVE-2014-1776, Apr.
- GPP passwords, MS14-025.
- OLE, MS14-060.
- Kerberos, MS14-068.
Right: The KEV tail
- 34 CVE-2014 entries.
- Heartbleed added 2022.
- POODLE never added.
- One ransomware flag.
Caption: Drupal said attacks began within hours; patching did not remove backdoors.
Notes: Part 3. IE [5][16][17][18]. GPP [19]. OLE [20][21]. Kerberos [25]. KEV [27][13][35]. Drupal [39].

## PART 4 | China was charged, and North Korea was named

| Date | Event | Grade |
|---|---|---|
| 1 May | Grand jury indicts five Unit 61398 officers | Confirmed (as charged) |
| 19 May | FBI announces the case and six victims | Confirmed |
| 9 Jun | CrowdStrike's Putter Panda report | Confirmed (vendor's finding) |
| Apr and Jun | CHS: about 4.5 million patients | Confirmed |
| 14 Oct | Talos on Group 72, Axiom | Confirmed |
| Late Nov | Sony hit by destructive malware | Confirmed |
| 19 Dec | FBI: North Korea responsible for Sony | Confirmed |
Notes: Parts 4 and 6. Indictment [43][42]. Putter Panda [44][45]. CHS [49], its China attribution Reported. Group 72 [46][47]. Sony [70][71]; Lazarus Group's ATT&CK entries cite 2016 and 2018 records [72]. Home study for Sony [126].

## PART 5 | Vendors described operations and named no state

Left: The reports
- Careto, 10 Feb.
- Dragonfly, 30 Jun.
- Epic Turla, 7 Aug.
- El Machete, 20 Aug.
- Darkhotel, 10 Nov.
- Regin, 24 Nov.
Right: The limits
- Regin dates to 2003.
- Careto runs from 2007.
- Attribution came later.
- ICS-CERT named Russia in 2021.
Caption: 2014 was mostly the year these operations were disclosed, not the year they began.
Notes: Part 5. Careto [59]. Dragonfly [52]. Turla [57]. Machete [60]. Darkhotel [61]. Regin [63][65]. Attribution [54][55]. Reading Inferred.

## PART 6 | Point-of-sale malware was an industry

| Date | Event | Grade |
|---|---|---|
| 14 Mar | Target 10-K: about 40 million cards | Confirmed |
| 12 Mar | Neiman Marcus: about 350,000 cards | Confirmed |
| 29 Apr | Michaels: about 2.6 million cards | Confirmed |
| 31 Jul | Backoff: more than 1,000 businesses | Confirmed |
| 18 Sep | Home Depot: about 56 million cards | Confirmed |
| 2 Oct | JPMorgan: 76 million households | Confirmed |
| 19 Dec | Staples: POS malware at 115 stores | Confirmed |
Notes: Part 7. Target [1]. Neiman Marcus [82]. Michaels [83]. Backoff [85]. Home Depot [78][79]. JPMorgan [76]. Staples [84].

## PART 7 | Takedowns went to court

| Date | Event | Grade |
|---|---|---|
| 28 Feb | MtGox applies for civil rehabilitation | Confirmed |
| 19 May | Blackshades: more than 90 arrests | Confirmed (as charged) |
| 2 Jun | GameOver Zeus and CryptoLocker disrupted | Confirmed |
| 30 Jun | Microsoft's No-IP and njRAT action | Confirmed |
| 22 Oct | TA14-295A on crypto ransomware | Confirmed |
| 6 Nov | Silk Road 2.0 operator arrested | Confirmed (as charged) |
Notes: Part 8. MtGox [7][8]. Blackshades [87]. GameOver Zeus [88][89][90]. No-IP [92]. Ransomware [91]. Silk Road 2.0 [93].

## PART 8 | Industrial systems were reached from the business side

Left: The record
- Havex in vendor installers.
- OPC servers enumerated.
- BlackEnergy on HMIs.
- A blast furnace damaged.
Right: The numbers
- 245 incidents in FY2014.
- 79 in energy.
- HMI campaign since 2011.
- Cimplicity flaw since 2012.
Caption: BSI gave no victim name and no date for the steel mill attack.
Notes: Part 9. Havex [50][51][53]. BlackEnergy [54]. Steel mill [94]. Numbers [95][54].

## PART 9 | Law and standards moved at both ends of the year

| Date | Event | Grade |
|---|---|---|
| 17 Jan | PPD-28 | Confirmed |
| 12 Feb | NIST Cybersecurity Framework 1.0 | Confirmed |
| 8 Apr | CJEU strikes down data retention | Confirmed |
| 13 May | CJEU Google Spain judgment | Confirmed |
| 25 Jun | Riley v. California | Confirmed |
| 5 Sep | NATO Wales cyber defence policy | Confirmed |
| 17 Oct | Executive Order 13681 | Confirmed |
| 18 Dec | Three US cybersecurity laws | Confirmed |
Notes: Part 10. PPD-28 [97]. CSF [96]. CJEU [98][99]. Riley [100]. NATO [107]. EO 13681 [103]. Laws [104][105][106].

## CROSS-CUTTING THEMES | What the year's record shows

- **Shared code:** three flaws in six months, answered by new institutions.
- **Card theft:** routine, and Home Depot learned of its breach from others.
- **The state named:** an indictment and an FBI attribution in one year.
- **Industrial systems:** reached through vendor downloads and office networks.
- **Windows identity:** GPP and Kerberos flaws were under targeted attack.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Shared code [11][28][31][112][113][111][109]. Card theft [77][1][85]. State [42][70]. Industrial [51][94][54]. Identity [19][25][27].

## MITRE MAPPINGS | 45 Enterprise and 14 ICS techniques, every one a later mapping

| Id | Technique | 2014 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Shellshock, Drupal |
| T1212 | Exploitation for Credential Access | MS14-068 |
| T1195.002 | Compromise Software Supply Chain | Havex installers |
| T1133 | External Remote Services | Backoff |
| T1561.002 | Disk Structure Wipe | Sony |
| T1486 | Data Encrypted for Impact | CryptoLocker |
| T0862 | Supply Chain Compromise (ICS) | Havex |
Caption: ATT&CK v20.0 ids; 31 Enterprise techniques are listed by ATT&CK for an object tied to 2014.
Notes: Part 12. Rows [29][39][118][25][51][85][71][88][53]. Basis scores in the layers: 100 Listed, 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2014 lessons still apply

Left: What 2014 taught
- Inventory shared libraries.
- Rotate keys after leaks.
- Retire broken protocols.
- Restore after compromise.
Right: What still applies
- MFA on vendor access.
- Patch Kerberos first.
- Offline backups.
- HMIs off the internet.
Notes: Top recommendations and Part 11. Libraries [11]. Keys [12][14]. Protocols [34][33][31][32]. Restore [39]. Vendor access [85][79]. Kerberos [25]. Backups [71][91]. HMIs [54].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Branded bugs as threats.
- The Senate Target report.
- Company attributions.
- 2014 state attribution.
Right: Understated
- MS14-068 and MS14-025.
- Havex's supply chain.
- The German steel mill.
- The KEV long tail.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [13][28][35][34][2][1][49][86][59][63][61][52][55]. Understated [25][19][51][53][94][27][29]. Cross-cutting themes and the overstated and understated passage.
