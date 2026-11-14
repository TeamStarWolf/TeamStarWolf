# Slide plan: The Year 2013 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2013.md
- Cover title: The Year 2013 / in Intrusions / A Dated Record
- Subtitle: APT1, Target and the year ransomware learned to encrypt
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2013.md, told from US-CERT and ICS-CERT alerts in CISA's archive, CERT/CC vulnerability notes, Microsoft advisories and bulletins, CVE, NVD and KEV records, Kaspersky's, Mandiant's, Citizen Lab's and ESET's reports, Cloudflare's Spamhaus posts, Target's, Adobe's, Yahoo's and Verizon's statements and filings, the Senate Commerce Committee's Target report, Justice Department, FBI, Treasury and Department of Energy records, and White House, NIST, ISO, IETF, European Commission, United Nations and MITRE records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A private report named a PLA unit, and the breaches got bigger

- **Plug-ins:** US-CERT warned on 10 January that Java CVE-2013-0422 was being exploited.
- **APT1:** Mandiant tied 141 victim organizations to a PLA unit on 19 February.
- **Espionage:** Kaspersky published Red October, Winnti, NetTraveler, Kimsuky and Icefog.
- **Reflection:** Spamhaus was hit at 120 Gbps, mostly by DNS reflection.
- **Breaches:** Adobe in October and Target in December; Yahoo's theft surfaced in 2016.
Caption: Grades: vendor, government and court records Confirmed; press accounts and the Senate's Target entry point Reported.
Notes: Plug-ins [2][3]. APT1 [43][121]. Espionage [1][16][46][50][31]. Reflection [12][13]. Breaches [32][40][122][89].

## KEY FACTS | Four numbers from the primary record

Stat: 141 | victim organizations in Mandiant's APT1 report
Stat: 120 | Gbps at Cloudflare's network, Spamhaus DDoS
Stat: 256 | incidents ICS-CERT responded to in 2013
Stat: 38 | CVE-2013 ids in CISA's KEV catalog today
- Six of the 38 KEV entries are flagged for known ransomware use.
- KEV added CVE-2013-3893 in August 2025, twelve years late.
- No 2013 record carries an ATT&CK id; every binding is later.
Notes: APT1 [43][121]. Spamhaus [13]. ICS-CERT [95]. KEV [4]. ATT&CK [10].

## PART 1 | The year in date order, from Java to Target

| Date | Event |
|---|---|
| 10 Jan | TA13-010A on Java 7 |
| 14 Jan | Kaspersky publishes Red October |
| 12 Feb | EO 13636 and PPD-21 |
| 19 Feb | Mandiant's APT1 report |
| 22 Mar | Spamhaus DDoS peaks |
| 28 May | Liberty Reserve indictment |
| 5 Jun | Citadel disrupted |
| 6 Jun | Verizon order and PRISM reported |
| 30 Sep | Silk Road seized |
| 3 Oct | Adobe discloses breach |
| 5 Nov | TA13-309A on CryptoLocker |
| 19 Dec | Target confirms 40 million cards |
Notes: Java [2]. Red October [1]. EO [96][7]. APT1 [43]. Spamhaus [13]. Liberty Reserve [66][22]. Citadel [23]. Press, Reported [60][61]. Silk Road [67]. Adobe [32]. CryptoLocker [35]. Target [122].

## PART 2 | China-attributed espionage went public

- **APT1:** 141 victims in 20 industries since 2006, and more than 3,000 indicators.
- **Unit 61398:** Mandiant linked APT1 to the PLA's 3rd Department, 2nd Bureau.
- **The Times:** the paper said intruders were inside for four months.
- **Winnti:** a trojan pushed from a game publisher's update server.
- **Icefog and NetTraveler:** lure documents and known Office exploits.
Caption: The China study is the home for APT1; this deck records the 2013 dates.
Notes: Part 2. APT1 [43][121][10]. The Times, Reported [5]. Winnti [16][45]. Icefog [31]. NetTraveler [46][47]. Home study [127].

## PART 3 | The wider state record, mostly without states named

Left: The reports
- Red October, from 2007.
- MiniDuke, a Reader zero-day.
- Kimsuky, in September.
- South Korea, in March.
Right: The attribution
- Kaspersky named no state.
- APT29 tie from 2021.
- North Korea "likely".
- FBI linked it in 2014.
Caption: State links came later from ATT&CK, the FBI and governments.
Notes: Part 3. Red October [1]. MiniDuke [52][53]. Kimsuky [50][51]. South Korea [49]. Home studies [127].

## PART 4 | Reflection made DDoS cheap

- **Spamhaus:** about 90 Gbps on 19 March and 120 Gbps on 22 March at Cloudflare.
- **Amplifier:** DNS reflection was the largest source of the traffic.
- **Remedy:** TA13-088A on 29 March told operators to close open resolvers.
- **Banks:** the US financial-sector DDoS ran from 2011 to 2013, as alleged.
- **Second-hand:** the 300 Gbps figure is relayed from a Tier 1 provider.
Caption: The Iran study is the home for the 2011 to 2013 financial-sector DDoS.
Notes: Part 4. Spamhaus [12][13]. TA13-088A [14]. Banks [27], as alleged. Figure, Reported [13]. Home study [127].

## PART 5 | Breaches were found by someone else, or found late

| Date | Event | Grade |
|---|---|---|
| Jul | DOE system: 104,000+ people | Confirmed |
| 25 Jul | Drinkman indictment, 160M+ cards | Confirmed (as charged) |
| Aug | Yahoo theft, disclosed 2016 | Confirmed |
| 3 Oct | Adobe: 2.9 million customers | Confirmed |
| 12 Dec | Justice Department tells Target | Confirmed |
| 19 Dec | Target: about 40 million cards | Confirmed |
Notes: Part 5. DOE [25]. Drinkman [68]. Yahoo [89][92][26]. Adobe [32][33]. Target [40][122].

## PART 6 | Clients were the front door

Left: Exploited in 2013
- Java, January.
- Reader, February.
- Internet Explorer, May.
- Internet Explorer, September.
- Office and Windows, November.
Right: The KEV tail
- 38 CVE-2013 entries.
- Six with ransomware use.
- CVE-2013-3893 added 2025.
- CVE-2013-3918 added 2025.
Caption: KEV dates are additions, not exploitation dates.
Notes: Part 6. Exploited [3][73][20][29][36][39]. KEV [4].

## PART 7 | Takedowns went after money as well as malware

| Date | Event | Grade |
|---|---|---|
| 28 May | Treasury's Section 311 on Liberty Reserve | Confirmed |
| 5 Jun | Citadel, 1,462 botnets | Confirmed |
| 30 Sep | Silk Road seized | Confirmed |
| 25 Oct | 173,991 bitcoins seized in total | Confirmed |
| 5 Nov | CryptoLocker encrypts files | Confirmed |
| 5 Dec | ZeroAccess disrupted | Confirmed |
Notes: Part 7. Liberty Reserve [22][66]. Citadel [23]. Silk Road [67]. CryptoLocker [35]. ZeroAccess [41].

## PART 8 | Policy turned toward frameworks

| Date | Event | Grade |
|---|---|---|
| 11 Jan | EC3 opens at Europol | Confirmed |
| 12 Feb | EO 13636 and PPD-21 | Confirmed |
| Apr | SP 800-53 Rev. 4 | Confirmed |
| Jun | RFC 6962, Certificate Transparency | Confirmed |
| 19 Jun | Microsoft's bounty programs | Confirmed |
| 24 Jun | UN expert report A/68/98 | Confirmed |
| Oct | ISO/IEC 27002:2013 | Confirmed |
Notes: Part 9. EC3 [100]. EO [96][7]. SP 800-53 [98]. RFC 6962 [115]. Bounties [116]. UN [102]. ISO [110].

## CROSS-CUTTING THEMES | What the year's record shows

- **Attribution:** went public, mostly from vendors rather than governments.
- **Clients:** Java, Internet Explorer, Reader and Office were the front door.
- **Reflection:** open resolvers made the Spamhaus attack cheap.
- **Ransomware:** lock screens gave way to CryptoLocker's encryption.
- **Discovery:** Target heard from the Justice Department; Yahoo found out in 2016.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Attribution [43][1][46][31][49][27][53]. Clients [3][20][29][36][73]. Reflection [12][14]. Ransomware [11][35]. Discovery [40][89].

## MITRE MAPPINGS | 60 Enterprise techniques, every one a later mapping

| Id | Technique | 2013 use |
|---|---|---|
| T1189 | Drive-by Compromise | Java, watering holes |
| T1566.001 | Spearphishing Attachment | APT1, Kimsuky |
| T1195.002 | Compromise Software Supply Chain | Winnti |
| T1550.002 | Pass the Hash | APT1 |
| T1102.001 | Dead Drop Resolver | MiniDuke |
| T1498.002 | Reflection Amplification | Spamhaus |
| T1486 | Data Encrypted for Impact | CryptoLocker |
Caption: ATT&CK v20.0 ids; 44 are listed by ATT&CK for objects tied to 2013 reports; four ICS ids are Inferred.
Notes: Part 11. Rows [2][10][51][16][53][12][35]. Basis scores in the layer: 100 Listed, 70 Described, 50 Reported. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2013 lessons still apply

Left: What 2013 taught
- Disable Java in browsers.
- Workaround before fix.
- Close open resolvers.
- Use indicators quickly.
Right: What still applies
- Backups out of reach.
- Fence vendor access.
- Hide management ports.
- Keep logs to classify.
Notes: Top recommendations and Part 10. Java [2][69]. Workarounds [29][81]. Resolvers [14]. Indicators [121]. Backups [35]. Vendors, Reported [40]. Management [80][24]. Logs [95].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Named breaches as the story.
- Target's entry point.
- Vendor attribution.
- Dollar and infection counts.
Right: Understated
- Dwell and discovery.
- The TLS weaknesses.
- The KEV tail.
- Industrial exposure.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [96][98][40][1][46][31][23][41][13][66]. Understated [1][89][92][95][117][118][119][4][28]. Cross-cutting themes and the overstated and understated passage.
