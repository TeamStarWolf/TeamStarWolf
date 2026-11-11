# Slide plan: The Year 2020 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2020.md
- Cover title: The Year 2020 in Intrusions / A Dated Record
- Subtitle: The workforce went remote, old VPN bugs became the front door, and identity was the prize
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2020.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Remote work turned old VPN bugs into the year's front door

- **The shift to remote work set the stage.** AA20-133A ties the year's VPN exploitation and Office 365 misconfiguration to it.
- **Old edge bugs, not zero-days, carried the year.** Citrix CVE-2019-19781 was the most exploited flaw of 2020.
- **Patching was not enough.** Credentials stolen through Pulse Secure kept working after the patch.
- **Ransomware became a data-theft business** and turned on US hospitals in October.
- **Identity was the blast radius of the biggest breach:** the SolarWinds actor forged SAML tokens.
Caption: Grades: advisories, filings and court records Confirmed; press Reported; public PoC code Demonstrated.
Notes: Remote work [90]; four of the most targeted flaws hit remote work, VPN or cloud [84]. Citrix most exploited [84]. Pulse credential reuse [89]. Maze and double extortion [49]; hospital warning [68]. SolarWinds SAML forgery [105][40]; fewer than 18,000 installs [104].

## KEY FACTS | Four emergency directives and a hospital warning marked the year

Stat: 4 | CISA emergency directives touching 2020
Stat: 57% | K-12 share of reported ransomware, Aug to Sep
Stat: <18,000 | customers believed to have installed tainted Orion
Stat: 10.0 | NVD CVSS 3.1 score for Zerologon
- Zerologon was patched 11 August 2020; CISA ordered every federal domain controller patched by 21 September.
- Trickbot fell to a Microsoft court order in October; Emotet's infrastructure was taken on 27 January 2021.
- ATT&CK v7 (July 2020) introduced sub-techniques; v8 (October 2020) retired PRE-ATT&CK.
Notes: Directives ED 20-02, 20-03, 20-04 and 21-01 [70][72][75][39]. K-12 share of incidents reported to the MS-ISAC, up from 28 percent from January to July [128]. Orion, about 33,000 customers notified [104]. Zerologon [79][80][75]. Takedowns [48][67]. ATT&CK versions [132][133].

## PART 1 | The year in date order, from Citrix to SolarWinds

| Date | Event |
|---|---|
| 10 Jan | AA20-010A: wide Pulse Secure CVE-2019-11510 exploitation continues |
| 20 Jan | APT41 campaign begins against more than 75 FireEye customers |
| 16 Apr | AA20-107A: Pulse credentials reused after patching |
| 15 Jul | Twitter accounts hijacked through phone spear phishing |
| 16 Jul | APT29 named for targeting COVID-19 vaccine development |
| 11 Aug | Microsoft releases the Netlogon (Zerologon) fix |
| 27 Sep | UHS loses access to its US IT applications |
| 28 Oct | AA20-302A warns of an imminent threat to US hospitals |
| 8 Dec | FireEye discloses the theft of its Red Team tools |
| 13 Dec | FireEye's SUNBURST report and CISA ED 21-01 |
Notes: Pulse [88][89]. APT41 [87]. APT29 [5]. Twitter [62][63]. Zerologon [79]. UHS [61]. Hospitals [68]. FireEye [36]. SUNBURST and ED 21-01 [37][39].

## PART 2 | Russia's services went after vaccines, Linux and the Olympics

- **GRU Unit 74455 indicted, 15 October.** Six officers charged over Ukraine, NotPetya, Georgia and the 2018 Winter Olympics.
- **The UK named the GRU for Olympic Destroyer** and for reconnoitring Tokyo 2020 organisers before the Games were postponed.
- **APT29 and the vaccine.** Public exploits for Citrix, Pulse, Fortinet and Zimbra, then WellMess and WellMail.
- **Drovorub, 13 August.** A GRU unit 26165 Linux toolset with a kernel-module rootkit.
- **Berserk Bear** hit dozens of US state, local and aviation networks and exfiltrated from at least two servers.
Notes: GRU indictment [1][2]. UK attribution [3]. APT29 [5]; WellMess S0514 [130]. Drovorub [4][46]. Berserk Bear, AA20-296A [8]. Strontium against more than 200 organisations [6]. Triton sanctions on TsNIIKhM [10].

## PART 2 | China, Iran and North Korea used the same short list of flaws

Left: China and Vietnam
- APT41 hit Citrix, Cisco RV320/RV325 and Zoho ManageEngine.
- MSS-affiliated actors used public exploits against US agencies.
- Four PLA members indicted for the 2017 Equifax intrusion.
- APT32 targeted the Wuhan government from January to April.
Right: Iran and North Korea
- Pioneer Kitten used Citrix as its primary access vector.
- An Iranian actor got voter registration data in at least one state.
- FASTCash 2.0: banks targeted again from February 2020.
- BeagleBoyz had attempted to steal nearly USD 2 billion since 2015.
Notes: APT41 [87]. AA20-258A [16]. Equifax, about 145 million Americans [13]. APT32 [21]. Pioneer Kitten, AA20-259A [25]. Election sites, AA20-304A [26]. FASTCash 2.0, AA20-239A [29]. APT39 designation [22].

## PART 3 | Ransomware crews stole the data before they encrypted it

- **Maze** exfiltrated data before encryption in nearly all intrusions and ran a public leak site from November 2019.
- **Blackbaud** paid 24 Bitcoin (about USD 250,000) and never verified the data was deleted.
- **The SEC** fined Blackbaud USD 3 million in 2023 for what it told investors.
- **Vastaamo** patients were extorted one by one for their therapy records (Reported).
- **Evil Corp** swapped BitPaymer for WastedLocker after sanctions; Symantec counted at least 31 US targets.
Caption: OFAC warned on 1 October 2020 that facilitating a ransom payment carries sanctions exposure.
Notes: Maze [49][50]. Blackbaud FTC [56]; SEC, more than 13,000 customers affected [57]. Vastaamo [59][60]. Evil Corp and WastedLocker [51][52][53]. OFAC [55].

## PART 3 | Hospitals were hit in the middle of the pandemic

Stat: USD 67M | UHS pre-tax impact for 2020
Stat: 24 h | loader to ransomware, sometimes, per Mandiant
Stat: 94% | Trickbot critical infrastructure eliminated by 20 Oct
- UHS lost its US IT applications on 27 September; ambulances and elective procedures were diverted.
- AA20-302A described TrickBot and BazarLoader delivering Ryuk, and later Conti.
- The agencies told hospitals to keep paper copies of information needed for critical care.
Notes: UHS [61]. AA20-302A [68]. Mandiant, KEGTAP, SINGLEMALT and WINEKEY, UNC1878 [69]. Microsoft, 120 of 128 servers down [66]; court order [48].

## PART 4 | CISA gave agencies one to fifteen days to patch

| Directive | Issued | Subject | Deadline |
|---|---|---|---|
| ED 20-02 | 14 Jan | CryptoAPI and RD Gateway | 29 Jan |
| ED 20-03 | 16 Jul | Windows DNS Server (SIGRed) | 17 Jul, then 24 Jul |
| ED 20-04 | 18 Sep | Netlogon (Zerologon) | Every DC by 21 Sep |
| ED 21-01 | 13 Dec | SolarWinds Orion | Disconnect; report by 14 Dec |
Caption: The 2020 directives are now closed, their actions moved into BOD 22-01, which created the KEV catalog.
Notes: ED 20-02 [70][71]. ED 20-03 [72][73][74]. ED 20-04 [75][76]. ED 21-01 [39][38]. BOD 20-01 on disclosure policies [77]. BOD 22-01 and KEV [78].

## PART 4 | The most exploited flaws of 2020 were already patched

| CVE | Product | NVD weakness | KEV ransomware use |
|---|---|---|---|
| CVE-2019-19781 | Citrix ADC and Gateway | CWE-22 | Known |
| CVE-2019-11510 | Pulse Connect Secure | CWE-22 | Known |
| CVE-2018-13379 | Fortinet FortiOS SSL VPN | CWE-22 | Known |
| CVE-2020-5902 | F5 BIG-IP TMUI | CWE-22 | Known |
| CVE-2020-15505 | MobileIron | CWE-706 | Unknown |
| CVE-2020-1472 | Netlogon (Zerologon) | NVD-CWE-noinfo | Known |
Caption: AA21-209A: a majority of the top CVEs of 2020 were disclosed during the past two years.
Notes: AA21-209A list of 14 [84]. KEV records [45]. Citrix [85]. F5 [95]. Zerologon [80]. AA20-283A chained Fortinet and MobileIron with Zerologon [9].

## PART 5 | Trust relationships carried intrusions to blameless customers

Left: Supply chain
- Tainted Orion updates shipped March to June 2020.
- The code went into the build system, not the source repository.
- SignSight: trojanized installers on Vietnam's certification authority site.
- WIZVERA VeraPort abused with stolen code-signing certificates.
Right: Cloud and data
- Marriott: up to about 5.2 million guests, via two franchise logins.
- easyJet: about 9 million customers and 2,208 card records.
- The OCC fined Capital One USD 80 million over cloud risk.
- A Microsoft support database sat misconfigured, 5 to 31 Dec 2019.
Notes: SolarWinds 8-K [104]. SignSight [20]. WIZVERA [34]. Marriott [114][115]. easyJet [117]. OCC [120]. Microsoft, 5 to 31 December 2019 [118].

## PART 6 | 2020 brought indictments, sanctions and a court order

| Date | Body | Action |
|---|---|---|
| 28 Jan 2020 | Grand jury, N.D. Georgia | Four PLA members (Equifax) |
| 17 Sep 2020 | Treasury OFAC | APT39, 45 individuals, Rana |
| 12 Oct 2020 | E.D. Virginia court | Order against Trickbot C2 |
| 15 Oct 2020 | Grand jury, W.D. Pennsylvania | Six GRU Unit 74455 officers |
| 23 Oct 2020 | Treasury | TsNIIKhM sanctions (Triton) |
| 8 Dec 2020 | C.D. California | Warrant for RGB officer |
| 15 Apr 2021 | The White House | SVR named for SolarWinds |
| 22 Oct 2024 | SEC | Four companies over SolarWinds disclosures |
Caption: Whether the naming deterred anyone is not something the sources measure.
Notes: Equifax [13]. APT39 [22]. Trickbot [48]. GRU [1]. Triton [10]. Jon Chang Hyok [32]. SVR [112]. SEC penalties on Unisys, Avaya, Check Point and Mimecast [113].

## MITRE MAPPINGS | 104 Enterprise and 9 ICS techniques, led by T1190

| Id | Technique | 2020 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Citrix, Pulse, F5, Fortinet across actors |
| T1133 | External Remote Services | VPN and RDP with stolen credentials |
| T1078 | Valid Accounts | Pulse credential reuse; Twitter staff logins |
| T1110.003 | Password Spraying | Strontium; healthcare spraying |
| T1195.002 | Compromise Software Supply Chain | Orion updates; SignSight; WIZVERA |
| T1606.002 | SAML Tokens | Forged tokens after the Orion foothold |
| T1486 | Data Encrypted for Impact | Ryuk, Maze, WastedLocker, Garmin |
Caption: ATT&CK v20.0 ids; revoked ids mapped through superseded_by.jsonl. MITRE notice in the notes.
Notes: Rows [16][25][9][8][89][40][49][69][63][6][42][104][20][34][105][68][52][54]. ICS from AA20-205A [125]. Two Navigator layers, Enterprise and ICS. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Credentials outlive the patch, so rotate them

Left: What 2020 taught
- Treat internet-facing remote access as a tier-zero asset.
- After patching an exploited edge device, reset what passed through it.
- Put phishing-resistant MFA on VPN, email and cloud admin.
- Verify build systems, not only source code.
Right: Where to look
- Token-signing certificates and federation trust changes.
- Pulse logons with credentials taken before the patch.
- Loader persistence: scheduled tasks, Startup LNK, BITS.
- Help-desk and account-support tool use.
Caption: AA20-352A: plan full identity reconstitution, including resetting KRBTGT twice.
Notes: Top recommendations [70][72][75][39][45][89][69][6][56][104]. Identity monitoring is Inferred; reconstitution [40]. Loader persistence [69]. Help desk [62][63].

## CROSS-CUTTING THEMES | One patch queue served against every actor

- **The perimeter moved to the VPN.** Russian, Chinese and Iranian state actors and ransomware crews used the same gateway flaws.
- **Credentials were the real prize,** from Pulse reuse to Twitter pretexting to SAML forgery.
- **Health care was a target twice over:** spies wanted vaccine research, criminals wanted hospitals' money.
- **Disclosure became a liability.** The SEC penalized Blackbaud for what it told investors, not for being breached.
- **Overstated: zero-days.** The stolen FireEye tools held none, and the mass exploitation ran on patched bugs.
Notes: Shared flaw list [5][8][16][87][25][89]. Credentials [89][6][63][56][114][105]. Health care [5][7][15][42][61][68][69]. Disclosure [57][113][63]. Zero-days [84][36]; the overstated reading is Inferred.
