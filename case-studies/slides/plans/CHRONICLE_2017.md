# Slide plan: The Year 2017 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2017.md
- Cover title: The Year 2017 / in Intrusions / A Dated Record
- Subtitle: Two worms, three poisoned updates and an attack on the safety layer
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2017.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One March patch decided the year's two biggest outbreaks

- **WannaCry, 12 May:** a self-spreading worm locked computers in more than 150 countries and disrupted at least 81 NHS trusts.
- **NotPetya, 27 June:** a wiper hidden in a Ukrainian accounting update, later called the costliest cyber-attack in history.
- **Both used SMBv1 flaws** Microsoft fixed on 14 March, weeks before the Shadow Brokers made the exploits public.
- **Trusted channels carried malware:** M.E.Doc, NetSarang and CCleaner updates, and IT service providers.
- **Equifax and Triton:** a 76-day data theft through a known Struts flaw, and malware built for safety controllers.
Caption: Grades: agencies, filings, audits, CVE and KEV records Confirmed; vendor attribution Reported; this study's reasoning Inferred.
Notes: WannaCry [15][16]. NotPetya [18][21]. MS17-010 [4]; Shadow Brokers triage [9]. Update channels [86][28][29]; MSPs [88]. Equifax [13]. Triton [25].

## KEY FACTS | 59 days from patch to worm, and 147 million people in one breach

Stat: 59 days | from MS17-010 to WannaCry; 105 to NotPetya
Stat: 81 of 236 | NHS trusts in England disrupted by WannaCry
Stat: ~147M | people in the Equifax settlement
Stat: 2.27M | users affected by the trojanized CCleaner
- The White House attributed WannaCry to North Korea on 19 December, with five allies.
- NotPetya was attributed to the Russian military on 15 February 2018.
- Merck reported about $135 million of sales effect and $175 million of expenses from a 27 June attack.
Notes: Patch window arithmetic Inferred from [4][15][18]. NHS [16]. Equifax counts: 143 million (8-K), 145.5 million (GAO), 147 million (FTC) [10][13][14]. CCleaner [30]. Attributions [41][21][22]. Merck, for the third quarter and first nine months; the 10-Q does not name NotPetya, so the tie is Inferred [19].

## PART 1 | The year in date order, from Vault 7 to the WannaCry attribution

| Date | Event |
|---|---|
| 7 Mar | WikiLeaks publishes Vault 7 Part 1, "Year Zero" |
| 14 Mar | Microsoft ships MS17-010 for the SMBv1 flaws |
| 27 Apr | TA17-117A on intrusions at IT service providers |
| 12 May | WannaCry spreads; NHS England hit |
| 27 Jun | NotPetya surfaces through M.E.Doc |
| 15 Aug | ShadowPad found in NetSarang; CCleaner 5.33 ships |
| 7 Sep | Equifax announces about 143 million affected |
| 24 Oct | Bad Rabbit spreads through compromised websites |
| 14 Dec | Mandiant publishes TRITON |
| 19 Dec | US and allies attribute WannaCry to North Korea |
Notes: Vault 7, provenance is WikiLeaks' claim [3]. MS17-010 [4]. TA17-117A [88]. WannaCry [15][16]. NotPetya [18][86]. NetSarang [28]; CCleaner [29]. Equifax [10]. Bad Rabbit [36][37]. Triton [25]. Attribution [41][44].

## PART 2 | WannaCry showed what one worm costs a health system

- **Spread:** SMBv1 exploits over TCP 445, first reported around 04:00 EDT on 12 May.
- **NHS England:** 603 other NHS organisations infected, 6,912 appointments known cancelled, no ransom paid.
- **Every infected body** ran unpatched or unsupported Windows.
- **Managed internet-facing firewalls** would have protected NHS bodies whatever their patch state (NAO).
- **A researcher's kill switch,** not a defense, slowed the outbreak.
Caption: Reach differs by source: tens of thousands (US-CERT), hundreds of thousands (White House), 300,000 (UK).
Notes: Mechanics [15]. NAO findings, more than 19,000 appointments estimated [16]. Microsoft's legacy-platform updates [62]. Reach [15][41][44]. Park Jin Hyok complaint and designation, 6 September 2018, allegations [45][42].

## PART 2 | NotPetya was a wiper wearing a ransom note

Left: How it spread
- Backdoored M.E.Doc updates on 14 April, 15 May and 22 June.
- A modified Mimikatz with WMIC or PsExec came first.
- EternalBlue and EternalRomance came after.
- With admin rights it changed the master boot record.
Right: What it cost
- FedEx: TNT Express hit, $0.79 per diluted share.
- DOJ alleges nearly $1 billion at three named victims.
- CISA: paying is unlikely to recover data.
- ATT&CK: better thought of as a wiper.
Notes: Talos found every installation came through M.E.Doc's update channel [86]; CISA spreading order [18]; ESET's DLL analysis Reported [77]. FedEx [20]. GRU Unit 74455 indictment, allegations [48]. CISA and ATT&CK [18][87]. Home study: Sandworm.

## PART 3 | States were named for 2017 operations, mostly years later

Left: Russia and North Korea
- Dragonfly targeted energy, nuclear and water (TA17-293A).
- GRU spearphishing of En Marche before the French vote.
- HIDDEN COBRA alerts on DeltaCharlie, FALLCHILL, Volgmer.
- FSB officers indicted over Yahoo on 15 March.
Right: China, Iran and Vietnam
- Cloud Hopper reached customers through their MSPs.
- Boyusec employees indicted on 27 November.
- APT33 named by Mandiant; APT34 used CVE-2017-11882.
- APT32 activity assessed as aligned with Vietnam.
Notes: Dragonfly [34][52][51]. En Marche, allegations [48]. HIDDEN COBRA [24][46][47]. Yahoo, allegations [53]. Cloud Hopper [88][8][54]. Boyusec [56]; the APT3 link is third-party attribution [57]. APT33, APT34 and APT32 are Mandiant's assessments, Reported [58][59][60].

## PART 4 | Leaked exploits and poisoned updates turned trust into a route

| Date | Channel | What happened |
|---|---|---|
| 14 Apr to 22 Jun | M.E.Doc updates | Backdoor, then XData and NotPetya |
| Apr | Shadow Brokers leak | SMB exploits already fixed by MS17-010 |
| 27 Apr | IT service providers | PlugX and RedLeaves to customers |
| 17 Jul | NetSarang packages | ShadowPad in nssock2.dll |
| 15 Aug | CCleaner 5.33 | Validly signed trojanized build |
Caption: Binding T1195.002 to the three update compromises is this study's reading (Inferred).
Notes: MSRC triage, three exploits did not reproduce on supported platforms [9]. M.E.Doc [86][18][77][17]. NetSarang, signing as Kaspersky reports it [28]. CCleaner, restore to before 15 August [29][30]. MSPs, at least 12 countries [88]. Attribution of NetSarang and CCleaner lives in the APT41 study.

## PART 6 | Equifax was four failures, not one missed patch

- **10 March:** intruders scan for the Struts flaw two days after US-CERT identified it.
- **The alert** went to an out-of-date list, and a scan a week later missed the portal.
- **13 May to 30 July:** about 9,000 queries; stored credentials opened 48 more databases.
- **An expired certificate** blinded the inspection device for about 10 months.
- **Uber,** by contrast, paid its 2016 intruders $100,000 through its bug bounty and disclosed a year late.
Caption: GAO's four factors: identification, detection, segmentation of database access and data governance.
Notes: GAO timeline and findings [13]; patch ordered within 48 hours and not verified [14]. Counts [10][12][14]. PLA indictment, allegations [55]. Uber [39][40]. Yahoo, three billion accounts [32].

## PART 7 | Triton hit the safety layer from an engineering workstation

- **Mandiant, 14 December:** TRITON reprogrammed Triconex safety controllers over TriStation.
- **A flaw in the malware** tripped the safety system and exposed the intrusion.
- **ATT&CK campaign C0030,** June to August 2017, at a petrochemical organization, by TEMP.Veles.
- **Treasury** designated Russia's TsNIIKhM for building the tools.
- **The key switch:** HatMan needs PROGRAM mode, so controllers should never be left in it.
Caption: Mandiant's 2017 view was "moderate confidence" of a nation-state sponsor; the government records came later.
Notes: Mandiant findings Confirmed, assessment Reported [25]. C0030 and S1009 [89][90]. Treasury [50]. DOJ indictment, allegations [51]. ICSA-18-107-02 [91]. Industroyer and CrashOverride, the 2016 grid attack reported in 2017 [49][79].

## PART 9 | The release-day exploitation flag aged badly

| CVE | What | At release | KEV added |
|---|---|---|---|
| CVE-2017-0144 | SMBv1 (MS17-010) | Exploited: No | 2022-02-10 |
| CVE-2017-5638 | Apache Struts S2-045 | Critical | 2021-11-03 |
| CVE-2017-0199 | Office RTF handling | Exploited: No | 2021-11-03 |
| CVE-2017-11882 | Office Equation Editor | Exploited: No | 2021-11-03 |
| CVE-2017-8759 | .NET Framework | Exploited: Yes | 2021-11-03 |
Caption: KEV began in November 2021; 86 CVE-2017 entries, 20 flagged for known ransomware use.
Notes: MSRC [4][72][73][92]. NVD [7][75][76]. KEV catalog 2026.11.10 [5]. Project Zero lists CVE-2017-0199 and CVE-2017-0143 to 0147 as 2017 in-the-wild zero-days [74]. KRACK [35]; Cloudbleed [2].

## PART 10 | 2017 was a year of naming and rule-making

- **NYDFS Part 500,** 1 March: cybersecurity rules for a regulated sector.
- **Executive Order 13800,** 11 May: agencies to use the NIST Framework immediately.
- **BOD 17-01,** 13 September: remove Kaspersky-branded products; the FY2018 NDAA followed.
- **SEC Cyber Unit,** 25 September, and the **VEP charter,** 15 November.
- **Takedowns:** Kelihos, AlphaBay, BTC-e, Andromeda; Mirai creators pleaded guilty.
Notes: [81][80][31][61][82][83][84]. Crime and law enforcement [66][67][68][70][69]. IC3: business email compromise losses above $675 million against ransomware above $2.3 million [71].

## MITRE MAPPINGS | 68 Enterprise and 28 ICS rows, with T1210 at the center

| Id | Technique | 2017 use |
|---|---|---|
| T1210 | Exploitation of Remote Services | WannaCry, NotPetya, Bad Rabbit |
| T1003.001 | LSASS Memory | NotPetya's modified Mimikatz |
| T1195.002 | Compromise Software Supply Chain | M.E.Doc, NetSarang, CCleaner |
| T1199 | Trusted Relationship | MSP intrusions |
| T1190 | Exploit Public-Facing Application | Equifax dispute portal |
| T1486 | Data Encrypted for Impact | WannaCry, NotPetya, Bad Rabbit |
| T0880 | Loss of Safety (ICS) | Triton |
Caption: ATT&CK v20.0 ids; 10 groups, 15 software objects and 7 campaigns; two Navigator layers.
Notes: Rows [85][87][18][26][86][28][29][88][13][90][25]. Layer scores: 100 Listed, 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The same short list of controls recurs in every 2017 advisory

Left: What 2017 taught
- Block SMB at the edge and between workstations.
- Patch known-exploited flaws on a clock and verify.
- Keep an inventory that names each system's owner.
- Treat updates and providers as privileged access.
Right: Where to look
- Remote WMI and PsExec use across workstations.
- New administrator accounts and deleted event logs.
- Query rates and small, steady outbound transfers.
- Safety controllers left in PROGRAM mode.
Caption: MFA on remote access, segmentation, allowlisting, logging and offline backups complete the list.
Notes: [15][18][16][14][13][29][88][34][79][25][91]. The common-list reading is Inferred.

## CROSS-CUTTING THEMES | Luck found the attacks that defenses missed

- **Leaked tools became everyone's tools** within weeks of the April release.
- **Credentials moved the attackers** more than exploits did: NotPetya, Dragonfly, the MSPs and Equifax.
- **Detection by luck:** the kill switch, the Triton safety trip and Equifax's certificate renewal.
- **Overstated:** NotPetya as ransomware, Equifax as one missed patch, "2017 KEV additions".
- **Understated:** email fraud, nearly 300 times ransomware's reported losses in IC3's 2017 count.
Notes: Leaks [9][4][15][18]. Credentials [18][34][88][13]. Detection [16][89][13]. Overstated [18][87][13][5]. Understated [71]. These readings are the study's (Inferred).
