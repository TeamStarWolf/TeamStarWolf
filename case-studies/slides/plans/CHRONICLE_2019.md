# Slide plan: The Year 2019 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2019.md
- Cover title: The Year 2019 in Intrusions / A Dated Record
- Subtitle: Ransomware went hunting, the edge became the front door, and names came months later
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2019.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | In 2019 ransomware crews stopped spraying and started hunting

- **Ransomware became a targeted business.** CrowdStrike called big game hunting the most lucrative crime enterprise of 2019.
- **Edge devices were the front door.** The 2019 Pulse Secure and Citrix flaws and a Fortinet flaw patched in May 2019 were the top three exploited CVEs of 2020.
- **Patching was not enough.** Credentials stolen before a patch were reused months later.
- **Governments named names, but late.** The 28 October 2019 attack on Georgia was attributed to the GRU on 20 February 2020.
- **The biggest exposures were configuration and design failures,** not exotic exploits.
Caption: Grades: government, court, vendor, NVD and KEV records Confirmed; press Reported; public exploit code Demonstrated.
Notes: Big game hunting [116]. Top three exploited CVEs of 2020 [73]. Credential reuse and Citrix guidance [75][71]; the general lesson is Inferred. Georgia [1][2]. Capital One and First American [91][98].

## KEY FACTS | Business email compromise, not ransomware, led reported losses

Stat: $3.5B+ | losses reported to FBI IC3 in 2019
Stat: $1.78B | BEC adjusted losses, the top loss type
Stat: $84,116 | average ransom payment, Q4 2019
Stat: +104% | average payment, Q3 to Q4 2019
- IC3's $8,965,847 in 2019 ransomware losses excludes lost business and remediation; IC3 calls it artificially low.
- Ransomware downtime averaged 16.2 days in Q4 2019, and RDP access sold for as little as $30 per IP address.
- ATT&CK ran v4, v5 and, from 24 October 2019, v6, the cloud release; sub-techniques arrived only in v7 in July 2020.
Notes: IC3 2019 figures [59]. Coveware payment, downtime and RDP price [60]. That BEC outweighs ransomware in the FBI's own counts is Inferred from [49][59]. ATT&CK versions [112][113][114].

## PART 1 | The year in date order, from Ryuk to Travelex

| Date | Event |
|---|---|
| 10 Jan | CrowdStrike publishes "Big Game Hunting with Ryuk" |
| 22 Jan | CISA Emergency Directive 19-01 on DNS tampering |
| 19 Mar | Norsk Hydro hit; plants switch to manual operations |
| 22 to 23 Mar | An outsider reaches Capital One data in its cloud environment |
| 17 Apr | Talos publishes Sea Turtle; Sodinokibi spreads through WebLogic |
| 14 May | Microsoft patches BlueKeep, CVE-2019-0708 |
| 16 Aug | Coordinated ransomware attack on Texas local government entities |
| 28 Oct | Disruptive attack on Georgia's websites and broadcasters |
| 5 Dec | Treasury sanctions Evil Corp and Maksim Yakubets |
| 31 Dec | Travelex hit by Sodinokibi (Reported) |
Notes: Ryuk [32]. ED 19-01 [118]. Norsk Hydro [33][34]. Capital One [89][91]. Sea Turtle [25]; Sodinokibi [38]. BlueKeep [61]. Texas [46]. Georgia [1][2]. Evil Corp [5]. Travelex [56].

## PART 2 | Russia's services hit Georgia, embassies and office printers

- **Georgia, 28 October.** Several thousand websites disrupted and at least two TV stations interrupted; attributed to the GRU's GTsST (Sandworm) only on 20 February 2020.
- **APT28.** Reached corporate networks through a VoIP phone, a printer and a video decoder; two had default passwords.
- **APT29, Operation Ghost.** Foreign ministries in at least three European countries, with new families PolyglotDuke, RegDuke and FatDuke.
- **Turla borrowed Iran's tools.** NCSC and NSA said its Neuron and Nautilus implants were very likely Iranian in origin.
- **Sandworm and Exim.** NSA said Sandworm had exploited CVE-2019-10149 since at least August 2019.
Notes: Georgia [1][2][119]. STRONTIUM IoT findings, nearly 1,400 notifications [3]. Operation Ghost [4][40]. Waterbug, 13 organizations in 10 countries [9]; NCSC and NSA advisory [7][8]. Exim, as relayed by CISA [82].

## PART 2 | Other states went after telecoms, DNS and money

Left: China and Iran
- APT41 ran espionage and crime at the same time (FireEye, 7 August).
- GALLIUM targeted telecoms through unpatched WildFly/JBoss services.
- Operation Wocao relied on legitimate VPN access and abused soft tokens.
- Phosphorus made more than 2,700 attempts to identify accounts and compromised 4.
Right: DNS and North Korea
- Sea Turtle hijacked DNS for at least 40 organizations in 13 countries.
- The UN Panel of Experts was investigating at least 35 reported DPRK attacks in 17 member states.
- Some estimates put DPRK proceeds as high as $2 billion.
- Treasury designated Lazarus Group, Bluenoroff and Andariel on 13 September.
Notes: APT41 [10]. GALLIUM [15]. Wocao [16]. Phosphorus [21]. Sea Turtle [25]. UN Panel S/2019/691 [28]. Treasury designations [29].

## PART 3 | Ryuk set the model: commodity malware first, then ransom by hand

Stat: 705.80 | BTC in tracked Ryuk payments by January 2019
Stat: 9 h | eCrime breakout time in 2019, up from 4 h 37 min
Stat: 202,675 | stolen SMTP credential pairs counted for Emotet
- TrickBot did the initial compromise, often delivered by Emotet; operators pushed Ryuk with PsExec.
- They stopped services with kill.bat, deleted shadow copies with vssadmin and moved by RDP.
- TrickBot's anchor_dns module tunneled command traffic over DNS with the XOR key 0xB9.
Notes: Ryuk, WIZARD SPIDER, 52 transactions [32]. Breakout time [116]. Emotet's return and credential count [41]. Ryuk toolkit and anchor_dns [44]. Human-operated ransomware framing [122].

## PART 3 | Victims ran plants by hand, and leaks became a weapon

- **Norsk Hydro, 19 March.** Plants switched to manual operations; recovery from backups; total cost around 800 MNOK.
- **Texas, August.** Twenty-three local government entities hit in one coordinated wave, per Texas DIR testimony.
- **Travelex, 31 December.** More than 1,500 stores affected and a $3 million demand (Reported).
- **Maze, November.** Published about 700 MB of Allied Universal files after a missed deadline (Reported).
- **Evil Corp, 5 December.** Treasury sanctions; Dridex used to steal more than $100 million; leader working for the FSB.
Caption: After 5 December 2019 a ransom payment could reach a sanctioned party, so the payee became a legal question.
Notes: Norsk Hydro [33][34][35]; LockerGoga per NSM, Reported [36]. Texas [46]; REvil affiliate, Reported [47]. Travelex [56][57]. Maze [53]; the public list of 11 victims [54]. Evil Corp [5][55].

## PART 4 | VPN appliances became the year's most reliable way in

Stat: 14,500+ | unpatched Pulse servers found on 24 August 2019
Stat: 50,000+ | Fortinet customers sent notices in November 2020
Stat: 3 | top exploited CVEs of 2020, all edge flaws published in 2019
- Pulse patched CVE-2019-11510 on 24 April; public exploit code followed in late August.
- Fortinet's FortiOS SSL VPN advisories came on 24 May; NCSC warned on 2 October of APT exploitation.
- Citrix disclosed CVE-2019-19781 on 17 December; public exploits appeared on 10 and 11 January 2020.
Caption: CISA: victims that patched without resetting credentials stayed exposed, and a patch does not evict an actor.
Notes: Pulse [58][74][75]. Fortinet [77][78][79]. NCSC alert [76]. Citrix [68][69]. Top three of 2020 [73]. Credential and Citrix guidance [75][71].

## PART 4 | Patch to harm took months, and BlueKeep never became a worm

| CVE | Product | NVD | KEV added | Later record |
|---|---|---|---|---|
| CVE-2019-11510 | Pulse Connect Secure | 10.0 | 2021-11-03 | Top-three exploited CVE of 2020 |
| CVE-2019-19781 | Citrix ADC and Gateway | 9.8 | 2021-11-03 | Top-three exploited CVE of 2020 |
| CVE-2018-13379 | FortiOS SSL VPN | 9.8 | 2021-11-03 | Top three of 2020; device IPs sold |
| CVE-2019-0708 | Windows RDS (BlueKeep) | 9.8 | 2021-11-03 | Coin miner, operator-driven |
| CVE-2019-10149 | Exim | 9.8 | 2022-01-10 | Sandworm since August 2019 |
| CVE-2019-12255 | VxWorks IPnet | 9.8 | Not in KEV | No in-the-wild record found |
Caption: The KEV launch batch of 3 November 2021 retro-tagged most of these; a date added is not an exploitation date.
Notes: NVD [39]. KEV catalog 2026.11.03, 119 CVE-2019 entries [66]. Top three [73]; Fortinet IPs [79]. BlueKeep [61][63][64]. Exim [82]. URGENT/11 [86][87]. The KEV reading is Inferred.

## PART 5 | The biggest exposures were configuration, not exploits

Left: Supply chain
- ShadowHammer: a backdoored ASUS updater seen on over 57,000 Kaspersky users' machines.
- The real target list was more than 600 MAC addresses.
- SolarWinds' earliest suspicious activity dates to September 2019.
Right: Cloud and exposed data
- Capital One: about 106 million people in the US and Canada, through a firewall misconfiguration.
- First American: about 885 million title files readable by changing URL digits (Reported).
- Ecuador: an open server held data on over 20 million people.
Caption: Regulators turned on governance: the OCC's $80 million penalty, the SEC's disclosure order, NY DFS charges.
Notes: ShadowHammer [11][12]. SolarWinds [123][124]. Capital One [89][91][120]. First American [97]; the SEC order [98]. Ecuador [108]. OCC [94], SEC [99], NY DFS [100].

## PART 6 | Analyses came in weeks; attributions and fines took years

| Date | Body | Action |
|---|---|---|
| 2019-01-22 | CISA | Emergency Directive 19-01 on DNS tampering |
| 2019-09-13 | US Treasury | Designations of Lazarus Group, Bluenoroff and Andariel |
| 2019-12-05 | US Treasury; FBI and DOJ | Evil Corp sanctions; charges against Yakubets and Turashev |
| 2020-02-20 | UK and US governments | Georgia attack attributed to GRU GTsST |
| 2020-08-06 | OCC | $80 million penalty for Capital One |
| 2021-11-08 | US Treasury | Designations of REvil's Polyanin and Vasinskyi |
| 2022-11-28 | Irish DPC | EUR 265 million fine for Facebook scraping |
Caption: The pattern across the dates is the study's own reading (Inferred).
Notes: ED 19-01 [118]. DPRK designations [29]. Evil Corp [5][55]. Georgia [1][2]. OCC [94]. REvil designations [48]. Irish DPC [107].

## MITRE MAPPINGS | 82 techniques, with T1190 the year's busiest door

| Id | Technique | 2019 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | WebLogic, Exim, Confluence, VPNs, BlueKeep |
| T1133 | External Remote Services | VPN and RDP access with stolen credentials |
| T1195.002 | Compromise Software Supply Chain | ASUS Live Update; SolarWinds test changes |
| T1584.002 | Compromise Infrastructure: DNS Server | Sea Turtle; ED 19-01 |
| T1486 | Data Encrypted for Impact | Norsk Hydro, Ryuk, REvil, Maze |
| T1490 | Inhibit System Recovery | vssadmin shadow-copy deletion |
| T1530 | Data from Cloud Storage | Capital One sync |
Caption: ATT&CK v20.0 ids, with pre-v7 ids mapped through superseded_by.jsonl. MITRE notice in the notes.
Notes: Rows [38][25][15][76][82][85][64][91][52][16][13][11][12][123][118][35][32][40]. 19 groups and the campaigns C0014, C0023, C0024 [40]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | A patched VPN is not a clean VPN

Left: What 2019 changed
- Give edge devices a days-scale patch clock, with an owner and a deadline.
- After patching, reset credentials, then check configuration, SSH keys and iptables.
- Rebuild a compromised appliance; the patch does not evict the actor.
- Treat an Emotet alert as a ransomware precursor; keep offline backups.
Right: Hunting leads from the primaries
- Citrix: traversal requests to /vpns/ and the nobody user's crontab.
- Pulse: valid-account logons from Tor after the patch date.
- Ryuk: PsExec service creation across many hosts and vssadmin deletion.
- DNS: certificates in CT logs that you did not request.
Notes: NCSC steps [76]. Pulse cases [75]. Citrix guidance [71]. Ryuk staging [32][44]. Backups [35][52]. ED 19-01 and Sea Turtle [118][25].

## CROSS-CUTTING THEMES | Fear and harm did not match in 2019

- **The time between patch and harm.** BlueKeep took about five months to a first campaign; Citrix under four weeks to public exploit.
- **Crime and state blur.** Evil Corp's leader worked for the FSB, and APT41 ran espionage and crime at once.
- **Actors inside actors.** Turla's use of Iranian tools makes indicators weak evidence of who is behind an intrusion.
- **The supplier is the route.** ShadowHammer, SolarWinds, APT10's aim at Visma's clients and the Texas MSP route.
- **Numbers need their definitions.** A payment is not a cost, and Armis's 2 billion devices is an install base.
Notes: Patch-to-harm dates [61][63][64][58][73][68][69]; the comparison is Inferred. Crime and state [5][10][28]. Turla [7]. Supply chain [11][123][52]; Reported [13][47]. Numbers [59][60][35][87].
