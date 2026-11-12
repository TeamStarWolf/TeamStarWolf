# Slide plan: The Year 2018 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2018.md
- Cover title: The Year 2018 / in Intrusions / A Dated Record
- Subtitle: Flawed processors, an Olympic wiper and a year of governments naming names
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2018.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | 2018 was the year governments named names

- **Spectre and Meltdown, 3 January:** flaws in the processors themselves let one program read another's memory.
- **Olympic Destroyer, 9 February:** a wiper took down Winter Olympics systems during the opening ceremony.
- **The edge was taken without exploits:** routers, switches and VPNFilter's 500,000 devices.
- **Indictments became the record:** GRU, MSS, IRGC-linked and North Korean operators were charged.
- **Disclosures grew:** Marriott's Starwood network had held an intruder since 2014.
Caption: Grades: advisories, filings, indictments as allegations, CVE and KEV records Confirmed; vendor attribution Reported; this study's reasoning Inferred.
Notes: Project Zero [1][2]. Olympic Destroyer [5][6]. TA18-106A [19]; VPNFilter [22][23]. Indictments [29][21][13][36][49][54][58]. Marriott [56].

## KEY FACTS | 1.35 Tbps against GitHub and up to 500 million Starwood guests

Stat: 1.35 Tbps | memcached reflection against GitHub, 28 February
Stat: 500K+ | devices running VPNFilter, Talos estimate
Stat: ~500M | Starwood guests in the breached database
Stat: 89 | CVE-2018 entries now in KEV
- The UK and the White House attributed NotPetya to the Russian military on 15 February.
- SamSam's indictment alleged over 200 victims and over $30 million in losses.
- IC3 counted $1.3 billion in email fraud losses against $3.6 million for ransomware.
Notes: GitHub [9]. VPNFilter [22]. Marriott, "up to" figures on the first day [56]. KEV catalog 2026.11.10, 33 flagged for known ransomware use [86]. NotPetya [7][8]. SamSam, allegations [54]. IC3 2018 [65].

## PART 1 | The year in date order, from Spectre to APT10

| Date | Event |
|---|---|
| 3 Jan | Project Zero publishes Spectre and Meltdown |
| 9 Feb | Olympic Destroyer hits the PyeongChang opening |
| 28 Feb | Memcached DDoS takes GitHub offline |
| 23 Mar | Nine Iranians charged over the Mabna Institute |
| 16 Apr | TA18-106A on Russian router and switch attacks |
| 23 May | Talos publishes VPNFilter; FBI seizes its domain |
| 13 Jul | Twelve GRU officers indicted |
| 6 Sep | Park Jin Hyok complaint unsealed |
| 30 Nov | Marriott discloses the Starwood breach |
| 20 Dec | APT10 indictment and allied attribution |
Notes: Spectre and Meltdown [1]. Olympic Destroyer [5]. GitHub [9][10]. Mabna, allegations [13]. TA18-106A [19]. VPNFilter [22][23]. GRU, allegations [29]. Park Jin Hyok, allegations [36]. Marriott [56]. APT10, allegations [58][59].

## PART 2 | Russia hit the Olympics and the network edge

Left: Destructive and disruptive
- Olympic Destroyer wiped systems during the ceremony.
- Talos found no theft and named no actor.
- VPNFilter carried a kill command.
- Infections spiked in Ukraine in May.
Right: Access and espionage
- Dragonfly reached energy networks through suppliers.
- Routers taken through defaults and Smart Install.
- GRU officers tried the OPCW's Wi-Fi in The Hague.
- LoJax put a rootkit in UEFI firmware.
Notes: Olympic Destroyer [5]; the 2020 indictment [6]. VPNFilter [22][23]. TA18-074A [11]. TA18-106A [19]; Smart Install [18]. GRU and OPCW, allegations [21][16]. LoJax, attribution Reported [62]. Home studies: Sandworm and Russia-attributed actors.

## PART 3 | North Korea, Iran and China were charged in court

Left: North Korea and Iran
- Park Jin Hyok: Sony, Bangladesh Bank, WannaCry.
- FASTCash drew cash from ATMs in 23 countries at once.
- Mabna sprayed passwords at university logins.
- SamSam's exchangers got the first bitcoin sanctions.
Right: China
- Thrip targeted satellite and defense firms.
- Jiangsu MSS officers charged over turbofan data.
- APT10 reached clients through their MSPs.
- The UK and allies named the MSS in December.
Notes: Park Jin Hyok, allegations [36][37]. FASTCash [40]. Mabna [13]; TA18-086A [77]. SamSam sanctions [55]. Thrip [26]. Jiangsu MSS, allegations [49]. APT10, allegations [58]; TA18-276B [42]; attribution [59].

## PART 6 | Ransomware went targeted while email fraud cost more

- **SamSam** entered over RDP and encrypted whole networks, hospitals to a port authority.
- **Ryuk appeared** in August in targeted attacks, with a take over $640,000 (Check Point).
- **Emotet** cost local governments up to $1 million per incident to clean up.
- **FIN7 and Infraud** faced arrests and indictments for card theft at scale.
- **Email fraud** cost about 360 times ransomware in IC3's count.
Caption: Indictment totals are allegations, not findings.
Notes: SamSam [57][54]. Ryuk, Reported [63]. Emotet [32]. FIN7, allegations [33]; Infraud, allegations [4]. IC3, $1,297,803,489 against $3,621,857 [65]; the ratio is Inferred.

## PART 8 | The biggest data disclosures were not all intrusions

| Date | Organization | What happened |
|---|---|---|
| 29 Mar | Under Armour | MyFitnessPal, about 150 million accounts |
| 4 Apr | Facebook | Up to 87 million shared with Cambridge Analytica |
| 3 Aug | TSMC | Virus outbreak from a misoperation |
| 28 Sep | Facebook | View As token theft, revised to about 30 million |
| 30 Nov | Marriott | Starwood network accessed since 2014 |
Caption: Cambridge Analytica was data misuse, and TSMC blamed its own installation error.
Notes: MyFitnessPal [14]. Cambridge Analytica [17]. TSMC [34]. View As [39][75]. Marriott [56].

## PART 9 | Trust in people and providers carried the intrusions

- **Staging targets:** Dragonfly went through less secure suppliers.
- **MSPs:** stolen administrator credentials reached clients in at least 12 countries.
- **event-stream:** a new npm maintainer added a malicious dependency.
- **Ticketmaster:** a supplier-hosted support widget carried malicious code.
- **The Big Hack:** a hardware-implant claim that Apple and AWS denied.
Notes: TA18-074A [11]. TA18-276B and the APT10 indictment [42][58]. event-stream [73]; home study npm supply-chain attacks. Ticketmaster [27]. Big Hack denials [43][44].

## PART 11 | A CVE-2018 id is not always a 2018 event

| CVE | What | KEV |
|---|---|---|
| CVE-2018-7600 | Drupal core (Drupalgeddon2) | Yes, ransomware use |
| CVE-2018-0171 | Cisco Smart Install | Yes |
| CVE-2018-8174 | Windows VBScript engine | Yes, ransomware use |
| CVE-2018-11776 | Apache Struts namespace | Yes |
| CVE-2018-10933 | libssh authentication bypass | No |
Caption: KEV began in November 2021, so none of its 89 CVE-2018 entries was added in 2018.
Notes: Drupal [15][89]. Cisco [90][91]. Microsoft [94]. Struts [98]. libssh [100]. KEV [86]. CVE-2018-13379, CVE-2018-15982 and CVE-2018-20250 were published in 2019 and belong to that record.

## PART 12 | The rulebook caught up on paper

- **NIST CSF 1.1,** 16 April, the same day as the router alert.
- **California Consumer Privacy Act,** chaptered 28 June.
- **Executive Order 13848,** 12 September, and the National Cyber Strategy, 20 September.
- **CISA Act,** 16 November: the agency gets its name.
- **Singapore and Australia** passed critical-infrastructure and access laws.
Notes: [79][80][82][83][84][81][85].

## MITRE MAPPINGS | 127 Enterprise and 4 ICS rows, with credentials at the center

| Id | Technique | 2018 use |
|---|---|---|
| T1133 | External Remote Services | Dragonfly VPN and RDP; SamSam |
| T1110.003 | Password Spraying | Mabna and TA18-086A |
| T1187 | Forced Authentication | Dragonfly's SMB lures |
| T1199 | Trusted Relationship | APT10 and the MSPs |
| T1602.002 | Network Device Configuration Dump | Router campaign |
| T1490 | Inhibit System Recovery | Olympic Destroyer |
| T1498.002 | Reflection Amplification | Memcached floods |
Caption: ATT&CK v20.0 ids; 13 groups, 19 software objects and 6 campaigns; two Navigator layers.
Notes: Rows [106][11][57][113][77][112][42][19][107][5][9][10]. Layer scores: 100 Listed, 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Every 2018 advisory asked for the same short list

Left: What 2018 taught
- MFA on every external interface.
- Network devices need owners and patches.
- Close RDP and SMB at the edge.
- Bound what a provider can do.
Right: Where to look
- Logins sprayed across many accounts.
- Device configs pulled over SNMP or TFTP.
- Deleted shadow copies and backup catalogs.
- MSP accounts in Domain Admin groups.
Caption: Offline backups, logging before the incident and reboots of the home and office edge complete the list.
Notes: [11][77][57][19][42][32][5][22]. The common-list reading is Inferred.

## CROSS-CUTTING THEMES | The advanced part of 2018 was patience, not exploits

- **No zero-day required:** defaults, legacy protocols and bought RDP passwords.
- **Trust was the attack surface:** suppliers, MSPs and a package maintainer.
- **The state was named in court,** often for conduct years earlier.
- **Overstated:** the Big Hack, first-day breach counts and TSMC as an attack.
- **Understated:** email fraud, and SamSam as the start of human-operated ransomware.
Notes: [19][18][57][46][11][42][58][73][29][21][49][43][44][39][75][34][65][54]. These readings are the study's (Inferred).
