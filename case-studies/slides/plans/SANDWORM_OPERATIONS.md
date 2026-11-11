# Slide plan: Sandworm: The Operations in the Public Record

- Study: case-studies/SANDWORM_OPERATIONS.md
- Cover title: Sandworm / The Operations / in the Public Record
- Subtitle: Three blackouts, NotPetya, a false flag and edge-device botnets, checked against the primaries
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/SANDWORM_OPERATIONS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One GRU unit has shaped the grid threat model for a decade

- Researchers call it Sandworm; governments call it Unit 74455 of Russia's military intelligence service, the GRU.
- Between 2015 and 2022 it turned the lights off in Ukraine three times and released NotPetya.
- It wiped computers at the PyeongChang opening ceremony while dressing the attack up as North Korean work.
- By the NCSC's later account it infected hundreds of thousands of home and office routers and storage devices.
- A grand jury indictment of six officers charges the 2015 and 2016 grid attacks, NotPetya, PyeongChang and the 2019 Georgia attack.
Caption: Grades: operations, dates and mechanics are Confirmed from primaries; claims only Andy Greenberg's book Sandworm makes are Reported.
Notes: Executive summary [42][46][5]. UK, US State Department and White House attributions [32][33][34][47][72]. The book read through WIRED excerpts [31][62][71]. Losses Confirmed where a company filing states them, Reported where only the book does.

## KEY FACTS | An indictment, three blackouts and a dozen names

Stat: 225,000 | customers lost power on 23 December 2015
Stat: ~$400M | FedEx's NotPetya cost, first half of FY2018
Stat: 500,000+ | VPNFilter devices in at least 54 countries
Stat: 6 | GRU officers indicted, 15 October 2020
- ATT&CK G0034 Sandworm Team, v4.2; also ELECTRUM, Telebots, Voodoo Bear, IRIDIUM, Seashell Blizzard and APT44.
- Sponsor: GRU Military Unit 74455, the GTsST, in Khimki; active since at least 2009 per ATT&CK.
- Blackouts on 23 December 2015, 17 December 2016 and 10 October 2022.
- Live G0034 lists 98 Enterprise, 27 ICS and 3 Mobile technique entries; this study binds 78 Enterprise and 49 ICS.
Notes: Names and ATT&CK record [14]. Sponsor [5][47]. 2015 figure [1]; ESET says about 250,000 households [4] and the UK 230,000 people [47]; the study uses 225,000 customers. 2016 [5][9]. 2022 [58]. FedEx [28]. VPNFilter [42]. Indictment, W.D. Pa. Criminal No. 20-316 [5].

## PART 1 | Each vendor named it differently, then governments named the unit

| Year | Who | Name or identification |
|---|---|---|
| 2014 | iSIGHT Partners and ESET (MS14-060 credit) | Sandworm campaign, CVE-2014-4114 |
| 2015 to 2017 | ESET | BlackEnergy group, then TeleBots |
| 2016 | Dragos | ELECTRUM, possibly Sandworm's ICS team |
| Later | Microsoft | IRIDIUM, now Seashell Blizzard |
| 20 Feb 2020 | UK and US State Department | GTsST, Unit 74455, Sandworm |
| 15 Oct 2020 | US indictment | Unit 74455 equals Sandworm Team, Telebots, Voodoo Bear, Iron Viking |
| 17 Apr 2024 | Mandiant | APT44 (FROZENBARENTS) |
Caption: The book credits FireEye with naming Sandworm in 2014; the MS14-060 bulletin credits iSIGHT Partners and ESET.
Notes: MS14-060 [63]. Book's account Reported [62]. ESET [70]. Dragos [13]. Microsoft [57]. UK [47]; State Department [72]. Indictment [5]. APT44 [60]. ATT&CK records all as associated names of G0034 [14].

## PART 3 | The 2015 blackout was done by hand, on the utilities' own screens

Stat: 225,000 | customers across three distribution companies
Stat: 27+ | substations taken offline
Stat: 30 min | between the three attacks
- Spearphishing with macro Office files from spring 2015 delivered BlackEnergy 3; no exploit code was found.
- Remote operators opened breakers over VPN, probably with previously obtained credentials; the VPNs appear to have lacked two-factor authentication.
- Malicious converter firmware, UPS disconnects, a telephone flood and KillDisk then slowed recovery.
- BlackEnergy was on every network, but neither it nor KillDisk caused the outage.
Caption: Read ATT&CK's BlackEnergy mapping in C0028 as presence and credential theft, not as the cause of the blackout.
Notes: Intrusion [2][5][6]. Outage, 23 December 2015 [1][2]; Kyivoblenergo seven 110 kV and 23 35 kV substations for about three hours [3]. At least 27 substations, medium confidence the number is higher [2]. Recovery sabotage [1][2][7]. BlackEnergy role [1][2][19]. Indictment alleges BlackEnergy stole the credentials [5].

## PART 4 | Industroyer automated 2016, but its relay attack failed on a bug

Left: What it could do
- Payloads for IEC 60870-5-101, IEC 60870-5-104, IEC 61850 and OPC DA, plus a wiper and a SIPROTEC DoS tool.
- Set to run at a chosen hour; triggers at 22:27 UTC on 17 December and 06:30 UTC on 20 December.
- Operators pivoted through MS-SQL servers and tried one Administrator password on more than 100 hosts.
Right: What it did
- A relatively brief blackout at one Kyiv substation, about one hour.
- The SIPROTEC tool failed to convert IP byte order and sent traffic to the wrong addresses.
- The UK says the attack cut power to a fifth of Kyiv for an hour.
Caption: Protection-related mappings (T0800, T0837, T1499.004) are capability, not confirmed effect.
Notes: Components and protocols [11]; US-CERT [10]. Trigger times and intrusion [9]. Two accounts created at 01:28 and logging disabled at 01:29 on 1 December 2016 [9]. Effect [9][47]. CVE-2015-5374 [11][12]. Greenberg's report of physical-damage intent is Reported [68].

## PART 5 | NotPetya was a wiper dressed as ransomware, shipped as an update

Stat: 80% | of Ukrainian businesses used M.E.Doc, per Talos
Stat: $300 | bitcoin ransom the indictment calls a ruse
Stat: 14 Mar 2017 | MS17-010 patch, months before the outbreak
- Backdoored M.E.Doc builds went out from 14 April 2017; on 27 June the update server proxied to an attacker host.
- First and usually most effective spread: modified Mimikatz with stolen credentials; EternalBlue and EternalRomance were the alternative.
- It overwrote the first 10 sectors of the disk; CISA judged recovery unlikely.
- The White House and UK attributed it to the Russian military on 15 February 2018.
Caption: ESET's Exaramel backdoor links Industroyer to TeleBots and through them to NotPetya, a vendor assessment.
Notes: Talos M.E.Doc backdoor and the 80 percent figure [20]. Delivery window alleged by the indictment [5]. Spread [22][23]. Ransom ruse [5]. Recovery [23]. Attribution [32][33]. Exaramel [35]. Constitution Day timing [60].

## PART 5 | The losses are in company filings; the book's totals run larger

| Victim | What the primary record says |
|---|---|
| FedEx (TNT Express) | About $300M in the quarter to 31 Aug 2017; about $400M in the first half of FY2018 |
| Merck | About $260M lower 2017 sales; about $285M costs net of insurance |
| Mondelez | $84M incremental expenses; $37M net recoveries in 2022 |
| Heritage Valley Health System | Two hospitals and 60 offices; over $2M (charged) |
| Three named victims together | Nearly $1 billion (charged) |
Caption: The book's more than $10 billion total is Reported; the White House statement says billions and gives no figure.
Notes: FedEx [27][28]. Merck [25][26]. Mondelez [29][30]; linking the 2022 recoveries to insurance litigation is Inferred. Heritage Valley and the combined figure from the indictment [5]. Book's table and the $10 billion figure [31]; White House [32]. Maersk's Ghana domain controller is Reported only [31].

## PART 6 | Olympic Destroyer forged its fingerprints, and analysts caught it

- Preparation began on or about 4 December 2017, the day before the IOC suspended the Russian Olympic Committee (charged).
- PowerShell scripts dumped credentials from more than 16,000 IT Company 1 computers in January 2018.
- At about 7:42 p.m. KST on 9 February 2018 the wiper ran across the domain; 30 Organizing Committee computers were wiped.
- Kaspersky showed the Rich header was forged to match Lazarus code; the indictment says the code emulated Lazarus.
- The actor returned in May and June 2018 with Spiez Laboratory and Salisbury-themed lures.
Caption: Mandiant later put the Olympics attack on APT44 as a response to the doping ban.
Notes: Indictment allegations [5]. Talos named Olympic Destroyer on 12 February [39]. Rich header and lures [40]. Spiez and Salisbury [41]. APT44 [60]. Book's other false trails Reported [71].

## PART 6 | Routers, firewalls and modems became part of the battlefield

Left: 2018 to 2019
- VPNFilter: at least 500,000 devices in at least 54 countries; a kill command could brick them.
- Stage 3 plugins sniffed traffic including Modbus TCP; the FBI asked owners to reboot.
- 28 Oct 2019: about 15,000 Georgian websites defaced and broadcasters interrupted.
Right: 2019 to 2022
- Cyclops Blink replaced VPNFilter on WatchGuard devices from June 2019 and survived firmware updates.
- Trend Micro found an ASUS variant, over 150 C2 servers and about 200 victims.
- AcidRain wiped Viasat modems; about 5,800 Enercon wind turbines lost remote monitoring.
Caption: The UK says Russia was almost certainly behind Viasat without naming Sandworm; ATT&CK lists AcidRain under G0034.
Notes: VPNFilter [42][43][44]; attribution moved over time [45][46][14]. Georgia [5][47][72]; UK "almost certainly (95%+)" [47]. Cyclops Blink advisory [48][49]; Trend Micro [50]. Viasat [59]; AcidRain, medium-confidence similarity to VPNFilter's dstr [45].

## PART 7 | In 2022 the playbook returned, but not every wiper was Sandworm's

| Date | Event | Attribution in the record |
|---|---|---|
| 13 Jan 2022 | WhisperGate | Microsoft: DEV-0586, distinct from Sandworm |
| 23 Feb 2022 | HermeticWiper | ESET could not attribute it |
| 14 Mar 2022 | CaddyWiper | ESET named no actor; later use in C0034 |
| 8 Apr 2022 | Industroyer2 | ESET high confidence Sandworm; CERT-UA: prevented |
| 10 to 12 Oct 2022 | Third blackout via MicroSCADA scilc.exe | Mandiant: Sandworm |
| 11 Oct 2022 | Prestige ransomware | Microsoft: IRIDIUM very likely |
Caption: The 2025 Poland wipers (C0063) carry split attribution in ATT&CK and are not assigned to Sandworm here.
Notes: WhisperGate [51]. HermeticWiper [52]; S0697 and S0698 linked to no group in library data [87]. CaddyWiper [53][75]. Industroyer2 [54][55]. October outage [58]. Prestige [57]. Mandiant: APT44 behind nearly all disruptive operations against Ukraine in the past decade [60]. C0063 [76].

## PART 8 | The record ran on credentials and native tools, not exploits

| CVE | Product | Use in the record | KEV |
|---|---|---|---|
| CVE-2014-4114 | Windows, via Office | Sandworm campaign, 2014 | Added 2022-03-03 |
| CVE-2014-0751 | GE CIMPLICITY HMI | BlackEnergy HMI campaign | Not in KEV |
| CVE-2015-5374 | Siemens SIPROTEC | Industroyer DoS tool (failed) | Not in KEV |
| CVE-2017-0144 | SMBv1, EternalBlue | NotPetya | Added 2022-02-10 |
| CVE-2017-0145 | SMBv1, EternalRomance | NotPetya and Bad Rabbit | Added 2022-02-10 |
Caption: No exploit code in 2015, native commands in 2016 and the vendor's own SCADA binary in 2022 (Inferred).
Notes: CVE table [63][64][65][8][66][11][12][22][23][24][37]. CVE-2013-3906 is cited on G0034's T1203 row but NVD was not opened [14]. Credentials and native tools [2][9][58]. The NSA Exim advisory (CVE-2019-10149) was not opened for this study.

## PART 9 | The indictment charges the core record; the book mostly holds up

Left: United States v. Andrienko et al.
- W.D. Pa. Criminal No. 20-316, filed 15 October 2020; seven counts.
- Charges cover 2015 and 2016 grids, the Ministry of Finance, the French campaign, NotPetya, PyeongChang, OPCW and DSTL, and Georgia.
- Charges are allegations; no defendant has been tried.
Right: The book against the record
- Confirmed in substance: the remote operators, flooded call centers and firmware sabotage.
- More cautious primaries: BlackEnergy's role in 2015, the 2016 damage intent.
- Reported only: the $10 billion total and the Ghana domain controller.
Caption: Bad Rabbit does not appear in the 2020 indictment; the UK attributed it to the GRU on 4 October 2018.
Notes: Indictment and counts [5]; FBI wanted notice [73]. Book editions [61]; excerpts [62][31][71]. Book verdicts from the Part 10 table [1][2][9][32]. Bad Rabbit [34][5].

## MITRE MAPPINGS | 78 Enterprise and 49 ICS techniques bound to dated events

| Id | Technique | Dated event |
|---|---|---|
| T1566.001 | Spearphishing Attachment | 2015 Office attachments; PyeongChang lures |
| T1195.002 | Compromise Software Supply Chain | M.E.Doc, 2017 |
| T1110 | Brute Force | 2016 scripted RPC authentication |
| T1505.003 | Web Shell | Neo-REGEORG, 2022 |
| T1542.002 | Component Firmware | Cyclops Blink |
| T1203 | Exploitation for Client Execution | CVE-2014-4114, 2014 |
Caption: Two Navigator layers: Enterprise (78) and ICS (49); scores mean a dated binding, not severity. MITRE notice in the notes.
Notes: Objects and techniques [14][15][16][17][18][19][75][77][78][79][80][81][82][83][87]. CAPEC pairings from the library data [87]. Top ICS mitigations: M0930 (17), M0807 (12), M0810 (11), M0953 (9) [86]. Top D3FEND: D3-NTF covers 23 of the 49 ICS techniques [87]. Revoked T1070.001 is now T1685.005 and T1562.004 is now T1686 [87]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Identity, Group Policy and edge devices are where Sandworm wins

Left: Watch
- Domain account creation, privilege grants and event-log disablement; in 2016 all three took a minute.
- Group Policy changes: HermeticWiper, CaddyWiper and Prestige were all pushed through it.
- What updaters launch: EzVit.exe ran NotPetya's command line.
Right: Harden
- Multi-factor authentication on every path into the control network.
- Enclaves, no modems, data diodes and gold-disk restoration plans.
- Inventory routers and firewalls; close management interfaces you do not need.
Caption: Allowlisting alone would not have stopped the 2022 outage, which used the vendor's own scilc.exe (Inferred).
Notes: Identity [1][5][9][23]. GPO [52][55][57][58]. Updaters [20][22]. MFA recommendation Inferred from [1][2][5]. CISA advice [1][10]. Edge devices [42][44][45][48]. Allowlisting and D3-PSA [58]. SMBv1 patching and credential theft [23].

## CROSS-CUTTING THEMES | Learn by hand, automate, then wipe the way back

- **Learn by hand, then automate.** Operators clicked through DMS screens in 2015, Industroyer spoke the protocols in 2016, and Industroyer2 shipped per-substation configs (Inferred).
- **Destruction follows disruption.** Every grid attack ended with a wiper aimed at recovery as much as at data.
- **Disguise is part of the payload.** NotPetya and Prestige posed as ransomware and Olympic Destroyer as Lazarus code.
- **The blast radius is not the target.** NotPetya was aimed at Ukraine, yet its largest recorded losses were at FedEx, Merck and Mondelez.
- **Overstated and understated.** The $10 billion total and every 2022 wiper as Sandworm's are overstated; the reliance on credentials is understated.
Notes: Learn then automate [2][11][55]. Wipers [1][11][54][58]. Disguise [5][23][40][57]. Blast radius [33][25][28][29]. Overstated and understated [32][25][26][9][51][52][53][2][58]. Library corrections from Part 12 [5][52][53][55][79][87].
