# Slide plan: The Year 2016 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2016.md
- Cover title: The Year 2016 / in Intrusions / A Dated Record
- Subtitle: Hack and leak, a bank heist over SWIFT, an IoT flood and a grid attack
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2016.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Most of the year's intrusions turned on a credential

- **Hack and leak:** GRU and SVR intrusions into a US political party, then publication.
- **A heist over SWIFT:** $951 million attempted from Bangladesh Bank's New York Fed account, $81 million lost.
- **IoT floods:** Mirai logged in with factory passwords and threw 620 Gbps and more at its targets.
- **A second winter outage in Ukraine,** this time with malware that spoke the grid's own protocols.
- **Governments moved from warning to naming:** a joint statement in October, sanctions and the JAR in December.
Caption: Grades: agencies, courts (as allegations), regulators, victims, vendors and CVE, NVD and KEV records Confirmed; press Reported.
Notes: Election intrusions [1][3][5]. Bangladesh Bank, BAE and DOJ figures [26][29]. Mirai [62][63]. Ukraine, ESET "highly probable" [18][19]. October statement [3]; sanctions and JAR [11][12][13][1]. The credential theme is the study's reading (Inferred) of [1][5][63][32][58].

## KEY FACTS | The largest theft, flood and disclosures of the year

Stat: $81M | lost of $951M attempted at Bangladesh Bank
Stat: 620 Gbps | Mirai's flood on 20 September
Stat: 1B+ | Yahoo accounts in the December disclosure
Stat: 60 | CVE-2016 ids in KEV, none added in 2016
- Ransomware reported to the FBI in 2016: 2,673 complaints and $2,431,261 in losses.
- OVH saw at least 1.1 Tbps, possibly 1.5 Tbps, in late September.
- The US answer on 29 December: nine sanctioned, 35 officials expelled, two compounds closed.
Notes: Bangladesh Bank, BAE; Treasury gives about $80 million stolen and $851 million attempted [26][27][29]. Mirai [62][63]. Yahoo, 500 million in September and more than one billion in December [80][81]. KEV count Inferred from catalog 2026.11.10 [65]. IC3 [51]. Sanctions and expulsions [11][12].

## PART 1 | The year in date order, from SWIFT to sanctions

| Date | Event |
|---|---|
| Feb | Bangladesh Bank SWIFT transfers attempted |
| 31 Mar | TA16-091A: Locky in hospitals |
| 12 Apr | Stolen DCCC credentials used (allegation) |
| 14 Jun | CrowdStrike names two bears in the DNC |
| 25 Jul | No More Ransom launches |
| 15 Aug | Cisco alerted to Shadow Brokers material |
| 20 Sep | 620 Gbps flood hits KrebsOnSecurity |
| 7 Oct | DHS and ODNI joint statement |
| 17 Nov | Shamoon 2 wipe time in Saudi Arabia |
| 17 Dec | Part of Kyiv without power for an hour |
| 29 Dec | Sanctions, expulsions and the JAR |
Notes: Bangladesh [26]. TA16-091A [49]. Indictment [5]. CrowdStrike [7]. No More Ransom [54]. Cisco [47]. Krebs [62]. Joint statement [3]. Shamoon 2 [32]. Kyiv [18]. Sanctions and JAR [11][12][1].

## PART 2 | Russia stole a party's email and published it

Left: The intrusions
- APT29 in a US political party from summer 2015.
- APT28 from spring 2016 through a fake webmail page.
- 12 April: a DCCC login used; 18 April: the DNC reached.
- WADA: APT28 entered ADAMS through an IOC account.
Right: The record
- 7 October: the IC confident Russia directed it.
- Election-system scanning was not attributed.
- January 2017 ICA: Putin ordered an influence campaign.
- July 2018: 12 GRU officers indicted.
Notes: JAR [1]. CrowdStrike [7]. Indictment allegations [5][6]. WADA [14]; anti-doping indictment [15]. Joint statement [3]. ICA [4]. ATT&CK G0007 and G0016 hold "reportedly" [9][10].

## PART 2 | North Korea moved money with valid SWIFT messages

- **BAE, 25 April:** custom malware worked with SWIFT Alliance Access and registered as a service.
- **The New York Fed, 9 March:** the instructions were fully authenticated by SWIFT under standard protocols.
- **DOJ, September 2018:** Park Jin Hyok charged; the conspiracy allegedly stole $81 million.
- **Treasury, September 2019:** Lazarus, Bluenoroff and Andariel designated; over 36 transfer requests.
- **ATT&CK** lists the heist under APT38 (G0082) and maps DYEPACK's SWIFT record manipulation.
Caption: The messages were valid; the bank sending them was compromised (Inferred).
Notes: BAE [26]. New York Fed [30]. DOJ complaint, an allegation [29]. Treasury [27]. ATT&CK G0082 [28]. Andariel in South Korea's defense ministry, Reported via Treasury [27].

## PART 2 | Wipers, a grid attack and zero-days with no state named

Left: Destructive
- Shamoon 2 wiped at 20:45 on 17 November.
- It spread with stolen, hardcoded administrator credentials.
- Kyiv lost power for about an hour on 17 December.
- ESET: Industroyer's use "highly probable".
Right: Espionage and spyware
- ProjectSauron: more than 30 organizations.
- PROMETHIUM and NEODYMIUM used one Flash zero-day.
- Trident: three iOS zero-days to install Pegasus.
- STRONTIUM ran Flash and Windows kernel zero-days.
Notes: Shamoon 2, Unit 42 named no actor [32][33]. Industroyer; US attribution came in 2020 and 2021 [18][19][23]. ProjectSauron [35][36]. Microsoft [38]. Trident [40][41]. STRONTIUM [43]; the Win32k CVE tie is Inferred [45].

## PART 3 | Ransomware went after hospitals, servers and a transit system

Stat: 2,673 | ransomware complaints to IC3 in 2016
Stat: ~900 | SFMTA office computers hit on 25 November
Stat: 160,000+ | keys in one tool at No More Ransom's launch
- **TA16-091A:** Locky reached hospitals in three countries; Samas came in through web servers.
- **SamSam** exploited JBoss early in 2016, then brute-forced RDP from mid-2016.
- **SFMTA** switched off faregates, never considered paying and restored from backups.
Notes: TA16-091A [49]. FBI PSA, all-time high, per-host pricing [50]. IC3 [51]. SamSam [58][59]. SFMTA [52]. No More Ransom [54][55]. KeRanger in Transmission, Reported [53].

## PART 3 | Bank fraud and crimeware infrastructure drew fines and takedowns

- **Tesco Bank:** 48 hours from 5 November, GBP 2.26 million taken, 8,261 accounts.
- **The FCA fined Tesco Bank** GBP 16.4 million in October 2018.
- **Avalanche:** fast-flux hosting for Citadel, Dridex, Emotet, GozNym and others (TA16-336A).
- **Lurk:** alleged members arrested in Russia in early June (Reported).
- **Bogachev and Belan** designated by Treasury on 29 December.
Notes: Tesco Bank [60][61]. Avalanche, takedown figures not checked [57]. Lurk [56]. Treasury designations under the amended EO 13694 [13].

## PART 4 | Mirai turned factory passwords into the year's largest floods

- **62 default pairs:** Mirai logged into IoT devices with common factory credentials.
- **20 September:** about 620 Gbps against KrebsOnSecurity, with no amplification or reflection.
- **Late September:** at least 1.1 Tbps against OVH; Mirai's source code went public.
- **21 October:** the Dyn outage; Flashpoint saw Mirai take part, without ruling out others (Reported).
- **TA16-288A's first fix:** change default passwords, disable UPnP, buy from secure vendors.
Caption: ATT&CK has no software object for Mirai, so the study binds techniques only.
Notes: Krebs [62]. TA16-288A, including the late-November TCP 7547 variant [63]. Dyn, press relaying Flashpoint; TA16-288A does not mention Dyn [64]. No Mirai object in the library data [107].

## PART 5 | Vendors flagged the exploited bugs years before KEV existed

| CVE | What | KEV added |
|---|---|---|
| CVE-2016-0189 | IE scripting engine | listed, ransomware use |
| CVE-2016-4655/6/7 | Trident, iOS | 2022-05-24 |
| CVE-2016-6366 | Cisco ASA SNMP | 2022-05-24 |
| CVE-2016-5195 | Dirty COW, Linux | 2022-03-03 |
| CVE-2016-7855 | Flash use-after-free | 2022-03-03 |
| CVE-2016-7255 | Win32k | 2021-11-03 |
| CVE-2016-6277 | NETGEAR routers | 2022-03-07 |
Caption: 60 CVE-2016 entries in KEV today, the first added in November 2021 (Inferred count).
Notes: MS16-051 [46]. Trident [40][41]. Shadow Brokers and ASA [47][48]. Dirty COW [70]. Flash [71]. MS16-135 [45]. NETGEAR [75]. KEV [65]. Firefox CVE-2016-9079 exploited against Tor Browser users, MFSA 2016-92 [76].

## PART 6 | Old thefts surfaced and a cloud key sat in public code

Left: Disclosed in 2016
- LinkedIn: 100 million members from 2012.
- Dropbox: 68 million credentials from 2012.
- Yahoo: 500 million in September, from 2014.
- Yahoo: over one billion in December, from 2013.
Right: Supply chain and cloud
- Linux Mint's ISO backdoored on 20 February.
- Transmission installers trojanized twice (Reported).
- left-pad: 273 packages unpublished, 2.5 hours.
- Uber: a key in public code opened cloud data.
Notes: LinkedIn [78]. Dropbox [79]. Yahoo [80][81][82]; SEC on Altaba, $35 million [83]. Linux Mint [90]. Transmission [53][91]. left-pad [92]. Uber, $100,000 through its bug bounty, disclosed November 2017 [84][85].

## PART 7 | The year wrote much of the decade's rulebook

| Date | Action |
|---|---|
| 27 Apr | GDPR, applicable from 25 May 2018 |
| 6 Jul | NIS Directive |
| 9 Jul | NATO: cyberspace a domain of operations |
| 26 Jul | PPD-41, US cyber incident coordination |
| 13 Sep | NYDFS proposes its cybersecurity rule |
| 7 Nov | China's Cybersecurity Law (Reported) |
| 29 Nov | UK Investigatory Powers Act |
| 29 Dec | Sanctions, expulsions and JAR-16-20296A |
Caption: Whether the year's incidents caused these rules is not something the sources state.
Notes: GDPR [100]. NIS [101]. NATO [103]. PPD-41 [94]. NYDFS [96]. China, DigiChina translation [106]. Investigatory Powers Act [105]. 29 December [11][12][13][1].

## MITRE MAPPINGS | 63 Enterprise and 22 ICS rows, with credentials at the front

| Id | Technique | 2016 use |
|---|---|---|
| T1598.003 | Spearphishing Link | APT28 fake webmail page |
| T1078.001 | Default Accounts | Mirai logins |
| T1078.002 | Domain Accounts | Shamoon 2 spread |
| T1561.002 | Disk Structure Wipe | Shamoon 2, KillDisk |
| T1565.001 | Stored Data Manipulation | APT38 DYEPACK |
| T1498 | Network Denial of Service | Mirai floods |
| T0831 | Manipulation of Control (ICS) | Industroyer |
Caption: ATT&CK v20.0 ids; 12 groups, 12 software, campaigns C0025 and C0028; two Navigator layers. MITRE notice in the notes.
Notes: Rows [1][9][63][32][33][16][28][62][21][19]. Basis scores in the layers: 100 Listed, 70 Described, 50 Reported, 40 Inferred. C0025 maps the operator tradecraft; the grid impact sits on S0604 [20][21]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The same short list of controls recurs in every 2016 advisory

Left: What 2016 taught
- Replace default and reused credentials.
- Put MFA on webmail, remote access and admin.
- Treat payment-message hosts as tier zero.
- Keep offline, tested backups and use them.
Right: Control systems
- Allowlist applications on ICS hosts.
- Authenticate and authorize ICS commands.
- Separate corporate and control credentials.
- Monitor at ICS boundaries.
Caption: The JAR, TA16-288A, TA17-163A and AA18-337A repeat one list (Inferred).
Notes: Recommendations [63][1][32][58][26][28][52][19]. JAR mitigations [1]. TA17-163A [19]. AA18-337A [58]. The tie between the Bangladesh case and the payment-host recommendation is Inferred.

## CROSS-CUTTING THEMES | Theft totals describe disclosure, not intrusion

- **Hack and leak became policy:** theft paired with publication, answered by sanctions and a report.
- **Trust in the message, not the sender:** SWIFT, signed installers and Linux Mint's own page.
- **Old thefts, new disclosures:** LinkedIn, Dropbox, Yahoo and OPM surfaced in 2016.
- **Overstated:** "Russia hacked the election systems", "Mirai took down the internet", the "$951 million" heist.
- **Understated:** the 2015 start of the election intrusions, and Ukraine's impact in the ATT&CK record.
Notes: Hack and leak [3][5][14][11][1]. Trust [30][53][91][90]. Disclosure lag [78][79][80][81][95][84]. Overstated [3][5][4][63][64][26][27][29]. Understated [1][4][20][21]. The readings are the study's (Inferred).
