# Iran-Attributed Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Other state-linked threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [MuddyWater group page](/mitre/groups/G0069.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, threat hunters, vulnerability managers, OT engineers and healthcare security teams

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 77 min (17,676 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a graded, dated account of which Iranian services, contractors and ATT&CK groups the public record names, how they got in (known edge-device flaws, password spraying, MFA fatigue and exposed controllers), where healthcare appears, and what the advisories say to patch, hunt and harden

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the actors and their sponsors](#part-1-the-actors-and-their-sponsors), [Part 8: the defender view](#part-8-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Actors](/THREAT_ACTORS.md), [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Defenders who have spent the last decade cleaning up after Iranian operators tend to describe the same few mornings. A VPN appliance that was patched months ago turns out to have handed out credentials before the patch. A water utility's controller screen shows a defacement message instead of tank levels. A hospital's building-management network shows a login nobody made. A university research group finds its mail read by someone who registered a look-alike login page. A medical technology company's devices are wiped, reportedly through its own device-management console. This study gathers the public record behind those mornings in one place, dates every event, names the agency or vendor that published it, and grades every claim by the source that supports it.

The record supports five plain statements. First, Iranian state cyber activity runs through two services and a ring of contractors: the US and allied governments attribute named clusters to the Ministry of Intelligence and Security (MOIS) and to the Islamic Revolutionary Guard Corps (IRGC), including its Cyber-Electronic Command, and the advisory, court and sanctions record names the front companies and contractors that did the work (Part 1; **Confirmed**, Treasury, FBI and CISA primaries). Second, the way in is rarely exotic: across eight joint advisories from 2020 to 2024 the actors used known, already-patched flaws in VPNs, firewalls, Exchange and Log4j, password spraying and MFA push fatigue, and internet-facing controllers left on default passwords (**Confirmed**); all but one of the 20 IT CVEs those advisories name are in CISA's Known Exploited Vulnerabilities catalog, each flagged for known ransomware use (**Confirmed**, KEV 2026.11.03). Third, the purpose has widened over time, from espionage and contractor data theft, to brokering access for ransomware crews, to disrupting operational technology, with destructive wiper attacks recurring from 2012 to 2026 (**Inferred** from the dated record). Fourth, healthcare is in the record repeatedly, usually because hospitals run the same exposed edge devices and controllers as everyone else: a US children's hospital in June 2021, US healthcare facilities among the Pioneer Kitten victims, healthcare among the 2023 to 2024 brute-force victims, Israeli hospitals during the 2023 war, as Israel's government records it, and medical research staff targeted for credential theft (**Confirmed**; the Israeli hospital cases are Confirmed only as Israel's own statements). Fifth, in March 2026 a persona the US government ties to MOIS claimed a wiper attack on the medical technology company Stryker, which its SEC filing describes as a global disruption to its Microsoft environment; prosecutors say Maryland hospitals and emergency services were affected (filing **Confirmed**; attribution and impact **Reported**).

What this means for a security program is practical. Patch internet-facing appliances against the KEV list and then hunt, because AA24-241A warns that patching alone may not be enough on a device that was vulnerable, AA22-320A says to treat late-patched Horizon servers as compromised, and AA20-259A says to rebuild compromised NetScaler devices. Treat password spraying, MFA fatigue and new MFA device registrations as intrusion signals, not help-desk noise. Take controllers, HMIs and building systems off the public internet and off default passwords, including the HVAC, water and life-safety systems inside hospitals. And treat device-management consoles as tier-zero systems: the Stryker reporting points to a legitimate remote-wipe function, not malware, as the weapon (**Inferred** from the SEC filing and press reporting).

Evidence grade: the advisories, sanctions releases, FBI records, ATT&CK pages and vendor reports are each **Confirmed** against a primary opened on 3 November 2026. Attribution statements are reported at the confidence each source states. Press coverage of the September 2024 DOJ announcement, the 2026 indictments, the 2026 Stryker attack and the August 2026 sanctions is **Reported**, because the DOJ and Treasury releases for those events could not be opened.

### Key facts at a glance

| Field | Value |
|---|---|
| Scope | Activity that a government, a vendor or MITRE ATT&CK attributes to the Iranian state, its intelligence services or its contractors, from the 2011 to 2013 bank DDoS campaign to October 2026 |
| ATT&CK record (v20.0) | 21 groups whose own description ties them to Iran, the Iranian government, the IRGC or MOIS: 19 Enterprise groups, [`G1027`](https://attack.mitre.org/groups/G1027/) CyberAv3ngers (ICS only) and [`G1029`](https://attack.mitre.org/groups/G1029/) UNC788 (Mobile only); four Iran-nexus campaigns ([`C0010`](/mitre/campaigns/C0010.md), [`C0038`](/mitre/campaigns/C0038.md), [`C0042`](/mitre/campaigns/C0042.md), [`C0044`](/mitre/campaigns/C0044.md)) |
| Sponsors named by governments | MOIS (MuddyWater, APT39 through Rana Intelligence Computing, the 2022 Albania attack, the Handala, Homeland Justice and Karma personas (DOJ, as reported)); IRGC (Mabna Institute, Najee Technology and Afkar System Yazd, Emennet Pasargad, the Cyber-Electronic Command and CyberAv3ngers, the 2024 campaign hack-and-leak) |
| Largest ATT&CK records | Magic Hound [`G0059`](/mitre/groups/G0059.md) 78 techniques, OilRig [`G0049`](/mitre/groups/G0049.md) 76, MuddyWater [`G0069`](/mitre/groups/G0069.md) 68, NIMBUS MANTICORE [`G1059`](/mitre/groups/G1059.md) 65, VOID MANTICORE [`G1055`](/mitre/groups/G1055.md) 63 (library data) |
| Combined technique footprint | 260 distinct Enterprise techniques across the 19 groups and eight joint advisories; 24 ATT&CK for ICS techniques across CyberAv3ngers, OilRig and APT33 |
| Most-reported techniques | Obtain Capabilities: Tool `T1588.002`, PowerShell `T1059.001`, Ingress Tool Transfer `T1105`, LSASS Memory `T1003.001`, Scheduled Task `T1053.005`, Exploit Public-Facing Application `T1190`, Archive via Utility `T1560.001` |
| Exploited CVEs (joint advisories) | 20 IT CVEs from Pulse Secure, Citrix, F5, Fortinet, Exchange, Netlogon, Log4j, Ivanti, PAN-OS and Check Point; 19 are in KEV, all with known ransomware use; plus Unitronics CVE-2023-6448 |
| Healthcare in the government record | AA20-259A, AA21-321A (a US children's hospital, June 2021), AA23-335A, AA24-241A, AA24-290A, the June 2025 fact sheet |
| US legal action | Indictments of 2016 (ITSecTeam and Mersad), 2018 (Mabna Institute; SamSam, a criminal case), 2019 (Witt), 2022 (Ahmadi and others), 2024 (IRGC-CEC front company staff; the campaign hack-and-leak), 2026 (Handala domain seizure; an expanded Mabna indictment) |
| Latest public activity | Iranian-affiliated tampering with Rockwell, Schneider and Siemens PLCs since March 2026 (AA26-097A, revised 22 July 2026); NIMBUS MANTICORE added to ATT&CK on 1 October 2026 |

### Key findings

- **The government record names the services and their fronts.** CISA, FBI, Cyber Command's CNMF and the UK NCSC call MuddyWater a subordinate element of MOIS; Treasury designated APT39 and its MOIS front Rana Intelligence Computing; Treasury and the FBI tie the Mabna Institute, Najee Technology, Afkar System Yazd, Emennet Pasargad (through its predecessor's 2019 designation) and the Cyber-Electronic Command fronts Mehrsam Andisheh Saz Nik and Dadeh Afzar Arman to the IRGC (**Confirmed** [18] [36] [44] [39] [37] [41]).
- **ATT&CK names a service for only some groups.** Of the 21 Iran-attributed ATT&CK groups, ATT&CK links four to the IRGC (Magic Hound as likely, CyberAv3ngers as suspected) and five to MOIS (Agrius through public reporting, and POLONIUM as a Lebanon-based group coordinating with MOIS); for the other twelve, including OilRig and APT33, it says only Iran or the Iranian government. The library's own Threat Actors page labels OilRig with MOIS and APT33 with the IRGC, which ATT&CK v20.0 does not do (**Confirmed** [1] [14]).
- **Edge devices and passwords are the front doors.** The joint advisories show the same entry points from 2020 to 2024: Pulse Secure, Citrix, F5, Fortinet, Exchange ProxyShell, VMware Horizon with Log4Shell, Ivanti, PAN-OS and Check Point flaws, then password spraying and MFA push bombing (**Confirmed** [15] [17] [19] [21] [24] [25]).
- **Access is sold and shared.** Pioneer Kitten (Fox Kitten) brokered network access and worked directly with NoEscape, RansomHouse and ALPHV/BlackCat affiliates for a share of ransoms. The FBI assesses the group serves the Government of Iran but that the ransomware side work is likely not sanctioned (**Confirmed** [24]). The 2023 to 2024 brute-force actors likely sold the access they gained (**Confirmed** [25]).
- **Destruction comes in personas.** The 2022 attack on Albania's government, claimed by "HomeLand Justice", is attributed to Iranian state actors by the US, UK and Microsoft, with MOIS named by Treasury and Check Point; the EU condemned it without naming Iran, and Albania cut diplomatic ties (**Confirmed** [20] [52] [60] [38] [75] [54]; ties cut **Reported** [94]). The same MOIS-linked operator, tracked by ATT&CK as VOID MANTICORE, is tied by Check Point to the Handala persona that claimed the March 2026 Stryker attack (**Confirmed** [6] [76]).
- **Operational technology is a target in its own right (Inferred).** CyberAv3ngers, which Treasury and Rewards for Justice tie to the IRGC Cyber-Electronic Command, compromised at least 75 Unitronics PLC and HMI devices from November 2023 (**Confirmed** [23] [40] [51]); in 2026 an Iranian-affiliated actor manipulated project files and HMI displays on Rockwell, Schneider and Siemens PLCs and, in one case, disabled shutdown and alarm logic (**Confirmed** [29]).
- **Healthcare is hit mostly through shared infrastructure (Inferred).** The authors of AA21-321A assess the actors exploit known vulnerabilities rather than choosing sectors, and they reached the children's hospital's networks by exploiting a Fortigate appliance (**Confirmed** [17]). Research and pharmaceutical targeting is a vendor-reported theme: TA453 against medical researchers, APT42 against pharmaceutical firms in March 2020, Peach Sandstorm against pharmaceutical targets in 2023 (**Confirmed** [79] [64] [71]).
- **The library's data is a little behind ATT&CK in two places.** The live VOID MANTICORE page lists 75 technique rows against the library's 63, and the live CyberAv3ngers page 19 ICS rows and three software entries against the library's 17 and none (**Confirmed** for the counts [6] [12] [1]; the cause is **Inferred**).

### Top recommendations

1. Patch every internet-facing VPN, firewall, mail server and remote-access gateway on the KEV list first, then hunt on the ones that were exposed. AA24-241A says patching alone may not be enough on a device that was vulnerable; AA22-320A says to treat VMware Horizon servers not patched promptly as compromised; AA20-259A says to rebuild compromised NetScaler devices (**Confirmed** [24] [21] [15]).
2. Treat identity noise as intrusion. Alert on many failed logins, one source IP across many accounts, impossible travel, MFA push floods and MFA device registrations from unexpected devices, and move administrators to phishing-resistant MFA (**Confirmed** guidance [25]). Pair this with the library's [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) countermeasures.
3. Get controllers and building systems off the internet and off default passwords. Disconnect OT and ICS assets from the public internet, put any remote access behind a VPN or gateway with MFA, change default ports and passwords, keep PLCs in run mode, and keep tested backups of controller logic (**Confirmed** guidance [23] [27]). In hospitals, start with HVAC, water, life-safety and building-automation systems, as the American Hospital Association advises (**Reported** [82]).
4. Watch for the access broker's toolkit. Unexpected AnyDesk, MeshCentral, Ligolo and ngrok, PowerShell Web Access enabled on servers, new local and domain accounts, new scheduled tasks and processes reading LSASS are the leads the advisories publish (**Confirmed** [24] [21]).
5. Protect device-management and identity consoles as tier-zero systems. The Stryker reporting points to a remote-wipe function in a management console, and the company's filing found no ransomware or malware (**Reported** [93]; **Confirmed** [59]; the link between them is **Inferred**). Limit who can issue fleet-wide wipe or reset actions, require approval for bulk actions, and log them to a place the console's own administrators cannot change (**Inferred** recommendation).
6. Plan for BitLocker abuse. Back up BitLocker recovery keys offline and alert on unexpected BitLocker activation (**Confirmed** guidance [19]).

## Scope and method

This study covers activity that a government, a security vendor or MITRE ATT&CK attributes to the Iranian state, to one of its services, or to a contractor or front company working for them, from the 2011 to 2013 DDoS campaign against US banks through the reporting available on 3 November 2026. It draws on five kinds of source: US and allied government advisories, sanctions releases, court records and FBI wanted notices; security vendor reports; the MITRE ATT&CK pages for the groups and campaigns; the CISA Known Exploited Vulnerabilities (KEV) catalog; and the TeamStarWolf library's own data files at commit `e85b559` (ATT&CK v20.0). Every source in the Sources table was opened on 3 November 2026.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the agency, court, vendor or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution at the confidence it states; it does not upgrade that confidence |
| Reported | Only a secondary source (press, a trade association, or a scanned filing whose text could not be read) was available |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

This study grades by source type (primary opened versus secondary only), the scheme the newer case studies use; under the case-studies README's original scheme a single vendor's report would read as Reported.

Four rules govern the names. The study says which name each source uses ("Microsoft's Peach Sandstorm", "Mandiant's APT42") instead of merging labels, and gives the ATT&CK object alongside where one exists. A source's own hedge travels with its claim ("assessed", "moderate confidence", "suspected"). Criminals who happen to be Iranian are kept apart from state actors: the SamSam ransomware operators were indicted as criminals, and neither the FBI nor Treasury alleges a government tie (**Confirmed** [45] [35]). And tradecraft is described at the level the advisories use, by technique name and ATT&CK ID, with no commands, payload strings or exploit details.

Other studies in this series hold neighboring material. Iranian exploitation of Log4Shell appears here only as part of the AA22-257A and AA22-320A record; the vulnerability itself is the subject of the [Log4Shell case study](/case-studies/LOG4SHELL.md). The operation against Iran's enrichment program is the subject of the [Stuxnet case study](/case-studies/STUXNET.md). The [Change Healthcare case study](/case-studies/CHANGE_HEALTHCARE_2024.md) covers the 2024 ALPHV/BlackCat attack on Change Healthcare; AA24-241A names ALPHV among the affiliates Pioneer Kitten worked with, but no source in this study links Pioneer Kitten to that attack. The [ICS attacks and advisories case study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) is the home for the 2024 to 2026 operational technology incidents, including the IOCONTROL reporting and the AA26-097A PLC campaign; this study keeps the actor's dated record and summarizes those events. The 2021 Exchange exploitation that AA21-321A describes is set in its wider context in the [Exchange Marauder case study](/case-studies/EXCHANGE_MARAUDER_2021.md), and the Iranian events of 2019 and 2020 sit beside the year's other intrusions in the [2019](/case-studies/CHRONICLE_2019.md) and [2020](/case-studies/CHRONICLE_2020.md) chronicles. POLONIUM, which the [other state-linked threat actors study](/case-studies/THREAT_ACTORS_OTHER_STATES.md) leaves to this record, is covered here; the [China](/case-studies/THREAT_ACTORS_CHINA.md), [Russia](/case-studies/THREAT_ACTORS_RUSSIA.md) and [United States](/case-studies/THREAT_ACTORS_UNITED_STATES.md) studies hold the other national records in this series.

Some primaries could not be opened on 3 November 2026 and are not cited as opened: the DOJ press releases for the September 2024 campaign hack-and-leak charges, the March 2026 Handala domain seizures and the August 2026 expanded Mabna indictment; the Treasury release of 24 August 2026; the HHS HC3 brief "Iranian Threat Actors and Healthcare" (its hhs.gov PDF returned 403); the DNI's 2015 testimony text; and Israel's INCD notice on Ziv Hospital. The DOJ seizure warrant itself was opened, but it is a scanned PDF with no text layer, so its contents are graded from press reporting. Where this study relies on reporting about one of these, the claim says so.

## Part 1: the actors and their sponsors

### What ATT&CK records

In the library's ATT&CK v20.0 data, 21 groups carry an ATT&CK description that attributes them to Iran, the Iranian government, the IRGC or MOIS, or, for POLONIUM, to coordination with MOIS actors (**Confirmed** [1]). Nineteen are Enterprise groups, each with a generated library page; CyberAv3ngers ([`G1027`](https://attack.mitre.org/groups/G1027/)) exists only in ATT&CK for ICS and UNC788 ([`G1029`](https://attack.mitre.org/groups/G1029/)) only in ATT&CK for Mobile, and the library generates no page for either (**Confirmed** [1]). Inside the library, CyberAv3ngers can be reached through its tool IOControl ([`S9046`](/mitre/software/S9046.md)) and the [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md).

Three keyword hits were read and left out: Strider ([`G0041`](/mitre/groups/G0041.md)), because Iran appears as a victim country; Ferocious Kitten ([`G0137`](/mitre/groups/G0137.md)), because it targets Persian-speaking people inside Iran and ATT&CK makes no state attribution; and HEXANE ([`G1001`](/mitre/groups/G1001.md)), because its own description makes no Iran attribution and it is named as Iran-nexus only in the narrative of the HomeLand Justice campaign (**Confirmed** [1] [13]).

ATT&CK group objects carry no first-seen or last-seen fields, so the "active since" column below comes from each description's own wording (**Confirmed** [1]). Technique and software counts are the library's direct group relationships; the live ATT&CK pages for some groups also roll up campaign relationships (see Part 9).

| ATT&CK group | Other names in ATT&CK v20.0 | Sponsor wording in ATT&CK | Active since (ATT&CK) | Techniques / software (library) |
|---|---|---|---|---|
| [`G0059`](/mitre/groups/G0059.md) Magic Hound | TA453, COBALT ILLUSION, Charming Kitten, ITG18, Phosphorus, Newscaster, APT35, Mint Sandstorm | Iranian-sponsored, likely acting on behalf of the IRGC | 2014 | 78 / 13 |
| [`G0049`](/mitre/groups/G0049.md) OilRig | COBALT GYPSY, IRN2, APT34, Helix Kitten, Evasive Serpens, Hazel Sandstorm, EUROPIUM, ITG13, Earth Simnavaz, Crambus, TA452 | Suspected Iranian group working on behalf of the Iranian government; no service named | 2014 | 76 / 30 (+6 ICS) |
| [`G0069`](/mitre/groups/G0069.md) MuddyWater | Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, MuddyKrill | Subordinate element of MOIS | 2017 | 68 / 21 |
| [`G1059`](/mitre/groups/G1059.md) NIMBUS MANTICORE | UNC1549, TA455, COBALT SMOKEY | State-sponsored espionage group associated with the IRGC | 2021 | 65 / 13 |
| [`G1055`](/mitre/groups/G1055.md) VOID MANTICORE | COBALT MYSTIQUE, Handala Hack, Homeland Justice, Karma, Karmabelow80, BANISHED KITTEN, Red Sandstorm | Operates on behalf of MOIS | mid-2022 | 63 / 0 |
| [`G0087`](/mitre/groups/G0087.md) APT39 | ITG07, Chafer, Remix Kitten | MOIS, through the front company Rana Intelligence Computing | 2014 | 53 / 11 |
| [`G0117`](/mitre/groups/G0117.md) Fox Kitten | UNC757, Parisite, Pioneer Kitten, RUBIDIUM, Lemon Sandstorm | Suspected nexus to the Iranian government | 2017 | 41 / 5 |
| [`G1044`](/mitre/groups/G1044.md) APT42 | none listed | Iranian-sponsored; tracked separately from Magic Hound by the originating vendor | 2015 | 33 / 2 |
| [`G0064`](/mitre/groups/G0064.md) APT33 | HOLMIUM, Elfin, Peach Sandstorm | Suspected Iranian group; no service named | 2013 | 31 / 16 (+3 ICS) |
| [`G1030`](/mitre/groups/G1030.md) Agrius | Pink Sandstorm, AMERICIUM, Agonizing Serpens, BlackShadow | Public reporting links it to MOIS | 2020 | 22 / 9 |
| [`G1012`](/mitre/groups/G1012.md) CURIUM | Crimson Sandstorm, TA456, Tortoise Shell, Yellow Liderc | Iranian; no service named | see page | 19 / 1 |
| [`G0077`](/mitre/groups/G0077.md) Leafminer | Raspite | Iranian; no service named | see page | 17 / 4 |
| [`G0122`](/mitre/groups/G0122.md) Silent Librarian | TA407, COBALT DICKENS | Affiliated with the Mabna Institute, acting for the IRGC | 2013 | 13 / 0 |
| [`G1009`](/mitre/groups/G1009.md) Moses Staff | DEV-0500, Marigold Sandstorm | Suspected Iranian; no service named | see page | 12 / 4 |
| [`G0052`](/mitre/groups/G0052.md) CopyKittens | none listed | Iranian; no service named | see page | 8 / 4 |
| [`G1005`](/mitre/groups/G1005.md) POLONIUM | Plaid Rain | Lebanon-based, coordinating with MOIS actors | see page | 7 / 2 |
| [`G0130`](/mitre/groups/G0130.md) Ajax Security Team | Operation Woolen-Goldfish, AjaxTM, Rocket Kitten, Flying Kitten, Operation Saffron Rose | Iranian; no service named | 2010 | 6 / 2 |
| [`G0003`](/mitre/groups/G0003.md) Cleaver | Threat Group 2889, TG-2889 | Iranian; no service named | see page | 5 / 4 |
| [`G0043`](/mitre/groups/G0043.md) Group5 | none listed | Iran nexus suspected, attribution "not definite" | see page | 4 / 2 |
| [`G1027`](https://attack.mitre.org/groups/G1027/) CyberAv3ngers | Soldiers of Soloman | Suspected IRGC-affiliated | 2020 | 17 ICS / 0 |
| [`G1029`](https://attack.mitre.org/groups/G1029/) UNC788 | none listed | Iranian; no service named | see page | 1 Mobile / 1 |

Sources: [1] for the table; the sponsor wording for Magic Hound, OilRig, MuddyWater, NIMBUS MANTICORE, VOID MANTICORE, APT39, Fox Kitten, APT42, APT33, Agrius and CyberAv3ngers was also read on the live pages [2] to [12]; the alias lists are from the library data [1] (**Confirmed**).

### How the sponsors split

Read side by side, ATT&CK's sponsor wording sorts the set three ways (**Confirmed** [1]):

- **IRGC**: Magic Hound (likely), Silent Librarian (through the Mabna Institute), NIMBUS MANTICORE, CyberAv3ngers (suspected).
- **MOIS**: MuddyWater, APT39, VOID MANTICORE, Agrius (through public reporting), and POLONIUM as a Lebanon-based group that coordinates with MOIS actors.
- **Iran, with no service named**: OilRig, APT33, CopyKittens, Leafminer, Fox Kitten, Cleaver, Group5 (not definite), Ajax Security Team, Moses Staff (suspected), CURIUM, APT42 and UNC788.

Vendors go further than ATT&CK in places. Mandiant estimates with moderate confidence that APT42 operates for the IRGC Intelligence Organization, and Check Point says Educated Manticore (its name for the APT42 and Charming Kitten activity) is believed to work for the IRGC-IO (**Confirmed** [64] [77]). Microsoft assessed with moderate confidence that the initial-access actors behind the 2022 Albania attack are linked to EUROPIUM, which it says is publicly linked to MOIS; ATT&CK lists EUROPIUM as an OilRig alias but names no service for OilRig (**Confirmed** [60] [1] [3]). Google's Threat Analysis Group calls APT42 IRGC-associated (**Confirmed** [74]).

### The contractors and fronts on the government record

The US government record puts names to the organizations that did the work. None of these are ATT&CK objects; the ATT&CK group each is closest to is given where a primary draws the link.

| Organization | Service | What the record says | Closest ATT&CK object | Sources |
|---|---|---|---|---|
| ITSecTeam and Mersad | IRGC and the Iranian Government | Seven managers or employees indicted for DDoS attacks on the US financial sector, 2011 to 2013; ATT&CK says Havij is distributed by an Iranian security company named ITSecTeam (that it is the same company is Inferred) | Ajax Security Team uses Havij ([`S0224`](/mitre/software/S0224.md)) (Inferred link) | [43] [1] |
| Mabna Institute | IRGC | Contractor working at the behest of the IRGC; data theft from about 144 US universities, 176 universities in 21 other countries, five US government agencies and 36 US companies (2018 figures) | Silent Librarian [`G0122`](/mitre/groups/G0122.md) | [44] [34] [1] |
| Rana Intelligence Computing Company | MOIS | Front company for APT39; designated with APT39 and 45 individuals in 2020 | APT39 [`G0087`](/mitre/groups/G0087.md) | [36] [7] |
| Net Peygard Samavat, renamed Emennet Pasargad, operating in 2024 as Aria Sepehr Ayandehsazan | IRGC (Net Peygard designated in 2019 for supporting the IRGC-EWCD) | 2020 voter-intimidation operation; 2023 Charlie Hebdo leak (Microsoft: NEPTUNIUM); 2024 Olympics display compromise (FBI: Cotton Sandstorm) | none | [37] [70] [30] |
| Najee Technology Hooshmand Fater LLC and Afkar System Yazd Company | IRGC | Ransomware and BitLocker extortion; Treasury says the activity is partly attributable to intrusion sets private firms call APT35 and Charming Kitten | Magic Hound [`G0059`](/mitre/groups/G0059.md) (through the APT35 alias) | [19] [39] |
| Danesh Novin Sahand | Government of Iran (FBI assessment) | Cover company used by Pioneer Kitten | Fox Kitten [`G0117`](/mitre/groups/G0117.md) | [24] |
| IRGC Cyber-Electronic Command, including its head Hamid Reza Lashgarian | IRGC | Six officials designated over the Unitronics PLC defacements | CyberAv3ngers [`G1027`](https://attack.mitre.org/groups/G1027/) | [40] [51] |
| Mehrsam Andisheh Saz Nik and Dadeh Afzar Arman | IRGC Cyber-Electronic Command | Multi-year spear-phishing and malware campaign against more than a dozen US companies and government entities | none named | [41] |

The link from Najee and Afkar to Magic Hound rests on Treasury's statement about APT35 and Charming Kitten and on ATT&CK listing both names as Magic Hound aliases; Treasury does not name the ATT&CK object (**Inferred** from [39] [1]).

## Part 2: the operational record

One row per dated event, report or government action, oldest first. "Actor" is the name the source uses; the ATT&CK object follows where one exists. A report's publication date is given where the activity itself is not dated more precisely.

| Date | Event | Actor (source's name; ATT&CK) | Grade | Sources |
|---|---|---|---|---|
| 2010 | Earliest activity in the ATT&CK set | Ajax Security Team, [`G0130`](/mitre/groups/G0130.md) | Confirmed | [1] |
| 2011 to 2013 | Coordinated DDoS attacks on the US financial sector | ITSecTeam and Mersad staff, working for the Iranian Government including the IRGC | Confirmed | [43] |
| 2012 | Shamoon wiper first used, by a group calling itself Cutting Sword of Justice; Unit 42 later describes the 2012 target as a Saudi energy company | Shamoon [`S0140`](/mitre/software/S0140.md) | Confirmed | [1] [67] |
| 2013 | Earliest activity for APT33 and Silent Librarian; the 2026 superseding Mabna indictment covers intrusions from 2013 | APT33 [`G0064`](/mitre/groups/G0064.md); Silent Librarian [`G0122`](/mitre/groups/G0122.md) | Confirmed (ATT&CK); Reported (2026 indictment) | [1] [88] |
| 2014-02 | Attack on Las Vegas Sands; DNI Clapper told the Senate Armed Services Committee on 2015-02-26 that Iran was behind it | not named | Reported | [96] |
| 2015 (fall) to 2016-05 | Helminth backdoor delivered by Excel lures, 4 to 12 May 2016, against Saudi financial and technology organizations, linked to a fall 2015 wave; Unit 42 calls the Iranian-operator indicators compelling but easily falsified | Unit 42's OilRig, [`G0049`](/mitre/groups/G0049.md); Helminth [`S0170`](/mitre/software/S0170.md) | Confirmed | [66] |
| 2015-12 to 2018 | SamSam ransomware: more than 6 million dollars from victims in critical infrastructure, healthcare, transportation and government; JBoss exploitation (early 2016), then RDP brute force and stolen credentials | Iran-based criminals; no government tie alleged | Confirmed | [45] [32] [35] |
| 2016-01-21 | SDNY indictment of seven ITSecTeam and Mersad employees (date as the FBI record gives it) | as above | Confirmed | [43] |
| mid-2016 to early 2017 | Compromise of a US aerospace organization; targeting of a Saudi aviation conglomerate and a South Korean petrochemical firm; Mandiant had not seen APT33 run destructive operations (report 2017-09-20) | Mandiant's APT33, [`G0064`](/mitre/groups/G0064.md) | Confirmed | [61] |
| 2016-11-17 | Shamoon 2 Disttrack samples set to wipe on this date against at least one Saudi organization; Unit 42 does not attribute it to Iran | Shamoon [`S0140`](/mitre/software/S0140.md) | Confirmed | [67] |
| 2017-11 | CVE-2017-11882 used against a Middle East government organization less than a week after the 14 November 2017 patch (report 2017-12-07) | Mandiant's APT34, loosely aligned with OilRig, [`G0049`](/mitre/groups/G0049.md) | Confirmed | [62] |
| 2018-03-23 | Nine Mabna Institute members announced as indicted (SDNY, 2018-02-07); Treasury sanctions the Institute the same day | Mabna Institute (IRGC); Silent Librarian [`G0122`](/mitre/groups/G0122.md) | Confirmed | [44] [34] |
| 2018-11-26 to 2018-12-03 | SamSam indictment in D.N.J. (2018-11-26), Treasury designation of two men who converted ransom payments (2018-11-28), CISA alert AA18-337A (2018-12-03) | Iran-based criminals | Confirmed | [45] [35] [32] |
| 2019-01-29 | Mandiant names APT39, tracked since November 2014, and assesses with moderate confidence that it supports Iranian national interests, prioritizing telecom and travel | Mandiant's APT39, [`G0087`](/mitre/groups/G0087.md) | Confirmed | [63] |
| 2019-02-13 | Former US Air Force intelligence specialist Monica Witt charged with espionage for Iran; four Iranians charged with a cyber campaign against US counterintelligence personnel | not named | Confirmed | [46] |
| 2019-08 to 2019-09 | More than 2,700 attempts to identify accounts and attacks on 241, including accounts tied to a US presidential campaign; four unrelated accounts compromised (report 2019-10-04) | Microsoft's Phosphorus, [`G0059`](/mitre/groups/G0059.md) | Confirmed | [69] |
| 2020-03 | Targeting of the pharmaceutical sector at the onset of COVID-19 | Mandiant's APT42, [`G1044`](/mitre/groups/G1044.md) | Confirmed | [64] |
| 2020-09-15 | AA20-259A: an Iran-based actor exploits Pulse Secure, Citrix and F5 flaws against US IT, government, healthcare, financial, insurance and media organizations | Pioneer Kitten / UNC757, [`G0117`](/mitre/groups/G0117.md) | Confirmed | [15] |
| 2020-09-17 | Treasury designates APT39, Rana Intelligence Computing and 45 individuals for a campaign against dissidents, journalists and about 15 US companies, mainly travel, across more than 30 countries | APT39, [`G0087`](/mitre/groups/G0087.md) | Confirmed | [36] |
| 2020-09-20 to 2020-10-20 | US state election websites scanned and exploited (20 September to 17 October); voter registration data obtained in at least one state; voter-intimidation emails sent on 20 October (AA20-304A, 2020-10-30) | an Iranian APT (AA20-304A); Treasury's 2021 release describes matching activity by Emennet Pasargad (the match is Inferred) | Confirmed | [16] [37] |
| late 2020 | Pay2Key hack-and-leak, which the FBI assesses was an information operation against Israeli cyber infrastructure, not a ransom operation | Pioneer Kitten; Pay2Key [`S0556`](/mitre/software/S0556.md) | Confirmed | [24] |
| late 2020 to mid-2022 | Watering hole and fake login pages, one spoofing Pfizer, against Israeli government, shipping, energy, aviation and healthcare organizations (report 2022-08-17) | Mandiant's UNC3890 (Iran-linked, moderate confidence); campaign [`C0010`](/mitre/campaigns/C0010.md) | Confirmed | [65] [1] |
| 2020-12 | Credential phishing of fewer than 25 senior staff at US and Israeli medical research organizations specializing in genetics, oncology and neurology (report 2021-03-30) | Proofpoint's TA453, [`G0059`](/mitre/groups/G0059.md) | Confirmed | [79] |
| 2021-02 to 2021-10 | A New Jersey municipality (February), small businesses hit with BitLocker ransom (March and April), transportation, emergency services, education and healthcare practices (June to August), a rural electric utility (October) | IRGC-affiliated group later designated as Najee Technology and Afkar System Yazd | Confirmed | [39] |
| 2021-03 | Fortinet exploitation begins | AA21-321A actors | Confirmed | [17] |
| 2021-05 | HomeLand Justice campaign first seen; initial access to Albanian government networks about 14 months before July 2022, through SharePoint CVE-2019-0604 | VOID MANTICORE, [`C0038`](/mitre/campaigns/C0038.md) | Confirmed | [13] [20] |
| 2021-06 | A Fortigate appliance exploited to reach environmental control networks of a US hospital specializing in healthcare for children; Treasury says the hospital was notified before patient care was affected | AA21-321A actors; IRGC-affiliated per Treasury | Confirmed | [17] [39] |
| summer 2021 | Hackers sponsored by the Iranian government went after Boston Children's Hospital; an intelligence partner tipped the FBI, which notified the hospital, and the threat was mitigated. Press reports the FBI contacted the hospital on 2021-08-03 | not named | Confirmed (FBI); Reported (date) | [50] [95] |
| 2021 | Outer Space campaign | OilRig, [`C0042`](/mitre/campaigns/C0042.md) | Confirmed | [1] |
| 2021-10 | Exchange ProxyShell exploitation begins | AA21-321A actors | Confirmed | [17] |
| 2021-11-17 | AA21-321A (FBI, CISA, ACSC, NCSC): an APT assessed as associated with the government of Iran targets the Transportation and Healthcare and Public Health sectors | AA21-321A actors | Confirmed | [17] |
| 2021-11-18 | Treasury designates Emennet Pasargad and six associates for the 2020 election operation | Emennet Pasargad | Confirmed | [37] |
| 2021-12 and 2022-02 | Log4j exploitation; BitLocker ransom against a US police department and a regional transport company in December 2021 | IRGC-affiliated actors (AA22-257A) | Confirmed | [19] |
| 2022-02 | Log4Shell exploited on an unpatched VMware Horizon server at a Federal Civilian Executive Branch agency, followed by XMRig, Mimikatz, PsExec and ngrok (AA22-320A, 2022-11-16) | likely Iranian government-sponsored actors | Confirmed | [21] |
| 2022 | Juicy Mix campaign | OilRig, [`C0044`](/mitre/campaigns/C0044.md) | Confirmed | [1] |
| 2022-02-24 | AA22-055A (FBI, CISA, CNMF, NCSC): MuddyWater is a subordinate element of MOIS, running campaigns for MOIS since about 2018 against telecom, defense, local government and oil and gas | MuddyWater, [`G0069`](/mitre/groups/G0069.md) | Confirmed | [18] |
| 2022-06-01 | FBI Director Wray describes the thwarted Boston Children's Hospital attack | as above | Confirmed | [50] |
| 2022-07-15 to 2022-07-18 | Destructive attack on the Government of Albania begins on 15 July: a ransomware-style encryptor then the ZeroCleare wiper; HomeLand Justice claims it on 18 July; medical appointment booking among the disrupted services | Iranian state actors (US, UK, Microsoft); VOID MANTICORE [`G1055`](/mitre/groups/G1055.md); ZeroCleare [`S1151`](/mitre/software/S1151.md) | Confirmed | [20] [52] [60] |
| 2022-08-10 | D.N.J. indictment of Mansour Ahmadi, Ahmad Khatibi Aghda and Amir Hossein Nickaein Ravari for intrusion, encryption and extortion from October 2020 to August 2022; Rewards for Justice offers up to 10 million dollars | the IRGC-affiliated Najee Technology and Afkar System Yazd group, per Treasury | Confirmed | [47] [39] |
| 2022-08-17 | Mandiant publishes UNC3890 | UNC3890; [`C0010`](/mitre/campaigns/C0010.md) | Confirmed | [65] |
| 2022-09-06 | Mandiant estimates with moderate confidence that APT42 operates for the IRGC Intelligence Organization, with more than 30 confirmed operations since early 2015 | APT42, [`G1044`](/mitre/groups/G1044.md) | Confirmed | [64] |
| 2022-09-07 | UK condemns the Iranian state for the Albania attack; NCSC assesses Iranian state-linked actors almost certainly responsible. Albania severs diplomatic relations and gives Iranian diplomats 24 hours to leave | as above | Confirmed (UK); Reported (Albania) | [52] [53] [94] |
| 2022-09-08 | EU High Representative expresses solidarity with Albania, together with NATO, and condemns the attack without naming Iran; Microsoft attributes it with high confidence to Iranian government-sponsored actors | as above | Confirmed | [54] [60] |
| 2022-09-09 | Treasury designates MOIS and Minister Esmail Khatib over the Albania attack and leaks, and names MuddyWater as a subordinate element of MOIS | MOIS | Confirmed | [38] |
| 2022-09 | Second wave of attacks on Albanian government networks | HomeLand Justice actors | Confirmed | [20] [13] |
| 2022-09-14 | AA22-257A re-assesses the AA21-321A actors as IRGC-affiliated, operating under Najee Technology and Afkar System Yazd; Treasury sanctions ten individuals and the two companies in a joint action with DOJ and State | IRGC-affiliated actors | Confirmed | [19] [39] |
| 2022-09-20 | NCSC, with US, Australian and Canadian agencies, publicly exposes IRGC-affiliated actors exploiting Fortinet, Exchange and Log4j for ransomware | as above | Confirmed | [55] |
| 2022-09-21 | AA22-264A attributes the Albania attack to Iranian state cyber actors using the HomeLand Justice persona | as above | Confirmed | [20] |
| 2022-11-03 | HHS HC3 publishes the TLP:CLEAR brief "Iranian Threat Actors and Healthcare"; trade coverage says it names Pioneer Kitten, Magic Kitten, Infy and UNC3890 | several | Reported | [81] |
| 2022-11-16 | AA22-320A on the FCEB Log4Shell intrusion | as above | Confirmed | [21] |
| 2023-01-04 | "Holy Souls" leak of Charlie Hebdo customer data (200,000 records claimed); Microsoft believes it was an Iranian government response (report 2023-02-02) | Microsoft's NEPTUNIUM, Emennet Pasargad | Confirmed | [70] |
| 2023-02 to 2023-07 | Password spraying against thousands of organizations, focused on satellite, defense and, to a lesser extent, pharmaceutical targets; exploitation of CVE-2022-47966 and CVE-2022-26134 in a subset of intrusions (report 2023-09-14) | Microsoft's Peach Sandstorm, [`G0064`](/mitre/groups/G0064.md) | Confirmed | [71] |
| 2023-10 onward | Brute force, password spraying and MFA push bombing against healthcare and public health, government, IT, engineering and energy organizations; access likely sold (AA24-290A) | Iranian actors (not named) | Confirmed | [25] |
| 2023-10 to 2023-12 | After 7 October, 43 percent of the Iranian nation-state activity Microsoft tracked targeted Israel; Israel's INCD records hospital targeting as a main trend of the war's cyber dimension | various | Confirmed | [72] [58] |
| 2023-11 | Tailored social engineering against Middle East affairs researchers in Belgium, France, Gaza, Israel, the UK and the US, with the MediaPl and MischiefTut backdoors (report 2024-01-17) | Microsoft's Mint Sandstorm, [`G0059`](/mitre/groups/G0059.md) | Confirmed | [73] |
| 2023-11-22 to 2024-01 | At least 75 Unitronics PLC and HMI devices compromised, 34 of them in US water and wastewater; Microsoft says a PLC at a Pennsylvania water authority was taken offline on 25 November | CyberAv3ngers, [`G1027`](https://attack.mitre.org/groups/G1027/) | Confirmed | [23] [72] |
| 2023-11-28 | CISA alert on exploitation of Unitronics PLCs in water and wastewater, through weak passwords and internet exposure | as above | Confirmed | [22] |
| 2023-12-01 | AA23-335A attributes the CyberAv3ngers persona to IRGC-affiliated actors; healthcare listed among the sectors that use these PLCs | as above | Confirmed | [23] |
| 2023-12-11 | CISA adds Unitronics CVE-2023-6448 to KEV | as above | Confirmed | [33] |
| 2023-12-18 | INCD attributes an attempted attack on Ziv Hospital to Iran and Hezbollah, as footnoted by Israel's Foreign Ministry (the INCD notice itself not opened; Israel is a party to the conflict) | not named | Confirmed (that the Ministry says so) | [57] |
| 2024-01-12 | INCD Alert 1676: groups working with Iranian intelligence attempted operations against Israeli water, energy and IT infrastructure (as cited by Israel's Foreign Ministry) | not named | Confirmed (that the Ministry says so) | [57] |
| 2024-02-02 | Treasury designates six IRGC Cyber-Electronic Command officials, including its head, over the PLC defacements | IRGC-CEC | Confirmed | [40] |
| 2024-04-23 | Treasury designates IRGC-CEC fronts Mehrsam Andisheh Saz Nik and Dadeh Afzar Arman and four individuals; DOJ unseals an indictment of four people the same day, including Alireza Shafie Nasab (as Treasury states) | IRGC-CEC | Confirmed | [41] |
| 2024-05 to 2024-06 | Personal email of roughly a dozen people tied to the Biden and Trump campaigns targeted; the US and Israel about 60 percent of known targeting over six months (report 2024-08-14) | Google TAG's APT42, [`G1044`](/mitre/groups/G1044.md) | Confirmed | [74] |
| 2024-05 onward | Accounts of officials and advisors to a 2024 presidential campaign compromised and the data leaked to media | IRGC members including Masoud Jalili | Confirmed | [42] |
| 2024-07 | Compromise of a French dynamic display provider during the Summer Olympics, and harvesting of IP camera content (advisory 2024-10-30) | Emennet Pasargad as Aria Sepehr Ayandehsazan (Cotton Sandstorm) | Confirmed | [30] |
| 2024-08-19 | ODNI, FBI and CISA attribute the reported compromise of the Trump campaign to Iran | Iran | Confirmed | [31] |
| 2024-08-28 | AA24-241A on Pioneer Kitten's access brokering for ransomware affiliates, 2017 through August 2024 | Pioneer Kitten, [`G0117`](/mitre/groups/G0117.md) | Confirmed | [24] |
| 2024-09-27 | Masoud Jalili, Yasar Balaghi and Seyyed Ali Aghamiri charged in D.D.C.; Treasury designates seven Iranians including Jalili | IRGC-affiliated | Confirmed | [48] [42] [89] |
| 2024-10-16 | AA24-290A on brute force and MFA push bombing (FBI, CISA, NSA, CSE, AFP, ASD's ACSC) | Iranian actors | Confirmed | [25] |
| 2024-12-18 | AA23-335A update: custom ladder logic, renamed devices, disabled upload and download functions, changed default ports, NCSC-observed PLC targeting including in the UK | CyberAv3ngers | Confirmed | [23] |
| 2025-06 (mid) | Spear-phishing wave against Israeli journalists, cyber experts and computer science professors after the Iran-Israel conflict (report 2025-06-25) | Check Point's Educated Manticore, [`G1044`](/mitre/groups/G1044.md) and [`G0059`](/mitre/groups/G0059.md) | Confirmed | [77] |
| 2025-06-27 | Health-ISAC warns of rising Iranian threats to healthcare and of state actors posing as hacktivists | various | Reported | [84] |
| 2025-06-30 | CISA, FBI, DC3 and NSA fact sheet: no sign of a coordinated campaign in the US yet, but heightened risk, especially for Defense Industrial Base firms with Israeli ties | various | Confirmed | [26] [27] [28] |
| 2025-12-02 | MuddyViper backdoor and a Snake-game-themed loader against Israeli critical infrastructure and one Egyptian target | ESET's MuddyWater, [`G0069`](/mitre/groups/G0069.md); MuddyViper [`S9032`](/mitre/software/S9032.md) | Confirmed | [78] |
| late 2025 to early 2026 | Starlink used for command and control | MuddyWater, [`G0069`](/mitre/groups/G0069.md) | Confirmed | [4] |
| 2026-02 (late) | Pay2Key ransomware intrusion at a US healthcare organization; no evidence of exfiltration | Beazley Security's Pay2Key (Iranian government-linked) | Confirmed | [80] |
| 2026-02-28 | US-Israel strikes mark the start of an Iranian retaliatory campaign; a 47-day near-total Iranian internet outage follows; state actors moved to Starlink (high confidence) | Iranian state actors (Unit 42) | Confirmed | [68] |
| 2026-03-02 | NCSC: likely no significant change in the direct threat to the UK, but almost certainly a heightened indirect risk for organizations with a Middle East presence | Iran-linked actors (NCSC assessment) | Confirmed | [56] |
| 2026-03-03 | FBI Cyber Division reminds critical infrastructure to apply the June 2025 mitigations; AHA tells hospitals to inventory internet-facing OT | FBI, AHA | Reported | [82] |
| 2026-03 onward | Tampering with internet-exposed Rockwell/Allen-Bradley, Schneider Electric and Siemens PLCs in government facilities, water and energy; project files and HMI displays manipulated; in one case shutdown and alarm logic disabled | an Iranian-affiliated APT (AA26-097A); Unit 42's CL-STA-1128 (Cyber Av3ngers) targeting Rockwell OT | Confirmed | [29] [68] |
| 2026-03-11 | Stryker identifies a cybersecurity incident causing a global disruption to its Microsoft environment, with no indication of ransomware or malware; Handala claims a wiper attack | Handala, which Check Point ties to Void Manticore, [`G1055`](/mitre/groups/G1055.md) | Confirmed (8-K, Check Point); Reported (claims) | [59] [76] [93] |
| 2026-03-19 | DOJ seizes four domains under a D. Md. warrant (case 1:26-mj-00683-CDA); reporting says DOJ attributes the Handala, Homeland Justice and Karma Below personas to MOIS and that Maryland hospitals and emergency services were affected | MOIS | Confirmed (filing exists); Reported (contents) | [49] [90] [91] [92] |
| 2026-04-07 | AA26-097A published (revised 2026-07-22) | as above | Confirmed | [29] |
| 2026-04-20 | ATT&CK creates VOID MANTICORE, whose description names the March 2026 Stryker attack under the Handala Hack persona | [`G1055`](/mitre/groups/G1055.md) | Confirmed | [6] |
| 2026-08-18 | Superseding indictment of 17 Mabna Institute members for intrusions for the IRGC since 2013: 144 US universities, 42 US companies, at least five agencies, more than 31 TB stolen; Behzad Mesri named in the HBO intrusion and extortion | Mabna Institute | Reported | [87] [88] |
| 2026-08-24 | Treasury sanctions five Iranian nationals over a hacking operation reported as directed by MOIS; four also charged in the expanded Mabna case | reported as MOIS | Reported | [86] |
| 2026-10-01 | ATT&CK creates NIMBUS MANTICORE, an IRGC-associated espionage group active since 2021 against aviation, aerospace, telecom, defense and IT organizations | [`G1059`](/mitre/groups/G1059.md) | Confirmed | [5] |

### Reading the record by era

Read together, the US record shows a shift in purpose over fifteen years (**Inferred** from the rows above; no single document states it). From 2011 to about 2020 the visible work is espionage against people the state watches, by MOIS (APT39's travel and telecom collection) and by the IRGC (Magic Hound, likely acting for the IRGC, against journalists and officials), plus IRGC contractor data theft (Mabna's universities), with the bank DDoS campaign as an early disruptive outlier. From about 2020 to 2024 the edge-device clusters turn to access brokering and ransomware, either alongside criminal affiliates (Pioneer Kitten) or with their own BitLocker extortion (Najee and Afkar). From late 2023 the IRGC Cyber-Electronic Command and its CyberAv3ngers persona move into operational technology, and MOIS-linked operators run destructive wiper and hack-and-leak operations: Agrius against Israel from 2020, the HomeLand Justice persona against Albania in 2022, and in 2026 the Handala persona against a US medical technology company.

### Where the sources disagree

- **When MuddyWater started.** ATT&CK says since at least 2017; AA22-055A says it has run campaigns for MOIS since about 2018 (**Confirmed** [4] [18]).
- **Whether the children's hospital is Boston Children's.** AA21-321A and Treasury place the access in June 2021; Director Wray describes the Boston Children's attempt as summer 2021, and press puts the FBI's call to the hospital on 3 August 2021. Neither primary says the two are the same event (**Inferred** that they may be).
- **Whether the 2026 PLC actor is CyberAv3ngers.** AA26-097A calls the actor Iranian-affiliated and says the agencies previously reported similar PLC activity by CyberAv3ngers (aka Shahid Kaveh Group), which it ties to the IRGC Cyber-Electronic Command. It does not state that the 2026 actor is CyberAv3ngers (**Confirmed** [29]). Unit 42 does use the Cyber Av3ngers name for its 2026 Rockwell cluster (**Confirmed** [68]).
- **How many Stryker devices were wiped.** Handala claimed more than 200,000; TechCrunch reports tens of thousands. Both are claims or press figures, and Stryker's filing gives no count (**Reported** [93] [91]; **Confirmed** [59]).
- **Who directed the August 2026 sanctioned group.** Press reports Treasury as saying MOIS directed the operation, while the Mabna case it overlaps is an IRGC case. The Treasury release could not be opened, so this study does not resolve it (**Reported** [86]).
- **Shamoon's author.** ATT&CK records the 2012 Shamoon use by a group calling itself Cutting Sword of Justice, which it describes as Iranian; Unit 42's 2016 Shamoon 2 report does not attribute the attack to Iran (**Confirmed** [1] [67]).
- **Albania and the EU.** The US, UK, Microsoft and Treasury name Iran or MOIS; the EU's declaration condemns the attack but names no state (**Confirmed** [20] [52] [60] [38] [54]).

## Part 3: tooling

### ATT&CK software attributed to the Iranian groups

The 19 Enterprise groups use 111 distinct ATT&CK software entries, every one with a generated library page (**Confirmed** [1]). The shared tools are mostly public or dual-use: Mimikatz ([`S0002`](/mitre/software/S0002.md), 8 groups), PsExec ([`S0029`](/mitre/software/S0029.md), 7), LaZagne ([`S0349`](/mitre/software/S0349.md), 4), Empire ([`S0363`](/mitre/software/S0363.md), 3), Net ([`S0039`](/mitre/software/S0039.md), 3) and ftp ([`S0095`](/mitre/software/S0095.md), 3). Two groups each use ngrok ([`S0508`](/mitre/software/S0508.md)), CrackMapExec ([`S0488`](/mitre/software/S0488.md)), ASPXSpy ([`S0073`](/mitre/software/S0073.md)), DEADWOOD ([`S1134`](/mitre/software/S1134.md), APT33 and Agrius), PowerSploit ([`S0194`](/mitre/software/S0194.md)), Pupy ([`S0192`](/mitre/software/S0192.md)) and NBTscan ([`S0590`](/mitre/software/S0590.md)) (**Confirmed** [1]).

| Group | Group-specific families in ATT&CK (selection) | Sources |
|---|---|---|
| OilRig [`G0049`](/mitre/groups/G0049.md) | BONDUPDATER [`S0360`](/mitre/software/S0360.md), Helminth [`S0170`](/mitre/software/S0170.md), POWRUNER [`S0184`](/mitre/software/S0184.md), SideTwist [`S0610`](/mitre/software/S0610.md), RDAT [`S0495`](/mitre/software/S0495.md), Solar [`S1166`](/mitre/software/S1166.md), Mango [`S1169`](/mitre/software/S1169.md), and the wiper ZeroCleare [`S1151`](/mitre/software/S1151.md) | [1] |
| MuddyWater [`G0069`](/mitre/groups/G0069.md) | POWERSTATS [`S0223`](/mitre/software/S0223.md), PowGoop [`S1046`](/mitre/software/S1046.md), Small Sieve [`S1035`](/mitre/software/S1035.md), STARWHALE [`S1037`](/mitre/software/S1037.md), Mori [`S1047`](/mitre/software/S1047.md), MuddyViper [`S9032`](/mitre/software/S9032.md), RustyWater [`S9037`](/mitre/software/S9037.md); remote-management tools ConnectWise [`S0591`](/mitre/software/S0591.md) and RemoteUtilities [`S0592`](/mitre/software/S0592.md) | [1] [18] [78] |
| Magic Hound [`G0059`](/mitre/groups/G0059.md) | CharmPower [`S0674`](/mitre/software/S0674.md), PowerLess [`S1012`](/mitre/software/S1012.md) | [1] |
| APT33 [`G0064`](/mitre/groups/G0064.md) | StoneDrill [`S0380`](/mitre/software/S0380.md), POWERTON [`S0371`](/mitre/software/S0371.md), TURNEDUP [`S0199`](/mitre/software/S0199.md) | [1] |
| Agrius [`G1030`](/mitre/groups/G1030.md) | Apostle [`S1133`](/mitre/software/S1133.md), MultiLayer Wiper [`S1135`](/mitre/software/S1135.md), Moneybird [`S1137`](/mitre/software/S1137.md) | [1] |
| Fox Kitten [`G0117`](/mitre/groups/G0117.md) | Pay2Key [`S0556`](/mitre/software/S0556.md), SystemBC [`S9001`](/mitre/software/S9001.md) | [1] |
| Moses Staff [`G1009`](/mitre/groups/G1009.md) | PyDCrypt [`S1032`](/mitre/software/S1032.md), DCSrv [`S1033`](/mitre/software/S1033.md), StrifeWater [`S1034`](/mitre/software/S1034.md) | [1] |
| APT42 [`G1044`](/mitre/groups/G1044.md) | NICECURL [`S1192`](/mitre/software/S1192.md), TAMECAT [`S1193`](/mitre/software/S1193.md) | [1] [9] |
| NIMBUS MANTICORE [`G1059`](/mitre/groups/G1059.md) | MiniBike [`S9059`](/mitre/software/S9059.md), MiniBus [`S9060`](/mitre/software/S9060.md), MiniFast [`S9052`](/mitre/software/S9052.md) and ten more | [1] [5] |
| Ajax Security Team [`G0130`](/mitre/groups/G0130.md) | Havij [`S0224`](/mitre/software/S0224.md), an ITSecTeam tool | [1] |
| CyberAv3ngers [`G1027`](https://attack.mitre.org/groups/G1027/) | IOControl [`S9046`](/mitre/software/S9046.md); the live group page also names three PLC programming tools as software, which the library data does not yet hold (see Part 9) | [1] [12] |

AA22-055A names MuddyWater's PowGoop, Small Sieve, Canopy (Starwhale), Mori and POWERSTATS; each is an ATT&CK software object under that name, Canopy as an alias of STARWHALE (**Confirmed** [18] [1]). Rewards for Justice says IOCONTROL was used against vendors including Unitronics (**Confirmed** [51]).

### Wipers and the destructive line

The Iranian record carries a recognizable wiper lineage. Shamoon ([`S0140`](/mitre/software/S0140.md)) was first used in 2012; ZeroCleare ([`S1151`](/mitre/software/S1151.md)), linked to OilRig in ATT&CK and a RawDisk-based wiper since at least 2019, followed a ransomware-style encryptor in the July 2022 Albania attack (**Confirmed** [1] [20]). The HomeLand Justice campaign also used CHIMNEYSWEEP ([`S1149`](/mitre/software/S1149.md)) and ROADSWEEP ([`S1150`](/mitre/software/S1150.md)) (**Confirmed** [13]). Check Point says Void Manticore's CI Wiper was first used against Albania in July 2022, and that Scarred Manticore hands off victims to Void Manticore for the destructive phase (**Confirmed** [75]). Agrius carries its own destructive tools: MultiLayer Wiper, and Apostle, which ATT&CK describes as both a wiper and, in later versions, ransomware (**Confirmed** [1]). Stryker may mark a change of method: a source told KrebsOnSecurity the attackers appear to have used Microsoft Intune's remote wipe, and the company's filing found no ransomware or malware (**Reported** [93]; **Confirmed** [59]; the fit between them is **Inferred**).

### Remote access and tunneling

Remote-management and tunneling tools recur across the record. AA24-241A names AnyDesk, MeshCentral, Ligolo and ngrok; AA22-320A records ngrok after the Horizon compromise; MuddyWater's ATT&CK record includes ConnectWise and RemoteUtilities (**Confirmed** [24] [21] [1]). In 2026 Unit 42 assesses with high confidence that state actors moved command and control to Starlink during the Iranian internet outage, and ATT&CK records MuddyWater using Starlink for C2 (**Confirmed** [68] [4]).

## Part 4: exploited vulnerabilities

The joint advisories name 20 distinct IT CVEs from 2020 to 2024. Nineteen are in the KEV catalog (version 2026.11.03), each marked as having known ransomware campaign use; CVE-2021-45105 is not in KEV. The Unitronics flaw CVE-2023-6448 was added on 11 December 2023 with ransomware use unknown (**Confirmed** [33], checked against the KEV JSON). CWE IDs below are the KEV catalog's own `cwes` field. Four more CVEs follow the joint-advisory rows: one from AA22-264A (the Albania attack) and three from vendor reports.

| CVE | Product | Named in | KEV date added | CWE (KEV) |
|---|---|---|---|---|
| CVE-2019-11510 | Pulse Connect Secure | AA20-259A [15] | 2021-11-03 | CWE-22 |
| CVE-2019-11539 | Pulse Connect Secure and Policy Secure | AA20-259A [15] | 2021-11-03 | CWE-78 |
| CVE-2019-19781 | Citrix ADC, Gateway and SD-WAN WANOP | AA20-259A [15], AA24-241A [24] | 2021-11-03 | CWE-22 |
| CVE-2020-5902 | F5 BIG-IP | AA20-259A [15] | 2021-11-03 | CWE-22 |
| CVE-2018-13379 | Fortinet FortiOS | AA21-321A [17], AA22-257A [19] | 2021-11-03 | CWE-22 |
| CVE-2020-12812 | Fortinet FortiOS | AA21-321A [17] | 2021-11-03 | CWE-178, CWE-287 |
| CVE-2019-5591 | Fortinet FortiOS | AA21-321A [17] | 2021-11-03 | CWE-306 |
| CVE-2021-34473 | Microsoft Exchange Server (ProxyShell) | AA21-321A [17], AA22-257A [19] | 2021-11-03 | CWE-918 |
| CVE-2021-34523 | Microsoft Exchange Server (ProxyShell) | AA22-257A [19] | 2021-11-03 | CWE-287 |
| CVE-2021-31207 | Microsoft Exchange Server (ProxyShell) | AA22-257A [19] | 2021-11-03 | CWE-20, CWE-434 |
| CVE-2020-1472 | Microsoft Netlogon | AA22-055A [18] | 2021-11-03 | CWE-330 |
| CVE-2020-0688 | Microsoft Exchange Server | AA22-055A [18] | 2021-11-03 | CWE-287 |
| CVE-2021-44228 | Apache Log4j2 (Log4Shell) | AA22-257A [19], AA22-320A [21] | 2021-12-10 | CWE-20, CWE-400, CWE-502 |
| CVE-2021-45046 | Apache Log4j2 | AA22-257A [19] | 2023-05-01 | CWE-917 |
| CVE-2021-45105 | Apache Log4j2 | AA22-257A [19] | not in KEV | not given |
| CVE-2023-3519 | Citrix NetScaler ADC and Gateway | AA24-241A [24] | 2023-07-19 | CWE-94 |
| CVE-2022-1388 | F5 BIG-IP | AA24-241A [24] | 2022-05-10 | CWE-306 |
| CVE-2024-21887 | Ivanti Connect Secure and Policy Secure | AA24-241A [24] | 2024-01-10 | CWE-77 |
| CVE-2024-3400 | Palo Alto Networks PAN-OS | AA24-241A [24] | 2024-04-12 | CWE-20, CWE-77 |
| CVE-2024-24919 | Check Point Quantum Security Gateways | AA24-241A [24] | 2024-05-30 | CWE-200 |
| CVE-2023-6448 | Unitronics Vision PLC and HMI | KEV only (added 2023-12-11, after the CyberAv3ngers activity; no advisory here names the CVE, so the link to CyberAv3ngers is **Inferred**) [33] | 2023-12-11 | CWE-1188 |
| CVE-2019-0604 | Microsoft SharePoint | AA22-264A [20] (Albania initial access) | 2021-11-03 | CWE-20 |
| CVE-2017-11882 | Microsoft Office | Mandiant APT34 report [62] | 2021-11-03 | CWE-119 |
| CVE-2022-47966 | Zoho ManageEngine | Microsoft Peach Sandstorm report [71] | 2023-01-23 | not given |
| CVE-2022-26134 | Atlassian Confluence | Microsoft Peach Sandstorm report [71] | 2022-06-02 | CWE-917 |

The pattern is old flaws in edge devices. Most of the CVEs were disclosed months or years before the advisory that names them, and the gap between disclosure and exploitation is not the point: the actors scan for appliances that were never patched, and AA21-321A's authors assess they exploit known vulnerabilities rather than choose sectors (**Confirmed** [17]; the reading is **Inferred**). The one fast case in the record is Mandiant's APT34 using CVE-2017-11882 less than a week after its patch (**Confirmed** [62]).

## Part 5: targets by sector and geography

**Geography.** The US, Israel and the Gulf states dominate the record, with Albania as the clearest European case (**Inferred** from the rows below). ATT&CK places APT33 against the US, Saudi Arabia and South Korea, NIMBUS MANTICORE against the US, Australia, the Middle East and Europe, and VOID MANTICORE against Albania, Israel and the US (**Confirmed** [10] [5] [6]). MuddyWater's MOIS campaigns span Asia, Africa, Europe and North America (**Confirmed** [18]). Pioneer Kitten's victims abroad include Israel, Azerbaijan and the UAE (**Confirmed** [24]). AA22-257A lists targets in the US, Australia, Canada and the UK, and the NCSC judges Afkar System Yazd is targeting UK organizations (**Confirmed** [19]). Google's TAG found the US and Israel made up about 60 percent of APT42's known targeting over six months in 2024 (**Confirmed** [74]). After 7 October 2023, 43 percent of the Iranian nation-state activity Microsoft tracked targeted Israel (**Confirmed** [72]).

**Sectors.** The sector lists in the record fall into four groups (**Confirmed** for each listing; the grouping is **Inferred**):

| Theme | Sectors | Example sources |
|---|---|---|
| People the state watches | dissidents, journalists, think tanks, academics, diaspora, officials, election campaigns, the travel and telecom data that track them | [2] [7] [36] [64] [69] [74] [42] |
| Strategic industry and research | aviation, aerospace, defense, satellite, energy, petrochemical, pharmaceutical and medical research, universities | [10] [61] [5] [71] [79] [44] |
| Whatever is exposed | IT, government, municipalities, transportation, police, education, finance, insurance, media, healthcare | [15] [17] [19] [24] [25] |
| Operational technology | water and wastewater, energy, government facilities, food and beverage, healthcare (as a user of the same PLCs) | [23] [27] [29] [51] |

## Part 6: the healthcare record

Someone running a hospital security program asks a narrower question than a threat-intelligence team does: which of these actors has touched healthcare, how, and on whose word. The table answers it. The US government record names the Healthcare and Public Health sector for four Iran-attributed clusters; research and pharmaceutical targeting rests on vendor reporting (**Inferred** summary of the rows).

| Date | Healthcare target | Actor and attribution | Grade | Sources |
|---|---|---|---|---|
| 2015-12 to 2018 | Hospitals and medical centers among SamSam victims (press names LabCorp) | Iran-based criminals; no state tie alleged | Confirmed (FBI, Treasury); Reported (victim names) | [45] [35] [97] |
| 2020-03 | Pharmaceutical sector at the onset of COVID-19 | Mandiant's APT42 (IRGC-IO, moderate confidence) | Confirmed | [64] |
| 2020-09-15 | Healthcare among the US sectors hit through Pulse Secure, Citrix and F5 | Pioneer Kitten / UNC757 | Confirmed | [15] |
| 2017 to 2024-08 | US healthcare facilities among the victims of the access broker | Pioneer Kitten (Government of Iran, FBI) | Confirmed | [24] |
| late 2020 to mid-2022 | Israeli healthcare organizations; a fake login page spoofing Pfizer | Mandiant's UNC3890 (Iran-linked, moderate confidence; not tied to the IRGC) | Confirmed | [65] [1] |
| 2020-12 | Senior staff at US and Israeli medical research organizations in genetics, oncology and neurology | Proofpoint's TA453; Proofpoint could not tie it independently to the IRGC but says the targeting appears to support IRGC collection priorities | Confirmed | [79] |
| 2021-06 | Environmental control networks of a US children's hospital, reached through a Fortigate appliance | AA21-321A actors; IRGC-affiliated per Treasury | Confirmed | [17] [39] |
| 2021-06 to 2021-08 | Healthcare practices | the same IRGC-affiliated group | Confirmed | [39] |
| summer 2021 | Boston Children's Hospital (attempt thwarted after an FBI warning) | hackers sponsored by the Iranian government (FBI) | Confirmed | [50] |
| 2022-07 | Albanian government services, including medical appointment booking | Iranian state (UK, US) | Confirmed | [52] [20] |
| 2023-02 to 2023-07 | Pharmaceutical targets, to a lesser extent than satellite and defense; healthcare among past Peach Sandstorm targets | Microsoft's Peach Sandstorm (APT33) | Confirmed | [71] |
| 2023-10 to 2023-12 | Israeli hospitals, which INCD says state attack groups treat as a legitimate target | various | Confirmed | [58] |
| 2023-10 onward | Healthcare and public health among the brute-force and MFA push bombing victims | Iranian actors (AA24-290A) | Confirmed | [25] |
| 2023-11 to 2024-01 | Healthcare among sectors that use the targeted Unitronics PLCs; the June 2025 fact sheet says US victims included the HPH sector | CyberAv3ngers (IRGC-affiliated) | Confirmed | [23] [27] |
| 2023-12-18 | Attempted attack on Ziv Hospital, attributed by INCD to Iran and Hezbollah | as cited by Israel's Foreign Ministry | Confirmed (that the Ministry says so) | [57] |
| 2026-02 (late) | Pay2Key ransomware at a US healthcare organization | Pay2Key (Iranian government-linked, Beazley Security) | Confirmed | [80] |
| 2026-03 | Handala's claimed targeting of Israeli healthcare | Unit 42 | Confirmed (that Unit 42 records the claim) | [68] |
| 2026-03-11 | Stryker, a medical technology company; some hospitals suspended connections to Stryker systems; prosecutors say emergency medical services and hospitals in Maryland were affected | Handala (MOIS, per reporting on DOJ filings; Void Manticore, per Check Point) | Confirmed (8-K, Check Point); Reported (impact, DOJ attribution) | [59] [76] [90] [93] |

Three readings follow. First, almost every confirmed US hospital case comes through an exposed edge device, a weak password or an internet-facing controller, the same front doors the actors use everywhere; the record shows opportunism, not a hospital-specific campaign (**Inferred** from [17] [24] [25] [23]). Second, the research and pharmaceutical cases are espionage against people, through credential phishing and social engineering. Proofpoint says the medical-research targeting appears to support IRGC collection priorities, and Mandiant attributes the APT42 pharmaceutical targeting to an actor it assesses works for the IRGC-IO (**Confirmed** [79] [64]). Third, the supply chain is an exposure point (**Inferred**): in 2026 a medical technology vendor's outage reached hospitals, and in June 2025 Health-ISAC warned that healthcare supply chains and Israeli-based software vendors are exposure points (**Confirmed** [59]; **Reported** [84] [90]).

The HHS HC3 brief "Iranian Threat Actors and Healthcare" of 3 November 2022 is the sector's own summary, but its primary copy could not be opened; trade coverage says it names Pioneer Kitten, Magic Kitten, Infy and UNC3890 and recommends phishing training and network segmentation (**Reported** [81]). AHA's guidance in July 2025 and March 2026 tells hospitals to stay alert and to inventory internet-facing OT and ICS such as HVAC, water, life-safety and building automation (**Reported** [83] [82]).

## Part 7: the government record

### United States: indictments, seizures and rewards

| Date | Court or agency | Defendants or target | Allegation | Sources |
|---|---|---|---|---|
| 2016-01-21 | SDNY | Seven ITSecTeam and Mersad managers or employees | DDoS on the US financial sector, 2011 to 2013, for the Iranian Government including the IRGC | [43] |
| 2018-02-07 (announced 2018-03-23) | SDNY | Nine Mabna Institute members | Theft from universities, agencies and companies at the behest of the IRGC | [44] |
| 2018-11-26 | D.N.J. | Shah Mansouri and Shahi Savandi | SamSam ransomware; no government tie stated | [45] |
| 2019-02-13 | FBI record (court not given here) | Monica Witt and four Iranians | Espionage for Iran; cyber campaign against US counterintelligence personnel | [46] |
| 2022-08-10 | D.N.J. | Mansour Ahmadi, Ahmad Khatibi Aghda, Amir Hossein Nickaein Ravari | Intrusion, exfiltration, encryption and extortion against critical infrastructure, agencies and non-profits, October 2020 to August 2022; unsealed as part of the action against the IRGC-affiliated Najee Technology and Afkar System Yazd group, per Treasury | [47] [39] |
| 2024-04-23 | DOJ and FBI (as stated by Treasury) | Four individuals tied to IRGC-CEC fronts, including Alireza Shafie Nasab | Spear-phishing and malware against US companies and agencies | [41] |
| 2024-09-27 | D.D.C. | Masoud Jalili, Yasar Balaghi, Seyyed Ali Aghamiri | Targeting people tied to the 2024 presidential campaigns, officials, think tank staff, journalists and activists since 2019; hack-and-leak to media | [48] [89] |
| 2026-03-19 | D. Md., case 1:26-mj-00683-CDA | Four domains | Seizure warrant; reporting says the affidavit ties Handala, Homeland Justice and Karma Below to MOIS and matches the Stryker incident | [49] [90] [91] [92] |
| 2026-08-18 | DOJ (superseding indictment) | 17 Mabna Institute members, including Behzad Mesri | Intrusions for the IRGC since 2013; HBO intrusion and extortion | [87] [88] |

The FBI page for Ahmadi and his co-defendants and the Rewards for Justice page for CyberAv3ngers each advertise rewards of up to 10 million dollars (**Confirmed** [47] [51]).

### United States: sanctions

| Date | Release | Designated | Basis | Sources |
|---|---|---|---|---|
| 2018-03-23 | sm0332 | Mabna Institute and individuals | IRGC outsourced intrusions to Mabna | [34] |
| 2018-11-28 | sm556 | Two Iran-based men | Converting SamSam ransom payments; no claim the government directed SamSam | [35] |
| 2020-09-17 | sm1127 | APT39, Rana Intelligence Computing, 45 individuals | Owned or controlled by MOIS | [36] |
| 2021-11-18 | jy0494 | Emennet Pasargad and six individuals (E.O. 13848) | 2020 election influence and intimidation | [37] |
| 2022-09-09 | jy0941 | MOIS and Minister Esmail Khatib | Albania attack and leaks; MuddyWater named as a MOIS element | [38] |
| 2022-09-14 | jy0948 | Ten individuals, Najee Technology, Afkar System Yazd | IRGC-affiliated ransomware; a children's hospital's SCADA access in June 2021 | [39] |
| 2024-02-02 | jy2072 | Six IRGC-CEC officials | Unitronics PLC defacements | [40] |
| 2024-04-23 | jy2292 | Mehrsam Andisheh Saz Nik, Dadeh Afzar Arman, four individuals | Spear-phishing and malware, including malware testing aimed at job seekers with a focus on military veterans | [41] |
| 2024-09-27 | jy2621 | Seven Iranians including IRGC member Masoud Jalili (E.O. 13848) | 2024 campaign hack-and-leak | [42] |
| 2026-08-24 | not opened | Five Iranian nationals | A hacking operation reported as directed by MOIS | [86] (Reported) |

### United States: advisories and joint statements

Every advisory in the record, with its co-authors, is in the timeline in Part 2. The allied co-authorship is itself part of the record: Australia's ACSC and the UK NCSC co-signed AA21-321A; the NCSC, ACSC and Canada's CCCS co-signed AA22-257A; Israel's INCD, CCCS and the NCSC co-signed AA23-335A; Canada's CSE, the Australian Federal Police and ASD's ACSC co-signed AA24-290A (**Confirmed** [17] [19] [23] [25]). The FBI, Treasury and the INCD issued the October 2024 Emennet Pasargad advisory together (**Confirmed** [30]). On 19 August 2024 ODNI, FBI and CISA attributed the reported Trump campaign compromise to Iran (**Confirmed** [31]).

### The United Kingdom, the EU, Albania and Israel

The UK government condemned Iran for the Albania attack on 7 September 2022, and the NCSC published the same assessment: Iranian state-linked actors almost certainly carried out the attacks that began on 15 July 2022 (**Confirmed** [52] [53]). The NCSC joined the September 2022 exposure of IRGC-affiliated ransomware operations, and in March 2026 advised UK organizations with a Middle East presence or supply chains to prepare for Iran-linked hacktivist spillover, including DDoS, phishing and ICS targeting (**Confirmed** [55] [56]). The EU's High Representative expressed solidarity with Albania, together with NATO, without naming Iran (**Confirmed** [54]). Albania cut diplomatic relations with Iran on 7 September 2022 (**Reported** [94]). Israel's Foreign Ministry records Iranian operations against Israeli hospitals, water, energy and IT, and the INCD's 2023 annual summary records state attack groups treating hospitals as a legitimate target; Israel is a party to the conflict, which a reader should weigh (**Confirmed** [57] [58]).

## Part 8: the defender view

### The front doors

For an exposure program, the joint record points to two front doors and a third that is newer (**Inferred** from [15] to [29]):

1. **Known edge-device vulnerabilities.** Exploit Public-Facing Application (`T1190`) and External Remote Services (`T1133`) against VPNs, firewalls, mail servers and remote-access gateways listed in KEV.
2. **Weak or reused credentials.** Password Spraying (`T1110.003`), Multi-Factor Authentication Request Generation (`T1621`), Device Registration (`T1098.005`) and Default Accounts (`T1078.001`).
3. **Internet-facing controllers.** Internet Accessible Device (`T0883`) and Default Credentials (`T1694.001`) in ATT&CK for ICS, the CyberAv3ngers path.

After access the tradecraft is commodity: PowerShell (`T1059.001`), Scheduled Task (`T1053.005`), LSASS Memory (`T1003.001`), Web Shell (`T1505.003`), Protocol Tunneling (`T1572`) and Remote Access Tools (`T1219`) (**Confirmed** for the mappings [1]; the reading is **Inferred**). Targeted espionage against people adds spearphishing and social engineering (`T1566.001`, `T1566.002`), which seven groups each carry in the ATT&CK record (**Confirmed** [1]).

### Hunting and detection leads published in the primaries

- Many failed logins, impossible travel, one IP address used across many accounts, MFA registrations from unexpected devices, and access to `ntds.dit` (AA24-290A) (**Confirmed** [25]).
- New accounts and new domain administrators (Windows events 4738, 4728 and 4670), new scheduled tasks, changes to Defender settings, processes accessing LSASS, RDP type-10 logons from one account to many hosts, and outbound connections to ngrok (AA22-320A) (**Confirmed** [21]).
- Unexpected AnyDesk, MeshCentral, Ligolo or ligolo-ng and ngrok, and PowerShell Web Access enabled on servers (AA24-241A) (**Confirmed** [24]).
- Unexpected outbound SSH, SMB and RDP (AA20-259A) (**Confirmed** [15]).
- Unauthorized BitLocker activation (AA22-257A) (**Confirmed** [19]).
- Remote-access log entries and firmware or configuration changes on OT devices (June 2025 fact sheet) (**Confirmed** [27]).

### Hardening guidance in the primaries

- Patch KEV-listed internet-facing systems first, use application control, require MFA for webmail and VPN, limit admin rights and add external-sender banners (AA22-055A) (**Confirmed** [18]).
- Rebuild compromised NetScaler devices, remediate the Active Directory forest if compromised, and use separate admin accounts on dedicated workstations (AA20-259A) (**Confirmed** [15]).
- Turn on Credential Guard, limit NTLM and WDigest, and move to phishing-resistant MFA (AA22-320A) (**Confirmed** [21]).
- Review help-desk password reset procedures, disable departing users' accounts, align with NIST digital identity guidance and disable RC4 for Kerberos (AA24-290A) (**Confirmed** [25]).
- Back up BitLocker recovery keys offline (AA22-257A) (**Confirmed** [19]).
- For OT: replace default passwords, take PLCs off the public internet, change the default port, put devices behind a VPN or gateway with MFA, segment networks, keep tested backups of PLC logic, keep PLCs in run mode, and ask manufacturers to ship without default passwords (AA23-335A and the June 2025 fact sheet) (**Confirmed** [23] [27]).

### Vulnerability management

The KEV view is unusually clean for this actor set: 19 of the 20 advisory IT CVEs are in KEV and every one is flagged for known ransomware use (**Confirmed** [33]). That makes KEV-first patching a direct defense against the Iranian edge-device clusters, with two cautions from the advisories themselves. Patching does not evict an actor that already holds stolen credentials or a web shell, so AA24-241A asks for a hunt after the patch, and AA22-320A asks defenders to assume compromise on a Horizon server that was not patched promptly (**Confirmed** [24] [21]). The library's [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) covers KEV-driven prioritization.

### Healthcare-specific steps

- Inventory every internet-facing OT and building system (HVAC, water treatment, life-safety, building automation, environmental controls) and bring it under the same patch and password rules as IT, as the AHA advises and as the June 2021 children's hospital case shows (**Reported** [82]; **Confirmed** [17]).
- Watch identity for spraying and MFA fatigue against clinical and research staff, whose accounts appear in both the AA24-290A victims and the TA453 and APT42 phishing record (**Confirmed** [25] [79] [64]).
- Treat a supplier outage as a security event. When a medical technology vendor is wiped, hospitals that suspend connections early limit their exposure; plan the disconnect in advance (**Inferred** from [93] [90]).
- Protect device-management consoles: restrict bulk wipe and reset rights, require a second approver, and log those actions outside the console (**Inferred** from [59] [93]).

### Where the library's countermeasure data is thin

The advisory guidance maps to D3FEND countermeasures that all have library pages, but the library's D3FEND 1.6.0 mapping leaves gaps against this playbook: Multi-factor Authentication (`D3-MFA`) maps Password Spraying but not MFA Request Generation (`T1621`) or External Remote Services (`T1133`); Software Update, Asset Vulnerability Enumeration and Software Inventory do not map `T1190`; Scheduled Job Analysis does not map `T1053.005`; and PowerShell (`T1059.001`) has no D3FEND mapping at all (**Confirmed** [1]). The countermeasures are still the right ones; the library's crosswalk simply does not draw those edges yet.

## Part 9: MITRE mappings

This part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every ID was checked against the library's data files at commit `e85b559` or the live ATT&CK pages on 3 November 2026, and the technique tables and Navigator layers were regenerated from the library's data files at commit `0c5b7ca` on 11 November 2026 with identical results; IDs that could not be checked are left out. Revoked IDs that advisories still cite are shown under their v20 successors, as `data/attack/superseded_by.jsonl` records them: DLL Side-Loading `T1574.002` as DLL `T1574.001` (AA22-055A), Disable or Modify Tools `T1562.001` as `T1685` (AA22-055A, AA22-320A, AA24-241A), and Downgrade Attack `T1562.010` as `T1689` (AA24-241A) (**Confirmed** [1]).

### Enterprise techniques

The table lists every Enterprise technique that ATT&CK v20.0 links to one of the 19 Iran-attributed Enterprise groups, plus every technique named in the eight joint advisories (AA20-259A, AA21-321A, AA22-055A, AA22-257A, AA22-320A, AA23-335A, AA24-241A, AA24-290A). That is 260 techniques: 237 from the groups, 23 only in the advisories, 96 in both (**Confirmed**, computed from [1] and the advisories). Revoked advisory IDs are counted under their successors, so `T1562.001` and `T1562.010` fold into `T1685` and `T1689`. Advisory technique lists were read from each advisory's own ATT&CK tables [15] [17] [18] [19] [21] [23] [24] [25]. Tactic names are the v20 names from the library's `technique_profiles.jsonl`. "Groups" lists the Iran-attributed groups whose ATT&CK record carries the technique, with procedure text and references on each group's page; "Advisories" gives the advisory and its publication date.

Counting each technique once per tactic it serves, the tally is Stealth 38, Credential Access 33, Persistence 31, Discovery 29, Execution 24, Privilege Escalation 24, Collection 23, Resource Development 23, Command and Control 21, Reconnaissance 15, Initial Access 14, Defense Impairment 13, Lateral Movement 10, Impact 10 and Exfiltration 5 (computed from [1]).

The most-reported techniques, scored as the number of groups plus the number of advisories that name them: Obtain Capabilities: Tool `T1588.002` (14 groups, 4 advisories), PowerShell `T1059.001` (11, 5), Ingress Tool Transfer `T1105` (10, 4), LSASS Memory `T1003.001` (10, 3), Scheduled Task `T1053.005` (8, 5), Exploit Public-Facing Application `T1190` (7, 5) and Archive via Utility `T1560.001` (8, 4). Password Spraying `T1110.003` is mapped to five groups (APT33, Leafminer, Silent Librarian, Agrius, NIMBUS MANTICORE); `T1621` and `T1098.005` appear only in AA24-290A (**Confirmed** [1] [25]).

<details>
<summary>All 260 Enterprise techniques (expand)</summary>

| ID | Technique | Tactic (v20) | Groups | Advisories | Sources |
|---|---|---|---|---|---|
| [`T1001.001`](/mitre/techniques/T1001-001.md) | Data Obfuscation: Junk Data | Command and Control | none | AA22-055A, 2022-02-24 | [18] |
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | Credential Access | G0087 | none | [1] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | OS Credential Dumping: LSASS Memory | Credential Access | G0003, G0049, G0059, G0064, G0069, G0077, G0087, G0117, G1030, G1055 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA22-320A, 2022-11-16 | [1], [15], [18], [21] |
| [`T1003.002`](/mitre/techniques/T1003-002.md) | OS Credential Dumping: Security Account Manager | Credential Access | G1030 | none | [1] |
| [`T1003.003`](/mitre/techniques/T1003-003.md) | OS Credential Dumping: NTDS | Credential Access | G0117 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1003.004`](/mitre/techniques/T1003-004.md) | OS Credential Dumping: LSA Secrets | Credential Access | G0049, G0064, G0069, G0077 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1003.005`](/mitre/techniques/T1003-005.md) | OS Credential Dumping: Cached Domain Credentials | Credential Access | G0049, G0064, G0069, G0077 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1003.006`](/mitre/techniques/T1003-006.md) | OS Credential Dumping: DCSync | Credential Access | G1059 | none | [1] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | Collection | G0049, G0059, G0087, G0117, G1012, G1030, G1055 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA24-290A, 2024-10-16 | [1], [15], [18], [25] |
| [`T1007`](/mitre/techniques/T1007.md) | System Service Discovery | Discovery | G0049, G1059 | none | [1] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | Command and Control | G0049 | none | [1] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | Discovery | G0049, G0087, G0117 | AA24-241A, 2024-08-28 | [1], [24] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | G0049, G0059, G0069, G1009, G1044 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1016.001`](/mitre/techniques/T1016-001.md) | System Network Configuration Discovery: Internet Connection Discovery | Discovery | G0059 | AA22-320A, 2022-11-16 | [1], [21] |
| [`T1016.002`](/mitre/techniques/T1016-002.md) | System Network Configuration Discovery: Wi-Fi Discovery | Discovery | G0059 | none | [1] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | Discovery | G0059, G0077, G0087, G0117, G1030 | AA20-259A, 2020-09-15; AA22-320A, 2022-11-16; AA24-290A, 2024-10-16 | [1], [15], [21], [25] |
| [`T1021`](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | none | AA20-259A, 2020-09-15 | [15] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Services: Remote Desktop Protocol | Lateral Movement | G0049, G0059, G0087, G0117, G1030, G1055, G1059 | AA20-259A, 2020-09-15; AA22-320A, 2022-11-16; AA24-290A, 2024-10-16 | [1], [15], [21], [25] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | Remote Services: SMB/Windows Admin Shares | Lateral Movement | G0087, G0117, G1009, G1059 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1021.004`](/mitre/techniques/T1021-004.md) | Remote Services: SSH | Lateral Movement | G0049, G0087, G0117 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1021.005`](/mitre/techniques/T1021-005.md) | Remote Services: VNC | Lateral Movement | G0117 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1025`](/mitre/techniques/T1025.md) | Data from Removable Media | Collection | G0049 | none | [1] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Obfuscated Files or Information: Software Packing | Stealth | G0087 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1027.003`](/mitre/techniques/T1027-003.md) | Obfuscated Files or Information: Steganography | Stealth | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1027.004`](/mitre/techniques/T1027-004.md) | Obfuscated Files or Information: Compile After Delivery | Stealth | G0069 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24 | [1], [15], [18] |
| [`T1027.005`](/mitre/techniques/T1027-005.md) | Obfuscated Files or Information: Indicator Removal from Tools | Stealth | G0049 | none | [1] |
| [`T1027.010`](/mitre/techniques/T1027-010.md) | Obfuscated Files or Information: Command Obfuscation | Stealth | G0059, G0069, G0077, G0117 | none | [1] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | G0043, G0049, G0059, G0064, G0087, G0117, G1009 | none | [1] |
| [`T1027.015`](/mitre/techniques/T1027-015.md) | Obfuscated Files or Information: Compression | Stealth | G1055, G1059 | none | [1] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | Discovery | G0049, G0059, G0069, G0087 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1036`](/mitre/techniques/T1036.md) | Masquerading | Stealth | G0049, G1030 | none | [1] |
| [`T1036.004`](/mitre/techniques/T1036-004.md) | Masquerading: Masquerade Task or Service | Stealth | G0059, G0117, G1055, G1059 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Masquerading: Match Legitimate Resource Name or Location | Stealth | G0049, G0059, G0069, G0087, G0117, G1044, G1055, G1059 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24 | [1], [15], [18] |
| [`T1036.010`](/mitre/techniques/T1036-010.md) | Masquerading: Masquerade Account Name | Stealth | G0059 | none | [1] |
| [`T1039`](/mitre/techniques/T1039.md) | Data from Network Shared Drive | Collection | G0117, G1059 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | G0064 | none | [1] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | G0069, G0087, G1012, G1030, G1055 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | G0049, G0059, G0077, G0087, G0117, G1030, G1059 | none | [1] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | G0049, G0059, G0069, G1044, G1055, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1048.002`](/mitre/techniques/T1048-002.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration | G1012 | none | [1] |
| [`T1048.003`](/mitre/techniques/T1048-003.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | G0049, G0064 | none | [1] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | G0049, G0059, G0069, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1053`](/mitre/techniques/T1053.md) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation | none | AA24-241A, 2024-08-28 | [24] |
| [`T1053.003`](/mitre/techniques/T1053-003.md) | Scheduled Task/Job: Cron | Execution, Persistence, Privilege Escalation | none | AA20-259A, 2020-09-15 | [15] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | G0049, G0059, G0064, G0069, G0087, G0117, G1044, G1059 | AA20-259A, 2020-09-15; AA21-321A, 2021-11-17; AA22-055A, 2022-02-24; AA22-257A, 2022-09-14; AA22-320A, 2022-11-16 | [1], [15], [17], [18], [19], [21] |
| [`T1055.013`](/mitre/techniques/T1055-013.md) | Process Injection: Process Doppelgänging | Stealth, Privilege Escalation | G0077 | none | [1] |
| [`T1056`](/mitre/techniques/T1056.md) | Input Capture | Collection, Credential Access | G0087, G1044 | AA24-241A, 2024-08-28 | [1], [24] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Input Capture: Keylogging | Collection, Credential Access | G0043, G0049, G0059, G0087, G0130, G1044 | none | [1] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | Discovery | G0049, G0059, G0069, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1059`](/mitre/techniques/T1059.md) | Command and Scripting Interpreter | Execution | G0049, G0087, G0117 | none | [1] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | Command and Scripting Interpreter: PowerShell | Execution | G0049, G0052, G0059, G0064, G0069, G0087, G0117, G1012, G1044, G1055, G1059 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA22-320A, 2022-11-16; AA24-241A, 2024-08-28; AA24-290A, 2024-10-16 | [1], [15], [18], [21], [24], [25] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Command and Scripting Interpreter: Windows Command Shell | Execution | G0049, G0059, G0069, G0117, G1030 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24 | [1], [15], [18] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Command and Scripting Interpreter: Visual Basic | Execution | G0049, G0059, G0064, G0069, G0087, G1044 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1059.006`](/mitre/techniques/T1059-006.md) | Command and Scripting Interpreter: Python | Execution | G0069, G0087, G1055 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1059.007`](/mitre/techniques/T1059-007.md) | Command and Scripting Interpreter: JavaScript | Execution | G0069, G0077, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1059.010`](/mitre/techniques/T1059-010.md) | Command and Scripting Interpreter: AutoHotKey & AutoIT | Execution | G0087 | none | [1] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | G0049, G0064 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1069.001`](/mitre/techniques/T1069-001.md) | Permission Groups Discovery: Local Groups | Discovery | G0049 | none | [1] |
| [`T1069.002`](/mitre/techniques/T1069-002.md) | Permission Groups Discovery: Domain Groups | Discovery | G0049 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1069.003`](/mitre/techniques/T1069-003.md) | Permission Groups Discovery: Cloud Groups | Discovery | none | AA24-290A, 2024-10-16 | [25] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | G1044 | none | [1] |
| [`T1070.003`](/mitre/techniques/T1070-003.md) | Indicator Removal: Clear Command History | Stealth | G0059 | none | [1] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | Indicator Removal: File Deletion | Stealth | G0043, G0049, G0059, G0087, G1059 | AA20-259A, 2020-09-15; AA22-320A, 2022-11-16 | [1], [15], [21] |
| [`T1070.007`](/mitre/techniques/T1070-007.md) | Indicator Removal: Clear Network Connection History and Configurations | Stealth | G1059 | none | [1] |
| [`T1070.008`](/mitre/techniques/T1070-008.md) | Indicator Removal: Clear Mailbox Data | Stealth | G1044 | none | [1] |
| [`T1071`](/mitre/techniques/T1071.md) | Application Layer Protocol | Command and Control | G0059, G1059 | none | [1] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Application Layer Protocol: Web Protocols | Command and Control | G0049, G0059, G0064, G0069, G0087, G1044, G1055 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA24-290A, 2024-10-16 | [1], [15], [18], [25] |
| [`T1071.004`](/mitre/techniques/T1071-004.md) | Application Layer Protocol: DNS | Command and Control | G0049, G0087 | none | [1] |
| [`T1072`](/mitre/techniques/T1072.md) | Software Deployment Tools | Execution, Lateral Movement | G1055, G1059 | none | [1] |
| [`T1074`](/mitre/techniques/T1074.md) | Data Staged | Collection | G1055 | none | [1] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Data Staged: Local Data Staging | Collection | G0069, G0087, G1030 | none | [1] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | G0049, G0064, G0087, G0117, G0122, G1005, G1055 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Valid Accounts: Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | G0059 | AA22-320A, 2022-11-16; AA23-335A, 2023-12-01 | [1], [21], [23] |
| [`T1078.002`](/mitre/techniques/T1078-002.md) | Valid Accounts: Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | G0049, G0059, G1030, G1055, G1059 | AA24-241A, 2024-08-28 | [1], [24] |
| [`T1078.003`](/mitre/techniques/T1078-003.md) | Valid Accounts: Local Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | G1059 | AA24-241A, 2024-08-28 | [1], [24] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Valid Accounts: Cloud Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | G0064, G1055, G1059 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | G0049, G0059, G0069, G1009, G1012, G1044, G1055 | AA22-055A, 2022-02-24; AA24-290A, 2024-10-16 | [1], [18], [25] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | G0059, G0069, G0077, G0087, G0117 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24 | [1], [15], [18] |
| [`T1087`](/mitre/techniques/T1087.md) | Account Discovery | Discovery | none | AA20-259A, 2020-09-15 | [15] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Account Discovery: Local Account | Discovery | G0049, G0117, G1009, G1044, G1059 | none | [1] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Account Discovery: Domain Account | Discovery | G0049, G0069, G0117, G1055, G1059 | AA22-055A, 2022-02-24; AA24-290A, 2024-10-16 | [1], [18], [25] |
| [`T1087.003`](/mitre/techniques/T1087-003.md) | Account Discovery: Email Account | Discovery | G0059 | none | [1] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | Command and Control | G0052, G0059, G0069, G0117, G1005 | AA22-320A, 2022-11-16 | [1], [21] |
| [`T1090.001`](/mitre/techniques/T1090-001.md) | Proxy: Internal Proxy | Command and Control | G0087 | none | [1] |
| [`T1090.002`](/mitre/techniques/T1090-002.md) | Proxy: External Proxy | Command and Control | G0069, G0087 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | G1055, G1059 | AA22-320A, 2022-11-16; AA24-241A, 2024-08-28 | [1], [21], [24] |
| [`T1098.002`](/mitre/techniques/T1098-002.md) | Account Manipulation: Additional Email Delegate Permissions | Persistence, Privilege Escalation | G0059 | none | [1] |
| [`T1098.005`](/mitre/techniques/T1098-005.md) | Account Manipulation: Device Registration | Persistence, Privilege Escalation | none | AA24-290A, 2024-10-16 | [25] |
| [`T1098.007`](/mitre/techniques/T1098-007.md) | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | G0059 | none | [1] |
| [`T1102`](/mitre/techniques/T1102.md) | Web Service | Command and Control | G0117, G1044, G1055 | none | [1] |
| [`T1102.002`](/mitre/techniques/T1102-002.md) | Web Service: Bidirectional Communication | Command and Control | G0059, G0069, G0087, G1005 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1104`](/mitre/techniques/T1104.md) | Multi-Stage Channels | Command and Control | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | G0049, G0059, G0064, G0069, G0087, G0117, G0130, G1009, G1055, G1059 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA22-320A, 2022-11-16; AA24-290A, 2024-10-16 | [1], [15], [18], [21], [25] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | Execution | G1059 | none | [1] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | Credential Access | G0049, G0087, G0117, G1030, G1055 | AA23-335A, 2023-12-01; AA24-290A, 2024-10-16 | [1], [23], [25] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Brute Force: Password Guessing | Credential Access | G1055 | none | [1] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Brute Force: Password Spraying | Credential Access | G0064, G0077, G0122, G1030, G1059 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1110.004`](/mitre/techniques/T1110-004.md) | Brute Force: Credential Stuffing | Credential Access | G1055 | none | [1] |
| [`T1111`](/mitre/techniques/T1111.md) | Multi-Factor Authentication Interception | Credential Access | G1044 | none | [1] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | G0049, G0059, G1044 | none | [1] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | Collection | G0043, G0049, G0059, G0069, G0087, G1044, G1055 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | Collection | G0059, G0122 | none | [1] |
| [`T1114.001`](/mitre/techniques/T1114-001.md) | Email Collection: Local Email Collection | Collection | G0059, G1059 | none | [1] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Email Collection: Remote Email Collection | Collection | G0059, G0077, G1055 | none | [1] |
| [`T1114.003`](/mitre/techniques/T1114-003.md) | Email Collection: Email Forwarding Rule | Collection | G0122 | none | [1] |
| [`T1115`](/mitre/techniques/T1115.md) | Clipboard Data | Collection | G0049, G0087 | none | [1] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | Collection | G0049, G1030, G1055 | none | [1] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | Discovery | G0049 | none | [1] |
| [`T1123`](/mitre/techniques/T1123.md) | Audio Capture | Collection | G1055 | none | [1] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | Discovery | G1012 | none | [1] |
| [`T1125`](/mitre/techniques/T1125.md) | Video Capture | Collection | G1055 | none | [1] |
| [`T1132.001`](/mitre/techniques/T1132-001.md) | Data Encoding: Standard Encoding | Command and Control | G0064, G0069, G1044 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1132.002`](/mitre/techniques/T1132-002.md) | Data Encoding: Non-Standard Encoding | Command and Control | none | AA22-055A, 2022-02-24 | [18] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | G0049, G1055 | AA24-241A, 2024-08-28; AA24-290A, 2024-10-16 | [1], [24], [25] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | G0087 | none | [1] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Create Account: Local Account | Persistence | G0059, G0077, G0087, G0117, G1059 | AA21-321A, 2021-11-17; AA22-257A, 2022-09-14; AA22-320A, 2022-11-16; AA24-241A, 2024-08-28 | [1], [17], [19], [21], [24] |
| [`T1136.002`](/mitre/techniques/T1136-002.md) | Create Account: Domain Account | Persistence | none | AA21-321A, 2021-11-17; AA22-257A, 2022-09-14; AA22-320A, 2022-11-16 | [17], [19], [21] |
| [`T1137.001`](/mitre/techniques/T1137-001.md) | Office Application Startup: Office Template Macros | Persistence | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1137.004`](/mitre/techniques/T1137-004.md) | Office Application Startup: Outlook Home Page | Persistence | G0049 | none | [1] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | G0049, G0069, G0087, G1030 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | G0059, G0077, G1012 | none | [1] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | G0059, G0069, G0087, G0117, G1009, G1030, G1055 | AA20-259A, 2020-09-15; AA21-321A, 2021-11-17; AA22-257A, 2022-09-14; AA22-320A, 2022-11-16; AA24-241A, 2024-08-28 | [1], [15], [17], [19], [21], [24] |
| [`T1195`](/mitre/techniques/T1195.md) | Supply Chain Compromise | Initial Access | G0049 | none | [1] |
| [`T1197`](/mitre/techniques/T1197.md) | BITS Jobs | Stealth, Persistence, Execution | G0087 | none | [1] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | G1005, G1055, G1059 | none | [1] |
| [`T1201`](/mitre/techniques/T1201.md) | Password Policy Discovery | Discovery | G0049 | none | [1] |
| [`T1202`](/mitre/techniques/T1202.md) | Indirect Command Execution | Stealth | none | AA24-290A, 2024-10-16 | [25] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | G0049, G0064, G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | User Execution: Malicious Link | Execution | G0049, G0059, G0064, G0069, G0087, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | User Execution: Malicious File | Execution | G0049, G0059, G0064, G0069, G0087, G0130, G1012, G1055, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1204.004`](/mitre/techniques/T1204-004.md) | User Execution: Malicious Copy and Paste | Execution | G0069 | none | [1] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | Lateral Movement | G0069, G0117 | none | [1] |
| [`T1213`](/mitre/techniques/T1213.md) | Data from Information Repositories | Collection | G1059 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1213.002`](/mitre/techniques/T1213-002.md) | Data from Information Repositories: Sharepoint | Collection | G1055, G1059 | none | [1] |
| [`T1213.005`](/mitre/techniques/T1213-005.md) | Data from Information Repositories: Messaging Applications | Collection | G0117, G1059 | none | [1] |
| [`T1217`](/mitre/techniques/T1217.md) | Browser Information Discovery | Discovery | G0117 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1218.001`](/mitre/techniques/T1218-001.md) | System Binary Proxy Execution: Compiled HTML File | Stealth | G0049 | none | [1] |
| [`T1218.003`](/mitre/techniques/T1218-003.md) | System Binary Proxy Execution: CMSTP | Stealth | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1218.005`](/mitre/techniques/T1218-005.md) | System Binary Proxy Execution: Mshta | Stealth | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | System Binary Proxy Execution: Rundll32 | Stealth | G0052, G0059, G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | Command and Control | G0049 | AA22-055A, 2022-02-24; AA24-241A, 2024-08-28 | [1], [18], [24] |
| [`T1219.002`](/mitre/techniques/T1219-002.md) | Remote Access Tools: Remote Desktop Software | Command and Control | G0069, G1055 | none | [1] |
| [`T1480`](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | none | AA22-055A, 2022-02-24 | [18] |
| [`T1482`](/mitre/techniques/T1482.md) | Domain Trust Discovery | Discovery | G0059 | AA24-241A, 2024-08-28; AA24-290A, 2024-10-16 | [1], [24], [25] |
| [`T1484.001`](/mitre/techniques/T1484-001.md) | Domain or Tenant Policy Modification: Group Policy Modification | Defense Impairment, Privilege Escalation | G1055 | none | [1] |
| [`T1484.002`](/mitre/techniques/T1484-002.md) | Domain or Tenant Policy Modification: Trust Modification | Defense Impairment, Privilege Escalation | none | AA24-290A, 2024-10-16 | [25] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | Impact | G1055 | none | [1] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | G0059, G1055 | AA21-321A, 2021-11-17; AA22-257A, 2022-09-14 | [1], [17], [19] |
| [`T1490`](/mitre/techniques/T1490.md) | Inhibit System Recovery | Impact | G1055 | none | [1] |
| [`T1491.001`](/mitre/techniques/T1491-001.md) | Defacement: Internal Defacement | Impact | none | AA23-335A, 2023-12-01 | [23] |
| [`T1497.001`](/mitre/techniques/T1497-001.md) | Virtualization/Sandbox Evasion: System Checks | Stealth, Discovery | G0049 | none | [1] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | Impact | none | AA23-335A, 2023-12-01 | [23] |
| [`T1505`](/mitre/techniques/T1505.md) | Server Software Component | Persistence | none | AA24-241A, 2024-08-28 | [24] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Server Software Component: Web Shell | Persistence | G0049, G0059, G0087, G0117, G1009, G1012, G1030 | AA20-259A, 2020-09-15; AA24-241A, 2024-08-28 | [1], [15], [24] |
| [`T1518`](/mitre/techniques/T1518.md) | Software Discovery | Discovery | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Software Discovery: Security Software Discovery | Discovery | G0069, G1044 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1530`](/mitre/techniques/T1530.md) | Data from Cloud Storage | Collection | G0117, G1044 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1531`](/mitre/techniques/T1531.md) | Account Access Removal | Impact | none | AA23-335A, 2023-12-01 | [23] |
| [`T1534`](/mitre/techniques/T1534.md) | Internal Spearphishing | Lateral Movement | G0069, G1059 | none | [1] |
| [`T1539`](/mitre/techniques/T1539.md) | Steal Web Session Cookie | Credential Access | G1044 | none | [1] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | G0049, G1030 | none | [1] |
| [`T1546.003`](/mitre/techniques/T1546-003.md) | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence | G0064 | none | [1] |
| [`T1546.008`](/mitre/techniques/T1546-008.md) | Event Triggered Execution: Accessibility Features | Privilege Escalation, Persistence | G0117 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1546.010`](/mitre/techniques/T1546-010.md) | Event Triggered Execution: AppInit DLLs | Privilege Escalation, Persistence | G0087 | none | [1] |
| [`T1547`](/mitre/techniques/T1547.md) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation | G1044 | none | [1] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | G0059, G0064, G0069, G0087, G1055, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1547.009`](/mitre/techniques/T1547-009.md) | Boot or Logon Autostart Execution: Shortcut Modification | Persistence, Privilege Escalation | G0087 | none | [1] |
| [`T1548.002`](/mitre/techniques/T1548-002.md) | Abuse Elevation Control Mechanism: Bypass User Account Control | Privilege Escalation | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1552`](/mitre/techniques/T1552.md) | Unsecured Credentials | Credential Access | G1059 | none | [1] |
| [`T1552.001`](/mitre/techniques/T1552-001.md) | Unsecured Credentials: Credentials In Files | Credential Access | G0049, G0064, G0069, G0077, G0117 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24 | [1], [15], [18] |
| [`T1552.002`](/mitre/techniques/T1552-002.md) | Unsecured Credentials: Credentials in Registry | Credential Access | G1055 | none | [1] |
| [`T1552.006`](/mitre/techniques/T1552-006.md) | Unsecured Credentials: Group Policy Preferences | Credential Access | G0064 | none | [1] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Subvert Trust Controls: Code Signing | Defense Impairment | G0049, G0052, G1009 | none | [1] |
| [`T1553.006`](/mitre/techniques/T1553-006.md) | Subvert Trust Controls: Code Signing Policy Modification | Defense Impairment | G0087 | none | [1] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | G0049, G0064, G0069, G0077, G0087 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA22-320A, 2022-11-16; AA24-290A, 2024-10-16 | [1], [15], [18], [21], [25] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | G0049, G0064, G0069, G0077, G0130, G1044 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1555.004`](/mitre/techniques/T1555-004.md) | Credentials from Password Stores: Windows Credential Manager | Credential Access | G0049 | none | [1] |
| [`T1555.005`](/mitre/techniques/T1555-005.md) | Credentials from Password Stores: Password Managers | Credential Access | G0117 | none | [1] |
| [`T1556`](/mitre/techniques/T1556.md) | Modify Authentication Process | Defense Impairment, Persistence, Credential Access | none | AA24-290A, 2024-10-16 | [25] |
| [`T1556.002`](/mitre/techniques/T1556-002.md) | Modify Authentication Process: Password Filter DLL | Defense Impairment, Persistence, Credential Access | G0049 | none | [1] |
| [`T1556.006`](/mitre/techniques/T1556-006.md) | Modify Authentication Process: Multi-Factor Authentication | Defense Impairment, Persistence, Credential Access | none | AA24-290A, 2024-10-16 | [25] |
| [`T1557.002`](/mitre/techniques/T1557-002.md) | Adversary-in-the-Middle: ARP Cache Poisoning | Credential Access, Collection | G0003 | none | [1] |
| [`T1558`](/mitre/techniques/T1558.md) | Steal or Forge Kerberos Tickets | Credential Access | none | AA20-259A, 2020-09-15 | [15] |
| [`T1558.003`](/mitre/techniques/T1558-003.md) | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | G1059 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1559.001`](/mitre/techniques/T1559-001.md) | Inter-Process Communication: Component Object Model | Execution | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1559.002`](/mitre/techniques/T1559-002.md) | Inter-Process Communication: Dynamic Data Exchange | Execution | G0069 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive Collected Data: Archive via Utility | Collection | G0052, G0059, G0064, G0069, G0087, G0117, G1030, G1055 | AA20-259A, 2020-09-15; AA21-321A, 2021-11-17; AA22-055A, 2022-02-24; AA22-257A, 2022-09-14 | [1], [15], [17], [18], [19] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive Collected Data: Archive via Custom Method | Collection | G0052 | none | [1] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Wipe: Disk Content Wipe | Impact | G1055 | none | [1] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Wipe: Disk Structure Wipe | Impact | G1055 | none | [1] |
| [`T1563.002`](/mitre/techniques/T1563-002.md) | Remote Service Session Hijacking: RDP Hijacking | Lateral Movement | G1059 | AA20-259A, 2020-09-15 | [1], [15] |
| [`T1564.003`](/mitre/techniques/T1564-003.md) | Hide Artifacts: Hidden Window | Stealth | G0052, G0059, G1055 | none | [1] |
| [`T1565.001`](/mitre/techniques/T1565-001.md) | Data Manipulation: Stored Data Manipulation | Impact | none | AA23-335A, 2023-12-01 | [23] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | Initial Access | G0069, G1055 | none | [1] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Phishing: Spearphishing Attachment | Initial Access | G0049, G0064, G0069, G0087, G0130, G1012, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Phishing: Spearphishing Link | Initial Access | G0049, G0059, G0064, G0069, G0087, G1044, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Phishing: Spearphishing via Service | Initial Access | G0049, G0059, G0130, G1012 | none | [1] |
| [`T1567`](/mitre/techniques/T1567.md) | Exfiltration Over Web Service | Exfiltration | G0059 | none | [1] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | G0069, G1005 | none | [1] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | System Services: Service Execution | Execution | G0087 | none | [1] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | Lateral Movement | G0059, G1030 | none | [1] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | Command and Control | G0059, G0064, G0069 | none | [1] |
| [`T1572`](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | G0049, G0059, G0117, G1055 | AA20-259A, 2020-09-15; AA22-055A, 2022-02-24; AA24-241A, 2024-08-28; AA24-290A, 2024-10-16 | [1], [15], [18], [24], [25] |
| [`T1573`](/mitre/techniques/T1573.md) | Encrypted Channel | Command and Control | G0059 | none | [1] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Encrypted Channel: Symmetric Cryptography | Command and Control | G0064, G0069 | none | [1] |
| [`T1573.002`](/mitre/techniques/T1573-002.md) | Encrypted Channel: Asymmetric Cryptography | Command and Control | G0049, G1044 | none | [1] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | Hijack Execution Flow: DLL | Stealth, Execution | G0069, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1574.014`](/mitre/techniques/T1574-014.md) | Hijack Execution Flow: AppDomainManager | Stealth, Execution | G1059 | none | [1] |
| [`T1583`](/mitre/techniques/T1583.md) | Acquire Infrastructure | Resource Development | G1030 | none | [1] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Acquire Infrastructure: Domains | Resource Development | G0049, G0059, G0069, G0122, G1012, G1044, G1055, G1059 | none | [1] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Acquire Infrastructure: Virtual Private Server | Resource Development | G1012, G1044, G1055, G1059 | none | [1] |
| [`T1583.004`](/mitre/techniques/T1583-004.md) | Acquire Infrastructure: Server | Resource Development | G1012, G1055 | none | [1] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Acquire Infrastructure: Web Services | Resource Development | G0059, G0069, G1005, G1055, G1059 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Compromise Infrastructure: Domains | Resource Development | G0059 | none | [1] |
| [`T1584.006`](/mitre/techniques/T1584-006.md) | Compromise Infrastructure: Web Services | Resource Development | G1012 | none | [1] |
| [`T1585`](/mitre/techniques/T1585.md) | Establish Accounts | Resource Development | G0117 | none | [1] |
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Establish Accounts: Social Media Accounts | Resource Development | G0003, G0059, G0117, G1012, G1055, G1059 | none | [1] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Establish Accounts: Email Accounts | Resource Development | G0059, G0122, G1012, G1044, G1055 | none | [1] |
| [`T1586.002`](/mitre/techniques/T1586-002.md) | Compromise Accounts: Email Accounts | Resource Development | G0049, G0059 | none | [1] |
| [`T1587.001`](/mitre/techniques/T1587-001.md) | Develop Capabilities: Malware | Resource Development | G0003, G0049, G1009, G1055, G1059 | none | [1] |
| [`T1588.001`](/mitre/techniques/T1588-001.md) | Obtain Capabilities: Malware | Resource Development | G0069, G1055 | AA21-321A, 2021-11-17; AA22-257A, 2022-09-14 | [1], [17], [19] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Obtain Capabilities: Tool | Resource Development | G0003, G0049, G0052, G0059, G0064, G0069, G0077, G0087, G0122, G1005, G1009, G1044, G1055, G1059 | AA21-321A, 2021-11-17; AA22-055A, 2022-02-24; AA22-257A, 2022-09-14; AA24-290A, 2024-10-16 | [1], [17], [18], [19], [25] |
| [`T1588.003`](/mitre/techniques/T1588-003.md) | Obtain Capabilities: Code Signing Certificates | Resource Development | G0049, G1059 | none | [1] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Obtain Capabilities: Digital Certificates | Resource Development | G0122 | none | [1] |
| [`T1588.007`](/mitre/techniques/T1588-007.md) | Obtain Capabilities: Artificial Intelligence | Resource Development | G1059 | none | [1] |
| [`T1589`](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | G0059, G1055 | AA24-290A, 2024-10-16 | [1], [25] |
| [`T1589.001`](/mitre/techniques/T1589-001.md) | Gather Victim Identity Information: Credentials | Reconnaissance | G0059 | none | [1] |
| [`T1589.002`](/mitre/techniques/T1589-002.md) | Gather Victim Identity Information: Email Addresses | Reconnaissance | G0059, G0122 | AA22-055A, 2022-02-24 | [1], [18] |
| [`T1589.003`](/mitre/techniques/T1589-003.md) | Gather Victim Identity Information: Employee Names | Reconnaissance | G0122 | none | [1] |
| [`T1590.004`](/mitre/techniques/T1590-004.md) | Gather Victim Network Information: Network Topology | Reconnaissance | G0069 | none | [1] |
| [`T1590.005`](/mitre/techniques/T1590-005.md) | Gather Victim Network Information: IP Addresses | Reconnaissance | G0059 | none | [1] |
| [`T1591`](/mitre/techniques/T1591.md) | Gather Victim Org Information | Reconnaissance | G1059 | none | [1] |
| [`T1591.001`](/mitre/techniques/T1591-001.md) | Gather Victim Org Information: Determine Physical Locations | Reconnaissance | G0059 | none | [1] |
| [`T1592.002`](/mitre/techniques/T1592-002.md) | Gather Victim Host Information: Software | Reconnaissance | G0059 | none | [1] |
| [`T1594`](/mitre/techniques/T1594.md) | Search Victim-Owned Websites | Reconnaissance | G0122 | none | [1] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Active Scanning: Vulnerability Scanning | Reconnaissance | G0059, G1055 | none | [1] |
| [`T1596`](/mitre/techniques/T1596.md) | Search Open Technical Databases | Reconnaissance | none | AA24-241A, 2024-08-28 | [24] |
| [`T1598.001`](/mitre/techniques/T1598-001.md) | Phishing for Information: Spearphishing Service | Reconnaissance | G1059 | none | [1] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Phishing for Information: Spearphishing Link | Reconnaissance | G0059, G0122, G1012 | none | [1] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Stage Capabilities: Upload Malware | Resource Development | G0049, G1044, G1059 | none | [1] |
| [`T1608.004`](/mitre/techniques/T1608-004.md) | Stage Capabilities: Drive-by Target | Resource Development | G1012 | none | [1] |
| [`T1608.005`](/mitre/techniques/T1608-005.md) | Stage Capabilities: Link Target | Resource Development | G0122, G1059 | none | [1] |
| [`T1608.006`](/mitre/techniques/T1608-006.md) | Stage Capabilities: SEO Poisoning | Resource Development | G1059 | none | [1] |
| [`T1621`](/mitre/techniques/T1621.md) | Multi-Factor Authentication Request Generation | Credential Access | none | AA24-290A, 2024-10-16 | [25] |
| [`T1649`](/mitre/techniques/T1649.md) | Steal or Forge Authentication Certificates | Credential Access | G1059 | none | [1] |
| [`T1651`](/mitre/techniques/T1651.md) | Cloud Administration Command | Execution | G1055 | none | [1] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | Impact | G1055 | AA24-241A, 2024-08-28 | [1], [24] |
| [`T1678`](/mitre/techniques/T1678.md) | Delay Execution | Stealth | G1059 | none | [1] |
| [`T1679`](/mitre/techniques/T1679.md) | Selective Exclusion | Stealth | G1055 | none | [1] |
| [`T1682`](/mitre/techniques/T1682.md) | Query Public AI Services | Reconnaissance | G1044 | none | [1] |
| [`T1683.001`](/mitre/techniques/T1683-001.md) | Generate Content: Written Content | Resource Development | G1059 | none | [1] |
| [`T1683.002`](/mitre/techniques/T1683-002.md) | Generate Content: Audio-Visual Content | Resource Development | G1059 | none | [1] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Social Engineering: Impersonation | Stealth | G0069, G1044, G1055, G1059 | none | [1] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | G0059, G0069, G1030 | AA22-055A, 2022-02-24; AA22-320A, 2022-11-16; AA24-241A, 2024-08-28 | [1], [18], [21], [24] |
| [`T1685.001`](/mitre/techniques/T1685-001.md) | Disable or Modify Tools: Disable or Modify Windows Event Log | Defense Impairment | G0059 | none | [1] |
| [`T1685.003`](/mitre/techniques/T1685-003.md) | Disable or Modify Tools: Modify or Spoof Tool UI | Defense Impairment | G1059 | none | [1] |
| [`T1686.003`](/mitre/techniques/T1686-003.md) | Disable or Modify System Firewall: Windows Host Firewall | Defense Impairment | G0049, G0059, G1009, G1055 | none | [1] |
| [`T1689`](/mitre/techniques/T1689.md) | Downgrade Attack | Defense Impairment | none | AA24-241A, 2024-08-28 | [24] |
| [`T1697`](/mitre/techniques/T1697.md) | Steal Application Specific Passwords | Credential Access | G1044 | none | [1] |
</details>

Vendor primaries add technique statements that are already in the table: Microsoft maps Peach Sandstorm's password spraying to `T1110.003` and its exploitation of CVE-2022-47966 and CVE-2022-26134 to `T1190` (**Confirmed** [71]).

### ATT&CK for ICS

ATT&CK for ICS links 24 techniques to three Iran-attributed groups: 17 to CyberAv3ngers, 6 to OilRig and 3 to APT33 (**Confirmed** [1]). The library has no ICS technique pages under `mitre/`, so the IDs link to attack.mitre.org; see also the library's [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md). The live CyberAv3ngers page lists 19 technique rows; the two not in the library's mapping are Denial of Service `T0814` and Loss of Productivity and Revenue `T0828` (**Confirmed** [12] [1]). AA23-335A itself lists only Enterprise IDs for the Unitronics activity (`T1110`, `T1078.001`, `T1565.001`, `T1531`, `T1499`, `T1491.001`), which are in the Enterprise table (**Confirmed** [23]).

| ID | Technique | Tactic | Groups | Sources |
|---|---|---|---|---|
| [`T0817`](https://attack.mitre.org/techniques/T0817/) | Drive-by Compromise | Initial Access | G0049 OilRig | [1] |
| [`T0826`](https://attack.mitre.org/techniques/T0826/) | Loss of Availability | Impact | G1027 CyberAv3ngers | [1], [12] |
| [`T0827`](https://attack.mitre.org/techniques/T0827/) | Loss of Control | Impact | G1027 CyberAv3ngers | [1], [12] |
| [`T0829`](https://attack.mitre.org/techniques/T0829/) | Loss of View | Impact | G1027 CyberAv3ngers | [1], [12] |
| [`T0838`](https://attack.mitre.org/techniques/T0838/) | Modify Alarm Settings | Inhibit Response Function | G1027 CyberAv3ngers | [1], [12] |
| [`T0843`](https://attack.mitre.org/techniques/T0843/) | Program Download | Lateral Movement | G1027 CyberAv3ngers | [1], [12] |
| [`T0845`](https://attack.mitre.org/techniques/T0845/) | Program Upload | Collection | G1027 CyberAv3ngers | [1], [12] |
| [`T0852`](https://attack.mitre.org/techniques/T0852/) | Screen Capture | Collection | G0064 APT33 | [1] |
| [`T0859`](https://attack.mitre.org/techniques/T0859/) | Valid Accounts | Persistence, Lateral Movement | G0049 OilRig | [1] |
| [`T0865`](https://attack.mitre.org/techniques/T0865/) | Spearphishing Attachment | Initial Access | G0049 OilRig, G0064 APT33 | [1] |
| [`T0869`](https://attack.mitre.org/techniques/T0869/) | Standard Application Layer Protocol | Command and Control | G0049 OilRig | [1] |
| [`T0871`](https://attack.mitre.org/techniques/T0871/) | Execution through API | Execution | G1027 CyberAv3ngers | [1], [12] |
| [`T0879`](https://attack.mitre.org/techniques/T0879/) | Damage to Property | Impact | G1027 CyberAv3ngers | [1], [12] |
| [`T0880`](https://attack.mitre.org/techniques/T0880/) | Loss of Safety | Impact | G1027 CyberAv3ngers | [1], [12] |
| [`T0883`](https://attack.mitre.org/techniques/T0883/) | Internet Accessible Device | Initial Access | G1027 CyberAv3ngers | [1], [12] |
| [`T0885`](https://attack.mitre.org/techniques/T0885/) | Commonly Used Port | Command and Control | G1027 CyberAv3ngers | [1], [12] |
| [`T0886`](https://attack.mitre.org/techniques/T0886/) | Remote Services | Initial Access, Lateral Movement | G1027 CyberAv3ngers | [1], [12] |
| [`T0889`](https://attack.mitre.org/techniques/T0889/) | Modify Program | Persistence | G1027 CyberAv3ngers | [1], [12] |
| [`T0892`](https://attack.mitre.org/techniques/T0892/) | Change Credential | Inhibit Response Function | G1027 CyberAv3ngers | [1], [12] |
| [`T1692.001`](https://attack.mitre.org/techniques/T1692/001/) | Unauthorized Message: Command Message | Evasion, Impair Process Control | G1027 CyberAv3ngers | [1], [12] |
| [`T1694.001`](https://attack.mitre.org/techniques/T1694/001/) | Insecure Credentials: Default Credentials | Persistence, Lateral Movement | G1027 CyberAv3ngers | [1], [12] |
| [`T1695`](https://attack.mitre.org/techniques/T1695/) | Block Communications | Inhibit Response Function | G1027 CyberAv3ngers | [1], [12] |
| [`T1701.001`](https://attack.mitre.org/techniques/T1701/001/) | Command and Scripting Interpreter: PowerShell | Execution | G0049 OilRig, G0064 APT33 | [1] |
| [`T1701.004`](https://attack.mitre.org/techniques/T1701/004/) | Command and Scripting Interpreter: Visual Basic | Execution | G0049 OilRig | [1] |

### ATT&CK for Mobile

UNC788 ([`G1029`](https://attack.mitre.org/groups/G1029/)) has one Mobile technique, Phishing [`T1660`](https://attack.mitre.org/techniques/T1660/) (Initial Access), and one software entry (**Confirmed** [1]). The library generates no Mobile group page.

### Groups, campaigns and software

| Object | ID | Relationship in ATT&CK v20.0 | Source |
|---|---|---|---|
| The 19 Enterprise groups | see Part 1 | Iran-attributed in their own description | [1] |
| CyberAv3ngers | [`G1027`](https://attack.mitre.org/groups/G1027/) | ICS-only group; no library page | [1] [12] |
| UNC788 | [`G1029`](https://attack.mitre.org/groups/G1029/) | Mobile-only group; no library page | [1] |
| UNC3890 campaign | [`C0010`](/mitre/campaigns/C0010.md) | 2020-12 to 2022-08; Israeli shipping, government, aviation, energy and healthcare; no group object | [1] |
| HomeLand Justice | [`C0038`](/mitre/campaigns/C0038.md) | 2021-05 to 2022-09; Albania; the Groups table lists only VOID MANTICORE, and HEXANE appears in the narrative only | [13] |
| Outer Space | [`C0042`](/mitre/campaigns/C0042.md) | OilRig, 2021 | [1] |
| Juicy Mix | [`C0044`](/mitre/campaigns/C0044.md) | OilRig, 2022 | [1] |
| HEXANE | [`G1001`](/mitre/groups/G1001.md) | Not Iran-attributed in its own description; named as Iran-nexus in C0038 | [1] [13] |
| Shamoon | [`S0140`](/mitre/software/S0140.md) | First used in 2012 by a group calling itself Cutting Sword of Justice | [1] |
| ZeroCleare | [`S1151`](/mitre/software/S1151.md) | RawDisk-based wiper since at least 2019; linked to OilRig; used in C0038 | [1] [13] |
| CHIMNEYSWEEP, ROADSWEEP | [`S1149`](/mitre/software/S1149.md), [`S1150`](/mitre/software/S1150.md) | Used in C0038 | [13] |
| IOControl | [`S9046`](/mitre/software/S9046.md) | Attributed to IRGC-affiliated CyberAv3ngers | [1] |
| Havij | [`S0224`](/mitre/software/S0224.md) | Iranian ITSecTeam tool used by Ajax Security Team | [1] |
| RDAT | [`S0495`](/mitre/software/S0495.md) | OilRig | [1] |
| Group software | 111 IDs | See Part 3 | [1] |

### CWE and CAPEC

CWE IDs are the KEV catalog's `cwes` field for each CVE (Part 4). CAPEC IDs come from the library's `data/weaknesses/cwe.jsonl` for weakness-to-pattern links and from the `capec` field of `data/attack/technique_profiles.jsonl` for technique-to-pattern links (**Confirmed** [1] [33]). Broad classes (CWE-20, CWE-119, CWE-200, CWE-400) are not expanded. See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

| Weakness | CVEs in this record | CAPEC patterns linked in the library data |
|---|---|---|
| CWE-22 Path Traversal | CVE-2019-11510, CVE-2019-19781, CVE-2020-5902, CVE-2018-13379 | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal; [CAPEC-64](/mitre/capec/CAPEC-64.md); [CAPEC-76](/mitre/capec/CAPEC-76.md); [CAPEC-78](/mitre/capec/CAPEC-78.md); [CAPEC-79](/mitre/capec/CAPEC-79.md) |
| CWE-78 OS Command Injection | CVE-2019-11539 | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection; [CAPEC-6](/mitre/capec/CAPEC-6.md); [CAPEC-15](/mitre/capec/CAPEC-15.md); [CAPEC-43](/mitre/capec/CAPEC-43.md); [CAPEC-108](/mitre/capec/CAPEC-108.md) |
| CWE-77 Command Injection | CVE-2024-21887, CVE-2024-3400 | [CAPEC-248](/mitre/capec/CAPEC-248.md) Command Injection; [CAPEC-136](/mitre/capec/CAPEC-136.md); [CAPEC-15](/mitre/capec/CAPEC-15.md); [CAPEC-183](/mitre/capec/CAPEC-183.md); [CAPEC-40](/mitre/capec/CAPEC-40.md); [CAPEC-43](/mitre/capec/CAPEC-43.md); [CAPEC-75](/mitre/capec/CAPEC-75.md); [CAPEC-76](/mitre/capec/CAPEC-76.md) |
| CWE-94 Code Injection | CVE-2023-3519 | [CAPEC-242](/mitre/capec/CAPEC-242.md) Code Injection; [CAPEC-35](/mitre/capec/CAPEC-35.md); [CAPEC-77](/mitre/capec/CAPEC-77.md) |
| CWE-287 Improper Authentication | CVE-2020-12812, CVE-2021-34523, CVE-2020-0688 | [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass; [CAPEC-114](/mitre/capec/CAPEC-114.md); [CAPEC-151](/mitre/capec/CAPEC-151.md); [CAPEC-194](/mitre/capec/CAPEC-194.md); [CAPEC-22](/mitre/capec/CAPEC-22.md); [CAPEC-57](/mitre/capec/CAPEC-57.md); [CAPEC-593](/mitre/capec/CAPEC-593.md); [CAPEC-633](/mitre/capec/CAPEC-633.md); [CAPEC-650](/mitre/capec/CAPEC-650.md); [CAPEC-94](/mitre/capec/CAPEC-94.md) |
| CWE-306 Missing Authentication for Critical Function | CVE-2019-5591, CVE-2022-1388 | [CAPEC-12](/mitre/capec/CAPEC-12.md); [CAPEC-166](/mitre/capec/CAPEC-166.md); [CAPEC-216](/mitre/capec/CAPEC-216.md); [CAPEC-36](/mitre/capec/CAPEC-36.md) Using Unpublished Interfaces or Functionality; [CAPEC-62](/mitre/capec/CAPEC-62.md) |
| CWE-434 Unrestricted Upload of Dangerous File Type | CVE-2021-31207 | [CAPEC-1](/mitre/capec/CAPEC-1.md) Accessing Functionality Not Properly Constrained by ACLs |
| CWE-502 Deserialization of Untrusted Data | CVE-2021-44228 | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection |
| CWE-917 Expression Language Injection | CVE-2021-45046, CVE-2022-26134 | None in the library data |
| CWE-918 Server-Side Request Forgery | CVE-2021-34473 | [CAPEC-664](/mitre/capec/CAPEC-664.md) Server Side Request Forgery |
| CWE-1188 Insecure Default Initialization | CVE-2023-6448 | The library's only linked pattern (CAPEC-665, Thunderbolt protection flaws) does not fit a PLC default password; see technique `T1078.001` below |

| Technique (Iranian use) | CAPEC patterns linked in the library data |
|---|---|
| `T1110.003` Password Spraying (AA24-290A, Peach Sandstorm) | [CAPEC-565](/mitre/capec/CAPEC-565.md) Password Spraying |
| `T1110` Brute Force (AA23-335A, AA24-290A) | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force |
| `T1078.001` Default Accounts (Unitronics PLCs, AA22-320A) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords |
| `T1133` External Remote Services (AA24-241A, AA24-290A) | [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials |
| `T1566.001` and `T1566.002` Spearphishing (seven groups each, AA22-055A) | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing |
| `T1505.003` Web Shell (seven groups, AA20-259A, AA24-241A) | [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server |
| `T1036.005` Match Legitimate Resource Name or Location (eight groups) | [CAPEC-543](/mitre/capec/CAPEC-543.md) Counterfeit Websites; [CAPEC-616](/mitre/capec/CAPEC-616.md) Establish Rogue Location |

### D3FEND countermeasures

The advisory guidance in Part 8 maps to these D3FEND countermeasures, each with a library page; the "library maps it to" column is the library's own `d3fend_countermeasures.jsonl` and `technique_to_d3fend.jsonl` (D3FEND 1.6.0). The live D3FEND pages for Multi-factor Authentication, Change Default Password and Software Update were opened; the live slug for the first is `d3f:Multi-factorAuthentication` (**Confirmed** [85] [1]). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

| Advisory guidance | D3FEND countermeasure | Library maps it to (Iran-relevant techniques) | Sources |
|---|---|---|---|
| Phishing-resistant MFA | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (`D3-MFA`) | `T1110.003`; not `T1621` or `T1133` | [18] [21] [25] [27] |
| Replace default passwords | [Change Default Password](/mitre/d3fend/change-default-password.md) (`D3-CDP`) | `T1078.001`, `T1110.003` | [23] [27] |
| NIST-aligned password policy | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (`D3-SPP`) | `T1110.003` | [25] |
| Patch KEV and internet-facing systems | [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (`D3-AVE`), [Software Inventory](/mitre/d3fend/software-inventory.md) (`D3-SWI`) | not `T1190` (a gap) | [18] [19] [21] [24] [27] |
| Reduce exposure, filter and allowlist remote access | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (`D3-ITF`), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (`D3-NTF`), [Disable Remote Access](/mitre/d3fend/disable-remote-access.md) (`D3-DRA`) | `D3-ITF` maps `T1190` | [21] [23] [27] |
| Application control | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`) | `T1204.002`, `T1505.003` | [18] |
| Impossible travel and unusual logons | [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) (`D3-UGLPA`) | `T1021.001`, `T1190`, `T1572` | [25] |
| Monitor new accounts | [Domain Account Monitoring](/mitre/d3fend/domain-account-monitoring.md) (`D3-DAM`), [Local Account Monitoring](/mitre/d3fend/local-account-monitoring.md) (`D3-LAM`) | `T1136.002`, `T1078.002`; `T1136.001` | [21] |
| Monitor new scheduled tasks | [Scheduled Job Analysis](/mitre/d3fend/scheduled-job-analysis.md) (`D3-SJA`) | not `T1053.005` (a gap) | [21] |
| RDP monitoring | [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (`D3-RTSD`) | `T1021.001` | [21] |
| Block tunneling egress (ngrok and similar) | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`) | `T1572`, `T1105`, `T1071.001` | [21] [24] |
| External-sender banners, link hygiene | [Email Filtering](/mitre/d3fend/email-filtering.md) (`D3-EF`), [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (`D3-URA`) | `T1566.001`, `T1566.002`, `T1204.001` | [18] |
| Disable departing accounts | [Account Locking](/mitre/d3fend/account-locking.md) (`D3-AL`) | the `T1078` family | [25] |
| Back up data and PLC logic | [Restore Configuration](/mitre/d3fend/restore-configuration.md) (`D3-RC`), [Restore File](/mitre/d3fend/restore-file.md) (`D3-RF`) | `D3-RF` maps `T1486` | [19] [23] [27] |
| No countermeasure in the library data | none | `T1059.001` PowerShell | [1] |

### Navigator layers

The study's techniques are collected in two ATT&CK Navigator layers, listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md):

- Enterprise: [`navigator/library-layers/threat-actors-iran.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-iran.json), 260 techniques in 313 technique-tactic entries. Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/threat-actors-iran.json). The score is the number of Iran-attributed groups plus the number of joint advisories that name the technique (maximum 18): a count of public reporting, not prevalence or severity. Each comment names the groups and the study's source numbers.
- ICS: [`navigator/case-studies/threat-actors-iran-ics.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/threat-actors-iran-ics.json), domain `ics-attack`, 24 techniques in 28 technique-tactic entries, scored by the number of the three groups (CyberAv3ngers, OilRig, APT33) linked to each. Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/case-studies/threat-actors-iran-ics.json). Curated layers under `navigator/library-layers/` must be `enterprise-attack`, so the ICS layer sits with the other ICS case-study layers.

### Notes on the library's data

- **Count drift against live ATT&CK.** The live VOID MANTICORE page lists 75 technique rows, 25 of them citing the HomeLand Justice campaign, and campaign-derived software (CHIMNEYSWEEP, Impacket, ftp among them); the library data holds 63 direct techniques and no group-level software. The live page appears to fold in campaign relationships the library's group counts leave out (**Confirmed** for the counts [6] [1]; the cause is **Inferred**). The live CyberAv3ngers page (version 1.1, modified 7 October 2026) lists 19 ICS technique rows and links three software entries in its description (Studio Logix 5000 Designer, Totally Integrated Automation (TIA) Portal and EcoStruxure Control Expert), whose own ATT&CK software pages returned 404 when this study re-checked them on 11 November 2026, so their IDs are left out here; the library holds 17 techniques and no software for the group, which points to data drift after the library's ATT&CK pull (**Inferred** [12] [1]).
- **The Threat Actors page needs a correction.** Its Iran-Nexus table lists CyberAv3ngers as a "Volt Typhoon lookalike" with ATT&CK ID "None" (ATT&CK has `G1027`), heads OilRig "(Ministry of Intelligence)" and APT33 "(IRGC)" where ATT&CK v20.0 names no service for either, and covers 4 of the 21 Iran-attributed ATT&CK groups (**Confirmed** [14] [1]). This study is the fuller record until that page is updated.

## Cross-cutting themes

- **Attribution has layers, and each source picks one.** The same cluster can be "Iranian" in ATT&CK, "IRGC-affiliated" in a joint advisory, "operating for the IRGC Intelligence Organization, moderate confidence" at Mandiant, and named by front company in a Treasury release. A defender's report should carry the layer and the confidence, not just the name. See the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md).
- **Contractors blur state and crime.** Pioneer Kitten serves the Government of Iran but works with ransomware affiliates on the side, which the FBI judges is likely not sanctioned; Najee and Afkar ran their own BitLocker extortion; SamSam's operators were Iranian criminals with no state tie alleged (**Confirmed** [24] [19] [45]). Treat "Iranian" and "state" as two separate claims.
- **Personas are a delivery mechanism.** HomeLand Justice, Karma, Handala, CyberAv3ngers, Holy Souls and Br0k3r are names chosen for an audience. Governments and vendors have tied each to a state organization, but the persona's own claims (device counts, victim lists) are claims (**Confirmed** [20] [75] [76] [23] [70] [24]; the reading is **Inferred**).
- **Legal action names people and fronts but does not stop the work.** Indictments in 2016, 2018, 2019, 2022, 2024 and 2026 and sanctions in 2018, 2020, 2021, 2022, 2024 and 2026 sit beside an activity record that continues through 2026 (**Inferred** from the timeline). The 2026 superseding Mabna indictment covers activity from 2013 (**Reported** [87] [88]).
- **Old flaws keep working.** Nineteen of the twenty advisory CVEs are now in KEV, most of them added in the catalog's first release on 3 November 2021, and controllers on default passwords need no CVE at all. The record argues for exposure management over novelty hunting (**Inferred** from [33] [23]).
- **Healthcare is in the blast radius more than the crosshairs.** The confirmed hospital cases come through shared infrastructure; the targeting that looks deliberate is research espionage and, in 2026, a supplier (**Inferred** from Part 6). See the [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md).

### Hype and evidence

Some threats in this record read larger than the evidence supports, and some read smaller.

- **Overstated: persona device counts.** Handala claimed it wiped more than 200,000 Stryker devices; TechCrunch reports tens of thousands, and Stryker's own filing gives no count (**Reported** [93] [91]; the filing **Confirmed** [59]). A persona writes for an audience, so its count stays a claim until the victim or a government confirms it (**Inferred**).
- **Overstated: the hospital cases as a hospital campaign.** The confirmed US hospital cases came through the same edge devices, weak passwords and exposed controllers the actors use everywhere, and the authors of AA21-321A assess the actors exploit known vulnerabilities rather than choosing sectors (**Confirmed** [17]). Reading those cases as a campaign aimed at hospitals overstates the record (**Inferred** from Part 6).
- **Understated: IRGC-CEC PLC tampering.** Treasury describes the 2023 Unitronics activity as defacements, but the AA23-335A update records custom ladder logic and disabled upload and download functions, and AA26-097A records manipulated project files and HMI displays and, in one case, disabled shutdown and alarm logic (**Confirmed** [40] [23] [29]). That is interference with process control, not only a defaced screen, and water, building and hospital facility teams should plan for it (**Inferred**).
- **Understated: device-management abuse.** The Stryker reporting points to a legitimate remote-wipe function in a management console, and the company's filing found no ransomware or malware (**Reported** [93]; **Confirmed** [59]; the link between them is **Inferred**). A program that hunts only for malware would miss a fleet wiped through its own console (**Inferred**).

## Sources

Every source below was opened on 3 November 2026. Grades apply to the source type: Confirmed for a primary (the publisher of the fact), Reported for secondary coverage or a filing whose text could not be read.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | TeamStarWolf library data at commit e85b559 (ATT&CK v20.0): data/attack/groups.jsonl, group_profiles.jsonl, group_to_technique.jsonl, campaign_profiles.jsonl, software_profiles.jsonl, technique_profiles.jsonl, superseded_by.jsonl, ics/, mobile/, d3fend_countermeasures.jsonl, technique_to_d3fend.jsonl; data/weaknesses/; generated mitre/ pages | https://github.com/TeamStarWolf/TeamStarWolf/tree/e85b5594301fe061043fe92040135252c97b695d/data/attack | 2026-11-03 | Confirmed |
| 2 | MITRE ATT&CK, Group G0059 Magic Hound (version 6.1, modified 31 July 2026) | https://attack.mitre.org/groups/G0059/ | 2026-11-03 | Confirmed |
| 3 | MITRE ATT&CK, Group G0049 OilRig (version 5.0, modified 31 July 2026) | https://attack.mitre.org/groups/G0049/ | 2026-11-03 | Confirmed |
| 4 | MITRE ATT&CK, Group G0069 MuddyWater (version 7.0, modified 31 July 2026) | https://attack.mitre.org/groups/G0069/ | 2026-11-03 | Confirmed |
| 5 | MITRE ATT&CK, Group G1059 NIMBUS MANTICORE (version 1.0, created 1 October 2026) | https://attack.mitre.org/groups/G1059/ | 2026-11-03 | Confirmed |
| 6 | MITRE ATT&CK, Group G1055 VOID MANTICORE (version 1.0, created 20 April 2026, modified 31 July 2026) | https://attack.mitre.org/groups/G1055/ | 2026-11-03 | Confirmed |
| 7 | MITRE ATT&CK, Group G0087 APT39 (version 3.2) | https://attack.mitre.org/groups/G0087/ | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, Group G0117 Fox Kitten (version 2.0) | https://attack.mitre.org/groups/G0117/ | 2026-11-03 | Confirmed |
| 9 | MITRE ATT&CK, Group G1044 APT42 (version 1.1, modified 22 September 2026) | https://attack.mitre.org/groups/G1044/ | 2026-11-03 | Confirmed |
| 10 | MITRE ATT&CK, Group G0064 APT33 (version 2.0) | https://attack.mitre.org/groups/G0064/ | 2026-11-03 | Confirmed |
| 11 | MITRE ATT&CK, Group G1030 Agrius (version 1.0) | https://attack.mitre.org/groups/G1030/ | 2026-11-03 | Confirmed |
| 12 | MITRE ATT&CK, Group G1027 CyberAv3ngers (version 1.1, modified 7 October 2026) | https://attack.mitre.org/groups/G1027/ | 2026-11-03 | Confirmed |
| 13 | MITRE ATT&CK, Campaign C0038 HomeLand Justice (version 1.1) | https://attack.mitre.org/campaigns/C0038/ | 2026-11-03 | Confirmed |
| 14 | TeamStarWolf library, THREAT_ACTORS.md at commit e85b559 | https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/THREAT_ACTORS.md | 2026-11-03 | Confirmed |
| 15 | CISA with FBI, AA20-259A, Iran-based actor exploiting VPN and edge vulnerabilities (2020-09-15) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-259a | 2026-11-03 | Confirmed |
| 16 | CISA, AA20-304A, Iranian APT targeting US voter information (2020-10-30) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-304a | 2026-11-03 | Confirmed |
| 17 | FBI, CISA, ACSC and NCSC, AA21-321A, Iranian Government-Sponsored APT Cyber Actors Exploiting Microsoft Exchange and Fortinet Vulnerabilities (2021-11-17) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a | 2026-11-03 | Confirmed |
| 18 | FBI, CISA, CNMF and NCSC, AA22-055A, MuddyWater (2022-02-24) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a | 2026-11-03 | Confirmed |
| 19 | FBI, CISA, NSA, CNMF, Treasury, ACSC, CCCS and NCSC, AA22-257A, IRGC-affiliated cyber actors (2022-09-14) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-257a | 2026-11-03 | Confirmed |
| 20 | FBI and CISA, AA22-264A, Iranian state actors' attack on the Government of Albania (2022-09-21) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a | 2026-11-03 | Confirmed |
| 21 | CISA and FBI, AA22-320A, Iranian government-sponsored APT compromises a federal network (2022-11-16) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a | 2026-11-03 | Confirmed |
| 22 | CISA alert, Exploitation of Unitronics PLCs used in Water and Wastewater Systems (2023-11-28) | https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems | 2026-11-03 | Confirmed |
| 23 | FBI, CISA, NSA, EPA, INCD, CCCS and NCSC, AA23-335A, IRGC-affiliated actors exploit PLCs (2023-12-01, updated 2024-12-18) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a | 2026-11-03 | Confirmed |
| 24 | FBI, CISA and DC3, AA24-241A, Iran-based actors enabling ransomware (2024-08-28) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a | 2026-11-03 | Confirmed |
| 25 | FBI, CISA, NSA, CSE, AFP and ASD's ACSC, AA24-290A, Iranian brute force and credential access (2024-10-16) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a | 2026-11-03 | Confirmed |
| 26 | CISA, FBI, DC3 and NSA, Iranian Cyber Actors May Target Vulnerable US Networks and Entities of Interest, web page (2025-06-30) | https://www.cisa.gov/resources-tools/resources/iranian-cyber-actors-may-target-vulnerable-us-networks-and-entities-interest | 2026-11-03 | Confirmed |
| 27 | The same joint fact sheet, PDF | https://www.cisa.gov/sites/default/files/2025-06/joint-fact-sheet-Iranian-cyber-actors-may-target-vulnerable-US-networks-and-entities-of-interest-508c-1.pdf | 2026-11-03 | Confirmed |
| 28 | The same fact sheet as posted by IC3 | https://www.ic3.gov/CSA/2025/250630.pdf | 2026-11-03 | Confirmed |
| 29 | FBI, CISA, NSA, EPA, DOE, CNMF and Treasury, AA26-097A, Iranian-affiliated APT disrupts PLCs (2026-04-07, revised 2026-07-22) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a | 2026-11-03 | Confirmed |
| 30 | FBI, Treasury and INCD, Emennet Pasargad advisory (2024-10-30) | https://www.ic3.gov/CSA/2024/241030.pdf | 2026-11-03 | Confirmed |
| 31 | ODNI, FBI and CISA, joint statement on Iranian election influence (2024-08-19) | https://content.govdelivery.com/accounts/USDHSCISA/bulletins/3afd156 | 2026-11-03 | Confirmed |
| 32 | CISA, AA18-337A, SamSam ransomware (2018-12-03) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a | 2026-11-03 | Confirmed |
| 33 | CISA, Known Exploited Vulnerabilities catalog, JSON feed (catalog version 2026.11.03) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |
| 34 | US Treasury, sm0332, Mabna Institute designation (2018-03-23) | https://home.treasury.gov/news/press-releases/sm0332 | 2026-11-03 | Confirmed |
| 35 | US Treasury, sm556, SamSam-related designations (2018-11-28) | https://home.treasury.gov/news/press-releases/sm556 | 2026-11-03 | Confirmed |
| 36 | US Treasury, sm1127, APT39 and Rana Intelligence Computing (2020-09-17) | https://home.treasury.gov/news/press-releases/sm1127 | 2026-11-03 | Confirmed |
| 37 | US Treasury, jy0494, Emennet Pasargad (2021-11-18) | https://home.treasury.gov/news/press-releases/jy0494 | 2026-11-03 | Confirmed |
| 38 | US Treasury, jy0941, MOIS and Minister Khatib (2022-09-09) | https://home.treasury.gov/news/press-releases/jy0941 | 2026-11-03 | Confirmed |
| 39 | US Treasury, jy0948, Najee Technology and Afkar System Yazd (2022-09-14) | https://home.treasury.gov/news/press-releases/jy0948 | 2026-11-03 | Confirmed |
| 40 | US Treasury, jy2072, IRGC Cyber-Electronic Command officials (2024-02-02) | https://home.treasury.gov/news/press-releases/jy2072 | 2026-11-03 | Confirmed |
| 41 | US Treasury, jy2292, IRGC-CEC front companies (2024-04-23) | https://home.treasury.gov/news/press-releases/jy2292 | 2026-11-03 | Confirmed |
| 42 | US Treasury, jy2621, election interference designations (2024-09-27) | https://home.treasury.gov/news/press-releases/jy2621 | 2026-11-03 | Confirmed |
| 43 | FBI, Iranian DDoS Attacks (wanted notice) | https://www.fbi.gov/wanted/cyber/iranian-ddos-attacks | 2026-11-03 | Confirmed |
| 44 | FBI, Iranian Mabna Hackers (wanted notice) | https://www.fbi.gov/wanted/cyber/iranian-mabna-hackers | 2026-11-03 | Confirmed |
| 45 | FBI, SamSam Subjects (wanted notice) | https://www.fbi.gov/wanted/cyber/samsam-subjects | 2026-11-03 | Confirmed |
| 46 | FBI, Monica Elfriede Witt (wanted notice) | https://www.fbi.gov/wanted/counterintelligence/monica-elfriede-witt | 2026-11-03 | Confirmed |
| 47 | FBI, Iranian Cyber Actors (wanted notice, Ahmadi and others) | https://www.fbi.gov/wanted/cyber/iranian-cyber-actors | 2026-11-03 | Confirmed |
| 48 | FBI, Masoud Jalili (wanted notice) | https://www.fbi.gov/wanted/cyber/masoud-jalili | 2026-11-03 | Confirmed |
| 49 | US District Court, D. Md., seizure warrant filing, case 1:26-mj-00683-CDA (filed 2026-03-19; scanned, no text layer) | https://www.justice.gov/opa/media/1431956/dl?inline | 2026-11-03 | Confirmed (existence); Reported (contents) |
| 50 | FBI, Director's remarks to the Boston Conference on Cyber Security (2022-06-01) | https://www.fbi.gov/news/speeches-and-testimony/directors-remarks-to-boston-conference-on-cyber-security-2022 | 2026-11-03 | Confirmed |
| 51 | Rewards for Justice, CyberAv3ngers | https://rewardsforjustice.net/rewards/cyberav3ngers/ | 2026-11-03 | Confirmed |
| 52 | UK government, UK condemns Iran for reckless cyber attack against Albania (2022-09-07) | https://www.gov.uk/government/news/uk-condemns-iran-for-reckless-cyber-attack-against-albania | 2026-11-03 | Confirmed |
| 53 | NCSC, UK condemns cyber attack (2022-09-07) | https://www.ncsc.gov.uk/news/uk-condemns-cyber-attack | 2026-11-03 | Confirmed |
| 54 | EEAS, Declaration by the High Representative on behalf of the EU expressing solidarity with Albania (2022-09-08) | `https://www.eeas.europa.eu/delegations/albania/cyber-attacks-declaration-high-representative-behalf-european-union-expressing-solidarity-albania_en` | 2026-11-03 | Confirmed |
| 55 | NCSC, UK and allies expose Iranian state agency for exploiting cyber vulnerabilities for ransomware operations (2022-09-20) | https://www.ncsc.gov.uk/sites/default/files/2026-08/UK-and-allies-expose-Iranian-state-agency-for-exploiting-cyber-vulnerabilities-for-ransomware-operations.pdf | 2026-11-03 | Confirmed |
| 56 | NCSC, advice to UK organisations following conflict in the Middle East (2026-03-02) | https://www.ncsc.gov.uk/news/ncsc-advises-uk-organisations-take-action-following-conflict-in-middle-east | 2026-11-03 | Confirmed |
| 57 | Israel Ministry of Foreign Affairs, Operation Rising Lion: key factual and legal aspects (2025) | https://www.gov.il/BlobFolder/generalpage/operation-rising-lion-key-factual-and-legal-aspects-of-the-iran-israel-hostilities-june-2025-11-aug-2025/en/English_Swords_of_Iron_DOCUMENTS_Operation_Rising_Lion_2025_Israel-Iran-Key_Factual_and_Legal_Aspects2.pdf | 2026-11-03 | Confirmed |
| 58 | Israel National Cyber Directorate, Annual Summary 2023 | https://www.gov.il/BlobFolder/news/booklet_yearly_summary_2023/en/booklet_yearly_summary_2023_eng.pdf | 2026-11-03 | Confirmed |
| 59 | Stryker Corporation, Form 8-K (2026-03-11) | `https://www.sec.gov/Archives/edgar/data/310764/000119312526102460/d76279d8k.htm` | 2026-11-03 | Confirmed |
| 60 | Microsoft, Microsoft investigates Iranian attacks against the Albanian government (2022-09-08) | https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/ | 2026-11-03 | Confirmed |
| 61 | Mandiant, APT33: insights into Iranian cyber espionage (2017-09-20) | https://cloud.google.com/blog/topics/threat-intelligence/apt33-insights-into-iranian-cyber-espionage | 2026-11-03 | Confirmed |
| 62 | Mandiant, targeted attack in the Middle East by APT34 (2017-12-07) | https://cloud.google.com/blog/topics/threat-intelligence/targeted-attack-in-middle-east-by-apt34 | 2026-11-03 | Confirmed |
| 63 | Mandiant, APT39: an Iranian cyber espionage group focused on personal information (2019-01-29) | https://cloud.google.com/blog/topics/threat-intelligence/apt39-iranian-cyber-espionage-group-focused-on-personal-information | 2026-11-03 | Confirmed |
| 64 | Mandiant, APT42: crooked charms, cons and compromises (2022-09-06) | https://cloud.google.com/blog/topics/threat-intelligence/apt42-charms-cons-compromises | 2026-11-03 | Confirmed |
| 65 | Mandiant, suspected Iranian actor targeting Israeli shipping (UNC3890) (2022-08-17) | https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping/ | 2026-11-03 | Confirmed |
| 66 | Unit 42, The OilRig campaign: attacks on Saudi Arabian organizations deliver Helminth backdoor (2016-05-26) | https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/ | 2026-11-03 | Confirmed |
| 67 | Unit 42, Shamoon 2: return of the Disttrack wiper (2016-11-30) | https://unit42.paloaltonetworks.com/unit42-shamoon-2-return-disttrack-wiper/ | 2026-11-03 | Confirmed |
| 68 | Unit 42, Iranian cyberattacks threat brief (2026) | https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/ | 2026-11-03 | Confirmed |
| 69 | Microsoft On the Issues, recent cyberattacks require us all to be vigilant (2019-10-04) | https://blogs.microsoft.com/on-the-issues/2019/10/04/recent-cyberattacks-require-us-all-to-be-vigilant/ | 2026-11-03 | Confirmed |
| 70 | Microsoft Security Insider, Iran responsible for Charlie Hebdo attacks (2023-02-02) | https://www.microsoft.com/en-us/security/security-insider/emerging-threats/iran-responsible-for-charlie-hebdo-attacks | 2026-11-03 | Confirmed |
| 71 | Microsoft, Peach Sandstorm password spray campaigns (2023-09-14) | https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/ | 2026-11-03 | Confirmed |
| 72 | Microsoft Security Insider, Iran surges cyber-enabled influence operations in support of Hamas | https://www.microsoft.com/en-us/security/security-insider/threat-landscape/iran-surges-cyber-enabled-influence-operations-in-support-of-hamas/ | 2026-11-03 | Confirmed |
| 73 | Microsoft, new TTPs observed in Mint Sandstorm campaign (2024-01-17) | https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/ | 2026-11-03 | Confirmed |
| 74 | Google Threat Analysis Group, Iranian-backed group steps up phishing campaigns against Israel and the US (2024-08-14) | https://blog.google/threat-analysis-group/iranian-backed-group-steps-up-phishing-campaigns-against-israel-us/ | 2026-11-03 | Confirmed |
| 75 | Check Point, Unveiling Void Manticore (2024-05-20) | https://blog.checkpoint.com/research/unveiling-void-manticore-structured-collaboration-between-espionage-and-destruction-in-mois/ | 2026-11-03 | Confirmed |
| 76 | Check Point Research, Handala Hack: unveiling the group's modus operandi (2026-03-12) | https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/ | 2026-11-03 | Confirmed |
| 77 | Check Point Research, Iranian Educated Manticore targets leading tech academics (2025-06-25) | https://research.checkpoint.com/2025/iranian-educated-manticore-targets-leading-tech-academics/ | 2026-11-03 | Confirmed |
| 78 | ESET, MuddyWater targets critical infrastructure in Israel and Egypt (2025-12-02) | https://www.eset.com/us/about/newsroom/research/iran-muddywater-critical-infrastructure-israel-egypt-snake-game-eset-research/ | 2026-11-03 | Confirmed |
| 79 | Proofpoint, BadBlood: TA453 targets US and Israeli medical research personnel (2021-03-30) | https://www.proofpoint.com/us/blog/threat-insight/badblood-ta453-targets-us-and-israeli-medical-research-personnel-credential | 2026-11-03 | Confirmed |
| 80 | Beazley Security, Pay2Key: Iranian-linked ransomware is back (2026) | https://beazley.security/insights/pay2key-iranian-linked-ransomware-is-back-back-again | 2026-11-03 | Confirmed |
| 81 | American Hospital Association, landing page for the HHS HC3 TLP:CLEAR brief "Iranian Threat Actors and Healthcare" (2022-11-03) | https://www.aha.org/cybersecurity-government-intelligence-reports/2022-11-03-hhs-ocio-hc3-tlp-clear-threat-brief-iranian-threat-actors-and | 2026-11-03 | Reported |
| 82 | American Hospital Association, FBI reminds of potentially malicious activity by Iranian cyber actors (2026-03-03) | https://www.aha.org/news/headline/2026-03-03-fbi-reminds-potentially-malicious-activity-iranian-cyber-actors | 2026-11-03 | Reported |
| 83 | American Hospital Association, agencies release fact sheet on Iranian cyber actors (2025-07-01) | https://www.aha.org/news/headline/2025-07-01-agencies-release-fact-sheet-potential-malicious-activity-iranian-cyber-actors | 2026-11-03 | Reported |
| 84 | Health-ISAC, Feds warn healthcare sector of rising Iranian cyberthreats (2025-06-27) | https://health-isac.org/feds-warn-healthcare-sector-of-rising-iranian-cyberthreats/ | 2026-11-03 | Reported |
| 85 | MITRE D3FEND, Multi-factor Authentication (D3-MFA), with Change Default Password and Software Update | https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/ | 2026-11-03 | Confirmed |
| 86 | Nextgov/FCW, Treasury sanctions Iranian hackers tied to critical infrastructure breaches (2026-08) | https://www.nextgov.com/cybersecurity/2026/08/treasury-sanctions-iranian-hackers-tied-critical-infrastructure-breaches/415619/ | 2026-11-03 | Reported |
| 87 | The National, Iran hackers and the HBO hacking case (2026-08-18) | https://www.thenationalnews.com/future/technology/2026/08/18/iran-hackers-hbo-hacking/ | 2026-11-03 | Reported |
| 88 | Cybersecurity Dive, DOJ charges 17 in Iran hacking campaign against US universities (2026-08) | https://www.cybersecuritydive.com/news/doj-charges-17-iran-hacking-campaign-us-university/828212/ | 2026-11-03 | Reported |
| 89 | Nextgov/FCW, US charges Iranian operatives for hacking Trump campaign (2024-09) | https://www.nextgov.com/cybersecurity/2024/09/us-charges-iranian-operatives-hacking-trump-campaign/399900/ | 2026-11-03 | Reported |
| 90 | The Record, FBI takes down leak sites tied to Iran's MOIS (2026-03-20) | https://therecord.media/fbi-takes-down-leak-sites-iran-mois | 2026-11-03 | Reported |
| 91 | TechCrunch, US accuses Iran's government of operating hacktivist group that hacked Stryker (2026-03-20) | https://techcrunch.com/2026/03/20/u-s-accuses-irans-government-of-operating-hacktivist-group-that-hacked-stryker/ | 2026-11-03 | Reported |
| 92 | Cybersecurity Dive, DOJ seizes domains tied to Iranian threat actor (2026-03) | https://cybersecuritydive.com/news/doj-seizure-domains-iran-threat-actor/815306 | 2026-11-03 | Reported |
| 93 | KrebsOnSecurity, Iran-backed hackers claim wiper attack on medtech firm Stryker (2026-03) | https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/ | 2026-11-03 | Reported |
| 94 | Voice of America, Albania cuts diplomatic ties with Iran (2022-09-07) | https://www.voanews.com/a/6734763.html | 2026-11-03 | Reported |
| 95 | GBH News, FBI director says Iran was behind thwarted cyberattack on Boston Children's Hospital (2022-06-01) | https://wgbh.org/news/local/2022-06-01/fbi-director-says-iran-was-behind-thwarted-cyberattack-on-boston-childrens-hospital | 2026-11-03 | Reported |
| 96 | The Register, Iran behind US casino hack (2015-02-27) | https://www.theregister.com/2015/02/27/iran_behind_us_casino_hack/ | 2026-11-03 | Reported |
| 97 | TechCrunch, Justice Department indicts two Iranians over SamSam ransomware attacks (2018-11-28) | https://techcrunch.com/2018/11/28/justice-department-indicts-two-iranians-over-samsam-ransomware-attacks | 2026-11-03 | Reported |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors](/THREAT_ACTORS.md) (see the correction note in Part 9)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Generated MITRE pages: groups [Magic Hound `G0059`](/mitre/groups/G0059.md), [OilRig `G0049`](/mitre/groups/G0049.md), [MuddyWater `G0069`](/mitre/groups/G0069.md), [NIMBUS MANTICORE `G1059`](/mitre/groups/G1059.md), [VOID MANTICORE `G1055`](/mitre/groups/G1055.md), [APT39 `G0087`](/mitre/groups/G0087.md), [Fox Kitten `G0117`](/mitre/groups/G0117.md), [APT42 `G1044`](/mitre/groups/G1044.md), [APT33 `G0064`](/mitre/groups/G0064.md), [Agrius `G1030`](/mitre/groups/G1030.md) and [Silent Librarian `G0122`](/mitre/groups/G0122.md); campaigns [`C0010`](/mitre/campaigns/C0010.md), [`C0038` HomeLand Justice](/mitre/campaigns/C0038.md), [`C0042` Outer Space](/mitre/campaigns/C0042.md) and [`C0044` Juicy Mix](/mitre/campaigns/C0044.md); software [Shamoon `S0140`](/mitre/software/S0140.md), [ZeroCleare `S1151`](/mitre/software/S1151.md), [Pay2Key `S0556`](/mitre/software/S0556.md), [POWERSTATS `S0223`](/mitre/software/S0223.md) and [IOControl `S9046`](/mitre/software/S9046.md); techniques [Exploit Public-Facing Application `T1190`](/mitre/techniques/T1190.md), [External Remote Services `T1133`](/mitre/techniques/T1133.md), [Password Spraying `T1110.003`](/mitre/techniques/T1110-003.md), [Multi-Factor Authentication Request Generation `T1621`](/mitre/techniques/T1621.md), [Default Accounts `T1078.001`](/mitre/techniques/T1078-001.md) and [Web Shell `T1505.003`](/mitre/techniques/T1505-003.md)
- Related case studies: [All case studies](/case-studies/README.md); [China-Attributed Threat Actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Other State-Linked Threat Actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-Attributed Threat Actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Log4Shell](/case-studies/LOG4SHELL.md), [Operation Exchange Marauder](/case-studies/EXCHANGE_MARAUDER_2021.md), [Stuxnet](/case-studies/STUXNET.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md), [APT41: The Public Record](/case-studies/APT41_PUBLIC_RECORD.md), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md)
- [Navigator layers](/navigator/index.md)
