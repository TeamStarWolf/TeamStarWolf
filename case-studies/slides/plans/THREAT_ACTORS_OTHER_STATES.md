# Slide plan: Other State-Linked Threat Actors: The Public Record

- Study: case-studies/THREAT_ACTORS_OTHER_STATES.md
- Cover title: Other State-Linked / Threat Actors / The Public Record
- Subtitle: The tier outside the five largest programs, from Darkhotel in 2004 to 2025
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/THREAT_ACTORS_OTHER_STATES.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Most victims of this tier never appear in big-five reports

- The tier is real and long-running: Darkhotel since 2004, most groups first seen from 2012 to 2017, reporting through 2025.
- Attribution is softer: only Dark Caracal is tied by ATT&CK to a named government body.
- The tradecraft is documents and lures: a malicious file opened by a user (13 groups), a spearphishing attachment (11).
- The most damaging routes need no CVE: Sea Turtle's DNS hijacking and MoustachedBouncer's ISP-level injection.
Caption: Four items rest on secondary or contested sources and are graded Reported, among them the Stealth Falcon zero-day link.
Notes: Long-running [12][26][42][46][53][54]. Dark Caracal and Lebanon's GDGS [12][40]. Technique counts across the 20 bound groups [32]. No-CVE routes [42][48]. Reported items [50][37][62][67].

## KEY FACTS | Twenty-seven groups reviewed, twenty bound, one named agency

Stat: 27 | Enterprise ATT&CK groups reviewed
Stat: 20 | groups bound in the MITRE mappings
Stat: 154 | Enterprise techniques linked to the 20
Stat: 22 | exploited CVEs, all in KEV
- Firmest attribution: Dark Caracal, tied to Lebanon's General Directorate of General Security.
- Oldest and newest: Darkhotel since at least 2004; Stealth Falcon's reported zero-day use in March 2025.
- Nine of the 22 CVEs are Office or Office components; six carry KEV's Known ransomware flag.
- Two ATT&CK campaigns: C0011 (Transparent Tribe) and C0033 (PROMETHIUM).
Notes: Groups reviewed against live ATT&CK pages, plus the Mobile-only G0097 [1][2][32]. Dark Caracal [12][40]. Darkhotel [26]; Stealth Falcon Reported [50]. KEV catalog 2026.11.03 [56]. Campaigns [8][22][32].

## PART 1 | Attribution in this tier is a ladder with few top rungs

| Rung in ATT&CK's wording | Groups |
|---|---|
| Named government body | Dark Caracal (Lebanon's GDGS) |
| "Suspected" country | APT32, Sidewinder, Transparent Tribe, Darkhotel, Higaisa |
| Country link without the hedge | SideCopy, Volatile Cedar, Sea Turtle |
| Explicitly unconfirmed | Stealth Falcon (UAE) |
| Region, language, movement or none | BITTER, Molerats, WIRTE, Machete, Metador and others |
Caption: Vendors sometimes go further: Mandiant aligns APT32 with Vietnam, ESET MoustachedBouncer with Belarus (medium confidence).
Notes: ATT&CK wording for every group [2] to [31]; the ladder reading is Inferred from the Part 1 table. Vendor assessments [34][35][48]. None of the 28 descriptions names healthcare [1].

## PART 2 | South Asia is a contest of neighbours, fought through documents

Left: India-linked
- Patchwork: six Office and Windows CVEs on its ATT&CK page; a late-2021 campaign on Pakistan's Ministry of Defense.
- Sidewinder: CVE-2017-11882 still in use in 2024; maritime and nuclear targets later that year.
- BITTER: government, energy and engineering; Confucius resembles Patchwork.
Right: Pakistan-linked
- Transparent Tribe trojanized an imitation of Aarogya Setu, India's COVID-19 app, in 2020.
- From December 2021 it went after Indian students with CrimsonRAT (campaign C0011).
- SideCopy's infection chain mimics Sidewinder's.
Caption: Lookalike chains mean a technique match is weak evidence of who is behind an intrusion (Inferred).
Notes: Patchwork [3][36]. Sidewinder [4][53][54]. Confucius [5]; BITTER [6]. Transparent Tribe [7][37][8][38]; the Pakistan intelligence link to fake Aarogya Setu apps is Reported [37]. SideCopy [9]. Gorgon Group not bound because of its criminal mix [10].

## PART 3 | APT32 holds the largest ATT&CK record in the tier

Stat: 78 | APT32 techniques in the library data
Stat: 15 | APT32 software objects
Stat: 2004 | Darkhotel's earliest activity per ATT&CK
- Mandiant (May 2017) assesses APT32 as aligned with Vietnamese state interests; dissidents targeted since 2013.
- Meta (December 2020) tied APT32 to CyberOne Group, an IT company in Vietnam; its targets include hospitals.
- Darkhotel reached traveling executives over hotel networks with Flash zero-days and abused certificates.
- Kaspersky made no nationality claim for Darkhotel; the South Korean suspicion is ATT&CK's.
Caption: Higaisa, also suspected South Korean, is not bound: no vendor primary was opened for it.
Notes: APT32 [2][32][34][35]. Darkhotel [26][52]. Higaisa [27].

## PART 4 | Middle East targets are dissidents, journalists and Israel

Left: Lebanon and the Gulf
- Dark Caracal: thousands of victims in 21+ countries through trojanized Signal and WhatsApp apps.
- Believed run from a GDGS building in Beirut (Lookout and EFF, 2018).
- Stealth Falcon: Emirati journalists and dissidents since 2012; UAE link not confirmed.
- BlackOasis: a believed Gamma Group customer.
Right: Hamas and Gaza
- Molerats (Gaza Cybergang): Arabic-speaking, active since 2012.
- WIRTE: a believed Gaza Cybergang subgroup; wipers against Israeli targets.
- APT-C-23: Android and iOS spyware since 2017; Israeli military assets.
Caption: Stealth Falcon's CVE-2025-33053 zero-day against a defense organization in Türkiye rests on a press account (Reported).
Notes: Dark Caracal [12][40][41]. Stealth Falcon [11][49]; 2025 zero-day via The Record [50]; KEV and NVD [51][56]. BlackOasis [15]. Gaza groups [16][17][18]. POLONIUM belongs with the Iran record [14].

## PART 5 | Sea Turtle went under everything by hijacking DNS

Stat: 40+ | organizations hit in 13 countries, 2017 to 2019
Stat: 7 | CVEs Talos listed, likely incomplete
Stat: 7 yrs | CISA ED 19-01 stayed open
- Talos (April 2019): high confidence that a state-sponsored actor hijacked DNS through registrars and registries.
- The operator of Greece's .gr domain disclosed a compromise on 19 April 2019.
- Hunt & Hackett tied 2021 to 2023 Netherlands campaigns through cPanel and SSH to Sea Turtle.
- Microsoft's Marbled Dust, which overlaps Sea Turtle, exploited Output Messenger CVE-2025-27920.
Caption: ED 19-01 names no actor; linking it to Sea Turtle is Inferred from timing and subject.
Notes: Talos [42][43]. ED 19-01 issued 22 January 2019 and closed 8 January 2026 [44]. Hunt & Hackett [45]. Marbled Dust [46]. KEV [56].

## PART 5 | In Belarus the attack came through the internet provider

- MoustachedBouncer, active since at least 2014, targets foreign embassies in Belarus.
- Since 2020 it has likely tampered with traffic at ISP level to serve a fake Windows Update that delivers Disco.
- ESET assesses with medium confidence that it is aligned with Belarus's interests.
- Mandiant links UNC1151 (Ghostwriter) with high confidence to the Belarusian government; no ATT&CK object exists.
- PROMETHIUM (StrongPity) has a heavy Turkish emphasis; a Türkiye link is Inferred from victimology only.
Caption: ESET's advice is an end-to-end encrypted VPN tunnel to a trusted network.
Notes: MoustachedBouncer [24][48][32]. UNC1151 [47][32]. PROMETHIUM and campaign C0033 [21][22]; NEODYMIUM [23].

## PART 7 | From hotel networks to zero-days, vendors wrote the record

| Date | Event |
|---|---|
| 10 Nov 2014 | Kaspersky's Darkhotel report |
| 29 May 2016 | Citizen Lab on Stealth Falcon |
| 14 May 2017 | Mandiant's report on APT32 |
| 18 Jan 2018 | Lookout and EFF on Dark Caracal |
| 22 Jan 2019 | CISA Emergency Directive 19-01 |
| 17 Apr 2019 | Talos's Sea Turtle report |
| 10 Dec 2020 | Meta takedown of APT32 |
| 10 Aug 2023 | ESET on MoustachedBouncer |
| 15 Oct 2024 | Kaspersky on SideWinder |
| Mar 2025 | Stealth Falcon zero-day (Reported) |
Caption: Commodity RATs recur across South Asian and Gaza groups, and FinFisher appears with Dark Caracal.
Notes: Rows [52][49][34][40][44][42][35][48][53][50]. Era reading Inferred from the Part 7 table. Tooling from Part 8 [15][40][32].

## PART 9 | All 22 CVEs are in KEV, and nine are old Office flaws

Stat: 22 | CVEs named, all in KEV
Stat: 9 | Office or Office components
Stat: 6 | with KEV's Known ransomware flag
Stat: 19 | added 3 Nov 2021 to 25 Mar 2022
- All nine Office CVEs entered KEV in its initial backfill, 3 November 2021 to 3 March 2022.
- Kaspersky still recorded SideWinder exploiting CVE-2017-11882 in 2024.
- Seven are internet-edge and server flaws Talos listed for Sea Turtle.
Caption: A remediation SLA keyed only to new KEV additions never raises the old Office flaws (Inferred).
Notes: KEV catalog version 2026.11.03, 1,767 entries [56]. Exceptions to the early window: CVE-2015-8651, CVE-2025-27920 and CVE-2025-33053 [56]. SideWinder [53]. Sea Turtle [42]. Group pages [3][4][6][7].

## PART 10 | Healthcare is collateral here; named harm comes from the big five

- None of the in-scope ATT&CK descriptions names healthcare.
- Meta lists hospitals among APT32's targets; Patchwork reached molecular medicine faculty.
- Dark Caracal compromised the devices of medical professionals.
- Transparent Tribe used health themes as lures: a fake COVID-19 app and a mental health survey.
- In the big five, WannaCry hit at least 81 of 236 NHS trusts, and North Korea's Maui hit US healthcare.
Caption: No indictment, sanctions designation or joint attribution names any of the 20 bound groups (Inferred).
Notes: Healthcare view [1][35][36][40][37][38]. NHS [91]; Maui and H0lyGh0st [96][97][98]. AA20-126A names no group [55]. Part 12 government record [44][35][39].

## PART 11 | US-linked platforms rest on leaks, not on admissions

- Kaspersky named Equation in February 2015 and linked it to the Stuxnet and Flame groups, naming no state.
- Regin: 27 victims in 14 countries; Kaspersky warned the metadata could be a false flag.
- Microsoft said the Shadow Brokers exploits were stolen from the NSA: a vendor statement.
- Vault 7's authenticity and China's NSA accusation over Northwestern Polytechnical are Reported.
Caption: The lesson is capability: firmware implants, GSM access and zero-click mobile chains were in the record by 2015 to 2023.
Notes: Equation and Fanny [57][58]. Flame [59]; Duqu 2.0 [60]; Regin [61]; the Lamberts [63]. Shadow Brokers and WannaCry [64][65]. Vault 7 [62]; CVERC [67]. Operation Triangulation [66]. The fuller record belongs to the United States study.

## MITRE MAPPINGS | This tier leads with a user opening a file

| Id | Technique | Groups of 20 |
|---|---|---|
| T1204.002 | Malicious File | 13 |
| T1566.001 | Spearphishing Attachment | 11 |
| T1105 | Ingress Tool Transfer | 10 |
| T1203 | Exploitation for Client Execution | 9 |
| T1059.001 | PowerShell | 8 |
| T1547.001 | Registry Run Keys / Startup Folder | 8 |
Caption: Layer scores count groups (1 to 13), not severity; the big-five advisories lead with T1190 instead. MITRE notice in notes.
Notes: 154 techniques as 181 technique-tactic entries: Stealth 39, Discovery 19, Execution 17 [32]. Vendor-stated T1584.002, T1557 and T1659 [42][48]. No D3FEND mapping for T1584.002, T1588.004, T1553.002, T1659, T1685.006 or T1690 [32]. Mobile techniques for Dark Caracal and APT-C-23 [32]. Comparison advisories [76][77][87]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Lock the registrar, block the macro, distrust the network

Left: Trust infrastructure
- Registry lock and MFA on every DNS and registrar account.
- Audit public DNS records; watch Certificate Transparency logs.
- DNSSEC signing and validation; passive DNS monitoring.
- Encrypted VPN to a trusted network on hotel and in-country links.
Right: Endpoints and phones
- Patch Office on a build-currency rule.
- Block macros from the internet; alert on PowerShell launched from Office.
- Official app stores only; block sideloading.
- Alert on binaries signed with weak or revoked certificates.
Caption: None of the trust-infrastructure items has a CVE, so a CVE-driven program will not raise them (Inferred).
Notes: DNS and registrar [42][43][44]. In-path injection [48]. Travelers [52]. Office build currency [56]. Macros and PowerShell [49][32]. Mobile apps [40][37]. Detection points Inferred.

## CROSS-CUTTING THEMES | Regional rivalry drives targeting; bought tools blur the actor

- **Attribution lives on the lower rungs.** One named agency, and many groups with no state at all.
- **Regional rivalry drives targeting.** India and Pakistan, Gaza and Israel, Türkiye and Kurdish groups.
- **Civil society carries the cost.** Journalists, activists and diaspora, often reached by phone.
- **Bought tools blur the actor.** FinFisher, Gamma Group and commodity RATs make tool hits leads.
- **Trust infrastructure is the outsized risk.** Registrars, certificates and the network path itself.
Notes: Ladder from Part 1. Rivalry Inferred from Parts 2 to 5. Civil society [11][15][35][40]. Tools Inferred from Part 8. Trust infrastructure [42][48]. Overstated: this tier's reach into Western healthcare and confidence in names; understated: DNS and registrar risk and old Office flaws [53]. The government spotlight falls elsewhere (Part 12).
