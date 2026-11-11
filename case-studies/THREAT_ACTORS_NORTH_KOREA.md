# North Korea-Attributed Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md), [Other state-linked threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [Lazarus Group page](/mitre/groups/G0032.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, threat hunters, vulnerability managers, healthcare security teams, hiring and HR security partners, and teams protecting cryptocurrency operations

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 76 min (17,590 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a graded, dated account of which North Korean state bodies and ATT&CK groups the public record names, how they get in (recruiter and interview lures, trojanized software, known flaws in internet-facing systems and IT workers hired under false identities), where healthcare appears, and what the advisories say to patch, hunt and harden

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: identity, names and the sponsor](#part-1-identity-names-and-the-sponsor), [Part 7: the defender view](#part-7-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Actors](/THREAT_ACTORS.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Insider Threat Reference](/INSIDER_THREAT_REFERENCE.md), [Blockchain Security Reference](/BLOCKCHAIN_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Few defenders meet a North Korean operator by name. They meet a recruiter on LinkedIn with a job that pays too well, a remote developer who will not turn on a camera, a messenger update at a small hospital, a trading app that a colleague installed, or a ransom note that claims to come from somebody else. Behind those encounters, governments and researchers describe one state program that has run for more than fifteen years: espionage against South Korea, the United States and their allies, destructive attacks such as the 2014 Sony Pictures wiper, and, increasingly, theft that a multilateral sanctions monitor counts in billions of dollars a year. This study gathers the public record of that program in one place, dates every event, and grades every claim by the source that supports it.

The record supports five plain statements. First, the attribution is unusually well documented. US criminal charges (2018, 2020, 2024), US Treasury designations (2018, 2019, 2023, 2025), joint advisories and statements co-signed by US, South Korean, Japanese and UK agencies, and a multilateral monitoring report by eleven states all name North Korean state bodies, from the Reconnaissance General Bureau (RGB) and its units to the Munitions Industry Department (**Confirmed**). Second, the money is the mission. US agencies said in 2020 that the regime increasingly relies on cybercrime to fund its weapons programs, and the eleven-state Multilateral Sanctions Monitoring Team (MSMT) counted at least $1.19 billion in cryptocurrency stolen in 2024 and at least $1.65 billion in the first nine months of 2025 (**Confirmed** [23] [73]). Third, healthcare is a deliberate target, not collateral. FBI, CISA and Treasury warned in July 2022 that North Korean state-sponsored actors had used Maui ransomware against healthcare organizations since at least May 2021, and a 2024 indictment charges an Andariel member with encrypting servers at a Kansas hospital and attacking other US healthcare providers to fund espionage (**Confirmed** [38] [57]). Fourth, a fast-expanding part of the record is not malware at all: thousands of North Korean IT workers hired under false identities, now extorting employers with stolen code, and reaching more than 70 US companies, including health care companies, in a single 2026 case (**Confirmed** [37] [66] [78]; the 'expanding' reading is **Inferred** from the 2022 to 2026 sequence). Fifth, the names do not line up. "Lazarus Group" is an umbrella that ATT&CK itself warns about, the US government uses its own names (HIDDEN COBRA, BeagleBoyz, TraderTraitor), and vendors split the same activity into APT38, APT43, APT45, Jasper Sleet, Famous Chollima and more (**Confirmed** for each mapping; the conclusion is **Inferred**).

What this means for a security program is practical. Identity is the perimeter: user execution of a malicious file (seven of eight groups) and spearphishing attachments (six) are the most widely shared behaviors across the eight ATT&CK groups, and five groups build fake personas and accounts. The IT worker scheme defeats hiring, not firewalls. Internet-facing systems at hospitals and clinics are exploited for ransom, through Log4Shell, SonicWall and NAS flaws that are all in CISA's Known Exploited Vulnerabilities (KEV) catalog. Cryptocurrency firms and their software suppliers face the largest thefts in this record. And a technique layer built from Andariel's ATT&CK page misses every technique ID in the 2024 Andariel advisory, and one built from all eight group pages still misses 10 of its 22, so defenders should read the advisories, not just the matrix.

Evidence grade: the court record, sanctions, advisories, ATT&CK pages and vendor reports are each **Confirmed** against a primary source opened on 3 November 2026. Attribution statements are reported at the confidence each source states, from "able to confirm" (FBI) to "likely theory" (Kaspersky, 2013). The 2026 Binance attribution is **Confirmed** as an FBI statement, but its acceptance is disputed in press coverage that is **Reported** only.

### Key facts at a glance

| Field | Value |
|---|---|
| Sponsor named by governments | The Reconnaissance General Bureau (RGB), North Korea's main intelligence bureau; Lazarus Group placed under the RGB 3rd Bureau's 110th Research Center (Treasury, 2019); Kimsuky under the RGB's 63rd Research Center (FBI, State and NSA, 2024); IT workers dispatched by the 313 General Bureau of the Munitions Industry Department (State, Treasury and FBI, 2022; MSMT, 2025) |
| ATT&CK v20.0 groups | Eight: [`G0032` Lazarus Group](/mitre/groups/G0032.md), [`G0067` APT37](/mitre/groups/G0067.md), [`G0082` APT38](/mitre/groups/G0082.md), [`G0094` Kimsuky](/mitre/groups/G0094.md), [`G0138` Andariel](/mitre/groups/G0138.md), [`G1036` Moonstone Sleet](/mitre/groups/G1036.md), [`G1049` AppleJeus](/mitre/groups/G1049.md), [`G1052` Contagious Interview](/mitre/groups/G1052.md) |
| US government names | HIDDEN COBRA (DHS and FBI, 2017), BeagleBoyz (bank theft, 2020), TraderTraitor (cryptocurrency theft, 2022 onward) |
| Active since | At least 2009 (HIDDEN COBRA, Lazarus Group, Andariel); Kimsuky and APT37 since at least 2012 |
| ATT&CK record | 240 distinct Enterprise techniques across the eight groups' direct relationships; campaigns [`C0022` Operation Dream Job](/mitre/campaigns/C0022.md) and [`C0057` 3CX Supply Chain Attack](/mitre/campaigns/C0057.md); 1 ICS technique (Lazarus) and 1 Mobile technique (Kimsuky) |
| Court record | Park Jin Hyok (complaint 2018-06-08; indictment with Jon Chang Hyok and Kim Il, warrants 2020-12-08, Central District of California); Rim Jong Hyok (indictment 2024-07-24, District of Kansas, Maui ransomware against US hospitals) |
| Sanctions | Park Jin Hyok and Chosun Expo (2018-09-06); Lazarus Group, Bluenoroff and Andariel (2019-09-13); Kimsuky (2023-11-30); Song Kum Hyok and a Russia-based IT worker network (2025-07-08) |
| Largest attributed thefts | Binance, more than $6 billion (FBI, 2026-10-31, disputed); Bybit, about $1.5 billion (FBI, 2025-02-26); Ronin bridge, $620 million (FBI, 2022-04-14); DMM Bitcoin, $308 million (FBI, DC3 and Japan's NPA, 2024-12-23) |
| Healthcare record | WannaCry and the NHS (2017); Maui ransomware against US healthcare since May 2021; COVID-19 vaccine and health ministry targeting (2020, single-vendor reports from Kaspersky and Microsoft); Andariel ransomware funding espionage (2024); Medusa ransomware attempt on a US healthcare organization (reported 2026-02-24 by a single vendor, Symantec); IT workers hired at health care companies (2026) |
| Latest public activity | Operation Lonestar Roundup against Texas laptop farms (searches 2026-09-21 to 25, announced 2026-10-13); the Binance theft on or about 2026-10-29 |

### Key findings

- **Every major attribution in this record has a dated government statement behind it, and WannaCry and DMM Bitcoin carry more than one government's.** Sony Pictures (FBI, December 2014), WannaCry (UK, US, Australia, Canada and New Zealand, December 2017), Bangladesh Bank (Treasury, 2018 and 2019), the Ronin, Harmony and Atomic Wallet thefts (FBI, 2022 and 2023), DMM Bitcoin (FBI with Japan's NPA, 2024) and Bybit (FBI, 2025) each carry a dated government statement (**Confirmed** [14] [19] [23] [21] [22] [34] [40] [45] [64] [65] [68]).
- **ATT&CK grades its own attribution, and the grades differ.** Four groups are "attributed to the Reconnaissance General Bureau" (G0032, G0082, G0138, G1049), APT37 is "state-sponsored", Kimsuky is "DPRK-based", Moonstone Sleet is "North Korean-linked" and Contagious Interview is "North Korea-aligned" (**Confirmed** [2] to [9]). This study keeps those words and does not upgrade them (**Inferred**).
- **Ransomware against healthcare pays for espionage.** AA24-207A says Andariel funds its espionage through ransomware against US healthcare entities and was seen running both against the same victim, sometimes on the same day (**Confirmed** [60]). The Rim Jong Hyok indictment names a Kansas hospital whose intranet, X-ray and imaging, document management and sleep lab servers were encrypted on or about 4 May 2021 (**Confirmed** [57]).
- **The attribution of Maui depends on whose names you use.** The US government ties Maui to Andariel. Mandiant's APT45, which overlaps Andariel, assesses with moderate confidence that the group has developed ransomware, but it cannot confirm ransomware use by APT45 and mentions Maui only by citing CISA, without attributing it (**Confirmed** [57] [60] [61]; the reconciliation is **Inferred**).
- **The IT worker scheme is now an insider threat with extortion.** From the 2022 guidance (a single worker able to earn over $300,000 a year) to the 2025 PSA on stolen-code extortion and the 2026 Operation Lonestar Roundup (over 40 suspected laptop farms searched, about 187 laptops and KVM devices seized, 14 people charged), the record shows growth, not decline (**Confirmed** [37] [66] [78]; the reading that the scheme is growing is **Inferred**).
- **The money is measured by sanctions monitors, not by the FBI.** FBI statements give per-incident figures; the only government annual totals opened for this study are MSMT's: at least $1.19 billion in 2024 and at least $1.65 billion from January to September 2025, counting only high-certainty heists (**Confirmed** [73]; the absence of an FBI annual figure is **Inferred** from what was opened).
- **ATT&CK under-represents the 2024 Andariel record.** None of the 22 technique IDs in AA24-207A is among Andariel's 12 direct ATT&CK relationships, and 10 are absent from all eight groups' records (computed from [60] and [12]; **Inferred**).

### Top recommendations

1. Verify people, not just accounts. Verify identity throughout employment, not only at hiring, audit staffing firms, and alert when one account logs in from several countries (**Confirmed** [66]); the FBI's October 2026 PSA calls the approach "identity in depth" (**Confirmed** [79]). Treat refusal to appear on video, a laptop shipped to a freight forwarder, or repositories copied to a personal account as red flags (**Confirmed** [48] [66]), and handle them as security incidents rather than HR matters (**Inferred**).
2. Patch internet-facing systems at hospitals and clinics on the KEV clock. All three initial access CVEs in the 2023 healthcare advisory (Log4Shell, SonicWall SMA 100, TerraMaster OS) are in KEV with known ransomware use. Do not stop at KEV: 16 of the 45 CVEs listed in AA24-207A are not in the catalog (**Confirmed** [41] [60] [83]).
3. Harden mail against impersonation. Kimsuky impersonates journalists and academics and exploits missing or `p=none` DMARC policies; set DMARC to `p=quarantine` or `p=reject` with aggregate reporting, and verify unusual requests by phone or video (**Confirmed** [44] [53]).
4. Treat cryptocurrency software and recruiter contact as supply chain risk. TraderTraitor and AppleJeus deliver trojanized trading and wallet apps through recruitment and investment lures; the DMM Bitcoin theft began with a fake LinkedIn recruiter contacting a supplier's employee (**Confirmed** [32] [35] [64]).
5. Plan healthcare recovery for an operator who is in no hurry. Maui appears designed for manual execution by a remote operator, has encrypted EHR, imaging and diagnostic servers, and sometimes caused long disruptions; keep offline, encrypted, immutable and tested backups, segment medical IoT and EHR systems, and disable or secure WAN-facing management interfaces (**Confirmed** [38] [41]).
6. Build detections from the advisories, not just the group pages. Load this study's Navigator layer (Part 8), which adds the advisory-only techniques, and hunt for the behaviors the advisories name: mshta launching HTA files, PowerShell run without `powershell.exe`, zeroed firewall registry values and HWP file-association changes (**Confirmed** [26]).

## Scope and method

This study covers activity that a government or vendor primary attributes to North Korea, or to a group that ATT&CK v20.0 attributes to North Korea, from the earliest US government label (HIDDEN COBRA activity since 2009) through the FBI's Binance alert of 31 October 2026 and press coverage dated 3 November 2026. It draws on six kinds of source: court records and FBI wanted pages; US Treasury designations; joint government advisories and FBI public service announcements (PSAs); the MSMT report and the statement of its member states; vendor threat reports; and the MITRE ATT&CK pages and the TeamStarWolf library's own data files. Every source in the Sources table was opened on 3 November 2026 unless its row says otherwise.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the court, agency, vendor or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution, at the confidence it states; it does not upgrade the source's confidence |
| Reported | Only a secondary source (press coverage) was available, or the primary did not open |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

Like the newer studies in this series, this one grades by source type (primary opened versus secondary only); under the README's original scheme, a single vendor's report would read as Reported.

Three rules govern the names. The study says which name each source uses ("Mandiant's APT45", "the FBI's TraderTraitor", "Microsoft's Jasper Sleet") instead of merging labels. A source's own hedge travels with its claim ("likely", "moderate confidence", "aligned"). And figures are reported as the source states them, including where two official sources count differently (48 or 81 NHS trusts; $1.5 billion or $1.4 billion for Bybit).

Several sources did not open and are not cited as opened: the Department of Justice press releases for the 2018 Park Jin Hyok charges and the 2021 three-hacker indictment (under justice.gov `/archives/`) and for the 2024 Rim Jong Hyok indictment (under justice.gov `/opa/pr/`, row 58), each behind a bot-verification page that was not bypassed; the HHS HC3 briefing decks (HTTP 403); the 2025-01-14 US, Japan and South Korea joint statement on 2024 thefts; the NCSC and NIS advisory body of 2023-11-23 beyond its news page; and the four South Korean agencies' July 2026 advisory. The FBI wanted pages, the indictment PDF, Treasury releases and Rewards for Justice cover the charging facts instead. Where a claim rests only on press coverage of an unopened primary, it is graded Reported.

This study links to, and does not retell, the library's other studies: [Log4Shell](/case-studies/LOG4SHELL.md) for CVE-2021-44228, [APT41](/case-studies/APT41_PUBLIC_RECORD.md) for the Chinese group that HHS briefed alongside North Korean actors in 2023, and [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md) for the 2024 US healthcare ransomware event, which is not attributed to North Korea. The 2014 Sony Pictures attack, the 2016 Bangladesh Bank heist and WannaCry are summarized here with their government record; their narrative lives in [Notable Incidents](/NOTABLE_INCIDENTS.md).

Other studies in this series hold neighboring material, and this study is the home for the North Korea actor record itself. The [United States-attributed threat actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) is the home for the April 2017 leak of the SMBv1 exploit that WannaCry reused and for the harm to the NHS; this study keeps WannaCry's attribution and government record. The [Sandworm operations study](/case-studies/SANDWORM_OPERATIONS.md) is the home for Olympic Destroyer, the 2018 attack dressed up as North Korean work. The [npm supply-chain attacks study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) holds the malicious packages that vendors tie to Contagious Interview and Jade Sleet, and the [AI threats study](/case-studies/AI_THREATS_2026.md) holds the provider reports on state actors, North Korea among them, using language models. The year-by-year context for the 2019 HOPLIGHT report and Treasury designation, the 2020 Operation Dream Job reporting and the 2021 AppleJeus advisory sits in the [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md) and [2021](/case-studies/CHRONICLE_2021.md) chronicles. The [China](/case-studies/THREAT_ACTORS_CHINA.md), [Russia](/case-studies/THREAT_ACTORS_RUSSIA.md), [Iran](/case-studies/THREAT_ACTORS_IRAN.md) and [other state-linked](/case-studies/THREAT_ACTORS_OTHER_STATES.md) studies hold the other national records in this series.

Tradecraft is described at the level the advisories use: technique names and IDs. No runnable commands, payload strings or exploit details appear here.

## Part 1: identity, names and the sponsor

### The eight ATT&CK groups

ATT&CK v20.0 attributes exactly eight groups to North Korea, and the library's data files list the same eight (**Confirmed** [1] [12]). A ninth group, Higaisa (`G0126`), mentions North Korea only as a target; ATT&CK says it has suspected South Korean origins, so it is excluded (**Confirmed** [1]). ATT&CK group objects record no last-seen date, so the "last modified" column is the page's edit date, not a last-activity date.

| ID | Name | ATT&CK wording (short) | Since at least | Aliases ATT&CK lists | Page version, created, modified | Library techniques and software | Sources |
|---|---|---|---|---|---|---|---|
| [`G0032`](/mitre/groups/G0032.md) | Lazarus Group | state-sponsored, attributed to the RGB | 2009 | Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet | v5.0; 31 May 2017; 31 July 2026 | 93 Enterprise, 1 ICS; 26 software | [2], [12] |
| [`G0067`](/mitre/groups/G0067.md) | APT37 | state-sponsored cyber espionage group | 2012 | InkySquid, ScarCruft, Reaper, Group123, TEMP.Reaper, Ricochet Chollima | v2.0; 18 April 2018; 31 July 2026 | 29; 13 software | [3], [12] |
| [`G0082`](/mitre/groups/G0082.md) | APT38 | state-sponsored, financial operations, attributed to the RGB | 2014 | includes BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet | v4.0; 29 January 2019; 09 October 2026 | 115; 6 software | [4], [12] |
| [`G0094`](/mitre/groups/G0094.md) | Kimsuky | DPRK-based cyber espionage group | 2012 | includes APT43, Emerald Sleet, THALLIUM, Velvet Chollima, TA427, Springtail | v5.2; 26 August 2019; 31 July 2026 | 130 Enterprise, 1 Mobile; 19 software | [5], [12] |
| [`G0138`](/mitre/groups/G0138.md) | Andariel | state-sponsored, a sub-set of Lazarus, attributed to the RGB | 2009 | Silent Chollima, PLUTONIUM, Onyx Sleet | v2.0; 29 September 2021; 31 July 2026 | 12; 2 software | [6], [12] |
| [`G1036`](/mitre/groups/G1036.md) | Moonstone Sleet | "North Korean-linked threat actor" | distinct from Lazarus since 2023 | Storm-1789 | v1.0; 26 August 2024; 31 July 2026 | 30; 1 software | [7], [12] |
| [`G1049`](/mitre/groups/G1049.md) | AppleJeus | state-sponsored, attributed to the RGB | 2018 | Gleaming Pisces, Citrine Sleet, UNC1720, UNC4736 | v1.0; 25 August 2025; 31 July 2026 | 2; 0 software | [8], [12] |
| [`G1052`](/mitre/groups/G1052.md) | Contagious Interview | "North Korea-aligned threat group active since 2023" | 2023 | includes DeceptiveDevelopment, DEV#POPPER, PurpleBravo, TAG-121 | v1.0; 19 October 2025; 31 July 2026 | 54; 4 software | [9], [12] |

What ATT&CK says about each, in brief (**Confirmed** for each [2] to [10]):

- **Lazarus Group** is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, and its malware is linked to Operation Flame, 1Mission, Troy, DarkSeoul and Ten Days of Rain. ATT&CK warns that public reporting often uses "Lazarus Group" as an umbrella term for several North Korean operators. Its attributed campaign [`C0022` Operation Dream Job](/mitre/campaigns/C0022.md) (aliases Operation North Star and Operation Interception) was "likely conducted by" Lazarus from September 2019 to August 2020 against defense, aerospace and government targets in the US, Israel, Australia, Russia and India.
- **APT37** targets primarily South Korea, and also Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait and other parts of the Middle East, with 2016 to 2018 campaigns including Operation Daybreak, Erebus, Golden Time and FreeMilk.
- **APT38** specializes in financial operations against banks, financial institutions, casinos, cryptocurrency exchanges, SWIFT endpoints and ATMs in at least 38 countries, and ATT&CK names the 2016 Bank of Bangladesh heist, Bancomext and Banco de Chile.
- **Kimsuky** first targeted South Korean government agencies, think tanks and subject-matter experts, then expanded to the UN and to government, education, business services and manufacturing in the US, Japan, Russia and Europe. ATT&CK assesses it was responsible for the 2014 Korea Hydro and Nuclear Power compromise and records LLM-assisted activity in 2023.
- **Andariel** has focused on South Korean government, military and domestic companies, including destructive attacks, and has also run financial operations against ATMs, banks and cryptocurrency exchanges.
- **Moonstone Sleet** carries out both financially motivated attacks and espionage, with tradecraft distinct from Lazarus since 2023, and is noted for fake companies and personas and a malicious game.
- **AppleJeus** targets the cryptocurrency industry and is held most notably responsible for the [`C0057` 3CX Supply Chain Attack](/mitre/campaigns/C0057.md) (November 2022 to March 2023).
- **Contagious Interview** runs espionage and financially motivated operations, stealing cryptocurrency and credentials, against software developers and cryptocurrency-related individuals on Windows, Linux and macOS.

Two ATT&CK software entries cite North Korea but are linked to no group: [KONNI `S0356`](/mitre/software/S0356.md), used by North Korean cyber actors since at least 2014, and [SYSCON `S0464`](/mitre/software/S0464.md), associated with campaigns that use North Korean themes (**Confirmed** [12]). ATT&CK's [`C0013` Operation Sharpshooter](/mitre/campaigns/C0013.md) (September 2017 to March 2019) is attributed to no group; its description notes similarities with earlier Lazarus operations (**Confirmed** [12]). None of these is counted here as North Korean activity.

### The sponsor as governments describe it

The government documents build a consistent organization chart (**Confirmed** for each line):

- **Reconnaissance General Bureau (RGB).** Treasury designated Lazarus Group, Bluenoroff and Andariel on 13 September 2019 as controlled by the RGB and placed Lazarus under the 110th Research Center of the RGB 3rd Bureau [22]. AA24-207A places Andariel in the RGB 3rd Bureau, based in Pyongyang and Sinuiju [60].
- **Kimsuky.** Treasury calls it RGB-subordinate and active since 2012 (designation of 30 November 2023, coordinated with Australia, Japan and South Korea) [52]; the May 2024 joint advisory says it is administratively subordinate to the RGB's 63rd Research Center [53].
- **BeagleBoyz.** The 2020 FASTCash advisory calls this bank-theft team "an element of" the RGB that overlaps, to varying degrees, with APT38, Bluenoroff, Lazarus and Stardust Chollima [25].
- **TraderTraitor.** The FBI's name for the cryptocurrency-theft cluster, equated in FBI statements with Lazarus Group and APT38 [35] [45], and in the DMM Bitcoin statement with Jade Sleet, UNC4899 and Slow Pisces [64].
- **IT workers.** The 2022 State, Treasury and FBI guidance names the 313 General Bureau of the Munitions Industry Department among the dispatching entities [37]; MSMT adds that the 313 General Bureau formed in a 2015 reorganization of the Korea Computer Center and is subordinate to the UN-designated Munitions Industry Department [73].
- **Front companies.** Treasury designated Chosun Expo Joint Venture, Park Jin Hyok's employer, on 6 September 2018 [21].

### Names the vendors use

Vendors draw boundaries in different places. Each line is that vendor's own mapping (**Confirmed** for each).

- **Mandiant (Google).** APT43, tracked since 2018, which operates on behalf of the regime and whose priorities "align" with the RGB's mission [42] (ATT&CK lists APT43 as a Kimsuky alias [5]); APT45, state-sponsored with high confidence and part of the RGB with moderate confidence, overlapping Andariel, Onyx Sleet, Stonefly and Silent Chollima [61]; UNC4736 for the X_TRADER and 3CX compromise [43].
- **Microsoft.** Diamond Sleet and Onyx Sleet (exploiting JetBrains TeamCity in 2023) [49]; Moonstone Sleet (formerly Storm-1789), "North Korean state-aligned" [55]; Jasper Sleet (formerly Storm-0287) for the IT worker program [70]; DEV-0530, now Storm-0530, for H0lyGh0st ransomware, likely overlapping PLUTONIUM (Andariel) but distinct [39]; and earlier Zinc and Cerium for 2020 vaccine-research targeting [27].
- **CrowdStrike.** Famous Chollima for the IT worker group in the 2026 DOJ case, as the DOJ release reports it [78].
- **Palo Alto Networks Unit 42.** Contagious Interview (CL-STA-0240) and Wagemole (CL-STA-0241) [50].
- **ESET.** DeceptiveDevelopment, a "North Korea-aligned" cluster not tied to a known actor [67]; Operation In(ter)ception with only hints of a Lazarus link [24].
- **Symantec.** Stonefly for Andariel and APT45 activity [63].
- **Kaspersky.** Kimsuky (first named 2013) [13]; Bluenoroff as a Lazarus subunit focused on financial theft [15].

### Where the sources disagree

| Topic | One source says | Another says | Sources |
|---|---|---|---|
| Kimsuky's origin, 2013 | Kaspersky's first report ends its title with a question mark and calls North Korean origin a "likely theory" | Later US advisories and ATT&CK state the attribution firmly | [13], [26], [5] |
| Operation In(ter)ception, 2019 | ESET found no strong evidence for attribution, only hints of a Lazarus link | ATT&CK's C0022 says "likely conducted by Lazarus Group" | [24], [10] |
| 3CX, 2023 | Mandiant: moderate confidence that UNC4736 is related to AppleJeus activity; weak infrastructure overlap with APT43 | ATT&CK attributes C0057 to G1049 without that hedge | [43], [8] |
| Contagious Interview start date | Unit 42: infrastructure from December 2022, activity from March 2023 (moderate confidence) | ESET: since at least November 2023 (high confidence, "North Korea-aligned") | [50], [67] |
| Wagemole confidence | Unit 42's body says high confidence | Its summary says moderate, an internal inconsistency | [50] |
| Maui ransomware | The US indictment and AA24-207A tie it to Andariel | Mandiant's APT45 report: moderate confidence APT45 developed ransomware; cannot confirm its ransomware use; cites CISA's Maui report without attributing Maui to APT45 | [57], [60], [61] |
| APT38 | THREAT_ACTORS.md calls it a Lazarus "financial subgroup" | ATT&CK tracks it as its own group, G0082 | [12], [4] |
| WannaCry NHS count | UK Foreign Office: 48 NHS trusts | National Audit Office: at least 81 of 236 trusts in England disrupted | [19], [18] |
| Bybit amount | FBI: about $1.5 billion | MSMT: $1.4 billion | [68], [73] |
| Binance, 2026 | FBI: North Korea responsible, more than $6 billion | Press: the US President said "We don't know if it's North Korea"; North Korea denied it (**Reported**) | [80], [81], [82] |

## Part 2: the operational record

The timeline gives one row per dated campaign, incident or report. "Confidence as stated" repeats the source's own hedge. Money figures are as each source states them.

| Event date | Actor (as the source names it) | Campaign, incident or report | Targets | Confidence as stated | Sources | Grade |
|---|---|---|---|---|---|---|
| Since 2009 (alert 2017-06-13) | HIDDEN COBRA, the US name for North Korean government cyber activity; commercial reporting calls it Lazarus Group and Guardians of Peace | TA17-164A: the DeltaCharlie DDoS botnet and intrusions | Media, aerospace, financial and critical infrastructure | DHS and FBI assess; FBI has high confidence in the listed IP addresses | [17] | Confirmed |
| March 2013 | North Korea (FBI) | Attack on South Korean banks and media outlets | South Korean banks and media | FBI states it was carried out by North Korea (in the December 2014 Sony update) | [14] | Confirmed |
| 2013 (report 2013-09-11) | Kimsuky (Kaspersky) | The Kimsuky operation | Sejong Institute, KIDA, Ministry of Unification, Hyundai Merchant Marine: 11 targets in South Korea and 2 in China | Tentative; basis is drop-account names and operator IPs in Jilin and Liaoning | [13] | Confirmed |
| 2014 | Kimsuky (G0094) | Korea Hydro and Nuclear Power compromise | South Korean nuclear operator | ATT&CK: assessed | [5] | Confirmed |
| Late November 2014 (FBI attribution 2014-12-19) | North Korean government (FBI); Lazarus Group (Treasury, 2019) | Destructive attack on Sony Pictures Entertainment | US media company | FBI concluded responsibility; basis: malware code, encryption and deletion overlaps and infrastructure overlap, sources and methods withheld | [14], [22], [2] | Confirmed |
| February 2016 | Lazarus with Bluenoroff (Treasury); Bluenoroff (Kaspersky); BeagleBoyz (US advisory) | Bangladesh Bank SWIFT heist | Bangladesh Bank's account at the New York Fed | Treasury: $81 million (2018) and about $80 million (2019); AA20-239A: $81 million taken, the New York Fed stopped the rest of a roughly $1 billion attempt; Kaspersky: up to $851 million targeted, one North Korean IP connection as the first direct link, not claiming all Bluenoroff activity | [21], [22], [25], [15] | Confirmed |
| Since 2015 (SWIFT) and 2016 (FASTCash); advisory 2020-08-26 | BeagleBoyz, "an element of" the RGB | FASTCash ATM cash-outs and SWIFT fraud | Banks in 38 nations | US agencies; nearly $2 billion attempted since 2015, citing public estimates; bank targeting resumed in February 2020 | [25] | Confirmed |
| September 2016 | Andariel (Treasury) | Intrusion into the South Korean Defense Minister's PC and the defense intranet | South Korean military | Treasury designation statement | [22] | Confirmed |
| January 2017 to September 2018 | Lazarus, Bluenoroff and Andariel together | Thefts from five Asian cryptocurrency exchanges | Exchanges; about $571 million | Treasury, citing industry and press reporting | [22] | Confirmed |
| 2017-05-12 (CISA alert TA17-132A); attribution 2017-12-19 | Lazarus Group | WannaCry ransomware | About 300,000 computers in 150 countries; at least 81 NHS trusts in England disrupted (NAO), 48 (UK Foreign Office) | UK NCSC: highly likely; joint attribution by Australia, Canada, New Zealand, the US and UK, with supporting statements from Denmark and Japan (AA20-106A) | [16], [18], [19], [23] | Confirmed |
| 2018-06-08 (complaint); 2018-09-06 (designation) | Park Jin Hyok, alleged RGB hacker in a conspiracy researchers label Lazarus Group and APT38 | Federal complaint for wire fraud and computer-related fraud conspiracy; Treasury designation of Park and Chosun Expo tying the conspiracy to Bangladesh Bank, WannaCry 2.0 and Sony | Numerous victims | Criminal allegation; OFAC designation | [20], [21] | Confirmed |
| Since 2018 (Celas Trade Pro disclosed August 2018); advisory 2021-02-17 | Lazarus Group (HIDDEN COBRA) | AppleJeus: seven trojanized cryptocurrency trading apps, FALLCHILL with the first | More than 30 countries since January 2020; energy, finance, government, industry, technology, telecom, focus on exchanges | US agencies: North Korean state-sponsored | [32] | Confirmed |
| 2019 | APT45 (Mandiant) | Targeting of nuclear research and power plants, including Kudankulam in India | Nuclear energy | Mandiant: high confidence state-sponsored, moderate confidence RGB | [61] | Confirmed |
| September to December 2019 (report 2020-06-17) | Possible Lazarus link (ESET) | Operation In(ter)ception | Aerospace and military firms in Europe and the Middle East | ESET: hints only; ATT&CK C0022: likely Lazarus | [24], [10] | Confirmed |
| 2019-09-13 | Lazarus Group, Bluenoroff, Andariel | Treasury designation under E.O. 13722 | Not applicable | Designation | [22] | Confirmed |
| 2020-04-15 | DPRK | AA20-106A guidance: the regime increasingly relies on cybercrime to fund WMD and missile programs | Global | State, Treasury, DHS and FBI | [23] | Confirmed |
| September 2020 | APT45 (Mandiant) | Targeting of a crop science division | Agriculture research | Mandiant, as above | [61] | Confirmed |
| 2020-09-25 and 2020-10-27 | Lazarus (Kaspersky) | Breach of a pharmaceutical company authorized to produce COVID-19 vaccines (Bookcode, through a South Korean software supply chain); compromise of two servers at a government health ministry (wAgent) | Pharma, health ministry | Kaspersky: high confidence Lazarus | [30] | Confirmed |
| 2020-10-27 | Kimsuky | AA20-301A: a likely global intelligence-gathering mission | Individuals, think tanks and government in South Korea, Japan and the US; cryptocurrency industry; COVID-19 only as a lure theme | CISA, FBI and CNMF: most likely active since 2012 | [26] | Confirmed |
| Published 2020-11-13 | Zinc and Cerium (Microsoft), with Russia's Strontium | Targeting of seven companies researching COVID-19 vaccines and treatments; fake recruiter lures (Zinc) and WHO-themed lures (Cerium) | Pharma and research in Canada, France, India, South Korea and the US | Microsoft attribution | [27] | Confirmed |
| 2020-12-08 (warrants) | Park Jin Hyok, Jon Chang Hyok, Kim Il | Indictment in the Lazarus/APT38 conspiracy: malicious cryptocurrency applications, bank heists, the Marine Chain coin offering | Banks, crypto holders | Criminal allegation | [20], [28], [29] | Confirmed |
| Late 2020 to January 2021 (report 2021-01-25) | A "government-backed entity based in North Korea" (Google TAG) | Campaign against vulnerability researchers: a fake research blog, Twitter personas and a malicious Visual Studio project | Security researchers | No confidence level stated | [31] | Confirmed |
| 2021-03-25 | HIDDEN COBRA, Andariel, APT37, APT38, TEMP.Hermit, TEMP.Firework, Kimsuky, Bureau 121, Bureau 325 | HHS HC3 briefing on North Korean cyber activity for the health sector (contents list only) | US health sector | Briefing | [33] | Confirmed (contents only) |
| Most of 2021 | APT43 (Mandiant) | Shift to health-related verticals, likely in support of pandemic response | Healthcare and health research | Mandiant | [42] | Confirmed |
| 2021, continued in 2023 | APT45 (Mandiant) | Healthcare and pharmaceutical targeting during a suspected 2021 COVID-19 outbreak in North Korea | Healthcare, pharma | Mandiant, as above | [61] | Confirmed |
| Since May 2021; Kansas hospital 2021-05-04; advisory 2022-07-06 | North Korean state-sponsored actors (advisory, no group named); Andariel (indictment) | Maui ransomware | US Healthcare and Public Health: EHR, diagnostics, imaging, intranet | FBI assesses; criminal allegation | [38], [57] | Confirmed |
| Since June 2021 (report 2022-07-14) | DEV-0530 (Microsoft), likely overlapping Andariel but distinct | H0lyGh0st ransomware | Small and midsize businesses in manufacturing, banking, schools and event planning | Microsoft | [39] | Confirmed |
| February 2022 (site) to March 2023 (3CX); report 2023-04-20 | UNC4736 (Mandiant); AppleJeus G1049 (ATT&CK) | Compromise of Trading Technologies' X_TRADER, then the 3CX DesktopApp | Software supply chain; fintech and crypto focus | Mandiant: moderate | [43], [8] | Confirmed |
| 2022-03-23 (reported 2022-03-29); FBI 2022-04-14; Treasury 2022-05-06 | Lazarus Group and APT38 | Ronin bridge (Axie Infinity) theft, $620 million; Treasury sanctions the Blender.io mixer, the first mixer it sanctioned | Blockchain gaming | FBI was "able to confirm"; Treasury: DPRK state-sponsored | [34], [36] | Confirmed |
| Since 2020; advisory 2022-04-18 | TraderTraitor (Lazarus Group, APT38, BlueNoroff, Stardust Chollima) | AA22-108A: recruitment-themed lures delivering trojanized Electron crypto apps | Exchanges, DeFi, play-to-earn games, crypto venture funds, large holders | FBI, CISA and Treasury: North Korean state-sponsored | [35] | Confirmed |
| 2022-05-16 | DPRK IT workers | State, Treasury and FBI guidance: thousands of workers abroad posing as non-North Koreans | Employers worldwide | Government guidance | [37] | Confirmed |
| June 2022 (reported 2022-06-24); FBI 2023-01-23 | Lazarus Group (APT38) | Harmony Horizon bridge theft, $100 million | DeFi bridge | FBI confirmed | [40] | Confirmed |
| August 2022 to 2023 (report 2023-11-21) | Contagious Interview (CL-STA-0240) and Wagemole (CL-STA-0241) | Contagious Interview: BeaverTail and InvisibleFerret against software developers; Wagemole: fake job seekers | Software developers; US employers | Unit 42: moderate; Wagemole high or moderate | [50] | Confirmed |
| Early 2023 (report 2023-08-24) | Lazarus (Cisco Talos) | Exploitation of ManageEngine ServiceDesk CVE-2022-47966 five days after public proof of concept, deploying QuiteRAT | Internet backbone and healthcare entities in Europe and the US; confirmed compromise at a European backbone provider | Talos attribution | [46] | Confirmed |
| 2023-02-09 | DPRK state-sponsored ransomware actors | AA23-040A: Maui, H0lyGh0st and public ransomware families; posed as REvil; likely spread through trojanized files for X-Popup, a messenger commonly used at small and medium South Korean hospitals | US and South Korean HPH and other critical infrastructure | NSA, FBI, CISA, HHS, ROK NIS, ROK DSA | [41] | Confirmed |
| 2023-06-01 | Kimsuky | CSA-20230601-1: spearphishing impersonating journalists and academics | Research centers, think tanks, academia, media | FBI, State, NSA with ROK NIS, NPA, MOFA | [44] | Confirmed |
| 2023-06-02 and 2023-06-22; FBI 2023-08-22 | TraderTraitor (Lazarus, APT38) | Atomic Wallet ($100 million), Alphapo ($60 million), CoinsPaid ($37 million); about 1,580 BTC worth over $40 million staged for cash-out | Crypto firms | FBI attribution | [45] | Confirmed |
| 2023 | Kimsuky (G0094) | LLM-assisted activity, including use of commercial LLMs for vulnerability research | Not stated | ATT&CK | [5] | Confirmed |
| August 2023 to April 2024 (report 2024-05-28) | Moonstone Sleet (Microsoft) | Trojanized PuTTY (August 2023), an aerospace compromise (December 2023), fake companies (January 2024), the DeTankWar game (February 2024), FakePenny ransomware with a $6.6 million demand (April 2024) | Software and IT, education, defense industrial base | Microsoft: "North Korean state-aligned" | [55] | Confirmed |
| September 2023 | APT43 (Kimsuky) and Lazarus Group, with China's APT41 | HHS HC3 brief on North Korean and Chinese threats to the US HPH sector | US healthcare | HHS deck did not open; trade press only | [47] | Reported |
| Early October 2023 (report 2023-10-18) | Diamond Sleet and Onyx Sleet (Microsoft) | Exploitation of JetBrains TeamCity CVE-2023-42793, possibly opportunistic | Media, IT services, defense in South Korea, the US and India | Microsoft | [49] | Confirmed |
| 2023-10-18 | DPRK IT workers | US and ROK update to the IT worker guidance with new red flags | Employers | Government guidance | [48] | Confirmed |
| Since November 2023 (report 2025-02-20) | DeceptiveDevelopment (ESET) | Activity against freelance developers using BeaverTail and InvisibleFerret | Crypto and DeFi developers | ESET: high confidence, North Korea-aligned | [67] | Confirmed |
| 2023-11-23 | DPRK state-linked actors | UK NCSC and ROK NIS joint warning on software supply chain attacks, including zero-days in third-party software | Software supply chains | Joint advisory (news page read) | [51] | Confirmed |
| 2023-11-30 | Kimsuky | Treasury designation, coordinated with Australia, Japan and South Korea | Not applicable | Designation | [52] | Confirmed |
| 2024-05-02 | Kimsuky | JCSA-20240502-001: spoofing senders through weak DMARC policies | Think tanks, academia, East Asia experts | FBI, State, NSA | [53] | Confirmed |
| 2024-05-16 | DPRK IT workers | FBI PSA on witting and unwitting US-based facilitators | US employers | FBI | [54] | Confirmed |
| Late March to May 2024; attribution 2024-12-23 and 2024-12-24 | TraderTraitor (Jade Sleet, UNC4899, Slow Pisces) | DMM Bitcoin theft, $308 million (about 48.2 billion yen), beginning with a fake LinkedIn recruiter approaching an employee of wallet-software firm Ginco | Japanese exchange | FBI, DC3 and NPA; the NPA page does not mention Lazarus | [64], [65] | Confirmed |
| 2024-07-24 (indictment); 2024-07-25 (advisory) | Rim Jong Hyok of the RGB's Andariel unit; Andariel (Onyx Sleet, DarkSeoul, Silent Chollima, Stonefly) | Indictment for hacking and money laundering conspiracy; AA24-207A on global espionage funded by ransomware against US healthcare; Rewards for Justice offer of up to $10 million | Defense, aerospace, nuclear and engineering; to a lesser extent medical and energy; US hospitals | Criminal allegation; FBI, CNMF, CISA, DC3, NSA, ROK NIS, ROK NPA, UK NCSC | [56], [57], [59], [60] | Confirmed |
| 2024-07-25 | APT45 (Mandiant) | Mandiant report on APT45: nuclear, financial, government, defense, healthcare and pharma targeting; overlaps with Andariel, Onyx Sleet, Stonefly and Silent Chollima | As above | Mandiant: high confidence state-sponsored, moderate confidence RGB; ransomware development assessed with moderate confidence; ransomware use not confirmed | [61] | Confirmed |
| August 2024 | Stonefly (Symantec) | Attacks on three US private organizations a month after the indictment; no ransomware deployed; likely financially motivated | US private sector | Symantec | [63] | Confirmed |
| 2024-09-03 | North Korea | FBI PSA on tailored social engineering against DeFi and crypto employees and research on companies tied to crypto ETFs | Crypto industry | FBI | [62] | Confirmed |
| 2025-01-23 | DPRK IT workers | FBI PSA: discovered workers extort victims with stolen code and sometimes leak it | US employers | FBI | [66] | Confirmed |
| On or about 2025-02-21 (PSA 2025-02-26) | TraderTraitor | Bybit theft, about $1.5 billion | Exchange | FBI assesses | [68] | Confirmed |
| 2025-06-30 | DPRK IT worker facilitators; Jasper Sleet (Microsoft) | DOJ DPRK RevGen: Domestic Enabler Initiative actions; Microsoft's Jasper Sleet report (300+ US companies employed workers from 2020 to 2022; 3,000 consumer accounts suspended; AI use since 2024) | More than 100 US companies (DOJ) | DOJ charges; Microsoft | [69], [70] | Confirmed |
| 2025-07-08 | Song Kum Hyok (Andariel-affiliated) and a Russia-based IT worker network | Treasury designation | Not applicable | Designation | [71] | Confirmed |
| 2025-07-23 | DPRK IT workers | FBI PSA update on facilitators, laptop hosting and remote access | US employers | FBI | [72] | Confirmed |
| 2025-10-22 | DPRK cyber actors and IT workers | MSMT/2025/2 report and joint statement by 11 states | Global | Multilateral; only high-certainty heists counted | [73], [74] | Confirmed |
| November 2025 onward (report 2026-02-24) | Lazarus actors (Symantec), sub-group unclear | Use of Medusa ransomware; an unsuccessful attempt on a US healthcare organization and an attack on a Middle East target | US healthcare and non-profits on the Medusa leak site, not all confirmed as DPRK | Symantec | [75] | Confirmed |
| 2025 to mid-2026 (article 2026-07-30) | Lazarus, with links to the Gunra ransomware group | Espionage backdoors in at least 72 South Korean organizations; 15 Korean sites compromised as watering holes | South Korean organizations | AhnLab: a "high likelihood of technical linkage", not a single-actor attribution; the four agencies' advisory was not opened | [76] | Reported |
| 2026-09-16 and 2026-10-08 | DPRK overseas labour program | Later MSMT reports: MSMT/2026/1 and a report circulated as UN document S/2026/745 | Not applicable | Titles only were read | [77] | Confirmed (existence) |
| 2026-09-21 to 25 (announced 2026-10-13) | DPRK IT workers; Famous Chollima (CrowdStrike, per DOJ) | Operation Lonestar Roundup; FBI PSA I-101326-PSA on facilitators, stolen identities, extortion and threats of violence | Over 70 US employers in one scheme, including health care companies | DOJ charges; FBI | [78], [79] | Confirmed |
| On or about 2026-10-29 (alert 2026-10-31) | TraderTraitor | Binance theft, more than $6 billion, converted to Ether | Exchange | FBI, with USSS and IRS-CI; disputed in press (Part 1) | [80], [81], [82] | Confirmed (FBI); Reported (dispute) |

### Reading the record by era

- **2009 to 2016: espionage and punishment.** The early record is dominated by South Korean government and defense targets, DDoS, and destructive attacks on banks and media in 2013 and Sony Pictures in 2014 (**Confirmed** [14] [17]). Kimsuky's espionage against South Korean policy institutions appears in 2013 (**Confirmed** [13]).
- **2016 to 2019: the bank robbers.** Bangladesh Bank, FASTCash and the first exchange thefts show a turn to revenue, and WannaCry shows what happens when a revenue tool spreads on its own (**Confirmed** [21] [22] [25]; the reading is **Inferred**).
- **2020 to 2022: crypto and the pandemic.** Trojanized trading apps, DeFi bridge thefts, COVID-19 vaccine targeting and ransomware aimed at healthcare (Maui) arrive together (**Confirmed** [27] [30] [32] [34] [38]).
- **2023 to 2026: scale and insiders.** Supply chain compromise (3CX), fake job interviews against developers, the IT worker scheme and thefts above $1 billion define the most recent period (**Confirmed** [43] [50] [68] [78] [80]).

## Part 3: tooling

### ATT&CK software attributed to the eight groups

The library's group relationships list the following software for each group; every ID has a library page (**Confirmed** [12]).

| Group | Software objects | Software (library pages) | Sources |
|---|---|---|---|
| [Lazarus Group `G0032`](/mitre/groups/G0032.md) | 26 | [AppleJeus `S0584`](/mitre/software/S0584.md), [AuditCred `S0347`](/mitre/software/S0347.md), [BADCALL `S0245`](/mitre/software/S0245.md), [Bankshot `S0239`](/mitre/software/S0239.md), [BLINDINGCAN `S0520`](/mitre/software/S0520.md), [Cryptoistic `S0498`](/mitre/software/S0498.md), [Dacls `S0497`](/mitre/software/S0497.md), [Dtrack `S0567`](/mitre/software/S0567.md), [ECCENTRICBANDWAGON `S0593`](/mitre/software/S0593.md), [FALLCHILL `S0181`](/mitre/software/S0181.md), [HARDRAIN `S0246`](/mitre/software/S0246.md), [HOPLIGHT `S0376`](/mitre/software/S0376.md), [HotCroissant `S0431`](/mitre/software/S0431.md), [KEYMARBLE `S0271`](/mitre/software/S0271.md), [MagicRAT `S1182`](/mitre/software/S1182.md), [netsh `S0108`](/mitre/software/S0108.md), [Proxysvc `S0238`](/mitre/software/S0238.md), [RATANKBA `S0241`](/mitre/software/S0241.md), [RawDisk `S0364`](/mitre/software/S0364.md), [Responder `S0174`](/mitre/software/S0174.md), [route `S0103`](/mitre/software/S0103.md), [TAINTEDSCRIBE `S0586`](/mitre/software/S0586.md), [ThreatNeedle `S0665`](/mitre/software/S0665.md), [TYPEFRAME `S0263`](/mitre/software/S0263.md), [Volgmer `S0180`](/mitre/software/S0180.md), [WannaCry `S0366`](/mitre/software/S0366.md) | [2], [12] |
| [APT37 `G0067`](/mitre/groups/G0067.md) | 13 | [BLUELIGHT `S0657`](/mitre/software/S0657.md), [Cobalt Strike `S0154`](/mitre/software/S0154.md), [CORALDECK `S0212`](/mitre/software/S0212.md), [DOGCALL `S0213`](/mitre/software/S0213.md), [Final1stspy `S0355`](/mitre/software/S0355.md), [HAPPYWORK `S0214`](/mitre/software/S0214.md), [KARAE `S0215`](/mitre/software/S0215.md), [NavRAT `S0247`](/mitre/software/S0247.md), [POORAIM `S0216`](/mitre/software/S0216.md), [ROKRAT `S0240`](/mitre/software/S0240.md), [SHUTTERSPEED `S0217`](/mitre/software/S0217.md), [SLOWDRIFT `S0218`](/mitre/software/S0218.md), [WINERACK `S0219`](/mitre/software/S0219.md) | [3], [12] |
| [APT38 `G0082`](/mitre/groups/G0082.md) | 6 | [DarkComet `S0334`](/mitre/software/S0334.md), [ECCENTRICBANDWAGON `S0593`](/mitre/software/S0593.md), [HOPLIGHT `S0376`](/mitre/software/S0376.md), [KillDisk `S0607`](/mitre/software/S0607.md), [Mimikatz `S0002`](/mitre/software/S0002.md), [Net `S0039`](/mitre/software/S0039.md) | [4], [12] |
| [Kimsuky `G0094`](/mitre/groups/G0094.md) | 19 | [Amadey `S1025`](/mitre/software/S1025.md), [AppleSeed `S0622`](/mitre/software/S0622.md), [BabyShark `S0414`](/mitre/software/S0414.md), [Brave Prince `S0252`](/mitre/software/S0252.md), [certutil `S0160`](/mitre/software/S0160.md), [CSPY Downloader `S0527`](/mitre/software/S0527.md), [gh0st RAT `S0032`](/mitre/software/S0032.md), [GoBear `S1197`](/mitre/software/S1197.md), [Gold Dragon `S0249`](/mitre/software/S0249.md), [Gomir `S1198`](/mitre/software/S1198.md), [HTTPTroy `S9007`](/mitre/software/S9007.md), [KGH_SPY `S0526`](/mitre/software/S0526.md), [Mimikatz `S0002`](/mitre/software/S0002.md), [NOKKI `S0353`](/mitre/software/S0353.md), [PsExec `S0029`](/mitre/software/S0029.md), [QuasarRAT `S0262`](/mitre/software/S0262.md), [schtasks `S0111`](/mitre/software/S0111.md), [TRANSLATEXT `S1201`](/mitre/software/S1201.md), [Troll Stealer `S1196`](/mitre/software/S1196.md) | [5], [12] |
| [Andariel `G0138`](/mitre/groups/G0138.md) | 2 | [gh0st RAT `S0032`](/mitre/software/S0032.md), [Rifdoor `S0433`](/mitre/software/S0433.md) | [6], [12] |
| [Moonstone Sleet `G1036`](/mitre/groups/G1036.md) | 1 | [Qilin `S1242`](/mitre/software/S1242.md) | [7], [12] |
| [AppleJeus `G1049`](/mitre/groups/G1049.md) | 0 | None | [8], [12] |
| [Contagious Interview `G1052`](/mitre/groups/G1052.md) | 4 | [BeaverTail `S1246`](/mitre/software/S1246.md), [HexEval Loader `S1249`](/mitre/software/S1249.md), [InvisibleFerret `S1245`](/mitre/software/S1245.md), [XORIndex Loader `S1248`](/mitre/software/S1248.md) | [9], [12] |

ATT&CK's campaign [`C0022` Operation Dream Job](/mitre/campaigns/C0022.md) adds [DRATzarus `S0694`](/mitre/software/S0694.md), [Responder `S0174`](/mitre/software/S0174.md) and [Torisma `S0678`](/mitre/software/S0678.md), and [`C0057` 3CX Supply Chain Attack](/mitre/campaigns/C0057.md) adds [FRP `S1144`](/mitre/software/S1144.md) (**Confirmed** [10] [12]). Moonstone Sleet's only ATT&CK software entry is [Qilin `S1242`](/mitre/software/S1242.md) ransomware; Microsoft's 2024 report describes the group's own FakePenny ransomware (**Confirmed** [7] [55]). Medusa ransomware, used by Lazarus actors (Symantec, 2026), is tracked by ATT&CK as [Medusa Ransomware `S1244`](/mitre/software/S1244.md) and linked to Medusa Group, not to a North Korean group; `S1220` MEDUSA is an unrelated Linux rootkit (**Confirmed** [75] [12]; the Lazarus use rests on a single vendor).

### Tools named in the record with no ATT&CK software object

These tools appear in the primaries but have no software object in the library's ATT&CK data, so they are named in prose only (**Confirmed** [12]).

| Tool | What the primary says | Source |
|---|---|---|
| Maui | Ransomware against US healthcare since May 2021, apparently built for manual execution by a remote operator | [38] |
| H0lyGh0st | Ransomware used by DEV-0530 since June 2021; named again in AA23-040A | [39], [41] |
| DeltaCharlie | DDoS botnet malware in TA17-164A | [17] |
| QuiteRAT | A MagicRAT derivative ([MagicRAT `S1182`](/mitre/software/S1182.md)) deployed after ManageEngine exploitation in 2023 | [46] |
| Bookcode, wAgent | Used against a vaccine maker and a health ministry in 2020 | [30] |
| Comebacker, Infohook, RP_Proxy | Used with Medusa ransomware alongside [BLINDINGCAN `S0520`](/mitre/software/S0520.md) and [Mimikatz `S0002`](/mitre/software/S0002.md) | [75] |
| FakePenny | Moonstone Sleet ransomware, April 2024 | [55] |
| Nukebot, Chisel | Used by Stonefly in August 2024 with [Dtrack `S0567`](/mitre/software/S0567.md), [Mimikatz `S0002`](/mitre/software/S0002.md), [Sliver `S0633`](/mitre/software/S0633.md) and FastReverseProxy, which ATT&CK tracks as [FRP `S1144`](/mitre/software/S1144.md) | [63], [12] |
| Trojanized apps (TraderTraitor Electron apps, X-Popup messenger files, PuTTY, the DeTankWar game) | Delivered through lures, supply chains or messenger updates | [35], [41], [55] |

### Shared tools and what they prove

Shared and commodity tools appear across groups: Mimikatz, gh0st RAT, Cobalt Strike and Sliver all appear in this record, and each is used by many unrelated actors. A hit on one of them is a lead, not an attribution (**Inferred**). The stronger signals in the record are the lure patterns (recruiters, job tests, trading apps) and the infrastructure and code overlaps the FBI cited for Sony (**Confirmed** [14]).

## Part 4: exploited vulnerabilities

The CVEs below are named in an opened primary as exploited by, or researched by, North Korea-attributed actors. KEV fields were read from the KEV catalog, version 2026.11.03 with 1,767 entries (**Confirmed** [83]). The CWE column gives the catalog's own `cwes` field.

| CVE | Product | Named by (date) | In KEV, date added | Known ransomware use (KEV) | CWE (KEV field) | Sources |
|---|---|---|---|---|---|---|
| CVE-2021-44228 | Apache Log4j2 (Log4Shell) | AA23-040A (2023-02-09), AA24-207A (2024-07-25) | Yes, 2021-12-10 | Known | CWE-20, CWE-400, CWE-502 | [41], [60], [83] |
| CVE-2021-20038 | SonicWall SMA 100 | AA23-040A (2023-02-09) | Yes, 2022-01-28 | Known | CWE-121 | [41], [83] |
| CVE-2022-24990 | TerraMaster OS | AA23-040A (2023-02-09) | Yes, 2023-02-10, the day after the advisory | Known | CWE-306 | [41], [83] |
| CVE-2023-42793 | JetBrains TeamCity | Microsoft (Diamond Sleet, Onyx Sleet; 2023-10-18) | Yes, 2023-10-04 | Known | CWE-288 | [49], [83] |
| CVE-2022-47966 | Zoho ManageEngine ServiceDesk | Cisco Talos (Lazarus; 2023-08-24) | Yes, 2023-01-23 | Known | None listed | [46], [83] |
| CVE-2021-43226 | Microsoft Windows | AA24-207A list (2024-07-25) | Yes, 2025-10-06 | Known | None listed | [60], [83] |

AA24-207A lists 45 CVEs that the actors researched and partly used for initial access; only CVE-2021-44228 is named outright as exploited (**Confirmed** [60]). Of the 45, 29 are in KEV and 20 of those carry known ransomware use; the 16 not in KEV include CVE-2023-32784 (KeePass), CVE-2021-45837 (TerraMaster), the three PHP Everywhere CVEs and CVE-2017-4946 (VMware) (**Confirmed** [83]). For CVE-2021-44228 in depth, see the [Log4Shell case study](/case-studies/LOG4SHELL.md), which carries NVD's CWE-917 alongside CWE-502.

What the vulnerability record says to a program owner (**Inferred** from the table): a KEV-only service level covers about two thirds of the Andariel list; the Log4Shell row shows the actors using a flaw that was already public and already in KEV; KEV's ransomware-use field reflects what is known now, not what was known when the actors used the flaw; and CVE-2021-43226 entered KEV more than a year after a joint advisory listed it. The 2024 indictment says the conspirators gained initial access typically through known but unpatched vulnerabilities (**Confirmed** [57]).

## Part 5: targets by sector and geography

### Healthcare and public health

None of the eight ATT&CK group descriptions names the healthcare sector, and Maui is not an ATT&CK software object, so the healthcare record comes from government advisories, court records and vendor reports (**Inferred** from the library data [12]). That record is long.

| Date | Event | Actor as named | Healthcare detail | Sources | Grade |
|---|---|---|---|---|---|
| 2017-05-12 | WannaCry | Lazarus Group (UK, 2017-12-19) | At least 81 of 236 NHS trusts in England disrupted, 595 GP practices infected, 6,912 cancelled appointments identified and an estimated 19,000 or more in all (NAO, which makes no attribution); 48 NHS trusts (UK Foreign Office) | [18], [19] | Confirmed |
| 2020-09-25 and 2020-10-27 | Vaccine maker and health ministry intrusions | Lazarus (Kaspersky, high confidence) | A pharmaceutical company authorized to produce COVID-19 vaccines; two servers of a government health ministry | [30] | Confirmed |
| Published 2020-11-13 | Vaccine research targeting | Zinc and Cerium (Microsoft) | Seven companies researching COVID-19 vaccines and treatments | [27] | Confirmed |
| 2021-03-25 | HC3 briefing | Nine North Korean names | A health-sector briefing on North Korean cyber activity | [33] | Confirmed (contents only) |
| 2021 | Health-related collection | APT43 (Mandiant); APT45 (Mandiant) | APT43 shifted to health-related verticals for most of 2021; APT45 targeted healthcare and pharma longer than other DPRK groups and showed continued interest in health research in 2023 | [42], [61] | Confirmed |
| On or about 2021-05-04 | Maui at a Kansas hospital | Andariel (indictment) | Four servers encrypted: intranet, X-ray and diagnostic imaging, electronic document management, sleep lab; further overt acts against Arkansas and Connecticut healthcare companies, a Florida hospital and a Colorado medical clinic | [57] | Confirmed |
| 2021 and 2022 | Maui extortion | Rim Jong Hyok and Andariel co-conspirators (MSMT) | Five US hospitals and medical providers extorted; staff cut off from electronic patient records and tools; services limited and appointments cancelled | [73] | Confirmed |
| 2022-07-06 | AA22-187A | North Korean state-sponsored actors | Maui against HPH since at least May 2021; EHR, diagnostics, imaging and intranet services encrypted, sometimes for long periods | [38] | Confirmed |
| 2023-02-09 | AA23-040A | DPRK state-sponsored ransomware actors | HHS co-signs; US and South Korean HPH targets; code likely spread through trojanized X-Popup messenger files, a messenger commonly used at small and medium South Korean hospitals; ransoms collected through foreign affiliates and intermediaries | [41] | Confirmed |
| Early 2023 | ManageEngine exploitation | Lazarus (Talos) | Healthcare entities in Europe and the US among the targets | [46] | Confirmed |
| September 2023 | HC3 threat brief | APT43 and Lazarus, with China's APT41 | Brief on North Korean and Chinese threats to US HPH, citing COVID-19 vaccine data among Lazarus operations | [47] | Reported |
| 2024-07-24 and 2024-07-25 | Rim Jong Hyok indictment, Rewards for Justice offer and AA24-207A | Andariel | Maui against US hospitals and healthcare companies; RFJ documents five healthcare providers among victims that also include four US defense contractors, two US Air Force bases and NASA; medical sector targeted to a lesser extent in espionage | [56], [57], [59], [60] | Confirmed |
| November 2025 onward (report 2026-02-24) | Medusa ransomware | Lazarus actors (Symantec) | An unsuccessful attempt on a US healthcare organization; four US healthcare and non-profit organizations on the Medusa leak site, not all confirmed as DPRK | [75] | Confirmed |
| 2026-10-13 | Operation Lonestar Roundup | DPRK IT workers | The Ohio scheme reached over 70 US employers, including health care companies, and earned about $3 million | [78] | Confirmed |

What the healthcare record shows (**Inferred** from the rows above): ransomware against hospitals is the strongest and best-documented healthcare link; according to the US record it is run by the same RGB unit that runs defense espionage, and the advisories name small and medium hospitals among the targets. Intelligence collection on vaccines and health research spiked during the pandemic, a reading that rests partly on single-vendor reports (Kaspersky [30], Microsoft [27]); the ManageEngine and Medusa healthcare rows also rest on single vendors (Talos [46], Symantec [75]). And the IT worker scheme now places North Korean staff inside health care companies with legitimate access. Healthcare defenders should read Maui alongside the sector's broader ransomware record in the [Change Healthcare 2024 study](/case-studies/CHANGE_HEALTHCARE_2024.md) and the [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md).

### Other sectors

| Sector | Representative events | Sources |
|---|---|---|
| Finance and banking | Bangladesh Bank, FASTCash and SWIFT fraud against banks in 38 nations; Bancomext and Banco de Chile | [4], [22], [25] |
| Cryptocurrency and DeFi | Five Asian exchanges (2017 to 2018), AppleJeus, Ronin, Harmony, Atomic Wallet, Alphapo, CoinsPaid, DMM Bitcoin, Bybit, Binance | [22], [32], [34], [40], [45], [64], [68], [80] |
| Defense, aerospace and nuclear | Operation Dream Job and In(ter)ception; South Korean defense intranet (2016); Kudankulam (2019); Andariel's 2024 espionage, including over 30 GB taken in a November 2022 intrusion at a US defense contractor; ITAR-controlled data accessed at a California defense contractor through IT workers | [10], [22], [24], [59], [60], [61], [69] |
| Government, think tanks, academia and media | Kimsuky against South Korean government and policy institutions, think tanks, academia and journalists; the UN | [5], [13], [26], [44], [52], [53] |
| Software and technology | Security researchers (2021), developers (Contagious Interview), TeamCity, 3CX and X_TRADER, the NCSC and NIS supply chain warning; IT workers at over 100 US companies | [31], [43], [49], [50], [51], [67], [69] |
| Media and entertainment | Sony Pictures (2014); South Korean media (2013); HIDDEN COBRA media targets | [14], [17] |
| Energy and critical infrastructure | KHNP (2014); AppleJeus energy targets; AA23-040A critical infrastructure | [5], [32], [41] |

### Geography

South Korea is the constant: government, defense, media, banks, nuclear and hospitals all appear (**Confirmed** [13] [22] [41] [60] [76]). The United States is the main second target, across healthcare, defense, finance, technology and employers of IT workers (**Confirmed** [38] [60] [69] [78]). Japan appears through Kimsuky, Andariel and DMM Bitcoin (**Confirmed** [26] [60] [64]); India through Kudankulam and Andariel (**Confirmed** [60] [61]); Europe and the Middle East through Operation In(ter)ception and the Medusa attack (**Confirmed** [24] [75]). The bank theft record spans 38 nations (**Confirmed** [25]), and MSMT names laundering networks in China, Russia, Argentina, Cambodia, Vietnam and the UAE, with IT workers based mainly in China and Russia (**Confirmed** [71] [73]).

## Part 6: the government record

### United States: charges

- **Park Jin Hyok.** Charged by complaint on 8 June 2018 in the Central District of California with conspiracy to commit wire fraud and computer-related fraud, as part of an RGB conspiracy that researchers label Lazarus Group and APT38; indicted with Jon Chang Hyok and Kim Il (warrants 8 December 2020) (**Confirmed** [20]). Jon is accused of building and spreading malicious cryptocurrency applications; Kim Il of a malicious crypto application, bank heists and the Marine Chain initial coin offering (**Confirmed** [28] [29]).
- **Rim Jong Hyok.** Indicted in the District of Kansas (2:24-cr-20061, filed 24 July 2024) for conspiracy to commit computer hacking and promotion money laundering, accused of using Maui against US hospitals and healthcare companies, laundering the proceeds and buying servers for espionage against government and technology victims in the US, South Korea and China (**Confirmed** [56] [57]). Rewards for Justice offers up to $10 million (**Confirmed** [59]).
- **IT worker facilitators.** The June 2025 DOJ actions brought two indictments, a plea and an arrest, searched 29 laptop farms in 16 states, and seized 29 financial accounts, 21 websites and about 200 computers. The Massachusetts indictment (2021 to October 2024) involved more than 80 compromised US identities, access to export-controlled military technology and losses of at least $3 million; a separate scheme stole about $900,000 in virtual currency from an Atlanta blockchain company (**Confirmed** [69]). Operation Lonestar Roundup (October 2026) charged 14 people (**Confirmed** [78]). The October 2026 release also lists DPRK RevGen actions in November 2025, April 2026 and May 2026, which were not opened (**Confirmed** for the list [78]).

### United States: sanctions

| Date | Designation | Basis Treasury gives | Source |
|---|---|---|---|
| 2018-09-06 | Park Jin Hyok and Chosun Expo Joint Venture (E.O. 13722) | Bangladesh Bank ($81 million), WannaCry 2.0, Sony Pictures | [21] |
| 2019-09-13 | Lazarus Group, Bluenoroff, Andariel (E.O. 13722) | RGB control; Sony, WannaCry, Bangladesh Bank, the 2016 Defense Ministry intrusion; about $571 million from five exchanges | [22] |
| 2022-05-06 | Blender.io mixer | Laundering the Ronin theft attributed to Lazarus | [36] |
| 2023-11-30 | Kimsuky (with Australia, Japan, ROK) | RGB-subordinate intelligence collection | [52] |
| 2025-07-08 | Song Kum Hyok, plus one person and four entities in a Russia-based IT worker network | Andariel-affiliated facilitation of IT worker schemes | [71] |

### United States and allies: advisories and statements

The joint advisories are the backbone of the public record: TA17-164A (2017), AA20-106A, AA20-239A and AA20-301A (2020), AA21-048A (2021), AA22-108A and AA22-187A (2022), AA23-040A and CSA-20230601-1 (2023), JCSA-20240502-001 and AA24-207A (2024) (**Confirmed** [17] [23] [25] [26] [32] [35] [38] [41] [44] [53] [60]). CISA's North Korea publications list shows no North Korea advisory after AA24-207A of 25 July 2024 (**Confirmed** [16]); since then the public US record has moved to FBI PSAs and alerts (2024 to 2026) and DOJ actions (**Confirmed** [62] [66] [68] [72] [79] [80]; the shift is **Inferred**). Co-signers include South Korea's NIS, NPA, MOFA and DSA, Japan's NPA and the UK's NCSC (**Confirmed** [41] [44] [60] [64]). The UK and South Korea also issued their own joint supply chain warning in November 2023 (**Confirmed** [51]).

### The multilateral record

The UN 1718 Committee's Panel of Experts was disbanded in April 2024 after Russia's March 2024 veto, and eleven states (the US, Australia, Canada, France, Germany, Italy, Japan, the Netherlands, New Zealand, South Korea and the UK) formed the MSMT in its place (**Confirmed** [74]). Its October 2025 report calls the DPRK cyber force a full-spectrum national program approaching China's and Russia's in sophistication, counts the thefts above, and records stablecoin use in procurement deals for military equipment and copper (**Confirmed** [73]). Its member states say the cyber and IT worker activity has yielded billions of dollars for WMD and missiles (**Confirmed** [74]). Two later MSMT reports exist (September and October 2026); only their titles were read (**Confirmed** [77]).

### Counting the money

| Measure | Figure | Who says so | Source | Grade |
|---|---|---|---|---|
| Attempted bank theft since 2015 | Nearly $2 billion | CISA, Treasury, FBI, USCYBERCOM, citing public estimates | [25] | Confirmed |
| Five exchanges, January 2017 to September 2018 | About $571 million | Treasury, citing industry and press | [22] | Confirmed |
| Cryptocurrency stolen in 2024 | At least $1.19 billion, about 50% more than 2023 | MSMT, with Mandiant and Chainalysis analysis | [73] | Confirmed |
| Cryptocurrency stolen January to September 2025 | At least $1.65 billion ($1.645 billion) | MSMT | [73] | Confirmed |
| A single IT worker or team per year | Over $300,000 per worker; over $3 million per team | State, Treasury, FBI (2022) | [37] | Confirmed |
| IT worker program per year | Hundreds of millions of dollars | DOJ (2026) | [78] | Confirmed |

No single FBI annual theft figure for 2024 or 2025 was found in what was opened; FBI figures are per incident (**Inferred** [64] [68]).

## Part 7: the defender view

### Healthcare: what the advisories ask for

AA22-187A and AA23-040A give the healthcare playbook (**Confirmed** [38] [41]):

- authenticate and encrypt connections to network services, IoT medical devices and the EHR system with PKI and certificates;
- use standard user accounts for daily work;
- disable or secure WAN-facing management interfaces such as Telnet, SSH, Winbox and HTTP;
- encrypt patient data at rest and in transit;
- segment the network in layers, and monitor IoT devices for erratic behavior;
- keep offline, encrypted, immutable backups and test restores;
- patch known exploited vulnerabilities first, restrict RDP and SMB, remove SMBv1, use application allowlisting and MFA.

AA23-040A ties these to CISA's Cross-Sector Cybersecurity Performance Goals: phishing-resistant MFA for RDP, webmail, VPN and backup accounts (CPG 1.3), KEV-first patching with central patch management (CPG 5.1), segmentation (CPG 8.1), immutable tested backups (CPG 7.3), third-party connection review (CPG 5.6 and 6.2) and application control (CPG 2.1) (**Confirmed** [41]). The X-Popup case adds one more: a messenger used at small hospitals was likely the delivery channel, so software update paths at small providers are part of the attack surface (**Confirmed** [41]; the lesson is **Inferred**).

### Andariel: exploitation to exfiltration

AA24-207A asks for Log4j upgraded to 2.17.0 or later, web shell defenses from NSA and ASD guidance with WAFs and authenticated reverse proxies, blocking unnecessary outbound connections and external access to admin panels, segmented web servers, command-line monitoring, MFA on remote access, and alerts on unexpected dual-use tools; it ships 22 YARA rules (**Confirmed** [60]). Because none of the advisory's 22 technique IDs appears in Andariel's ATT&CK record, a detection program mapped only to the group page would miss this chain (computed from [12] and [60]; **Inferred**).

### Kimsuky: mail and trust

- MFA and user awareness are the key mitigations in AA20-301A, which also gives behavioral detections: mshta launching HTA files, PowerShell run without `powershell.exe`, zeroed firewall registry values and HWP file-association changes (**Confirmed** [26]).
- CSA-20230601-1 says: no macros on emailed documents; verify identities by phone or video, since DPRK actors avoid voice or video; be cautious when a contact moves the conversation to another messaging platform; use phishing-resistant MFA, application control, protected view and KEV-first patching (**Confirmed** [44]).
- JCSA-20240502-001 says to set DMARC to `p=quarantine` or `p=reject` with `rua` aggregate reporting, aligned with CISA CPG 2.M (**Confirmed** [53]).

See the [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md) and [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md).

### Remote IT workers: an insider program

The FBI's PSAs build a hiring and employment checklist (**Confirmed** [48] [54] [66] [72] [79]): watch for refusal to appear on video, cheating on coding tests, laptops shipped to freight forwarders, and threats to release source code; check for US-based facilitators who receive and host laptops and set up remote access; apply least privilege and limit remote-desktop tools; alert on one account logging in from several countries; monitor exfiltration to personal repositories and cloud storage; verify identity throughout employment, not just at hiring; and audit staffing firms. The 2026 PSA calls the overall approach "identity in depth" (**Confirmed** [79]). See the [Insider Threat Reference](/INSIDER_THREAT_REFERENCE.md) and [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md).

### Cryptocurrency and payments

AA22-108A recommends verifying cryptocurrency software from its primary source, disabling external Office macros, blocking or monitoring newly registered domains, allowlisting and MFA (**Confirmed** [35]). AA20-239A's payment-system guidance covers chip and PIN, cryptogram and MAC validation, MFA for switch servers, firewalled enclaves, mutual TLS and transaction baselining; note that its ATT&CK table pairs several IDs with the wrong names, so do not copy its mappings (**Confirmed** [25]). The Bybit PSA asks virtual asset service providers to block transactions with listed laundering addresses (**Confirmed** [68]). See the [Blockchain Security Reference](/BLOCKCHAIN_SECURITY_REFERENCE.md).

### Endpoint hardening against Moonstone Sleet

Microsoft recommends tamper protection, network protection, EDR in block mode, credential hardening against LSASS access and attack surface reduction rules (**Confirmed** [55]; Microsoft's own guidance).

### What is overstated and what is understated

- **Overstated: "Lazarus did it."** ATT&CK itself warns that the name is an umbrella, and the US government, Mandiant, Microsoft and CrowdStrike split the same activity differently. Reports that say only "Lazarus" lose the detail a defender needs (**Confirmed** [2]; the judgment is **Inferred**).
- **Overstated: settled attribution for the newest theft.** The FBI attributes Binance to TraderTraitor; press coverage records public doubt from the US President, a North Korean denial and no confirmation from Binance (**Confirmed** [80]; **Reported** [81] [82]).
- **Understated: healthcare as a North Korean target.** ATT&CK's group text never mentions it, yet three joint advisories, an indictment, an MSMT finding and vendor reports do (**Inferred** from Part 5).
- **Understated: the IT worker program.** It now reaches into hundreds of US employers, includes extortion, and supplies access for intrusions; it is a hiring and identity problem that technical controls alone will not catch (**Confirmed** [37] [66] [70] [78]; the judgment is **Inferred**).
- **Understated: the advisory gap in ATT&CK.** The Andariel group page holds 12 techniques; the 2024 advisory describes a different 22 (computed from [12] and [60]; **Inferred**).

## Part 8: MITRE mappings

This part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every ID was checked against the live ATT&CK pages or the library's data files on 3 November 2026; IDs that could not be checked are left out. Revoked IDs that 2020-era advisories still cite (`T1562.001` Disable or Modify Tools) are shown under their v20 successor (`T1685`), as `data/attack/superseded_by.jsonl` records them; the live `T1685` page (v1.0, created 14 April 2026, modified 11 September 2026, tactic Defense Impairment) lists Lazarus Group, APT38, Kimsuky and Contagious Interview among its procedure examples (**Confirmed** [11] [12]).

### Enterprise techniques in the ATT&CK group records

The union of the eight groups' direct technique relationships in the library's ATT&CK v20.0 data is 240 Enterprise techniques, and every one has a library page (**Confirmed** [12]). By number of groups sharing a technique: 127 are used by one group, 52 by two, 31 by three, 15 by four, 10 by five, 4 by six and 1 by seven (computed from [12]). Counted once per tactic, the union spans Stealth 54, Execution 24, Persistence 24, Privilege Escalation 24, Resource Development 23, Discovery 20, Command and Control 19, Collection 19, Credential Access 17, Reconnaissance 16, Initial Access 12, Impact 11, Defense Impairment 11, Exfiltration 6 and Lateral Movement 5 (**Confirmed** [12]).

The shared core is persona-driven social engineering followed by commodity host activity (**Confirmed** [12]; the reading is **Inferred**):

- **Seven of eight groups:** [`T1204.002`](/mitre/techniques/T1204-002.md) Malicious File (all but AppleJeus).
- **Six groups:** [`T1082`](/mitre/techniques/T1082.md) System Information Discovery, [`T1105`](/mitre/techniques/T1105.md) Ingress Tool Transfer, [`T1547.001`](/mitre/techniques/T1547-001.md) Registry Run Keys / Startup Folder, [`T1566.001`](/mitre/techniques/T1566-001.md) Spearphishing Attachment.
- **Five groups:** [`T1005`](/mitre/techniques/T1005.md), [`T1033`](/mitre/techniques/T1033.md), [`T1053.005`](/mitre/techniques/T1053-005.md) Scheduled Task, [`T1057`](/mitre/techniques/T1057.md), [`T1059.003`](/mitre/techniques/T1059-003.md), [`T1059.005`](/mitre/techniques/T1059-005.md), [`T1071.001`](/mitre/techniques/T1071-001.md) Web Protocols, and three persona-building techniques shared by Lazarus Group, APT38, Kimsuky, Moonstone Sleet and Contagious Interview: [`T1583.001`](/mitre/techniques/T1583-001.md) Domains, [`T1585.001`](/mitre/techniques/T1585-001.md) Social Media Accounts and [`T1585.002`](/mitre/techniques/T1585-002.md) Email Accounts.

The table lists all 240. "Where it appears" is the ATT&CK group record (the group pages are dated in Part 1: [2] to [9]); where an opened advisory also lists the technique, its date and source number follow. ATT&CK group pages also roll up techniques from attributed campaigns: the live Lazarus page shows about 117 Enterprise techniques by a manual tally against 93 direct relationships, probably for that reason (**Confirmed** for the tally, approximate [2]). Campaign-only techniques (C0022 has 55 and C0057 has 22 in the library data) are not added to this table.

| ID | Technique | Tactic (v20) | Groups with a direct ATT&CK relationship | Where it appears | Sources |
|---|---|---|---|---|---|
| [`T1001.003`](/mitre/techniques/T1001-003.md) | Data Obfuscation: Protocol or Service Impersonation | Command and Control | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | OS Credential Dumping: LSASS Memory | Credential Access | 2: G0094, G1036 | ATT&CK group record | [5], [7], [12] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | Collection | 5: G0032, G0067, G0082, G0094, G0138 | ATT&CK group record | [2], [3], [4], [5], [6], [12] |
| [`T1007`](/mitre/techniques/T1007.md) | System Service Discovery | Discovery | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | Command and Control | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1010`](/mitre/techniques/T1010.md) | Application Window Discovery | Discovery | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | Discovery | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | 3: G0032, G0094, G1036 | ATT&CK group record | [2], [5], [7], [12] |
| [`T1020`](/mitre/techniques/T1020.md) | Automated Exfiltration | Exfiltration | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Services: Remote Desktop Protocol | Lateral Movement | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | Remote Services: SMB/Windows Admin Shares | Lateral Movement | 1: G0032 | ATT&CK group record; also AA24-207A (Andariel), 2024-07-25 [60] | [2], [60], [12] |
| [`T1021.004`](/mitre/techniques/T1021-004.md) | Remote Services: SSH | Lateral Movement | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | 3: G0067, G0094, G1036 | ATT&CK group record | [3], [5], [7], [12] |
| [`T1027.001`](/mitre/techniques/T1027-001.md) | Obfuscated Files or Information: Binary Padding | Stealth | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Obfuscated Files or Information: Software Packing | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1027.003`](/mitre/techniques/T1027-003.md) | Obfuscated Files or Information: Steganography | Stealth | 2: G0067, G0138 | ATT&CK group record | [3], [6], [12] |
| [`T1027.007`](/mitre/techniques/T1027-007.md) | Obfuscated Files or Information: Dynamic API Resolution | Stealth | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1027.009`](/mitre/techniques/T1027-009.md) | Obfuscated Files or Information: Embedded Payloads | Stealth | 2: G0032, G1036 | ATT&CK group record | [2], [7], [12] |
| [`T1027.010`](/mitre/techniques/T1027-010.md) | Obfuscated Files or Information: Command Obfuscation | Stealth | 3: G0082, G0094, G1052 | ATT&CK group record | [4], [5], [9], [12] |
| [`T1027.012`](/mitre/techniques/T1027-012.md) | Obfuscated Files or Information: LNK Icon Smuggling | Stealth | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | 4: G0032, G0094, G1036, G1052 | ATT&CK group record | [2], [5], [7], [9], [12] |
| [`T1027.015`](/mitre/techniques/T1027-015.md) | Obfuscated Files or Information: Compression | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1027.016`](/mitre/techniques/T1027-016.md) | Obfuscated Files or Information: Junk Code Insertion | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | Discovery | 5: G0032, G0067, G0082, G0094, G1036 | ATT&CK group record | [2], [3], [4], [5], [7], [12] |
| [`T1036`](/mitre/techniques/T1036.md) | Masquerading | Stealth | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1036.001`](/mitre/techniques/T1036-001.md) | Masquerading: Invalid Code Signature | Stealth | 1: G0067 | ATT&CK group record | [3], [12] |
| [`T1036.003`](/mitre/techniques/T1036-003.md) | Masquerading: Rename Legitimate Utilities | Stealth | 2: G0032, G0082 | ATT&CK group record | [2], [4], [12] |
| [`T1036.004`](/mitre/techniques/T1036-004.md) | Masquerading: Masquerade Task or Service | Stealth | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Masquerading: Match Legitimate Resource Name or Location | Stealth | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1036.006`](/mitre/techniques/T1036-006.md) | Masquerading: Space after Filename | Stealth | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1036.007`](/mitre/techniques/T1036-007.md) | Masquerading: Double File Extension | Stealth | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1036.008`](/mitre/techniques/T1036-008.md) | Masquerading: Masquerade File Type | Stealth | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | 4: G0032, G0082, G0094, G1052 | ATT&CK group record | [2], [4], [5], [9], [12] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1048.002`](/mitre/techniques/T1048-002.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1048.003`](/mitre/techniques/T1048-003.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | 2: G0032, G1052 | ATT&CK group record | [2], [9], [12] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | 3: G0032, G0082, G0138 | ATT&CK group record | [2], [4], [6], [12] |
| [`T1053.003`](/mitre/techniques/T1053-003.md) | Scheduled Task/Job: Cron | Execution, Persistence, Privilege Escalation | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | 5: G0032, G0067, G0082, G0094, G1036 | ATT&CK group record | [2], [3], [4], [5], [7], [12] |
| [`T1053.006`](/mitre/techniques/T1053-006.md) | Scheduled Task/Job: Systemd Timers | Execution, Persistence, Privilege Escalation | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | Stealth, Privilege Escalation | 3: G0067, G0082, G0094 | ATT&CK group record | [3], [4], [5], [12] |
| [`T1055.001`](/mitre/techniques/T1055-001.md) | Process Injection: Dynamic-link Library Injection | Stealth, Privilege Escalation | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1055.012`](/mitre/techniques/T1055-012.md) | Process Injection: Process Hollowing | Stealth, Privilege Escalation | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Input Capture: Keylogging | Collection, Credential Access | 3: G0032, G0082, G0094 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [4], [5], [26], [12] |
| [`T1056.002`](/mitre/techniques/T1056-002.md) | Input Capture: GUI Input Capture | Collection, Credential Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1056.003`](/mitre/techniques/T1056-003.md) | Input Capture: Web Portal Capture | Collection, Credential Access | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | Discovery | 5: G0032, G0067, G0082, G0094, G0138 | ATT&CK group record | [2], [3], [4], [5], [6], [12] |
| [`T1059`](/mitre/techniques/T1059.md) | Command and Scripting Interpreter | Execution | 1: G0067 | ATT&CK group record | [3], [12] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | Command and Scripting Interpreter: PowerShell | Execution | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1059.002`](/mitre/techniques/T1059-002.md) | Command and Scripting Interpreter: AppleScript | Execution | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Command and Scripting Interpreter: Windows Command Shell | Execution | 5: G0032, G0067, G0082, G0094, G1052 | ATT&CK group record | [2], [3], [4], [5], [9], [12] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Command and Scripting Interpreter: Unix Shell | Execution | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Command and Scripting Interpreter: Visual Basic | Execution | 5: G0032, G0067, G0082, G0094, G1052 | ATT&CK group record | [2], [3], [4], [5], [9], [12] |
| [`T1059.006`](/mitre/techniques/T1059-006.md) | Command and Scripting Interpreter: Python | Execution | 4: G0067, G0082, G0094, G1052 | ATT&CK group record | [3], [4], [5], [9], [12] |
| [`T1059.007`](/mitre/techniques/T1059-007.md) | Command and Scripting Interpreter: JavaScript | Execution | 3: G0082, G0094, G1052 | ATT&CK group record | [4], [5], [9], [12] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1070.003`](/mitre/techniques/T1070-003.md) | Indicator Removal: Clear Command History | Stealth | 2: G0032, G0082 | ATT&CK group record | [2], [4], [12] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | Indicator Removal: File Deletion | Stealth | 4: G0032, G0082, G0094, G1052 | ATT&CK group record | [2], [4], [5], [9], [12] |
| [`T1070.006`](/mitre/techniques/T1070-006.md) | Indicator Removal: Timestomp | Stealth | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Application Layer Protocol: Web Protocols | Command and Control | 5: G0032, G0067, G0082, G0094, G1036 | ATT&CK group record | [2], [3], [4], [5], [7], [12] |
| [`T1071.002`](/mitre/techniques/T1071-002.md) | Application Layer Protocol: File Transfer Protocols | Command and Control | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1071.003`](/mitre/techniques/T1071-003.md) | Application Layer Protocol: Mail Protocols | Command and Control | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Data Staged: Local Data Staging | Collection | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1078.003`](/mitre/techniques/T1078-003.md) | Valid Accounts: Local Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Valid Accounts: Cloud Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | 6: G0032, G0067, G0082, G0094, G1036, G1052 | ATT&CK group record | [2], [3], [4], [5], [7], [9], [12] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | 4: G0032, G0082, G0094, G1052 | ATT&CK group record; also AA23-040A (DPRK ransomware), 2023-02-09 [41] | [2], [4], [5], [9], [41], [12] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | Command and Control | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1090.001`](/mitre/techniques/T1090-001.md) | Proxy: Internal Proxy | Command and Control | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1090.002`](/mitre/techniques/T1090-002.md) | Proxy: External Proxy | Command and Control | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1098.007`](/mitre/techniques/T1098-007.md) | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1102.001`](/mitre/techniques/T1102-001.md) | Web Service: Dead Drop Resolver | Command and Control | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1102.002`](/mitre/techniques/T1102-002.md) | Web Service: Bidirectional Communication | Command and Control | 3: G0032, G0067, G0094 | ATT&CK group record | [2], [3], [5], [12] |
| [`T1104`](/mitre/techniques/T1104.md) | Multi-Stage Channels | Command and Control | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | 6: G0032, G0067, G0082, G0094, G0138, G1036 | ATT&CK group record | [2], [3], [4], [5], [6], [7], [12] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | Execution | 4: G0032, G0067, G0082, G0094 | ATT&CK group record | [2], [3], [4], [5], [12] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | Credential Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Brute Force: Password Spraying | Credential Access | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1111`](/mitre/techniques/T1111.md) | Multi-Factor Authentication Interception | Credential Access | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | Collection | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Email Collection: Remote Email Collection | Collection | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1114.003`](/mitre/techniques/T1114-003.md) | Email Collection: Email Forwarding Rule | Collection | 1: G0094 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [5], [26], [12] |
| [`T1115`](/mitre/techniques/T1115.md) | Clipboard Data | Collection | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | Discovery | 1: G0067 | ATT&CK group record | [3], [12] |
| [`T1123`](/mitre/techniques/T1123.md) | Audio Capture | Collection | 1: G0067 | ATT&CK group record | [3], [12] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | Discovery | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1132.001`](/mitre/techniques/T1132-001.md) | Data Encoding: Standard Encoding | Command and Control | 2: G0032, G0082 | ATT&CK group record | [2], [4], [12] |
| [`T1132.002`](/mitre/techniques/T1132-002.md) | Data Encoding: Non-Standard Encoding | Command and Control | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | 1: G0094 | ATT&CK group record; also AA23-040A (DPRK ransomware), 2023-02-09 [41] | [5], [41], [12] |
| [`T1134.002`](/mitre/techniques/T1134-002.md) | Access Token Manipulation: Create Process with Token | Stealth, Privilege Escalation | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Create Account: Local Account | Persistence | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | 4: G0032, G0082, G0094, G1036 | ATT&CK group record | [2], [4], [5], [7], [12] |
| [`T1176.001`](/mitre/techniques/T1176-001.md) | Software Extensions: Browser Extensions | Persistence | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1185`](/mitre/techniques/T1185.md) | Browser Session Hijacking | Collection | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | 4: G0032, G0067, G0082, G0138 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [3], [4], [6], [26], [12] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | 1: G0094 | ATT&CK group record; also AA23-040A (DPRK ransomware), 2023-02-09 [41]; AA24-207A (Andariel), 2024-07-25 [60] | [5], [41], [60], [12] |
| [`T1195.001`](/mitre/techniques/T1195-001.md) | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Initial Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | 1: G1036 | ATT&CK group record | [7], [12] |
| [`T1202`](/mitre/techniques/T1202.md) | Indirect Command Execution | Stealth | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | 3: G0032, G0067, G0138 | ATT&CK group record | [2], [3], [6], [12] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | User Execution: Malicious Link | Execution | 3: G0082, G0094, G1052 | ATT&CK group record | [4], [5], [9], [12] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | User Execution: Malicious File | Execution | 7: G0032, G0067, G0082, G0094, G0138, G1036, G1052 | ATT&CK group record | [2], [3], [4], [5], [6], [7], [9], [12] |
| [`T1204.004`](/mitre/techniques/T1204-004.md) | User Execution: Malicious Copy and Paste | Execution | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1204.005`](/mitre/techniques/T1204-005.md) | User Execution: Malicious Library | Execution | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1205`](/mitre/techniques/T1205.md) | Traffic Signaling | Stealth, Persistence, Command and Control | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1213.005`](/mitre/techniques/T1213-005.md) | Data from Information Repositories: Messaging Applications | Collection | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1213.006`](/mitre/techniques/T1213-006.md) | Data from Information Repositories: Databases | Collection | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1217`](/mitre/techniques/T1217.md) | Browser Information Discovery | Discovery | 3: G0082, G0094, G1036 | ATT&CK group record | [4], [5], [7], [12] |
| [`T1218`](/mitre/techniques/T1218.md) | System Binary Proxy Execution | Stealth | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1218.001`](/mitre/techniques/T1218-001.md) | System Binary Proxy Execution: Compiled HTML File | Stealth | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1218.005`](/mitre/techniques/T1218-005.md) | System Binary Proxy Execution: Mshta | Stealth | 3: G0032, G0082, G0094 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [4], [5], [26], [12] |
| [`T1218.007`](/mitre/techniques/T1218-007.md) | System Binary Proxy Execution: Msiexec | Stealth | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1218.010`](/mitre/techniques/T1218-010.md) | System Binary Proxy Execution: Regsvr32 | Stealth | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | System Binary Proxy Execution: Rundll32 | Stealth | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1219.002`](/mitre/techniques/T1219-002.md) | Remote Access Tools: Remote Desktop Software | Command and Control | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1222.002`](/mitre/techniques/T1222-002.md) | File and Directory Permissions Modification: Linux and Mac Permissions | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1480`](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1480.002`](/mitre/techniques/T1480-002.md) | Execution Guardrails: Mutual Exclusion | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | Impact | 2: G0032, G0082 | ATT&CK group record | [2], [4], [12] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | 2: G0082, G1036 | ATT&CK group record; also AA22-187A (Maui), 2022-07-06 [38]; AA23-040A (DPRK ransomware), 2023-02-09 [41] | [4], [7], [38], [41], [12] |
| [`T1489`](/mitre/techniques/T1489.md) | Service Stop | Impact | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1491.001`](/mitre/techniques/T1491-001.md) | Defacement: Internal Defacement | Impact | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1497`](/mitre/techniques/T1497.md) | Virtualization/Sandbox Evasion | Stealth, Discovery | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1497.001`](/mitre/techniques/T1497-001.md) | Virtualization/Sandbox Evasion: System Checks | Stealth, Discovery | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Server Software Component: Web Shell | Persistence | 2: G0082, G0094 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [4], [5], [26], [12] |
| [`T1518`](/mitre/techniques/T1518.md) | Software Discovery | Discovery | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Software Discovery: Security Software Discovery | Discovery | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1529`](/mitre/techniques/T1529.md) | System Shutdown/Reboot | Impact | 3: G0032, G0067, G0082 | ATT&CK group record | [2], [3], [4], [12] |
| [`T1534`](/mitre/techniques/T1534.md) | Internal Spearphishing | Lateral Movement | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1539`](/mitre/techniques/T1539.md) | Steal Web Session Cookie | Credential Access | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Pre-OS Boot: Bootkit | Stealth, Persistence | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1543.001`](/mitre/techniques/T1543-001.md) | Create or Modify System Process: Launch Agent | Persistence, Privilege Escalation | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1543.004`](/mitre/techniques/T1543-004.md) | Create or Modify System Process: Launch Daemon | Persistence, Privilege Escalation | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1546.001`](/mitre/techniques/T1546-001.md) | Event Triggered Execution: Change Default File Association | Privilege Escalation, Persistence | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1546.004`](/mitre/techniques/T1546-004.md) | Event Triggered Execution: Unix Shell Configuration Modification | Privilege Escalation, Persistence | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1546.016`](/mitre/techniques/T1546-016.md) | Event Triggered Execution: Installer Packages | Privilege Escalation, Persistence | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | 6: G0032, G0067, G0082, G0094, G1036, G1052 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [3], [4], [5], [7], [9], [26], [12] |
| [`T1547.009`](/mitre/techniques/T1547-009.md) | Boot or Logon Autostart Execution: Shortcut Modification | Persistence, Privilege Escalation | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1547.013`](/mitre/techniques/T1547-013.md) | Boot or Logon Autostart Execution: XDG Autostart Entries | Persistence, Privilege Escalation | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1548.002`](/mitre/techniques/T1548-002.md) | Abuse Elevation Control Mechanism: Bypass User Account Control | Privilege Escalation | 2: G0067, G0082 | ATT&CK group record | [3], [4], [12] |
| [`T1548.003`](/mitre/techniques/T1548-003.md) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1548.006`](/mitre/techniques/T1548-006.md) | Abuse Elevation Control Mechanism: TCC Manipulation | Privilege Escalation | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Use Alternate Authentication Material: Pass the Hash | Lateral Movement | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1552.001`](/mitre/techniques/T1552-001.md) | Unsecured Credentials: Credentials In Files | Credential Access | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1552.003`](/mitre/techniques/T1552-003.md) | Unsecured Credentials: Shell History | Credential Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1552.004`](/mitre/techniques/T1552-004.md) | Unsecured Credentials: Private Keys | Credential Access | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Subvert Trust Controls: Code Signing | Defense Impairment | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1553.005`](/mitre/techniques/T1553-005.md) | Subvert Trust Controls: Mark-of-the-Web Bypass | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1555.001`](/mitre/techniques/T1555-001.md) | Credentials from Password Stores: Keychain | Credential Access | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | 3: G0067, G0082, G0094 | ATT&CK group record | [3], [4], [5], [12] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | Credential Access, Collection | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1557.001`](/mitre/techniques/T1557-001.md) | Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay | Credential Access, Collection | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1559.001`](/mitre/techniques/T1559-001.md) | Inter-Process Communication: Component Object Model | Execution | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1559.002`](/mitre/techniques/T1559-002.md) | Inter-Process Communication: Dynamic Data Exchange | Execution | 1: G0067 | ATT&CK group record | [3], [12] |
| [`T1560`](/mitre/techniques/T1560.md) | Archive Collected Data | Collection | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive Collected Data: Archive via Utility | Collection | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1560.002`](/mitre/techniques/T1560-002.md) | Archive Collected Data: Archive via Library | Collection | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive Collected Data: Archive via Custom Method | Collection | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Wipe: Disk Content Wipe | Impact | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Wipe: Disk Structure Wipe | Impact | 3: G0032, G0067, G0082 | ATT&CK group record | [2], [3], [4], [12] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hide Artifacts: Hidden Files and Directories | Stealth | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1564.002`](/mitre/techniques/T1564-002.md) | Hide Artifacts: Hidden Users | Stealth | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1564.003`](/mitre/techniques/T1564-003.md) | Hide Artifacts: Hidden Window | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1564.011`](/mitre/techniques/T1564-011.md) | Hide Artifacts: Ignore Process Interrupts | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1564.012`](/mitre/techniques/T1564-012.md) | Hide Artifacts: File/Path Exclusions | Stealth | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1565.001`](/mitre/techniques/T1565-001.md) | Data Manipulation: Stored Data Manipulation | Impact | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1565.002`](/mitre/techniques/T1565-002.md) | Data Manipulation: Transmitted Data Manipulation | Impact | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1565.003`](/mitre/techniques/T1565-003.md) | Data Manipulation: Runtime Data Manipulation | Impact | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | Initial Access | 2: G0094, G1049 | ATT&CK group record | [5], [8], [12] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Phishing: Spearphishing Attachment | Initial Access | 6: G0032, G0067, G0082, G0094, G0138, G1036 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [3], [4], [5], [6], [7], [26], [12] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Phishing: Spearphishing Link | Initial Access | 3: G0032, G0082, G0094 | ATT&CK group record; also AA20-301A (Kimsuky), 2020-10-27 [26] | [2], [4], [5], [26], [12] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Phishing: Spearphishing via Service | Initial Access | 4: G0032, G0082, G1036, G1052 | ATT&CK group record | [2], [4], [7], [9], [12] |
| [`T1567`](/mitre/techniques/T1567.md) | Exfiltration Over Web Service | Exfiltration | 2: G0082, G1052 | ATT&CK group record; also AA24-207A (Andariel), 2024-07-25 [60] | [4], [9], [60], [12] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1568`](/mitre/techniques/T1568.md) | Dynamic Resolution | Command and Control | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | System Services: Service Execution | Execution | 2: G0082, G1036 | ATT&CK group record | [4], [7], [12] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | Command and Control | 3: G0032, G0082, G1052 | ATT&CK group record | [2], [4], [9], [12] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Encrypted Channel: Symmetric Cryptography | Command and Control | 2: G0032, G1052 | ATT&CK group record | [2], [9], [12] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | Hijack Execution Flow: DLL | Stealth, Execution | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1574.013`](/mitre/techniques/T1574-013.md) | Hijack Execution Flow: KernelCallbackTable | Stealth, Execution | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1583`](/mitre/techniques/T1583.md) | Acquire Infrastructure | Resource Development | 2: G0094, G1052 | ATT&CK group record; also AA23-040A (DPRK ransomware), 2023-02-09 [41] | [5], [9], [41], [12] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Acquire Infrastructure: Domains | Resource Development | 5: G0032, G0082, G0094, G1036, G1052 | ATT&CK group record | [2], [4], [5], [7], [9], [12] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Acquire Infrastructure: Virtual Private Server | Resource Development | 3: G0082, G1036, G1052 | ATT&CK group record; also AA23-040A (DPRK ransomware), 2023-02-09 [41] | [4], [7], [9], [41], [12] |
| [`T1583.004`](/mitre/techniques/T1583-004.md) | Acquire Infrastructure: Server | Resource Development | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Acquire Infrastructure: Web Services | Resource Development | 4: G0032, G0082, G0094, G1052 | ATT&CK group record | [2], [4], [5], [9], [12] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Compromise Infrastructure: Domains | Resource Development | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Compromise Infrastructure: Server | Resource Development | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1585`](/mitre/techniques/T1585.md) | Establish Accounts | Resource Development | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Establish Accounts: Social Media Accounts | Resource Development | 5: G0032, G0082, G0094, G1036, G1052 | ATT&CK group record | [2], [4], [5], [7], [9], [12] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Establish Accounts: Email Accounts | Resource Development | 5: G0032, G0082, G0094, G1036, G1052 | ATT&CK group record | [2], [4], [5], [7], [9], [12] |
| [`T1586.002`](/mitre/techniques/T1586-002.md) | Compromise Accounts: Email Accounts | Resource Development | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1586.003`](/mitre/techniques/T1586-003.md) | Compromise Accounts: Cloud Accounts | Resource Development | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1587`](/mitre/techniques/T1587.md) | Develop Capabilities | Resource Development | 3: G0094, G1036, G1052 | ATT&CK group record | [5], [7], [9], [12] |
| [`T1587.001`](/mitre/techniques/T1587-001.md) | Develop Capabilities: Malware | Resource Development | 4: G0032, G0094, G1036, G1052 | ATT&CK group record | [2], [5], [7], [9], [12] |
| [`T1588.001`](/mitre/techniques/T1588-001.md) | Obtain Capabilities: Malware | Resource Development | 1: G0138 | ATT&CK group record | [6], [12] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Obtain Capabilities: Tool | Resource Development | 4: G0032, G0082, G0094, G1052 | ATT&CK group record | [2], [4], [5], [9], [12] |
| [`T1588.003`](/mitre/techniques/T1588-003.md) | Obtain Capabilities: Code Signing Certificates | Resource Development | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Obtain Capabilities: Digital Certificates | Resource Development | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1588.005`](/mitre/techniques/T1588-005.md) | Obtain Capabilities: Exploits | Resource Development | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1588.007`](/mitre/techniques/T1588-007.md) | Obtain Capabilities: Artificial Intelligence | Resource Development | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1589`](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1589.002`](/mitre/techniques/T1589-002.md) | Gather Victim Identity Information: Email Addresses | Reconnaissance | 3: G0032, G0094, G1036 | ATT&CK group record | [2], [5], [7], [12] |
| [`T1589.003`](/mitre/techniques/T1589-003.md) | Gather Victim Identity Information: Employee Names | Reconnaissance | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1590.005`](/mitre/techniques/T1590-005.md) | Gather Victim Network Information: IP Addresses | Reconnaissance | 1: G0138 | ATT&CK group record | [6], [12] |
| [`T1591`](/mitre/techniques/T1591.md) | Gather Victim Org Information | Reconnaissance | 3: G0032, G0094, G1036 | ATT&CK group record | [2], [5], [7], [12] |
| [`T1592.002`](/mitre/techniques/T1592-002.md) | Gather Victim Host Information: Software | Reconnaissance | 1: G0138 | ATT&CK group record | [6], [12] |
| [`T1593`](/mitre/techniques/T1593.md) | Search Open Websites/Domains | Reconnaissance | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1593.001`](/mitre/techniques/T1593-001.md) | Search Open Websites/Domains: Social Media | Reconnaissance | 2: G0094, G1052 | ATT&CK group record | [5], [9], [12] |
| [`T1593.002`](/mitre/techniques/T1593-002.md) | Search Open Websites/Domains: Search Engines | Reconnaissance | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1593.003`](/mitre/techniques/T1593-003.md) | Search Open Websites/Domains: Code Repositories | Reconnaissance | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1594`](/mitre/techniques/T1594.md) | Search Victim-Owned Websites | Reconnaissance | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1596`](/mitre/techniques/T1596.md) | Search Open Technical Databases | Reconnaissance | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1598`](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | 2: G0094, G1036 | ATT&CK group record | [5], [7], [12] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Phishing for Information: Spearphishing Link | Reconnaissance | 2: G0094, G1036 | ATT&CK group record | [5], [7], [12] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Stage Capabilities: Upload Malware | Resource Development | 4: G0082, G0094, G1036, G1052 | ATT&CK group record | [4], [5], [7], [9], [12] |
| [`T1620`](/mitre/techniques/T1620.md) | Reflective Code Loading | Stealth | 3: G0032, G0082, G0094 | ATT&CK group record | [2], [4], [5], [12] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | Impact | 4: G0082, G0094, G1049, G1052 | ATT&CK group record | [4], [5], [8], [9], [12] |
| [`T1677`](/mitre/techniques/T1677.md) | Poisoned Pipeline Execution | Execution | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1678`](/mitre/techniques/T1678.md) | Delay Execution | Stealth | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1680`](/mitre/techniques/T1680.md) | Local Storage Discovery | Discovery | 2: G0032, G0094 | ATT&CK group record | [2], [5], [12] |
| [`T1681`](/mitre/techniques/T1681.md) | Search Threat Vendor Data | Reconnaissance | 1: G1052 | ATT&CK group record | [9], [12] |
| [`T1682`](/mitre/techniques/T1682.md) | Query Public AI Services | Reconnaissance | 1: G0094 | ATT&CK group record | [5], [12] |
| [`T1683.001`](/mitre/techniques/T1683-001.md) | Generate Content: Written Content | Resource Development | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1683.002`](/mitre/techniques/T1683-002.md) | Generate Content: Audio-Visual Content | Resource Development | 2: G0082, G1052 | ATT&CK group record | [4], [9], [12] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Social Engineering: Impersonation | Stealth | 3: G0082, G0094, G1052 | ATT&CK group record | [4], [5], [9], [12] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | 4: G0032, G0082, G0094, G1052 | ATT&CK group record; also ATT&CK T1685 page, procedure examples, page modified 2026-09-11 [11] | [2], [4], [5], [9], [11], [12] |
| [`T1685.003`](/mitre/techniques/T1685-003.md) | Disable or Modify Tools: Modify or Spoof Tool UI | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Disable or Modify Tools: Clear Windows Event Logs | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1686`](/mitre/techniques/T1686.md) | Disable or Modify System Firewall | Defense Impairment | 2: G0082, G0094 | ATT&CK group record | [4], [5], [12] |
| [`T1686.002`](/mitre/techniques/T1686-002.md) | Disable or Modify System Firewall: Network Device Firewall | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |
| [`T1686.003`](/mitre/techniques/T1686-003.md) | Disable or Modify System Firewall: Windows Host Firewall | Defense Impairment | 1: G0032 | ATT&CK group record | [2], [12] |
| [`T1690`](/mitre/techniques/T1690.md) | Prevent Command History Logging | Defense Impairment | 1: G0082 | ATT&CK group record | [4], [12] |

### Enterprise techniques stated only in government advisories

These IDs appear in an opened advisory's own ATT&CK table but in none of the eight groups' ATT&CK records (**Confirmed** [41] [60] [12]). Only IDs the verification pass checked are bound; AA24-207A lists 22 IDs in all.

| ID | Technique | Tactic (v20) | Stated by (advisory, date) | Sources |
|---|---|---|---|---|
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | Credential Access | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1021`](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | AA23-040A (DPRK ransomware), 2023-02-09 [41]; AA24-207A (Andariel), 2024-07-25 [60] | [41], [60], [12] |
| [`T1039`](/mitre/techniques/T1039.md) | Data from Network Shared Drive | Collection | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | Exfiltration | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1071`](/mitre/techniques/T1071.md) | Application Layer Protocol | Command and Control | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1087`](/mitre/techniques/T1087.md) | Account Discovery | Discovery | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1195`](/mitre/techniques/T1195.md) | Supply Chain Compromise | Initial Access | AA23-040A (DPRK ransomware), 2023-02-09 [41] | [41], [12] |
| [`T1572`](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1587.004`](/mitre/techniques/T1587-004.md) | Develop Capabilities: Exploits | Resource Development | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1592`](/mitre/techniques/T1592.md) | Gather Victim Host Information | Reconnaissance | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |
| [`T1595`](/mitre/techniques/T1595.md) | Active Scanning | Reconnaissance | AA24-207A (Andariel), 2024-07-25 [60] | [60], [12] |

Two advisory IDs are deliberately not bound. AA22-187A lists `T1059.008` with the label "Command-Line Interface", but ATT&CK names `T1059.008` Network Device CLI, which does not fit a Windows encryptor; only its `T1486` is bound (**Confirmed** [38] [12]). AA20-239A pairs several IDs with the wrong names (for example `T1056` given for OS Credential Dumping and the revoked `T1101` for Data Obfuscation), so none of its rows is copied (**Confirmed** [25]).

### Mobile and ICS

Kimsuky has one ATT&CK for Mobile technique, `T1660` Phishing, and Lazarus Group has one ATT&CK for ICS technique, `T0865` Spearphishing Attachment (**Confirmed** [12]). The library has no ATT&CK Mobile or ICS technique page for either ID (its `mitre/f3/T1660.md` is a page in a different framework), so neither is linked and neither is in the Enterprise layer (**Confirmed** [12]).

### Groups, campaigns and software

| Object | ID | Role in this study | Sources |
|---|---|---|---|
| Lazarus Group | [`G0032`](/mitre/groups/G0032.md) | Umbrella group; Sony, WannaCry, Dream Job, Ronin, Harmony, Medusa | [2] |
| APT37 | [`G0067`](/mitre/groups/G0067.md) | South Korea-focused espionage | [3] |
| APT38 | [`G0082`](/mitre/groups/G0082.md) | Bank and crypto theft; BeagleBoyz, Bluenoroff, Sapphire Sleet aliases | [4] |
| Kimsuky | [`G0094`](/mitre/groups/G0094.md) | Policy espionage; APT43 alias; 2023 designation | [5] |
| Andariel | [`G0138`](/mitre/groups/G0138.md) | Maui ransomware and defense espionage (US record) | [6] |
| Moonstone Sleet | [`G1036`](/mitre/groups/G1036.md) | Fake companies, game and ransomware | [7] |
| AppleJeus | [`G1049`](/mitre/groups/G1049.md) | Crypto industry; 3CX | [8] |
| Contagious Interview | [`G1052`](/mitre/groups/G1052.md) | Operations against software developers and crypto individuals | [9] |
| Operation Dream Job | [`C0022`](/mitre/campaigns/C0022.md) | Lazarus campaign, 2019 to 2020 | [10] |
| 3CX Supply Chain Attack | [`C0057`](/mitre/campaigns/C0057.md) | AppleJeus campaign, 2022 to 2023 | [8], [12] |
| Operation Sharpshooter | [`C0013`](/mitre/campaigns/C0013.md) | Not attributed by ATT&CK; similarities with Lazarus noted | [12] |
| WannaCry | [`S0366`](/mitre/software/S0366.md) | The 2017 ransomware | [2], [19] |
| AppleJeus (software) | [`S0584`](/mitre/software/S0584.md) | Trojanized trading apps | [32] |
| FALLCHILL | [`S0181`](/mitre/software/S0181.md) | Delivered with the first AppleJeus version | [32] |
| BLINDINGCAN | [`S0520`](/mitre/software/S0520.md) | Used with Medusa in 2025 to 2026 | [75] |
| MagicRAT | [`S1182`](/mitre/software/S1182.md) | Parent of QuiteRAT | [46] |
| Dtrack | [`S0567`](/mitre/software/S0567.md) | Used by Stonefly in 2024 | [63] |
| FRP | [`S1144`](/mitre/software/S1144.md) | FastReverseProxy; 3CX campaign tool, used by Stonefly in 2024 | [8], [63], [12] |
| Medusa Ransomware | [`S1244`](/mitre/software/S1244.md) | Used by Lazarus actors (Symantec, 2026, single vendor); ATT&CK links the family to Medusa Group, not to a North Korean group | [75], [12] |
| BeaverTail, InvisibleFerret | [`S1246`](/mitre/software/S1246.md), [`S1245`](/mitre/software/S1245.md) | Contagious Interview and DeceptiveDevelopment malware | [9], [50], [67] |
| ROKRAT | [`S0240`](/mitre/software/S0240.md) | APT37 | [3] |
| Rifdoor | [`S0433`](/mitre/software/S0433.md) | Andariel | [6] |
| Qilin | [`S1242`](/mitre/software/S1242.md) | Moonstone Sleet's ATT&CK software entry | [7] |
| KONNI, SYSCON | [`S0356`](/mitre/software/S0356.md), [`S0464`](/mitre/software/S0464.md) | North Korea-linked software with no group in ATT&CK | [12] |

The full per-group software list is in Part 3.

### CWE and CAPEC

CWE IDs come from the KEV `cwes` field for each exploited CVE (Part 4); CAPEC IDs come from the library's `data/weaknesses/cwe.jsonl` for weakness-to-pattern links and the `capec` field of `data/attack/technique_profiles.jsonl` for technique-to-pattern links (**Confirmed** [12] [83]). See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

| Weakness | CVEs in this record | CAPEC patterns linked in the library data |
|---|---|---|
| CWE-502 Deserialization of Untrusted Data | CVE-2021-44228 | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection |
| CWE-917 Expression Language Injection | CVE-2021-44228 (NVD, per the [Log4Shell study](/case-studies/LOG4SHELL.md)) | None in the library data |
| CWE-121 Stack-based Buffer Overflow | CVE-2021-20038 | None in the library data |
| CWE-306 Missing Authentication for Critical Function | CVE-2022-24990 | Five broad patterns, not expanded here |
| CWE-288 Authentication Bypass Using an Alternate Path or Channel | CVE-2023-42793 | Two patterns, neither specific to this flaw |
| CWE-20, CWE-400 | CVE-2021-44228 (KEV field) | Broad classes, not expanded |

| Technique (use in this record) | CAPEC patterns linked in the library data |
|---|---|
| `T1566.001`, `T1566.002`, `T1566.003` Spearphishing (Kimsuky, recruiters, fake interviews) | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing |
| `T1195.002` Compromise Software Supply Chain (Moonstone Sleet's trojanized software) | [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update; [CAPEC-442](/mitre/capec/CAPEC-442.md) Infected Software; [CAPEC-443](/mitre/capec/CAPEC-443.md); [CAPEC-523](/mitre/capec/CAPEC-523.md); [CAPEC-669](/mitre/capec/CAPEC-669.md) Alteration of a Software Update; [CAPEC-673](/mitre/capec/CAPEC-673.md); [CAPEC-678](/mitre/capec/CAPEC-678.md); [CAPEC-691](/mitre/capec/CAPEC-691.md) |
| `T1195` Supply Chain Compromise (AA23-040A) | [CAPEC-438](/mitre/capec/CAPEC-438.md); [CAPEC-439](/mitre/capec/CAPEC-439.md) Manipulation During Distribution; [CAPEC-446](/mitre/capec/CAPEC-446.md) |
| `T1505.003` Web Shell (AA20-301A) | [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server |
| `T1547.001` Registry Run Keys / Startup Folder | [CAPEC-270](/mitre/capec/CAPEC-270.md) Modification of Registry Run Keys |
| `T1056.001` Keylogging | [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger |
| `T1685` Disable or Modify Tools | [CAPEC-571](/mitre/capec/CAPEC-571.md) Block Logging to Central Repository; [CAPEC-578](/mitre/capec/CAPEC-578.md) Disable Security Software |
| `T1133` External Remote Services (AA23-040A) | [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials |
| `T1021.002` SMB/Windows Admin Shares (AA24-207A) | [CAPEC-561](/mitre/capec/CAPEC-561.md) Windows Admin Shares with Stolen Credentials |
| `T1078` Valid Accounts (IT workers, stolen credentials) | [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials |
| `T1592`, `T1595` host information and scanning (AA24-207A) | [CAPEC-169](/mitre/capec/CAPEC-169.md) Footprinting |
| `T1087` Account Discovery (AA24-207A) | [CAPEC-575](/mitre/capec/CAPEC-575.md) Account Footprinting |

### D3FEND countermeasures

None of the opened advisories cites D3FEND (**Confirmed** [38] [41] [60]). The table pairs each advisory recommendation with the library's D3FEND entry that implements it; the IDs and pages are confirmed in the library data, and the pairing is this study's own (**Inferred** [12]). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

| Advisory recommendation | D3FEND countermeasure in the library | Advisory sources |
|---|---|---|
| MFA, phishing-resistant MFA | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (`D3-MFA`) | [26], [41], [44] |
| Application allowlisting | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`) | [35], [38], [41], [44], [60] |
| KEV-first patching and inventory | [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (`D3-AVE`), [Software Inventory](/mitre/d3fend/software-inventory.md) (`D3-SWI`) | [41], [44], [60] |
| DMARC enforcement and spoofed-sender handling | [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (`D3-SRA`), [Sender MTA Reputation Analysis](/mitre/d3fend/sender-mta-reputation-analysis.md) (`D3-SMRA`), [Email Filtering](/mitre/d3fend/email-filtering.md) (`D3-EF`) | [53] |
| PKI-authenticated connections to medical devices and EHR | [Message Authentication](/mitre/d3fend/message-authentication.md) (`D3-MAN`) | [38] |
| Block unnecessary outbound connections | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`) | [60] |
| WAFs and blocking external admin panels | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (`D3-ITF`) | [60] |
| Disable WAN management interfaces, restrict RDP | [Disable Remote Access](/mitre/d3fend/disable-remote-access.md) (`D3-DRA`), [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (`D3-RTSD`) | [38], [41], [44] |
| Standard user accounts, least privilege | [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (`D3-UAP`) | [38], [66] |
| Credential hardening against LSASS access | [Credential Hardening](/mitre/d3fend/credential-hardening.md) (`D3-CH`) | [55] |
| Encrypt patient data at rest | [Disk Encryption](/mitre/d3fend/disk-encryption.md) (`D3-DENCR`), [File Encryption](/mitre/d3fend/file-encryption.md) (`D3-FE`) | [38], [41] |
| Command-line monitoring | [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`) | [26], [60] |
| Protected view and disabling macros | [File Analysis](/mitre/d3fend/file-analysis.md) (`D3-FA`), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (`D3-DA`) | [35], [44] |
| Tested, immutable backups | [Restore File](/mitre/d3fend/restore-file.md) (`D3-RF`) | [38], [41] |

The library's technique-to-D3FEND data covers the shared core well: `T1566.001` maps to 31 D3FEND techniques (including Email Filtering and [Email Removal](/mitre/d3fend/email-removal.md)), `T1204.002` to 15 (including Executable Allowlisting), `T1190` to 14 (including Inbound Traffic Filtering), `T1547.001` to 18, `T1053.005` to 12 (including Process Spawn Analysis), `T1105` to 11 (including Outbound Traffic Filtering), `T1486` to 11 (including Restore File) and `T1133` to 1. `T1059.001` PowerShell has no D3FEND row, although Kimsuky's advisory gives PowerShell detections (**Confirmed** [12] [26]).

### Navigator layer

The study's techniques are collected in an ATT&CK Navigator layer, [`navigator/library-layers/threat-actors-north-korea.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-north-korea.json), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/threat-actors-north-korea.json). It holds 251 Enterprise techniques: the 240 from the group records, scored 100, and the 11 advisory-only techniques, scored 60. Scores mean evidence basis, not frequency or severity. Each technique's comment names the groups or advisory and the study's source numbers. The Mobile and ICS techniques are left out (see above).

## Cross-cutting themes

- **Revenue drives the program.** From Bangladesh Bank to Binance, the largest events in the record are thefts, and US agencies and MSMT both tie the proceeds to weapons programs. A state that steals to fund itself behaves more like an organized crime group with intelligence-service backing than like a classic espionage service (**Confirmed** [23] [73] [74]; the comparison is **Inferred**). See the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md).
- **Trust is the attack surface.** Recruiters, job tests, coding interviews, trading apps, messenger updates, a trading platform's installer and the hiring process itself all appear as access paths. Each is something people were taught to trust. See [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md) and the [SolarWinds study](/case-studies/SOLARWINDS_SUNBURST.md) for another supply chain record.
- **One unit, two missions.** AA24-207A's observation that Andariel ran ransomware and espionage against the same victim, sometimes on the same day, means a ransomware incident at a hospital or defense supplier should be scoped as a possible espionage incident too (**Confirmed** [60]; the advice is **Inferred**). The [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) documents the same dual pattern for a Chinese group.
- **Attribution is a ladder, not a label.** The record runs from "able to confirm" (FBI) and criminal indictments down to "likely theory" (Kaspersky, 2013), "moderate confidence" (Mandiant on 3CX) and "aligned" (ESET, ATT&CK). A defender's report should carry the rung, not just the name.
- **Names fragment faster than activity does.** Lazarus Group, HIDDEN COBRA, BeagleBoyz, TraderTraitor, APT38, Bluenoroff, Sapphire Sleet and Jade Sleet can all describe overlapping money-theft activity, and the library's own pages differ on whether APT38 is a subgroup (**Confirmed** [4] [12] [25] [64]; the conclusion is **Inferred**).
- **The record has moved from advisories to enforcement.** Since July 2024 the public US record is mostly FBI PSAs, theft attributions and DOJ actions against facilitators, not new CISA advisories (**Inferred** from [16] and the timeline).
- **The library's own data has edges.** The group pages hold 240 techniques, but the Andariel advisory chain, Maui and H0lyGh0st live outside them. Readers comparing tools against this layer should know which count they are using.

## Sources

Every source below was opened on 3 November 2026 unless its row says otherwise. Grades apply to the source type: Confirmed for a primary (the publisher of the fact), Reported for secondary coverage or an unopened primary.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | MITRE ATT&CK, Groups index (ATT&CK v20.0) | https://attack.mitre.org/groups/ | 2026-11-03 | Confirmed |
| 2 | MITRE ATT&CK, Group G0032 Lazarus Group (v5.0, modified 31 July 2026) | https://attack.mitre.org/groups/G0032/ | 2026-11-03 | Confirmed |
| 3 | MITRE ATT&CK, Group G0067 APT37 (v2.0) | https://attack.mitre.org/groups/G0067/ | 2026-11-03 | Confirmed |
| 4 | MITRE ATT&CK, Group G0082 APT38 (v4.0, modified 09 October 2026) | https://attack.mitre.org/groups/G0082/ | 2026-11-03 | Confirmed |
| 5 | MITRE ATT&CK, Group G0094 Kimsuky (v5.2) | https://attack.mitre.org/groups/G0094/ | 2026-11-03 | Confirmed |
| 6 | MITRE ATT&CK, Group G0138 Andariel (v2.0) | https://attack.mitre.org/groups/G0138/ | 2026-11-03 | Confirmed |
| 7 | MITRE ATT&CK, Group G1036 Moonstone Sleet (v1.0) | https://attack.mitre.org/groups/G1036/ | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, Group G1049 AppleJeus (v1.0) | https://attack.mitre.org/groups/G1049/ | 2026-11-03 | Confirmed |
| 9 | MITRE ATT&CK, Group G1052 Contagious Interview (v1.0) | https://attack.mitre.org/groups/G1052/ | 2026-11-03 | Confirmed |
| 10 | MITRE ATT&CK, Campaign C0022 Operation Dream Job (v1.2) | https://attack.mitre.org/campaigns/C0022/ | 2026-11-03 | Confirmed |
| 11 | MITRE ATT&CK, Technique T1685 Disable or Modify Tools (v1.0) | https://attack.mitre.org/techniques/T1685/ | 2026-11-03 | Confirmed |
| 12 | TeamStarWolf library data and generated pages at commit e85b559: data/attack/ (groups, group_profiles, group_to_technique, software, software_profiles, campaigns, technique_profiles, superseded_by, d3fend_countermeasures, technique_to_d3fend, ics/, mobile/), data/weaknesses/, mitre/ and navigator/ | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-03 | Confirmed |
| 13 | Kaspersky, "The Kimsuky Operation: A North Korean APT?" (2013-09-11) | https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/ | 2026-11-03 | Confirmed |
| 14 | FBI, Update on Sony Investigation (2014-12-19) | https://www.fbi.gov/news/press-releases/update-on-sony-investigation | 2026-11-03 | Confirmed |
| 15 | Kaspersky, "Lazarus Under the Hood" (2017-04-03) | https://securelist.com/lazarus-under-the-hood/77908/ | 2026-11-03 | Confirmed |
| 16 | CISA, North Korea cyber threat publications list | https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/north-korea/publications | 2026-11-03 | Confirmed |
| 17 | DHS and FBI, TA17-164A HIDDEN COBRA: North Korea's DDoS Botnet Infrastructure (2017-06-13) | https://www.cisa.gov/news-events/alerts/2017/06/13/hidden-cobra-north-koreas-ddos-botnet-infrastructure | 2026-11-03 | Confirmed |
| 18 | UK National Audit Office, Investigation: WannaCry cyber attack and the NHS | https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/ | 2026-11-03 | Confirmed |
| 19 | UK Foreign Office, Foreign Office Minister condemns North Korean actor for WannaCry attacks (2017-12-19) | https://www.gov.uk/government/news/foreign-office-minister-condemns-north-korean-actor-for-wannacry-attacks | 2026-11-03 | Confirmed |
| 20 | FBI, Wanted: Park Jin Hyok | https://www.fbi.gov/wanted/cyber/park-jin-hyok | 2026-11-03 | Confirmed |
| 21 | US Treasury, sm473: Park Jin Hyok and Chosun Expo designated (2018-09-06) | https://home.treasury.gov/news/press-releases/sm473 | 2026-11-03 | Confirmed |
| 22 | US Treasury, sm774: Lazarus Group, Bluenoroff and Andariel designated (2019-09-13) | https://home.treasury.gov/news/press-releases/sm774 | 2026-11-03 | Confirmed |
| 23 | State, Treasury, DHS and FBI, AA20-106A Guidance on the North Korean Cyber Threat (2020-04-15) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a | 2026-11-03 | Confirmed |
| 24 | ESET, Operation In(ter)ception (2020-06-17) | https://www.welivesecurity.com/2020/06/17/operation-interception-aerospace-military-companies-cyberspies/ | 2026-11-03 | Confirmed |
| 25 | CISA, Treasury, FBI and USCYBERCOM, AA20-239A FASTCash 2.0 (2020-08-26) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a | 2026-11-03 | Confirmed |
| 26 | CISA, FBI and CNMF, AA20-301A North Korean APT Focus: Kimsuky (2020-10-27) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a | 2026-11-03 | Confirmed |
| 27 | Microsoft On the Issues, post on cyberattacks against health care organizations researching COVID-19 (2020-11-13) | https://blogs.microsoft.com/on-the-issues/2020/11/13/health-care-cyberattacks-covid-19-paris-peace-forum/ | 2026-11-03 | Confirmed |
| 28 | FBI, Wanted: Jon Chang Hyok | https://www.fbi.gov/wanted/cyber/jon-chang-hyok | 2026-11-03 | Confirmed |
| 29 | FBI, Wanted: Kim Il | https://www.fbi.gov/wanted/cyber/kim-il | 2026-11-03 | Confirmed |
| 30 | Kaspersky, Lazarus covets COVID-19-related intelligence | https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/ | 2026-11-03 | Confirmed |
| 31 | Google TAG, New campaign targeting security researchers (2021-01-25) | https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/ | 2026-11-03 | Confirmed |
| 32 | FBI, CISA and Treasury, AA21-048A AppleJeus (2021-02-17) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a | 2026-11-03 | Confirmed |
| 33 | H-ISAC cover note for the HHS HC3 briefing "North Korean Cyber Activity" (2021-03-25; contents list only, the HHS deck returned 403) | https://www.aha.org/system/files/media/file/2021/03/h-isac-tlp-white-hc3-threat-intelligence-briefing-north-korean-cyber-activity-march-25-2021.pdf | 2026-11-03 | Confirmed |
| 34 | FBI, Statement on attribution of malicious cyber activity posed by the DPRK (Ronin, 2022-04-14) | https://www.fbi.gov/news/press-releases/fbi-statement-on-attribution-of-malicious-cyber-activity-posed-by-the-democratic-peoples-republic-of-korea | 2026-11-03 | Confirmed |
| 35 | FBI, CISA and Treasury, AA22-108A TraderTraitor (2022-04-18) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a | 2026-11-03 | Confirmed |
| 36 | US Treasury, jy0768: Blender.io designated (2022-05-06) | https://home.treasury.gov/news/press-releases/jy0768 | 2026-11-03 | Confirmed |
| 37 | State, Treasury and FBI, Guidance on the DPRK Information Technology Workers (2022-05-16) | https://ofac.treasury.gov/media/923126/download | 2026-11-03 | Confirmed |
| 38 | FBI, CISA and Treasury, AA22-187A Maui Ransomware against the HPH Sector (2022-07-06) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-187a | 2026-11-03 | Confirmed |
| 39 | Microsoft Security, DEV-0530 H0lyGh0st ransomware (2022-07-14) | https://www.microsoft.com/en-us/security/blog/2022/07/14/north-korean-threat-actor-targets-small-and-midsize-businesses-with-h0lygh0st-ransomware/ | 2026-11-03 | Confirmed |
| 40 | FBI, Lazarus Group responsible for Harmony's Horizon bridge theft (2023-01-23) | https://www.fbi.gov/news/press-releases/fbi-confirms-lazarus-group-cyber-actors-responsible-for-harmonys-horizon-bridge-currency-theft | 2026-11-03 | Confirmed |
| 41 | NSA, FBI, CISA, HHS, ROK NIS and ROK DSA, AA23-040A Ransomware Attacks on Critical Infrastructure Fund DPRK (2023-02-09) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-040a | 2026-11-03 | Confirmed |
| 42 | Mandiant (Google Cloud), APT43 (2023-03-28) | https://cloud.google.com/blog/topics/threat-intelligence/apt43-north-korea-cybercrime-espionage | 2026-11-03 | Confirmed |
| 43 | Mandiant (Google Cloud), 3CX software supply chain compromise (2023-04-20) | https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise | 2026-11-03 | Confirmed |
| 44 | FBI, State, NSA, ROK NIS, NPA and MOFA, CSA-20230601-1 Kimsuky social engineering (2023-06-01) | https://www.ic3.gov/CSA/2023/230601.pdf | 2026-11-03 | Confirmed |
| 45 | FBI, FBI identifies cryptocurrency funds stolen by DPRK (2023-08-22) | https://www.fbi.gov/news/press-releases/fbi-identifies-cryptocurrency-funds-stolen-by-dprk | 2026-11-03 | Confirmed |
| 46 | Cisco Talos, Lazarus QuiteRAT (2023-08-24) | https://blog.talosintelligence.com/lazarus-quiterat/ | 2026-11-03 | Confirmed |
| 47 | Industrial Cyber, coverage of the HC3 threat brief on North Korean and Chinese threats to HPH (September 2023; the HHS PDF returned 403) | https://industrialcyber.co/news/hc3-threat-brief-highlights-north-korean-chinese-cyber-threats-targeting-healthcare-and-public-health-sector/ | 2026-11-03 | Reported |
| 48 | US and ROK via FBI IC3, PSA231018 additional guidance on DPRK IT workers (2023-10-18) | https://www.ic3.gov/PSA/2023/PSA231018 | 2026-11-03 | Confirmed |
| 49 | Microsoft Security, North Korean actors exploiting TeamCity CVE-2023-42793 (2023-10-18) | https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/ | 2026-11-03 | Confirmed |
| 50 | Palo Alto Networks Unit 42, two campaigns target job hunters (2023-11-21) | https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/ | 2026-11-03 | Confirmed |
| 51 | UK NCSC, UK and Republic of Korea warn of DPRK supply chain attacks (2023-11-23; news page) | https://www.ncsc.gov.uk/news/uk-republic-of-korea-issue-warning-dprk-state-linked-cyber-actors-attacking-software-supply-chains | 2026-11-03 | Confirmed |
| 52 | US Treasury, jy1938: Kimsuky designated (2023-11-30) | https://home.treasury.gov/news/press-releases/jy1938 | 2026-11-03 | Confirmed |
| 53 | FBI, State and NSA, JCSA-20240502-001 Kimsuky and weak DMARC (2024-05-02) | https://www.ic3.gov/CSA/2024/240502.pdf | 2026-11-03 | Confirmed |
| 54 | FBI IC3, PSA240516 DPRK use of US-based facilitators (2024-05-16) | https://www.ic3.gov/PSA/2024/PSA240516 | 2026-11-03 | Confirmed |
| 55 | Microsoft Security, Moonstone Sleet (2024-05-28) | https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/ | 2026-11-03 | Confirmed |
| 56 | FBI, Wanted: Rim Jong Hyok | https://www.fbi.gov/wanted/cyber/rim-jong-hyok | 2026-11-03 | Confirmed |
| 57 | US v. Rim Jong Hyok, indictment, D. Kan. 2:24-cr-20061 (filed 2024-07-24) | https://www.justice.gov/d9/2024-07/hyok_filed_indictment.pdf | 2026-11-03 | Confirmed |
| 58 | DOJ, North Korean government hacker charged for ransomware attacks targeting US hospitals (2024-07-25) | https://www.justice.gov/opa/pr/north-korean-government-hacker-charged-involvement-ransomware-attacks-targeting-us-hospitals | Not opened (bot check) | Reported |
| 59 | Rewards for Justice, Rim Jong Hyok | https://rewardsforjustice.net/rewards/rim-jong-hyok/ | 2026-11-03 | Confirmed |
| 60 | FBI, CNMF, CISA, DC3, NSA, ROK NIS, ROK NPA and UK NCSC, AA24-207A North Korea Cyber Group Conducts Global Espionage Campaign (2024-07-25) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a | 2026-11-03 | Confirmed |
| 61 | Mandiant (Google Cloud), APT45: North Korea's digital military machine (2024-07-25) | https://cloud.google.com/blog/topics/threat-intelligence/apt45-north-korea-digital-military-machine | 2026-11-03 | Confirmed |
| 62 | FBI IC3, PSA240903 social engineering against the crypto industry (2024-09-03) | https://www.ic3.gov/PSA/2024/PSA240903 | 2026-11-03 | Confirmed |
| 63 | Symantec Threat Hunter Team, Stonefly extortion attacks on US organizations (activity August 2024) | https://www.security.com/threat-intelligence/stonefly-north-korea-extortion | 2026-11-03 | Confirmed |
| 64 | FBI, DC3 and NPA, TraderTraitor responsible for the $308 million DMM Bitcoin theft (2024-12-23) | https://www.fbi.gov/news/press-releases/fbi-dc3-and-npa-identification-of-north-korean-cyber-actors-tracked-as-tradertraitor-responsible-for-theft-of-308-million-from-bitcoindmmcom | 2026-11-03 | Confirmed |
| 65 | Japan National Police Agency, DMM Bitcoin notice (2024-12-24, Japanese, with an English provisional translation link) | https://www.npa.go.jp/bureau/cyber/koho/caution/caution20241224.html | 2026-11-03 | Confirmed |
| 66 | FBI IC3, PSA250123 North Korean IT workers conducting data extortion (2025-01-23) | https://www.ic3.gov/PSA/2025/PSA250123 | 2026-11-03 | Confirmed |
| 67 | ESET, DeceptiveDevelopment targets freelance developers (2025-02-20) | https://www.welivesecurity.com/en/eset-research/deceptivedevelopment-targets-freelance-developers/ | 2026-11-03 | Confirmed |
| 68 | FBI IC3, PSA250226 North Korea responsible for the $1.5 billion Bybit theft (2025-02-26) | https://www.ic3.gov/PSA/2025/PSA250226 | 2026-11-03 | Confirmed |
| 69 | DOJ, coordinated nationwide actions against North Korean remote IT worker schemes (2025-06-30) | https://www.justice.gov/opa/pr/justice-department-announces-coordinated-nationwide-actions-combat-north-korean-remote | 2026-11-03 | Confirmed |
| 70 | Microsoft Security, Jasper Sleet: North Korean remote IT workers (2025-06-30) | https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/ | 2026-11-03 | Confirmed |
| 71 | US Treasury, sb0190: Song Kum Hyok and a Russia-based IT worker network designated (2025-07-08) | https://home.treasury.gov/news/press-releases/sb0190 | 2026-11-03 | Confirmed |
| 72 | FBI IC3, PSA250723-4 IT worker threat update (2025-07-23) | https://www.ic3.gov/PSA/2025/PSA250723-4 | 2026-11-03 | Confirmed |
| 73 | Multilateral Sanctions Monitoring Team, MSMT/2025/2 report on DPRK cyber and IT worker activities (2025-10-22) | https://msmt.info/api/file/download/18919 | 2026-11-03 | Confirmed |
| 74 | New Zealand MFAT, joint statement of the MSMT member states on the cyber and IT worker report (2025-10-22) | https://www.mfat.govt.nz/en/media-and-resources/joint-statement-of-the-multilateral-sanctions-monitoring-team-msmt-on-the-report-covering-dprk-cyber-and-it-worker-activities | 2026-11-03 | Confirmed |
| 75 | Symantec and Carbon Black, Lazarus actors using Medusa ransomware (2026-02-24) | https://www.security.com/threat-intelligence/lazarus-medusa-ransomware | 2026-11-03 | Confirmed |
| 76 | The Record, article on Lazarus espionage in South Korea and links to the Gunra ransomware group (2026-07-30) | https://therecord.media/north-korea-hackers-ransomware | 2026-11-03 | Reported |
| 77 | MSMT, site listing of reports (MSMT/2026/1 posted 2026-09-16; S/2026/745 posted 2026-10-08; titles only) | https://msmt.info/ | 2026-11-03 | Confirmed |
| 78 | DOJ, coordinated actions against North Korean remote IT worker schemes, Operation Lonestar Roundup (2026-10-13) | https://www.justice.gov/opa/pr/justice-department-announces-coordinated-actions-combat-north-korean-remote-it-worker | 2026-11-03 | Confirmed |
| 79 | FBI IC3, PSA I-101326-PSA North Korean IT workers and US facilitators (2026-10-13) | https://www.ic3.gov/PSA/2026/PSA261013 | 2026-11-03 | Confirmed |
| 80 | FBI, North Korea responsible for $6 billion Binance attack (2026-10-31) | https://www.fbi.gov/investigate/cyber/alerts/2026/north-korea-responsible-for-6-billion-binance-attack | 2026-11-03 | Confirmed |
| 81 | The Korea Times (Yonhap), FBI says North Korea responsible for over $6 billion crypto theft from Binance (2026-11-01) | https://www.koreatimes.co.kr/foreignaffairs/northkorea/20261101/fbi-says-n-korea-responsible-for-over-6-bil-crypto-theft-from-binance | 2026-11-03 | Reported |
| 82 | CoinDesk, North Korea denies role in Binance hack (2026-11-03) | https://www.coindesk.com/business/2026/11/03/north-korea-denies-role-in-usd6-4-billion-binance-hack-after-fbi-points-to-tradertraitor | 2026-11-03 | Reported |
| 83 | CISA, Known Exploited Vulnerabilities catalog, JSON feed (catalog version 2026.11.03, 1,767 entries) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors](/THREAT_ACTORS.md) (its North Korea sections), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md) (the 2014 Sony Pictures, Bangladesh Bank and 2017 WannaCry entries), [CVE Reference](/CVE_REFERENCE.md)
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Insider Threat Reference](/INSIDER_THREAT_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Blockchain Security Reference](/BLOCKCHAIN_SECURITY_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Generated MITRE pages: groups [Lazarus Group `G0032`](/mitre/groups/G0032.md), [APT37 `G0067`](/mitre/groups/G0067.md), [APT38 `G0082`](/mitre/groups/G0082.md), [Kimsuky `G0094`](/mitre/groups/G0094.md), [Andariel `G0138`](/mitre/groups/G0138.md), [Moonstone Sleet `G1036`](/mitre/groups/G1036.md), [AppleJeus `G1049`](/mitre/groups/G1049.md) and [Contagious Interview `G1052`](/mitre/groups/G1052.md); campaigns [`C0022` Operation Dream Job](/mitre/campaigns/C0022.md), [`C0057` 3CX Supply Chain Attack](/mitre/campaigns/C0057.md) and [`C0013` Operation Sharpshooter](/mitre/campaigns/C0013.md); software [WannaCry `S0366`](/mitre/software/S0366.md), [AppleJeus `S0584`](/mitre/software/S0584.md), [FALLCHILL `S0181`](/mitre/software/S0181.md), [BLINDINGCAN `S0520`](/mitre/software/S0520.md), [MagicRAT `S1182`](/mitre/software/S1182.md), [Dtrack `S0567`](/mitre/software/S0567.md), [BeaverTail `S1246`](/mitre/software/S1246.md) and [KONNI `S0356`](/mitre/software/S0356.md); techniques [Malicious File `T1204.002`](/mitre/techniques/T1204-002.md), [Spearphishing Attachment `T1566.001`](/mitre/techniques/T1566-001.md), [Exploit Public-Facing Application `T1190`](/mitre/techniques/T1190.md), [Data Encrypted for Impact `T1486`](/mitre/techniques/T1486.md), [Financial Theft `T1657`](/mitre/techniques/T1657.md) and [Valid Accounts `T1078`](/mitre/techniques/T1078.md)
- Related case studies: [All case studies](/case-studies/README.md); [China-Attributed Threat Actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Iran-Attributed Threat Actors](/case-studies/THREAT_ACTORS_IRAN.md), [Other State-Linked Threat Actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md), [United States-Attributed Threat Actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [Log4Shell](/case-studies/LOG4SHELL.md), [APT41: The Public Record](/case-studies/APT41_PUBLIC_RECORD.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md), [npm Supply-Chain Attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [AI Threats 2026](/case-studies/AI_THREATS_2026.md), [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions](/case-studies/CHRONICLE_2021.md)
- [Navigator layers](/navigator/index.md)
