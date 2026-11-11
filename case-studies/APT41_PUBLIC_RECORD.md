# APT41: The Public Record, 2012 to 2026

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [APT41 group page](/mitre/groups/G0096.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, threat hunters and defenders tracking China-nexus intrusion sets

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 65 min (15,052 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a sourced account of APT41's aliases, operations and tooling from 2012 to 2026, you are checking your exposure to the vulnerabilities it exploited, or you want the defender view and the MITRE mappings in one place

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 4: exploited vulnerabilities](#part-4-exploited-vulnerabilities), [Part 7: the defender view](#part-7-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The intrusion set most researchers now call APT41 has a public record that runs through games, software, telecoms, healthcare, government and diplomacy. Game studios found their source code and code-signing certificates gone in the early 2010s. Software vendors found their own update channels shipping backdoors to customers in 2017 and 2018. A telecom operator found a tool on its SMS servers that read text messages for chosen phone numbers. A medical provider, universities, US state agencies, shipping companies and, by 2026, diplomatic agencies in Central Asia all appear in incident reports that end with the same name, or with one of the dozen other names vendors give the same activity. This study gathers that public record in one place, dates every event, and grades every claim by the source that supports it.

The record supports four plain statements. First, the people behind this activity have been working since at least 2012, and three US indictments in 2019 and 2020 charged five men in China and two Malaysian businessmen over intrusions alleged to run from about 2011 into 2020 (**Confirmed**, court records). Second, the group mixes state-aligned espionage with crime for profit: FireEye assessed with high confidence that it runs Chinese state-sponsored espionage alongside financially motivated activity potentially outside state control, and the indictments describe game-currency fraud, crypto-jacking and ransomware next to espionage against telecoms, universities and dissidents (**Confirmed**). Third, its tradecraft is consistent across fourteen years: software supply-chain compromise, stolen code-signing certificates, very fast exploitation of internet-facing applications, and, from 2022 on, command and control hidden in mainstream cloud services such as Google Sheets, Google Calendar, Google Drive and Microsoft OneDrive (each element **Confirmed** in vendor primaries at the confidence each vendor states; the consistency across fourteen years is **Inferred**). Fourth, the name is not one thing. Microsoft, Symantec, Trend Micro, Google, Secureworks, CrowdStrike, ESET and MITRE ATT&CK each draw the boundary in a different place, so a defender reading two reports about "APT41" may be reading about two different clusters (**Confirmed** for each vendor's mapping; the conclusion is **Inferred**).

What this means for a security program is practical. Internet-facing applications are the dominant way in, and exploitation starts within hours of a disclosure (Log4Shell, December 2021) or months before one (the USAHerds zero-day, first exploited in July 2021 and added to CISA's Known Exploited Vulnerabilities catalog only in December 2024). Egress controls that trust Google, Microsoft and Cloudflare traffic by default miss this group's command channels. A valid code-signing certificate on a binary is not evidence that the binary is safe. And firmware is in scope: the record includes a master boot record bootkit, a UEFI firmware implant and, in 2026, a UEFI bootkit.

Evidence grade: the court record, the ATT&CK record and the vendor reports are each **Confirmed** against a primary source opened on 3 November 2026. Attribution statements inside vendor reports are reported at the confidence each vendor states, which ranges from "high" to "likely". Press coverage of the 2020 arrests, the COVID relief fraud and the Taiwan cases is **Reported**.

### Key facts at a glance

| Field | Value |
|---|---|
| Common name | APT41 (FireEye, now Mandiant, 2019); renamed SPIRE CASTLE in Google Threat Intelligence Group's 2026 naming scheme |
| ATT&CK object | [`G0096`](/mitre/groups/G0096.md), version 4.2, last modified 31 July 2026; associated groups Wicked Panda, Brass Typhoon and BARIUM |
| Other vendor names | Brass Typhoon (formerly BARIUM, Microsoft), WICKED PANDA (CrowdStrike), Earth Baku (Trend Micro), HOODOO (Google), Grayfly and Blackfly (Symantec), BRONZE ATLAS (Secureworks), RedGolf (Recorded Future) |
| Assessed sponsor | Chinese state-sponsored espionage that also runs financially motivated operations (FireEye, high confidence; ATT&CK, "assessed") |
| Active since | At least 2012 (FireEye, ATT&CK); Secureworks' wider BRONZE ATLAS cluster since at least 2007 |
| ATT&CK v20.0 record | 102 technique and sub-technique IDs on the group page (82 direct, 20 through campaigns), 33 software objects, 2 attributed campaigns ([`C0017`](/mitre/campaigns/C0017.md), [`C0040`](/mitre/campaigns/C0040.md)) |
| Court record | Indictments of 2019-08-15 (Zhang Haoran, Tan Dailin), 2020-08-11 (Jiang Lizhi, Qian Chuan, Fu Qiang of Chengdu 404 Network Technology) and 2020-08-18 (Wong Ong Hua, Ling Yang Ching of SEA Gamer Mall), all in the District of Columbia |
| Signature tradecraft | Software supply-chain compromise; stolen code-signing certificates; rapid exploitation of internet-facing applications; cloud-service command and control; bootkits and firmware implants |
| Exploited CVEs now in KEV | CVE-2019-19781, CVE-2019-11510, CVE-2019-16920, CVE-2019-16278, CVE-2019-1652, CVE-2019-1653, CVE-2019-3396, CVE-2020-10189, CVE-2021-26855, CVE-2021-44207, CVE-2021-44228, plus four older Office and ActiveX CVEs |
| Latest public activity | BlackX UEFI bootkit against diplomatic agencies in Tajikistan, Uzbekistan and Turkmenistan, found early 2026 (Kaspersky, medium confidence, published 2026-10-22) |

### Key findings

- **The court record is the firmest ground.** Three District of Columbia indictments allege a hacking conspiracy against high-technology organizations from about May 2011, a video game conspiracy from no later than November 2014, and a racketeering conspiracy at Chengdu 404 Network Technology from about May 2014 to about August 2020 affecting over 100 victims (**Confirmed** [60] [61] [62]). The 2020 indictment states that cybersecurity professionals have in some instances tracked the activity as APT41, Barium, Winnti, Wicked Panda and Wicked Spider (**Confirmed** [61]).
- **Espionage and profit run side by side.** The 2019 FireEye report found that the two motivations were balanced concurrently from 2014 onward, and recorded one intrusion where the group tried to steal data from a healthcare target while trying to deploy ransomware at a video game studio (**Confirmed** [18]). The indictments add game-currency fraud, crypto-jacking and ransomware against a non-profit, a real estate developer and a Taiwanese energy company (**Confirmed**, allegations [61] [62]).
- **Supply chains are a repeated entry point.** FireEye rates the July 2017 NetSarang compromise (ShadowPad) and a July 2018 game-distributor compromise as confirmed APT41 operations, and leaves CCleaner (March 2017) and the first stage of ASUS Live Update (June to November 2018) unconfirmed (**Confirmed** [18]).
- **Exploitation is fast.** APT41 used proof-of-concept code for Confluence CVE-2019-3396 within 23 days of disclosure, exploited Log4Shell within hours of the 10 December 2021 advisory, and used the USAHerds zero-day CVE-2021-44207 from July 2021 (**Confirmed** [18] [21]).
- **Cloud services carry the command channel.** GC2, used by Google's HOODOO, took commands from Google Sheets (2022), TOUGHPROGRESS from Google Calendar (2024), DUSTTRAP-era data left through OneDrive (2023 to 2024), and Google Drive carried MoonWalk (Zscaler: APT41/Earth Baku, moderate confidence) and GearDoor (Check Point: Silver Dragon, likely within the APT41 umbrella) (**Confirmed** [25] [23] [22] [56] [53]). Google disrupted the Calendar and Workspace infrastructure itself (**Confirmed** [23]).
- **The name covers different clusters at different vendors.** Microsoft maps Brass Typhoon to APT41 but lists Leopard Typhoon (LEAD, Winnti Group) separately; Symantec calls Grayfly the espionage arm of APT41 and tracks Blackfly as its cybercrime arm; ATT&CK lists Blackfly under Winnti Group ([`G0044`](/mitre/groups/G0044.md)), which it keeps separate from APT41 while recording a partial overlap (**Confirmed** [16] [43] [7] [1]).
- **The ATT&CK record is broad but has gaps a defender should know.** ATT&CK maps no Mobile or ICS technique to APT41 although it attributes the mobile spyware LightSpy to the group, and the library's D3FEND data has no countermeasure edge for code signing (`T1553.002`), code-signing certificates (`T1588.003`), domain generation algorithms (`T1568.002`) or dead drop resolvers (`T1102.001`), all of which APT41 uses (**Confirmed** [1] [77]).

### Top recommendations

1. Patch internet-facing applications on an exploitation clock, not a scoring clock. APT41 and the clusters vendors equate with it have exploited Citrix, Pulse Secure (2020 indictment, an allegation), Cisco, Zoho, Confluence, Exchange (Trend Micro's Earth Baku), Log4j and USAHerds, a niche application in use at US state governments. Treat any internet-facing flaw with a public proof of concept as days-to-exploit, and do not wait for a KEV listing: the USAHerds flaw was exploited for about three and a half years before CISA added it (**Inferred** from [21] [75]).
2. Inspect, do not trust, traffic to major cloud services. Baseline which hosts talk to Google Calendar, Sheets and Drive, OneDrive, Cloudflare Workers and TryCloudflare, and alert on servers and service accounts that start. Pair this with the library's [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) countermeasures.
3. Treat code signing as a claim to verify. FireEye's 2019 report records APT41 abusing at least 19 code-signing certificates, most from video game companies, and the 2024 DUST report still finds presumably stolen ones (**Confirmed** [18] [22]). Track which publishers you allow and revoke trust in certificates reported as abused. The library's D3FEND data has no countermeasure for code signing itself (Part 7); [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) covers the TLS certificates on its web C2.
4. Hunt for the published artifacts. The vendor reports give concrete leads: `java.exe` spawning `cmd.exe` or `bitsadmin.exe`, `certutil` downloads, `schtasks /change` on existing SYSTEM tasks, SAM and SYSTEM hive copies, `ping` to unusual subdomains carrying encoded data, and Tomcat Manager web shells. Part 7 lists them with their sources.
5. Put firmware and boot integrity in scope for high-value hosts. The record includes ROCKBOOT (MBR bootkit), MoonBounce (UEFI firmware) and BlackX (UEFI bootkit abusing CVE-2022-21894). Use [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md) and [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md) where the platform supports them.
6. Read vendor names before merging reports. When two reports say APT41, check which cluster each vendor means before you combine their indicators or technique lists.

## Scope and method

This study covers activity publicly attributed to APT41, or to a vendor cluster that a primary source equates with APT41, from the earliest public reporting (Kaspersky, April 2013, on activity going back to 2007 and game intrusions from about 2010) through the Kaspersky BlackX report of 22 October 2026. It draws on five kinds of source: court records and government advisories; vendor threat reports; the MITRE ATT&CK pages for the group, its campaigns and software; the CISA Known Exploited Vulnerabilities (KEV) catalog and NIST's National Vulnerability Database (NVD); and the TeamStarWolf library's own data files. Every source in the Sources table at the end was opened on 3 November 2026.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the court, agency, vendor, or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution, at the confidence it states; it does not upgrade the source's own confidence |
| Reported | Only a secondary source (press coverage) was available |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

This study grades by source type (primary opened versus secondary only); the other studies in this folder grade by corroboration, under which single-vendor reports would read as Reported.

Three rules govern the names. The study says which name each source uses ("Trend Micro's Earth Baku", "Symantec's Grayfly", "ESET's Winnti Group") instead of merging labels. A vendor's own hedge travels with its claim ("likely", "medium confidence"). And ATT&CK campaign [`C0012`](/mitre/campaigns/C0012.md), Operation CuckooBees, is described but not counted as APT41 activity, because ATT&CK attributes it to no group (**Confirmed** [4]).

Some sources that ATT&CK cites for APT41 did not load on 3 November 2026 and are not cited here as opened: the old fireeye.com and mandiant.com report links (on 3 November 2026 they redirected to a Mandiant landing page; the cloud.google.com copies are cited instead), the Cybereason Operation CuckooBees post (it redirected to a generic blog index), the DOJ press release of 16 September 2020, the DCSO CyTec post, the BlackBerry LightSpy post and the Mandiant UNC3886 report. Where the technique tables below rely on one of these through ATT&CK, the row says so.

## Part 1: identity and aliases

### What ATT&CK records

In ATT&CK v20.0 (released 13 October 2026 [78]), APT41 is group [`G0096`](/mitre/groups/G0096.md), created 23 September 2019 and last modified 31 July 2026. ATT&CK describes it as a group researchers have assessed as a Chinese state-sponsored espionage group that also conducts financially motivated operations, active since at least 2012, against healthcare, telecom, technology, finance, education, retail and video game targets in 14 countries (**Confirmed** [1]). It lists exactly three associated groups: Wicked Panda, Brass Typhoon and BARIUM (**Confirmed** [1]). ATT&CK defines associated groups as best-effort overlaps drawn from public reporting and does not present them as exact overlaps (**Confirmed** [5]).

The description also says APT41 overlaps at least partially with BARIUM and Winnti Group ([`G0044`](/mitre/groups/G0044.md)). Winnti Group is a separate ATT&CK object whose own associated group is Blackfly (**Confirmed** [1] [7]). So "Winnti" is not an ATT&CK associated group of APT41, but ATT&CK does record an overlap; neither point should be read as ATT&CK accepting or rejecting a link. Double Dragon appears on the G0096 page only as the title of the 2019 report, and Earth Baku, HOODOO, Grayfly, BRONZE ATLAS and RedGolf do not appear at all (**Confirmed** [1]).

ATT&CK keeps neighboring Chinese clusters as distinct objects and records overlaps in prose. Axiom ([`G0001`](/mitre/groups/G0001.md)) may overlap Winnti Group but appears distinct on tactics and targeting. Earth Lusca ([`G1006`](/mitre/groups/G1006.md)) uses malware common to APT41 and the Winnti cluster, but researchers assess its techniques and infrastructure as separate. RedEcho ([`G1042`](/mitre/groups/G1042.md)) overlaps APT41 and is tied to ShadowPad through shared infrastructure (**Confirmed** [9] [8] [10]).

### What the vendors call it

| Name | Vendor | What the vendor's own page says | Grade | Source |
|---|---|---|---|---|
| APT41 | FireEye, now Mandiant | Chinese state-sponsored espionage plus financially motivated activity potentially outside state control, assessed with high confidence; activity traced to 2012 | Confirmed | [18] |
| SPIRE CASTLE | Google Threat Intelligence Group | New name for APT41 under the scheme published 24 July 2026 (table added 30 July), in which CASTLE marks People's Republic of China actors | Confirmed | [27] |
| HOODOO | Google | APT41 is "also tracked as HOODOO" | Confirmed | [23] |
| Brass Typhoon (formerly BARIUM) | Microsoft | Mapped to WICKED PANDA and APT41. Leopard Typhoon (LEAD) is a separate row, listed with WICKED PANDA, TG-2633 and Winnti Group among its other names | Confirmed | [16] |
| WICKED PANDA | CrowdStrike | A China-based, state-sponsored adversary that moved from criminal operations to state-sponsored intrusions; community identifiers include APT41, Winnti, BARIUM and LEAD | Confirmed | [47] |
| Earth Baku | Trend Micro | A group that carries out attacks under the alias APT41 | Confirmed | [39] |
| Earth Longzhi, Earth Freybug | Trend Micro | A subgroup and a subset of APT41 | Confirmed | [40] [41] |
| Grayfly, Blackfly | Symantec | Grayfly (also GREF, Wicked Panda) is the espionage arm of APT41; Blackfly, the cybercrime arm, is tracked separately. Symantec's 2023 Blackfly report lists the aliases APT41, Winnti Group and Bronze Atlas | Confirmed | [43] [45] |
| BRONZE ATLAS | Secureworks (now part of Sophos) | Aliases include APT41, Axiom, BARIUM, Blackfly, Brass Typhoon, CTG-2633, Earth Baku, GREF, Group 72, Red Kelpie, TA415, TG-2633, Wicked Panda and Winnti, each credited to its vendor; operating since at least 2007 | Confirmed (archived profile, 18 November 2025) | [46] |
| RedGolf | Recorded Future | Closely overlaps activity reported as APT41/BARIUM; its KEYPLUG infrastructure, tracked as GhostWolf, was used from at least 2021 to 2023 | Confirmed | [48] |
| Group-IB alias list | Group-IB | BARIUM, Winnti, LEAD, Wicked Spider, Wicked Panda, Blackfly, Suckfly, Winnti Umbrella and Double Dragon | Confirmed | [49] |
| Winnti Group | ESET (following Kaspersky's 2013 naming) | "Winnti Group" for the people and "Winnti" for the malware family; the three ESET Winnti Group posts cited here do not mention APT41; ESET's SideWalk post names APT41 only as FireEye's attribution of CROSSWALK [37] | Confirmed | [36] [34] [35] [37] |

### How the boundaries differ

Laid side by side, the mappings disagree in specific ways (**Inferred** from the rows above). Microsoft splits BARIUM from LEAD and puts WICKED PANDA under both. Symantec splits one APT41 into an espionage arm and a crime arm. Secureworks lists Axiom, Blackfly and Winnti among BRONZE ATLAS's aliases, crediting each to its vendor. ATT&CK keeps APT41, Winnti Group and Axiom as three objects and records the overlap in prose. ESET keeps Winnti Group, SparklingGoblin and FishMonger as clusters of their own, and its Operation FishMedley post places FishMonger under the Winnti Group umbrella and revises its 2020 Hong Kong attribution from Winnti Group to FishMonger (**Confirmed** [38]). Symantec's Spyder Loader post and Kaspersky's ShadowHammer post make no APT41 attribution at all (**Confirmed** [44] [32]).

The safe reading for a defender: the security community uses these names for activity that overlaps with APT41, and only some of it is the same activity. When this study cites a report, it names the cluster that report uses.

## Part 2: the operational record

The table lists every dated campaign, report and legal action the verified record supports, in order of the event date, or of the publication date where the source gives no event date. "Named actor" is the name the source itself uses. Court records state allegations, and their dates are "on or about" dates.

| Event date | Published | What happened | Named actor in the source | Grade | Source |
|---|---|---|---|---|---|
| At least 2007 | Undated profile | Secureworks dates its BRONZE ATLAS cluster to at least 2007 | BRONZE ATLAS | Confirmed | [46] |
| 2007 or earlier; game intrusions from about 2010 | 2013-04-11 | Kaspersky reports at least 35 infected online-game companies with a strong Southeast Asia focus, theft of game source code and code-signing certificates, the Winnti backdoor, a signed 64-bit rootkit and PlugX; attributes the work to a criminal group with Chinese origins, noting a Korean-language path | Winnti (criminal group) | Confirmed | [28] |
| 2011-05 to at least 2018-11 | 2019-08-15 | Computer hacking conspiracy against high-technology organizations; HOP POINT ONE leased from 2011-05-12 to 2016-11-09 for command and control | Zhang Haoran, Tan Dailin (indictment) | Confirmed (allegation) | [60] |
| 2012 | 2019-08-07 | FireEye traces APT41 activity to 2012, when members targeted the video game industry for financial gain | APT41 | Confirmed | [18] |
| 2013-12-04 | 2019-08-15 | Spear-phishing email to employees of Victim A, a video game company | Zhang, Tan (indictment) | Confirmed (allegation) | [60] |
| 2014 onward | 2019-08-07 | Espionage and financially motivated work balanced concurrently | APT41 | Confirmed | [18] |
| 2014-05 to 2020-08 | 2020-08-11 | Racketeering conspiracy run through Chengdu 404 Network Technology, over 100 victims | Jiang Lizhi, Qian Chuan, Fu Qiang (indictment) | Confirmed (allegation) | [61] |
| 2014-06 to 2018-12 | 2020-08-18 | SEA Gamer Mall founder and product chief allegedly pay Tan and Zhang to hack game companies and sell the stolen digital goods through seagm.com | Wong Ong Hua, Ling Yang Ching (indictment) | Confirmed (allegation) | [62] |
| No later than 2014-11 to at least 2018-11 | 2019-08-15 | Video game conspiracy; malware installed at Victim B on 2014-11-26 | Zhang, Tan (indictment) | Confirmed (allegation) | [60] |
| 2014-12 | 2019-08-07 | Online games from a Southeast Asian distributor trojanized with SOGU; FireEye rates it possibly APT41 or a close affiliate | APT41 (possible) | Confirmed | [18] |
| 2015-03 to at least 2020-01 | 2020-08-11 | Intrusion at ECS #11, an encrypted messaging provider; over 4,000,000 queries for accounts tied to phone numbers | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2015-06 to 2017-02 | 2020-08-11 | ECS #1 compromised; source code and code-signing certificates viewed; customer credentials taken | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| Late 2015 | 2019-08-07 | FireEye observes no intellectual property theft by APT41 after this point | APT41 | Confirmed | [18] |
| 2016-10-17 | 2019-08-15 | Spear-phishing of Victim A in New York with malware set to use a command-and-control dead drop | Zhang, Tan (indictment) | Confirmed (allegation) | [60] |
| Probably since 2016 (brief dated 2019-12-06) | 2019-12-06 | Germany's BfV warns industry of "WinNTI" attacks using WinNTI version 3 malware; the brief does not name APT41 | WinNTI | Confirmed | [73] |
| 2017-01-12 | 2020-08-11 | An ECS #1 customer account is used against MANUFACTURER #2 (Winnti/Pasteboy, Barlaiy/PoisonPlug); damages over $1,000,000 | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2017-03 | 2019-08-07 | CCleaner compromise; FireEye finds overlaps (TeamViewer entry, DGA, dead drop resolvers, COLDJAVA) but too little to attribute | Unconfirmed APT41 | Confirmed | [18] |
| 2017-07 | 2017-08-15; 2019-08-07 | NetSarang's `nssock2.dll` backdoored (compiled 2017-07-13) in five packages dated 2017-07-17, signed with NetSarang's certificate, activated at a Hong Kong company. Kaspersky names no actor; FireEye rates it confirmed APT41; ATT&CK says ShadowPad was first identified here | Kaspersky: none; FireEye: APT41 | Confirmed | [29] [18] [11] |
| 2017-10-31 | 2017-10-31 | Microsoft's Digital Crimes Unit first publishes notice of civil action 1:17-cv-1224 (E.D. Va.), titled Barium, against John Doe defendants associated with internet domains; hearings 2017-11-17 and 2018-09-28 | Barium | Confirmed | [59] |
| 2017-12-06 | 2020-08-11 | Crypto-jacking: Jiang allegedly says mining has started on a Singapore domain of over 7000 machines | Jiang (indictment) | Confirmed (allegation) | [61] |
| 2018-05-03 | 2020-08-11 | ECS #1 account used against MEDICAL PROVIDER #3 to install Crosswalk/ProxIP | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2018-06; 2018-10 | 2019-08-07 | Spear-phishing with a decentralized gaming platform lure; an XMRig Monero miner compiled | APT41 | Confirmed | [18] |
| 2018-06 to 2018-11 | 2019-08-07 | ASUS Live Update compromise (ShadowHammer): stage 1 unconfirmed APT41, reported stage 2 confirmed APT41. Kaspersky's ShadowHammer post makes no APT41 attribution | FireEye: split rating | Confirmed | [18] [32] |
| 2018-07 | 2019-08-07 | Southeast Asian game distributor compromise (Infestation, PointBlank; CRACKSHOT) | Confirmed APT41 | Confirmed | [18] |
| 2018-11-12 to 2019-02-21 | 2020-08-11 | SonarX, a Chengdu 404 "Information Risk Assessment System" of harvested social media data, queried for Hong Kong pro-democracy figures, a US government-funded broadcaster covering Uyghurs, and a Tibetan monk | Chengdu 404 (indictment) | Confirmed (allegation) | [61] |
| 2019 (to 2019-03) | 2019-03-11 | ESET reports trojanized builds of two games and one gaming platform in Asia, including Electronics Extreme (Thailand), with a Winnti second stage | Winnti Group (likely) | Confirmed | [33] |
| 2019 | 2019-08-07 | Proof-of-concept code for Confluence CVE-2019-3396 used within 23 days of disclosure | APT41 | Confirmed | [18] |
| 2019-05 | 2020-08-11 | Webshell on a UNIVERSITY #4 computer (2019-05-08); keylogger data from Pakistani telecom ECS #12 | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2019 (first reported to subscribers 2019-08) | 2019-10-31 | MESSAGETAP, a 64-bit Linux ELF on a telecom's SMSC servers, saves SMS traffic for chosen phone numbers, IMSI numbers and keywords; call detail records stolen in the same intrusion | APT41 | Confirmed | [19] |
| 2019-08-07 | 2019-08-07 | FireEye publishes APT41: A Dual Espionage and Cyber Crime Operation | APT41 | Confirmed | [17] [18] |
| 2019-08-15 | 2019-08-15 | D.C. grand jury indicts Zhang Haoran and Tan Dailin (case 19-cr-274) | Indictment | Confirmed | [60] |
| 2019 | 2019-10-21 | ESET attributes the skip-2.0 Microsoft SQL Server backdoor ("magic password") to the Winnti Group on shared tooling | Winnti Group | Confirmed | [34] |
| 2019-10 to 2019-11 | 2020-01-31 | Two Hong Kong universities compromised during the protests (at least three more suspected); Winnti malware found end of October, a ShadowPad launcher in November | Winnti Group | Confirmed | [35] |
| About 2019-10 to 2020-01 | 2020-08-11 | Over 67,000 photos taken from a Taiwan university (about October 2019); Gophish spear-phishing of three Hong Kong universities (2019-11-01); PlugX on four Hong Kong University #7 hosts (January 2020) | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2019-12 | 2020-08-11 | UK government websites targeted with Acunetix | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2019-12 to 2022-05 | Campaign page | Operation CuckooBees ([`C0012`](/mitre/campaigns/C0012.md)): ATT&CK gives it no group; its description says researchers assessed actors affiliated with Winnti Group, APT41 and BARIUM ran it | Unattributed in ATT&CK | Confirmed | [4] |
| 2019 to 2020 | 2020-08-11 | Rapid exploitation of CVE-2019-19781, CVE-2019-11510, CVE-2019-16920, CVE-2019-16278, CVE-2019-1652/1653 and CVE-2020-10189, typically followed by widely available RATs | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| Early 2020 (Speculoos waves 2020-01-31 to 2020-02-24) | 2020-03-25; 2020-04-13 | Global exploitation wave against Citrix, Cisco and Zoho, using only public malware such as Cobalt Strike and Meterpreter; Unit 42 records Speculoos, a FreeBSD backdoor, delivered through CVE-2019-19781 in waves on 2020-01-31/02-01 and 2020-02-24 | APT41 | Confirmed | [20] [51] |
| 2020-02 | 2020-05-21 | ESET finds PipeMon used against MMO game developers in South Korea and Taiwan; the post does not mention APT41 | Winnti Group | Confirmed | [36] |
| 2020-03-08 to 2020-05-04 | 2020-08-11 | Ransomware: CVE-2020-10189 access on 2020-03-08, then DEVELOPER #17 (a US real estate company with a computer in Ohio) encrypted 2020-03-19, NGO #16 (anti-poverty non-profit) 2020-03-23, and ENERGY COMPANY #18 (Taiwan) 2020-05-04, disrupting retail payment systems | Chengdu 404 defendants (indictment) | Confirmed (allegation) | [61] |
| 2020-05-04 to 2020-05-15 | 2020-05-17 | Taiwan's Investigation Bureau says the Winnti Group was behind ransomware at CPC Corp and Formosa Petrochemical, using Active Directory task scheduling and a US$3,000 demand | Winnti Group (MJIB) | Reported | [70] |
| 2020-05 | Page dated 2024-08-19 | Positive Technologies traces samples that first resembled Higaisa to Winnti/APT41 and documents the FunnySwitch backdoor with Crosswalk, ShadowPad and PlugX; targets include Russian game developers and Hong Kong organizations | Winnti (APT41) | Confirmed | [50] |
| 2020-05 to 2021-02; 2021-08 to 2022-06 | 2022-11-09 | Two campaigns with Symatic, CroxLoader, BigpipeLoader, OutLoader and AVBurner (RTCore64.sys, CVE-2019-16098) against Taiwan, China, Thailand, Malaysia, Indonesia, Pakistan and Ukraine | Earth Longzhi, "APT41's subgroup" | Confirmed | [40] |
| 2020-07 to 2021-08 | 2021-08-24 | StealthVector, StealthMutant and ScrambleCross against India, Indonesia, Malaysia, the Philippines, Taiwan and Vietnam; initial access through SQL injection and ProxyLogon CVE-2021-26855 to plant China Chopper | Earth Baku (alias APT41) | Confirmed | [39] |
| 2020-08-11; 2020-08-18 | Same dates | Indictments of Jiang, Qian and Fu (1:20-cr-00158) and of Wong and Ling (1:20-cr-00166) | Indictments | Confirmed | [61] [62] |
| 2020-09 | 2020-09-17 | DOJ announcement, as quoted: Wong and Ling arrested in Sitiawan, Malaysia, on US warrants, facing 23 counts; hundreds of accounts, servers, domains and dead drop pages seized | Press coverage | Reported | [63] |
| 2020-10-01 | 2020-10-01 | CISA AA20-275A names "APT41 (known as Double Dragon)" as exploiting Citrix NetScaler/ADC, Cisco routers and Zoho ManageEngine Desktop Central | APT41 | Confirmed | [66] |
| 2021 | 2022-08-18 | Four campaigns (ColunmTK, DelayLinkTK, Mute-Pond, Gentle-Voice), an estimated 13 victim organizations in 13 countries | APT41 | Confirmed | [49] |
| Spring 2021 | 2022-01-20 | MoonBounce, a UEFI implant in the CORE_DXE firmware component, found alongside ScrambleCross/SideWalk, StealthVector and StealthMutant on other machines in the same network; other ScrambleCross victims using the same C2 included an organization controlling transport-technology enterprises | APT41 or a closely affiliated actor, "medium to high confidence" | Confirmed | [30] |
| 2021-05 to 2022-02 | 2022-03-08 | Campaign [`C0017`](/mitre/campaigns/C0017.md): at least six US state government networks compromised; USAHerds zero-day CVE-2021-44207 first exploited July 2021; Log4Shell exploited within hours of the 2021-12-10 advisory; two state victims re-compromised in late February 2022; Mandiant says the goals remain unknown | APT41 | Confirmed | [21] [2] |
| 2021-07-19 | 2021-07-19 | Joint NSA, CISA and FBI advisory AA21-200B on Chinese state-sponsored tactics cites FireEye's 2020 This Is Not a Test post for T1190 and maps countermeasures to D3FEND; APT41 appears only in that reference title | Chinese state-sponsored actors | Confirmed | [67] [20] |
| 2021 (Grayfly active since at least 2017-03) | 2021-08-24; 2021-09-09 | ESET documents SideWalk (SparklingGoblin), most likely coded by CROSSWALK's developers; Symantec reports Grayfly's Sidewalk against telecoms, IT, media and finance in Taiwan, Vietnam, the US and Mexico | ESET: SparklingGoblin, linked to Winnti Group; Symantec: Grayfly, "the espionage arm of APT41" | Confirmed | [37] [43] |
| 2022-07; 2022-10 | 2023-04 | Google's TAG disrupts HOODOO's use of GC2, which takes commands from Google Sheets and exfiltrates to Drive, against a Taiwanese media organization (October 2022); GC2 used against an Italian job search website (July 2022) | HOODOO (APT41) | Confirmed | [25] |
| 2022-09-22 | 2022-09-22 | HHS HC3 briefing "APT41 and Recent Activity" for the health sector | APT41 | Confirmed | [65] |
| Not dated; dwell of more than a year | 2022-10-18 | Spyder Loader against Hong Kong organizations, a likely continuation of CuckooBees; the post's text names no actor | None named | Confirmed | [44] |
| Not dated | 2022-12-05 | The US Secret Service says APT41 stole at least $20 million in COVID relief benefits (SBA loans and unemployment insurance) in over a dozen states | APT41 | Reported | [69] |
| Late 2022 to early 2023 | 2023-02-28 | Two subsidiaries of an Asian materials and composites conglomerate hit with Backdoor.Winnkit, a credential dumper, Mimikatz, a svchost process-hollowing tool and a screenshot tool | Blackfly (aka APT41, Winnti Group) | Confirmed | [45] |
| Late 2022 onward | 2024-08-09 | Expansion beyond the Indo-Pacific to Italy, Germany, the UAE and Qatar (Georgia and Romania suspected) via IIS servers and Godzilla, with StealthVector, StealthReacher, SneakCross and MEGAcmd | Earth Baku, "associated with APT41" | Confirmed | [42] |
| At least 2021 to 2023 | 2023-03-30 | KEYPLUG infrastructure tracked as GhostWolf | RedGolf (overlaps APT41/BARIUM) | Confirmed | [48] |
| 2017 to 2023-04 | 2023-07-19 | Android surveillanceware WyrmSpy (samples since 2017) and DragonEgg (early 2021 to April 2023), linked through a hard-coded C2 IP to an APT41 domain from the DOJ indictment and a WHOIS registrant tied to an indicted individual | APT41 | Confirmed | [54] |
| 2023-10-02 | 2023-10-02 | ThreatFabric press announcement: LightSpy targets WeChat payment systems and was previously attributed to APT41 | APT41 (previous attribution) | Confirmed | [55] |
| 2023 to mid-2024 | 2024-07-18 | Campaign [`C0040`](/mitre/campaigns/C0040.md), APT41 DUST: prolonged access at shipping and logistics, media and entertainment, technology and automotive organizations, most of them operating in Italy, Spain, Taiwan, Thailand, Turkey and the UK | APT41 | Confirmed | [22] [3] |
| Not dated | 2024-04-02 | UNAPIMON unhooking DLL, SessionEnv DLL side-loading and remote scheduled tasks, with tactics similar to CuckooBees | Earth Freybug, "a subset of APT41" | Confirmed | [41] |
| 2024-04 | 2024-07-10 | DodgeBox loader found; it loads MoonWalk, which uses Google Drive for C2; samples from Thailand and Taiwan | APT41/Earth Baku, moderate confidence | Confirmed | [53] |
| Since at least 2024-08; late 2024-10 | 2025-05-28 | Free hosting used to reach hundreds of targets; an exploited government website serves a customs-themed ZIP whose LNK runs PLUSDROP, PLUSINJECT and TOUGHPROGRESS, with Google Calendar for C2; Google takes down the calendars and Workspace projects | APT41, high confidence | Confirmed | [23] |
| About 2024-10-31 | 2024-10-31 | Sophos Pacific Rim attributes clusters "with varying levels of confidence" to Volt Typhoon, APT31 and APT41/Winnti; no APT41-specific detail | APT41/Winnti | Confirmed | [58] |
| Since 2022 | 2025-01-28 | GTIG says POISONPLUG.SHADOW (often called ShadowPad) appears restricted to APT41-associated clusters, protected by the ScatterBrain obfuscating compiler | APT41-associated clusters | Confirmed | [24] |
| 2025 | Undated advisory | Singapore's IMDA issues an ICM-sector advisory summarizing the GTIG TOUGHPROGRESS report, which it dates 2025-05-29 | APT41 | Confirmed | [72] |
| 2025 | 2026-01-04 (reported 2026-01-05) | Taiwan's National Security Bureau lists APT41 among the top five Chinese groups threatening its critical infrastructure in 2025 | APT41 | Reported | [71] |
| Mid-2024 to 2026-03 | 2026-03-03 | Government entities, mainly in Southeast Asia, with fewer in Europe and a phishing wave focused on Uzbekistan; BamboLoader, MonikerLoader, GearDoor (Google Drive C2), SilverScreen, SSHcmd and Cobalt Strike over DNS tunneling | Silver Dragon, "likely operating within the umbrella of APT41" | Confirmed | [56] |
| 2026-02-12 | 2026-02-12 | Activity likely associated with APT41 used Gemini for knowledge synthesis, real-time troubleshooting and code translation; Google disabled the associated assets | APT41 (likely) | Confirmed | [26] |
| 2026-04-03 | 2026-04-03 | A Linux ELF reported to harvest AWS, GCP, Azure and Alibaba Cloud credentials from the instance metadata service, with C2 in Alibaba Cloud Singapore; the attribution rests mainly on third-party tags, classifiers and code lineage | APT41/Winnti, as the author states it | Confirmed | [57] |
| 2026-07-24 | 2026-07-24 | Google renames APT41 to SPIRE CASTLE | SPIRE CASTLE | Confirmed | [27] |
| Early 2026 | 2026-10-22 | BlackX UEFI bootkit at diplomatic agencies in Tajikistan, Uzbekistan and Turkmenistan; abuses CVE-2022-21894 (Baton Drop) to enroll Machine Owner Keys, tampers with ETW through a kernel driver, runs a RAT with cloud-storage C2, and drops a second payload, OxiDLLRunner | APT41, medium confidence | Confirmed | [31] |

### Reading the record by era

**2010 to 2014: games and certificates.** The earliest public reporting is about game companies: Kaspersky's 2013 Winnti report describes source-code and certificate theft from at least 35 online-game companies, and the 2019 indictment's video game conspiracy starts no later than November 2014 (**Confirmed** [28] [60]). Game-company certificates still appear in 2024. Mandiant found DUST components signed with presumably stolen certificates, one apparently tied to a South Korean gaming company. It also found a DUSTTRAP sample on VirusTotal signed with another South Korean gaming company's certificate, which Mandiant had seen UNC3914 use in 2020; Mandiant and TAG saw no direct relation between UNC3914 and APT41 (**Confirmed** [22]).

**2014 to 2019: two missions at once.** FireEye's timing analysis found operations at gaming targets most frequent between 18:00 and 07:00 UTC+8, which it called some indication that the group is moonlighting, and state-mission activity more frequent between 14:00 and 22:00 China Standard Time; the report cautions that years of data do not represent a daily schedule (**Confirmed** [18]). This is the period of the supply-chain compromises and of MESSAGETAP.

**2019 to 2020: indictments and an exploitation wave.** The first indictment came on 15 August 2019, the FireEye report eight days earlier. Months later came its widest public wave: early 2020 exploitation of Citrix, Cisco and Zoho, then ransomware through Zoho access in March 2020 (**Confirmed** [60] [20] [61]). The 2020 indictments and the September 2020 arrests in Malaysia followed (**Confirmed** [61] [62]; arrests **Reported** [63]).

**2021 to 2022: undeterred.** HC3 said the indictments did not hinder APT41 as it moved into 2021 (**Confirmed** [65]). Group-IB counted four campaigns in 2021, Mandiant documented C0017 against US state governments, and Kaspersky found MoonBounce in firmware (**Confirmed** [49] [21] [30]).

**2023 to 2026: cloud and firmware.** The later record is espionage-heavy: DUST, TOUGHPROGRESS, Silver Dragon and BlackX describe intelligence collection, and none of the later primaries reports new financially motivated APT41 activity (**Inferred**; an absence of reporting is not an absence of activity). The command channel moved into Google and Microsoft services, payload hosting moved to free and serverless platforms, and the persistence layer moved down into UEFI (**Confirmed** [22] [23] [56] [31]).

## Part 3: tooling

### ATT&CK software attributed to APT41

ATT&CK's G0096 software table lists 33 objects, and every one has a library page (**Confirmed** [1] [77]). Two more, Windows Credential Editor ([`S0005`](/mitre/software/S0005.md)) and Winnti for Windows ([`S0141`](/mitre/software/S0141.md)), appear only inside technique procedure text, so 33 is the attributed set, not every software object the page mentions (**Confirmed** [1]). Winnti for Windows in particular is attributed in ATT&CK only to Winnti Group and Aquatic Panda ([`G0143`](/mitre/groups/G0143.md)), although APT41's `T1574.001` procedure names it (**Confirmed** [12]).

| ID | Name | Type | ATT&CK reference for APT41 | Note |
|---|---|---|---|---|
| [`S0073`](/mitre/software/S0073.md) | ASPXSpy | malware | 2019 report [18] | Web shell |
| [`S0190`](/mitre/software/S0190.md) | BITSAdmin | tool | 2020 wave [20] | |
| [`S0069`](/mitre/software/S0069.md) | BLACKCOFFEE | malware | 2019 report [18] | Stage 3 of the CCleaner chain; shared with APT17 and APT40 per FireEye [18] |
| [`S0160`](/mitre/software/S0160.md) | certutil | tool | 2020 wave [20] | Also used to fetch DUSTPAN in DUST [22] |
| [`S0020`](/mitre/software/S0020.md) | China Chopper | malware | 2019 report [18]; DCSO 2022 (not opened) | Planted through ProxyLogon by Earth Baku [39] |
| [`S0154`](/mitre/software/S0154.md) | Cobalt Strike | malware | 2020 wave [20]; Group-IB, Air India, 2021-06-10 (not opened) | BEACON in C0017 and C0040 [21] [22] |
| [`S1052`](/mitre/software/S1052.md) | DEADEYE | malware | C0017 [21] | Launcher with EMBED and APPEND variants |
| [`S0021`](/mitre/software/S0021.md) | Derusbi | malware | 2019 report [18] | |
| [`S0105`](/mitre/software/S0105.md) | dsquery | tool | C0017 [21] | |
| [`S1158`](/mitre/software/S1158.md) | DUSTPAN | malware | C0040 [22]; C0017 [21] | Mandiant calls it consistent with Trend Micro's StealthVector [21] |
| [`S1159`](/mitre/software/S1159.md) | DUSTTRAP | malware | C0040 [22] | Plugin framework keyed to MachineGUID |
| [`S0363`](/mitre/software/S0363.md) | Empire | tool | CrowdStrike 2020 (not opened) | |
| [`S0095`](/mitre/software/S0095.md) | ftp | tool | 2020 wave [20] | |
| [`S0032`](/mitre/software/S0032.md) | gh0st RAT | malware | 2019 report [18] | |
| [`S0357`](/mitre/software/S0357.md) | Impacket | tool | DCSO 2022 (not opened) | |
| [`S0100`](/mitre/software/S0100.md) | ipconfig | tool | Group-IB, Air India, 2021-06-10 (not opened) | |
| [`S1051`](/mitre/software/S1051.md) | KEYPLUG | malware | C0017 [21] | KEYPLUG.LINUX variant; WSS through Cloudflare |
| [`S1185`](/mitre/software/S1185.md) | LightSpy | malware | BlackBerry 2024 (not opened) | Mobile and desktop spyware; APT41 is the only group ATT&CK lists [14] |
| [`S0443`](/mitre/software/S0443.md) | MESSAGETAP | malware | MESSAGETAP report [19] | SMSC data miner |
| [`S0002`](/mitre/software/S0002.md) | Mimikatz | tool | 2019 report [18] | |
| [`S1221`](/mitre/software/S1221.md) | MOPSLED | malware | Mandiant UNC3886 2024 (not opened) | Shared with UNC3886 ([`G1048`](/mitre/groups/G1048.md)) [13] |
| [`S0039`](/mitre/software/S0039.md) | Net | tool | 2019 report [18] | |
| [`S0104`](/mitre/software/S0104.md) | netstat | tool | 2019 report [18] | |
| [`S0385`](/mitre/software/S0385.md) | njRAT | malware | 2019 report [18] | |
| [`S0097`](/mitre/software/S0097.md) | Ping | tool | 2019 report [18] | Used for DNS exfiltration in C0017 [21] |
| [`S0013`](/mitre/software/S0013.md) | PlugX | malware | 2019 report [18] | Mapped to 15 groups in the library data [77] |
| [`S0194`](/mitre/software/S0194.md) | PowerSploit | tool | 2019 report [18] | |
| [`S0006`](/mitre/software/S0006.md) | pwdump | tool | 2019 report [18] | |
| [`S0112`](/mitre/software/S0112.md) | ROCKBOOT | malware | 2019 report [18] | MBR bootkit, deployed on a limited basis |
| [`S0596`](/mitre/software/S0596.md) | ShadowPad | malware | 2019 report [18]; Insikt 2021 (not opened) | Alias POISONPLUG.SHADOW; now mapped to 8 groups [11] |
| [`S0225`](/mitre/software/S0225.md) | sqlmap | tool | Group-IB 2021 [49] | |
| [`S0430`](/mitre/software/S0430.md) | Winnti for Linux | malware | CrowdStrike 2020 (not opened) | Also Aquatic Panda and Earth Lusca [77] |
| [`S0412`](/mitre/software/S0412.md) | ZxShell | malware | 2019 report [18] | |

### ShadowPad and the sharing question

ShadowPad is the clearest case of why one tool does not identify one actor. ATT&CK says it was first identified in the NetSarang compromise in mid-July 2017 and was originally thought to be used only by APT41; it now links it to eight groups: Mustang Panda, RedEcho, Tropic Trooper, Tonto Team, APT41, Aquatic Panda, Earth Lusca and BRONZE BUTLER (**Confirmed** [11]). SentinelOne assesses ShadowPad as a privately sold platform that succeeded PlugX in 2015 and has been used since 2017 by at least five clusters as its list names them (APT41, Tick and Tonto Team as one cluster, Operation Redbonus, Operation Redkanku and Fishmonger); it says BARIUM's victims included NetSarang, ASUS and, allegedly, CCleaner (**Confirmed** [52]). GTIG adds a finer cut: POISONPLUG is used by several likely related PRC groups, but POISONPLUG.SHADOW appears restricted to clusters associated with APT41 (**Confirmed** [24]). PlugX is wider still, with 15 groups in the library's ATT&CK data (**Confirmed** [77]).

### Vendor-named tools with no ATT&CK software object

None of these has an ATT&CK software ID or a library page, so this study names them in prose only (**Confirmed** [77]).

| Tool | What it does, per the source | First public report | Cluster named | Source |
|---|---|---|---|---|
| Winnti (malware family) and a signed 64-bit rootkit | Backdoor and kernel rootkit used against game companies | Kaspersky, 2013-04-11 | Winnti | [28] |
| SOGU | Backdoor in trojanized game installers, December 2014 | FireEye, 2019 | Possibly APT41 | [18] |
| CRACKSHOT | Malware in the 2018 Infestation and PointBlank compromises | FireEye, 2019 | APT41 | [18] |
| DIRTCLEANER, COLDJAVA | First stages of the CCleaner chain that loaded BLACKCOFFEE | FireEye, 2019 | Unconfirmed APT41 | [18] |
| Crosswalk/ProxIP, Winnti/Pasteboy, Barlaiy/Poison Plug, PlugX/Fast | Malware names in the 2020 indictment | Indictment, 2020-08-11 | Chengdu 404 defendants | [61] |
| Speculoos | FreeBSD backdoor delivered through CVE-2019-19781; Unit 42 says it was highly likely crafted for this campaign by APT41 | Unit 42, 2020-04-13 | APT41 | [51] |
| FunnySwitch | Backdoor alongside Crosswalk, ShadowPad and PlugX | Positive Technologies | Winnti/APT41 | [50] |
| StealthVector, StealthMutant, ScrambleCross | Shellcode loaders and a backdoor | Trend Micro, 2021-08-24 | Earth Baku | [39] |
| SideWalk | Backdoor using a Cloudflare Worker for C2 and Google Docs as a dead drop resolver; ESET equates ScrambleCross with SideWalk | ESET, 2021-08-24 | SparklingGoblin | [37] |
| MoonBounce | UEFI firmware implant in CORE_DXE | Kaspersky, 2022-01-20 | APT41 or closely affiliated | [30] |
| LOWKEY.PASSIVE, BADPOTATO | Passive backdoor; ConfuserEx-obfuscated privilege-escalation binary | Mandiant, 2022-03-08 | APT41 | [21] |
| Symatic, CroxLoader, BigpipeLoader, OutLoader, AVBurner | Loaders, and a tool that abuses the RTCore64.sys driver | Trend Micro, 2022-11-09 | Earth Longzhi | [40] |
| Spyder Loader | Loader against Hong Kong organizations | Symantec, 2022-10-18 | None named | [44] |
| GC2 | Open-source red-team tool that takes commands from Google Sheets and exfiltrates to Drive | Google, April 2023 | HOODOO | [25] |
| Backdoor.Winnkit | Backdoor | Symantec, 2023-02-28 | Blackfly | [45] |
| WyrmSpy, DragonEgg | Android surveillanceware | Lookout, 2023-07-19 | APT41 | [54] |
| UNAPIMON | API unhooking DLL | Trend Micro, 2024-04-02 | Earth Freybug | [41] |
| DodgeBox, MoonWalk | Loader with call-stack spoofing, side-loaded through Sandboxie and AhnLab binaries; backdoor with Google Drive C2 | Zscaler, 2024-07-10 | APT41/Earth Baku | [53] |
| ANTSWORD, BLUEBEAM, SQLULDR2, PINEGROVE | Web shells, an Oracle data exporter, an exfiltration tool to OneDrive | Mandiant, 2024-07-18 | APT41 | [22] |
| StealthReacher, SneakCross | Loader; backdoor using Google services for C2 | Trend Micro, 2024-08-09 | Earth Baku | [42] |
| PLUSDROP, PLUSINJECT, TOUGHPROGRESS | In-memory dropper, process-hollowing injector, Google Calendar backdoor | GTIG, 2025-05-28 | APT41 | [23] |
| ScatterBrain | Obfuscating compiler protecting POISONPLUG.SHADOW | GTIG, 2025-01-28 | APT41-associated clusters | [24] |
| BamboLoader, MonikerLoader, GearDoor, SilverScreen, SSHcmd | Loaders, a Google Drive backdoor and utilities | Check Point, 2026-03-03 | Silver Dragon | [56] |
| BlackX, OxiDLLRunner | UEFI bootkit and a second payload | Kaspersky, 2026-10-22 | APT41 (medium confidence) | [31] |

### Code-signing certificates

Certificate abuse runs through the whole record. Kaspersky reported certificate theft from game companies in 2013; FireEye's 2019 blog highlights consistent signing of malware with compromised certificates; the 2020 indictment describes stolen code-signing certificates and payloads that decrypt only on designated victims; Kaspersky found the NetSarang backdoor signed with NetSarang's own certificate; and the 2024 DUST report shows three presumably stolen certificates (CCR INC, OOO ALEAN-TOUR and Gala Lab Corp, the last from an additional DUSTTRAP sample on VirusTotal, a certificate Mandiant had seen UNC3914 use in 2020; Mandiant and TAG saw no direct relation between UNC3914 and APT41) (**Confirmed** [28] [17] [61] [29] [22]).

### Supply-chain compromises and who attributes them

| Date | Target | FireEye rating (2019) | Other primaries | Source |
|---|---|---|---|---|
| 2014-12 | Online games from a Southeast Asian distributor (SOGU) | Possibly APT41 or a close affiliate | | [18] |
| 2017-03 | CCleaner | Unconfirmed APT41 | SentinelOne: BARIUM's victims "allegedly" included CCleaner | [18] [52] |
| 2017-07 | NetSarang (ShadowPad) | Confirmed APT41 | Kaspersky: no actor named | [18] [29] |
| 2018-06 to 2018-11 | ASUS Live Update (ShadowHammer) | Stage 1 unconfirmed; reported stage 2 confirmed | Kaspersky: no APT41 attribution | [18] [32] |
| 2018-07 | Southeast Asian game distributor (Infestation, PointBlank; CRACKSHOT) | Confirmed APT41 | | [18] |
| To 2019-03 | Two games and one gaming platform in Asia, including Electronics Extreme | Not rated | ESET: likely Winnti Group | [33] |
| 2011 to 2018 (conspiracy period) | A software vendor's legitimate software modified | Not rated | 2019 indictment (allegation) | [60] |

FireEye also notes that follow-on payloads were limited to chosen machines by matching individual system identifiers (**Confirmed** [18]).

## Part 4: exploited vulnerabilities

The table joins each vulnerability the verified record ties to APT41, or to a cluster a primary equates with it, to NVD's weakness (CWE) list and the CISA KEV catalog as published on 3 November 2026 (catalog version 2026.11.03).

| CVE | Product | Use in the record (source, event date) | CWE (NVD) | KEV added | KEV ransomware use | Sources |
|---|---|---|---|---|---|---|
| CVE-2012-0158 | Microsoft MSCOMCTL.OCX | Observed vulnerability list, 2019 report | CWE-94 (KEV field; NVD not checked) | 2021-11-03 | Known | [18] [75] |
| CVE-2015-1641 | Microsoft Office | Same list | CWE-399 (KEV field; a CWE category, not in the library's weakness data) | 2021-11-03 | Unknown | [18] [75] |
| CVE-2017-0199 | Microsoft Office and WordPad | Same list | None listed in KEV | 2021-11-03 | Known | [18] [75] |
| CVE-2017-11882 | Microsoft Office | Same list | CWE-119 (KEV field) | 2021-11-03 | Known | [18] [75] |
| CVE-2019-3396 | Atlassian Confluence | Proof-of-concept code within 23 days of disclosure, 2019 | CWE-22 (KEV field) | 2021-11-03 | Known | [18] [75] |
| CVE-2019-19781 | Citrix ADC, Gateway, SD-WAN WANOP | Early 2020 wave; Speculoos from 2020-01-31; 2020 indictment; AA20-275A | CWE-22 | 2021-11-03 | Known | [20] [51] [61] [66] [75] [76] |
| CVE-2019-11510 | Pulse Connect Secure (Ivanti) | 2020 indictment | CWE-22 | 2021-11-03 | Known | [61] [75] [76] |
| CVE-2019-16920 | D-Link routers | 2020 indictment | CWE-78 | 2022-03-25 | Unknown | [61] [75] [76] |
| CVE-2019-16278 | Nostromo nhttpd | 2020 indictment | CWE-22 | 2024-11-07 | Unknown | [61] [75] [76] |
| CVE-2019-1652 | Cisco RV320 and RV325 | 2020 indictment; FireEye's 2020 post says the exploit used against a Cisco RV320 on 2020-02-21 is unknown and notes a public Metasploit module that chains CVE-2019-1652 and CVE-2019-1653 | CWE-20, CWE-78 | 2022-03-03 | Unknown | [61] [20] [75] [76] |
| CVE-2019-1653 | Cisco RV320 and RV325 | Same | CWE-284 | 2021-11-03 | Unknown | [61] [20] [75] [76] |
| CVE-2020-10189 | Zoho ManageEngine Desktop Central | Early 2020 wave; ransomware access on 2020-03-08 (indictment); NVD CVSS 3.1 9.8, published 2020-03-06 | CWE-502 | 2021-11-03 | Unknown | [20] [61] [75] [76] |
| CVE-2021-26855 | Microsoft Exchange (ProxyLogon) | Earth Baku initial access to plant China Chopper, 2021 | CWE-918 (KEV field) | 2021-11-03 | Known | [39] [75] |
| CVE-2021-44207 | Acclaim USAHerds | Zero-day, first exploited July 2021 (C0017); NVD CVSS 3.1 8.1, published 2021-12-21 | CWE-798 | 2024-12-23 | Unknown | [21] [75] [76] |
| CVE-2021-44228 | Apache Log4j2 (Log4Shell) | Exploited within hours of the 2021-12-10 advisory (C0017) | CWE-20, CWE-400, CWE-502, CWE-917 | 2021-12-10 | Known | [21] [75] [76] |
| CVE-2019-16098 | RTCore64.sys driver | AVBurner in the Earth Longzhi campaigns | Not checked | Not in KEV | | [40] [75] |
| CVE-2022-21894 | Windows Boot Manager (Baton Drop) | BlackX Machine Owner Key enrollment, early 2026 | Not checked | Not in KEV | | [31] [75] |

Two notes on the CWE column. For Log4Shell, three CWEs come from the Apache CNA and CWE-917 from NVD's own analysis; for CVE-2019-1653, CWE-284 comes from Cisco while NVD's own entry says no information (**Confirmed** [76]). ATT&CK's `T1059.004` procedure for APT41 cites "CVE-2019-19871", but the report it cites covers CVE-2019-19781 throughout, so this study treats the ATT&CK string as a typo and does not repeat it as a CVE (**Inferred** from [1] [20]).

Two dates stand out (**Inferred** from the table). USAHerds went about three and a half years from first APT41 exploitation (July 2021) to KEV listing (23 December 2024), and the vendor had a patch around 15 November 2021 per Mandiant's update (**Confirmed** [21]). And the driver and boot-manager flaws in the record are not in KEV at all. A KEV-only patch policy would have missed both cases.

## Part 5: targets by sector and geography

| Period | Sectors | Geographies | Source, grade |
|---|---|---|---|
| About 2010 to 2013 | Online games | Strong Southeast Asia focus | [28], Confirmed |
| 2012 to 2019 (cumulative) | Healthcare, high tech, media, pharmaceuticals, retail, software, telecoms, travel, education, video games, virtual currencies, generally aligned with China's Five-Year plans | 14 countries and Hong Kong: France, India, Italy, Japan, Myanmar, the Netherlands, Singapore, South Korea, South Africa, Switzerland, Thailand, Turkey, the UK and the US | [18], Confirmed |
| 2011 to 2018 | High-technology organizations; video game companies with servers in New York, Texas, Washington, Illinois and California; a UK-resident software employee | US, UK | [60], Confirmed (allegation) |
| 2014 to 2018 | Video game companies | US, France, South Korea, Japan, Singapore | [62], Confirmed (allegation) |
| 2014 to 2020 | Over 100 victims, including software, telecoms (Pakistan), universities (Hong Kong, Taiwan), a non-profit, real estate, a Taiwanese energy company, and government entities in Vietnam, India and the UK; dissident and media targets through SonarX | Global | [61], Confirmed (allegation) |
| Indictment period | Telecommunications providers | US, Australia, China (Tibet), Chile, India, Indonesia, Malaysia, Pakistan, Singapore, South Korea, Taiwan, Thailand (FBI, "allegedly targeted") | [64], Confirmed |
| 2019 | A telecom provider's SMS infrastructure | Not stated | [19], Confirmed |
| 2019 to 2020 | Universities during the Hong Kong protests | Hong Kong | [35], Confirmed (Winnti Group) |
| 2020 to 2022 | Not stated | Taiwan, China, Thailand, Malaysia, Indonesia, Pakistan, Ukraine | [40], Confirmed (Earth Longzhi) |
| 2020 to 2021 | Not stated by sector | India, Indonesia, Malaysia, the Philippines, Taiwan, Vietnam | [39], Confirmed (Earth Baku) |
| Not dated | US COVID relief programs (SBA loans, unemployment insurance) | Over a dozen US states | [69], Reported |
| 2021 | An estimated 13 organizations | The US, Taiwan, India, Thailand, China, Hong Kong, Mongolia, Indonesia, Vietnam, Bangladesh, Ireland, Brunei and the UK | [49], Confirmed |
| 2021 | Transport technology (a ScrambleCross victim sharing MoonBounce's C2; not stated to be the firmware victim) | Not stated | [30], Confirmed |
| 2021-05 to 2022-02 | US state governments | United States | [21], Confirmed |
| 2022 | Media (Taiwan); a job search website (Italy) | Taiwan, Italy | [25], Confirmed (HOODOO) |
| Late 2022 to early 2023 | Materials and composites | Asia | [45], Confirmed (Blackfly) |
| Late 2022 onward | Government, media and communications, telecom, technology, healthcare, education | Italy, Germany, the UAE, Qatar; Georgia and Romania suspected | [42], Confirmed (Earth Baku) |
| 2023 to 2024 | Shipping and logistics, media and entertainment, technology, automotive | Mostly Italy, Spain, Taiwan, Thailand, Turkey, the UK | [22], Confirmed |
| 2024 to 2025 | Governments, reached through an exploited government website and links sent to hundreds of targets | Global | [23], Confirmed |
| Mid-2024 to 2026 | Government entities | Mainly Southeast Asia; fewer in Europe; a phishing wave focused on Uzbekistan | [56], Confirmed (Silver Dragon) |
| 2025 | Critical infrastructure | Taiwan | [71], Reported |
| Early 2026 | Diplomatic agencies | Tajikistan, Uzbekistan, Turkmenistan | [31], Confirmed |

Telecoms, healthcare, high technology and government recur from 2014 to 2026, while the geography widens from East and Southeast Asia to Europe, the Middle East and, by 2026, Central Asia (**Inferred** from the table).

## Part 6: the government record

### United States: three indictments

- **US v. Zhang Haoran and Tan Dailin** (D.D.C., case 19-cr-274, Judge Amit P. Mehta, returned 2019-08-15). It charges a computer hacking conspiracy against high-technology organizations (about May 2011 to at least November 2018) and a video game conspiracy (no later than November 2014 to at least November 2018). It alleges resume-themed spear-phishing attachments, supply-chain attacks that modified a software vendor's legitimate software, C2 domains mimicking Google and Microsoft, leased hop-point servers, and C2 dead drops on public web pages; the victims include video game companies with servers in five US states and Victim C, a UK resident (**Confirmed**, allegations [60]).
- **US v. Jiang Lizhi, Qian Chuan and Fu Qiang** (D.D.C., case 1:20-cr-00158, 2020-08-11). The three held the roles of Vice President for the Technical Department, President, and Manager for Big Data Development at Chengdu 404 Network Technology Co., Ltd. The racketeering count covers about May 2014 to about August 2020 and over 100 victims (**Confirmed** [61]). The indictment alleges that in June 2012 chats Jiang said he was "very close" with the Ministry of State Security and that this tie gave him protection. That is an allegation about a 2012 conversation, not a finding that the Ministry tasked any operation (**Confirmed**, allegation [61]).
- **US v. Wong Ong Hua and Ling Yang Ching** (D.D.C., case 1:20-cr-00166, filed 2020-08-18, related to 19-cr-274 and 20-cr-158). It alleges that the two Malaysian nationals, founder and CEO and chief product officer of SEA Gamer Mall Sdn Bhd, paid Tan and Zhang to hack video game companies from at least June 2014 to December 2018, that the hackers altered game databases to inflate in-game currency, used stolen signing certificates and supply-chain attacks, and monitored victims' fraud teams (**Confirmed**, allegations [62]). This indictment does not use the name APT41.

The FBI's wanted listing names Zhang, Tan, Qian, Fu and Jiang as part of a Chinese hacking group "known as APT 41 and BARIUM", from the Washington field office, and lists the telecommunications providers they allegedly targeted (**Confirmed** [64]). Press coverage of the DOJ announcement of 16 September 2020 reports the arrests of Wong and Ling in Malaysia and court-ordered seizures of hundreds of accounts, servers, domains and dead drop pages; the DOJ page itself did not load, and the extradition outcome is not checked (**Reported** [63]).

### United States: advisories and other agencies

- **CISA AA20-275A** (initial version 2020-10-01) names APT41 as exploiting Citrix, Cisco and Zoho, citing ATT&CK G0096 (**Confirmed** [66]).
- **NSA, CISA and FBI AA21-200B** (2021-07-19) cites FireEye's 2020 post This Is Not a Test [20] as its reference for `T1190`, and maps that technique to D3FEND countermeasures including Software Update (`D3-SU`) and Inbound Traffic Filtering (`D3-ITF`); APT41 appears only in the reference title (**Confirmed** [67]).
- **CISA AA20-258A** (2020-09-14) covers Ministry of State Security-affiliated actors and does not name APT41, Winnti or BARIUM, so it is not an APT41 advisory; AA22-158A, AA25-239A, AA26-251A and AA26-281A do not mention APT41 either (**Confirmed** [68]).
- **HHS HC3, "APT41 and Recent Activity"** (2022-09-22) tells the health sector the indictments did not hinder the group in 2021, summarizes C0017 and MoonBounce, and lists the ATT&CK software IDs S0069, S0020, S0154, S0032, S0002, S0013 and S0596 (**Confirmed** [65]).
- **US Secret Service**, through NBC News (2022-12-05): at least $20 million in COVID relief stolen, described as the first pandemic fraud the US government publicly tied to foreign state-sponsored hackers (**Reported** [69]).
- **Microsoft's civil action** 1:17-cv-1224 (E.D. Va.), first published 2017-10-31, names John Doe defendants associated with internet domains in a case titled Barium. The court page itself does not tie BARIUM to APT41; that link comes from Microsoft's naming page (**Confirmed** [59] [16]).

### Taiwan, Singapore, Germany and the United Kingdom

- **Taiwan.** On 2020-05-15 the Ministry of Justice Investigation Bureau said the Winnti Group was behind ransomware at CPC Corp (announced 2020-05-04) and Formosa Petrochemical, that the group likely held access for months and used Active Directory task scheduling to push the ransomware, and that it asked US authorities about a US-based VPS provider (**Reported** [70]). The 2020 US indictment separately alleges ransomware at a Taiwanese energy company on 2020-05-04 (**Confirmed**, allegation [61]); whether these describe the same intrusion is not established by either source. In January 2026 the National Security Bureau listed APT41 with BlackTech, Flax Typhoon, Mustang Panda and UNC3886 as the top five Chinese groups targeting Taiwan's critical infrastructure in 2025 (**Reported** [71]).
- **Singapore.** IMDA's ICM-sector advisory summarizes the GTIG TOUGHPROGRESS report and maps `T1566.002`, `T1204.002`, `T1027`, `T1055.009`, `T1036.008` and `T1102` in its Annex B (**Confirmed** [72]). The advisory's own text describes process hollowing of svchost.exe, which fits Process Hollowing (`T1055.012`) better than Proc Memory (`T1055.009`) (**Inferred**).
- **Germany.** The BfV's Cyber-Brief 01/2019 (2019-12-06) warns German industry of "WinNTI" attacks probably since 2016 using WinNTI version 3, describing DLL search-order hijacking, a rundll32 loader, reflective loading, a payload decrypted with the target hostname, svchost injection and a hook on sysmon's EventWrite (**Confirmed** [73]). The brief does not name APT41, and ATT&CK keeps Winnti Group separate with a partial overlap, so linking it to APT41 is **Inferred**.
- **United Kingdom.** A GOV.UK search for APT41 returned no results (**Confirmed** [74]). The UK appears in the record as a victim location: Victim C in the 2019 indictment, and UK government entities targeted and compromised, including websites scanned with Acunetix in December 2019, in the 2020 indictment (**Confirmed** [60] [61]).

## Part 7: the defender view

### What the dual mission means in practice

FireEye recorded one instance in which APT41 tried to steal data from a healthcare target while also trying to deploy ransomware at a video game studio, so the same operators can be running an espionage intrusion and a ransomware attempt at once (**Confirmed** [18]). In another documented case the group pointed a victim's anti-virus update domain to 1.1.1.1 in the DNS console before trying to push Encryptor RaaS ransomware through group policy (**Confirmed** [18]). An incident responder who finds APT41 tooling should not assume the objective is only data theft, and one who finds ransomware should not assume the actor is only criminal (**Inferred**).

### Hunting leads published in the primaries

| Lead | Where it comes from | Source |
|---|---|---|
| `java.exe` spawning `cmd.exe` or `bitsadmin.exe`; `certutil` downloading executables; PowerShell `Net.WebClient` downloads | 2020 exploitation wave | [20] |
| `/tmp/bsd` and `/tmp/un` on Citrix appliances; `install.bat` creating a `StorSyncSvc` service whose ServiceDll is a Cobalt Strike BEACON loader | 2020 exploitation wave | [20] |
| BADPOTATO; copies of the SAM and SYSTEM hives followed by Mimikatz `lsadump::sam`; `dsquery` enumeration | C0017, 2022 | [21] |
| `schtasks /change` on existing SYSTEM tasks; DEADEYE parts joined with `copy /y /b`; `.vmp` sections renamed `.upx` | C0017, 2022 | [21] |
| KEYPLUG over WebSocket Secure through Cloudflare; dead drop resolvers on tech forums; `ping` to attacker subdomains carrying hex-encoded data, read back from DNS logs | C0017, 2022 | [21] |
| Tomcat Manager web shells (ANTSWORD, BLUEBEAM); `certutil` fetching DUSTPAN; DUSTTRAP payloads keyed to MachineGUID; OneDrive exfiltration | C0040, 2024 | [22] |
| LNK files posing as PDFs inside ZIPs linked from email; svchost.exe hollowing; Google Calendar API traffic from workstations | TOUGHPROGRESS, 2024 | [23] |
| Sandboxie- and AhnLab-signed binaries side-loading unexpected DLLs; call-stack spoofing | DodgeBox, 2024 | [53] |

Published detection content exists for most of these: FireEye's 2020 Appendix A YARA rules; Mandiant's 2022 YARA for KEYPLUG and BADPOTATO and its pointer to the HeySerial deserialization hunting tool; the DUST report's YARA for DUSTTRAP, DUSTPAN keys, PINEGROVE, SQLULDR2 and three certificate hunts, plus Google SecOps rules such as "WinRAR Command Line CSV to RAR"; and GTIG's four YARA rules for the TOUGHPROGRESS chain (**Confirmed** [20] [21] [22] [23]). The DUST report's own ATT&CK table cites the revoked `T1574.002` and a typo, `T15931.002`, so import its technique list through the library's revocation map rather than as published (**Confirmed** [22] [77]).

### Where the library's countermeasure data is thin

The library's D3FEND data has countermeasures for most APT41 behaviors (Part 8 lists them) but none for code signing (`T1553.002`), code-signing certificates (`T1588.003`), domain generation algorithms (`T1568.002`), dead drop resolvers (`T1102.001`), bidirectional web-service C2 (`T1102.002`), environmental keying (`T1480.001`), group policy modification (`T1484.001`) or pass the hash (`T1550.002`) (**Confirmed** [77]). Several of these are this group's signatures. Coverage for them has to come from controls outside the D3FEND mapping: certificate allowlisting and revocation, DNS analytics, egress policy for cloud APIs, and identity monitoring (**Inferred**).

### Vulnerability management

APT41's exploitation tempo argues for three program changes (**Inferred** from Part 4). Prioritize internet-facing assets by exposure and public exploit availability, because the group has exploited flaws within hours of an advisory. Watch niche and vertical software, not only the big vendors: USAHerds served state agriculture departments. And track firmware, boot and driver flaws separately, because neither of the two in this record is in KEV.

## Part 8: MITRE mappings

This part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every ID was checked against the live ATT&CK pages or the library's data files on 3 November 2026; IDs that could not be checked are left out. Revoked IDs that vendors still cite (`T1574.002` DLL Side-Loading, `T1562.001` Disable or Modify Tools) are shown under their v20 successors (`T1574.001`, `T1685`) as `data/attack/superseded_by.jsonl` records them (**Confirmed** [77]).

### Enterprise techniques recorded by ATT&CK

The live G0096 page lists 102 technique and sub-technique IDs, all in the Enterprise domain (**Confirmed** [1]). The library's direct group relationship holds 82 of them; the other 20 reach the group page only through the attributed campaigns C0017 and C0040, whose procedure text is campaign-scoped (**Confirmed** for the counts [1] [77]; that ATT&CK's group page rolls up campaign techniques is **Inferred** from that pattern). Three parent techniques (`T1102`, `T1567`, `T1574`) appear on the campaign pages but not on the group page, which shows only their sub-techniques; the table includes them and marks them in the basis column (**Confirmed** [2] [3]). Tactic names are the v20 names, read from the library's `technique_profiles.jsonl`, which matched every live page spot-checked (**Confirmed** [15] [77]).

Across the 102 group-page IDs, counting each technique once per tactic it serves, the tally is Stealth 20, Persistence 13, Discovery 13, Execution 11, Command and Control 11, Privilege Escalation 10, Collection 8, Credential Access 7, Defense Impairment 6, Reconnaissance 5, Initial Access 5, Resource Development 4, Lateral Movement 4, Exfiltration 4 and Impact 2 (computed from [1] and [77]).

"Where it appears" gives the report ATT&CK cites for the procedure and its date. Where that report was opened for this study, its source number follows; where it was not, the row says so, and the ATT&CK page itself ([1]) is the source.

| ID | Technique | Tactic (v20) | ATT&CK basis | Where it appears (report, date) | Sources |
|---|---|---|---|---|---|
| [`T1001.003`](/mitre/techniques/T1001-003.md) | Data Obfuscation: Protocol or Service Impersonation | Command and Control | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | OS Credential Dumping: LSASS Memory | Credential Access | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [18] |
| [`T1003.002`](/mitre/techniques/T1003-002.md) | OS Credential Dumping: Security Account Manager | Credential Access | group; campaign C0017 | Mandiant, US state governments, 2022-03-08 [21]; Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [2], [21], [49] |
| [`T1003.003`](/mitre/techniques/T1003-003.md) | OS Credential Dumping: NTDS | Credential Access | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | Collection | group; campaign C0017 | Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | Command and Control | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | Discovery | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | Stealth | group | FireEye 2019 report, 2019-08-07 [18]; CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened) | [1], [18] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | Discovery | group | DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Services: Remote Desktop Protocol | Lateral Movement | group | FireEye 2019 report, 2019-08-07 [18]; CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [18] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | Remote Services: SMB/Windows Admin Shares | Lateral Movement | group | CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | group; campaign C0017 | Mandiant, US state governments, 2022-03-08 [21]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [2], [20], [21] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Obfuscated Files or Information: Software Packing | Stealth | group; campaign C0017 | Mandiant, US state governments, 2022-03-08 [21]; Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [2], [21], [49] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1030`](/mitre/techniques/T1030.md) | Data Transfer Size Limits | Exfiltration | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | Discovery | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, US state governments, 2022-03-08 [21]; Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [2], [18], [21], [49] |
| [`T1036.004`](/mitre/techniques/T1036-004.md) | Masquerading: Masquerade Task or Service | Stealth | group; campaign C0017 and C0040 | Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [3], [21], [22] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Masquerading: Match Legitimate Resource Name or Location | Stealth | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1037`](/mitre/techniques/T1037.md) | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [18] |
| [`T1048.003`](/mitre/techniques/T1048-003.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened) | [1], [18] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | Stealth, Privilege Escalation | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Input Capture: Keylogging | Collection, Credential Access | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | Command and Scripting Interpreter: PowerShell | Execution | group | FireEye 2019 report, 2019-08-07 [18]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [18], [20] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Command and Scripting Interpreter: Windows Command Shell | Execution | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, US state governments, 2022-03-08 [21]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [2], [18], [20], [21] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Command and Scripting Interpreter: Unix Shell | Execution | group | FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [20] |
| [`T1059.007`](/mitre/techniques/T1059-007.md) | Command and Scripting Interpreter: JavaScript | Execution | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1069`](/mitre/techniques/T1069.md) | Permission Groups Discovery | Discovery | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1070.003`](/mitre/techniques/T1070-003.md) | Indicator Removal: Clear Command History | Stealth | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | Indicator Removal: File Deletion | Stealth | group; campaign C0040 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, DUST, 2024-07-18 [22]; Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [3], [18], [22], [49] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Application Layer Protocol: Web Protocols | Command and Control | group; campaign C0017 and C0040 | Mandiant, DUST, 2024-07-18 [22]; Mandiant, US state governments, 2022-03-08 [21]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [2], [3], [20], [21], [22] |
| [`T1071.002`](/mitre/techniques/T1071-002.md) | Application Layer Protocol: File Transfer Protocols | Command and Control | group | FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [20] |
| [`T1071.004`](/mitre/techniques/T1071-004.md) | Application Layer Protocol: DNS | Command and Control | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened) | [1], [18] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Data Staged: Local Data Staging | Collection | campaign C0017 and C0040 | Mandiant, DUST, 2024-07-18 [22]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [3], [21], [22] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | group | FireEye 2019 report, 2019-08-07 [18]; CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened) | [1], [18] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | group | FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [20] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Account Discovery: Local Account | Discovery | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Account Discovery: Domain Account | Discovery | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | Command and Control | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1098.007`](/mitre/techniques/T1098-007.md) | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1102`](/mitre/techniques/T1102.md) | Web Service | Command and Control | campaign C0017 and C0040 pages only | Mandiant, US state governments, 2022-03-08 [21]; Mandiant, DUST, 2024-07-18 [22] | [2], [3], [21], [22] |
| [`T1102.001`](/mitre/techniques/T1102-001.md) | Web Service: Dead Drop Resolver | Command and Control | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1104`](/mitre/techniques/T1104.md) | Multi-Stage Channels | Command and Control | group | FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [20] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | group; campaign C0017 and C0040 | Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22]; Mandiant, US state governments, 2022-03-08 [21]; Group-IB, World Tour 2021, 2022-08-18 [49]; FireEye, This Is Not a Test, 2020-03-25 [20]; DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [2], [3], [20], [21], [22], [49] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | Credential Access | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened) | [1], [18] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | Collection | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1134`](/mitre/techniques/T1134.md) | Access Token Manipulation | Stealth, Privilege Escalation | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened) | [1], [18] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Create Account: Local Account | Persistence | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | group; campaign C0017 | Mandiant, US state governments, 2022-03-08 [21]; Group-IB, World Tour 2021, 2022-08-18 [49]; FireEye, This Is Not a Test, 2020-03-25 [20]; DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [2], [20], [21], [49] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1197`](/mitre/techniques/T1197.md) | BITS Jobs | Stealth, Persistence, Execution | group | CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [20] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1213.003`](/mitre/techniques/T1213-003.md) | Data from Information Repositories: Code Repositories | Collection | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1213.006`](/mitre/techniques/T1213-006.md) | Data from Information Repositories: Databases | Collection | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1218.001`](/mitre/techniques/T1218-001.md) | System Binary Proxy Execution: Compiled HTML File | Stealth | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | System Binary Proxy Execution: Rundll32 | Stealth | group | CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened) | [1] |
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Execution Guardrails: Environmental Keying | Stealth | group | N. Carr post, 2019-10-30 (ATT&CK reference, not opened) | [1] |
| [`T1484.001`](/mitre/techniques/T1484-001.md) | Domain or Tenant Policy Modification: Group Policy Modification | Defense Impairment, Privilege Escalation | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | group | FireEye 2019 report, 2019-08-07 [18]; DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [18] |
| [`T1496.001`](/mitre/techniques/T1496-001.md) | Resource Hijacking: Compute Hijacking | Impact | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Server Software Component: Web Shell | Persistence | campaign C0017 and C0040 | Mandiant, DUST, 2024-07-18 [22]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [3], [21], [22] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Pre-OS Boot: Bootkit | Stealth, Persistence | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | group; campaign C0040 | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [3], [18], [20], [22] |
| [`T1546.008`](/mitre/techniques/T1546-008.md) | Event Triggered Execution: Accessibility Features | Privilege Escalation, Persistence | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | group | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [18], [20] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Use Alternate Authentication Material: Pass the Hash | Lateral Movement | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Subvert Trust Controls: Code Signing | Defense Impairment | group; campaign C0040 | FireEye 2019 report, 2019-08-07 [18]; Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22] | [1], [3], [18], [22] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive Collected Data: Archive via Utility | Collection | group; campaign C0040 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, DUST, 2024-07-18 [22]; DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1], [3], [18], [22] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive Collected Data: Archive via Custom Method | Collection | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Phishing: Spearphishing Attachment | Initial Access | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1567`](/mitre/techniques/T1567.md) | Exfiltration Over Web Service | Exfiltration | campaign C0017 page only | Mandiant, US state governments, 2022-03-08 [21] | [2], [21] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1568.002`](/mitre/techniques/T1568-002.md) | Dynamic Resolution: Domain Generation Algorithms | Command and Control | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | System Services: Service Execution | Execution | group; campaign C0040 | Group-IB, Air India, 2021-06-10 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22]; FireEye, This Is Not a Test, 2020-03-25 [20] | [1], [3], [20], [22] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | Lateral Movement | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1573.002`](/mitre/techniques/T1573-002.md) | Encrypted Channel: Asymmetric Cryptography | Command and Control | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1574`](/mitre/techniques/T1574.md) | Hijack Execution Flow | Stealth, Execution | campaign C0017 page only | Mandiant, US state governments, 2022-03-08 [21] | [2], [21] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | Hijack Execution Flow: DLL | Stealth, Execution | group; campaign C0040 | FireEye 2019 report, 2019-08-07 [18]; CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened); Mandiant, DUST, 2024-07-18 [22] | [1], [3], [18], [22] |
| [`T1574.006`](/mitre/techniques/T1574-006.md) | Hijack Execution Flow: Dynamic Linker Hijacking | Stealth, Execution | group | CrowdStrike 2020 Global Threat Report, 2020-03-02 (ATT&CK reference, not opened) | [1] |
| [`T1583.007`](/mitre/techniques/T1583-007.md) | Acquire Infrastructure: Serverless | Resource Development | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1586.003`](/mitre/techniques/T1586-003.md) | Compromise Accounts: Cloud Accounts | Resource Development | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Obtain Capabilities: Tool | Resource Development | group; campaign C0017 | FireEye 2019 report, 2019-08-07 [18]; Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [18], [21] |
| [`T1588.003`](/mitre/techniques/T1588-003.md) | Obtain Capabilities: Code Signing Certificates | Resource Development | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1593.002`](/mitre/techniques/T1593-002.md) | Search Open Websites/Domains: Search Engines | Reconnaissance | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1594`](/mitre/techniques/T1594.md) | Search Victim-Owned Websites | Reconnaissance | campaign C0040 | Mandiant, DUST, 2024-07-18 [22] | [1], [3], [22] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Active Scanning: Vulnerability Scanning | Reconnaissance | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1595.003`](/mitre/techniques/T1595-003.md) | Active Scanning: Wordlist Scanning | Reconnaissance | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1596.005`](/mitre/techniques/T1596-005.md) | Search Open Technical Databases: Scan Databases | Reconnaissance | group; campaign C0040 | Mandiant, DUST, 2024-07-18 [22]; Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [3], [22], [49] |
| [`T1599`](/mitre/techniques/T1599.md) | Network Boundary Bridging | Defense Impairment | group | DCSO CyTec, 2022-12-24 (ATT&CK reference, not opened) | [1] |
| [`T1680`](/mitre/techniques/T1680.md) | Local Storage Discovery | Discovery | campaign C0017 | Mandiant, US state governments, 2022-03-08 [21] | [1], [2], [21] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Social Engineering: Impersonation | Stealth | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | group | Group-IB, World Tour 2021, 2022-08-18 [49] | [1], [49] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Disable or Modify Tools: Clear Windows Event Logs | Defense Impairment | group | FireEye 2019 report, 2019-08-07 [18] | [1], [18] |

### Enterprise techniques stated by vendor and government primaries

These IDs appear in a primary source's own ATT&CK table but not in ATT&CK's APT41 record. Zscaler's DodgeBox table also lists `T1027`, `T1480.001`, `T1574.002` (now `T1574.001`) and `T1562.001` (now `T1685`), which ATT&CK already records (**Confirmed** [53] [77]). IMDA's `T1055.009` is left out here for the reason given in Part 6.

| ID | Technique | Tactic (v20) | Stated by (report, date) | Sources |
|---|---|---|---|---|
| [`T1027.007`](/mitre/techniques/T1027-007.md) | Obfuscated Files or Information: Dynamic API Resolution | Stealth | Zscaler ThreatLabz, DodgeBox, 2024-07-10 (APT41/Earth Baku, moderate confidence) | [53] |
| [`T1620`](/mitre/techniques/T1620.md) | Reflective Code Loading | Stealth | Zscaler ThreatLabz, DodgeBox, 2024-07-10 | [53] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | Execution | Zscaler ThreatLabz, DodgeBox, 2024-07-10 | [53] |
| [`T1480`](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | Zscaler ThreatLabz, DodgeBox, 2024-07-10 | [53] |
| [`T1574.014`](/mitre/techniques/T1574-014.md) | Hijack Execution Flow: AppDomainManager | Stealth, Execution | Check Point Research, Silver Dragon, 2026-03-03 (likely within the APT41 umbrella) | [56] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Phishing: Spearphishing Link | Initial Access | Singapore IMDA advisory, Annex B, summarizing the GTIG report of 2025-05-28 | [72] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | User Execution: Malicious File | Execution | Singapore IMDA advisory, Annex B | [72] |
| [`T1036.008`](/mitre/techniques/T1036-008.md) | Masquerading: Masquerade File Type | Stealth | Singapore IMDA advisory, Annex B | [72] |

### Enterprise techniques inferred by this study

These are this study's mappings from a dated narrative to a technique. They are **Inferred**, carry a lower score in the Navigator layer, and should not be quoted as ATT&CK or vendor mappings.

| ID | Technique | Tactic (v20) | Narrative it rests on (report, date) | Sources |
|---|---|---|---|---|
| [`T1542.001`](/mitre/techniques/T1542-001.md) | Pre-OS Boot: System Firmware | Stealth, Persistence | MoonBounce, a UEFI CORE_DXE firmware implant detected in spring 2021 (Kaspersky: APT41 or a closely affiliated actor, medium to high confidence) | [30] |
| [`T1055.012`](/mitre/techniques/T1055-012.md) | Process Injection: Process Hollowing | Stealth, Privilege Escalation | PLUSINJECT hollows a legitimate svchost.exe, found late October 2024 (GTIG); a Blackfly svchost process-hollowing tool, late 2022 to early 2023 (Symantec) | [23], [45], [72] |
| [`T1102.002`](/mitre/techniques/T1102-002.md) | Web Service: Bidirectional Communication | Command and Control | TOUGHPROGRESS takes commands through Google Calendar (GTIG, 2024); GC2 takes commands from Google Sheets (Google, 2022); MoonWalk (Zscaler, 2024) and GearDoor (Check Point, 2026) use Google Drive for C2 | [23], [25], [53], [56] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Acquire Infrastructure: Web Services | Resource Development | free web hosting (InfinityFree, TryCloudflare) and Cloudflare Workers used to host payloads since at least August 2024 (GTIG) | [23] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | AVBurner abuses the vulnerable RTCore64.sys driver (CVE-2019-16098) in the Earth Longzhi campaigns, 2020 to 2022 (Trend Micro) | [40] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | Collection | a Blackfly screenshot tool, late 2022 to early 2023 (Symantec) | [45] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | MESSAGETAP filters SMS traffic on SMSC servers, first reported August 2019 (FireEye); the library data maps S0443 to T1040 at the software level | [19], [77] |
| [`T1552.005`](/mitre/techniques/T1552-005.md) | Unsecured Credentials: Cloud Instance Metadata API | Credential Access | a Linux ELF reported to harvest cloud credentials from the 169.254.169.254 metadata service, 2026-04-03 (Breakglass Intelligence, automated pipeline) | [57] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Acquire Infrastructure: Domains | Resource Development | C2 domains that mimic Google and Microsoft (2019 indictment, an allegation) | [60] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Acquire Infrastructure: Virtual Private Server | Resource Development | leased hop-point servers, HOP POINT ONE from 2011-05-12 (2019 indictment, an allegation) | [60] |
| [`T1588.007`](/mitre/techniques/T1588-007.md) | Obtain Capabilities: Artificial Intelligence | Resource Development | activity likely associated with APT41 used Gemini for knowledge synthesis, troubleshooting and code translation, 2026-02-12 (GTIG) | [26] |

### Mobile and ICS

ATT&CK maps no Mobile or ICS technique to APT41 (**Confirmed** [1]). LightSpy ([`S1185`](/mitre/software/S1185.md)) runs on Android, iOS, macOS and Windows and is attributed to APT41, and Lookout's WyrmSpy and DragonEgg are Android surveillanceware (**Confirmed** [14] [54]), but no verified source in this study maps those behaviors to Mobile technique IDs, so none are given. There is no ATT&CK for ICS record for APT41.

### Groups, campaigns and software

| Object | ID | Relationship to APT41 in ATT&CK v20.0 | Source |
|---|---|---|---|
| APT41 | [`G0096`](/mitre/groups/G0096.md) | The group | [1] |
| Campaign C0017 | [`C0017`](/mitre/campaigns/C0017.md) | Attributed; May 2021 to February 2022; 29 techniques | [2] |
| APT41 DUST | [`C0040`](/mitre/campaigns/C0040.md) | Attributed; First Seen January 2023, Last Seen June 2024 (the description says to July 2024); 23 techniques | [3] |
| Operation CuckooBees | [`C0012`](/mitre/campaigns/C0012.md) | Not attributed; the description names actors affiliated with Winnti Group, APT41 and BARIUM; December 2019 to May 2022 | [4] |
| Winnti Group | [`G0044`](/mitre/groups/G0044.md) | Separate group (associated group Blackfly); partial overlap recorded in G0096's description | [1] [7] |
| Axiom | [`G0001`](/mitre/groups/G0001.md) | Separate; may overlap Winnti Group | [9] |
| Earth Lusca | [`G1006`](/mitre/groups/G1006.md) | Separate; shares malware with APT41 | [8] |
| RedEcho | [`G1042`](/mitre/groups/G1042.md) | Separate; overlaps APT41, tied to ShadowPad | [10] |
| Aquatic Panda | [`G0143`](/mitre/groups/G0143.md) | Separate; shares Winnti for Windows, Winnti for Linux and ShadowPad | [12] [11] [77] |
| UNC3886 | [`G1048`](/mitre/groups/G1048.md) | Separate; shares MOPSLED | [13] |
| Software | 33 IDs | See the table in Part 3 | [1] |
| Winnti for Windows | [`S0141`](/mitre/software/S0141.md) | Named in an APT41 procedure; attributed to Winnti Group and Aquatic Panda | [12] |
| Windows Credential Editor | [`S0005`](/mitre/software/S0005.md) | Named in an APT41 procedure only | [1] |
| PipeMon | [`S0501`](/mitre/software/S0501.md) | Winnti Group tool (ESET, 2020); not attributed to APT41 | [36] [77] |

The library's Enterprise group and campaign files held 178 groups and 57 campaigns on 3 November 2026, against 182 and 61 on the live v20 indexes, which list every domain (**Confirmed** [5] [6] [77]). The four extra groups are Mobile and ICS groups that the library keeps in its Mobile data (Bouncing Golf, UNC788) and ICS data (ALLANITE, CyberAv3ngers), with no generated group page; the four extra campaigns are not in the library's data. None of them bears on APT41 (**Confirmed** [77]).

### CWE and CAPEC

CWE IDs come from Part 4: the NVD record for each exploited CVE, or the CWE field of the KEV catalog where Part 4 marks it as a KEV field (CWE-22 for CVE-2019-3396, CWE-918, CWE-94 and CWE-119) (**Confirmed** [75] [76]). CAPEC IDs come from the library's own data: `data/weaknesses/cwe.jsonl` for weakness-to-pattern links, and the `capec` field of `data/attack/technique_profiles.jsonl` for technique-to-pattern links (**Confirmed** [76] [77]). The broad classes CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption) and CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer) are not expanded, because their pattern lists say nothing specific about these flaws. CWE-399, the KEV field for CVE-2015-1641, is a CWE category rather than a weakness and is not in the library's weakness data, so it has no pattern links. See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md) for the frameworks.

| Weakness | CVEs in this record | CAPEC patterns linked in the library data |
|---|---|---|
| CWE-22 Path Traversal | CVE-2019-19781, CVE-2019-11510, CVE-2019-16278 (and CVE-2019-3396 per KEV) | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal; [CAPEC-64](/mitre/capec/CAPEC-64.md); [CAPEC-76](/mitre/capec/CAPEC-76.md); [CAPEC-78](/mitre/capec/CAPEC-78.md); [CAPEC-79](/mitre/capec/CAPEC-79.md) |
| CWE-78 OS Command Injection | CVE-2019-16920, CVE-2019-1652 | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection; [CAPEC-6](/mitre/capec/CAPEC-6.md); [CAPEC-15](/mitre/capec/CAPEC-15.md); [CAPEC-43](/mitre/capec/CAPEC-43.md); [CAPEC-108](/mitre/capec/CAPEC-108.md) |
| CWE-94 Improper Control of Generation of Code (Code Injection) | CVE-2012-0158 (KEV field) | [CAPEC-242](/mitre/capec/CAPEC-242.md) Code Injection; [CAPEC-35](/mitre/capec/CAPEC-35.md); [CAPEC-77](/mitre/capec/CAPEC-77.md) |
| CWE-502 Deserialization of Untrusted Data | CVE-2020-10189, CVE-2021-44228 | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection |
| CWE-798 Use of Hard-coded Credentials | CVE-2021-44207 | [CAPEC-191](/mitre/capec/CAPEC-191.md) Read Sensitive Constants Within an Executable; [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords |
| CWE-918 Server-Side Request Forgery | CVE-2021-26855 (KEV field) | [CAPEC-664](/mitre/capec/CAPEC-664.md) Server Side Request Forgery |
| CWE-917 Expression Language Injection | CVE-2021-44228 | None in the library data |
| CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer | CVE-2017-11882 (KEV field) | A broad class with 12 linked patterns, not expanded; see [CWE Reference](/CWE_REFERENCE.md) |
| CWE-284 Improper Access Control | CVE-2019-1653 | A broad class; see [CWE Reference](/CWE_REFERENCE.md) |

| Technique (APT41 use) | CAPEC patterns linked in the library data |
|---|---|
| `T1195.002` Compromise Software Supply Chain (NetSarang, game distributors) | [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update; [CAPEC-442](/mitre/capec/CAPEC-442.md) Infected Software; [CAPEC-443](/mitre/capec/CAPEC-443.md); [CAPEC-523](/mitre/capec/CAPEC-523.md); [CAPEC-669](/mitre/capec/CAPEC-669.md) Alteration of a Software Update; [CAPEC-673](/mitre/capec/CAPEC-673.md) Developer Signing Maliciously Altered Software; [CAPEC-678](/mitre/capec/CAPEC-678.md); [CAPEC-691](/mitre/capec/CAPEC-691.md) |
| `T1553.002` Code Signing (stolen certificates) | [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code; [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities; [CAPEC-473](/mitre/capec/CAPEC-473.md) Signature Spoof |
| `T1566.001` Spearphishing Attachment, `T1566.002` Spearphishing Link | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing |
| `T1505.003` Web Shell (ASPXSpy, China Chopper, ANTSWORD, BLUEBEAM) | [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server |
| `T1542.003` Bootkit, `T1014` Rootkit (ROCKBOOT, Winnkit, BlackX) | [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit |
| `T1542.001` System Firmware (MoonBounce, Inferred) | [CAPEC-532](/mitre/capec/CAPEC-532.md) Altered Installed BIOS |
| `T1574.001` DLL (search order hijacking, side-loading) | [CAPEC-471](/mitre/capec/CAPEC-471.md) Search Order Hijacking; [CAPEC-641](/mitre/capec/CAPEC-641.md) DLL Side-Loading |
| `T1550.002` Pass the Hash | [CAPEC-644](/mitre/capec/CAPEC-644.md) Use of Captured Hashes (Pass The Hash) |
| `T1056.001` Keylogging | [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger |
| `T1036.004` Masquerade Task or Service | [CAPEC-504](/mitre/capec/CAPEC-504.md) Task Impersonation |
| `T1685` Disable or Modify Tools | [CAPEC-571](/mitre/capec/CAPEC-571.md) Block Logging to Central Repository; [CAPEC-578](/mitre/capec/CAPEC-578.md) Disable Security Software |
| `T1599` Network Boundary Bridging | [CAPEC-700](/mitre/capec/CAPEC-700.md) Network Boundary Bridging |
| `T1040` Network Sniffing (MESSAGETAP, Inferred) | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (also CAPEC-57 and CAPEC-65 in the library data) |
| `T1113` Screen Capture (Blackfly, Inferred) | [CAPEC-648](/mitre/capec/CAPEC-648.md) Collect Data from Screen Capture |

### D3FEND countermeasures

D3FEND countermeasures below come from the library's `data/attack/technique_to_d3fend.jsonl` and each links to its library page (**Confirmed** [77]). AA21-200B maps `T1190` to Application Hardening (`D3-AH`), Software Update (`D3-SU`), File Analysis (`D3-FA`), Client-server Payload Profiling (`D3-CSPP`), Process Lineage Analysis (`D3-PLA`) and Inbound Traffic Filtering (`D3-ITF`). The library data shares Inbound Traffic Filtering and Client-server Payload Profiling, but not the other four (**Confirmed** [67] [77]). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

| APT41 behavior | Techniques | D3FEND countermeasures in the library data |
|---|---|---|
| Exploiting internet-facing applications | `T1190` | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (`D3-ITF`), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (`D3-NTSA`), [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (`D3-DQSA`), [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md) (`D3-APCA`) |
| Software supply-chain compromise | `T1195.002` | [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`), [Software Inventory](/mitre/d3fend/software-inventory.md) (`D3-SWI`), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (`D3-AVE`) |
| UEFI firmware implant (Inferred) | `T1542.001` | [Firmware Verification](/mitre/d3fend/firmware-verification.md) (`D3-FV`), [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md) (`D3-SFV`), [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md) (`D3-FBA`) |
| Bootkits | `T1542.003` | [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md) (`D3-BA`), [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`) |
| DNS command and control and DNS exfiltration | `T1071.004` | [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) (`D3-DNSTA`), [DNS Denylisting](/mitre/d3fend/dns-denylisting.md) (`D3-DNSDL`), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`) |
| Web and encrypted C2 | `T1071.001`, `T1573.002` | [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) (`D3-CA`), [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md) (`D3-NTCD`) |
| Cloud-service C2 and exfiltration | `T1102`, `T1567.002` | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`), [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) (`D3-PMAD`), [Per Host Download-Upload Ratio Analysis](/mitre/d3fend/per-host-download-upload-ratio-analysis.md) (`D3-PHDURA`) |
| Web shells | `T1505.003` | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (`D3-FIM`), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`), [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`) |
| Scheduled tasks, WMI, SAM dumping, rundll32 | `T1053.005`, `T1047`, `T1003.002`, `T1218.011` | [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`), [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md) (`D3-PLA`) |
| Task and service masquerading | `T1036.004` | [Scheduled Job Analysis](/mitre/d3fend/scheduled-job-analysis.md) (`D3-SJA`) |
| DLL hijacking and side-loading | `T1574.001` | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (`D3-FIM`), [Local File Permissions](/mitre/d3fend/local-file-permissions.md) (`D3-LFP`) |
| Process hollowing (Inferred) | `T1055.012` | [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) (`D3-PCSV`), [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (`D3-MBT`) |
| Disabling security tools | `T1685` (through its predecessor `T1562.001`) | [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`), [System Daemon Monitoring](/mitre/d3fend/system-daemon-monitoring.md) (`D3-SDM`) |
| Phishing and malicious files | `T1566.001`, `T1566.002`, `T1204.002` | [Email Filtering](/mitre/d3fend/email-filtering.md) (`D3-EF`), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (`D3-DA`), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`) |
| No countermeasure in the library data | `T1553.002`, `T1588.003`, `T1568.002`, `T1102.001`, `T1102.002`, `T1480.001`, `T1484.001`, `T1550.002` | See Part 7 |

### Navigator layer

The study's techniques are collected in an ATT&CK Navigator layer, [`navigator/library-layers/apt41-public-record.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/apt41-public-record.json), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/apt41-public-record.json). Scores mean membership and evidence basis, not frequency or severity: 100 for techniques ATT&CK v20.0 records for APT41 or its attributed campaigns, 60 for IDs a vendor or government primary states in its own ATT&CK table, and 30 for this study's inferences. Each technique's comment names the study's source numbers. Operation CuckooBees techniques are left out because ATT&CK attributes that campaign to no group.

### Notices

ATT&CK content in this study: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE. CAPEC, CWE and D3FEND material is used under their terms as recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

## Cross-cutting themes

- **Attribution is a ladder, not a label.** The same activity reaches readers at very different confidence: a grand jury's allegation, FireEye's "high confidence", Kaspersky's "medium to high" and "medium", Zscaler's "moderate", Check Point's "likely", and Recorded Future's "closely overlaps". A defender's report should carry the rung, not just the name. See the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md).
- **Names fragment faster than activity does.** Between Microsoft's two typhoons, Symantec's two arms, Trend Micro's subgroups, Google's 2026 rename and ATT&CK's three separate objects, the same intrusion can carry four names in four reports. Merging indicators across those names without checking the vendor's boundary produces false confidence (**Inferred**).
- **Trust relationships are the attack surface.** Update channels, code-signing certificates, managed-service customer accounts (ECS #1 in the indictment) and mainstream cloud APIs all appear as access or concealment paths. Each is something defenders were told to trust. See [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md).
- **Legal action did not change the tempo.** The 2019 and 2020 indictments, the 2020 arrests and seizures, Microsoft's civil action and Google's infrastructure takedowns are all on the record, and the public reporting continues through 2026 (**Inferred** from the timeline).
- **Shared tools blur the picture.** ShadowPad, PlugX and Winnti malware are used by many clusters, so a tool hit is a lead, not an attribution. Conversely, GTIG's finding that POISONPLUG.SHADOW appears restricted to APT41-associated clusters shows that variant-level detail can narrow the field (**Confirmed** [11] [24]).
- **The library's own data has edges worth knowing.** ATT&CK's group page and the library's group page count differently (102 against 82) because of campaign roll-up, and the library's D3FEND data leaves several APT41 signatures without a countermeasure. Readers comparing tools against this layer should know which count they are using.

## Sources

Every source below was opened on 3 November 2026. Grades apply to the source type: Confirmed for a primary (the publisher of the fact), Reported for secondary press coverage. Three URLs are printed as text rather than links because automated link checkers cannot open them: Lookout's page [54] answers a non-browser client with HTTP 403, the Positive Technologies page [50] is served with a certificate from the Russian Trusted Sub CA, which common trust stores do not include, and the Sophos page [58] timed out on repeated automated requests on 3 November 2026. Copy them into a browser to read them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | MITRE ATT&CK, Group G0096 APT41 (version 4.2, last modified 31 July 2026; ATT&CK v20.0) | https://attack.mitre.org/groups/G0096/ | 2026-11-03 | Confirmed |
| 2 | MITRE ATT&CK, Campaign C0017 (May 2021 to February 2022) | https://attack.mitre.org/campaigns/C0017/ | 2026-11-03 | Confirmed |
| 3 | MITRE ATT&CK, Campaign C0040 APT41 DUST | https://attack.mitre.org/campaigns/C0040/ | 2026-11-03 | Confirmed |
| 4 | MITRE ATT&CK, Campaign C0012 Operation CuckooBees (version 1.1) | https://attack.mitre.org/campaigns/C0012/ | 2026-11-03 | Confirmed |
| 5 | MITRE ATT&CK, Groups index (definition of Associated Groups) | https://attack.mitre.org/groups/ | 2026-11-03 | Confirmed |
| 6 | MITRE ATT&CK, Campaigns index | https://attack.mitre.org/campaigns/ | 2026-11-03 | Confirmed |
| 7 | MITRE ATT&CK, Group G0044 Winnti Group (version 1.2) | https://attack.mitre.org/groups/G0044/ | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, Group G1006 Earth Lusca | https://attack.mitre.org/groups/G1006/ | 2026-11-03 | Confirmed |
| 9 | MITRE ATT&CK, Group G0001 Axiom | https://attack.mitre.org/groups/G0001/ | 2026-11-03 | Confirmed |
| 10 | MITRE ATT&CK, Group G1042 RedEcho | https://attack.mitre.org/groups/G1042/ | 2026-11-03 | Confirmed |
| 11 | MITRE ATT&CK, Software S0596 ShadowPad (version 1.3) | https://attack.mitre.org/software/S0596/ | 2026-11-03 | Confirmed |
| 12 | MITRE ATT&CK, Software S0141 Winnti for Windows | https://attack.mitre.org/software/S0141/ | 2026-11-03 | Confirmed |
| 13 | MITRE ATT&CK, Software S1221 MOPSLED | https://attack.mitre.org/software/S1221/ | 2026-11-03 | Confirmed |
| 14 | MITRE ATT&CK, Software S1185 LightSpy | https://attack.mitre.org/software/S1185/ | 2026-11-03 | Confirmed |
| 15 | MITRE ATT&CK, technique pages for the v20 tactic names (T1684.001, T1685, T1685.005, T1680, T1553.002) | https://attack.mitre.org/techniques/T1684/001/ | 2026-11-03 | Confirmed |
| 16 | Microsoft, How Microsoft names threat actors (updated 2026-10-21) | https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming | 2026-11-03 | Confirmed |
| 17 | FireEye (now Mandiant), APT41: A Dual Espionage and Cyber Crime Operation, blog (2019-08-07) | https://cloud.google.com/blog/topics/threat-intelligence/apt41-dual-espionage-and-cyber-crime-operation | 2026-11-03 | Confirmed |
| 18 | FireEye (now Mandiant), APT41, A Dual Espionage and Cyber Crime Operation, full report PDF (2019) | https://services.google.com/fh/files/misc/apt41-a-dual-espionage-and-cyber-crime-operation.pdf | 2026-11-03 | Confirmed |
| 19 | FireEye, MESSAGETAP: Who's Reading Your Text Messages? (2019-10-31) | https://cloud.google.com/blog/topics/threat-intelligence/messagetap-who-is-reading-your-text-messages | 2026-11-03 | Confirmed |
| 20 | FireEye, This Is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits (2020-03-25) | https://cloud.google.com/blog/topics/threat-intelligence/apt41-initiates-global-intrusion-campaign-using-multiple-exploits | 2026-11-03 | Confirmed |
| 21 | Mandiant, Does This Look Infected? A Summary of APT41 Targeting U.S. State Governments (2022-03-08) | https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments | 2026-11-03 | Confirmed |
| 22 | Mandiant with Google TAG, APT41 Has Arisen From the DUST (2024-07-18) | https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust | 2026-11-03 | Confirmed |
| 23 | Google Threat Intelligence Group, Mark Your Calendar: APT41 Innovative Tactics (2025-05-28) | https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics | 2026-11-03 | Confirmed |
| 24 | Google Threat Intelligence Group, ScatterBrain and POISONPLUG.SHADOW (2025-01-28) | https://cloud.google.com/blog/topics/threat-intelligence/scatterbrain-unmasking-poisonplug-obfuscator/ | 2026-11-03 | Confirmed |
| 25 | Google Cloud, Threat Horizons report, April 2023 (PDF) | https://services.google.com/fh/files/blogs/gcat_threathorizons_full_apr2023.pdf | 2026-11-03 | Confirmed |
| 26 | Google Threat Intelligence Group, AI Threat Tracker: Distillation, Experimentation, and (Continued) Integration of AI for Adversarial Use (2026-02-12) | https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use | 2026-11-03 | Confirmed |
| 27 | Google Threat Intelligence Group, updated cyber threat actor naming system (2026-07-24, table added 2026-07-30) | https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system | 2026-11-03 | Confirmed |
| 28 | Kaspersky GReAT, Winnti: more than just a game (2013-04-11) | https://securelist.com/winnti-more-than-just-a-game/37029/ | 2026-11-03 | Confirmed |
| 29 | Kaspersky GReAT, ShadowPad in corporate networks (2017-08-15) | https://securelist.com/shadowpad-in-corporate-networks/81432/ | 2026-11-03 | Confirmed |
| 30 | Kaspersky, MoonBounce: the dark side of UEFI firmware (2022-01-20) | https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/ | 2026-11-03 | Confirmed |
| 31 | Kaspersky GReAT, BlackX UEFI bootkit (2026-10-22) | https://securelist.com/uefi-bootkit-blackx/121539/ | 2026-11-03 | Confirmed |
| 32 | Kaspersky, Operation ShadowHammer | https://securelist.com/operation-shadowhammer-a-high-profile-supply-chain-attack/90380/ | 2026-11-03 | Confirmed |
| 33 | ESET, Gaming industry still in the scope of attackers in Asia (2019-03-11) | https://www.welivesecurity.com/2019/03/11/gaming-industry-scope-attackers-asia/ | 2026-11-03 | Confirmed |
| 34 | ESET, Winnti Group skip-2.0 Microsoft SQL Server backdoor (2019-10-21) | https://www.welivesecurity.com/2019/10/21/winnti-group-skip2-0-microsoft-sql-server-backdoor/ | 2026-11-03 | Confirmed |
| 35 | ESET, Winnti Group targeting universities in Hong Kong (2020-01-31) | https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/ | 2026-11-03 | Confirmed |
| 36 | ESET, No "Game over" for the Winnti Group (2020-05-21) | https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/ | 2026-11-03 | Confirmed |
| 37 | ESET, SideWalk may be as dangerous as CROSSWALK (2021-08-24) | https://www.welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/ | 2026-11-03 | Confirmed |
| 38 | ESET, Operation FishMedley | https://www.welivesecurity.com/en/eset-research/operation-fishmedley/ | 2026-11-03 | Confirmed |
| 39 | Trend Micro, APT41 Resurfaces as Earth Baku With New Cyberespionage Campaign (2021-08-24) | https://www.trendmicro.com/en_us/research/21/h/apt41-resurfaces-as-earth-baku-with-new-cyberespionage-campaign.html | 2026-11-03 | Confirmed |
| 40 | Trend Micro, Hack the Real Box: APT41's New Subgroup Earth Longzhi (2022-11-09) | https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html | 2026-11-03 | Confirmed |
| 41 | Trend Micro, Earth Freybug and UNAPIMON (2024-04-02) | https://www.trendmicro.com/en_us/research/24/d/earth-freybug.html | 2026-11-03 | Confirmed |
| 42 | Trend Micro, A Dive into Earth Baku's Latest Campaign (2024-08-09) | https://www.trendmicro.com/en_us/research/24/h/earth-baku-latest-campaign.html | 2026-11-03 | Confirmed |
| 43 | Symantec, Grayfly and the Sidewalk malware (2021-09-09) | https://www.security.com/threat-intelligence/grayfly-china-sidewalk-malware | 2026-11-03 | Confirmed |
| 44 | Symantec, Spyder Loader and Operation CuckooBees in Hong Kong (2022-10-18) | https://www.security.com/threat-intelligence/spyder-loader-cuckoobees-hong-kong | 2026-11-03 | Confirmed |
| 45 | Symantec, Blackfly espionage against materials technology (2023-02-28) | https://www.security.com/threat-intelligence/blackfly-espionage-materials | 2026-11-03 | Confirmed |
| 46 | Secureworks, BRONZE ATLAS threat profile (archived copy captured 2025-11-18; the profile now sits on sophos.com) | https://web.archive.org/web/20251118161938/https://www.secureworks.com/research/threat-profiles/bronze-atlas | 2026-11-03 | Confirmed |
| 47 | CrowdStrike, WICKED PANDA adversary profile | https://www.crowdstrike.com/en-us/adversaries/wicked-panda/ | 2026-11-03 | Confirmed |
| 48 | Recorded Future Insikt Group, With KEYPLUG, China's RedGolf Spies On, Steals From Wide Field of Targets (2023-03-30) | https://www.recordedfuture.com/research/with-keyplug-chinas-redgolf-spies-on-steals-from-wide-field-targets | 2026-11-03 | Confirmed |
| 49 | Group-IB, APT41 World Tour 2021 on a tight schedule (2022-08-18) | https://www.group-ib.com/blog/apt41-world-tour-2021/ | 2026-11-03 | Confirmed |
| 50 | Positive Technologies, Higaisa or Winnti? APT41 backdoors, old and new (page dated 2024-08-19) | `https://global.ptsecurity.com/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new` | 2026-11-03 | Confirmed |
| 51 | Palo Alto Networks Unit 42, APT41 Using New Speculoos Backdoor (2020-04-13) | https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/ | 2026-11-03 | Confirmed |
| 52 | SentinelOne, ShadowPad: A Masterpiece of Privately Sold Malware in Chinese Espionage (updated 2025-01-09) | https://www.sentinelone.com/labs/shadowpad-a-masterpiece-of-privately-sold-malware-in-chinese-espionage/ | 2026-11-03 | Confirmed |
| 53 | Zscaler ThreatLabz, DodgeBox: A deep dive into the updated arsenal of APT41, Part 1 (2024-07-10) | https://www.zscaler.com/blogs/security-research/dodgebox-deep-dive-updated-arsenal-apt41-part-1 | 2026-11-03 | Confirmed |
| 54 | Lookout, WyrmSpy and DragonEgg surveillanceware attributed to APT41 (2023-07-19) | `https://www.lookout.com/threat-intelligence/article/wyrmspy-dragonegg-surveillanceware-apt41` | 2026-11-03 | Confirmed |
| 55 | ThreatFabric, LightSpy and mobile payment systems, press announcement (2023-10-02) | https://www.threatfabric.com/blogs/threatfabric-uncovers-cyber-espionage-linked-to-state-backed-group-misusing-mobile-payment-systems | 2026-11-03 | Confirmed |
| 56 | Check Point Research, Silver Dragon Targets Organizations in Southeast Asia and Europe (2026-03-03) | https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/ | 2026-11-03 | Confirmed |
| 57 | Breakglass Intelligence, APT41/Winnti ELF cloud credential harvester (2026-04-03) | https://intel.breakglass.tech/post/apt41-winnti-elf-cloud-credential-harvester-alibaba-typosquat | 2026-11-03 | Confirmed |
| 58 | Sophos, Pacific Rim (2024-10-31) | `https://www.sophos.com/en-us/blog/pacific-rim-neutralizing-china-based-threat/` | 2026-11-03 | Confirmed |
| 59 | Microsoft Digital Crimes Unit, Barium notice of pleadings, E.D. Va. 1:17-cv-1224 | https://www.microsoft.com/en-us/corporate-responsibility/customer-security-trust/digital-crimes-unit/notice-of-pleadings/barium/ | 2026-11-03 | Confirmed |
| 60 | US v. Zhang Haoran and Tan Dailin, indictment, D.D.C. 19-cr-274 (2019-08-15) | https://www.justice.gov/opa/press-release/file/1317216/download | 2026-11-03 | Confirmed |
| 61 | US v. Jiang Lizhi, Qian Chuan and Fu Qiang, indictment, D.D.C. 1:20-cr-00158 (2020-08-11) | https://www.justice.gov/opa/press-release/file/1317206/download | 2026-11-03 | Confirmed |
| 62 | US v. Wong Ong Hua and Ling Yang Ching, indictment, D.D.C. 1:20-cr-00166 (filed 2020-08-18) | https://www.justice.gov/opa/press-release/file/1317211/download | 2026-11-03 | Confirmed |
| 63 | Security Affairs, coverage of the DOJ APT41 announcement (2020-09-17) | https://securityaffairs.com/108381/apt/apt41-doj-indictments.html | 2026-11-03 | Reported |
| 64 | FBI, APT 41 Group wanted listing | https://www.fbi.gov/wanted/cyber/apt-41-group | 2026-11-03 | Confirmed |
| 65 | HHS HC3, APT41 and Recent Activity, TLP:WHITE briefing (2022-09-22), copy hosted by the American Hospital Association | https://www.aha.org/system/files/media/file/2022/09/hhs-ocio-hc3-tlp-white-threat-briefing-apt41-and-recent-activity-september-22-9-22-22.pdf | 2026-11-03 | Confirmed |
| 66 | CISA, AA20-275A (initial version 2020-10-01) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-275a | 2026-11-03 | Confirmed |
| 67 | NSA, CISA and FBI, AA21-200B (initial version 2021-07-19) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b | 2026-11-03 | Confirmed |
| 68 | CISA, AA20-258A (2020-09-14); AA22-158A, AA25-239A, AA26-251A and AA26-281A were also read for APT41 mentions | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-258a | 2026-11-03 | Confirmed |
| 69 | NBC News, Chinese hackers stole millions in Covid relief money (2022-12-05) | https://www.nbcnews.com/tech/security/chinese-hackers-covid-fraud-millions-rcna59636 | 2026-11-03 | Reported |
| 70 | Taipei Times, Bureau names ransomware culprits (2020-05-17) | https://www.taipeitimes.com/News/taiwan/archives/2020/05/17/2003736564 | 2026-11-03 | Reported |
| 71 | Taipei Times, coverage of the National Security Bureau's 2025 cyber threat report (2026-01-05, page 2) | https://www.taipeitimes.com/News/front/archives/2026/01/05/2003850052/2 | 2026-11-03 | Reported |
| 72 | Singapore IMDA, Advisory for ICM Sector: APT41 Recent Activities | https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/apt41-recent-activities.pdf | 2026-11-03 | Confirmed |
| 73 | Germany BfV, Cyber-Brief Nr. 01/2019 (2019-12-06), copy hosted by the Brandenburg interior ministry | https://mik.brandenburg.de/sixcms/media.php/9/20191220_BfV_Brief.pdf | 2026-11-03 | Confirmed |
| 74 | GOV.UK search API, query APT41 | https://www.gov.uk/api/search.json?q=APT41 | 2026-11-03 | Confirmed |
| 75 | CISA, Known Exploited Vulnerabilities catalog, JSON feed (catalog version 2026.11.03) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |
| 76 | NIST National Vulnerability Database, CVE API 2.0 records for each CVE in Part 4 (example: CVE-2021-44228) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 | 2026-11-03 | Confirmed |
| 77 | TeamStarWolf library data and generated pages on main: data/attack/, data/weaknesses/, mitre/ and navigator/ | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-03 | Confirmed |
| 78 | MITRE ATT&CK, Versions | https://attack.mitre.org/resources/versions/ | 2026-11-03 | Confirmed |

## Related references

- [Threat Actors](/THREAT_ACTORS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Generated MITRE pages: group [APT41 `G0096`](/mitre/groups/G0096.md) and [Winnti Group `G0044`](/mitre/groups/G0044.md); campaigns [`C0017`](/mitre/campaigns/C0017.md), [`C0040` APT41 DUST](/mitre/campaigns/C0040.md) and [`C0012` Operation CuckooBees](/mitre/campaigns/C0012.md); software [ShadowPad `S0596`](/mitre/software/S0596.md), [PlugX `S0013`](/mitre/software/S0013.md), [KEYPLUG `S1051`](/mitre/software/S1051.md), [DUSTPAN `S1158`](/mitre/software/S1158.md), [DUSTTRAP `S1159`](/mitre/software/S1159.md), [MESSAGETAP `S0443`](/mitre/software/S0443.md), [Winnti for Linux `S0430`](/mitre/software/S0430.md) and [LightSpy `S1185`](/mitre/software/S1185.md); techniques [Exploit Public-Facing Application `T1190`](/mitre/techniques/T1190.md), [Compromise Software Supply Chain `T1195.002`](/mitre/techniques/T1195-002.md), [Code Signing `T1553.002`](/mitre/techniques/T1553-002.md), [Bootkit `T1542.003`](/mitre/techniques/T1542-003.md) and [Dead Drop Resolver `T1102.001`](/mitre/techniques/T1102-001.md)
- [The SharePoint ToolShell case study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), another China-linked mass-exploitation record
