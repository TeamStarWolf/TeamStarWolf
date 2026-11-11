# Other State-Linked Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Healthcare Security](/HEALTHCARE_SECURITY_REFERENCE.md), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Sea Turtle group page](/mitre/groups/G1041.md), [APT32 group page](/mitre/groups/G0050.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, threat hunters, vulnerability management teams and security teams supporting travelers, journalists or civil society

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 77 min (17,631 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a sourced account of the state-linked groups outside the five largest programs, how firmly each is attributed, what tradecraft and exploited vulnerabilities the record shows, or the defender lessons from DNS hijacking and network-path injection

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the inventory, and how firmly each group is attributed](#part-1-the-inventory-and-how-firmly-each-group-is-attributed), [Part 13: the defender view](#part-13-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Most of the people on the receiving end of state-linked hacking never read about China, Russia, Iran or North Korea in the reports that describe them. They are Emirati journalists and dissidents who opened a document that asked them to enable macros. They are students at Indian universities who received macro-laden documents. They are foreign diplomats in Minsk whose Windows Update prompt was not from Microsoft. They are foreign ministries in the Middle East and North Africa whose DNS records were quietly pointed somewhere else. They are Vietnamese activists abroad, Pakistani defense researchers, users tied to the Kurdish military in Iraq and, in one Lebanese operation, thousands of people in more than 21 countries, among them medical professionals, lawyers and journalists. This study gathers the public record on the state-linked groups outside the five largest programs, dates every event, and grades every claim by the source that supports it.

The record supports four plain statements. First, this tier is real and long-running: the groups in scope have been active since at least 2004 (Darkhotel), with most first seen between 2012 and 2017, and new public reporting continued through 2025 (**Confirmed**, ATT&CK and vendor primaries [12] [26] [42] [46] [53] [54]). Second, attribution here is softer than for the big five. Only one group in the set, Dark Caracal, is attributed by ATT&CK to a named government body (Lebanon's General Directorate of General Security), and Lookout and EFF said the operation was believed to be run from one of its buildings in Beirut (**Confirmed** [12] [40]). Most of the others are "suspected", "linked", or carry no named state at all. Third, the tradecraft is mostly document-and-lure work: across the 20 groups this study binds, the most common techniques are a malicious file opened by a user (13 groups), a spearphishing attachment (11), tool download (10) and exploitation of an old client application such as Office (9) (**Confirmed** [32]). Fourth, the most damaging routes in this tier use no software vulnerability at all: Sea Turtle took over DNS registrar accounts and registries to hijack name resolution, and MoustachedBouncer injected a fake Windows Update at internet service provider level (**Confirmed** [42] [48]).

For a security program, three practical points follow. Every CVE the opened record names for these groups (22 in total) is in CISA's Known Exploited Vulnerabilities catalog, nine of them in Microsoft Office or its MSCOMCTL control (KEV lists CVE-2014-4114 under Windows) (**Confirmed** [56]), and all nine Office CVEs entered KEV between 3 November 2021 and 3 March 2022, in its initial backfill (**Confirmed** [56]), so a patch rule keyed only to new KEV entries misses them (**Inferred**). DNS registrar accounts, certificate issuance and traffic from untrusted networks need to be on the exposure register even though they carry no CVE (**Inferred** from [42] [44] [48]). And for healthcare, the record shows exposure but not a mission: none of these groups' ATT&CK descriptions names healthcare, and the vendor record shows hospitals, medical research faculty and medical professionals hit as part of wider regional and political targeting (**Inferred** from [1] [35] [36] [40]).

The study also gives, in Part 11, a short comparison with the five largest programs, including the famous platforms that public reporting links to the United States. That record differs in kind: no US government body has attributed any of those platforms to itself, and the sponsor link rests on leaks, a vendor statement and a rival government's accusation (**Inferred** from [57] to [67]).

Evidence grade: the ATT&CK record, vendor reports, government advisories and the library's data files are each **Confirmed** against a primary source opened on 3 November 2026. Attribution statements are reported at the confidence each source states. Four items rest on secondary or contested sources and are graded **Reported**: the Stealth Falcon link to CVE-2025-33053 [50], the Indian press account of a Pakistan intelligence link to fake Aarogya Setu apps [37], the Vault 7 documents' authenticity [62] and China's attribution of the Northwestern Polytechnical University intrusion [67].

### Key facts at a glance

| Field | Value |
|---|---|
| Scope | State-linked groups outside China, Russia, Iran, North Korea and the United States; the MITRE mappings (Part 14) bind 20 groups: the 14 whose ATT&CK text names or suspects a state, a state body, a region (BITTER, "suspected South Asian") or a Hamas affiliation, or calls them likely state-sponsored, plus 6 that ATT&CK leaves stateless but that vendor primaries or ATT&CK's own overlap notes place in that tier (Confucius, Molerats, APT-C-23, PROMETHIUM, MoustachedBouncer and BlackOasis; the placement is **Inferred** where no source names a state) |
| Groups reviewed | 27 Enterprise ATT&CK groups checked against their live pages, plus the Mobile-only `G0097` Bouncing Golf; 20 of the 27 are bound in the MITRE mappings (Part 14) |
| Firmest attribution | Dark Caracal ([`G0070`](/mitre/groups/G0070.md)): ATT&CK attributes it to Lebanon's General Directorate of General Security; Lookout and EFF said it was believed run from a GDGS building in Beirut [12] [40] |
| Nexus by region | South Asia (India-linked: Patchwork, Sidewinder, BITTER, Confucius; Pakistan-linked: Transparent Tribe, SideCopy); Vietnam (APT32); South Korea (Darkhotel); Lebanon (Dark Caracal, Volatile Cedar); UAE, unconfirmed (Stealth Falcon); Hamas or Gaza (Molerats, WIRTE, APT-C-23); Türkiye (Sea Turtle); Belarus interests (MoustachedBouncer) |
| Oldest and newest | Darkhotel, active since at least 2004 [26]; Stealth Falcon's reported zero-day use against a defense organization in Türkiye, March 2025 (**Reported** [50]) |
| ATT&CK record | 154 distinct Enterprise techniques linked to the 20 bound groups; 2 campaigns ([`C0011`](/mitre/campaigns/C0011.md), [`C0033`](/mitre/campaigns/C0033.md)) [32] |
| Most-linked techniques | `T1204.002` Malicious File (13 groups), `T1566.001` Spearphishing Attachment (11), `T1105` Ingress Tool Transfer (10), `T1203` Exploitation for Client Execution (9) [32] |
| Exploited CVEs | 22 named by the opened primaries and live ATT&CK pages, all 22 in CISA KEV (catalog 2026.11.03); 9 Office or Office components, 7 Sea Turtle edge and server flaws, 6 with KEV "Known" ransomware use [56] |
| Government and platform action | CISA Emergency Directive 19-01 on DNS tampering, 22 January 2019, closed 8 January 2026 [44]; Meta takedowns of APT32 (2020) and of Bitter APT and APT36 (2022) [35] [39] |
| Healthcare | No in-scope ATT&CK description names healthcare; vendor records show hospitals (APT32), molecular medicine researchers (Patchwork) and medical professionals (Dark Caracal) among wider target sets [1] [35] [36] [40] |

### Key findings

- **Attribution in this tier is a ladder with few top rungs.** ATT&CK attributes Dark Caracal to a named Lebanese agency, calls APT32 "suspected Vietnam-based", Sidewinder "suspected Indian", Transparent Tribe "suspected Pakistan-based" and Darkhotel "suspected South Korean", says the UAE link for Stealth Falcon "has not been confirmed", and names no state at all for Confucius, BITTER, Molerats, APT-C-23, PROMETHIUM, NEODYMIUM, MoustachedBouncer, Machete and Metador (**Confirmed** [2] to [31]). Vendors sometimes go further: Mandiant assesses APT32 as aligned with Vietnamese state interests, Meta tied APT32 to an IT company in Vietnam, and ESET assesses with medium confidence that MoustachedBouncer is aligned with Belarus's interests (**Confirmed** [34] [35] [48]).
- **South Asia is the densest cluster.** Six groups target each other's governments and militaries: India-linked Patchwork, Sidewinder, Confucius and BITTER, and Pakistan-linked Transparent Tribe and SideCopy (**Confirmed** [3] to [9]). Gorgon Group, whose members ATT&CK suspects are Pakistan-based, mixes crime with attacks on UK, Spanish, Russian and US government bodies (**Confirmed** [10]). SideCopy's infection chain mimics Sidewinder's, and Confucius resembles Patchwork, so lookalike tradecraft is part of the picture (**Confirmed** [5] [9]).
- **Sea Turtle is the outlier with the widest blast radius.** Talos assessed with high confidence that a state-sponsored actor hijacked DNS through registrars, registries and ccTLD operators, hitting at least 40 organizations in 13 countries from about January 2017 to the first quarter of 2019, and the operator of Greece's .gr domain disclosed a compromise on 19 April 2019 (**Confirmed** [42] [43]). Hunt & Hackett tied 2021 to 2023 campaigns in the Netherlands to the same actor, and Microsoft tied 2024 and 2025 zero-day exploitation of a messaging server to Marbled Dust, a name it says overlaps Sea Turtle (**Confirmed** [45] [46]).
- **Surveillance of dissidents is a mission, not a side effect.** Stealth Falcon (Emirati journalists, activists and dissidents since 2012), Dark Caracal (thousands of victims, trojanized Signal and WhatsApp apps), APT32 (Vietnamese activists at home and abroad) and BlackOasis (a believed customer of Gamma Group, with opposition bloggers and activists among its interests) all target civil society (**Confirmed** [11] [12] [15] [35] [40] [49]).
- **Commercial spyware blurs who the actor is.** BlackOasis is believed to be a Gamma Group customer, Dark Caracal used FinFisher alongside custom tools, and Stealth Falcon's state link is circumstantial (**Confirmed** [15] [40] [49]). When the tooling is bought, the defensive signal is the commercial implant family as much as the operator (**Inferred**).
- **Old Office bugs still work.** Patchwork, BITTER, Sidewinder and Transparent Tribe exploit Office flaws from 2010 to 2018, among them CVE-2012-0158, CVE-2017-0199 and CVE-2017-11882; Kaspersky still recorded SideWinder exploiting CVE-2017-11882 in 2024 (**Confirmed** [3] [4] [6] [7] [53]).
- **Healthcare appears as collateral and as a lure.** Meta lists hospitals among APT32's business targets; Patchwork reached molecular medicine and biological sciences faculty for the first time in its late-2021 campaign; Dark Caracal compromised devices of medical professionals; Transparent Tribe spread a trojanized imitation of Aarogya Setu, India's COVID-19 tracking app and used a mental health survey as a lure (**Confirmed** [35] [36] [37] [38] [40]). The sustained healthcare harm in the government record comes from the big five (**Inferred** from Part 11).

### Top recommendations

1. Patch Office on a build-currency rule, not a "new KEV entry" rule. Nine of the 22 CVEs this tier is known to exploit are Office or Office components, most from 2010 to 2018, and all nine entered KEV between 3 November 2021 and 3 March 2022, in its initial backfill, not as fresh additions (**Confirmed** [56]; the rule is **Inferred**). Track Office build age across the fleet and close the gap between installed and supported builds. See the [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).
2. Put DNS and registrar accounts on the exposure register. Enable registry lock, require multi-factor authentication on every DNS management and registrar account, audit public DNS records, and monitor Certificate Transparency logs for certificates you did not request, as CISA's ED 19-01 and Talos advised (**Confirmed** [42] [43] [44]). None of this has a CVE, so a CVE-driven program will not raise it by itself.
3. Treat untrusted networks as hostile for travelers and in-country staff. Darkhotel selected traveling executives on hotel networks, and ESET's advice for foreign organizations in Belarus is an end-to-end encrypted VPN tunnel to a trusted network, so in-path injection has nothing to tamper with (**Confirmed** [48] [52]).
4. Block macros and watch what Office launches. Stealth Falcon's entry point was a macro document leading to a PowerShell backdoor, and malicious files and spearphishing attachments are the two most-linked techniques in the set (**Confirmed** [32] [49]). The library maps [Email Filtering](/mitre/d3fend/email-filtering.md) and [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) to these techniques (Part 14).
5. Control where mobile apps come from. Dark Caracal relied on trojanized Android messaging apps from a watering-hole site, and Transparent Tribe spread a trojanized imitation of Aarogya Setu, India's COVID-19 tracking app (**Confirmed** [37] [40]). Official stores only, with sideloading blocked by mobile device management, is the control. See the [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md).
6. Read the sponsor rung before acting on a name. A report that says "suspected" or names no state is evidence about tradecraft, not about intent. Carry the source's confidence into internal reporting.

## Scope and method

This study covers every Enterprise group in ATT&CK v20.0 whose ATT&CK description names a state nexus other than China, Russia, Iran, North Korea or the United States, or calls the group likely state-sponsored, plus the groups ATT&CK places close to them. The library's group data was filtered first, and each candidate's live ATT&CK page was then opened. On 3 November 2026 the live ATT&CK group index listed 182 group IDs, against 178 in the library's Enterprise data; the four missing are `G0097` Bouncing Golf (Mobile only), `G1000` ALLANITE (ICS), `G1027` CyberAv3ngers (ICS) and `G1029` UNC788 (Mobile), and none has a generated group page (**Confirmed** [1] [32]). Of the four, only Bouncing Golf falls in this study's scope. For all 27 in-scope Enterprise groups, the live ATT&CK description matched the library's text (citations stripped), and every Enterprise technique the library lists for them appeared on the live page (**Confirmed** [2] [32]).

Vendor and government primaries were then opened for the groups with a public record beyond ATT&CK. The study draws on five kinds of source: the MITRE ATT&CK pages for groups and campaigns; vendor and research reports (Mandiant, Kaspersky, Cisco Talos, ESET, Microsoft, Citizen Lab, Lookout and EFF, Hunt & Hackett, ThreatDown and Meta); US government directives and advisories; the CISA KEV catalog and NVD; and the TeamStarWolf library's own data files. Every source in the Sources table was opened on 3 November 2026.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the agency, vendor, research lab or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution, at the confidence it states; it does not upgrade the source's own confidence |
| Reported | Only a secondary source was available, or the claim is a leak publisher's or a rival government's assertion that no independent primary confirms |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

This study grades by source type (primary opened versus secondary only), the scheme the newer case studies use; under the case-studies README's original scheme, single-vendor reports would read as Reported.

Three rules govern the names. The study says which name each source uses ("Talos's Sea Turtle", "Microsoft's Marbled Dust", "Kaspersky's SideWinder") instead of merging labels. A source's own hedge travels with its claim ("suspected", "medium confidence", "not been confirmed"). And where a placement goes beyond what ATT&CK says, it is labelled: calling Confucius India-linked rests on its Patchwork overlap, and placing PROMETHIUM under Türkiye rests on victimology only (**Inferred** [5] [21]).

Some groups sit at the edge of this scope and have their home in a companion study in this series: POLONIUM, which researchers assess coordinated with actors affiliated with Iran's MOIS, belongs with the Iran record, and Winter Vivern, which ATT&CK links to Russian and Belorussian interests, belongs with the [Russia record](/case-studies/THREAT_ACTORS_RUSSIA.md). Each gets one paragraph here. The Equation group's United States link is summarized in Part 11 and belongs to the United States study. Events with their own case studies (Stuxnet, SolarWinds, Sandworm, APT41, Log4Shell and Change Healthcare) are linked, not repeated.

Two primaries could not be opened on 3 November 2026: Check Point Research's report on Stealth Falcon's 2025 zero-day (the claim rests on The Record's account and on NVD listing the Check Point report as a reference) and the Russian FSB statement on Operation Triangulation (Part 11). Tradecraft is described at the level the advisories use, by technique name and ID; the study reproduces no commands, payload strings or exploit details.

## Part 1: the inventory, and how firmly each group is attributed

The table lists every group reviewed, with ATT&CK's own attribution wording, the year ATT&CK gives for the start of activity, the targets ATT&CK names, and the library's Enterprise technique and software counts. Every row is **Confirmed** against the live ATT&CK page in the source column and the library data [32].

| Group | ATT&CK ID | Aliases (ATT&CK) | Attribution wording in ATT&CK | Active since | Targets named by ATT&CK | Techniques / software | Source |
|---|---|---|---|---|---|---|---|
| Dark Caracal | [`G0070`](/mitre/groups/G0070.md) | none | Attributed to the Lebanese General Directorate of General Security (GDGS) | 2012 | Not stated in the description | 12 / 3 (plus Mobile software) | [12] |
| Volatile Cedar | [`G0123`](/mitre/groups/G0123.md) | Lebanese Cedar | Lebanese group with political and ideological motives | 2012 | Individuals, companies and institutions worldwide | 5 / 2 | [13] |
| POLONIUM | [`G1005`](/mitre/groups/G1005.md) | Plaid Rain | Lebanon-based; researchers assess coordination with MOIS-affiliated actors | February 2022 | Israeli critical manufacturing, IT and defense industry | 7 / 2 | [14] |
| APT32 | [`G0050`](/mitre/groups/G0050.md) | SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH | Suspected Vietnam-based | 2014 | Private sector, foreign governments, dissidents, journalists; Vietnam, the Philippines, Laos, Cambodia | 78 / 15 | [2] |
| Patchwork | [`G0040`](/mitre/groups/G0040.md) | Hangover Group, Dropping Elephant, Chinastrats, MONSOON, Operation Hangover | Not definitively attributed; circumstantial evidence suggests a pro-Indian or Indian entity | First observed December 2015 | Diplomatic and government; US think tanks, March and April 2018 | 41 / 8 | [3] |
| Sidewinder | [`G0121`](/mitre/groups/G0121.md) | T-APT-04, Rattlesnake | Suspected Indian | 2012 | Government, military and business in Asia, mainly Pakistan, China, Nepal, Afghanistan | 30 / 1 | [4] |
| Confucius | [`G0142`](/mitre/groups/G0142.md) | none | No state named; similarities to Patchwork | 2013 | Military, high-profile, business and government targets in South Asia | 19 / 1 | [5] |
| BITTER | [`G1002`](/mitre/groups/G1002.md) | T-APT-17 | Suspected South Asian | 2013 | Government, energy, engineering; Pakistan, China, Bangladesh, Saudi Arabia | 16 / 1 | [6] |
| Transparent Tribe | [`G0134`](/mitre/groups/G0134.md) | COPPER FIELDSTONE, APT36, Mythic Leopard, ProjectM | Suspected Pakistan-based | 2013 | Diplomatic, defense and research organizations in India and Afghanistan | 14 / 5 | [7] |
| SideCopy | [`G1008`](/mitre/groups/G1008.md) | none | Pakistani group; infection chain mimics Sidewinder | 2019 | Indian and Afghan government personnel | 16 / 2 | [9] |
| Gorgon Group | [`G0078`](/mitre/groups/G0078.md) | none | Members suspected Pakistan-based or with Pakistan connections; criminal and targeted attacks | Not stated | Government organizations in the UK, Spain, Russia and the US | 16 / 4 | [10] |
| Stealth Falcon | [`G0038`](/mitre/groups/G0038.md) | none | Possible UAE government link on circumstantial evidence, not confirmed | 2012 | Emirati journalists, activists and dissidents | 16 / 0 | [11] |
| BlackOasis | [`G0063`](/mitre/groups/G0063.md) | none | Middle Eastern; believed customer of Gamma Group; reportedly close to NEODYMIUM | Not stated | UN figures, opposition bloggers, activists, regional correspondents, think tanks | 1 / 0 | [15] |
| Molerats | [`G0021`](/mitre/groups/G0021.md) | Operation Molerats, Gaza Cybergang | Arabic-speaking, politically motivated; no state named | 2012 | Mainly the Middle East, Europe and the US | 16 / 6 | [16] |
| WIRTE | [`G0090`](/mitre/groups/G0090.md) | Ashen Lepus | Believed subgroup of the Hamas-affiliated Gaza Cybergang | August 2018 | Diplomatic, financial, military, legal, technology; Middle East, North Africa, Europe; wipers against Israeli targets | 26 / 8 | [17] |
| APT-C-23 | [`G1028`](/mitre/groups/G1028.md) | Mantis, Arid Viper, Desert Falcon, TAG-63, Grey Karkadann, Big Bang APT, Two-tailed Scorpion | No sponsor named | 2014; mobile spyware since 2017 | The Middle East, including Israeli military assets | 0 Enterprise, 3 Mobile / 1 | [18] |
| Bouncing Golf | `G0097` (no library page) | none | A cyberespionage campaign; no sponsor named | Not stated | Middle Eastern countries | Mobile only (2) | [19] |
| Sea Turtle | [`G1041`](/mitre/groups/G1041.md) | Teal Kurma, Marbled Dust, Cosmic Wolf, SILICON | Türkiye-linked | 2017 | Espionage and service-provider compromise in Asia, Europe, North America; ccTLD registrars and DNS providers | 27 / 1 | [20] |
| PROMETHIUM | [`G0056`](/mitre/groups/G0056.md) | StrongPity | No state named; heavy emphasis on Turkish targets | 2012 | Global, with Turkish emphasis | 11 / 2 | [21] |
| NEODYMIUM | [`G0055`](/mitre/groups/G0055.md) | none | No state named; resembles PROMETHIUM; reportedly close to BlackOasis | May 2016 campaign | Heavily Turkish victims | 0 / 1 | [23] |
| MoustachedBouncer | [`G1019`](/mitre/groups/G1019.md) | none | No sponsor named in ATT&CK text | 2014 | Foreign embassies in Belarus | 8 / 3 | [24] |
| Winter Vivern | [`G1035`](/mitre/groups/G1035.md) | TA473, UAC-0114 | Linked to Russian and Belorussian interests | 2020 | European government and NGO entities; sporadic Indian and US victims | 27 / 0 | [25] |
| Darkhotel | [`G0012`](/mitre/groups/G0012.md) | DUBNIUM, Zigzag Hail | Suspected South Korean | 2004 | East Asian victims, including traveling executives over hotel networks | 24 / 0 | [26] |
| Higaisa | [`G0126`](/mitre/groups/G0126.md) | none | Suspected South Korean origins | As early as 2009; disclosed early 2019 | Government, public and trade organizations in North Korea; also China, Japan, Russia, Poland | 28 / 3 | [27] |
| The White Company | [`G0089`](/mitre/groups/G0089.md) | none | Likely state-sponsored; state not named | 2017 to 2018 (Operation Shaheen) | Government and military organizations in Pakistan | 7 / 2 | [28] |
| Machete | [`G0095`](/mitre/groups/G0095.md) | APT-C-43, El Machete | Suspected Spanish-speaking; no state named | 2010 | Government, intelligence, military, telecom, power; Latin America (especially Venezuela), the US, Europe, Russia, Asia | 11 / 1 | [29] |
| Metador | [`G1013`](/mitre/groups/G1013.md) | none | Suspected cyber espionage group; no state named | First reported September 2022 | A small number of telecoms, ISPs and universities in the Middle East and Africa | 9 / 2 | [30] |
| Equation | [`G0020`](/mitre/groups/G0020.md) | none | No sponsor named | Not stated | Not stated; zero-day use and hard-disk firmware overwrite | 4 / 0 | [31] |

Reading the ladder. One group (Dark Caracal) is attributed to a named agency. Five carry a "suspected" country (APT32, Sidewinder, Transparent Tribe, Darkhotel, Higaisa) and three a country link without the hedge (SideCopy "Pakistani", Volatile Cedar "Lebanese", Sea Turtle "Türkiye-linked"). One is explicitly unconfirmed (Stealth Falcon). The rest name a region, a language, a movement or nothing (**Inferred** from the table). That spread is the main difference between this tier and the big five, where governments publish joint attributions with named units (Part 11).

The healthcare question starts here. None of these 28 descriptions names healthcare as a target. The two ATT&CK groups whose descriptions do mention healthcare, `G0107` Whitefly (linked to the SingHealth attack) and `G0071` Orangeworm (healthcare targeting, likely corporate espionage), are outside this scope because ATT&CK names no sponsor for either (**Inferred** from [1]). The vendor record in Parts 2 to 5 and Part 10 fills in what ATT&CK does not.

## Part 2: South Asia

### India-linked groups

**Patchwork** ([`G0040`](/mitre/groups/G0040.md)) is the best documented of the India-linked groups. ATT&CK says it is not definitively attributed but that circumstantial evidence suggests a pro-Indian or Indian entity; it was first observed in December 2015, targets diplomatic and government sectors, and spearphished US think tanks in March and April 2018 (**Confirmed** [3]). ThreatDown (Malwarebytes) describes it plainly as an Indian threat actor and documented a late November to early December 2021 campaign against Pakistan's Ministry of Defense, defense and academic institutions and research institutes (**Confirmed** [36]). That campaign used RTF lures impersonating Pakistani authorities that exploited the Microsoft Equation Editor (`T1566.001`, `T1203`) to drop a BADNEWS variant ThreatDown calls Ragnatela; the post names no CVE (**Confirmed** [36]). For the first time, the targets included faculty researching molecular medicine and biological sciences (**Confirmed** [36]). ATT&CK's group page names six Office and Windows CVEs for Patchwork: CVE-2017-8570, CVE-2012-1856, CVE-2014-4114, CVE-2017-0199, CVE-2017-11882 and CVE-2015-1641 (**Confirmed** [3] [32]).

**Sidewinder** ([`G0121`](/mitre/groups/G0121.md)) is called a suspected Indian group by ATT&CK, active since at least 2012 against government, military and business entities in Asia, mainly Pakistan, China, Nepal and Afghanistan (**Confirmed** [4]). Kaspersky's October 2024 report widens the picture: government, military, logistics, infrastructure, telecom, finance, universities and oil trading across South Asia, the Middle East and Africa, reached through template-injection documents that exploit CVE-2017-11882 (`T1566.001`, `T1203`) and a post-exploitation tool Kaspersky calls StealerBot (**Confirmed** [53]). In the second half of 2024 the group sharply increased attacks on maritime infrastructure and logistics and targeted nuclear energy entities in South Asia (**Confirmed** [54]). Neither Kaspersky report names healthcare. ATT&CK lists CVE-2017-11882 and CVE-2020-0674 for the group and one software object, Koadic ([`S0250`](/mitre/software/S0250.md)) (**Confirmed** [4] [32]).

**Confucius** ([`G0142`](/mitre/groups/G0142.md)) has targeted military, high-profile, business and government targets in South Asia since at least 2013, and researchers note similarities to Patchwork; ATT&CK names no state, so calling it India-linked is **Inferred** from that overlap (**Confirmed** for the ATT&CK text [5]). Its one Enterprise software object is WarzoneRAT ([`S0670`](/mitre/software/S0670.md)) [32].

**BITTER** ([`G1002`](/mitre/groups/G1002.md)) is a suspected South Asian espionage group active since at least 2013 against government, energy and engineering organizations in Pakistan, China, Bangladesh and Saudi Arabia (**Confirmed** [6]). ATT&CK lists CVE-2012-0158, CVE-2017-11882, CVE-2018-0798 and CVE-2018-0802 for initial exploitation and CVE-2021-1732 for privilege escalation, and its software object ZxxZ ([`S1013`](/mitre/software/S1013.md)) (**Confirmed** [6] [32]). Meta reported action against Bitter APT in its second-quarter 2022 adversarial threat report; the landing page gives no sector detail (**Confirmed** [39]).

### Pakistan-linked groups

**Transparent Tribe** ([`G0134`](/mitre/groups/G0134.md)), also APT36, is called suspected Pakistan-based by ATT&CK and has targeted diplomatic, defense and research organizations in India and Afghanistan since at least 2013 (**Confirmed** [7]). Kaspersky describes it as typically targeting Indian military and government personnel (**Confirmed** [37]). In 2020 the group trojanized an Android package imitating Aarogya Setu, India's official COVID-19 tracking app, carrying a modified AhMyth remote access tool (**Confirmed** [37]). Kaspersky cites Indian press reports for a Pakistan intelligence link to fake Aarogya Setu apps sent to Indian Army groups, and for the Indian Army's warning to personnel in late April 2020; that link is **Reported** [37]. From December 2021, the group went after students at Indian universities and colleges with CrimsonRAT delivered through macro documents, a shift away from its usual government and military targets, and ATT&CK records the activity as campaign [`C0011`](/mitre/campaigns/C0011.md), still ongoing as of July 2022 (**Confirmed** [8] [38]). One lure file in that campaign was themed as a mental health survey: a health-themed lure, not a health-sector victim (**Confirmed** [38]). Talos assesses with high confidence that a hosting provider in Lahore ran parts of the infrastructure (**Confirmed** [38]). Meta's 2022 report links APT36 to state-linked actors in Pakistan (**Confirmed** [39]). ATT&CK names CVE-2012-0158 and CVE-2010-3333 for the group (**Confirmed** [7]).

**SideCopy** ([`G1008`](/mitre/groups/G1008.md)) is a Pakistani group that has targeted South Asian countries, including Indian and Afghan government personnel, since at least 2019, with an infection chain that mimics Sidewinder's; its software objects are Action RAT ([`S1028`](/mitre/software/S1028.md)) and AuTo Stealer ([`S1029`](/mitre/software/S1029.md)) (**Confirmed** [9] [32]).

**Gorgon Group** ([`G0078`](/mitre/groups/G0078.md)) has members ATT&CK suspects are Pakistan-based or have Pakistan connections, and it mixes criminal campaigns with targeted attacks on government organizations in the UK, Spain, Russia and the US (**Confirmed** [10]). Because of the criminal mix it is not bound in Part 14.

**The White Company** ([`G0089`](/mitre/groups/G0089.md)) is the reverse case: ATT&CK calls it a likely state-sponsored actor but does not name the state, and from 2017 through 2018 it ran Operation Shaheen against government and military organizations in Pakistan, with NETWIRE ([`S0198`](/mitre/software/S0198.md)) and Revenge RAT ([`S0379`](/mitre/software/S0379.md)) (**Confirmed** [28] [32]).

### What South Asia shows

The South Asian record is a contest between neighbours, conducted through documents. Lookalike chains (SideCopy copying Sidewinder, Confucius resembling Patchwork) mean that a technique match is weak evidence of who is behind an intrusion (**Inferred** from [5] [9]). For an organization outside the region, exposure comes through staff, partners and research ties to South Asian institutions rather than through direct targeting (**Inferred** from [53] and the target lists above).

## Part 3: Southeast and East Asia

### APT32 (Vietnam)

APT32 ([`G0050`](/mitre/groups/G0050.md)) has the largest ATT&CK record in this tier: 78 techniques and 15 software objects in the library's data (**Confirmed** [2] [32]). ATT&CK calls it a suspected Vietnam-based group active since at least 2014, targeting the private sector, foreign governments, dissidents and journalists, focused on Vietnam, the Philippines, Laos and Cambodia, with heavy use of strategic web compromises (**Confirmed** [2]).

Mandiant's May 2017 report assesses APT32 as aligned with Vietnamese state interests. It dates intrusions against foreign companies investing in Vietnam to at least 2014, against dissidents and journalists to at least 2013, and records the targeting of a Western legislature in 2014 (**Confirmed** [34]). The sectors Mandiant lists are manufacturing, consumer products, hospitality, network security, technology infrastructure, banking, media, foreign governments and the Vietnamese diaspora, in Vietnam, Germany, the Philippines, China, the US and Australia; healthcare is not named (**Confirmed** [34]). Delivery was macro-document spearphishing (`T1566.001`, `T1204.002`) carrying WINDSHIELD ([`S0155`](/mitre/software/S0155.md)), KOMPROGO ([`S0156`](/mitre/software/S0156.md)), SOUNDBITE ([`S0157`](/mitre/software/S0157.md)), PHOREAL ([`S0158`](/mitre/software/S0158.md)) and Cobalt Strike BEACON ([`S0154`](/mitre/software/S0154.md)) (**Confirmed** [34] [32]).

In December 2020 Meta linked APT32 to CyberOne Group, an IT company in Vietnam (**Confirmed** [35]). Meta's target list is wider than Mandiant's: Vietnamese activists at home and abroad, the governments of Laos and Cambodia, NGOs, news agencies, and businesses in IT, hospitality, agriculture, commodities, hospitals, retail, automotive and mobile services (**Confirmed** [35]). The methods were fake personas and Pages, malicious Play Store apps, watering holes, DLL side-loading and malicious documents (**Confirmed** [35]).

### Darkhotel and Higaisa (South Korea, suspected)

Darkhotel ([`G0012`](/mitre/groups/G0012.md)) is the oldest group in the set. ATT&CK calls it a suspected South Korean group that has targeted East Asian victims since at least 2004, including traveling executives over hotel Internet networks (**Confirmed** [26]). Kaspersky's November 2014 report describes the hotel-network delivery, Flash zero-days in spearphishing, and abuse of weak certificates from at least ten certificate authorities, later replaced by stolen legitimate certificates (`T1189`, `T1203`, `T1553.002`); Kaspersky made no language or nationality attribution, so the South Korean suspicion is ATT&CK's wording, not Kaspersky's (**Confirmed** [52]). ATT&CK names CVE-2015-8651 for the group (**Confirmed** [26]).

Higaisa ([`G0126`](/mitre/groups/G0126.md)) is suspected to have South Korean origins and targets government, public and trade organizations in North Korea, as well as China, Japan, Russia and Poland. It was first disclosed in early 2019 but assessed to have operated since as early as 2009 (**Confirmed** [27]). Its suspected origin rests on ATT&CK's wording alone and no vendor primary for it was opened, so it is not bound in Part 14; its 28 techniques sit on its group page.

## Part 4: the Middle East

### Lebanon

Dark Caracal ([`G0070`](/mitre/groups/G0070.md)) is the clearest case of a named government body in this tier. ATT&CK attributes it to the Lebanese General Directorate of General Security and dates it to at least 2012 (**Confirmed** [12]). The January 2018 Lookout and EFF report says the operation was believed to be administered from a GDGS building in Beirut and counted thousands of victims in more than 21 countries, with hundreds of gigabytes exfiltrated (**Confirmed** [40]). The victims included military personnel, enterprises, medical professionals, activists, journalists, lawyers and educational institutions, and targets also included governments, utilities, financial institutions, manufacturers and defense contractors (**Confirmed** [40]). The main vector was trojanized Signal and WhatsApp Android apps that relied on permissions the user granted, with no exploit, and EFF named victims in the US, Canada, Germany, Lebanon and France (**Confirmed** [41]). The actor also used a watering-hole site, phishing through WhatsApp and Facebook, and physical access (`T1189`, `T1566.003`), with a toolset of Pallas, FinFisher ([`S0182`](/mitre/software/S0182.md)), Bandook ([`S0234`](/mitre/software/S0234.md)) and CrossRAT ([`S0235`](/mitre/software/S0235.md)) (**Confirmed** [40] [32]). Pallas is a Mobile-only ATT&CK object with no library page.

Volatile Cedar ([`G0123`](/mitre/groups/G0123.md)) is a Lebanese group operating since 2012 with political and ideological motives against individuals, companies and institutions worldwide, with Caterpillar WebShell ([`S0572`](/mitre/software/S0572.md)) and Explosive ([`S0569`](/mitre/software/S0569.md)) (**Confirmed** [13] [32]).

POLONIUM ([`G1005`](/mitre/groups/G1005.md)) is Lebanon-based by ATT&CK's account and has targeted Israeli critical manufacturing, IT and defense-industry organizations since at least February 2022; researchers assess it coordinated with actors affiliated with Iran's MOIS, and its tools are CreepyDrive ([`S1023`](/mitre/software/S1023.md)) and CreepySnail ([`S1024`](/mitre/software/S1024.md)) (**Confirmed** [14] [32]). Its fuller home is the Iran record in this series.

### The Gulf: Stealth Falcon and BlackOasis

Stealth Falcon ([`G0038`](/mitre/groups/G0038.md)) has run targeted spyware attacks against Emirati journalists, activists and dissidents since at least 2012; ATT&CK says circumstantial evidence suggests a possible UAE government link that has not been confirmed (**Confirmed** [11]). Citizen Lab's May 2016 report documented targets including a London-based journalist, delivery by macro documents and tracked links (`T1566.001`, `T1566.002`, `T1204.002`), a PowerShell backdoor with RC4-encrypted command and control, and theft of browser and credential-vault data (`T1059.001`, `T1573.001`, `T1555.003`, `T1555.004`) (**Confirmed** [49]). In 2025, according to Check Point as relayed by The Record, Stealth Falcon exploited CVE-2025-33053, a WebDAV and Internet Shortcut working-directory flaw, as a zero-day against a major defense organization in Türkiye in March 2025, using tools Check Point calls Horus Agent and Horus Loader (**Reported** [50]). The Check Point primary could not be opened; NVD lists it as a reference (**Confirmed** [51]). CISA added CVE-2025-33053 to KEV on 10 June 2025, with a due date of 1 July 2025 and CWE-73, and NVD published it the same day with a CVSS 3.1 score of 8.8 from Microsoft (**Confirmed** [51] [56]).

BlackOasis ([`G0063`](/mitre/groups/G0063.md)) is described by ATT&CK as a Middle Eastern group believed to be a customer of Gamma Group, with interests that include UN figures, opposition bloggers, activists, regional correspondents and think tanks; it is reportedly closely associated with NEODYMIUM (**Confirmed** [15]). Its ATT&CK record is one technique.

### Hamas and Gaza

Three groups carry a Gaza or Hamas nexus but no state sponsor. Molerats ([`G0021`](/mitre/groups/G0021.md)), the Gaza Cybergang, is an Arabic-speaking, politically motivated group operating since 2012, with victims mainly in the Middle East, Europe and the US (**Confirmed** [16]). WIRTE ([`G0090`](/mitre/groups/G0090.md)) is believed to be a subgroup of the Hamas-affiliated Gaza Cybergang, active since at least August 2018 against diplomatic, financial, military, legal and technology organizations in the Middle East, North Africa and Europe, and it has added wiper attacks against Israeli targets (**Confirmed** [17]). APT-C-23 ([`G1028`](/mitre/groups/G1028.md)), also Arid Viper and Desert Falcon, has been active since at least 2014, focused on the Middle East including Israeli military assets, and has built Android and iOS spyware since 2017; the library holds no Enterprise technique and three Mobile techniques for it (**Confirmed** [18] [32]). Bouncing Golf (`G0097`) is a Mobile-domain cyberespionage campaign against Middle Eastern countries with no sponsor named and no library page (**Confirmed** [19]).

## Part 5: Türkiye and Belarus

### Sea Turtle

Sea Turtle ([`G1041`](/mitre/groups/G1041.md)) is called a Türkiye-linked actor by ATT&CK, active since at least 2017 in espionage and service-provider compromise across Asia, Europe and North America, and notable for targeting ccTLD registrars and DNS providers to hijack resolution and spoof login portals (**Confirmed** [20]). Its record is the most consequential in this tier.

Talos's April 2019 report assessed with high confidence that an advanced state-sponsored actor was behind the activity, without naming a nation (**Confirmed** [42]). The campaign ran from about January 2017 to the first quarter of 2019 and hit at least 40 organizations in 13 countries: primarily foreign ministries, militaries, intelligence bodies and energy organizations in the Middle East and North Africa, with telecoms, ISPs, IT firms, registrars and a registry as secondary victims; no healthcare organization appears (**Confirmed** [42]). The method was DNS record hijacking through registrar and registry compromise (`T1584.002`), adversary-in-the-middle servers that harvested credentials (`T1557`), certificates obtained for victim domains (`T1588.004`) and stolen credentials (`T1078`) (**Confirmed** [42]). Talos listed seven CVEs the actor exploited (`T1190`) and said the list is likely incomplete: CVE-2009-1151, CVE-2014-6271, CVE-2017-3881, CVE-2017-6736, CVE-2017-12617, CVE-2018-0296 and CVE-2018-7600, all now in KEV (**Confirmed** [42] [56]).

Talos's July 2019 follow-up reported that ICS-Forth, the operator of Greece's .gr ccTLD, disclosed a compromise on 19 April 2019 and that attacker access lasted through at least 24 April (**Confirmed** [43]). It recommended registry lock, multi-factor authentication for DNS management and VPN access, DNSSEC signing and validation, restricting IMAP, and passive DNS monitoring (**Confirmed** [43]).

Before either Talos report, on 22 January 2019, CISA issued Emergency Directive 19-01, ordering federal agencies to audit DNS records, change DNS account passwords, add multi-factor authentication to DNS accounts and monitor Certificate Transparency logs, each within 10 business days (**Confirmed** [44]). The directive names no actor, so linking it to Sea Turtle is **Inferred** from timing and subject. CISA closed the directive on 8 January 2026 (**Confirmed** [44]).

Hunt & Hackett's January 2024 report attributed 2021 to 2023 campaigns in the Netherlands against telecom, media, ISPs, IT service providers and Kurdish websites to Sea Turtle, which it assesses acts in line with Turkish interests (**Confirmed** [45]). Access came through compromised cPanel accounts and SSH (`T1078`, `T1133`). The actor used SnappyTCP ([`S1163`](/mitre/software/S1163.md)), cleared logs and command history (`T1685.006`, `T1690`), and staged an email archive in a public web directory (`T1114.001`, `T1074.002`, `T1560.001`) (**Confirmed** [45]).

In May 2025 Microsoft reported that Marbled Dust, a Türkiye-affiliated espionage actor it says overlaps Sea Turtle and UNC1326, exploited CVE-2025-27920 in Output Messenger (`T1190`) against users tied to the Kurdish military in Iraq, with activity from April 2024 (**Confirmed** [46]). Microsoft says the actor historically targets European and Middle Eastern governments opposing Turkish interests, plus telecom and IT; no healthcare is named (**Confirmed** [46]).

### PROMETHIUM and NEODYMIUM

PROMETHIUM ([`G0056`](/mitre/groups/G0056.md)), also StrongPity, is an espionage group active since at least 2012, operating globally with a heavy emphasis on Turkish targets; ATT&CK names no state, so a Türkiye link is **Inferred** from victimology only (**Confirmed** for the ATT&CK text [21]). Campaign [`C0033`](/mitre/campaigns/C0033.md) used StrongPity ([`S0491`](/mitre/software/S0491.md)) against Android users, and ATT&CK calls it the group's first publicly documented mobile campaign; the library dates it from May 2016 to January 2023 (**Confirmed** [22] [32]). NEODYMIUM ([`G0055`](/mitre/groups/G0055.md)) ran a campaign in May 2016 that heavily targeted Turkish victims, resembles PROMETHIUM, and is reportedly closely associated with BlackOasis, though ATT&CK found no evidence the names are aliases; no state is named, and its one software object is Wingbird ([`S0176`](/mitre/software/S0176.md)) (**Confirmed** [23] [32]).

### Belarus

MoustachedBouncer ([`G1019`](/mitre/groups/G1019.md)) is described by ATT&CK as a cyberespionage group active since at least 2014 that targets foreign embassies in Belarus, with no sponsor named (**Confirmed** [24]). ESET's August 2023 report assesses with medium confidence that it is aligned with Belarus's interests (**Confirmed** [48]). Since 2020 it has likely tampered with traffic at ISP level to serve a fake Windows Update (`T1659` Content Injection) that delivers Disco ([`S1088`](/mitre/software/S1088.md)); it also uses NightClub ([`S1090`](/mitre/software/S1090.md)) with SMTP command and control and SharpDisco ([`S1089`](/mitre/software/S1089.md)), and a Disco plugin uses CVE-2021-1732 for privilege escalation (`T1068`) (**Confirmed** [48] [32]). ESET's advice is an end-to-end encrypted VPN tunnel to a trusted network (**Confirmed** [48]).

UNC1151, also known through the Ghostwriter information operations, is linked by Mandiant with high confidence to the Belarusian government and with moderate confidence to its military, without ruling out Russian contributions (**Confirmed** [47]). From 2016 to 2021 it targeted mainly Ukraine, Lithuania, Latvia, Poland and Germany: governments (defense ministries most often), webmail providers, businesses, intergovernmental bodies, dissidents and media, chiefly through credential phishing (`T1566.002`); no healthcare is named (**Confirmed** [47]). No UNC1151 or Ghostwriter object exists in the library's ATT&CK data, so it cannot be bound by ID (**Confirmed** [32]).

Winter Vivern ([`G1035`](/mitre/groups/G1035.md)) is linked by ATT&CK to Russian and Belorussian interests, active since at least 2020 against European government and NGO entities, with sporadic Indian and US victims, using document phishing and server-side exploitation (**Confirmed** [25]). Its home is the Russia record in this series.

## Part 6: unnamed sponsors and Spanish-speaking groups

Three groups appear in espionage reporting with no state attached. Machete ([`G0095`](/mitre/groups/G0095.md)) is a suspected Spanish-speaking group active since at least 2010, focused on Latin America and especially Venezuela, plus the US, Europe, Russia and Asia, against government, intelligence, military, telecom and power organizations (**Confirmed** [29]). Metador ([`G1013`](/mitre/groups/G1013.md)) was first reported in September 2022 against a small number of telecoms, ISPs and universities in the Middle East and Africa; it was named after a malware string, researchers expected Spanish-language command-and-control responses, and its tools are Mafalda ([`S1060`](/mitre/software/S1060.md)) and metaMain ([`S1059`](/mitre/software/S1059.md)) (**Confirmed** [30] [32]). Among the groups reviewed here, The White Company (Part 2) is the only one ATT&CK calls likely state-sponsored without naming the state (**Confirmed** [28]).

These groups sit in the inventory because their targets and resourcing look like state work, but a defender should treat the sponsor question as open. They are not bound in Part 14, except The White Company.

## Part 7: the operational record

One row per dated campaign, report or government action in the verified record for this tier. "Since" rows mark the start of activity as ATT&CK or the vendor states it.

| Date | Group | Event or report | Targets | Confidence as the source states it | Grade | Source |
|---|---|---|---|---|---|---|
| 2004 onward | Darkhotel | Active since at least 2004, including hotel-network targeting of traveling executives | East Asian victims | ATT&CK: suspected South Korean | Confirmed | [26] |
| 2009 onward | Higaisa | Assessed to have operated since as early as 2009 | Government, public and trade organizations in North Korea, China, Japan, Russia, Poland | ATT&CK: suspected South Korean origins | Confirmed | [27] |
| 2010 onward | Machete | Active since at least 2010 | Government, intelligence, military, telecom, power; Latin America | ATT&CK: suspected Spanish-speaking | Confirmed | [29] |
| 2012 onward | Dark Caracal | Operating since at least 2012 | Thousands of victims in 21+ countries | ATT&CK: attributed to GDGS; Lookout and EFF: believed run from a GDGS building | Confirmed | [12] [40] |
| 2012 onward | Stealth Falcon | Targeted spyware attacks since at least 2012 | Emirati journalists, activists, dissidents | ATT&CK: UAE link not confirmed | Confirmed | [11] |
| 2012 onward | Sidewinder, Volatile Cedar, Molerats, PROMETHIUM | Each active since 2012 by ATT&CK's account | South Asia; worldwide; Middle East and Europe; Turkish emphasis | As in Part 1 | Confirmed | [4] [13] [16] [21] |
| 2013 onward | APT32 | Targeting of dissidents and journalists since at least 2013 | Vietnamese dissidents and journalists | Mandiant: aligned with Vietnamese state interests | Confirmed | [34] |
| 2013 onward | Transparent Tribe, Confucius, BITTER | Each active since at least 2013 | India and Afghanistan; South Asia; Pakistan, China, Bangladesh, Saudi Arabia | As in Part 1 | Confirmed | [7] [5] [6] |
| 2014 | APT32 | Intrusions against foreign companies investing in Vietnam; targeting of a Western legislature | Private sector; a Western legislature | Mandiant | Confirmed | [34] |
| 2014 onward | MoustachedBouncer, APT-C-23 | Each active since at least 2014 | Foreign embassies in Belarus; the Middle East | ATT&CK names no sponsor for either | Confirmed | [24] [18] |
| 2014-11-10 | Darkhotel | Kaspersky report on hotel-network delivery, Flash zero-days and certificate abuse | Traveling executives | Kaspersky makes no nationality attribution | Confirmed | [52] |
| 2015-12 | Patchwork | First observed | Diplomatic and government | ATT&CK: pro-Indian or Indian entity suggested | Confirmed | [3] |
| 2016 to 2021 | UNC1151 | Credential phishing and Ghostwriter-linked operations | Ukraine, Lithuania, Latvia, Poland, Germany | Mandiant: high confidence Belarusian government | Confirmed | [47] |
| 2016-05 | NEODYMIUM | Campaign heavily targeting Turkish victims | Turkish victims | No state named | Confirmed | [23] |
| 2016-05 to 2023-01 | PROMETHIUM | Campaign C0033, StrongPity against Android users | Android users | No state named | Confirmed | [22] |
| 2016-05-29 | Stealth Falcon | Citizen Lab report on macro documents and a PowerShell backdoor | Emirati dissidents; a London-based journalist | Circumstantial UAE link | Confirmed | [49] |
| 2017 onward | APT-C-23 | Android and iOS spyware development | The Middle East | No sponsor named | Confirmed | [18] |
| 2017-01 to 2019-Q1 | Sea Turtle | DNS hijacking through registrars and registries | 40+ organizations in 13 countries, mainly MENA national security bodies | Talos: high confidence, state-sponsored, nation not named | Confirmed | [42] |
| 2017 to 2018 | The White Company | Operation Shaheen | Government and military organizations in Pakistan | ATT&CK: likely state-sponsored | Confirmed | [28] |
| 2017-05-14 | APT32 | Mandiant report on APT32 | Private sector, foreign governments, diaspora | Aligned with Vietnamese state interests | Confirmed | [34] |
| 2018-01-18 | Dark Caracal | Lookout and EFF report | Military, enterprises, medical professionals, activists, journalists, lawyers, educational institutions | Believed run from a GDGS building | Confirmed | [40] [41] |
| 2018-03 to 2018-04 | Patchwork | Spearphishing of US think tanks | US think tanks | ATT&CK | Confirmed | [3] |
| 2018-08 onward | WIRTE | Active since at least August 2018 | Middle East, North Africa, Europe | Believed Gaza Cybergang subgroup | Confirmed | [17] |
| 2019 onward | SideCopy | Active since at least 2019 | Indian and Afghan government personnel | ATT&CK: Pakistani | Confirmed | [9] |
| 2019-01-22 | (no actor named) | CISA Emergency Directive 19-01, DNS infrastructure tampering | US federal agencies' DNS | Names no actor | Confirmed | [44] |
| Early 2019 | Higaisa | First public disclosure | As above | ATT&CK | Confirmed | [27] |
| 2019-04-17 | Sea Turtle | Talos report, seven CVEs named | As above | High confidence | Confirmed | [42] |
| 2019-04-19 to 2019-04-24 | Sea Turtle | ICS-Forth (.gr ccTLD) compromise disclosed; access through at least 24 April | The .gr registry | Talos | Confirmed | [43] |
| 2019-07-09 | Sea Turtle | Talos follow-up with hardening advice | Registries and their customers | Talos | Confirmed | [43] |
| 2020 | Transparent Tribe | Trojanized Aarogya Setu COVID-19 app with modified AhMyth | Android users (app, Confirmed); Indian Army groups (Reported via Kaspersky) | Kaspersky; the Pakistan intelligence link is from Indian press | Confirmed (app); Reported (link) | [37] |
| 2020-04 | Transparent Tribe | Indian Army warns personnel about fake Aarogya Setu apps | Indian Army | Indian press via Kaspersky | Reported | [37] |
| 2020 onward | MoustachedBouncer | ISP-level injection of a fake Windows Update | Foreign embassies in Belarus | ESET: likely | Confirmed | [48] |
| 2020 onward | Winter Vivern | Active since at least 2020 | European government and NGOs | ATT&CK: Russian and Belorussian interests | Confirmed | [25] |
| 2020-08-26 | Transparent Tribe | Kaspersky "Transparent Tribe, part 2" | Indian military and government personnel | Kaspersky | Confirmed | [37] |
| 2020-12-10 | APT32 | Meta takedown; APT32 linked to CyberOne Group | Activists, governments of Laos and Cambodia, NGOs, news agencies, businesses including hospitals | Meta | Confirmed | [35] |
| 2021-11 to 2021-12 | Patchwork | Campaign against Pakistan's Ministry of Defense and research institutes, including molecular medicine faculty (published 2022-01-07) | Pakistani defense, academic and research bodies | ThreatDown: Indian threat actor | Confirmed | [36] |
| 2021-11-16 | UNC1151 | Mandiant links UNC1151 to the Belarusian government | As above | High confidence (government), moderate (military) | Confirmed | [47] |
| 2021 to 2023 | Sea Turtle | Campaigns in the Netherlands through cPanel and SSH access | Telecom, media, ISPs, IT providers, Kurdish websites | Hunt & Hackett: in line with Turkish interests | Confirmed | [45] |
| 2021-12 to 2022-07 | Transparent Tribe | Campaign C0011 against students (Talos, published 2022-07-13) | Indian universities and colleges | Talos: high confidence on Lahore hosting | Confirmed | [8] [38] |
| 2022-02 onward | POLONIUM | Targeting of Israeli organizations | Israeli critical manufacturing, IT, defense industry | ATT&CK: Lebanon-based, coordinated with MOIS-affiliated actors | Confirmed | [14] |
| 2022-08-04 | Bitter APT, APT36 | Meta second-quarter 2022 adversarial threat report | Not detailed on the landing page | Meta: APT36 linked to state-linked actors in Pakistan | Confirmed | [39] |
| 2022-09 | Metador | First reported | Telecoms, ISPs, universities in the Middle East and Africa | No state named | Confirmed | [30] |
| 2023-08-10 | MoustachedBouncer | ESET report | Foreign embassies in Belarus | Medium confidence, aligned with Belarus | Confirmed | [48] |
| 2024-01-05 | Sea Turtle | Hunt & Hackett report | As above | In line with Turkish interests | Confirmed | [45] |
| 2024-04 onward | Marbled Dust (Sea Turtle overlap) | Exploitation of CVE-2025-27920 in Output Messenger (published 2025-05-12) | Users tied to the Kurdish military in Iraq | Microsoft: Türkiye-affiliated | Confirmed | [46] |
| 2024-10-15 | SideWinder | Kaspersky report; CVE-2017-11882 and StealerBot | Government, military, logistics, telecom, finance, universities across South Asia, the Middle East, Africa | Kaspersky | Confirmed | [53] |
| 2024 second half | SideWinder | Sharp increase against maritime and logistics; nuclear energy targets (published 2025-03-10) | Maritime infrastructure; South Asian nuclear energy | Kaspersky | Confirmed | [54] |
| 2025-03 | Stealth Falcon | CVE-2025-33053 used as a zero-day (Check Point via The Record, 2025-06-10) | A major defense organization in Türkiye | Check Point, primary not opened | Reported | [50] |
| 2025-06-10 | (CVE) | CVE-2025-33053 added to KEV and published by NVD | Windows users | CISA and NVD | Confirmed | [51] [56] |
| 2026-01-08 | (no actor named) | CISA closes ED 19-01 | US federal agencies | CISA | Confirmed | [44] |
| 2026-07-31 | Several groups | Live ATT&CK pages for G0050, G0040, G0012, G0038, G0121, G0134, G1002, G1019 and G1041 show v20.0 content last modified on this date; G0070 shows version 1.4, last modified 2 September 2026 | Not applicable | MITRE | Confirmed | [20] [32] |

Reading the record by era. Before 2014 the public record is mostly "since" dates assigned later. From 2014 to 2019 the large vendor reports land (Darkhotel, APT32, Stealth Falcon, Dark Caracal, Sea Turtle), and the US government responds to DNS tampering with an emergency directive. From 2020 on, platform takedowns (Meta) join the record, and the targeting shifts toward students, mobile users and, for SideWinder, maritime and nuclear sectors (**Inferred** from the table).

## Part 8: tooling

The library holds a generated page for every Enterprise software object below; the counts and names come from the library's group data, which matched the live group pages (**Confirmed** [32]).

| Group | ATT&CK software (Enterprise) |
|---|---|
| APT32 | [Arp `S0099`](/mitre/software/S0099.md), [Cobalt Strike `S0154`](/mitre/software/S0154.md), [Denis `S0354`](/mitre/software/S0354.md), [Goopy `S0477`](/mitre/software/S0477.md), [ipconfig `S0100`](/mitre/software/S0100.md), [Kerrdown `S0585`](/mitre/software/S0585.md), [KOMPROGO `S0156`](/mitre/software/S0156.md), [Mimikatz `S0002`](/mitre/software/S0002.md), [Net `S0039`](/mitre/software/S0039.md), [netsh `S0108`](/mitre/software/S0108.md), [OSX_OCEANLOTUS.D `S0352`](/mitre/software/S0352.md), [PHOREAL `S0158`](/mitre/software/S0158.md), [RotaJakiro `S1078`](/mitre/software/S1078.md), [SOUNDBITE `S0157`](/mitre/software/S0157.md), [WINDSHIELD `S0155`](/mitre/software/S0155.md) |
| Patchwork | [AutoIt backdoor `S0129`](/mitre/software/S0129.md), [BackConfig `S0475`](/mitre/software/S0475.md), [BADNEWS `S0128`](/mitre/software/S0128.md), [NDiskMonitor `S0272`](/mitre/software/S0272.md), [PowerSploit `S0194`](/mitre/software/S0194.md), [QuasarRAT `S0262`](/mitre/software/S0262.md), [TINYTYPHON `S0131`](/mitre/software/S0131.md), [Unknown Logger `S0130`](/mitre/software/S0130.md); Mobile-only VajraSpy (`S9006`, no library page) |
| Sidewinder | [Koadic `S0250`](/mitre/software/S0250.md) |
| Confucius | [WarzoneRAT `S0670`](/mitre/software/S0670.md) |
| BITTER | [ZxxZ `S1013`](/mitre/software/S1013.md) |
| Transparent Tribe | [Crimson `S0115`](/mitre/software/S0115.md), [DarkComet `S0334`](/mitre/software/S0334.md), [njRAT `S0385`](/mitre/software/S0385.md), [ObliqueRAT `S0644`](/mitre/software/S0644.md), [Peppy `S0643`](/mitre/software/S0643.md) |
| SideCopy | [Action RAT `S1028`](/mitre/software/S1028.md), [AuTo Stealer `S1029`](/mitre/software/S1029.md) |
| Dark Caracal | [Bandook `S0234`](/mitre/software/S0234.md), [CrossRAT `S0235`](/mitre/software/S0235.md), [FinFisher `S0182`](/mitre/software/S0182.md); Mobile-only Pallas (`S0399`, no library page) |
| Volatile Cedar | [Caterpillar WebShell `S0572`](/mitre/software/S0572.md), [Explosive `S0569`](/mitre/software/S0569.md) |
| POLONIUM | [CreepyDrive `S1023`](/mitre/software/S1023.md), [CreepySnail `S1024`](/mitre/software/S1024.md) |
| Molerats | [DropBook `S0547`](/mitre/software/S0547.md), [DustySky `S0062`](/mitre/software/S0062.md), [MoleNet `S0553`](/mitre/software/S0553.md), [PoisonIvy `S0012`](/mitre/software/S0012.md), [SharpStage `S0546`](/mitre/software/S0546.md), [Spark `S0543`](/mitre/software/S0543.md) |
| WIRTE | [AshTag `S9031`](/mitre/software/S9031.md), [Empire `S0363`](/mitre/software/S0363.md), [Ferocious `S0679`](/mitre/software/S0679.md), [Havoc `S1229`](/mitre/software/S1229.md), [IronWind `S9029`](/mitre/software/S9029.md), [LitePower `S0680`](/mitre/software/S0680.md), [Rclone `S1040`](/mitre/software/S1040.md), [SameCoin `S9030`](/mitre/software/S9030.md) |
| APT-C-23 | [Micropsia `S0339`](/mitre/software/S0339.md) |
| Sea Turtle | [SnappyTCP `S1163`](/mitre/software/S1163.md) |
| MoustachedBouncer | [Disco `S1088`](/mitre/software/S1088.md), [NightClub `S1090`](/mitre/software/S1090.md), [SharpDisco `S1089`](/mitre/software/S1089.md) |
| PROMETHIUM | [StrongPity `S0491`](/mitre/software/S0491.md), [Truvasys `S0178`](/mitre/software/S0178.md) |
| NEODYMIUM | [Wingbird `S0176`](/mitre/software/S0176.md) |
| The White Company | [NETWIRE `S0198`](/mitre/software/S0198.md), [Revenge RAT `S0379`](/mitre/software/S0379.md) |
| Gorgon Group | [NanoCore `S0336`](/mitre/software/S0336.md), [QuasarRAT `S0262`](/mitre/software/S0262.md), [Remcos `S0332`](/mitre/software/S0332.md), [njRAT `S0385`](/mitre/software/S0385.md) |
| Higaisa | [PlugX `S0013`](/mitre/software/S0013.md), [certutil `S0160`](/mitre/software/S0160.md), [gh0st RAT `S0032`](/mitre/software/S0032.md) |
| Machete | [Machete `S0409`](/mitre/software/S0409.md) |
| Metador | [Mafalda `S1060`](/mitre/software/S1060.md), [metaMain `S1059`](/mitre/software/S1059.md) |
| Darkhotel, Stealth Falcon, BlackOasis, Winter Vivern | None in ATT&CK |

Three patterns stand out. Commodity remote access tools (njRAT, DarkComet, QuasarRAT, NETWIRE, Revenge RAT, PoisonIvy) recur across South Asian and Gaza groups, so a hit on one is a weak attribution signal (**Inferred**). Commercial surveillance software appears directly (FinFisher with Dark Caracal; BlackOasis as a Gamma Group customer), which means the "state actor" is sometimes a buyer of tooling (**Confirmed** [15] [40]; the conclusion is **Inferred**). And the two infrastructure-level actors carry small, purpose-built toolsets: one implant for Sea Turtle, three for MoustachedBouncer (**Confirmed** [32]).

## Part 9: exploited vulnerabilities

Every CVE that the opened primaries and live ATT&CK pages name for this group set, 22 in all, is in the CISA KEV catalog (catalog version 2026.11.03, 1,767 entries) (**Confirmed** [56]). Six of them carry KEV's "Known" flag for use in ransomware campaigns.

| CVE | Named for | KEV ransomware use "Known" | Source |
|---|---|---|---|
| CVE-2025-33053 | Stealth Falcon (Reported) | No | [50] [51] [56] |
| CVE-2021-1732 | MoustachedBouncer (Disco plugin), BITTER | Yes | [48] [6] [56] |
| CVE-2017-11882 | Sidewinder, BITTER, Patchwork | Yes | [4] [6] [3] [53] [56] |
| CVE-2018-0802 | BITTER | Yes | [6] [56] |
| CVE-2018-0798 | BITTER | No | [6] [56] |
| CVE-2012-0158 | BITTER, Transparent Tribe | Yes | [6] [7] [56] |
| CVE-2017-0199 | Patchwork | Yes | [3] [56] |
| CVE-2017-8570 | Patchwork | No | [3] [56] |
| CVE-2012-1856 | Patchwork | No | [3] [56] |
| CVE-2014-4114 | Patchwork | No | [3] [56] |
| CVE-2015-1641 | Patchwork | No | [3] [56] |
| CVE-2010-3333 | Transparent Tribe | No | [7] [56] |
| CVE-2020-0674 | Sidewinder | No | [4] [56] |
| CVE-2015-8651 | Darkhotel | No | [26] [56] |
| CVE-2009-1151 | Sea Turtle | No | [42] [56] |
| CVE-2014-6271 | Sea Turtle | No | [42] [56] |
| CVE-2017-3881 | Sea Turtle | No | [42] [56] |
| CVE-2017-6736 | Sea Turtle | No | [42] [56] |
| CVE-2017-12617 | Sea Turtle | No | [42] [56] |
| CVE-2018-0296 | Sea Turtle | No | [42] [56] |
| CVE-2018-7600 | Sea Turtle | Yes | [42] [56] |
| CVE-2025-27920 | Marbled Dust (Sea Turtle overlap) | No | [46] [56] |

Microsoft's report for Marbled Dust (Part 5) names CVE-2025-27920 in Output Messenger; CISA added it to KEV on 19 May 2025 with CWE-22 (**Confirmed** [46] [56]).

What this means for vulnerability management:

1. **Office build currency is the control that matters for this tier.** Nine of the 22 are Microsoft Office or its MSCOMCTL control (KEV lists CVE-2014-4114 under Windows), and most date from 2010 to 2018 (**Confirmed** [56]). All nine Office CVEs entered KEV between 3 November 2021 and 3 March 2022, in its initial backfill, and 19 of the 22 were added between 3 November 2021 and 25 March 2022; the exceptions are CVE-2015-8651 (25 May 2022), CVE-2025-27920 (19 May 2025) and CVE-2025-33053 (10 June 2025) (**Confirmed** [56]). A remediation SLA keyed only to new KEV additions never raises them (**Inferred**).
2. **Seven are internet-edge and server flaws** that Talos listed for Sea Turtle, with Talos's own warning that the list is likely incomplete (**Confirmed** [42]).
3. **Ransomware and state exploitation overlap on the same flaws.** Six of the 22 carry KEV's "Known" ransomware flag (**Confirmed** [56]), so one patch closes both doors (**Inferred**).
4. **The highest-impact routes have no CVE.** Registrar and DNS account compromise (Sea Turtle) and ISP-level injection (MoustachedBouncer) need non-CVE exposure items: registrar multi-factor authentication and registry lock, Certificate Transparency monitoring and encrypted egress from untrusted networks (**Inferred** from [42] [44] [48]).

## Part 10: targets by sector and geography, and the healthcare view

### By sector and geography

| Sector | Groups and evidence | Geography | Source |
|---|---|---|---|
| Government, foreign ministries, diplomats | Patchwork, Sidewinder, BITTER, Transparent Tribe, SideCopy, Sea Turtle, MoustachedBouncer, Winter Vivern, UNC1151, The White Company, Machete, Higaisa, APT32 | South Asia; MENA; Belarus; Europe; Latin America; Southeast Asia | [3] [4] [6] [7] [9] [20] [24] [25] [27] [28] [29] [42] [47] |
| Military and defense industry | Sidewinder, Transparent Tribe, Patchwork (Pakistan's Ministry of Defense, 2021), POLONIUM, Stealth Falcon (defense organization in Türkiye, 2025, Reported), Dark Caracal | South Asia; Israel; Türkiye | [4] [7] [14] [36] [40] [50] |
| Civil society: journalists, activists, dissidents, diaspora | Stealth Falcon, Dark Caracal, APT32, BlackOasis | UAE and London; 21+ countries; Vietnam and abroad | [11] [15] [35] [40] [49] |
| Telecom, ISPs, IT and hosting providers, registrars | Sea Turtle, Metador, SideWinder, Marbled Dust | MENA; the Netherlands; Africa | [30] [42] [45] [46] [53] |
| Energy, nuclear, maritime and logistics | BITTER (energy), Sea Turtle (energy bodies), SideWinder (nuclear, maritime) | Pakistan, China, Bangladesh, Saudi Arabia; MENA; South Asia | [6] [42] [54] |
| Academia and research | Transparent Tribe (students, C0011), Patchwork (molecular medicine faculty), Metador (universities), SideWinder (universities) | India; Pakistan; Middle East and Africa | [8] [36] [30] [53] |
| Business | APT32 (manufacturing, hospitality, banking, media and more), Darkhotel (traveling executives) | Vietnam, Germany, the Philippines, China, the US, Australia; East Asia | [34] [35] [52] |

### The healthcare view

This tier does not target healthcare as a mission. None of the in-scope ATT&CK descriptions names healthcare (**Inferred** from [1]). What the vendor record shows is healthcare as collateral or opportunity inside wider regional and political targeting (**Inferred** [35] [36] [40]):

- **APT32:** Meta lists hospitals among the businesses APT32 targeted, alongside IT, hospitality, agriculture, commodities, retail, automotive and mobile services (**Confirmed** [35]). Mandiant's 2017 sector list does not name healthcare (**Confirmed** [34]).
- **Patchwork:** the late-2021 campaign reached faculty researching molecular medicine and biological sciences for the first time, as part of a campaign against Pakistan's defense and research establishment (**Confirmed** [36]).
- **Dark Caracal:** medical professionals were among the victims whose devices were compromised (**Confirmed** [40]).
- **Transparent Tribe:** health themes appeared as lures, not targets: a trojanized imitation of the Aarogya Setu COVID-19 tracking app in 2020 and a mental health survey document in 2022 (**Confirmed** [37] [38]).

For a hospital or health system in the US or Europe, the practical exposure from this tier is staff mobile devices (trojanized messaging and health apps), clinicians and researchers who travel, and research collaborations with South and Southeast Asian institutions (**Inferred** [53] and the target lists above). The 2020 joint CISA and NCSC advisory AA20-126A shows the general pattern of state actors going after COVID-19 response bodies (healthcare, pharmaceutical companies, universities, medical research and local government) through password spraying and VPN and Citrix exploitation (`T1110.003`, `T1190`), but it names no group or state, so it is context, not attribution (**Confirmed** [55]).

The sustained, named healthcare harm in the government record comes from the larger programs, summarized in Part 11: North Korean ransomware against hospitals, Iranian access brokering, and espionage against vaccine research (**Inferred** from Part 11). The 2024 Change Healthcare ransomware attack has its own study, [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md).

## Part 11: the wider record, the five largest programs in brief

The groups above are one tier of a larger landscape. The five largest state programs each have a companion study in this series; this Part gives the dated public record for each in short, so the tiers can be compared, with particular attention to the platforms public reporting links to the United States and to the healthcare record. Events with their own case studies are linked, not repeated.

### Platforms linked in reporting to the United States

ATT&CK names no sponsor for the Equation group ([`G0020`](/mitre/groups/G0020.md)); it describes zero-day exploit use and the ability to overwrite hard-disk firmware (**Confirmed** [31]). The vendor record is detailed about the tools and silent about the state:

- **Equation (Kaspersky, 16 February 2015).** Kaspersky GReAT named the Equation group, linked it to the Stuxnet and Flame groups, and named no state. Its tools are EquationLaser, EquationDrug, DoubleFantasy, TripleFantasy, Fanny, GrayFish and GROK, and one module can reprogram firmware on more than a dozen hard-drive brands. Kaspersky estimated thousands, possibly tens of thousands, of victims in government, telecoms, aerospace, energy, nuclear and finance (**Confirmed** [57]).
- **Fanny and Stuxnet (17 February 2015).** The Fanny worm used two zero-days, the LNK flaw CVE-2010-2568 and MS09-025, that Stuxnet added later (June 2009 and March 2010), and Kaspersky concluded Equation had them years earlier. Sinkhole data showed more than 11,200 IP addresses, 59.36% in Pakistan (**Confirmed** [58]). Stuxnet ([`S0603`](/mitre/software/S0603.md)) has its own study, [Stuxnet](/case-studies/STUXNET.md).
- **Flame (28 May 2012).** About 20 MB of attack toolkit with victims in Iran, Lebanon, Syria and Israel; Kaspersky said a nation state probably sponsored it but that nothing ties Flame to a specific state (**Confirmed** [59]; ATT&CK object [`S0143`](/mitre/software/S0143.md)).
- **Duqu 2.0 (10 June 2015).** Kaspersky found a successor to the 2011 Duqu inside its own network, with some 2014 to 2015 infections tied to venues of the P5+1 Iran nuclear talks; no state named (**Confirmed** [60]; Duqu is [`S0038`](/mitre/software/S0038.md)).
- **Regin (24 November 2014).** 27 victims in 14 countries, among them Belgium, Germany, Iran, Russia and Syria, and a log of GSM base-station controller commands against 136 cells in April and May 2008. Kaspersky called nation-state support likely, warned the metadata could be a false flag, and named no state (**Confirmed** [61]; [`S0019`](/mitre/software/S0019.md)).
- **The Lamberts (11 April 2017).** Kaspersky's name for the actor Symantec calls Longhorn, with colour-coded tools (Black, Blue, Green, White, Pink and Gray Lambert) in use since at least 2008 and first exposed in 2014 through Black Lambert and CVE-2014-4148; no state named (**Confirmed** [63]; Green Lambert is [`S0690`](/mitre/software/S0690.md)).
- **Vault 7 (7 March 2017).** WikiLeaks' "Year Zero" release claims to be 8,761 documents from the CIA's Center for Cyber Intelligence and names the Engineering Development Group and UMBRAGE. This is the leak publisher's claim; authenticity was never officially confirmed (**Reported** [62]).
- **The Shadow Brokers dump and WannaCry (April and May 2017).** Microsoft's security response center found that EternalBlue, EternalRomance, EternalChampion and EternalSynergy were already fixed by MS17-010, with other exploits covered by MS08-067, MS09-050, MS10-061 and MS14-068 (**Confirmed** [64]). After WannaCry, Microsoft stated that the exploits were stolen from the NSA, noted the patch had shipped on 14 March 2017, and called for a Digital Geneva Convention: a vendor statement, not a US government admission (**Confirmed** [65]).
- **Operation Triangulation (1 June 2023).** Kaspersky disclosed a zero-click iMessage chain on iOS found on its staff phones, with traces back to 2019, and made no state attribution; a 2025 update notes that MITRE added an ATT&CK campaign page (**Confirmed** [66]). That campaign is not in the library's data, so it is not linked. The Russian FSB statement blaming US intelligence could not be opened and is not relied on.
- **Northwestern Polytechnical University (disclosed 22 June 2022; report 5 September 2022).** China's CVERC, working with 360, attributes the intrusion to NSA TAO, saying TAO used more than 40 NSA-specific tools (it names FoxAcid, SecondDate and NOPEN) and that more than 1,100 attack chains were found. This is a rival government's accusation, and the attribution is unverified (**Reported** [67]).

Taken together: no US government body has attributed any of these platforms to itself. The sponsor link rests on leaks (the Shadow Brokers and Vault 7), Microsoft's 2017 statement about NSA-origin exploits, and China's CVERC accusation (a Russian FSB statement on Triangulation exists but could not be opened), while the vendors describe the tools without naming a state (**Inferred** [57] to [67]). That is the reverse of the big-four record below, where Western governments publish named-unit attributions. A defender's lesson from this set is about capability, not attribution: firmware implants, GSM network access and zero-click mobile chains were all in the record by 2015 to 2023.

### China

China's public record moved from vendor exposure to multinational attribution and sanctions; its companion study is [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md). Mandiant attributed APT1 ([`G0006`](/mitre/groups/G0006.md)) to PLA Unit 61398 of the General Staff 3rd Department, 2nd Bureau, with 141 victims and economic espionage since 2006 (**Confirmed** [68], 19 February 2013). On 20 December 2018 the UK's NCSC held APT10 ([`G0045`](/mitre/groups/G0045.md), Cloud Hopper) responsible "with the highest level of probability" and judged the MSS responsible, for a campaign against managed service providers and their clients since at least 2016 (**Confirmed** [69]). Microsoft attributed the Exchange zero-day exploitation (CVE-2021-26855, -26857, -26858, -27065) to HAFNIUM ([`G0125`](/mitre/groups/G0125.md)), a state-sponsored group operating from China whose targets included infectious disease researchers (**Confirmed** [70], 2 March 2021); that event's home is [Operation Exchange Marauder](/case-studies/EXCHANGE_MARAUDER_2021.md). The White House attributed that exploitation to MSS-affiliated actors with a high degree of confidence on 19 July 2021, joined by the EU, UK and NATO, and named contract hackers doing ransomware for profit and four MSS hackers charged over a campaign that included healthcare (**Confirmed** [71]). The same day, AA21-200A tied the indicted APT40 ([`G0065`](/mitre/groups/G0065.md)) actors to the MSS Hainan State Security Department and its front company Hainan Xiandun, active since at least 2009 (**Confirmed** [72]). In July 2024, eight countries led by Australia's ACSC assessed that APT40 acts for the MSS and turns public proofs of concept into working exploits within hours or days, including Log4Shell CVE-2021-44228 (**Confirmed** [73]; see [Log4Shell](/case-studies/LOG4SHELL.md)).

Volt Typhoon ([`G1017`](/mitre/groups/G1017.md)) marked a shift from theft to preparation. Microsoft reported on 24 May 2023 a China-based state-sponsored actor active since mid-2021, with targets in Guam and elsewhere in the US, building, with moderate confidence, the ability to disrupt US to Asia communications in a crisis, with initial access through Fortinet FortiGuard devices (**Confirmed** [74]). The same-day advisory AA23-144A described its living-off-the-land tradecraft (**Confirmed** [75]), and on 7 February 2024 AA24-038A assessed with high confidence that it was pre-positioning on IT networks in communications, energy, transport and water to disrupt operational technology in a crisis, with some footholds held for at least five years (**Confirmed** [76]). Salt Typhoon ([`G1045`](/mitre/groups/G1045.md)) followed: on 27 August 2025, 23 agencies from 13 countries described actors targeting backbone, provider-edge and customer-edge routers of major telecoms since at least 2021, and named three Chinese companies (Sichuan Juxinhe, Beijing Huanyu Tianqiong and Sichuan Zhixin Ruijie) that supply the PLA and MSS (**Confirmed** [77]). On 25 March 2024 the UK said APT31 ([`G0128`](/mitre/groups/G0128.md), ATT&CK's ZIRCONIUM) ran 2021 reconnaissance against parliamentarians and that a China state-affiliated actor likely compromised the Electoral Commission between late 2021 and October 2022, sanctioning the MSS front Wuhan Xiaoruizhi and two APT31 members; the release uses both "almost certain" and "highly likely" in different places (**Confirmed** [78]). On 3 January 2025 Treasury sanctioned Integrity Technology Group of Beijing for supporting Flax Typhoon, active since at least 2021 (**Confirmed** [79]). For healthcare, the FBI and CISA warned on 13 May 2020 of likely PRC targeting and compromise of COVID-19 research, healthcare and pharmaceutical organizations (**Confirmed** [80]). The fullest single-group record is in [APT41: The Public Record](/case-studies/APT41_PUBLIC_RECORD.md).

### Russia

The companion study is [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md). On 4 October 2018 the UK's NCSC said the GRU was almost certainly responsible for a campaign of attacks, naming aliases including APT28 ([`G0007`](/mitre/groups/G0007.md)) and Sandworm, and operations against WADA medical files (August 2016), the DNC (2016), Bad Rabbit ([`S0606`](/mitre/software/S0606.md), October 2017) and attempts on the OPCW (2018) (**Confirmed** [81]). On 16 July 2020 NCSC and Canada's CSE assessed that APT29 ([`G0016`](/mitre/groups/G0016.md)) is almost certainly part of the Russian intelligence services and had targeted COVID-19 vaccine development in Canada, the US and the UK with WellMess ([`S0514`](/mitre/software/S0514.md)) and WellMail ([`S0515`](/mitre/software/S0515.md)), with NSA agreement (**Confirmed** [82]). The White House named the SVR as the perpetrator of the SolarWinds Orion campaign on 15 April 2021; that event's home is [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md) (**Confirmed** [84]). AA21-116A covered SVR tradecraft (**Confirmed** [83]); AA23-347A reported SVR exploitation of JetBrains TeamCity CVE-2023-42793 from late September 2023, compromising a few dozen companies opportunistically while possibly preparing supply-chain access (**Confirmed** [85]); and Microsoft reported that Midnight Blizzard password-sprayed a legacy test tenant from late November 2023 and reached senior leadership email, detected on 12 January 2024 (**Confirmed** [89]). On 9 May 2023 Five Eyes agencies attributed the Snake implant (developed as Uroburos, [`S0022`](/mitre/software/S0022.md), from late 2003) to a unit of FSB Center 16 that also runs Turla ([`G0010`](/mitre/groups/G0010.md)), with infrastructure in more than 50 countries (**Confirmed** [86]). AA25-141A (21 May 2025) attributed to GRU Unit 26165 (APT28) a campaign since 2022 against logistics and technology firms that move aid to Ukraine and against IP cameras, about 81% of them in Ukraine (**Confirmed** [87]). AA24-249A (5 September 2024) attributed operations to GRU Unit 29155, overlapping Cadet Blizzard and Ember Bear ([`G1003`](/mitre/groups/G1003.md)), including WhisperGate ([`S0689`](/mitre/software/S0689.md)) from 13 January 2022, scanning across 26 NATO members and healthcare among the targeted sectors (**Confirmed** [88]). Sandworm's record is in [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md).

### North Korea

North Korea's record is the one most tied to healthcare harm. WannaCry ([`S0366`](/mitre/software/S0366.md)) hit NHS England on 12 May 2017: the UK National Audit Office found at least 81 of 236 trusts and 595 GP practices affected, with 6,912 cancelled appointments recorded and an estimated 19,000 or more, and unpatched or unsupported Windows as the common weakness; the report names no perpetrator (**Confirmed** [91]). On 19 December 2017 the UK said the NCSC assessed it highly likely that Lazarus Group ([`G0032`](/mitre/groups/G0032.md)) was behind WannaCry, which hit about 300,000 computers in 150 countries including 48 NHS trusts (**Confirmed** [90]). On 13 September 2019 Treasury sanctioned Lazarus Group, Bluenoroff and Andariel ([`G0138`](/mitre/groups/G0138.md)) as controlled by the RGB, citing Sony Pictures (2014), the theft of about $80M from Bangladesh Bank (2016) and WannaCry, including over $112M in NHS cost (**Confirmed** [92]). The NHS harm was collateral damage, not targeting (**Inferred** [91] [92]).

The money record runs alongside: the BeagleBoyz, an RGB element overlapping APT38 ([`G0082`](/mitre/groups/G0082.md)) to varying degrees, abused SWIFT from 2015 and ran FASTCash ATM cash-outs from 2016 against banks in 38 nations, with nearly $2B attempted by public estimate (**Confirmed** [93]); TraderTraitor trojanized crypto applications from at least 2020 and links to AppleJeus ([`S0584`](/mitre/software/S0584.md)) (**Confirmed** [95]); and the FBI attributed the theft of about $1.5B from Bybit, on or about 21 February 2025, to TraderTraitor (**Confirmed** [99]). Kimsuky ([`G0094`](/mitre/groups/G0094.md)), active since about 2012, is most likely tasked by the regime with global intelligence gathering (**Confirmed** [94]).

Then the targeting of healthcare became direct. The FBI assessed that North Korean state-sponsored actors had used Maui ransomware against US healthcare and public health organizations since May 2021, encrypting electronic health record, diagnostics, imaging and intranet servers (**Confirmed** [96]). A February 2023 joint advisory from US agencies, HHS and South Korea's NIS and DSA described state-sponsored ransomware (Maui, H0lyGh0st, sometimes posing as REvil) against US and South Korean healthcare, with entry through [Log4Shell](/case-studies/LOG4SHELL.md) CVE-2021-44228, SonicWall CVE-2021-20038 and TerraMaster CVE-2022-24990, and a trojanized X-Popup messenger used by Korean hospitals (**Confirmed** [97]). In July 2024, agencies including NCSC-UK and the ROK NIS placed Andariel in the RGB 3rd Bureau and said it funds espionage against defense, aerospace, nuclear and engineering targets with ransomware against US healthcare, sometimes hitting the same victim for both (**Confirmed** [98]).

### Iran

Iran's record mixes state espionage, destructive attacks and access brokering into the ransomware economy. Treasury sanctioned two Iran-based men in November 2018 for converting SamSam ransom bitcoin into rial; SamSam had more than 200 victims including hospitals, and Treasury does not state state sponsorship (**Confirmed** [106]). Treasury sanctioned APT39 ([`G0087`](/mitre/groups/G0087.md)), 45 individuals and the front company Rana Intelligence Computing for MOIS work against dissidents, journalists and the travel sector on 17 September 2020 (**Confirmed** [102]). In June 2021 an Iranian government-sponsored APT exploiting Fortinet and ProxyShell flaws reached the environmental control networks of a US children's hospital (**Confirmed** [100]). AA22-055A described MuddyWater ([`G0069`](/mitre/groups/G0069.md)) as a subordinate element of the MOIS, active since about 2018, with PowGoop ([`S1046`](/mitre/software/S1046.md)), Small Sieve ([`S1035`](/mitre/software/S1035.md)), Canopy (ATT&CK's STARWHALE, [`S1037`](/mitre/software/S1037.md)), Mori ([`S1047`](/mitre/software/S1047.md)) and POWERSTATS ([`S0223`](/mitre/software/S0223.md)) (**Confirmed** [101] [32]). Iranian state actors calling themselves HomeLand Justice hit the Government of Albania with ransomware and wipers in July 2022 after about 14 months of access, then struck again in September 2022 (**Confirmed** [107]). IRGC-affiliated CyberAv3ngers compromised at least 75 Unitronics PLCs and HMIs, at least 34 in US water, between 22 November 2023 and January 2024, with healthcare among the affected sectors; the advisory maps only Enterprise ATT&CK, and CyberAv3ngers (`G1027`) has no library group page (**Confirmed** [103] [32]). The FBI assesses that Pioneer Kitten (ATT&CK's Fox Kitten, [`G0117`](/mitre/groups/G0117.md)) is Iranian state-sponsored and sells access to NoEscape, RansomHouse and ALPHV affiliates, ransomware work it says is likely not sanctioned by the state, with US healthcare facilities among the victims (**Confirmed** [104]). Since October 2023 Iranian actors have used password spraying and MFA push bombing against healthcare and other sectors, and some of that activity may come from third parties who bought the access (**Confirmed** [105]). Google TAG reported that APT42 ([`G1044`](/mitre/groups/G1044.md)), associated with the IRGC, phished people tied to the Biden and Trump campaigns in May and June 2024 (**Confirmed** [108]). On 30 June 2025 a joint fact sheet warned of possible Iranian activity against US critical infrastructure and firms tied to Israel while saying no coordinated campaign had been observed (**Confirmed** [109]).

### How state-actor healthcare harm takes shape

In the government record, state-actor harm to healthcare takes three forms (**Inferred** [96] to [98], [100], [104], [105], [82], [70]):

1. **Ransomware for revenue:** North Korea's Maui and H0lyGh0st operations and Andariel's ransomware-funded espionage (AA22-187A, AA23-040A, AA24-207A).
2. **Access brokering and partnering with ransomware groups:** Iranian actors (AA21-321A, AA24-241A, AA24-290A).
3. **Espionage against vaccine and disease research:** APT29 in 2020 and HAFNIUM in 2021.

WannaCry's harm to the NHS was collateral damage, not targeting. The other-states tier in Parts 1 to 10 fits none of the three forms as a pattern; its healthcare contact is incidental (**Inferred**).

## Part 12: the government and platform record for this tier

The big five draw joint advisories, indictments and sanctions. This tier draws far fewer, and they are mostly indirect:

- **CISA Emergency Directive 19-01 (22 January 2019, closed 8 January 2026)** is the one US government action in this record aimed at the DNS-tampering method Sea Turtle used, though it names no actor (**Confirmed** [44]; the link to Sea Turtle is **Inferred**).
- **Meta's takedowns** are the most direct public actions against named groups: APT32 and its tie to CyberOne Group (10 December 2020), and Bitter APT and APT36 (4 August 2022) (**Confirmed** [35] [39]).
- **The Indian Army's warning** about fake Aarogya Setu apps (late April 2020) is known only through Indian press reports cited by Kaspersky (**Reported** [37]).
- **CISA's KEV listing of CVE-2025-33053** on 10 June 2025, the day it was disclosed, is the government trace of Stealth Falcon's reported zero-day (**Confirmed** [56]; the Stealth Falcon link is **Reported** [50]).

No indictment, sanctions designation or joint multinational attribution names any of the 20 bound groups in the verified record (**Inferred** from the sources opened). The contrast is itself a finding: defenders facing this tier work from vendor and platform reporting, not from government advisories with technique tables.

## Part 13: the defender view

### What a document-and-lure tier means in practice

The technique counts describe a familiar chain: a spearphishing attachment or link, a user opening a file, an old Office or browser exploit or a macro, then script interpreters (PowerShell and Visual Basic, eight groups each) and run-key persistence (eight groups) (**Confirmed** [32]; the reading is **Inferred**). The good news for defenders is that the controls already exist and are well understood. The bad news is that they must work everywhere, including on the laptops of travelers and the phones of staff.

### Hardening and hunting leads, by source

For DNS and registrar compromise (Talos [42] [43] and CISA ED 19-01 [44]):

- Registry lock with out-of-band confirmation, and multi-factor authentication on every DNS management and registrar account (**Confirmed** [42] [43] [44]).
- Audit public DNS records, change DNS account passwords, and monitor Certificate Transparency logs for certificates you did not request (**Confirmed** [44]).
- DNSSEC-sign domains and validate in recursive resolvers; restrict IMAP; monitor passive DNS for abnormal record changes (**Confirmed** [43]).

For hosting and IT service providers (Hunt & Hackett [45]): Sea Turtle's 2021 to 2023 access came through compromised cPanel accounts and SSH, and the actor cleared logs and command history (**Confirmed** [45]). Keep centralized logs outside the host, put multi-factor authentication on hosting control panels, and reduce internet-exposed SSH (**Inferred** from [45]).

For in-path injection (ESET [48]): an end-to-end encrypted VPN tunnel, ideally out-of-band rather than from the endpoint, providing connectivity from a trusted network, which ESET recommends for foreign organizations in Belarus; treat any Windows Update prompt that does not come from Microsoft's update channel as hostile, and watch for SMTP command and control from workstations (**Confirmed** for the VPN advice [48]; the detection points are **Inferred** from [48]).

For dissident and journalist surveillance (Citizen Lab [49], Lookout and EFF [40] [41]): block macros in files from the internet and alert on PowerShell launched from Office (`T1059.001` following `T1204.002`); allow mobile apps from official stores only and block sideloading (**Inferred** from [40] [49]).

For travelers (Kaspersky [52]): use a VPN before anything else on hotel and guest Wi-Fi, and alert on binaries signed with weak-key or revoked certificates (`T1553.002`) (**Inferred** from [52]).

### Where the library's countermeasure data is thin

`T1584.002` DNS Server, `T1588.004` Digital Certificates, `T1553.002` Code Signing, `T1659` Content Injection, `T1685.006` Clear Linux or Mac System Logs and `T1690` Prevent Command History Logging have no D3FEND mapping in the library's data (**Confirmed** [32]). Multi-factor Authentication (`D3-MFA`), Software Update (`D3-SU`) and Application Configuration Hardening (`D3-ACH`) have library pages, but the library maps none of them to `T1078`, `T1203`, `T1190`, `T1566.001` or `T1566.002`, so this study cites them as guidance from the sources above, not as library-mapped countermeasures (**Confirmed** [32]). And D3FEND's own Email Filtering page lists `T1566.001` and `T1566.002` as inferred, experimental relationships rather than confirmed mappings (**Confirmed** [33]).

### Overstated and understated

- **Overstated: the reach of this tier into Western healthcare.** Nothing in the verified record shows any of these groups running a healthcare campaign; the contacts are incidental (**Inferred**).
- **Overstated: confidence in names.** Many of these groups carry "suspected" or no state at all, and several mimic each other's tradecraft. Reports that present them as settled national programs go further than the sources (**Inferred** from Part 1).
- **Understated: DNS and registrar risk.** Sea Turtle's method compromises the trust layer under everything else, carries no CVE, and was serious enough for a US emergency directive that stayed open for seven years (**Inferred** from [42] [44]).
- **Understated: old Office flaws.** They are routinely treated as solved, yet Kaspersky still recorded CVE-2017-11882 in 2024 operations (**Confirmed** [53]).

## Part 14: MITRE mappings

This part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND for 20 groups: the 14 whose ATT&CK text names or suspects a state, a state body, a region (BITTER, "suspected South Asian") or a Hamas affiliation outside the big five, or calls them likely state-sponsored, plus 6 that ATT&CK leaves stateless but that vendor primaries or ATT&CK's own overlap notes place in that tier (Confucius, Molerats, APT-C-23, PROMETHIUM, MoustachedBouncer and BlackOasis; the placement is **Inferred** where no source names a state): `G0050`, `G0121`, `G0040`, `G0142`, `G1002`, `G0134`, `G1008`, `G0012`, `G0038`, `G0070`, `G0123`, `G1005`, `G0021`, `G0090`, `G1028`, `G1041`, `G1019`, `G0056`, `G0063` and `G0089` (**Confirmed** [32]). Every ID was checked against the library's data files or the live ATT&CK page on 3 November 2026; IDs that could not be checked are left out. Tactic names are the v20 names (for example `stealth` and `defense-impairment`), read from the library's `technique_profiles.jsonl`.

### Enterprise techniques stated by vendor and government primaries

These are the techniques a dated primary describes for a group in this set. Every technique also appears in the ATT&CK record for the set below; three Stealth Falcon entries (`T1566.001`, `T1566.002`, `T1204.002`, Citizen Lab [49]) and the UNC1151 entry are vendor-stated and absent from that group's ATT&CK record (**Confirmed** [32] [47] [49]).

| Technique | Name | Tactic | Dated event or report | Source |
|---|---|---|---|---|
| [`T1584.002`](/mitre/techniques/T1584-002.md) | DNS Server | resource-development | Sea Turtle DNS hijacking through registrars and registries, January 2017 to Q1 2019 (Talos, 2019-04-17) | [42] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | Sea Turtle credential harvesting, 2017 to 2019 | [42] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Digital Certificates | resource-development | Sea Turtle certificates for victim domains, 2017 to 2019 | [42] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Sea Turtle stolen credentials (2017 to 2019); compromised cPanel accounts (2021 to 2023) | [42] [45] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Sea Turtle's seven named CVEs (2019-04-17); Marbled Dust CVE-2025-27920 (2025-05-12) | [42] [46] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | Sea Turtle SSH access, 2021 to 2023 | [45] |
| [`T1685.006`](/mitre/techniques/T1685-006.md) | Clear Linux or Mac System Logs | defense-impairment | Sea Turtle log clearing, 2021 to 2023 | [45] |
| [`T1690`](/mitre/techniques/T1690.md) | Prevent Command History Logging | defense-impairment | Sea Turtle history clearing, 2021 to 2023 | [45] |
| [`T1114.001`](/mitre/techniques/T1114-001.md) | Local Email Collection | collection | Sea Turtle email archive, 2021 to 2023 | [45] |
| [`T1074.002`](/mitre/techniques/T1074-002.md) | Remote Data Staging | collection | Sea Turtle archive staged in a public web directory, 2021 to 2023 | [45] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive via Utility | collection | Sea Turtle email archive, 2021 to 2023 | [45] |
| [`T1659`](/mitre/techniques/T1659.md) | Content Injection | initial-access, command-and-control | MoustachedBouncer fake Windows Update via ISP-level injection, since 2020 (ESET, 2023-08-10) | [48] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | MoustachedBouncer Disco plugin, CVE-2021-1732 (ESET, 2023-08-10) | [48] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | PowerShell | execution | Stealth Falcon backdoor (Citizen Lab, 2016-05-29) | [49] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Symmetric Cryptography | command-and-control | Stealth Falcon RC4-encrypted C2 (2016-05-29) | [49] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Web Browsers | credential-access | Stealth Falcon browser theft (2016-05-29) | [49] |
| [`T1555.004`](/mitre/techniques/T1555-004.md) | Windows Credential Manager | credential-access | Stealth Falcon credential-vault theft (2016-05-29) | [49] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | APT32 macro documents (Mandiant, 2017-05-14); Stealth Falcon (2016-05-29); Patchwork RTF lures (December 2021); SideWinder template-injection documents (Kaspersky, 2024-10-15) | [34] [49] [36] [53] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Stealth Falcon tracked links (2016-05-29); UNC1151 credential phishing, 2016 to 2021 (not an ATT&CK group) | [49] [47] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | APT32 macro documents (2017-05-14); Stealth Falcon macro documents (2016-05-29) | [34] [49] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Dark Caracal watering-hole site (2018-01-18); Darkhotel hotel-network delivery (2014-11-10) | [40] [52] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Spearphishing via Service | initial-access | Dark Caracal phishing through WhatsApp and Facebook (2018-01-18) | [40] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Darkhotel Flash zero-days (2014-11-10); Patchwork Equation Editor exploit (December 2021); SideWinder CVE-2017-11882 (2024-10-15) | [52] [36] [53] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | Darkhotel weak and stolen certificates (2014-11-10) | [52] |

### Enterprise techniques recorded by ATT&CK for the 20 groups

ATT&CK v20.0 links 154 distinct Enterprise techniques to the 20 groups (**Confirmed** [32]); every technique the library lists for these groups appears on the live group page [2] to [28]. The table is sorted by the number of groups linked, then by ID. Counting each technique once per tactic it serves gives 181 technique-tactic entries: Stealth 39, Discovery 19, Execution 17, Resource Development 16, Command and Control 15, Initial Access 12, Collection 11, Persistence 11, Privilege Escalation 9, Credential Access 8, Lateral Movement 8, Defense Impairment 6, Reconnaissance 6 and Exfiltration 4 (computed from [32]).

| Technique | Name | Tactic | Groups (n) | Groups | Source |
|---|---|---|---|---|---|
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | 13 | G0012 Darkhotel, G0021 Molerats, G0040 Patchwork, G0050 APT32, G0056 PROMETHIUM, G0070 Dark Caracal, G0089 The White Company, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius, G1002 BITTER, G1008 SideCopy | [32] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | 11 | G0012 Darkhotel, G0021 Molerats, G0040 Patchwork, G0050 APT32, G0089 The White Company, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius, G1002 BITTER, G1008 SideCopy | [32] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | 10 | G0012 Darkhotel, G0021 Molerats, G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G0123 Volatile Cedar, G0142 Confucius, G1002 BITTER, G1008 SideCopy | [32] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | 9 | G0012 Darkhotel, G0040 Patchwork, G0050 APT32, G0089 The White Company, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius, G1002 BITTER, G1041 Sea Turtle | [32] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | stealth | 8 | G0012 Darkhotel, G0040 Patchwork, G0050 APT32, G0056 PROMETHIUM, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G1008 SideCopy | [32] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | PowerShell | execution | 8 | G0021 Molerats, G0038 Stealth Falcon, G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G0142 Confucius, G1019 MoustachedBouncer | [32] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | 8 | G0021 Molerats, G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius, G1008 SideCopy | [32] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | command-and-control | 8 | G0038 Stealth Falcon, G0050 APT32, G0070 Dark Caracal, G0090 WIRTE, G0121 Sidewinder, G0142 Confucius, G1002 BITTER, G1041 Sea Turtle | [32] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 8 | G0012 Darkhotel, G0021 Molerats, G0040 Patchwork, G0050 APT32, G0056 PROMETHIUM, G0070 Dark Caracal, G0121 Sidewinder, G0142 Confucius | [32] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | Malicious Link | execution | 7 | G0021 Molerats, G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius | [32] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | 7 | G0021 Molerats, G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G0134 Transparent Tribe, G0142 Confucius | [32] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | stealth | 6 | G0012 Darkhotel, G0050 APT32, G0070 Dark Caracal, G0121 Sidewinder, G0134 Transparent Tribe, G1002 BITTER | [32] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task | execution, persistence, privilege-escalation | 6 | G0021 Molerats, G0038 Stealth Falcon, G0040 Patchwork, G0050 APT32, G0142 Confucius, G1002 BITTER | [32] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | discovery | 6 | G0012 Darkhotel, G0038 Stealth Falcon, G0040 Patchwork, G0050 APT32, G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | discovery | 6 | G0012 Darkhotel, G0040 Patchwork, G0050 APT32, G0070 Dark Caracal, G0121 Sidewinder, G0142 Confucius | [32] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | 6 | G0012 Darkhotel, G0040 Patchwork, G0050 APT32, G0056 PROMETHIUM, G0070 Dark Caracal, G0134 Transparent Tribe | [32] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Tool | resource-development | 6 | G0040 Patchwork, G0050 APT32, G0090 WIRTE, G1002 BITTER, G1005 POLONIUM, G1041 Sea Turtle | [32] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | discovery | 5 | G0012 Darkhotel, G0038 Stealth Falcon, G0050 APT32, G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | 5 | G0012 Darkhotel, G0040 Patchwork, G0050 APT32, G0070 Dark Caracal, G0090 WIRTE | [32] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Security Software Discovery | discovery | 5 | G0012 Darkhotel, G0040 Patchwork, G0089 The White Company, G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | DLL | stealth, execution | 5 | G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Domains | resource-development | 5 | G0050 APT32, G0090 WIRTE, G0134 Transparent Tribe, G1002 BITTER, G1041 Sea Turtle | [32] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Software Packing | stealth | 4 | G0040 Patchwork, G0070 Dark Caracal, G0089 The White Company, G1019 MoustachedBouncer | [32] |
| [`T1027.010`](/mitre/techniques/T1027-010.md) | Command Obfuscation | stealth | 4 | G0040 Patchwork, G0050 APT32, G0090 WIRTE, G0121 Sidewinder | [32] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | discovery | 4 | G0038 Stealth Falcon, G0040 Patchwork, G0050 APT32, G0121 Sidewinder | [32] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | exfiltration | 4 | G0038 Stealth Falcon, G0050 APT32, G0090 WIRTE, G0142 Confucius | [32] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | discovery | 4 | G0012 Darkhotel, G0021 Molerats, G0038 Stealth Falcon, G0121 Sidewinder | [32] |
| [`T1059.007`](/mitre/techniques/T1059-007.md) | JavaScript | execution | 4 | G0021 Molerats, G0050 APT32, G0121 Sidewinder, G1019 MoustachedBouncer | [32] |
| [`T1218.005`](/mitre/techniques/T1218-005.md) | Mshta | stealth | 4 | G0050 APT32, G0121 Sidewinder, G0142 Confucius, G1008 SideCopy | [32] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | 4 | G0012 Darkhotel, G0021 Molerats, G0040 Patchwork, G0056 PROMETHIUM | [32] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Upload Malware | resource-development | 4 | G0050 APT32, G0090 WIRTE, G1002 BITTER, G1008 SideCopy | [32] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | 3 | G0038 Stealth Falcon, G0040 Patchwork, G0070 Dark Caracal | [32] |
| [`T1036.004`](/mitre/techniques/T1036-004.md) | Masquerade Task or Service | stealth | 3 | G0050 APT32, G0056 PROMETHIUM, G1002 BITTER | [32] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | 3 | G0050 APT32, G1002 BITTER, G1019 MoustachedBouncer | [32] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | File Deletion | stealth | 3 | G0040 Patchwork, G0050 APT32, G0089 The White Company | [32] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Local Data Staging | collection | 3 | G0040 Patchwork, G0090 WIRTE, G0121 Sidewinder | [32] |
| [`T1078.003`](/mitre/techniques/T1078-003.md) | Local Accounts | stealth, persistence, privilege-escalation, initial-access | 3 | G0050 APT32, G0056 PROMETHIUM, G1041 Sea Turtle | [32] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | collection | 3 | G0040 Patchwork, G0121 Sidewinder, G0142 Confucius | [32] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | discovery | 3 | G0012 Darkhotel, G0089 The White Company, G0121 Sidewinder | [32] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | stealth | 3 | G0012 Darkhotel, G0021 Molerats, G0090 WIRTE | [32] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | persistence | 3 | G0050 APT32, G0123 Volatile Cedar, G1041 Sea Turtle | [32] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Web Browsers | credential-access | 3 | G0021 Molerats, G0038 Stealth Falcon, G0040 Patchwork | [32] |
| [`T1559.002`](/mitre/techniques/T1559-002.md) | Dynamic Data Exchange | execution | 3 | G0040 Patchwork, G0121 Sidewinder, G1002 BITTER | [32] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Web Services | resource-development | 3 | G0050 APT32, G0142 Confucius, G1005 POLONIUM | [32] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Spearphishing Link | reconnaissance | 3 | G0040 Patchwork, G0050 APT32, G0121 Sidewinder | [32] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | discovery | 2 | G0038 Stealth Falcon, G0050 APT32 | [32] |
| [`T1027.015`](/mitre/techniques/T1027-015.md) | Compression | stealth | 2 | G0021 Molerats, G0090 WIRTE | [32] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | execution | 2 | G0038 Stealth Falcon, G0050 APT32 | [32] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | 2 | G0012 Darkhotel, G0050 APT32 | [32] |
| [`T1059`](/mitre/techniques/T1059.md) | Command and Scripting Interpreter | execution | 2 | G0038 Stealth Falcon, G0050 APT32 | [32] |
| [`T1074.002`](/mitre/techniques/T1074-002.md) | Remote Data Staging | collection | 2 | G1019 MoustachedBouncer, G1041 Sea Turtle | [32] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 2 | G1005 POLONIUM, G1041 Sea Turtle | [32] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | command-and-control | 2 | G1005 POLONIUM, G1019 MoustachedBouncer | [32] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | execution | 2 | G0090 WIRTE, G1008 SideCopy | [32] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | 2 | G0040 Patchwork, G0050 APT32 | [32] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | 2 | G0070 Dark Caracal, G1019 MoustachedBouncer | [32] |
| [`T1114.001`](/mitre/techniques/T1114-001.md) | Local Email Collection | collection | 2 | G0090 WIRTE, G1041 Sea Turtle | [32] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | 2 | G0123 Volatile Cedar, G1041 Sea Turtle | [32] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | initial-access | 2 | G1005 POLONIUM, G1041 Sea Turtle | [32] |
| [`T1218.010`](/mitre/techniques/T1218-010.md) | Regsvr32 | stealth | 2 | G0050 APT32, G0090 WIRTE | [32] |
| [`T1497.001`](/mitre/techniques/T1497-001.md) | System Checks | stealth, discovery | 2 | G0012 Darkhotel, G0090 WIRTE | [32] |
| [`T1518`](/mitre/techniques/T1518.md) | Software Discovery | discovery | 2 | G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | 2 | G0050 APT32, G0056 PROMETHIUM | [32] |
| [`T1560`](/mitre/techniques/T1560.md) | Archive Collected Data | collection | 2 | G0040 Patchwork, G0050 APT32 | [32] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hidden Files and Directories | stealth | 2 | G0050 APT32, G0134 Transparent Tribe | [32] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration to Cloud Storage | exfiltration | 2 | G0142 Confucius, G1005 POLONIUM | [32] |
| [`T1568`](/mitre/techniques/T1568.md) | Dynamic Resolution | command-and-control | 2 | G0134 Transparent Tribe, G1002 BITTER | [32] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | command-and-control | 2 | G0050 APT32, G0090 WIRTE | [32] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Symmetric Cryptography | command-and-control | 2 | G0012 Darkhotel, G0038 Stealth Falcon | [32] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Domains | resource-development | 2 | G0134 Transparent Tribe, G1008 SideCopy | [32] |
| [`T1587.002`](/mitre/techniques/T1587-002.md) | Code Signing Certificates | resource-development | 2 | G0040 Patchwork, G0056 PROMETHIUM | [32] |
| [`T1598.002`](/mitre/techniques/T1598-002.md) | Spearphishing Attachment | reconnaissance | 2 | G0121 Sidewinder, G1008 SideCopy | [32] |
| [`T1608.004`](/mitre/techniques/T1608-004.md) | Drive-by Target | resource-development | 2 | G0050 APT32, G0134 Transparent Tribe | [32] |
| [`T1680`](/mitre/techniques/T1680.md) | Local Storage Discovery | discovery | 2 | G0040 Patchwork, G0142 Confucius | [32] |
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | credential-access | 1 | G0050 APT32 | [32] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | LSASS Memory | credential-access | 1 | G0050 APT32 | [32] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | discovery | 1 | G0050 APT32 | [32] |
| [`T1020`](/mitre/techniques/T1020.md) | Automated Exfiltration | exfiltration | 1 | G0121 Sidewinder | [32] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | lateral-movement | 1 | G0040 Patchwork | [32] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | 1 | G0050 APT32 | [32] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | stealth | 1 | G0063 BlackOasis | [32] |
| [`T1027.001`](/mitre/techniques/T1027-001.md) | Binary Padding | stealth | 1 | G0040 Patchwork | [32] |
| [`T1027.004`](/mitre/techniques/T1027-004.md) | Compile After Delivery | stealth | 1 | G1041 Sea Turtle | [32] |
| [`T1027.005`](/mitre/techniques/T1027-005.md) | Indicator Removal from Tools | stealth | 1 | G0040 Patchwork | [32] |
| [`T1027.011`](/mitre/techniques/T1027-011.md) | Fileless Storage | stealth | 1 | G0050 APT32 | [32] |
| [`T1027.016`](/mitre/techniques/T1027-016.md) | Junk Code Insertion | stealth | 1 | G0050 APT32 | [32] |
| [`T1036`](/mitre/techniques/T1036.md) | Masquerading | stealth | 1 | G0050 APT32 | [32] |
| [`T1036.003`](/mitre/techniques/T1036-003.md) | Rename Legitimate Utilities | stealth | 1 | G0050 APT32 | [32] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | 1 | G0050 APT32 | [32] |
| [`T1048.003`](/mitre/techniques/T1048-003.md) | Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | 1 | G0050 APT32 | [32] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | discovery | 1 | G0050 APT32 | [32] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | stealth, privilege-escalation | 1 | G0050 APT32 | [32] |
| [`T1055.012`](/mitre/techniques/T1055-012.md) | Process Hollowing | stealth, privilege-escalation | 1 | G0040 Patchwork | [32] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | execution | 1 | G1041 Sea Turtle | [32] |
| [`T1070.006`](/mitre/techniques/T1070-006.md) | Timestomp | stealth | 1 | G0050 APT32 | [32] |
| [`T1071.003`](/mitre/techniques/T1071-003.md) | Mail Protocols | command-and-control | 1 | G0050 APT32 | [32] |
| [`T1072`](/mitre/techniques/T1072.md) | Software Deployment Tools | execution, lateral-movement | 1 | G0050 APT32 | [32] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | 1 | G0012 Darkhotel | [32] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Local Account | discovery | 1 | G0050 APT32 | [32] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | 1 | G0012 Darkhotel | [32] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | 1 | G1002 BITTER | [32] |
| [`T1102`](/mitre/techniques/T1102.md) | Web Service | command-and-control | 1 | G0050 APT32 | [32] |
| [`T1102.001`](/mitre/techniques/T1102-001.md) | Dead Drop Resolver | command-and-control | 1 | G0040 Patchwork | [32] |
| [`T1102.002`](/mitre/techniques/T1102-002.md) | Bidirectional Communication | command-and-control | 1 | G1005 POLONIUM | [32] |
| [`T1132.001`](/mitre/techniques/T1132-001.md) | Standard Encoding | command-and-control | 1 | G0040 Patchwork | [32] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | 1 | G1041 Sea Turtle | [32] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | 1 | G0050 APT32 | [32] |
| [`T1137`](/mitre/techniques/T1137.md) | Office Application Startup | persistence | 1 | G0050 APT32 | [32] |
| [`T1197`](/mitre/techniques/T1197.md) | BITS Jobs | stealth, persistence, execution | 1 | G0040 Patchwork | [32] |
| [`T1205.001`](/mitre/techniques/T1205-001.md) | Port Knocking | stealth, persistence, command-and-control | 1 | G0056 PROMETHIUM | [32] |
| [`T1213.006`](/mitre/techniques/T1213-006.md) | Databases | collection | 1 | G1041 Sea Turtle | [32] |
| [`T1216.001`](/mitre/techniques/T1216-001.md) | PubPrn | stealth | 1 | G0050 APT32 | [32] |
| [`T1218.001`](/mitre/techniques/T1218-001.md) | Compiled HTML File | stealth | 1 | G0070 Dark Caracal | [32] |
| [`T1218.007`](/mitre/techniques/T1218-007.md) | Msiexec | stealth | 1 | G0021 Molerats | [32] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | Rundll32 | stealth | 1 | G0050 APT32 | [32] |
| [`T1221`](/mitre/techniques/T1221.md) | Template Injection | stealth | 1 | G0142 Confucius | [32] |
| [`T1222.002`](/mitre/techniques/T1222-002.md) | Linux and Mac Permissions | defense-impairment | 1 | G0050 APT32 | [32] |
| [`T1497`](/mitre/techniques/T1497.md) | Virtualization/Sandbox Evasion | stealth, discovery | 1 | G0012 Darkhotel | [32] |
| [`T1497.002`](/mitre/techniques/T1497-002.md) | User Activity Based Checks | stealth, discovery | 1 | G0012 Darkhotel | [32] |
| [`T1548.002`](/mitre/techniques/T1548-002.md) | Bypass User Account Control | privilege-escalation | 1 | G0040 Patchwork | [32] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Pass the Hash | lateral-movement | 1 | G0050 APT32 | [32] |
| [`T1550.003`](/mitre/techniques/T1550-003.md) | Pass the Ticket | lateral-movement | 1 | G0050 APT32 | [32] |
| [`T1552.002`](/mitre/techniques/T1552-002.md) | Credentials in Registry | credential-access | 1 | G0050 APT32 | [32] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | credential-access | 1 | G0038 Stealth Falcon | [32] |
| [`T1555.004`](/mitre/techniques/T1555-004.md) | Windows Credential Manager | credential-access | 1 | G0038 Stealth Falcon | [32] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | 1 | G1041 Sea Turtle | [32] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive via Utility | collection | 1 | G1041 Sea Turtle | [32] |
| [`T1564.003`](/mitre/techniques/T1564-003.md) | Hidden Window | stealth | 1 | G0050 APT32 | [32] |
| [`T1564.004`](/mitre/techniques/T1564-004.md) | NTFS File Attributes | stealth | 1 | G0050 APT32 | [32] |
| [`T1564.011`](/mitre/techniques/T1564-011.md) | Ignore Process Interrupts | stealth | 1 | G1041 Sea Turtle | [32] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | initial-access | 1 | G1041 Sea Turtle | [32] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Spearphishing via Service | initial-access | 1 | G0070 Dark Caracal | [32] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | Service Execution | execution | 1 | G0050 APT32 | [32] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | lateral-movement | 1 | G0050 APT32 | [32] |
| [`T1573`](/mitre/techniques/T1573.md) | Encrypted Channel | command-and-control | 1 | G1002 BITTER | [32] |
| [`T1583`](/mitre/techniques/T1583.md) | Acquire Infrastructure | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1583.002`](/mitre/techniques/T1583-002.md) | DNS Server | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Virtual Private Server | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1584.002`](/mitre/techniques/T1584-002.md) | DNS Server | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Social Media Accounts | resource-development | 1 | G0050 APT32 | [32] |
| [`T1586.002`](/mitre/techniques/T1586-002.md) | Email Accounts | resource-development | 1 | G0090 WIRTE | [32] |
| [`T1587.003`](/mitre/techniques/T1587-003.md) | Digital Certificates | resource-development | 1 | G0056 PROMETHIUM | [32] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Digital Certificates | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1589`](/mitre/techniques/T1589.md) | Gather Victim Identity Information | reconnaissance | 1 | G0050 APT32 | [32] |
| [`T1589.002`](/mitre/techniques/T1589-002.md) | Email Addresses | reconnaissance | 1 | G0050 APT32 | [32] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | 1 | G0123 Volatile Cedar | [32] |
| [`T1595.003`](/mitre/techniques/T1595-003.md) | Wordlist Scanning | reconnaissance | 1 | G0123 Volatile Cedar | [32] |
| [`T1608.003`](/mitre/techniques/T1608-003.md) | Install Digital Certificate | resource-development | 1 | G1041 Sea Turtle | [32] |
| [`T1614`](/mitre/techniques/T1614.md) | System Location Discovery | discovery | 1 | G1008 SideCopy | [32] |
| [`T1659`](/mitre/techniques/T1659.md) | Content Injection | initial-access, command-and-control | 1 | G1019 MoustachedBouncer | [32] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Impersonation | stealth | 1 | G0090 WIRTE | [32] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs | defense-impairment | 1 | G0050 APT32 | [32] |
| [`T1685.006`](/mitre/techniques/T1685-006.md) | Clear Linux or Mac System Logs | defense-impairment | 1 | G1041 Sea Turtle | [32] |
| [`T1690`](/mitre/techniques/T1690.md) | Prevent Command History Logging | defense-impairment | 1 | G1041 Sea Turtle | [32] |

### Mobile

The library's Mobile data records two techniques for Dark Caracal (`T1437.001` Web Protocols, `T1476` Deliver Malicious Application via Other Means), three for APT-C-23 (`T1422` System Network Configuration Discovery, `T1655.001` Match Legitimate Name or Location, `T1660` Phishing) and two for the Mobile-only Bouncing Golf (`T1476`, `T1655.001`) (**Confirmed** [32]). The library generates no technique pages for the Mobile domain, so these are not linked. The Mobile software objects Pallas (`S0399`, Dark Caracal) and VajraSpy (`S9006`, Patchwork) have no library page. No group in this set has an ATT&CK for ICS record.

### Groups, campaigns and software

| Object | ID | Relationship in ATT&CK v20.0 | Source |
|---|---|---|---|
| The 20 bound groups | `G0050` `G0121` `G0040` `G0142` `G1002` `G0134` `G1008` `G0012` `G0038` `G0070` `G0123` `G1005` `G0021` `G0090` `G1028` `G1041` `G1019` `G0056` `G0063` `G0089` | Each linked in Part 1; every one has a generated page | [32] |
| Reviewed, not bound | [`G0078`](/mitre/groups/G0078.md), [`G1035`](/mitre/groups/G1035.md), [`G0126`](/mitre/groups/G0126.md), [`G0095`](/mitre/groups/G0095.md), [`G1013`](/mitre/groups/G1013.md), [`G0055`](/mitre/groups/G0055.md), [`G0020`](/mitre/groups/G0020.md) | Criminal mix, home in another study, or no state named | [10] [25] [27] [29] [30] [23] [31] |
| Bouncing Golf | `G0097` | Mobile only; no library page | [19] |
| Campaign C0011 | [`C0011`](/mitre/campaigns/C0011.md) | Transparent Tribe against Indian students, December 2021 to July 2022 | [8] [32] |
| Campaign C0033 | [`C0033`](/mitre/campaigns/C0033.md) | PROMETHIUM StrongPity against Android users, May 2016 to January 2023 | [22] [32] |
| UNC1151 / Ghostwriter | none | No object in the library's ATT&CK data | [32] [47] |
| Software | 72 Enterprise IDs with library pages, plus the Mobile-only `S0399` and `S9006` | See Part 8 | [32] |

### CWE and CAPEC

KEV lists a CWE for 20 of the 22 CVEs in this set (Part 9), for example CWE-787 for CVE-2021-1732, CWE-119 for CVE-2017-11882, CWE-94 for CVE-2012-0158, CWE-78 for CVE-2014-6271, CWE-434 for CVE-2017-12617 and CWE-22 for CVE-2025-27920; only CVE-2017-0199 and CVE-2017-8570 have none (**Confirmed** [56]). CVE-2025-33053 carries CWE-73 (External Control of File Name or Path) in both KEV and NVD (**Confirmed** [51] [56]). CAPEC IDs come from the `capec` field of the library's `technique_profiles.jsonl` (**Confirmed** [32]). See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

| Technique | CAPEC patterns linked in the library data |
|---|---|
| `T1566.001` Spearphishing Attachment, `T1566.002` Spearphishing Link, `T1566.003` Spearphishing via Service (Dark Caracal) | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing |
| `T1078` Valid Accounts (Sea Turtle) | [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials |
| `T1690` Prevent Command History Logging (Sea Turtle) | [CAPEC-13](/mitre/capec/CAPEC-13.md) Subverting Environment Variable Values; [CAPEC-268](/mitre/capec/CAPEC-268.md) Audit Log Manipulation |
| `T1584.002` DNS Server (Sea Turtle) | [CAPEC-142](/mitre/capec/CAPEC-142.md) DNS Cache Poisoning |
| `T1557` Adversary-in-the-Middle (Sea Turtle) | [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (AiTM) |
| `T1553.002` Code Signing (Darkhotel and others) | [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities; [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code; [CAPEC-473](/mitre/capec/CAPEC-473.md) Signature Spoof |
| `T1547.001` Registry Run Keys / Startup Folder | [CAPEC-270](/mitre/capec/CAPEC-270.md) Modification of Registry Run Keys |
| `T1036.005` Match Legitimate Resource Name or Location | [CAPEC-543](/mitre/capec/CAPEC-543.md) Counterfeit Websites; [CAPEC-616](/mitre/capec/CAPEC-616.md) Establish Rogue Location |
| `T1204.002`, `T1203`, `T1189`, `T1190` | None in the library data |

### D3FEND countermeasures

The countermeasures below come from the library's `data/attack/technique_to_d3fend.jsonl` (D3FEND 1.6.0), and each links to its library page (**Confirmed** [32]). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

| Behavior in this set | Techniques | D3FEND countermeasures in the library data |
|---|---|---|
| Spearphishing | `T1566.001`, `T1566.002` (URL Analysis: `T1566.002` only) | [Email Filtering](/mitre/d3fend/email-filtering.md) (`D3-EF`; D3FEND itself marks the relationship inferred and experimental [33]), [URL Analysis](/mitre/d3fend/url-analysis.md) (`D3-UA`), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (`D3-DA`) |
| Malicious files and run-key persistence | `T1204.002`, `T1547.001` | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`) |
| Client, privilege and server exploitation | `T1203`, `T1068`, `T1190` | [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (`D3-SAOR`), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (`D3-PSEP`) |
| Run-key persistence | `T1547.001` | [System Init Config Analysis](/mitre/d3fend/system-init-config-analysis.md) (`D3-SICA`) |
| Web command and control | `T1071.001` | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`), [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) (`D3-CA`) |
| No countermeasure in the library data | `T1584.002`, `T1588.004`, `T1553.002`, `T1659`, `T1685.006`, `T1690` | See Part 13 |
| Source guidance, not library-mapped | `T1078`, `T1203`, `T1190`, `T1566.001`, `T1566.002` | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (`D3-MFA`), [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`), [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) (`D3-ACH`), as advised by [42] [43] [44] [45] |

### Techniques the major-state advisories state (comparison, not in the layer)

The government advisories summarized in Part 11 publish their own technique IDs. They are listed here for comparison and left out of this study's layer, because their home is the companion study for each state. Every ID was checked against the library's data (**Confirmed** [32]).

| Advisory (date) | Actor | Techniques stated | Source |
|---|---|---|---|
| AA20-301A (2020-10-27) | Kimsuky | `T1566.001`, `T1185`, `T1218.005`, `T1505.003`, `T1114.003` (among 27) | [94] |
| AA21-321A (2021-11-17) | Iranian government-sponsored APT | `T1190`, `T1053.005`, `T1136.001`, `T1486` | [100] |
| AA22-187A (2022-07-06) | North Korean state-sponsored actors (Maui) | `T1059.008`, `T1486` | [96] |
| AA23-040A (2023-02-09) | DPRK ransomware actors | `T1190`, `T1133`, `T1195`, `T1486` | [97] |
| AA23-129A (2023-05-09) | FSB Center 16 (Snake) | `T1014`, `T1027.002`, `T1055.001`, `T1071.001`, `T1090.003`, `T1095`, `T1572`, `T1573` | [86] |
| AA23-335A (2023-12-01) | IRGC-affiliated CyberAv3ngers | `T1110`, `T1078.001`, `T1565.001`, `T1531`, `T1499`, `T1491.001` | [103] |
| AA24-038A (2024-02-07) | Volt Typhoon | `T1190`, `T1133`, `T1059`, `T1218`, `T1105`, `T1090.003`, `T1584.005` (among others) | [76] |
| AA24-190A (2024-07-08) | APT40 | `T1190`, `T1505.003`, `T1558.003`, `T1003`, `T1021.001`, `T1572` (among others) | [73] |
| AA24-207A (2024-07-25) | Andariel | `T1190`, `T1003`, `T1021.002`, `T1567`, `T1572` | [98] |
| AA24-290A (2024-10-16) | Iranian actors | `T1110.003`, `T1621` | [105] |
| AA25-141A (2025-05-21) | GRU Unit 26165 | `T1110.003`, `T1566.001`, `T1190`, `T1133`, `T1199`, `T1003.003` | [87] |
| AA25-239A (2025-08-27) | Salt Typhoon-linked actors | `T1190`, `T1199`, `T1098.004`, `T1686` (the advisory cites `T1562.004`, revoked in ATT&CK v20.0), `T1599`, `T1602.001`, `T1602.002`, `T1572` (among 42) | [77] |

The comparison shows the difference in kind. The big-five advisories lead with `T1190` against edge devices, valid accounts and tunneling; this tier leads with `T1204.002` and `T1566.001`. The shared ground is `T1190` and `T1566.001` (**Inferred** from both tables).

### Navigator layer

The study's techniques are collected in an ATT&CK Navigator layer, [`navigator/library-layers/other-state-actors.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/other-state-actors.json), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/other-state-actors.json). It holds the 154 Enterprise techniques above as 181 technique-tactic entries, domain `enterprise-attack`, ATT&CK version 20. The score is the number of the study's 20 groups that ATT&CK links to the technique (1 to 13); it measures breadth across the tier, not severity, and it is not an attribution claim. Each comment names the groups and the study's source numbers and, where a primary describes the technique, the dated report. Group lists in the comments follow ATT&CK's links only; the vendor-stated Stealth Falcon and UNC1151 entries appear under the comment's primary record, not as ATT&CK links for `G0038`.

### Notices

The ATT&CK, CWE, CAPEC and D3FEND notices close the [Sources](#sources) part.

## Cross-cutting themes

- **Attribution is a ladder, and this tier lives on the lower rungs.** One named agency, a handful of "suspected" countries, one explicitly unconfirmed link, and many groups with no state at all. A defender's report should carry the rung, not just the name. See the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md).
- **Regional rivalry drives the targeting.** India-linked and Pakistan-linked groups target each other; Gaza groups target Israel; a Türkiye-linked actor targets Kurdish groups and governments opposing Turkish interests; a Belarus-aligned actor targets the embassies in its own capital (**Inferred** from Parts 2 to 5).
- **Civil society carries much of the cost.** Journalists, activists, dissidents, lawyers and diaspora communities appear in the Stealth Falcon, Dark Caracal, APT32 and BlackOasis records, often reached through their phones (**Confirmed** [11] [15] [35] [40]).
- **Bought tools blur the actor.** Commercial surveillance software and commodity remote access tools recur across groups, so tool hits are leads, not attributions (**Inferred** from Part 8).
- **Trust infrastructure is the outsized risk.** Registrars, registries, certificate issuance and the network path itself (Sea Turtle and MoustachedBouncer) sit beneath every other control (**Inferred** from [42] [48]).
- **The government spotlight falls elsewhere.** Joint advisories, sanctions and indictments concentrate on the big five; for this tier, vendors, researchers and platforms carry the public record (**Inferred** from Part 12).
- **The library's own data has edges worth knowing.** The library's Enterprise data holds 178 of the 182 live ATT&CK groups; the other four are ICS-only or Mobile-only and have no generated group page; Mobile techniques have no generated pages, and several of this tier's signature techniques have no D3FEND mapping (**Confirmed** [1] [32]).

## Sources

Every source below was opened on 3 November 2026. Grades apply to the source type: Confirmed for a primary (the publisher of the fact), Reported for secondary coverage or for a leak publisher's or rival government's assertion.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | MITRE ATT&CK, Groups index (182 group IDs, ATT&CK v20.0) | https://attack.mitre.org/groups/ | 2026-11-03 | Confirmed |
| 2 | MITRE ATT&CK, Group G0050 APT32 | https://attack.mitre.org/groups/G0050/ | 2026-11-03 | Confirmed |
| 3 | MITRE ATT&CK, Group G0040 Patchwork | https://attack.mitre.org/groups/G0040/ | 2026-11-03 | Confirmed |
| 4 | MITRE ATT&CK, Group G0121 Sidewinder | https://attack.mitre.org/groups/G0121/ | 2026-11-03 | Confirmed |
| 5 | MITRE ATT&CK, Group G0142 Confucius | https://attack.mitre.org/groups/G0142/ | 2026-11-03 | Confirmed |
| 6 | MITRE ATT&CK, Group G1002 BITTER | https://attack.mitre.org/groups/G1002/ | 2026-11-03 | Confirmed |
| 7 | MITRE ATT&CK, Group G0134 Transparent Tribe | https://attack.mitre.org/groups/G0134/ | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, Campaign C0011 | https://attack.mitre.org/campaigns/C0011/ | 2026-11-03 | Confirmed |
| 9 | MITRE ATT&CK, Group G1008 SideCopy | https://attack.mitre.org/groups/G1008/ | 2026-11-03 | Confirmed |
| 10 | MITRE ATT&CK, Group G0078 Gorgon Group | https://attack.mitre.org/groups/G0078/ | 2026-11-03 | Confirmed |
| 11 | MITRE ATT&CK, Group G0038 Stealth Falcon | https://attack.mitre.org/groups/G0038/ | 2026-11-03 | Confirmed |
| 12 | MITRE ATT&CK, Group G0070 Dark Caracal (version 1.4, last modified 2 September 2026) | https://attack.mitre.org/groups/G0070/ | 2026-11-03 | Confirmed |
| 13 | MITRE ATT&CK, Group G0123 Volatile Cedar | https://attack.mitre.org/groups/G0123/ | 2026-11-03 | Confirmed |
| 14 | MITRE ATT&CK, Group G1005 POLONIUM | https://attack.mitre.org/groups/G1005/ | 2026-11-03 | Confirmed |
| 15 | MITRE ATT&CK, Group G0063 BlackOasis | https://attack.mitre.org/groups/G0063/ | 2026-11-03 | Confirmed |
| 16 | MITRE ATT&CK, Group G0021 Molerats | https://attack.mitre.org/groups/G0021/ | 2026-11-03 | Confirmed |
| 17 | MITRE ATT&CK, Group G0090 WIRTE | https://attack.mitre.org/groups/G0090/ | 2026-11-03 | Confirmed |
| 18 | MITRE ATT&CK, Group G1028 APT-C-23 | https://attack.mitre.org/groups/G1028/ | 2026-11-03 | Confirmed |
| 19 | MITRE ATT&CK, Group G0097 Bouncing Golf | https://attack.mitre.org/groups/G0097/ | 2026-11-03 | Confirmed |
| 20 | MITRE ATT&CK, Group G1041 Sea Turtle | https://attack.mitre.org/groups/G1041/ | 2026-11-03 | Confirmed |
| 21 | MITRE ATT&CK, Group G0056 PROMETHIUM | https://attack.mitre.org/groups/G0056/ | 2026-11-03 | Confirmed |
| 22 | MITRE ATT&CK, Campaign C0033 | https://attack.mitre.org/campaigns/C0033/ | 2026-11-03 | Confirmed |
| 23 | MITRE ATT&CK, Group G0055 NEODYMIUM | https://attack.mitre.org/groups/G0055/ | 2026-11-03 | Confirmed |
| 24 | MITRE ATT&CK, Group G1019 MoustachedBouncer | https://attack.mitre.org/groups/G1019/ | 2026-11-03 | Confirmed |
| 25 | MITRE ATT&CK, Group G1035 Winter Vivern | https://attack.mitre.org/groups/G1035/ | 2026-11-03 | Confirmed |
| 26 | MITRE ATT&CK, Group G0012 Darkhotel | https://attack.mitre.org/groups/G0012/ | 2026-11-03 | Confirmed |
| 27 | MITRE ATT&CK, Group G0126 Higaisa | https://attack.mitre.org/groups/G0126/ | 2026-11-03 | Confirmed |
| 28 | MITRE ATT&CK, Group G0089 The White Company | https://attack.mitre.org/groups/G0089/ | 2026-11-03 | Confirmed |
| 29 | MITRE ATT&CK, Group G0095 Machete | https://attack.mitre.org/groups/G0095/ | 2026-11-03 | Confirmed |
| 30 | MITRE ATT&CK, Group G1013 Metador | https://attack.mitre.org/groups/G1013/ | 2026-11-03 | Confirmed |
| 31 | MITRE ATT&CK, Group G0020 Equation | https://attack.mitre.org/groups/G0020/ | 2026-11-03 | Confirmed |
| 32 | TeamStarWolf library data and generated pages on main: data/attack/ (ATT&CK v20.0, D3FEND 1.6.0, CAPEC 3.9), mitre/ and navigator/ | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-03 | Confirmed |
| 33 | MITRE D3FEND, Email Filtering (D3-EF), D3FEND 1.6.0 | https://d3fend.mitre.org/technique/d3f:EmailFiltering/ | 2026-11-03 | Confirmed |
| 34 | Mandiant (FireEye), APT32 cyber espionage report, 2017-05-14 | https://cloud.google.com/blog/topics/threat-intelligence/cyber-espionage-apt32 | 2026-11-03 | Confirmed |
| 35 | Meta, action against hackers in Bangladesh and Vietnam, 2020-12-10 | https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/ | 2026-11-03 | Confirmed |
| 36 | ThreatDown (Malwarebytes), Patchwork APT caught in its own web, 2022-01-07 | https://www.threatdown.com/blog/patchwork-apt-caught-in-its-own-web/ | 2026-11-03 | Confirmed |
| 37 | Kaspersky Securelist, Transparent Tribe, part 2, 2020-08-26 | https://securelist.com/transparent-tribe-part-2/98233/ | 2026-11-03 | Confirmed |
| 38 | Cisco Talos, Transparent Tribe targets education, 2022-07-13 | https://blog.talosintelligence.com/transparent-tribe-targets-education/ | 2026-11-03 | Confirmed |
| 39 | Meta, Adversarial Threat Report Q2 2022, 2022-08-04 | https://about.fb.com/news/2022/08/metas-adversarial-threat-report-q2-2022/ | 2026-11-03 | Confirmed |
| 40 | Lookout and EFF, "Dark Caracal: Cyber-espionage at a Global Scale", 2018-01-18 | https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf | 2026-11-03 | Confirmed |
| 41 | EFF press release on Dark Caracal, 2018-01-18 | https://www.eff.org/press/releases/eff-and-lookout-uncover-new-malware-espionage-campaign-infecting-thousands-around | 2026-11-03 | Confirmed |
| 42 | Cisco Talos, "DNS Hijacking Abuses Trust In Core Internet Service" (Sea Turtle), 2019-04-17 | https://blog.talosintelligence.com/seaturtle/ | 2026-11-03 | Confirmed |
| 43 | Cisco Talos, "Sea Turtle keeps on swimming", 2019-07-09 | https://blog.talosintelligence.com/sea-turtle-keeps-on-swimming/ | 2026-11-03 | Confirmed |
| 44 | CISA Emergency Directive 19-01, Mitigate DNS Infrastructure Tampering, 2019-01-22 (closed 2026-01-08) | https://www.cisa.gov/news-events/directives/ed-19-01-mitigate-dns-infrastructure-tampering | 2026-11-03 | Confirmed |
| 45 | Hunt & Hackett, Turkish espionage campaigns in the Netherlands, 2024-01-05 | https://www.huntandhackett.com/blog/turkish-espionage-campaigns | 2026-11-03 | Confirmed |
| 46 | Microsoft Threat Intelligence, Marbled Dust zero-day in Output Messenger, 2025-05-12 | https://www.microsoft.com/en-us/security/blog/2025/05/12/marbled-dust-leverages-zero-day-in-output-messenger-for-regional-espionage/ | 2026-11-03 | Confirmed |
| 47 | Mandiant, UNC1151 linked to the Belarusian government, 2021-11-16 | https://cloud.google.com/blog/topics/threat-intelligence/unc1151-linked-to-belarus-government | 2026-11-03 | Confirmed |
| 48 | ESET Research, MoustachedBouncer espionage against foreign diplomats in Belarus, 2023-08-10 | https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/ | 2026-11-03 | Confirmed |
| 49 | Citizen Lab, "Keep Calm and (Don't) Enable Macros" (Stealth Falcon), 2016-05-29 | https://citizenlab.ca/2016/05/stealth-falcon/ | 2026-11-03 | Confirmed |
| 50 | The Record, Microsoft and CISA zero-day used against a Turkish defense organization, 2025-06-10 (secondary; the Check Point primary could not be opened) | https://therecord.media/microsoft-cisa-zero-day-turkish-defense-org | 2026-11-03 | Reported |
| 51 | NVD CVE API record, CVE-2025-33053 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-33053 | 2026-11-03 | Confirmed |
| 52 | Kaspersky Securelist, "The Darkhotel APT", 2014-11-10 | https://securelist.com/the-darkhotel-apt/66779/ | 2026-11-03 | Confirmed |
| 53 | Kaspersky Securelist, SideWinder APT, 2024-10-15 | https://securelist.com/sidewinder-apt/114089/ | 2026-11-03 | Confirmed |
| 54 | Kaspersky Securelist, SideWinder updates its toolset and targets the nuclear sector, 2025-03-10 | https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/ | 2026-11-03 | Confirmed |
| 55 | CISA and NCSC, AA20-126A, APT groups target healthcare and essential services, 2020-05-05 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-126a | 2026-11-03 | Confirmed |
| 56 | CISA Known Exploited Vulnerabilities catalog JSON, catalog version 2026.11.03 (1,767 entries) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |
| 57 | Kaspersky GReAT, "Equation: The Death Star of Malware Galaxy", 2015-02-16 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-03 | Confirmed |
| 58 | Kaspersky GReAT, "A Fanny Equation: I am your father, Stuxnet", 2015-02-17 | https://securelist.com/a-fanny-equation-i-am-your-father-stuxnet/68787/ | 2026-11-03 | Confirmed |
| 59 | Kaspersky, "The Flame: Questions and Answers", 2012-05-28 | https://securelist.com/the-flame-questions-and-answers/34344/ | 2026-11-03 | Confirmed |
| 60 | Kaspersky, "The Mystery of Duqu 2.0", 2015-06-10 | https://securelist.com/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/70504/ | 2026-11-03 | Confirmed |
| 61 | Kaspersky, "Regin: nation-state ownage of GSM networks", 2014-11-24 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-03 | Confirmed |
| 62 | WikiLeaks, Vault 7 "Year Zero", 2017-03-07 (a leak publisher's claim; authenticity never officially confirmed) | https://wikileaks.org/ciav7p1/ | 2026-11-03 | Reported |
| 63 | Kaspersky GReAT, "Unraveling the Lamberts toolkit", 2017-04-11 | https://securelist.com/unraveling-the-lamberts-toolkit/77990/ | 2026-11-03 | Confirmed |
| 64 | Microsoft MSRC, "Protecting customers and evaluating risk", 2017-04-15 | https://www.microsoft.com/en-us/msrc/blog/2017/04/protecting-customers-and-evaluating-risk | 2026-11-03 | Confirmed |
| 65 | Microsoft On the Issues, urgent collective action after WannaCrypt, 2017-05-14 | https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/ | 2026-11-03 | Confirmed |
| 66 | Kaspersky, "Operation Triangulation", 2023-06-01 | https://securelist.com/operation-triangulation/109842/ | 2026-11-03 | Confirmed |
| 67 | China CVERC with 360, Northwestern Polytechnical University intrusion report, 2022-09-05 (a rival government's accusation; attribution unverified) | https://www.cverc.org.cn/head/zhaiyao/news20220905-NPU.htm | 2026-11-03 | Reported |
| 68 | Mandiant, APT1 report on China's cyber espionage units, 2013-02-19 | https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units | 2026-11-03 | Confirmed |
| 69 | UK Government, "UK and allies reveal global scale of Chinese cyber campaign", 2018-12-20 | https://www.gov.uk/government/news/uk-and-allies-reveal-global-scale-of-chinese-cyber-campaign | 2026-11-03 | Confirmed |
| 70 | Microsoft, "HAFNIUM targeting Exchange Servers with 0-day exploits", 2021-03-02 | https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/ | 2026-11-03 | Confirmed |
| 71 | White House statement attributing malicious cyber activity to the PRC, 2021-07-19 (archived) | https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2021/07/19/the-united-states-joined-by-allies-and-partners-attributes-malicious-cyber-activity-and-irresponsible-state-behavior-to-the-peoples-republic-of-china/ | 2026-11-03 | Confirmed |
| 72 | FBI and CISA, AA21-200A, APT40 tradecraft, 2021-07-19 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a | 2026-11-03 | Confirmed |
| 73 | ASD's ACSC and partners, AA24-190A, APT40 advisory, 2024-07-08 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a | 2026-11-03 | Confirmed |
| 74 | Microsoft, Volt Typhoon targets US critical infrastructure, 2023-05-24 | https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/ | 2026-11-03 | Confirmed |
| 75 | NSA, CISA, FBI and partners, AA23-144A, 2023-05-24 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a | 2026-11-03 | Confirmed |
| 76 | CISA, NSA, FBI and partners, AA24-038A, 2024-02-07 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a | 2026-11-03 | Confirmed |
| 77 | NSA, CISA, FBI and 20 partner agencies, AA25-239A, 2025-08-27 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a | 2026-11-03 | Confirmed |
| 78 | UK Government, China state-affiliated organisations and individuals held responsible, 2024-03-25 | https://www.gov.uk/government/news/uk-holds-china-state-affiliated-organisations-and-individuals-responsible-for-malicious-cyber-activity | 2026-11-03 | Confirmed |
| 79 | US Treasury OFAC, Integrity Technology Group sanctions (Flax Typhoon), 2025-01-03 | https://home.treasury.gov/news/press-releases/jy2769 | 2026-11-03 | Confirmed |
| 80 | FBI and CISA, warning on PRC targeting of COVID-19 research, 2020-05-13 | https://www.cisa.gov/news-events/news/fbi-and-cisa-warn-against-chinese-targeting-covid-19-research-organizations | 2026-11-03 | Confirmed |
| 81 | UK Government, "UK exposes Russian cyber attacks", 2018-10-04 | https://www.gov.uk/government/news/uk-exposes-russian-cyber-attacks | 2026-11-03 | Confirmed |
| 82 | NCSC, "Advisory: APT29 targets COVID-19 vaccine development", 2020-07-16 | https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development | 2026-11-03 | Confirmed |
| 83 | US agencies, AA21-116A, SVR tradecraft, 2021-04-26 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a | 2026-11-03 | Confirmed |
| 84 | White House fact sheet, imposing costs for harmful foreign activities by the Russian government, 2021-04-15 (archived) | https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/ | 2026-11-03 | Confirmed |
| 85 | US, Polish and UK agencies, AA23-347A, SVR exploitation of JetBrains TeamCity, 2023-12-13 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a | 2026-11-03 | Confirmed |
| 86 | Five Eyes agencies, AA23-129A, Snake malware, 2023-05-09 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a | 2026-11-03 | Confirmed |
| 87 | Multinational agencies, AA25-141A, GRU Unit 26165 targeting logistics and technology, 2025-05-21 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a | 2026-11-03 | Confirmed |
| 88 | US and partner agencies, AA24-249A, GRU Unit 29155, 2024-09-05 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a | 2026-11-03 | Confirmed |
| 89 | Microsoft MSRC, actions following attack by nation-state actor Midnight Blizzard, 2024-01 | https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/ | 2026-11-03 | Confirmed |
| 90 | UK Government, Foreign Office minister condemns North Korean actor for WannaCry, 2017-12-19 | https://www.gov.uk/government/news/foreign-office-minister-condemns-north-korean-actor-for-wannacry-attacks | 2026-11-03 | Confirmed |
| 91 | UK National Audit Office, "Investigation: WannaCry cyber attack and the NHS", 2017-10-27 | https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/ | 2026-11-03 | Confirmed |
| 92 | US Treasury OFAC, sanctions on North Korean state-sponsored groups, 2019-09-13 | https://home.treasury.gov/news/press-releases/sm774 | 2026-11-03 | Confirmed |
| 93 | US agencies, AA20-239A, FASTCash 2.0 (BeagleBoyz), 2020-08-26 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a | 2026-11-03 | Confirmed |
| 94 | CISA, FBI and CNMF, AA20-301A, Kimsuky, 2020-10-27 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a | 2026-11-03 | Confirmed |
| 95 | FBI, CISA and Treasury, AA22-108A, TraderTraitor, 2022-04-18 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a | 2026-11-03 | Confirmed |
| 96 | FBI, CISA and Treasury, AA22-187A, Maui ransomware, 2022-07-06 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-187a | 2026-11-03 | Confirmed |
| 97 | NSA, FBI, CISA, HHS, ROK NIS and DSA, AA23-040A, DPRK ransomware against healthcare, 2023-02-09 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-040a | 2026-11-03 | Confirmed |
| 98 | US, South Korean and UK agencies, AA24-207A, Andariel, 2024-07-25 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a | 2026-11-03 | Confirmed |
| 99 | FBI IC3 public service announcement on the Bybit theft, 2025-02-26 | https://www.ic3.gov/PSA/2025/PSA250226 | 2026-11-03 | Confirmed |
| 100 | US, Australian and UK agencies, AA21-321A, Iranian government-sponsored APT, 2021-11-17 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a | 2026-11-03 | Confirmed |
| 101 | US and UK agencies, AA22-055A, MuddyWater, 2022-02-24 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a | 2026-11-03 | Confirmed |
| 102 | US Treasury OFAC, APT39 and Rana Intelligence Computing sanctions, 2020-09-17 | https://home.treasury.gov/news/press-releases/sm1127 | 2026-11-03 | Confirmed |
| 103 | US, Israeli, Canadian and UK agencies, AA23-335A, IRGC-affiliated actors exploit PLCs, 2023-12-01 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a | 2026-11-03 | Confirmed |
| 104 | US agencies, AA24-241A, Iran-based actors enable ransomware, 2024-08-28 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a | 2026-11-03 | Confirmed |
| 105 | US, Canadian and Australian agencies, AA24-290A, Iranian brute force and MFA push bombing, 2024-10-16 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a | 2026-11-03 | Confirmed |
| 106 | US Treasury OFAC, SamSam-related sanctions, 2018-11-28 | https://home.treasury.gov/news/press-releases/sm556 | 2026-11-03 | Confirmed |
| 107 | US agencies, AA22-264A, Iranian state actors against the Government of Albania (events of July and September 2022) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a | 2026-11-03 | Confirmed |
| 108 | Google TAG, Iranian-backed group steps up phishing against Israel and the US, 2024-08-14 | https://blog.google/threat-analysis-group/iranian-backed-group-steps-up-phishing-campaigns-against-israel-us/ | 2026-11-03 | Confirmed |
| 109 | CISA, FBI, DC3 and NSA fact sheet, Iranian cyber actors may target vulnerable US networks, 2025-06-30 | https://www.cisa.gov/resources-tools/resources/iranian-cyber-actors-may-target-vulnerable-us-networks-and-entities-interest | 2026-11-03 | Confirmed |


*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors](/THREAT_ACTORS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Related case studies: [All case studies](/case-studies/README.md); [China-Attributed Threat Actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Operation Exchange Marauder](/case-studies/EXCHANGE_MARAUDER_2021.md), [APT41: The Public Record](/case-studies/APT41_PUBLIC_RECORD.md), [Stuxnet](/case-studies/STUXNET.md), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [Log4Shell](/case-studies/LOG4SHELL.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md)
- Generated MITRE pages: groups [Sea Turtle `G1041`](/mitre/groups/G1041.md), [APT32 `G0050`](/mitre/groups/G0050.md), [Dark Caracal `G0070`](/mitre/groups/G0070.md), [Transparent Tribe `G0134`](/mitre/groups/G0134.md), [Patchwork `G0040`](/mitre/groups/G0040.md), [Sidewinder `G0121`](/mitre/groups/G0121.md), [Stealth Falcon `G0038`](/mitre/groups/G0038.md), [MoustachedBouncer `G1019`](/mitre/groups/G1019.md), [Darkhotel `G0012`](/mitre/groups/G0012.md) and [Equation `G0020`](/mitre/groups/G0020.md); campaigns [`C0011`](/mitre/campaigns/C0011.md) and [`C0033`](/mitre/campaigns/C0033.md); software [SnappyTCP `S1163`](/mitre/software/S1163.md), [Disco `S1088`](/mitre/software/S1088.md), [NightClub `S1090`](/mitre/software/S1090.md), [FinFisher `S0182`](/mitre/software/S0182.md), [BADNEWS `S0128`](/mitre/software/S0128.md) and [Crimson `S0115`](/mitre/software/S0115.md); techniques [Malicious File `T1204.002`](/mitre/techniques/T1204-002.md), [Spearphishing Attachment `T1566.001`](/mitre/techniques/T1566-001.md), [DNS Server `T1584.002`](/mitre/techniques/T1584-002.md), [Content Injection `T1659`](/mitre/techniques/T1659.md) and [Code Signing `T1553.002`](/mitre/techniques/T1553-002.md)
