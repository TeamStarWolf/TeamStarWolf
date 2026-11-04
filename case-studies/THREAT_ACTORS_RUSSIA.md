# Russia-Attributed Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Healthcare Security](/HEALTHCARE_SECURITY_REFERENCE.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)

## Executive summary

Anyone who has defended a network in Europe or North America over the past decade has met the activity in this study, usually under a nickname. Fancy Bear in an election inbox. Cozy Bear in a vaccine lab. Sandworm switching off substations in Ukraine. Snake infrastructure in more than 50 countries. Star Blizzard writing to a think-tank researcher as a trusted colleague. Behind those nicknames, governments have now named the paying customer: three military intelligence units of the GRU, the SVR foreign intelligence service, two centers of the FSB security service and a Ministry of Defense research institute. This study gathers the public record on those units and the groups the community tracks for them, dates every event, and grades every claim by the source that supports it.

The record supports five plain statements. First, attribution is unusually specific. Joint advisories from the US, the UK and their partners map tracked groups to named units: GRU Unit 26165 to APT28, GRU Unit 74455 to Sandworm, GRU Unit 29155 to the WhisperGate operators, the SVR to APT29, FSB Center 16 to Berserk Bear and the Snake toolset, FSB Center 18 to Star Blizzard, and TsNIIKhM to the Triton operators (**Confirmed**, AA22-110A, AA23-129A, AA23-341A, AA24-249A [30] [38] [40] [51]). Second, the court record is deep. US grand juries indicted GRU officers in 2018 (twice) and 2020, four Russian government employees over energy-sector intrusions in 2022, an FSB officer in 2023 and five Unit 29155 officers in 2024 (**Confirmed**, FBI wanted notices [7] [9] [14] [29] [39] [52]). Third, the way in is ordinary. Every one of the 26 CVEs named in five joint advisories and an FBI notice on these actors is in CISA's Known Exploited Vulnerabilities catalog, and FSB Center 16 was still exploiting a 2018 Cisco flaw in 2025 (**Confirmed** [92] [56]). Fourth, the services overlap and the labels move. The December 2025 attack on Poland's energy sector was assigned to Sandworm by ESET at medium confidence, while CERT Polska found a high degree of infrastructure overlap with the cluster known as Static Tundra, Berserk Bear, Ghost Blizzard or Dragonfly (which the FBI attributes to FSB Center 16 [56]), before the UK and EU formally attributed it to FSB Centre 16 in July 2026 (**Confirmed** [79] [58] [61]). Fifth, healthcare sits in the record in three ways: espionage against vaccine research (APT29 and APT28 in 2020), collateral damage from destructive malware (NotPetya in 2017), and sector lists in broad targeting advisories (Unit 29155 in 2024, FSB Center 16 in 2026). Disruptive attacks on hospitals themselves come from Russia-based criminals and pro-Russia hacktivists, not from a named state unit (**Inferred** from [12] [50] [32] [51] [62] [33] [34]).

What this means for a security program is practical. The most-stated technique across these advisories is exploitation of a public-facing application, so internet-facing patching against KEV is the shared first control against all three services. Identity is the second front: password spraying, dormant accounts, stolen tokens, MFA fatigue and session-cookie theft recur in the SVR, GRU and FSB advisories alike. End-of-life routers and switches are exposure in their own right. Healthcare organisations should plan for state espionage against research and for criminal disruption of care, and should not assume that only one of the two applies.

Evidence grade: the government, court and ATT&CK record is **Confirmed** against primary sources opened on 3 November 2026. Vendor attributions are reported at the confidence each vendor states. Two press items (the Dutch Laundry Bear attribution and the Merck NotPetya ruling), the ATT&CK descriptions of the 2016 election intrusions, the indictments, TEMP.Veles, ALLANITE and the criminal groups, the Ukrainian attributions of Gamaredon and Kyivstar, and HC3's SolarWinds hospital claim are **Reported**, because only a secondary or summary source was opened for them.

### Key facts at a glance

| Field | Value |
|---|---|
| Services named by governments | GRU: 85th GTsSS (Unit 26165), GTsST (Unit 74455), 161st Specialist Training Center (Unit 29155); SVR; FSB: Center 16 (Unit 71330) and Center 18 (Unit 64829); Ministry of Defense research institute TsNIIKhM [30] [51] |
| Main tracked groups | APT28 [`G0007`](/mitre/groups/G0007.md), Sandworm Team [`G0034`](/mitre/groups/G0034.md), Ember Bear [`G1003`](/mitre/groups/G1003.md), APT29 [`G0016`](/mitre/groups/G0016.md), Turla [`G0010`](/mitre/groups/G0010.md), Dragonfly [`G0035`](/mitre/groups/G0035.md), Star Blizzard [`G1033`](/mitre/groups/G1033.md), Gamaredon Group [`G0047`](/mitre/groups/G0047.md), TEMP.Veles [`G0088`](/mitre/groups/G0088.md) |
| Earliest dated activity | Snake development from late 2003 (FSB, per nine agencies) [38]; APT28 and Turla active since at least 2004 (ATT&CK) [80] [83] |
| US indictments | 2018-07-13 (12 GRU officers), 2018-10-03 (7 GRU officers), 2020-10-15 (6 GRU officers), announced 2022-03-24 (4 Russian government employees), 2023-12-05 (an FSB officer and a Callisto Group affiliate), announced 2024-09-05 (5 Unit 29155 officers and a civilian) [7] [9] [14] [29] [39] [52] |
| Sanctions | US Treasury: TsNIIKhM (2020-10-23), six technology companies serving the intelligence services (2021-04-15); UK: two Star Blizzard members, Peretyatko and Korinets (2023-12-07); UK: 24 designations announced with the first joint UK-EU cyber sanctions package (2026-07-13) [17] [20] [41] [61] |
| CVEs in the advisories | 26 named in AA20-296A, AA22-011A, AA23-347A, AA24-249A, AA25-141A and FBI PSA I-082025-PSA; all 26 in KEV; 11 marked for known ransomware use [92] |
| ATT&CK v20.0 footprint | 330 Enterprise techniques across nine groups, eight campaigns and eight advisories (252 at group level, 41 campaign-only, 37 advisory-only) [100] |
| Healthcare in the record | SVR vaccine-research espionage (2020); NotPetya collateral (2017); Unit 29155 (2024) and FSB Center 16 (2026) sector lists; hospital disruption by KillNet and Russia-based ransomware crews [12] [32] [51] [62] [35] [34] |
| Latest public record | UK-EU formal attribution of the December 2025 Poland energy attack to FSB Centre 16 and a 19-agency router advisory, both 2026-07-13 [61] [62]; FBI notice on APT28 SOHO router compromise, 2026-04-07 [59] |

### Key findings

- **Governments name units, not just countries.** AA22-110A, issued by five governments on 20 April 2022, lists FSB Center 16 (unit 71330), FSB Center 18 (unit 64829), the SVR, GRU 85th GTsSS (unit 26165), GRU GTsST (unit 74455) and TsNIIKhM as the Russian organizations that run cyber operations, and maps them to Berserk Bear, APT29, APT28, Sandworm and TEMP.Veles (**Confirmed** [30]). AA24-249A adds GRU Unit 29155, separate from the other two GRU units (**Confirmed** [51]).
- **Confidence has firmed over time.** FireEye called APT28 "most likely sponsored by the Russian government" in 2014; the NCSC and partners said "almost certainly" Unit 26165 in 2023. Dragonfly went from "Russian government cyber actors" via Symantec (2018) to "almost certainly" FSB Center 16 (2022) to a formal UK-EU attribution (2026) (**Confirmed** for each statement [65] [37] [5] [30] [61]; the trend is **Inferred**).
- **The court record reaches the GRU, the FSB and TsNIIKhM; no SVR officer is charged in the record opened.** The 2018 election indictment charged officers of both Unit 26165 and Unit 74455; the 2020 indictment charged Unit 74455 officers for Ukraine, NotPetya, Olympic Destroyer and Georgia; the 2022 case charged a TsNIIKhM employee over safety-system attacks; the 2023 case charged an FSB officer; the 2024 case charged Unit 29155 officers over WhisperGate (**Confirmed** [7] [8] [14] [29] [39] [52]).
- **Old, known flaws carry the intrusions.** All 26 CVEs named in the five joint advisories and the FBI notice are in KEV; the earliest entries date from the catalog's launch on 3 November 2021. CVE-2018-0171 in Cisco Smart Install has been in KEV since that day, yet the FBI reported FSB Center 16 exploiting it in August 2025 (**Confirmed** [92] [56]; the patch-debt reading is **Inferred**).
- **Identity attacks cross every service.** Password spraying is stated for the SVR (AA24-057A), the GRU (AA24-249A, AA25-141A) and earlier Russian state actors (AA22-011A); Star Blizzard steals session cookies that defeat ordinary MFA (AA23-341A); Midnight Blizzard sprayed a legacy Microsoft test tenant without MFA in late 2023 (**Confirmed** [45] [51] [55] [26] [40] [69]).
- **Network devices are a long campaign.** TA18-106A (2018) warned of Russian state exploitation of routers through Smart Install, SNMP and GRE; APT28 used a 2017 Cisco flaw for Jaguar Tooth in 2021; APT28 used compromised EdgeRouters to proxy traffic and harvest credentials (2024) and hijacked DHCP and DNS on compromised SOHO routers for adversary-in-the-middle attacks (FBI, 2026); FSB Center 16 copied router configurations worldwide through 2026 (**Confirmed** [6] [37] [46] [59] [62]).
- **Sources disagree on the newest attacks.** ESET assigns the 29 December 2025 Poland wiper attempt to Sandworm at medium confidence; CERT Polska reports a high degree of infrastructure overlap with the Static Tundra, Berserk Bear, Ghost Blizzard and Dragonfly cluster and does not mention Sandworm; ATT&CK records both readings in campaign C0063 and associates it with no group (**Confirmed** [79] [58] [90]). The operational record of the attack and the attribution dispute are covered in [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md).
- **Healthcare is a target of espionage and a casualty of disruption.** APT29 went after COVID-19 vaccine research in Canada, the US and the UK in 2020; SVR TeamCity exploitation in 2023 reached a medical-device software maker; HC3 recorded KillNet's 28 January 2023 DDoS wave on hospitals; the FBI counted at least 16 Conti attacks on US healthcare and first-responder networks in a year (**Confirmed** [12] [42] [35] [23]).

### Top recommendations

1. Patch internet-facing systems against KEV first, then against every CVE these advisories name. `T1190` Exploit Public-Facing Application is stated in six of the eight advisories with ATT&CK tables opened for this study, across GRU, SVR and FSB units (**Inferred** from [16] [26] [38] [42] [51] [55]). Treat "in KEV and named in a Russia advisory" as the top tier of your remediation SLA.
2. Inventory and retire end-of-life network devices. Disable Cisco Smart Install, SNMPv1 and v2c and Telnet, block TCP 4786 at the boundary and keep management planes off the internet, as TA18-106A asked in 2018; the FBI's 2025 notice shows the same Smart Install flaw still being exploited on end-of-life devices (**Confirmed** [6] [56]).
3. Move to phishing-resistant MFA and close the identity gaps the advisories list: dormant accounts, over-privileged service accounts, legacy OAuth applications with app-only mail rights, open device registration (**Confirmed** [45] [51] [55] [69]). Use [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Credential Hardening](/mitre/d3fend/credential-hardening.md) as the countermeasure pages.
4. Block outbound SMB and NTLM to the internet and plan NTLM retirement. AA25-141A ties this to the Outlook NTLM flaw CVE-2023-23397 that Unit 26165 used (**Confirmed** [55]).
5. Put EDR on mail servers and domain controllers first, alert when EDR goes silent, and keep memory forensics available for kernel implants such as Snake (**Confirmed** [55] [42] [38]).
6. Healthcare and life-science organisations: treat research data as an espionage target and clinical operations as a disruption target. Use the NCSC 2020 vaccine advisory and AA24-249A sector lists for the first, and the HC3 KillNet notes and ransomware advisories for the second (**Inferred** from [12] [51] [35] [18]).
7. Test controls against the study layer. AA24-249A and AA23-347A ask defenders to validate security controls against the ATT&CK techniques they list (**Confirmed** [51] [42]); Part 8 gives the layer.

## Scope and method

This study covers activity that a government, a court record, MITRE ATT&CK or a named vendor attributes to a Russian state organization, from the earliest dated record (FSB development of Snake from late 2003) to the UK-EU attribution and the 19-agency router advisory of 13 July 2026. It adds a short, separately labelled section on Russia-nexus groups that no government opened for this study attributes to a named service, and on Russia-based criminal and hacktivist groups, because both matter to defenders and especially to healthcare. It draws on six kinds of source: US court records restated in FBI wanted notices; joint government advisories and attribution statements from the US, UK, France, Czechia and others; sanctions designations; vendor threat reports; the MITRE ATT&CK, D3FEND and CAPEC record; and the TeamStarWolf library's own data files at commit `e85b5594`. Every source in the Sources table was opened on 3 November 2026.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the court, agency, vendor, victim or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution, at the confidence it states; it does not upgrade the source's own confidence |
| Reported | Only a secondary source (press coverage, or ATT&CK's summary of an indictment or report that was not itself opened) was available |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

This study grades by source type (primary opened versus secondary only), the scheme the newer case studies use; under the README's original scheme, single-vendor reports would read as Reported.

Four rules govern the names and the boundaries.

1. The study says which name each source uses ("Microsoft's Midnight Blizzard", "Mandiant's APT44", "CERT Polska's Static Tundra cluster") rather than merging labels, and a source's own hedge travels with its claim ("almost certainly", "medium confidence", "highly likely").
2. Where a government names a unit and ATT&CK does not, both are reported. ATT&CK's Star Blizzard page, for example, names no service; the joint advisory it cites says FSB Centre 18 (**Confirmed** [87] [40]).
3. Events that have a home study elsewhere in the library are summarized here in one paragraph and linked. Sandworm's operations (the Ukraine grid attacks, NotPetya, Olympic Destroyer, Industroyer2) belong in `case-studies/SANDWORM_OPERATIONS.md`; the SolarWinds Orion compromise belongs in [SOLARWINDS_SUNBURST.md](/case-studies/SOLARWINDS_SUNBURST.md); the ALPHV attack on Change Healthcare belongs in `case-studies/CHANGE_HEALTHCARE_2024.md`; the operational record of the 29 December 2025 attack on Polish energy sites, and the attribution dispute around it, belong in [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md). For a comparison with a China-attributed actor that mixes espionage and crime, see `case-studies/APT41_PUBLIC_RECORD.md`.
4. Tradecraft is described at the level the advisories use, by technique name and ATT&CK id. The study reproduces no commands, payloads or exploit details.

Some sources did not load on 3 November 2026 and are not cited as opened. justice.gov served a bot-verification page to scripted clients, so the Justice Department press releases of 13 July 2018, 4 October 2018, 19 October 2020, 24 March 2022, 9 May 2023 (Operation MEDUSA), 5 September 2024 and 3 October 2024 were not read; the indictments are cited instead through the FBI wanted notices, which are primary government documents that restate each charge, court, date and unit, and one Justice Department release (15 February 2024) was read from an archived copy of the same URL. NSA PDFs on media.defense.gov returned 403, including the 2021 GRU brute-force advisory (only the CISA bulletin announcing it was opened) and the 2020 Drovorub advisory. The NCSC's October 2018 GRU statement has been removed. Ukraine's SSU statement on Gamaredon, the German government's May 2024 APT28 attribution, the US State Department's Viasat page, the Dutch AIVD and MIVD Laundry Bear report, HHS's February 2024 brief on Russian actors and the New Jersey court opinion in the Merck case did not load either. Where a claim rests on a secondary account of one of these, it is graded Reported.

## Part 1: the services, the units and the names

### The unit map as governments draw it

| Service | Unit as governments name it | Community names cited by the same documents | ATT&CK object | Sources |
|---|---|---|---|---|
| GRU | 85th Main Special Service Center (GTsSS), military unit 26165 | APT28, Fancy Bear, Forest Blizzard, BlueDelta, Sofacy, Pawn Storm, Sednit, Tsar Team | [`G0007`](/mitre/groups/G0007.md) APT28 | [30] [55] [60] [80] |
| GRU | Main Center for Special Technologies (GTsST), military unit or field post 74455 | Sandworm, APT44, Seashell Blizzard, ELECTRUM, Voodoo Bear, Telebots | [`G0034`](/mitre/groups/G0034.md) Sandworm Team | [30] [10] [15] [71] [82] |
| GRU | 161st Specialist Training Center, military unit 29155 | Cadet Blizzard, Ember Bear, UNC2589, UAC-0056, DEV-0586 | [`G1003`](/mitre/groups/G1003.md) Ember Bear | [51] [86] |
| SVR | Foreign Intelligence Service | APT29, Cozy Bear, the Dukes, NOBELIUM, Midnight Blizzard | [`G0016`](/mitre/groups/G0016.md) APT29 | [19] [22] [30] [45] [81] |
| FSB | Center 16, military unit 71330 | Berserk Bear, Energetic Bear, Dragonfly, Crouching Yeti, Ghost Blizzard, Static Tundra; and a unit within Center 16 running the Snake and Turla toolset (Venomous Bear, Secret Blizzard) | [`G0035`](/mitre/groups/G0035.md) Dragonfly; [`G0010`](/mitre/groups/G0010.md) Turla | [30] [38] [56] [83] [84] |
| FSB | Center 18 (Center for Information Security), military unit 64829 | Star Blizzard, SEABORGIUM, Callisto Group, COLDRIVER, TA446; Gamaredon (Primitive Bear, Armageddon) per Ukraine's government only | [`G1033`](/mitre/groups/G1033.md) Star Blizzard; [`G0047`](/mitre/groups/G0047.md) Gamaredon Group | [30] [40] [85] |
| Ministry of Defense | Central Scientific Research Institute of Chemistry and Mechanics (TsNIIKhM) | TEMP.Veles, XENOTIME; the Triton (TRISIS, HatMan) operators | [`G0088`](/mitre/groups/G0088.md) TEMP.Veles | [17] [30] |

France named a further GRU unit. Its April 2025 statement links GRU Unit 20728 to pressure on Ukrainian infrastructure, while UK and US documents tie APT28 itself to Unit 26165 (**Confirmed** [53] [55] [60]).

### How ATT&CK words each attribution

ATT&CK, the community's shared catalog of adversary behavior, carries its own attribution sentence for each group. Read side by side with the government record, the wording falls into four tiers (**Confirmed** for each sentence [80] to [90]; the tiering is **Inferred**).

| Tier | Groups | ATT&CK wording |
|---|---|---|
| Named service in ATT&CK's own text | APT28 (GRU 85th GTsSS, unit 26165), Sandworm Team (GRU GTsST, unit 74455), Ember Bear (GRU 161st Specialist Training Center, Unit 29155), APT29 (SVR), Turla (FSB), Dragonfly (FSB Center 16) | Attributed to the named unit or service [80] [82] [86] [81] [83] [84] |
| Service named only as another government's claim | Gamaredon Group | "Suspected Russian"; ATT&CK carries the November 2021 Ukrainian government attribution to FSB Center 18 rather than its own [85] |
| Russia-nexus, no service named | Star Blizzard (originating in Russia, campaigns aligned to Russian state interests), Saint Bear (Russian-nexus, since early 2021), Winter Vivern (linked to Russian and Belorussian interests), TEMP.Veles (Russia-based), ALLANITE (suspected Russian, ATT&CK for ICS only) | [87] [88] [89] [94] [95] |
| Russia-based criminal | Wizard Spider ([`G0102`](/mitre/groups/G0102.md)), Indrik Spider ([`G0119`](/mitre/groups/G0119.md), Evil Corp) | Criminal groups; Indrik Spider changed tactics after 2019 US sanctions and an indictment [93] |

Three groups ATT&CK describes only by language (FIN5, whose actors "likely speak Russian"; Nomadic Octopus, "Russian-speaking"; RedCurl, "allegedly a Russian-speaking" actor) [93] are left out: language is not attribution.

### Vendor names in common use

Microsoft's "Blizzard" names appear throughout the sources opened, so they are given here with the other names each ATT&CK object lists (**Confirmed** from the library's copy of the ATT&CK alias lists [93] and the vendor posts cited).

| ATT&CK object | Blizzard name | Other names on the ATT&CK object |
|---|---|---|
| APT28 `G0007` | Forest Blizzard | Fancy Bear, STRONTIUM, Sofacy, Sednit, Pawn Storm, Tsar Team, IRON TWILIGHT, SNAKEMACKEREL, FROZENLAKE, GruesomeLarch |
| Sandworm Team `G0034` | Seashell Blizzard | APT44, ELECTRUM, IRIDIUM, Telebots, Voodoo Bear, IRON VIKING, FROZENBARENTS |
| Ember Bear `G1003` | Cadet Blizzard | DEV-0586, UNC2589, Bleeding Bear, Frozenvista, UAC-0056 |
| APT29 `G0016` | Midnight Blizzard | Cozy Bear, The Dukes, NOBELIUM, YTTRIUM, UNC2452, UNC3524, Dark Halo, IRON RITUAL, IRON HEMLOCK |
| Turla `G0010` | Secret Blizzard | Snake, Venomous Bear, Krypton, Waterbug, WhiteBear, IRON HUNTER |
| Dragonfly `G0035` | Ghost Blizzard | Energetic Bear, Berserk Bear, Crouching Yeti, BROMINE, TEMP.Isotope, DYMALLOY, IRON LIBERTY |
| Star Blizzard `G1033` | Star Blizzard | SEABORGIUM, Callisto Group, COLDRIVER, TA446 |
| Gamaredon Group `G0047` | Aqua Blizzard | Primitive Bear, ACTINIUM, Armageddon, Shuckworm, IRON TILDEN |

Two naming traps are worth knowing. ATT&CK lists UAC-0056 as an alias of both Ember Bear and Saint Bear ([`G1031`](/mitre/groups/G1031.md)), while treating the two as distinct groups, and AA24-249A uses UAC-0056 for Unit 29155 (**Confirmed** [93] [86] [51]). And AA24-249A warns that vendor names may not map one-to-one to its own attribution (**Confirmed** [51]). The FBI's 2025 notice makes the same point for FSB Center 16, calling Berserk Bear and Dragonfly separate but related clusters (**Confirmed** [56]).

## Part 2: the groups one by one

### APT28 (GRU 85th GTsSS, Unit 26165)

ATT&CK attributes APT28 to GRU military unit 26165, active since at least 2004; the library data lists 93 Enterprise techniques and 29 software entries, and its only ATT&CK campaign is [`C0051`](/mitre/campaigns/C0051.md), the Nearest Neighbor campaign of February 2022 to November 2024 (**Confirmed** [80]). The live page lists 31 software ids; the library's copy lacks two, netsh ([`S0108`](/mitre/software/S0108.md)) and the Mobile-domain X-Agent for Android (`S0314`, no library page) (**Confirmed** [80] [93]).

FireEye's first public report, on 27 October 2014, said APT28 was most likely sponsored by the Russian government from Moscow and active since at least 2007 against governments, militaries and security organisations (**Confirmed** [65]). The UK's GRU profile attributes to Unit 26165 the April to May 2015 Bundestag hack, TV5Monde (2015), the 2016 DNC and DCCC intrusions, the 2017 French election, the 2018 intrusions into the OPCW, the Spiez laboratory and DSTL, and Paris 2024 (**Confirmed** [60]). The 2016 election thread is covered in the US record: the December 2016 GRIZZLY STEPPE report confirms APT28 entered a US political party in spring 2016 (**Confirmed** [2]), CrowdStrike placed FANCY BEAR in the DNC network from April 2016 with possible GRU affiliation (**Confirmed** [66]), and the July 2018 indictment placed defendant Lukashev in Unit 26165 (**Confirmed** [8]).

APT28 also attacked sport. WADA confirmed in September 2016 that Tsar Team (APT28, Fancy Bear) reached its ADAMS database through an IOC-created Rio 2016 account, probably by spear-phishing, and published confidential athlete medical data, including Therapeutic Use Exemptions (**Confirmed** [1]). A Western District of Pennsylvania grand jury indicted seven GRU officers on 3 October 2018 for intrusions from 2014 to May 2018 into USADA, WADA and other victims; defendant Morenets is listed in Unit 26165 (**Confirmed** [9]).

From 2021 the record turns to network devices and mail. APT28 exploited CVE-2017-6742 on Cisco routers to deploy Jaguar Tooth, hitting about 250 Ukrainian victims and US government institutions; the NCSC and partners assess "almost certainly" Unit 26165, with high confidence (**Confirmed** [36] [37]). In January 2024 a court-authorized operation neutralized hundreds of SOHO routers that Unit 26165 had repurposed from a network criminals built with Moobot malware (**Confirmed**, archived DOJ release [44]), and an 11-country advisory of 27 February 2024 described APT28's use of compromised Ubiquiti EdgeRouters to harvest credentials, collect NTLMv2 digests, proxy traffic and host spear-phishing pages (**Confirmed** [46]). Czechia attributed attacks on its institutions using a 2023 Outlook zero-day to APT28 on 3 May 2024 (**Confirmed** [47]). France formally condemned the GRU's use of APT28 against about a dozen French entities since 2021 on 29 April 2025, and ANSSI's companion report covers French government, diplomatic and research targets from 2021 to 2024 while naming no service (**Confirmed** [53] [54]).

AA25-141A, published in May 2025 by agencies from eleven countries and corrected in April 2026, reports that Unit 26165 has targeted Western logistics and technology companies since 2022 across 13 countries, including air traffic management, and targeted IP cameras at borders and rail stations from March 2022, 81% of them in Ukraine; the camera activity is assessed as "likely connected" (**Confirmed** [55]). In April 2026 the FBI reported that since at least 2024 APT28 had compromised SOHO routers, including TP-Link devices through CVE-2023-50224, and hijacked DHCP and DNS to run adversary-in-the-middle attacks on Outlook Web Access before narrowing to military, government and critical-infrastructure users (**Confirmed** [59]).

### Sandworm Team (GRU GTsST, Unit 74455)

ATT&CK attributes Sandworm Team to GRU unit 74455, active since at least 2009, with 79 Enterprise, 4 ICS and 3 Mobile techniques, 27 software entries and three campaigns: [`C0028`](/mitre/campaigns/C0028.md) (December 2015 to January 2016), [`C0025`](/mitre/campaigns/C0025.md) (December 2016) and [`C0034`](/mitre/campaigns/C0034.md) (June to October 2022) (**Confirmed** [82]). The live page also shows CaddyWiper ([`S0693`](/mitre/software/S0693.md)) and the Mobile-domain CHEMISTGAMES, which are not in the library's G0034 software list (**Confirmed** [82] [93]).

The operational story lives in `case-studies/SANDWORM_OPERATIONS.md`. In summary: the UK's GRU profile attributes to Unit 74455 BlackEnergy (2015, when 230,000 people lost power), Industroyer (2016), NotPetya and BadRabbit (2017), Georgia (2018) and Olympic Destroyer (2018) (**Confirmed** [60]); the White House and the UK both attributed NotPetya to the Russian military on 15 February 2018 (**Confirmed** [3] [4]); a Western District of Pennsylvania grand jury indicted six GRU officers, among them Andrienko of Unit 74455, on 15 October 2020 for Ukraine, the French campaign, Georgia, NotPetya, the 2018 Winter Olympics and nerve-agent investigations (**Confirmed** [14]); the US and UK attributed the 28 October 2019 Georgia attack to the GTsST on 20 February 2020 (**Confirmed** [10] [11]); and the UK exposed GTsST reconnaissance of Tokyo 2020 and confirmed the Pyeongchang Olympic Destroyer false flag on 19 October 2020 (**Confirmed** [15]). Mandiant graduated the group to APT44 in April 2024, "sponsored by Russian military intelligence" (**Confirmed** [71]). Ukraine's SBU named Unit 74455 for the December 2023 Kyivstar outage, which affected 24 million customers; the UK profile records no UK attribution of that attack (**Reported** [60]). AA25-343A adds that Unit 74455 likely supported the creation of the hacktivist front CARR and funded its DDoS tools through at least September 2024 (**Confirmed** [57]).

### Ember Bear and Cadet Blizzard (GRU Unit 29155)

ATT&CK links Ember Bear to the GRU 161st Specialist Training Center (Unit 29155), active since at least 2020, and credits it with the WhisperGate ([`S0689`](/mitre/software/S0689.md)) wiper attacks on Ukraine in early 2022; it has 47 techniques and 11 software entries (**Confirmed** [86]). AA24-249A, from the FBI, CISA, NSA and partners on 5 September 2024, attributes operations since 2020 to Unit 29155, including WhisperGate from 13 January 2022, and says the unit is separate from Units 26165 and 74455 (**Confirmed** [51]). The FBI counted more than 14,000 domain-scanning instances across at least 26 NATO members, and the listed target sectors include government services, financial services, transportation, energy and healthcare in NATO and EU members and in Central American and Asian countries (**Confirmed** [51]). The advisory notes that WhisperGate is not unique to Unit 29155 and that a related sample was seen at a US-based victim (**Confirmed** [51]). Five Unit 29155 officers and a civilian, Amin Stigal, are wanted for activity from December 2020 to August 2024, and Rewards for Justice offers up to $10 million (**Confirmed** [52]). The UK profile attributes Estonia (2020) and WhisperGate (2022) to the unit, and the UK said in May 2022 that Russian military intelligence was "almost certainly" involved in WhisperGate (**Confirmed** [60] [31]).

### APT29 (SVR)

ATT&CK attributes APT29 to the SVR, operating since at least 2008 against European and NATO government networks, research institutes and think tanks, with 66 techniques, 49 software entries and two campaigns: [`C0023`](/mitre/campaigns/C0023.md) Operation Ghost (September 2013 to October 2019) and [`C0024`](/mitre/campaigns/C0024.md), the SolarWinds Compromise (August 2019 to January 2021) (**Confirmed** [81]). The GRIZZLY STEPPE report confirms APT29 entered a US political party in summer 2015, and CrowdStrike found COZY BEAR in the DNC from summer 2015 with no sign of collaboration with FANCY BEAR (**Confirmed** [2] [66]).

The SolarWinds story belongs in [SOLARWINDS_SUNBURST.md](/case-studies/SOLARWINDS_SUNBURST.md). In summary: on 15 April 2021 the White House formally named the SVR, citing the Intelligence Community's high confidence and more than 16,000 affected systems; Treasury sanctioned six technology companies that support the intelligence services' cyber programs; and the UK assessed it highly likely that the SVR compromised SolarWinds Orion (**Confirmed** [19] [20] [21]).

The SVR's healthcare record starts in 2020. On 16 July 2020 the NCSC and Canada's CSE assessed APT29 as almost certainly part of the Russian intelligence services and said it had targeted COVID-19 vaccine development in Canada, the US and the UK with WellMess ([`S0514`](/mitre/software/S0514.md)) and WellMail ([`S0515`](/mitre/software/S0515.md)); the NSA agreed and CISA endorsed the technical detail (**Confirmed** [12] [13]). AA21-116A then equated SVR cyber actors with APT29 and reported WELLMESS intrusions that went after vaccine research repositories and Active Directory servers (**Confirmed** [22]). In December 2023, the FBI, CISA, NSA, Poland's SKW, CERT Polska and the NCSC reported that the SVR had exploited JetBrains TeamCity CVE-2023-42793 at scale since September 2023, compromising a few dozen companies and more than 100 devices; victims included software firms making billing and medical-device software, and the agencies judged the exploitation opportunistic (**Confirmed** [42]).

Microsoft's breach disclosure follows. Midnight Blizzard password-sprayed a legacy test tenant account from late November 2023 and read senior leadership email; Microsoft detected it on 12 January 2024, and its posts say "Russian state-sponsored" without naming the SVR (**Confirmed** [68]). The 8 March 2024 update reports access to some source code repositories and internal systems and password sprays up to ten times higher in February 2024 (**Confirmed** [70]). HPE's 8-K says a suspected nation-state actor believed to be Midnight Blizzard took data from its cloud email from May 2023, and that HPE was notified on 12 December 2023 (**Confirmed** [43]). AA24-057A, from the NCSC and seven partner agencies on 26 February 2024, assesses that APT29 is almost certainly part of the SVR and is shifting to initial access through cloud services (**Confirmed** [45]). Microsoft saw Midnight Blizzard's RDP-file spear-phishing first on 22 October 2024, against thousands of targets in more than 100 organisations, and noted the US and UK attribution to the SVR (**Confirmed** [73]). On 31 July 2026 Microsoft reassessed Storm-2372, a device-code phishing actor active since August 2024 against sectors including health, as an initial-access sub-cluster of Midnight Blizzard; in February 2025 it had called the actor Russia-aligned at moderate confidence (**Confirmed** [75]).

### Turla and Snake (FSB Center 16)

ATT&CK attributes Turla to the FSB, with victims in more than 50 countries since at least 2004, including government, embassies, military, education, research and pharmaceutical companies; it has 68 techniques, 30 software entries and no campaign objects (**Confirmed** [83]). Kaspersky's Epic Turla report of August 2014 found several hundred infected computers in more than 45 countries in the same sectors, with earliest dated artifacts from September 2012, and named no sponsor (**Confirmed** [64]).

AA23-129A, from nine agencies on 9 May 2023, says the FSB began developing Snake as "Uroburos" in late 2003, with first versions around early 2004, and attributes Snake to a known unit within Center 16 that also runs Turla tools; it calls Snake the most sophisticated espionage tool in the FSB's arsenal and rates memory analysis as the most effective detection (**Confirmed** [38]). Microsoft later reported Secret Blizzard taking over the infrastructure of the Pakistan-based Storm-0156 from November 2022 to reach Afghan government and Indian military targets (**Confirmed** [74]), and using an ISP-level adversary-in-the-middle position to push ApolloShadow at foreign embassies in Moscow, seen in February 2025 (**Confirmed** [77]). Both posts rely on CISA's FSB Center 16 attribution. The library's Turla software pages include Uroburos ([`S0022`](/mitre/software/S0022.md)), Carbon ([`S0335`](/mitre/software/S0335.md)), Kazuar ([`S0265`](/mitre/software/S0265.md)), ComRAT ([`S0126`](/mitre/software/S0126.md)), LightNeuron ([`S0395`](/mitre/software/S0395.md)) and TinyTurla ([`S0668`](/mitre/software/S0668.md)) (**Confirmed** [93]).

### Dragonfly, Berserk Bear and Static Tundra (FSB Center 16)

ATT&CK attributes Dragonfly to FSB Center 16, active since at least 2010 against defense, aviation, government, ICS-related and critical infrastructure targets, with 56 Enterprise and 2 ICS techniques and 10 software entries (**Confirmed** [84]). Its government record is a decade long. TA18-074A, of 15 March 2018, described a multi-stage campaign since at least March 2016 by "Russian government cyber actors" against US government entities and the energy, nuclear, commercial facilities, water, aviation and critical manufacturing sectors, staging through small commercial facilities and collecting ICS information; it names Dragonfly only through Symantec's reporting (**Confirmed** [5]). AA20-296A, of 22 October 2020, reported Berserk Bear targeting dozens of US state, local, territorial and tribal government and aviation networks since at least September 2020, with data taken from at least two servers (**Confirmed** [16]). On 24 March 2022 the UK and US exposed Center 16 as the group behind a global campaign against critical infrastructure, noting the FBI indictment for targeting the Wolf Creek nuclear plant in Kansas in 2017 (**Confirmed** [28]).

The network-device thread runs from 2018 to 2026. The FBI's August 2025 notice attributes to Center 16 (Talos's Static Tundra) exploitation of Cisco Smart Install CVE-2018-0171 and of SNMP on end-of-life devices, with configuration files collected from thousands of devices at US critical-infrastructure entities and an interest in ICS protocols; it says the unit has compromised network devices for over a decade (**Confirmed** [56]). AA26-194A, from 19 agencies on 13 July 2026, describes Center 16 opportunistically abusing SNMP default community strings and Cisco flaws CVE-2018-0171 and CVE-2008-4128 to copy router configurations worldwide, and names Healthcare and Public Health among the sectors most at risk (**Confirmed** [62]). On the same day the UK and EU member states formally attributed the failed December 2025 attack on Poland's energy sector to FSB Centre 16, saying it could have cut power to 500,000 citizens (**Confirmed** [61] [63]).

### Star Blizzard (FSB Center 18)

ATT&CK describes Star Blizzard as originating in Russia with campaigns aligned to Russian state interests; the description does not name the FSB, which appears only in the title of the joint advisory it cites (**Confirmed** [87]). That advisory, AA23-341A of 7 December 2023, from the NCSC and seven partners, assesses Star Blizzard as almost certainly subordinate to FSB Centre 18 and describes its targeting of academia, defense, government, NGOs, think tanks and politicians, mostly in the UK and US, expanding in 2022 to defense-industrial targets and DOE facilities (**Confirmed** [40]). The UK statement of the same day attributes the targeting of UK parliamentarians from 2015 to 2023, the 2018 Institute for Statecraft hack, the 2019 UK-US trade document leak and the compromise of the Institute founder's account from December 2021 (**Confirmed** [41]). A Northern District of California grand jury indicted FSB officer Ruslan Peretyatko and Callisto Group affiliate Andrey Korinets for a spear-phishing campaign seeking US intelligence on defense, foreign affairs and nuclear research (**Confirmed** [39]). Microsoft seized 66 Star Blizzard domains by court order and the Justice Department seized 41 more in October 2024; Microsoft counted 82 customers targeted from January 2023 (**Confirmed** [72]). Google's threat intelligence group attributes LOSTKEYS and its 2025 replacements NOROBOT, YESROBOT and MAYBEROBOT, delivered through fake CAPTCHA lures, to COLDRIVER, which it calls Russian state-sponsored without naming an agency (**Confirmed** [78]). The only ATT&CK software object is Spica ([`S1140`](/mitre/software/S1140.md)) (**Confirmed** [87]).

### Gamaredon Group (FSB Center 18, per Ukraine)

ATT&CK describes Gamaredon as a suspected Russian group targeting Ukrainian military, law enforcement, judiciary and NGOs since 2013, and carries the November 2021 Ukrainian government attribution to FSB Center 18 rather than its own; it has 70 techniques and 6 software entries (**Confirmed** [85]). The five-government AA22-110A describes PRIMITIVE BEAR only as industry reporting and does not attribute it (**Confirmed** [30]). The SSU primary did not load, so the Center 18 link is **Reported** here [99].

### TEMP.Veles and Triton (TsNIIKhM)

ATT&CK describes TEMP.Veles as Russia-based and tied to TRITON, with 0 Enterprise and 2 ICS techniques and two campaigns: [`C0032`](/mitre/campaigns/C0032.md), the IT foothold of October 2014 to January 2017, and [`C0030`](/mitre/campaigns/C0030.md), the Triton safety-instrumented-system attack of June to August 2017 (**Reported**, from the library's copy of ATT&CK [94]). Treasury designated TsNIIKhM on 23 October 2020 for its connection to Triton and its role in the August 2017 attack on a Middle East petrochemical facility, citing reported 2019 probing of at least 20 US electric utilities (**Confirmed** [17]). The FBI notice for Evgeny Gladkikh of TsNIIKhM's Applied Development Center lists a charge of conspiracy to damage an energy facility from August 2014 to July 2018, with safety instrumented systems as the target, in the case announced on 24 March 2022 (**Confirmed** [29]). The library has no generated page for the Triton software object `S1009`, an ICS-domain entry (**Confirmed** [100]).

### Russia-nexus groups with no named service in the sources opened

These groups are tied to Russia by ATT&CK or a vendor, but no government source opened for this study names a service for them.

| Group | What the record says | Grade and sources |
|---|---|---|
| Saint Bear [`G1031`](/mitre/groups/G1031.md) | Russian-nexus actor active since early 2021 against Ukraine and Georgia, using Saint Bot ([`S1018`](/mitre/software/S1018.md)) and OutSteel ([`S1017`](/mitre/software/S1017.md)); 18 techniques; ATT&CK keeps it distinct from Ember Bear | Confirmed [88] [86] |
| Winter Vivern [`G1035`](/mitre/groups/G1035.md) | No explicit state attribution; linked to Russian and Belorussian interests; active since at least 2020 against European government and NGO entities; 27 techniques, no software | Confirmed [89] |
| Void Blizzard (Laundry Bear) | Microsoft assesses with high confidence that it is Russia-affiliated, active since at least April 2024, targeting sectors including healthcare, with a Ukrainian aviation target in October 2024 and NGO adversary-in-the-middle phishing in April 2025; Dutch AIVD and MIVD and the FBI collaborated; no ATT&CK group id found | Confirmed [76] |
| Laundry Bear and the Dutch police | Dutch services tie Laundry Bear to the September 2024 Dutch police breach and call it extremely likely Russian state supported | Reported (press account [103]; the AIVD and MIVD primary did not load) |
| ALLANITE (`G1000`) | ATT&CK for ICS only: a suspected Russian group targeting US and UK electric utilities, 4 ICS techniques; the library has no generated page for it | Reported [95] |

### Russia-based criminal and hacktivist groups

These are not state units, but the government record ties several of them to Russia and to healthcare, so defenders meet them in the same threat models.

- **Wizard Spider** ([`G0102`](/mitre/groups/G0102.md)): TrickBot ([`S0266`](/mitre/software/S0266.md)), Conti ([`S0575`](/mitre/software/S0575.md)) and Ryuk ([`S0446`](/mitre/software/S0446.md)); ATT&CK lists targets ranging to hospitals, with 64 techniques and 22 software entries (**Reported** [93]). Treasury calls Trickbot a Russia-based gang whose current members are associated with the Russian Intelligence Services (**Confirmed** [34]).
- **Indrik Spider** ([`G0119`](/mitre/groups/G0119.md), Evil Corp): Dridex ([`S0384`](/mitre/software/S0384.md)), BitPaymer ([`S0570`](/mitre/software/S0570.md)) and WastedLocker ([`S0612`](/mitre/software/S0612.md)); ATT&CK records that it changed tactics after the 2019 US sanctions and indictment (**Reported** [93]).
- **LockBit**: Treasury designated Russian national Dmitry Khoroshev as leader of the Russia-based LockBit group on 7 May 2024 (**Confirmed** [48]).
- **KillNet**: HC3 says KillNet has been active since January 2022 and that its ties to the FSB or SVR are unconfirmed (**Confirmed** [33]).
- **CARR and NoName057(16)**: AA25-343A assesses that GRU Unit 74455 likely supported CARR's creation and funded its DDoS tools, and that the Kremlin-linked CISM created NoName057(16); the named targets were water, food and agriculture, and energy (**Confirmed** [57]).

## Part 3: the operational record

### Timeline

One row per dated operation, report or government action. "Attributed to" uses each source's own name and hedge. Sandworm and SolarWinds rows are kept short; their home studies carry the detail.

| Date | Attributed to | Event, report or action | Targets and sectors | Grade | Sources |
|---|---|---|---|---|---|
| Late 2003 to early 2004 | FSB (Center 16 unit) | Snake development begins as "Uroburos"; first versions around early 2004 | Government, research, journalists in 50+ countries (later) | Confirmed | [38] |
| From 2004 | APT28; Turla | Earliest activity ATT&CK records for each group | Government, embassies, military, research, pharmaceutical (Turla) | Confirmed | [80] [83] |
| From 2008 | APT29 (SVR) | Earliest activity ATT&CK records | European and NATO governments, research institutes, think tanks | Confirmed | [81] |
| From 2009, 2010, 2013 | Sandworm; Dragonfly; Gamaredon | Earliest activity ATT&CK records for each | Ukraine; critical infrastructure; Ukrainian military, law enforcement, judiciary and NGOs | Confirmed | [82] [84] [85] |
| 2012-09 to 2014-08 | Turla (Kaspersky: no sponsor named) | Epic Turla operation | Several hundred computers, 45+ countries; government, embassies, military, education, research, pharmaceutical | Confirmed | [64] |
| 2013-09 to 2019-10 | APT29 | Campaign C0023 Operation Ghost | Government targets | Confirmed | [81] [94] |
| 2014 to 2018-05 | GRU Unit 26165 | Intrusions into USADA, WADA and other anti-doping and sports bodies (indicted 2018-10-03) | Sport, anti-doping | Confirmed | [9] |
| 2014-08 to 2018-07 | TsNIIKhM employee | Conspiracy to damage an energy facility, targeting safety instrumented systems (charged, announced 2022-03-24) | Energy | Confirmed | [29] |
| 2014-10 to 2017-01 | TEMP.Veles | Campaign C0032, IT foothold before Triton | Petrochemical | Reported | [94] |
| 2014-10-27 | APT28 (FireEye: most likely Russian government) | First public APT28 report | Governments, militaries, security organisations | Confirmed | [65] |
| 2015-04 to 2015-05 | GRU Unit 26165 | German Bundestag intrusion | Parliament | Confirmed | [60] |
| 2015 | GRU Unit 26165 (UK); APT28 (France) | TV5Monde attack | Broadcaster | Confirmed | [60] [53] |
| 2015 summer | APT29 | Intrusion into a US political party (the DNC) | Political | Confirmed | [2] [66] |
| 2015-12 | GRU Unit 74455 | BlackEnergy attack on Ukraine's grid, 230,000 people without power (campaign C0028); see the Sandworm study | Electric power | Confirmed | [60] [82] |
| 2016-03 onward | Russian government cyber actors (Dragonfly per Symantec) | Multi-stage campaign staging through small commercial facilities, collecting ICS information (alert TA18-074A) | US energy, nuclear, commercial facilities, water, aviation, critical manufacturing | Confirmed | [5] |
| 2016 spring (April) | APT28 | Intrusion into the DNC; CrowdStrike report 2016-06-14 | Political | Confirmed | [2] [66] |
| 2016 (disclosed 2016-09-13) | Tsar Team (APT28) | Access to WADA's ADAMS database through a Rio 2016 account; athlete medical data published | Sport, athlete medical data | Confirmed | [1] |
| 2016 | GRU Unit 26165 | DNC and DCCC intrusions (UK attribution); 2016 election hack-and-leak (indicted 2018-07-13) | Political, election infrastructure | Confirmed | [60] [7] |
| 2016-12 | GRU Unit 74455 | Industroyer attack on Kyiv's grid (campaign C0025); see the Sandworm study | Electric power | Confirmed | [60] [82] |
| 2016-12-29 | APT28 and APT29 (US government) | GRIZZLY STEPPE joint analysis report | Political | Confirmed | [2] |
| 2017 | FSB Center 16 | Targeting of the Wolf Creek nuclear plant in Kansas (FBI indictment) | Nuclear | Confirmed | [28] |
| 2017 | GRU Unit 26165 (UK); Unit 74455 (2020 indictment) | French presidential election targeting | Political | Confirmed | [60] [14] |
| 2017 | FSB employees, one of them in Center 18 | Indictment recorded by AA22-110A | Email accounts of US government and military personnel and private organizations | Confirmed | [30] |
| 2017-06 | GRU Unit 74455 (Russian military per US and UK) | NotPetya; see the Sandworm study | Worldwide; a US pharmaceutical manufacturer and US hospital record systems per HC3 | Confirmed | [3] [4] [32] [60] |
| 2017-06 to 2017-08 | TEMP.Veles; TsNIIKhM (Treasury) | Triton attack on a safety instrumented system at a Middle East (UK: Saudi) petrochemical plant (campaign C0030) | Petrochemical | Confirmed | [17] [28] [94] |
| 2017 | GRU Unit 74455 | BadRabbit | Not stated in the source | Confirmed | [60] |
| 2018 (Pyeongchang Games) | GRU Unit 74455 | Olympic Destroyer at Pyeongchang, a false flag posing as North Korean and Chinese hackers, and VPNFilter on devices in the Republic of Korea | Olympics | Confirmed | [15] [60] |
| 2018-02-15 | Russian military | US and UK attribute NotPetya | Worldwide | Confirmed | [3] [4] |
| 2018-03-15 | Russian government cyber actors | Alert TA18-074A | US critical infrastructure | Confirmed | [5] |
| 2018-04-16 | Russian state-sponsored actors | Alert TA18-106A on routers, switches, firewalls and NIDS; update 2018-04-19 on DNS redirection through GRE tunnels | Network infrastructure worldwide | Confirmed | [6] |
| 2018 | GRU Unit 26165 | Intrusions against the OPCW, the Spiez laboratory and DSTL | Chemical-weapons investigation | Confirmed | [60] |
| 2018 | Star Blizzard (FSB Centre 18) | Institute for Statecraft hack | Think tank | Confirmed | [41] |
| 2018-07-13 | 12 GRU officers (Units 26165 and 74455) | District of Columbia indictment for 2016 election interference | Political, election boards and suppliers | Confirmed | [7] [8] |
| 2018-10-03 | 7 GRU officers | Western District of Pennsylvania indictment (announced 2018-10-04) | Anti-doping, sport | Confirmed | [9] |
| 2018 | GRU Unit 74455 | Attacks on Georgia | Government | Confirmed | [60] |
| 2019 | Star Blizzard | UK-US trade document leak | Government | Confirmed | [41] |
| 2019 | Indrik Spider (Evil Corp) | US sanctions and indictment | Financial crime | Reported | [93] |
| 2019 | Reported probing cited by Treasury in the TsNIIKhM designation | Probing of at least 20 US electric utilities | Electric power | Confirmed (that Treasury cites it) | [17] |
| 2019-10-28 | GRU GTsST (Unit 74455) | Disruptive attack on Georgia: several thousand websites and at least two TV broadcasters; US and UK attribution 2020-02-20 | Government, media | Confirmed | [10] [11] |
| 2019-08 to 2021-01 | APT29 (SVR) | SolarWinds Compromise (campaign C0024); see the SolarWinds study | Government, technology; 16,000+ systems | Confirmed | [19] [81] |
| 2020 | APT29 | Targeting of COVID-19 vaccine development; advisory 2020-07-16 | Healthcare, pharmaceutical research in Canada, the US and the UK | Confirmed | [12] [13] |
| 2020 | GRU Unit 29155 | Attack on Estonia | Government | Confirmed | [60] |
| 2020-09 onward | Berserk Bear (FSB Center 16) | Intrusions into US state, local, territorial and tribal government and aviation networks (AA20-296A, 2020-10-22) | Government, aviation | Confirmed | [16] |
| 2020-10-15 | 6 GRU officers (Andrienko listed in Unit 74455) | Western District of Pennsylvania indictment | Ukraine, France, Georgia, NotPetya victims, Olympics | Confirmed | [14] |
| 2020-10-19 | GRU GTsST | UK exposes reconnaissance against Tokyo 2020 organisers, logistics services and sponsors | Olympics | Confirmed | [15] |
| 2020-10-23 | TsNIIKhM | Treasury designation under CAATSA section 224 | Petrochemical, energy | Confirmed | [17] |
| 2020-10-28 | Cybercrime (no attribution) | AA20-302A: increased and imminent threat to US hospitals from TrickBot, BazarLoader, Ryuk and Conti | Healthcare | Confirmed | [18] |
| 2020-11 | Strontium among three nation-state actors (Microsoft) | Attacks on seven companies researching COVID-19 vaccines and treatments | Pharmaceutical research in Canada, France, India, South Korea, the US | Confirmed | [67] |
| 2021-03-16 to 2021-05-14 | Conti operators (nationality not stated) | Health Service Executive, Ireland: phishing to Conti detonation; all IT switched off | Healthcare | Confirmed | [25] |
| 2021-04-15 | SVR | US formal attribution of SolarWinds; Treasury sanctions on six technology companies; UK attribution | Government, technology | Confirmed | [19] [20] [21] |
| 2021-04-26 | SVR (APT29) | AA21-116A on SVR trends and WELLMESS | Government, think tanks, IT, vaccine research | Confirmed | [22] |
| 2021-05-20 | Conti | FBI FLASH: at least 16 attacks on US healthcare and first-responder networks | Healthcare, first responders | Confirmed | [23] |
| 2021 | APT28 (GRU Unit 26165) | Jaguar Tooth on Cisco routers through CVE-2017-6742; advisory 2023-04-18 | About 250 Ukrainian victims, US government | Confirmed | [36] [37] |
| 2021-07-01 | GRU 85th GTsSS | Joint advisory on a global brute-force campaign (bulletin opened; the advisory PDF did not load) | Not checked | Confirmed | [24] |
| 2021-11 | Gamaredon (FSB Center 18, per Ukraine) | Ukrainian government attribution | Ukrainian military, law enforcement, judiciary | Reported | [85] [99] |
| 2021 to 2024 | APT28 (GRU, per France) | Attacks on about a dozen French entities, including a Paris 2024 sports body | Government, diplomatic, research, sport | Confirmed | [53] [54] |
| 2021-12 onward | Star Blizzard | Compromise of the Institute for Statecraft founder's account | Think tank | Confirmed | [41] |
| 2022-01-11 | Russian state-sponsored actors | AA22-011A: 13 initial-access CVEs, TTPs and mitigations | US critical infrastructure | Confirmed | [26] |
| 2022-01-13 | GRU Unit 29155 | WhisperGate against Ukrainian organisations | Government | Confirmed | [51] [31] |
| 2022-02 to 2024-11 | APT28 | Campaign C0051 Nearest Neighbor: nearby Wi-Fi networks and zero-day CVE-2022-38028 | Organisations with expertise on Ukraine | Confirmed | [97] |
| 2022-02-15 to 2022-02-16 | GRU (UK) | DDoS on Ukraine's banking sector; UK judgment 2022-02-18 | Finance | Confirmed | [27] |
| 2022-02-24 | Russia (UK: almost certainly; no unit named) | Viasat KA-SAT disruption about an hour before the invasion, also hitting central European wind farms | Satellite communications, energy | Confirmed | [31] |
| 2022-03 | Killnet | DDoS on a US airport | Aviation | Confirmed | [30] |
| 2022-03 onward | GRU Unit 26165 | IP-camera targeting at borders and rail stations, 81% in Ukraine | Transport | Confirmed | [55] |
| 2022-03-24 | FSB Center 16; TsNIIKhM | UK and US expose Center 16; US charges four Russian government employees for 2012 to 2018 energy-sector intrusions; UK sanctions TsNIIKhM | Energy, nuclear | Confirmed | [28] [29] |
| 2022-04-20 | GRU, SVR, FSB, TsNIIKhM | Five Eyes advisory AA22-110A maps services to groups | Critical infrastructure | Confirmed | [30] |
| 2022-05 | KillNet | Reported threat against ventilators in British hospitals and the UK health ministry | Healthcare | Confirmed | [33] |
| 2022 onward | GRU Unit 26165 | Targeting of Western logistics and technology companies in 13 countries (AA25-141A) | Defense, transport, maritime, air traffic management, IT | Confirmed | [55] |
| 2022-06 to 2022-10 | Sandworm | Campaign C0034, 2022 Ukraine electric power attack; see the Sandworm study | Electric power | Confirmed | [82] |
| 2022-11 onward | Secret Blizzard (Turla) | Takeover of Storm-0156 infrastructure (Microsoft post 2024-12-04) | Afghan government, Indian military | Confirmed | [74] |
| 2022-12-08 and 2022-12-16 | KillMilk; KillNet | Threat to sell Americans' health data; targeting of Humana Military | Healthcare | Confirmed | [35] |
| 2023 | APT28 (GRU) | Attacks on Czech institutions through a 2023 Outlook zero-day; Czech attribution 2024-05-03 | Government | Confirmed | [47] |
| 2023-01 to 2024-08 | Star Blizzard | 82 Microsoft customers targeted from January 2023; 30+ civil-society organisations | Civil society, government | Confirmed | [72] |
| 2023-01-28 | KillNet and affiliates | Over 90 coordinated DDoS attacks; 55% on health systems with a hospital or Level I trauma centres, 48 US states alleged | Healthcare | Confirmed | [35] |
| 2023-02-09 | Trickbot | Treasury sanctions; members associated with Russian Intelligence Services; ambulances diverted from three Minnesota facilities in 2020 | Healthcare | Confirmed | [34] |
| 2023-04-18 | APT28 | NCSC, NSA, CISA and FBI advisory on Jaguar Tooth | Network devices | Confirmed | [36] [37] |
| 2023-05 to 2023-12-12 | Midnight Blizzard (HPE: believed to be) | Data taken from HPE's cloud email; 8-K filed 2024-01-19 | Technology | Confirmed | [43] |
| 2023-05-09 | FSB Center 16 | AA23-129A on Snake | Government, research, media in 50+ countries | Confirmed | [38] |
| 2023-09 onward | SVR (APT29) | Exploitation of TeamCity CVE-2023-42793 (AA23-347A, 2023-12-12) | Software firms incl. billing and medical-device software; an energy trade association | Confirmed | [42] |
| 2023-11 to 2024-01-12 | Midnight Blizzard | Password spray of a legacy test tenant; senior leadership email read | Technology | Confirmed | [68] [69] |
| 2023-12 | GRU Unit 74455 (per Ukraine's SBU) | Kyivstar outage, 24 million customers | Telecommunications | Reported | [60] |
| 2023-12-05 | FSB officer Peretyatko; Callisto affiliate Korinets | Northern District of California indictment | Defense, foreign affairs, nuclear research | Confirmed | [39] |
| 2023-12-07 | Star Blizzard (FSB Centre 18) | AA23-341A; UK attribution and sanctions | Academia, defense, government, NGOs, think tanks, politicians | Confirmed | [40] [41] |
| 2024-01 (announced 2024-02-15) | GRU Unit 26165 | Court-authorized disruption of a SOHO router network built on Moobot | Network devices | Confirmed | [44] |
| 2024-02 | Midnight Blizzard | Access to source code repositories; sprays up to tenfold (Microsoft 2024-03-08) | Technology | Confirmed | [70] |
| 2024-02-26 | SVR (APT29) | AA24-057A on cloud initial access | Aviation, education, law enforcement, local councils, military | Confirmed | [45] |
| 2024-02-27 | GRU 85th GTsSS (APT28) | 11-country advisory on compromised Ubiquiti EdgeRouters | Network devices | Confirmed | [46] |
| 2024-04 onward | Void Blizzard (Microsoft) | Espionage against critical sectors, including healthcare | Government, defense, healthcare, NGOs | Confirmed | [76] |
| 2024-04-17 | Sandworm (Mandiant APT44) | Mandiant graduates Sandworm to APT44 | Ukraine, worldwide | Confirmed | [71] |
| 2024-05-07 | LockBit leader | Treasury designation of Dmitry Khoroshev | Healthcare among other sectors | Confirmed | [48] |
| 2024-05-10 | Black Basta (origin not stated) | AA24-131A: 12 of 16 critical infrastructure sectors incl. healthcare, 500+ organisations | Healthcare and others | Confirmed | [49] |
| 2024-06-06 | Midnight Blizzard | HC3 threat actor profile for the health sector | Healthcare | Confirmed | [50] |
| 2024-08 onward | Storm-2372 (from 2026-07-31: a Midnight Blizzard sub-cluster) | Device-code phishing | Sectors including health | Confirmed | [75] |
| 2024-09 | Laundry Bear (Dutch services, per press) | Breach of the Dutch police | Law enforcement | Reported | [103] |
| 2024-09-05 | GRU Unit 29155 | AA24-249A; five officers and a civilian wanted; $10 million reward | Government, finance, transport, energy, healthcare | Confirmed | [51] [52] |
| 2024 | GRU Unit 26165 | Paris 2024 targeting | Sport | Confirmed | [60] |
| 2024-10-03 | Star Blizzard | Microsoft seizes 66 domains and DOJ 41 | Civil society | Confirmed | [72] |
| 2024-10-22 | Midnight Blizzard | RDP-file spear-phishing, thousands of targets in 100+ organisations | Government, academia, defense, NGOs | Confirmed | [73] |
| 2024 to 2025-02 | Secret Blizzard | ISP-level adversary-in-the-middle pushes ApolloShadow at embassies in Moscow | Diplomatic | Confirmed | [77] |
| 2024 to 2026-04-07 | GRU 85th GTsSS (APT28) | SOHO router compromise incl. TP-Link CVE-2023-50224; DHCP and DNS hijack for adversary-in-the-middle on Outlook Web Access | Military, government, critical infrastructure | Confirmed | [59] |
| 2025-03 to 2025-12 | Russian state-sponsored (ATT&CK); no group associated | Campaign C0063, 2025 Poland Wiper Attacks with DynoWiper and LazyWiper | Polish wind, solar, combined heat and power, a manufacturer | Confirmed | [90] [98] |
| 2025-04-29 | GRU (France); APT28 (ANSSI) | French formal attribution and ANSSI report CERTFR-2025-CTI-007 | Government, diplomatic, research | Confirmed | [53] [54] |
| 2025-05 | GRU Unit 26165 | AA25-141A, 11 countries (corrected 2026-04-17) | Logistics, technology | Confirmed | [55] |
| 2025-05 to 2025-09 | COLDRIVER (GTIG: Russian state-sponsored) | LOSTKEYS disclosed, then NOROBOT, YESROBOT and MAYBEROBOT through fake CAPTCHA lures (post 2025-10-20) | Not checked | Confirmed | [78] |
| 2025-05-27 | Void Blizzard | Microsoft disclosure | Healthcare among critical sectors | Confirmed | [76] |
| 2025-08-20 | FSB Center 16 (Static Tundra) | FBI PSA on Smart Install CVE-2018-0171 and SNMP exploitation | US critical infrastructure networking devices | Confirmed | [56] |
| 2025-12-09 | GRU Unit 74455 (CARR support); CISM (NoName057(16)) | AA25-343A on pro-Russia hacktivists | Water, food and agriculture, energy | Confirmed | [57] |
| 2025-12-29 | Sandworm (ESET, medium confidence); Static Tundra and Dragonfly overlap (CERT Polska) | RTUs damaged at 30+ wind and PV farms; wipers tried at a CHP plant (blocked by EDR) and a manufacturer; full record in [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) | Energy, manufacturing | Confirmed | [79] [58] |
| 2026-04-07 | GRU 85th GTsSS (APT28) | FBI PSA on router exploitation | Network devices | Confirmed | [59] |
| 2026-07-13 | FSB Centre 16 | UK and EU formal attribution of the Poland attack; first joint UK-EU cyber sanctions package (24 designations incl. GRU leaders and OOO IMPULS); 19-agency AA26-194A; NCSC call to critical sectors | Energy; Healthcare and Public Health among most at risk | Confirmed | [61] [62] [63] |
| 2026-07-31 | Midnight Blizzard | Microsoft reassesses Storm-2372 as its initial-access sub-cluster | Health among sectors | Confirmed | [75] |

### Reading the record by era

- **2003 to 2014: long-running espionage, quietly named.** The FSB's Snake work and APT28's activity date from 2003 and 2004, but two landmark vendor reports opened for this study (Kaspersky's Epic Turla and FireEye's APT28) date from 2014, and neither named a service with certainty (**Confirmed** [38] [64] [65]).
- **2015 to 2018: disruption and influence.** The Ukrainian grid attacks, NotPetya, the Bundestag, TV5Monde, the DNC, WADA and the OPCW all fall in four years, and the US and UK answered with formal attribution in 2018 and the first GRU indictments (**Confirmed** [60] [3] [4] [7] [9]).
- **2019 to 2021: supply chains, vaccines and naming the SVR.** SolarWinds and the vaccine-research campaign moved the SVR to the front, and the US formally named it in April 2021 (**Confirmed** [19] [12]).
- **2022 to 2024: war-time operations and identity.** WhisperGate, Viasat and the 2022 grid attack run alongside SVR cloud-identity intrusions at Microsoft and HPE and Unit 26165's logistics campaign (**Confirmed** [51] [31] [68] [43] [55]).
- **2025 to 2026: routers, disagreements and joint sanctions.** Network-device campaigns by both the GRU and the FSB, disputed attribution of the Poland attack, and the first joint UK-EU cyber sanctions package close the record (**Confirmed** [56] [59] [79] [58] [61]).

## Part 4: the government record

### Indictments

| Date | Court | Defendants and unit | Conduct charged | Sources |
|---|---|---|---|---|
| 2017 (recorded in AA22-110A) | Not stated in the source | FSB employees, including one Center 18 employee | Accessing email accounts of US government and military personnel and private organizations | [30] |
| 2018-07-13 | District of Columbia | 12 GRU officers; Lukashev in Unit 26165, Kovalev in Unit 74455 | Eleven charged with hacking, stealing documents and staging their release in the 2016 US elections; Osadchuk and Kovalev charged separately for intrusions into state election boards, secretaries of state and election-technology suppliers | [7] [8] |
| 2018-10-03 (announced 2018-10-04) | Western District of Pennsylvania | 7 GRU officers; Morenets in Unit 26165 | Intrusions from 2014 to May 2018 into USADA, WADA and other victims | [9] |
| 2020-10-15 | Western District of Pennsylvania | 6 GRU officers; Andrienko in Unit 74455 | Ukrainian critical infrastructure, a French political campaign, Georgia, NotPetya, the 2018 Winter Olympics, nerve-agent investigations | [14] |
| Announced 2022-03-24 | Not stated in the source | 4 Russian government employees, incl. Gladkikh of TsNIIKhM | Energy-sector intrusions from 2012 to 2018; conspiracy to damage an energy facility (safety instrumented systems) | [29] |
| 2023-12-05 | Northern District of California | FSB officer Peretyatko; Korinets (Callisto Group affiliate) | Spear-phishing for US intelligence on defense, foreign affairs and nuclear research | [39] |
| Announced 2024-09-05 | Not stated in the source | 5 GRU Unit 29155 officers and civilian Amin Stigal | Activity from December 2020 to August 2024, incl. WhisperGate; up to $10 million reward | [52] |

ATT&CK's own summaries of the 2018 and 2020 indictments are consistent with this record; for the October 2018 case ATT&CK counts five Unit 26165 officers and names a US nuclear facility among the victims, where the FBI notice counts seven GRU officers (**Reported**, as ATT&CK summaries [93]).

### Sanctions and disruptions

| Date | Actor | Action | Sources |
|---|---|---|---|
| 2019 | Indrik Spider (Evil Corp) | US sanctions and indictment, after which the group changed tactics | [93] |
| 2020-10-23 | TsNIIKhM | US Treasury designation under CAATSA section 224 for its connection to Triton | [17] |
| 2021-04-15 | ERA Technopolis, Pasit, SVA, Neobit, AST, Positive Technologies | US Treasury sanctions on companies supporting the GRU, SVR and FSB cyber programs | [20] |
| 2022-03-24 | TsNIIKhM | UK sanctions over the 2017 Saudi petrochemical safety-system incident | [28] |
| 2023-02-09 | Trickbot members | US Treasury sanctions | [34] |
| 2023-12-07 | Peretyatko and Korinets | UK sanctions | [41] |
| 2024-01 (announced 2024-02-15) | GRU Unit 26165 router network | Court-authorized disruption | [44] |
| 2024-05-07 | Dmitry Khoroshev (LockBit) | US Treasury designation | [48] |
| 2024-10-03 | Star Blizzard | Microsoft court-ordered seizure of 66 domains; DOJ seizure of 41 | [72] |
| 2026-07-13 | 24 individuals and entities incl. GRU leaders and OOO IMPULS | UK designations announced with the first joint UK-EU cyber sanctions package | [61] |

### Formal attributions outside the indictments

| Date | Government | Actor named | Event | Confidence wording | Sources |
|---|---|---|---|---|---|
| 2016-12-29 | United States | APT28 and APT29 (RIS) | Intrusions into a US political party | "confirms" | [2] |
| 2018-02-15 | United States; United Kingdom | Russian military | NotPetya | US: launched by the Russian military; NCSC: almost certainly | [3] [4] |
| 2020-02-20 | United States; United Kingdom | GRU GTsST (Unit 74455) | Georgia, 28 October 2019 | UK: "with the highest level of probability" | [10] [11] |
| 2020-07-16 | UK, Canada; US agrees | APT29 | COVID-19 vaccine targeting | Almost certainly part of the intelligence services; highly likely sought vaccine IP | [12] [13] |
| 2020-10-19 | United Kingdom | GRU GTsST | Tokyo 2020 reconnaissance; Pyeongchang 2018 | "reveals" and "confirms" | [15] |
| 2021-04-15 | United States; United Kingdom | SVR | SolarWinds Orion | US: high confidence; UK: highly likely | [19] [21] |
| 2022-02-18 | United Kingdom | GRU | DDoS on Ukrainian banks | "judges" | [27] |
| 2022-03-24 | United Kingdom with the US | FSB Center 16 | Global critical-infrastructure campaign | "exposes" | [28] |
| 2022-04-20 | Five Eyes | FSB Center 16 and 18, SVR, GRU units 26165 and 74455, TsNIIKhM | Unit map | Center 16: almost certainly (US and UK) | [30] |
| 2022-05-10 | United Kingdom | Russia; Russian military intelligence | Viasat; WhisperGate | Almost certainly | [31] |
| 2023-04-18 | UK, US | GRU Unit 26165 | Jaguar Tooth | Almost certainly, high confidence | [37] |
| 2023-05-09 | Nine agencies | FSB Center 16 unit | Snake | Attributes | [38] |
| 2023-12-07 | UK and seven partners | FSB Centre 18 | Star Blizzard | Almost certainly subordinate; the UK page also says highly likely | [40] [41] |
| 2024-05-03 | Czechia | APT28, associated with the GRU | Outlook zero-day attacks on Czech institutions | "Russian state-controlled actor" | [47] |
| 2024-09-05 | US and partners | GRU Unit 29155 | WhisperGate and global scanning | Attributes | [51] |
| 2025-04-29 | France | GRU (APT28) | About a dozen French entities since 2021 | Formal condemnation | [53] |
| 2026-07-13 | UK and EU member states | FSB Centre 16 | Poland energy attack, December 2025 | Formal attribution; no confidence level on the NCSC page | [61] [63] |

### How confidence moved

The same actors reached readers at very different strength over twelve years. APT28 went from FireEye's "most likely" Russian government (2014) to "almost certainly" Unit 26165 (2023). Dragonfly went from "Russian government cyber actors", with the group name only via Symantec (2018), to "almost certainly" FSB Center 16 (2022) to formal UK-EU attribution (2026). Storm-2372 went from moderate-confidence Russia-aligned (2025) to a Midnight Blizzard sub-cluster (2026). Microsoft's own breach posts on Midnight Blizzard said "Russian state-sponsored" and left the SVR naming to governments (**Inferred** from [65] [37] [5] [30] [61] [75] [68]). The UK GRU profile gives the UK's attribution of BlackEnergy and Industroyer as "in 2015" and "in 2016", the event years, while AA22-110A says only that they were previously attributed; the date of the first UK statement was not checked, so the profile may be using event years as shorthand (**Inferred** [60] [30]).

## Part 5: exploited vulnerabilities

AA22-011A lists 13 CVEs that Russian state actors used for initial access; AA20-296A, AA23-347A, AA24-249A, AA25-141A and the FBI's August 2025 notice add 13 more, for 26 in all (**Confirmed** [26] [16] [42] [51] [55] [56]). Every one of the 26 is in KEV as of catalog version 2026.11.03, and KEV marks 11 of them for known ransomware campaign use (**Confirmed** [92]). The KEV date and CWE columns below come from the same feed; CVE-2017-6742, CVE-2022-38028, CVE-2023-50224 and CVE-2008-4128, named in other primaries, were checked in the same feed. The NCSC's 2020 vaccine advisory names four of the same CVEs for APT29 (**Confirmed** [12]).

| CVE | Product (KEV) | Named by (actor, date) | KEV added | Ransomware use (KEV) | CWE (KEV) |
|---|---|---|---|---|---|
| CVE-2018-13379 | Fortinet FortiOS | AA22-011A (2022-01-11); AA20-296A Berserk Bear (2020-10-22); NCSC APT29 (2020-07-16) | 2021-11-03 | Known | CWE-22 |
| CVE-2019-1653 | Cisco RV320 and RV325 routers | AA22-011A | 2021-11-03 | Unknown | CWE-284 |
| CVE-2019-2725 | Oracle WebLogic Server | AA22-011A | 2022-01-10 | Known | CWE-74 |
| CVE-2019-7609 | Elastic Kibana | AA22-011A | 2022-01-10 | Unknown | CWE-94 |
| CVE-2019-9670 | Synacor Zimbra Collaboration Suite | AA22-011A; NCSC APT29 | 2022-01-10 | Unknown | CWE-611 |
| CVE-2019-10149 | Exim MTA | AA22-011A; AA20-296A | 2022-01-10 | Unknown | CWE-78 |
| CVE-2019-11510 | Ivanti Pulse Connect Secure | AA22-011A; NCSC APT29 | 2021-11-03 | Known | CWE-22 |
| CVE-2019-19781 | Citrix ADC and Gateway | AA22-011A; AA20-296A; NCSC APT29; AA21-116A (SVR, described as a zero-day) | 2021-11-03 | Known | CWE-22 |
| CVE-2020-0688 | Microsoft Exchange Server | AA22-011A; AA20-296A | 2021-11-03 | Known | CWE-287 |
| CVE-2020-4006 | VMware (multiple products) | AA22-011A | 2021-11-03 | Unknown | CWE-78 |
| CVE-2020-5902 | F5 BIG-IP | AA22-011A | 2021-11-03 | Known | CWE-22 |
| CVE-2020-14882 | Oracle WebLogic Server | AA22-011A | 2021-11-03 | Unknown | None listed |
| CVE-2021-26855 | Microsoft Exchange Server | AA22-011A | 2021-11-03 | Known | CWE-918 |
| CVE-2020-1472 | Microsoft Netlogon | AA20-296A Berserk Bear | 2021-11-03 | Known | CWE-330 |
| CVE-2021-33044 | Dahua IP camera firmware | AA24-249A Unit 29155 (2024-09-05) | 2024-08-21 | Unknown | CWE-287 |
| CVE-2021-33045 | Dahua IP camera firmware | AA24-249A | 2024-08-21 | Unknown | CWE-287 |
| CVE-2022-26134 | Atlassian Confluence | AA24-249A | 2022-06-02 | Known | CWE-917 |
| CVE-2022-26138 | Atlassian Confluence | AA24-249A | 2022-07-29 | Unknown | CWE-798 |
| CVE-2022-3236 | Sophos Firewall | AA24-249A | 2022-09-23 | Unknown | CWE-94 |
| CVE-2023-23397 | Microsoft Office (Outlook NTLM) | AA25-141A Unit 26165 (2025-05) | 2023-03-14 | Unknown | CWE-294 |
| CVE-2023-38831 | RARLAB WinRAR | AA25-141A | 2023-08-24 | Known | CWE-351 |
| CVE-2020-12641 | Roundcube Webmail | AA25-141A | 2023-06-22 | Unknown | CWE-78 |
| CVE-2020-35730 | Roundcube Webmail | AA25-141A | 2023-06-22 | Unknown | CWE-79 |
| CVE-2021-44026 | Roundcube Webmail | AA25-141A | 2023-06-22 | Unknown | CWE-89 |
| CVE-2023-42793 | JetBrains TeamCity | AA23-347A SVR (2023-12-12) | 2023-10-04 | Known | CWE-288 |
| CVE-2018-0171 | Cisco IOS and IOS XE (Smart Install) | FBI PSA, FSB Center 16 (2025-08-20); AA26-194A (2026-07-13) | 2021-11-03 | Unknown | CWE-20 |
| CVE-2017-6742 | Cisco IOS and IOS XE | NCSC and partners, APT28 Jaguar Tooth (2023-04-18) | 2023-04-19 | Unknown | CWE-119 |
| CVE-2022-38028 | Microsoft Windows | ATT&CK campaign C0051, APT28 (zero-day) | 2024-04-23 | Unknown | None listed |
| CVE-2023-50224 | TP-Link TL-WR841N | FBI PSA, APT28 (2026-04-07) | 2025-09-03 | Unknown | CWE-290 |
| CVE-2008-4128 | Cisco IOS | AA26-194A, FSB Center 16 (2026-07-13) | 2026-07-13 | Unknown | CWE-352 |

Sources: [26] [16] [12] [22] [51] [55] [42] [56] [62] [37] [97] [59] [92].

AA24-249A adds that Unit 29155 obtained, but was not seen exploiting, scripts for CVE-2020-1472, CVE-2021-26084, CVE-2021-3156, CVE-2021-4034 and CVE-2022-27666 (**Confirmed** [51]).

Three readings for a vulnerability-management program follow (**Inferred** from the table).

1. **KEV is the right floor, and it is not enough on its own.** All 26 advisory CVEs are in KEV, and the earliest dateAdded values are the catalog's launch day, so a KEV-first program would have caught them. But CVE-2018-0171 sat in KEV from 3 November 2021 and was still being exploited by FSB Center 16 in August 2025 [92] [56]: the gap was patching, not knowledge.
2. **The edge is the target class.** VPNs and gateways (Fortinet, Pulse, Citrix, F5, Sophos), mail and collaboration (Exchange, Zimbra, Roundcube, Outlook, Confluence), CI/CD (TeamCity), cameras (Dahua) and routers (Cisco, TP-Link) make up nearly the whole list.
3. **Age is no comfort.** CVE-2008-4128 entered KEV on the day of AA26-194A, 13 July 2026, eighteen years after its CVE year [92] [62]. Long-lived network firmware needs inventory and end-of-life tracking, not just CVE scanning.

## Part 6: targets by sector and geography

### The sector pattern

Across the advisories, the emphasized sectors are government and diplomatic networks, think tanks and NGOs, energy and other critical infrastructure, defense and aerospace, transport and logistics, telecommunications, research and, for specific operations, sport and elections. Geography centers on Ukraine, NATO and EU members, the US, the UK and Canada, with Georgia, the Republic of Korea (Pyeongchang), Japan (Tokyo 2020), Afghanistan and India (Turla via Storm-0156), Poland and Czechia in specific operations (**Inferred** from [30] [51] [55] [40] [38] [15] [74] [58] [47]).

| Service and unit | Sectors the sources name | Healthcare named? | Sources |
|---|---|---|---|
| GRU Unit 26165 (APT28) | Government, travel and hospitality, research institutions, NGOs (AA22-110A); defense industry, transport hubs, maritime, air traffic management, IT services in 12 European countries and the US (AA25-141A); sport and anti-doping | Not in AA22-110A or AA25-141A; HC3 (2022) lists healthcare among APT28 targets; HC3 (2024) says APT28 targeted pharmaceutical companies and clinical researchers for COVID-19 IP | [30] [55] [32] [50] |
| GRU Unit 74455 (Sandworm) | Electric power, government, media, Olympics; water, food and agriculture, energy through CARR | NotPetya collateral (HC3); not in AA25-343A | [60] [32] [57] |
| GRU Unit 29155 | Government services, financial services, transportation, energy, healthcare | Yes (AA24-249A) | [51] |
| SVR (APT29) | Government, diplomatic, think tanks, healthcare, energy; IT companies; aviation, education, law enforcement, local councils, military | Yes (NCSC 2020, UK 2021, AA24-057A, HC3 2022 and 2024) | [12] [21] [45] [32] [50] |
| FSB Center 16 (Turla, Snake) | Education, small businesses, media, government facilities, financial services, critical manufacturing, communications (US victims) | Not in AA23-129A; HC3 (2022) lists research and pharmaceutical companies | [38] [32] |
| FSB Center 16 (Berserk Bear, Static Tundra) | Energy, nuclear, water, aviation, critical manufacturing; SLTT government | Yes: Healthcare and Public Health among the most at risk (AA26-194A) | [5] [16] [62] |
| FSB Center 18 (Star Blizzard) | Academia, defense, government, NGOs, think tanks, politicians; DOE facilities | Not in AA23-341A | [40] |

### The healthcare thread

The healthcare record is scattered across espionage advisories, sector notes and ransomware alerts, so it is gathered here in one place. It falls into four kinds of exposure.

**1. State espionage against research and clinical data.** The 2020 NCSC and CSE advisory says APT29 predominantly targets governmental, diplomatic, think-tank, healthcare and energy organisations, and that throughout 2020 it targeted organisations developing COVID-19 vaccines in Canada, the US and the UK, highly likely to steal vaccine development and testing IP (**Confirmed** [12] [13]). It used public exploits for Citrix, Pulse Secure, FortiGate and Zimbra, credential spear-phishing, and WellMess (in use since at least 2018) and WellMail, neither previously tied to APT29 in public (**Confirmed** [12]). Microsoft reported in November 2020 that three nation-state actors, one of them Strontium, which it says originates from Russia, targeted seven companies researching COVID-19 vaccines and treatments in Canada, France, India, South Korea and the US; Microsoft does not say which actor hit which company (**Confirmed** [67]). HC3's 2024 profile says both Midnight Blizzard and APT28 targeted foreign pharmaceutical companies and clinical researchers for vaccine and treatment IP, and adds Australia to the 2020 target countries, which the NCSC advisory does not list (**Confirmed** [50]; the two sources disagree). WADA's 2016 statement shows the same appetite for medical data in another setting: APT28 published athletes' confidential Therapeutic Use Exemptions (**Confirmed** [1]).

**2. Supply-chain and software exposure.** SVR exploitation of TeamCity in 2023 reached companies making software for billing and medical devices (**Confirmed** [42]). HC3's 2022 deck says SolarWinds affected a US hospital, but that claim rests in the deck on a press article, not a primary record; the SolarWinds study is the home for it (**Reported** [32]). HC3 also flags Midnight Blizzard's 2023 social engineering over Microsoft Teams, which it calls a staple in healthcare (**Confirmed** [50]).

**3. Collateral damage and broad critical-infrastructure targeting.** HC3's 2022 brief states that NotPetya shut down a US pharmaceutical manufacturer and affected the medical record systems of dozens of US hospitals (**Confirmed** [32]; the home study is `case-studies/SANDWORM_OPERATIONS.md`). A press account of the 2023 New Jersey appellate ruling reports that NotPetya infected about 40,000 Merck computers in 64 countries and that the insurers' war exclusion did not bar Merck's claim (**Reported** [104]; the court opinion did not load). AA22-011A names Healthcare and Public Health among sectors Russian state actors have targeted, without naming an incident; AA24-249A lists healthcare among Unit 29155's target sectors; AA26-194A names Healthcare and Public Health among those most at risk from FSB Center 16's router campaign (**Confirmed** [26] [51] [62]). Void Blizzard and Storm-2372 both list healthcare or health among their targets (**Confirmed** [76] [75]).

**4. Hacktivist and criminal disruption.** HC3 records KillNet's reported threat against ventilators in British hospitals and the UK health ministry in May 2022, KillMilk's threat to sell Americans' health data and KillNet's targeting of Humana Military in December 2022, and more than 90 coordinated DDoS attacks on 28 January 2023, 55% against health systems with at least one hospital or hospitals with Level I trauma centres, across 48 US states (alleged) (**Confirmed** [33] [35]). HC3 advises treating KillNet's claims with caution. On the criminal side, AA20-302A warned on 28 October 2020 of an increased and imminent threat to US hospitals from TrickBot, BazarLoader, Ryuk and Conti, without attributing the operators to Russia (**Confirmed** [18]); Treasury later said Trickbot targeted hospitals during the pandemic, including three Minnesota facilities that had to divert ambulances (**Confirmed** [34]); the FBI counted at least 16 Conti attacks on US healthcare and first-responder networks in a year (**Confirmed** [23]); AA22-110A says Conti affiliates targeted US healthcare and first responders and that Emotet's operators targeted healthcare (**Confirmed** [30]); the HSE review in Ireland traces Conti from a phishing email on 16 March 2021 to detonation on 14 May, after which all HSE IT was switched off and recovery took over four months, without stating the attackers' nationality (**Confirmed** [25]); AA24-131A says Black Basta hit healthcare among 12 of 16 critical infrastructure sectors and over 500 organisations, with no origin stated (**Confirmed** [49]); and Treasury's LockBit designation says affiliates attacked healthcare among other sectors (**Confirmed** [48]). HC3's 2024 profile groups LockBit, Royal, Black Basta and ALPHV among Russian actors that regularly attack the sector (**Confirmed** [50]). The ALPHV attack on Change Healthcare has its own study: `case-studies/CHANGE_HEALTHCARE_2024.md`.

**What the record does not show.** None of the government documents opened for this study attributes a disruptive attack on a hospital to a Russian state unit. The state record on healthcare is espionage, collateral damage and sector lists; the attacks that disrupted care came from criminal ransomware crews (Trickbot's ambulance diversions, Conti at the HSE), some of whom Treasury links to the intelligence services, while pro-Russia hacktivists added DDoS waves and threats (**Inferred** from [12] [32] [51] [62] [33] [34]). In ATT&CK's own descriptions of the Russia-linked groups, healthcare appears only twice: Turla lists pharmaceutical companies and Wizard Spider lists hospitals (**Inferred** from [93]).

## Part 7: the defender view

### What the advisories ask for

The advisories share most of their recommendations, which makes them a useful checklist across all three services.

| Control area | What the advisories say | Sources |
|---|---|---|
| Patching | Patch KEV first; then critical internet-facing remote code execution; run regular automated vulnerability scans; organisations that did not patch TeamCity promptly should assume compromise | [30] [51] [42] |
| Identity | Enforce MFA, and phishing-resistant MFA on webmail and VPN (passkeys or PKI smartcards); strong unique passwords incl. service accounts; lockout at 5 to 10 attempts; disable dormant accounts; least privilege for service accounts; canary service accounts with alerting; short session lifetimes; restrict device enrollment; MFA alone does not stop session-cookie theft | [30] [51] [55] [45] [40] |
| Network devices | Disable Smart Install, SNMPv1 and v2c and Telnet; block TCP 4786 at the boundary; block outbound TFTP; keep management interfaces off the internet | [6] |
| Legacy protocols | Restrict NTLM and WDigest; block NTLM and SMB to external infrastructure; plan NTLM retirement; remove Group Policy Preference passwords; enable Credential Guard | [30] [55] |
| IT and OT | Segment IT and OT with a DMZ; watch for unexpected controller reboots | [30] [26] |
| Endpoint | EDR on mail servers and domain controllers first; attack surface reduction rules; PowerShell Constrained Language Mode; restrict and update PowerShell; detect Impacket, PsExec and WMI | [55] [51] |
| Cloud and mail | Audit app-only permissions and ApplicationImpersonation holders; review EWS full_access_as_app grants; disable or monitor mail forwarding rules; audit for privileged certificate access and rogue identity providers; require authentication for device registration | [69] [40] [22] |
| Recovery | Offline, immutable, regularly tested backups; after a deep compromise, reset krbtgt twice and consider rebuilding the AD forest | [30] [16] |
| Validation | Test security controls against each advisory's ATT&CK technique list | [51] [42] |

### Detection and hunting leads in the primaries

- **Identity logs.** Failed logins across many accounts (spraying), impossible travel, activity on dormant accounts, atypical user agents, and access to `ntds.dit` on domain controllers (AA22-011A) (**Confirmed** [26]). AA24-057A prefers low-false-positive indicators such as user-agent changes over IP blocklists, because the SVR routes through residential proxies (**Confirmed** [45]).
- **EDR health.** Alert when EDR is disabled or loses contact, bring test and development systems under the security baseline, and hunt TeamCity logs for configuration changes; AA23-347A supplies Sigma rules and a GraphicalProton YARA rule (**Confirmed** [42]).
- **Kernel implants.** For Snake, AA23-129A rates memory analysis as the most effective detection because network and host signatures are easily changed (**Confirmed** [38]).
- **Microsoft 365.** Entra ID Protection password-spray detections, OAuth app permission audits and EWS grant reviews (**Confirmed** [69]).
- **OT.** Unexpected controller reboots (AA22-011A) and the ICS-protocol interest the FBI noted in Center 16's device collection (**Confirmed** [26] [56]).

### A vulnerability- and exposure-management reading

The defender view for a VM program, as this study reads the record (**Inferred** unless a source is named):

1. **Edge first.** `T1190` and `T1133` are the common entry across GRU, SVR and FSB units, and every CVE these advisories name is in KEV. A remediation tier for "KEV and named in a Russia advisory" covering VPN, mail, collaboration, CI/CD and network devices is the single highest-yield control [26] [51] [55] [42] [56] [92].
2. **End-of-life gear is exposure, not just vulnerability.** The FSB device campaign used a 2018 CVE and legacy SNMP and Smart Install [56] [6]. Inventory end-of-life routers and switches as findings with owners and dates.
3. **Identity findings belong in the same backlog as CVEs.** "Account without MFA", "dormant account still enabled", "over-privileged service account" and "legacy OAuth app with app-only mail permissions" are the conditions the SVR exploited [45] [22] [69].
4. **Phishing-resistant MFA, not any MFA.** AA24-249A and AA25-141A ask for it, and AA23-341A shows why: cookie theft defeats ordinary MFA [51] [55] [40].
5. **Measure the gap between KEV and patch.** The 2018 Smart Install CVE shows that knowing is not the bottleneck [92] [56].

### Where the library's countermeasure data is thin

The library's D3FEND mapping has no countermeasure rows for `T1059.001` PowerShell, `T1588.002` Obtain Capabilities: Tool, `T1595.002` Vulnerability Scanning, `T1098.005` Device Registration, `T1110` Brute Force (the parent), `T1485` Data Destruction, `T1550.002` Pass the Hash, `T1606.002` SAML Tokens or `T1685.005` Clear Windows Event Logs, and maps `T1133` External Remote Services only to Session Termination (**Confirmed** [102]). Several of these are among the most widely recorded techniques across the Russian groups, so a coverage tool driven by D3FEND alone will under-count controls against them. The live D3FEND page for Multi-factor Authentication labels its ATT&CK links as inferred and experimental, so D3FEND pairings in this study are the library's mapping, not an official pairing (**Confirmed** [91]).

## Part 8: MITRE mappings

This part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every ID was checked against the live ATT&CK pages or the library's data files on 3 November 2026; IDs that could not be checked are left out. Revoked IDs that advisories still cite are shown under their v20 successors as `data/attack/superseded_by.jsonl` records them: `T1574.002` DLL Side-Loading becomes `T1574.001` DLL, `T1562.001` becomes `T1685` Disable or Modify Tools, and `T1070.001` becomes `T1685.005` Clear Windows Event Logs (**Confirmed** [100]).

### Enterprise techniques

The table holds the union of three sets: the techniques ATT&CK v20.0 records at group level for the nine Russia-attributed groups with a government-named sponsor or a TsNIIKhM link (APT28, APT29, Sandworm Team, Turla, Dragonfly, Gamaredon Group, Ember Bear, Star Blizzard, TEMP.Veles); the techniques recorded only on their eight attributed campaigns; and the technique IDs stated in the ATT&CK tables of eight joint advisories (AA20-296A, AA22-011A, AA23-129A, AA23-341A, AA23-347A, AA24-057A, AA24-249A, AA25-141A). That is 330 live Enterprise techniques: 252 recorded at group level, 41 more only on campaigns and 37 more only in the advisories; 154 of the 330 are named in at least one advisory (**Confirmed** [100] [101]). Saint Bear, Winter Vivern, Wizard Spider and Indrik Spider are left out because no government source opened for this study names a Russian service for them, and campaign C0063 is left out because ATT&CK associates it with no group. One advisory list is partial: the 2021 GRU brute-force advisory's tables did not load (**Confirmed** [24]).

Counting each technique once per tactic it serves, the tally is Stealth 49, Persistence 42, Privilege Escalation 36, Command and Control 34, Credential Access 34, Discovery 31, Resource Development 29, Collection 24, Reconnaissance 23, Execution 21, Initial Access 19, Lateral Movement 18, Defense Impairment 14, Impact 10 and Exfiltration 8 (computed from [100]).

The most widely recorded techniques across the nine groups are `T1005` Data from Local System, `T1059.001` PowerShell and `T1588.002` Tool (seven groups each); `T1566.001` Spearphishing Attachment, `T1105` Ingress Tool Transfer, `T1204.002` Malicious File, `T1036.005` Match Legitimate Resource Name or Location and `T1070.004` File Deletion (six); and `T1190`, `T1078`, `T1133`, `T1595.002`, `T1505.003`, `T1053.005` and `T1203` (five) (**Confirmed** [101]). `T1190` is the ID stated in the most advisories, six of the eight (**Inferred** count over the advisories opened).

"Recorded by ATT&CK for" names the groups and campaigns in the library's copy of ATT&CK v20.0, which matched the live pages on the technique fields checked; the APT28 and Sandworm software lists differ slightly from the live pages (Part 2) [96] [80] [82]. "Stated in advisory" gives the advisory and its date. Source numbers refer to the Sources table.

| ID | Technique | Tactic (v20) | Recorded by ATT&CK for | Stated in advisory (date) | Sources |
|---|---|---|---|---|---|
| [`T1001`](/mitre/techniques/T1001.md) | Data Obfuscation | Command and Control | Gamaredon Group | AA23-129A (2023-05-09) | [38] [85] [101] |
| [`T1001.001`](/mitre/techniques/T1001-001.md) | Data Obfuscation: Junk Data | Command and Control | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1001.002`](/mitre/techniques/T1001-002.md) | Data Obfuscation: Steganography | Command and Control | C0023 Operation Ghost (2013-09 to 2019-10) | Not named in the advisories opened | [94] |
| [`T1001.003`](/mitre/techniques/T1001-003.md) | Data Obfuscation: Protocol or Service Impersonation | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | Credential Access | APT28; Ember Bear | AA23-129A (2023-05-09); AA23-347A (2023-12-12); AA24-249A (2024-09-05) | [38] [42] [51] [80] [86] [101] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | OS Credential Dumping: LSASS Memory | Credential Access | APT28; Sandworm Team; Ember Bear; C0025 2016 Ukraine Electric Power Attack (2016-12); C0030 Triton SIS Attack (2017-06 to 2017-08); C0032 Triton IT foothold (2014-10 to 2017-01) | AA23-347A (2023-12-12); AA24-249A (2024-09-05) | [42] [51] [80] [82] [86] [94] [101] |
| [`T1003.002`](/mitre/techniques/T1003-002.md) | OS Credential Dumping: Security Account Manager | Credential Access | APT29; Dragonfly; Ember Bear; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA23-347A (2023-12-12); AA24-249A (2024-09-05) | [42] [51] [81] [84] [86] [94] [97] [101] |
| [`T1003.003`](/mitre/techniques/T1003-003.md) | OS Credential Dumping: NTDS | Credential Access | APT28; Sandworm Team; Dragonfly; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA22-011A (2022-01-11); AA25-141A (2025-05) | [26] [55] [80] [82] [84] [94] [97] [101] |
| [`T1003.004`](/mitre/techniques/T1003-004.md) | OS Credential Dumping: LSA Secrets | Credential Access | APT29; Dragonfly; Ember Bear | Not named in the advisories opened | [81] [84] [86] [101] |
| [`T1003.006`](/mitre/techniques/T1003-006.md) | OS Credential Dumping: DCSync | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | Collection | APT28; Turla; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [81] [82] [83] [84] [85] [86] [94] [101] |
| [`T1006`](/mitre/techniques/T1006.md) | Direct Volume Access | Stealth | C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [94] [97] |
| [`T1007`](/mitre/techniques/T1007.md) | System Service Discovery | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | Discovery | Turla; Dragonfly; Gamaredon Group | Not named in the advisories opened | [83] [84] [85] [101] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | Stealth | APT28 | AA23-129A (2023-05-09) | [38] [80] [101] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | Turla; Dragonfly | Not named in the advisories opened | [83] [84] [101] |
| [`T1016.001`](/mitre/techniques/T1016-001.md) | System Network Configuration Discovery: Internet Connection Discovery | Discovery | Turla; APT29; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [81] [83] [85] [94] [101] |
| [`T1016.002`](/mitre/techniques/T1016-002.md) | System Network Configuration Discovery: Wi-Fi Discovery | Discovery | C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [94] [97] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | Discovery | Turla; Sandworm Team; Dragonfly; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | Not named in the advisories opened | [82] [83] [84] [86] [94] [101] |
| [`T1020`](/mitre/techniques/T1020.md) | Automated Exfiltration | Exfiltration | Gamaredon Group | AA23-347A (2023-12-12) | [42] [85] [101] |
| [`T1021`](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | Ember Bear | Not named in the advisories opened | [86] [101] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Services: Remote Desktop Protocol | Lateral Movement | Dragonfly; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0032 Triton IT foothold (2014-10 to 2017-01); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA25-141A (2025-05) | [55] [84] [94] [97] [101] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | Remote Services: SMB/Windows Admin Shares | Lateral Movement | APT28; Turla; Sandworm Team; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [80] [82] [83] [94] [97] [101] |
| [`T1021.004`](/mitre/techniques/T1021-004.md) | Remote Services: SSH | Lateral Movement | C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [94] |
| [`T1021.005`](/mitre/techniques/T1021-005.md) | Remote Services: VNC | Lateral Movement | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1021.006`](/mitre/techniques/T1021-006.md) | Remote Services: Windows Remote Management | Lateral Movement | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1021.007`](/mitre/techniques/T1021-007.md) | Remote Services: Cloud Services | Lateral Movement | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1025`](/mitre/techniques/T1025.md) | Data from Removable Media | Collection | APT28; Turla; Gamaredon Group | Not named in the advisories opened | [80] [83] [85] [101] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | Sandworm Team; Gamaredon Group; C0025 2016 Ukraine Electric Power Attack (2016-12) | AA23-129A (2023-05-09) | [38] [82] [85] [94] [101] |
| [`T1027.001`](/mitre/techniques/T1027-001.md) | Obfuscated Files or Information: Binary Padding | Stealth | APT29 | AA23-347A (2023-12-12) | [42] [81] [101] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Obfuscated Files or Information: Software Packing | Stealth | APT29; C0025 2016 Ukraine Electric Power Attack (2016-12) | AA23-129A (2023-05-09) | [38] [81] [94] [101] |
| [`T1027.003`](/mitre/techniques/T1027-003.md) | Obfuscated Files or Information: Steganography | Stealth | C0023 Operation Ghost (2013-09 to 2019-10) | Not named in the advisories opened | [94] |
| [`T1027.004`](/mitre/techniques/T1027-004.md) | Obfuscated Files or Information: Compile After Delivery | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1027.005`](/mitre/techniques/T1027-005.md) | Obfuscated Files or Information: Indicator Removal from Tools | Stealth | Turla; C0030 Triton SIS Attack (2017-06 to 2017-08) | Not named in the advisories opened | [83] [94] [101] |
| [`T1027.006`](/mitre/techniques/T1027-006.md) | Obfuscated Files or Information: HTML Smuggling | Stealth | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1027.010`](/mitre/techniques/T1027-010.md) | Obfuscated Files or Information: Command Obfuscation | Stealth | Turla; Sandworm Team; Gamaredon Group | Not named in the advisories opened | [82] [83] [85] [101] |
| [`T1027.011`](/mitre/techniques/T1027-011.md) | Obfuscated Files or Information: Fileless Storage | Stealth | Turla | Not named in the advisories opened | [83] [101] |
| [`T1027.012`](/mitre/techniques/T1027-012.md) | Obfuscated Files or Information: LNK Icon Smuggling | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1027.015`](/mitre/techniques/T1027-015.md) | Obfuscated Files or Information: Compression | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1027.016`](/mitre/techniques/T1027-016.md) | Obfuscated Files or Information: Junk Code Insertion | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1029`](/mitre/techniques/T1029.md) | Scheduled Transfer | Exfiltration | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1030`](/mitre/techniques/T1030.md) | Data Transfer Size Limits | Exfiltration | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | Discovery | Sandworm Team; Dragonfly; Gamaredon Group | AA23-347A (2023-12-12) | [42] [82] [84] [85] [101] |
| [`T1036`](/mitre/techniques/T1036.md) | Masquerading | Stealth | APT28; Sandworm Team; Ember Bear | AA23-129A (2023-05-09); AA23-347A (2023-12-12) | [38] [42] [80] [82] [86] [101] |
| [`T1036.004`](/mitre/techniques/T1036-004.md) | Masquerading: Masquerade Task or Service | Stealth | C0024 SolarWinds Compromise (2019-08 to 2021-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | Not named in the advisories opened | [94] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Masquerading: Match Legitimate Resource Name or Location | Stealth | APT28; Turla; APT29; Sandworm Team; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0030 Triton SIS Attack (2017-06 to 2017-08); C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [80] [81] [82] [83] [85] [86] [94] [101] |
| [`T1036.008`](/mitre/techniques/T1036-008.md) | Masquerading: Masquerade File Type | Stealth | C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [94] |
| [`T1036.010`](/mitre/techniques/T1036-010.md) | Masquerading: Masquerade Account Name | Stealth | Dragonfly; C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [84] [94] [101] |
| [`T1037`](/mitre/techniques/T1037.md) | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1037.001`](/mitre/techniques/T1037-001.md) | Boot or Logon Initialization Scripts: Logon Script (Windows) | Persistence, Privilege Escalation | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1037.004`](/mitre/techniques/T1037-004.md) | Boot or Logon Initialization Scripts: RC Scripts | Persistence, Privilege Escalation | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1039`](/mitre/techniques/T1039.md) | Data from Network Shared Drive | Collection | APT28; Gamaredon Group | Not named in the advisories opened | [80] [85] [101] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | APT28; Sandworm Team; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-129A (2023-05-09) | [38] [80] [82] [94] [101] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | Sandworm Team; Gamaredon Group | AA23-347A (2023-12-12) | [42] [82] [85] [101] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | Ember Bear | AA23-129A (2023-05-09); AA23-347A (2023-12-12); AA24-249A (2024-09-05) | [38] [42] [51] [86] [101] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | APT29; Sandworm Team; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12) | AA23-347A (2023-12-12) | [42] [81] [82] [85] [86] [94] [101] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | Exfiltration | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1048.002`](/mitre/techniques/T1048-002.md) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration | APT28; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [94] [101] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | Turla; Sandworm Team | AA23-347A (2023-12-12) | [42] [82] [83] [101] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | APT29; Sandworm Team; Dragonfly; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0030 Triton SIS Attack (2017-06 to 2017-08); C0032 Triton IT foothold (2014-10 to 2017-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA23-347A (2023-12-12); AA25-141A (2025-05) | [42] [55] [81] [82] [84] [85] [86] [94] [101] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | Stealth, Privilege Escalation | Turla; Gamaredon Group; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-347A (2023-12-12) | [42] [83] [85] [94] [101] |
| [`T1055.001`](/mitre/techniques/T1055-001.md) | Process Injection: Dynamic-link Library Injection | Stealth, Privilege Escalation | Turla | AA23-129A (2023-05-09) | [38] [83] [101] |
| [`T1056`](/mitre/techniques/T1056.md) | Input Capture | Collection, Credential Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Input Capture: Keylogging | Collection, Credential Access | APT28; Sandworm Team; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-129A (2023-05-09) | [38] [80] [82] [94] [101] |
| [`T1056.003`](/mitre/techniques/T1056-003.md) | Input Capture: Web Portal Capture | Collection, Credential Access | C0030 Triton SIS Attack (2017-06 to 2017-08) | Not named in the advisories opened | [94] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | Discovery | APT28; Turla; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-347A (2023-12-12) | [42] [80] [83] [85] [94] [101] |
| [`T1059`](/mitre/techniques/T1059.md) | Command and Scripting Interpreter | Execution | Dragonfly | AA25-141A (2025-05) | [55] [84] [101] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | Command and Scripting Interpreter: PowerShell | Execution | APT28; Turla; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0030 Triton SIS Attack (2017-06 to 2017-08); C0032 Triton IT foothold (2014-10 to 2017-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA23-129A (2023-05-09); AA23-347A (2023-12-12); AA24-249A (2024-09-05); AA25-141A (2025-05) | [38] [42] [51] [55] [80] [81] [82] [83] [84] [85] [86] [94] [97] [101] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Command and Scripting Interpreter: Windows Command Shell | Execution | APT28; Turla; Dragonfly; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA22-011A (2022-01-11); AA23-347A (2023-12-12); AA25-141A (2025-05) | [26] [42] [55] [80] [83] [84] [85] [94] [97] [101] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Command and Scripting Interpreter: Visual Basic | Execution | Turla; Sandworm Team; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA25-141A (2025-05) | [55] [82] [83] [85] [94] [101] |
| [`T1059.006`](/mitre/techniques/T1059-006.md) | Command and Scripting Interpreter: Python | Execution | Turla; APT29; Dragonfly | AA25-141A (2025-05) | [55] [81] [83] [84] [101] |
| [`T1059.007`](/mitre/techniques/T1059-007.md) | Command and Scripting Interpreter: JavaScript | Execution | Turla; Star Blizzard | Not named in the advisories opened | [83] [87] [101] |
| [`T1059.009`](/mitre/techniques/T1059-009.md) | Command and Scripting Interpreter: Cloud API | Execution | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | APT28; Turla; APT29 | AA23-347A (2023-12-12) | [42] [80] [81] [83] [101] |
| [`T1069`](/mitre/techniques/T1069.md) | Permission Groups Discovery | Discovery | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1069.001`](/mitre/techniques/T1069-001.md) | Permission Groups Discovery: Local Groups | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1069.002`](/mitre/techniques/T1069-002.md) | Permission Groups Discovery: Domain Groups | Discovery | Turla; Dragonfly; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [83] [84] [94] [101] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | Indicator Removal: File Deletion | Stealth | APT28; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01); C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [80] [81] [82] [84] [85] [86] [94] [101] |
| [`T1070.006`](/mitre/techniques/T1070-006.md) | Indicator Removal: Timestomp | Stealth | APT28; APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [80] [81] [94] [101] |
| [`T1070.008`](/mitre/techniques/T1070-008.md) | Indicator Removal: Clear Mailbox Data | Stealth | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1071`](/mitre/techniques/T1071.md) | Application Layer Protocol | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Application Layer Protocol: Web Protocols | Command and Control | APT28; Turla; Sandworm Team; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-129A (2023-05-09); AA24-249A (2024-09-05) | [38] [51] [80] [82] [83] [85] [94] [101] |
| [`T1071.002`](/mitre/techniques/T1071-002.md) | Application Layer Protocol: File Transfer Protocols | Command and Control | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1071.003`](/mitre/techniques/T1071-003.md) | Application Layer Protocol: Mail Protocols | Command and Control | APT28; Turla | AA23-129A (2023-05-09) | [38] [80] [83] [101] |
| [`T1071.004`](/mitre/techniques/T1071-004.md) | Application Layer Protocol: DNS | Command and Control | Ember Bear | AA23-129A (2023-05-09); AA24-249A (2024-09-05) | [38] [51] [86] [101] |
| [`T1072`](/mitre/techniques/T1072.md) | Software Deployment Tools | Execution, Lateral Movement | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1074`](/mitre/techniques/T1074.md) | Data Staged | Collection | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Data Staged: Local Data Staging | Collection | APT28; Dragonfly; C0032 Triton IT foothold (2014-10 to 2017-01); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [80] [84] [94] [97] [101] |
| [`T1074.002`](/mitre/techniques/T1074-002.md) | Data Staged: Remote Data Staging | Collection | APT28; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [94] [101] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | APT28; APT29; Sandworm Team; Dragonfly; Star Blizzard; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01); C0032 Triton IT foothold (2014-10 to 2017-01) | AA20-296A (2020-10-22); AA22-011A (2022-01-11); AA23-129A (2023-05-09); AA23-341A (2023-12-07) | [16] [26] [38] [40] [80] [81] [82] [84] [87] [94] [101] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Valid Accounts: Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Ember Bear | AA24-249A (2024-09-05) | [51] [86] [101] |
| [`T1078.002`](/mitre/techniques/T1078-002.md) | Valid Accounts: Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Sandworm Team; C0023 Operation Ghost (2013-09 to 2019-10); C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [82] [94] [101] |
| [`T1078.003`](/mitre/techniques/T1078-003.md) | Valid Accounts: Local Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Turla; APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [81] [83] [94] [101] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Valid Accounts: Cloud Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | APT28; APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA24-057A (2024-02-26) | [45] [80] [81] [94] [101] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | Lateral Movement | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | Turla; Sandworm Team; Gamaredon Group | Not named in the advisories opened | [82] [83] [85] [101] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | APT28; Turla; Sandworm Team; Dragonfly; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-129A (2023-05-09) | [38] [80] [82] [83] [84] [85] [94] [101] |
| [`T1087`](/mitre/techniques/T1087.md) | Account Discovery | Discovery | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Account Discovery: Local Account | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Account Discovery: Domain Account | Discovery | Turla; Sandworm Team; Dragonfly; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA25-141A (2025-05) | [55] [82] [83] [84] [94] [101] |
| [`T1087.003`](/mitre/techniques/T1087-003.md) | Account Discovery: Email Account | Discovery | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1087.004`](/mitre/techniques/T1087-004.md) | Account Discovery: Cloud Account | Discovery | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | Command and Control | Turla; Sandworm Team; Gamaredon Group | Not named in the advisories opened | [82] [83] [85] [101] |
| [`T1090.001`](/mitre/techniques/T1090-001.md) | Proxy: Internal Proxy | Command and Control | Turla; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [83] [94] [97] [101] |
| [`T1090.002`](/mitre/techniques/T1090-002.md) | Proxy: External Proxy | Command and Control | APT28; APT29 | AA24-057A (2024-02-26); AA25-141A (2025-05) | [45] [55] [80] [81] [101] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Proxy: Multi-hop Proxy | Command and Control | APT28; APT29; Gamaredon Group; Ember Bear | AA22-011A (2022-01-11); AA23-129A (2023-05-09); AA24-249A (2024-09-05); AA25-141A (2025-05) | [26] [38] [51] [55] [80] [81] [85] [86] [101] |
| [`T1090.004`](/mitre/techniques/T1090-004.md) | Proxy: Domain Fronting | Command and Control | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | Lateral Movement, Initial Access | APT28; Gamaredon Group | Not named in the advisories opened | [80] [85] [101] |
| [`T1092`](/mitre/techniques/T1092.md) | Communication Through Removable Media | Command and Control | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | Command and Control | Gamaredon Group; Ember Bear; C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA23-129A (2023-05-09); AA24-249A (2024-09-05) | [38] [51] [85] [86] [94] [101] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | C0025 2016 Ukraine Electric Power Attack (2016-12) | AA23-347A (2023-12-12) | [42] [94] |
| [`T1098.001`](/mitre/techniques/T1098-001.md) | Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1098.002`](/mitre/techniques/T1098-002.md) | Account Manipulation: Additional Email Delegate Permissions | Persistence, Privilege Escalation | APT28; APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA25-141A (2025-05) | [55] [80] [81] [94] [101] |
| [`T1098.003`](/mitre/techniques/T1098-003.md) | Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1098.005`](/mitre/techniques/T1098-005.md) | Account Manipulation: Device Registration | Persistence, Privilege Escalation | APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA24-057A (2024-02-26) | [45] [81] [94] [101] |
| [`T1098.007`](/mitre/techniques/T1098-007.md) | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1102`](/mitre/techniques/T1102.md) | Web Service | Command and Control | Turla; Gamaredon Group | Not named in the advisories opened | [83] [85] [101] |
| [`T1102.002`](/mitre/techniques/T1102-002.md) | Web Service: Bidirectional Communication | Command and Control | APT28; Turla; Sandworm Team; Gamaredon Group; C0023 Operation Ghost (2013-09 to 2019-10) | Not named in the advisories opened | [80] [82] [83] [85] [94] [101] |
| [`T1102.003`](/mitre/techniques/T1102-003.md) | Web Service: One-Way Communication | Command and Control | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1104`](/mitre/techniques/T1104.md) | Multi-Stage Channels | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09); AA25-141A (2025-05) | [38] [55] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | APT28; Turla; APT29; Sandworm Team; Dragonfly; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA24-249A (2024-09-05) | [51] [80] [81] [82] [83] [84] [85] [94] [101] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | Execution | Turla; Sandworm Team; Gamaredon Group | AA23-129A (2023-05-09) | [38] [82] [83] [85] [101] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | Credential Access | APT28; Turla; Dragonfly; Ember Bear; C0025 2016 Ukraine Electric Power Attack (2016-12) | AA20-296A (2020-10-22); AA24-057A (2024-02-26); AA25-141A (2025-05) | [16] [45] [55] [80] [83] [84] [86] [94] [101] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Brute Force: Password Guessing | Credential Access | APT28; APT29 | AA22-011A (2022-01-11); AA25-141A (2025-05) | [26] [55] [80] [81] [101] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Brute Force: Password Cracking | Credential Access | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Brute Force: Password Spraying | Credential Access | APT28; APT29; Ember Bear; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA22-011A (2022-01-11); AA24-249A (2024-09-05); AA25-141A (2025-05) | [26] [51] [55] [80] [81] [86] [94] [97] [101] |
| [`T1111`](/mitre/techniques/T1111.md) | Multi-Factor Authentication Interception | Credential Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | Turla; Dragonfly; Gamaredon Group; Ember Bear; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-129A (2023-05-09) | [38] [83] [84] [85] [86] [94] [101] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | Collection | APT28; Dragonfly; Gamaredon Group | Not named in the advisories opened | [80] [84] [85] [101] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | Collection | Ember Bear | AA24-249A (2024-09-05); AA25-141A (2025-05) | [51] [55] [86] [101] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Email Collection: Remote Email Collection | Collection | APT28; APT29; Dragonfly; Star Blizzard; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-341A (2023-12-07); AA25-141A (2025-05) | [40] [55] [80] [81] [84] [87] [94] [101] |
| [`T1114.003`](/mitre/techniques/T1114-003.md) | Email Collection: Email Forwarding Rule | Collection | Star Blizzard | AA23-341A (2023-12-07) | [40] [87] [101] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | Collection | APT28; Gamaredon Group; Ember Bear | AA23-129A (2023-05-09); AA25-141A (2025-05) | [38] [55] [80] [85] [86] [101] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | Discovery | APT28; Turla; Gamaredon Group | Not named in the advisories opened | [80] [83] [85] [101] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1125`](/mitre/techniques/T1125.md) | Video Capture | Collection | Ember Bear | AA24-249A (2024-09-05); AA25-141A (2025-05) | [51] [55] [86] [101] |
| [`T1132`](/mitre/techniques/T1132.md) | Data Encoding | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1132.001`](/mitre/techniques/T1132-001.md) | Data Encoding: Standard Encoding | Command and Control | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1132.002`](/mitre/techniques/T1132-002.md) | Data Encoding: Non-Standard Encoding | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | APT28; APT29; Sandworm Team; Dragonfly; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01); C0032 Triton IT foothold (2014-10 to 2017-01) | AA20-296A (2020-10-22); AA25-141A (2025-05) | [16] [55] [80] [81] [82] [84] [86] [94] [101] |
| [`T1134.001`](/mitre/techniques/T1134-001.md) | Access Token Manipulation: Token Impersonation/Theft | Stealth, Privilege Escalation | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1134.002`](/mitre/techniques/T1134-002.md) | Access Token Manipulation: Create Process with Token | Stealth, Privilege Escalation | Turla | Not named in the advisories opened | [83] [101] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | Dragonfly | AA23-129A (2023-05-09) | [38] [84] [101] |
| [`T1136`](/mitre/techniques/T1136.md) | Create Account | Persistence | C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [94] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Create Account: Local Account | Persistence | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1136.002`](/mitre/techniques/T1136-002.md) | Create Account: Domain Account | Persistence | C0025 2016 Ukraine Electric Power Attack (2016-12); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | Not named in the advisories opened | [94] |
| [`T1136.003`](/mitre/techniques/T1136-003.md) | Create Account: Cloud Account | Persistence | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1137`](/mitre/techniques/T1137.md) | Office Application Startup | Persistence | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1137.002`](/mitre/techniques/T1137-002.md) | Office Application Startup: Office Test | Persistence | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | APT28; Turla; Sandworm Team; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA23-129A (2023-05-09) | [38] [80] [82] [83] [85] [94] [97] [101] |
| [`T1187`](/mitre/techniques/T1187.md) | Forced Authentication | Credential Access | Dragonfly | AA25-141A (2025-05) | [55] [84] [101] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | APT28; Turla; Dragonfly | AA20-296A (2020-10-22) | [16] [80] [83] [84] [101] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | APT28; APT29; Sandworm Team; Dragonfly; Ember Bear; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA20-296A (2020-10-22); AA22-011A (2022-01-11); AA23-129A (2023-05-09); AA23-347A (2023-12-12); AA24-249A (2024-09-05); AA25-141A (2025-05) | [16] [26] [38] [42] [51] [55] [80] [81] [82] [84] [86] [94] [101] |
| [`T1195`](/mitre/techniques/T1195.md) | Supply Chain Compromise | Initial Access | Sandworm Team; Ember Bear | Not named in the advisories opened | [82] [86] [101] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | Sandworm Team; Dragonfly; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA22-011A (2022-01-11) | [26] [82] [84] [94] [101] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | APT28; APT29; Sandworm Team; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA25-141A (2025-05) | [55] [80] [81] [82] [94] [101] |
| [`T1201`](/mitre/techniques/T1201.md) | Password Policy Discovery | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | APT28; APT29; Sandworm Team; Dragonfly; Ember Bear | AA23-347A (2023-12-12) | [42] [80] [81] [82] [84] [86] [101] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | User Execution: Malicious Link | Execution | APT28; Turla; APT29; Sandworm Team; Gamaredon Group | AA25-141A (2025-05) | [55] [80] [81] [82] [83] [85] [101] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | User Execution: Malicious File | Execution | APT28; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Star Blizzard; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA25-141A (2025-05) | [55] [80] [81] [82] [84] [85] [87] [94] [101] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | Lateral Movement | APT28; Dragonfly; Ember Bear | AA23-347A (2023-12-12) | [42] [80] [84] [86] [101] |
| [`T1211`](/mitre/techniques/T1211.md) | Exploitation for Stealth | Stealth | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1212`](/mitre/techniques/T1212.md) | Exploitation for Credential Access | Credential Access | Not recorded for these groups or campaigns | AA22-011A (2022-01-11) | [26] |
| [`T1213`](/mitre/techniques/T1213.md) | Data from Information Repositories | Collection | APT28; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [94] [101] |
| [`T1213.001`](/mitre/techniques/T1213-001.md) | Data from Information Repositories: Confluence | Collection | Not recorded for these groups or campaigns | AA24-249A (2024-09-05) | [51] |
| [`T1213.002`](/mitre/techniques/T1213-002.md) | Data from Information Repositories: Sharepoint | Collection | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1213.003`](/mitre/techniques/T1213-003.md) | Data from Information Repositories: Code Repositories | Collection | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1213.006`](/mitre/techniques/T1213-006.md) | Data from Information Repositories: Databases | Collection | Turla; Sandworm Team | Not named in the advisories opened | [82] [83] [101] |
| [`T1218.005`](/mitre/techniques/T1218-005.md) | System Binary Proxy Execution: Mshta | Stealth | APT29; Gamaredon Group | Not named in the advisories opened | [81] [85] [101] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | System Binary Proxy Execution: Rundll32 | Stealth | APT28; Sandworm Team; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | Not named in the advisories opened | [80] [82] [85] [94] [101] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | Command and Control | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1221`](/mitre/techniques/T1221.md) | Template Injection | Stealth | APT28; Dragonfly; Gamaredon Group | Not named in the advisories opened | [80] [84] [85] [101] |
| [`T1480`](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1482`](/mitre/techniques/T1482.md) | Domain Trust Discovery | Discovery | C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-129A (2023-05-09) | [38] [94] |
| [`T1484.001`](/mitre/techniques/T1484-001.md) | Domain or Tenant Policy Modification: Group Policy Modification | Defense Impairment, Privilege Escalation | C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | Not named in the advisories opened | [94] |
| [`T1484.002`](/mitre/techniques/T1484-002.md) | Domain or Tenant Policy Modification: Trust Modification | Defense Impairment, Privilege Escalation | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | Impact | Sandworm Team; C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA24-249A (2024-09-05) | [51] [82] [94] [101] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1489`](/mitre/techniques/T1489.md) | Service Stop | Impact | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1490`](/mitre/techniques/T1490.md) | Inhibit System Recovery | Impact | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1491.001`](/mitre/techniques/T1491-001.md) | Defacement: Internal Defacement | Impact | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | Defacement: External Defacement | Impact | Sandworm Team; Ember Bear | Not named in the advisories opened | [82] [86] [101] |
| [`T1497.001`](/mitre/techniques/T1497-001.md) | Virtualization/Sandbox Evasion: System Checks | Stealth, Discovery | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | Impact | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | Impact | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1505.001`](/mitre/techniques/T1505-001.md) | Server Software Component: SQL Stored Procedures | Persistence | C0025 2016 Ukraine Electric Power Attack (2016-12) | AA23-347A (2023-12-12) | [42] [94] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Server Software Component: Web Shell | Persistence | APT28; APT29; Sandworm Team; Dragonfly; Ember Bear; C0032 Triton IT foothold (2014-10 to 2017-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA24-249A (2024-09-05) | [51] [80] [81] [82] [84] [86] [94] [101] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Software Discovery: Security Software Discovery | Discovery | Turla; Gamaredon Group | Not named in the advisories opened | [83] [85] [101] |
| [`T1528`](/mitre/techniques/T1528.md) | Steal Application Access Token | Credential Access | APT28; APT29 | AA24-057A (2024-02-26) | [45] [80] [81] [101] |
| [`T1534`](/mitre/techniques/T1534.md) | Internal Spearphishing | Lateral Movement | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1539`](/mitre/techniques/T1539.md) | Steal Web Session Cookie | Credential Access | Sandworm Team; Star Blizzard; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-341A (2023-12-07) | [40] [82] [87] [94] [101] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Pre-OS Boot: Bootkit | Stealth, Persistence | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1543.002`](/mitre/techniques/T1543-002.md) | Create or Modify System Process: Systemd Service | Persistence, Privilege Escalation | C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | Not named in the advisories opened | [94] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [94] |
| [`T1546.003`](/mitre/techniques/T1546-003.md) | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence | Turla; APT29; C0023 Operation Ghost (2013-09 to 2019-10); C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [81] [83] [94] [101] |
| [`T1546.008`](/mitre/techniques/T1546-008.md) | Event Triggered Execution: Accessibility Features | Privilege Escalation, Persistence | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1546.012`](/mitre/techniques/T1546-012.md) | Event Triggered Execution: Image File Execution Options Injection | Privilege Escalation, Persistence | C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [94] |
| [`T1546.013`](/mitre/techniques/T1546-013.md) | Event Triggered Execution: PowerShell Profile | Privilege Escalation, Persistence | Turla | Not named in the advisories opened | [83] [101] |
| [`T1546.015`](/mitre/techniques/T1546-015.md) | Event Triggered Execution: Component Object Model Hijacking | Privilege Escalation, Persistence | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1546.016`](/mitre/techniques/T1546-016.md) | Event Triggered Execution: Installer Packages | Privilege Escalation, Persistence | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1547`](/mitre/techniques/T1547.md) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation | Not recorded for these groups or campaigns | AA23-347A (2023-12-12) | [42] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | APT28; Turla; APT29; Dragonfly; Gamaredon Group | AA25-141A (2025-05) | [55] [80] [81] [83] [84] [85] [101] |
| [`T1547.004`](/mitre/techniques/T1547-004.md) | Boot or Logon Autostart Execution: Winlogon Helper DLL | Persistence, Privilege Escalation | Turla | Not named in the advisories opened | [83] [101] |
| [`T1547.006`](/mitre/techniques/T1547-006.md) | Boot or Logon Autostart Execution: Kernel Modules and Extensions | Persistence, Privilege Escalation | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1547.009`](/mitre/techniques/T1547-009.md) | Boot or Logon Autostart Execution: Shortcut Modification | Persistence, Privilege Escalation | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1548.002`](/mitre/techniques/T1548-002.md) | Abuse Elevation Control Mechanism: Bypass User Account Control | Privilege Escalation | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1550`](/mitre/techniques/T1550.md) | Use Alternate Authentication Material | Lateral Movement | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1550.001`](/mitre/techniques/T1550-001.md) | Use Alternate Authentication Material: Application Access Token | Lateral Movement | APT28; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [94] [101] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Use Alternate Authentication Material: Pass the Hash | Lateral Movement | APT28; Ember Bear | AA24-249A (2024-09-05) | [51] [80] [86] [101] |
| [`T1550.003`](/mitre/techniques/T1550-003.md) | Use Alternate Authentication Material: Pass the Ticket | Lateral Movement | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1550.004`](/mitre/techniques/T1550-004.md) | Use Alternate Authentication Material: Web Session Cookie | Lateral Movement | Star Blizzard; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-341A (2023-12-07) | [40] [87] [94] [101] |
| [`T1552.001`](/mitre/techniques/T1552-001.md) | Unsecured Credentials: Credentials In Files | Credential Access | Ember Bear | AA24-249A (2024-09-05) | [51] [86] [101] |
| [`T1552.004`](/mitre/techniques/T1552-004.md) | Unsecured Credentials: Private Keys | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA22-011A (2022-01-11) | [26] [94] |
| [`T1552.006`](/mitre/techniques/T1552-006.md) | Unsecured Credentials: Group Policy Preferences | Credential Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Subvert Trust Controls: Code Signing | Defense Impairment | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1553.005`](/mitre/techniques/T1553-005.md) | Subvert Trust Controls: Mark-of-the-Web Bypass | Defense Impairment | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1553.006`](/mitre/techniques/T1553-006.md) | Subvert Trust Controls: Code Signing Policy Modification | Defense Impairment | Turla | Not named in the advisories opened | [83] [101] |
| [`T1554`](/mitre/techniques/T1554.md) | Compromise Host Software Binary | Persistence | C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [94] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA22-011A (2022-01-11) | [26] [94] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | Sandworm Team; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-347A (2023-12-12) | [42] [82] [94] [101] |
| [`T1555.004`](/mitre/techniques/T1555-004.md) | Credentials from Password Stores: Windows Credential Manager | Credential Access | Turla | Not named in the advisories opened | [83] [101] |
| [`T1556.006`](/mitre/techniques/T1556-006.md) | Modify Authentication Process: Multi-Factor Authentication | Defense Impairment, Persistence, Credential Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1556.007`](/mitre/techniques/T1556-007.md) | Modify Authentication Process: Hybrid Identity | Defense Impairment, Persistence, Credential Access | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1557.004`](/mitre/techniques/T1557-004.md) | Adversary-in-the-Middle: Evil Twin | Credential Access, Collection | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1558.001`](/mitre/techniques/T1558-001.md) | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access | Not recorded for these groups or campaigns | AA23-347A (2023-12-12) | [42] |
| [`T1558.003`](/mitre/techniques/T1558-003.md) | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA22-011A (2022-01-11) | [26] [94] |
| [`T1559`](/mitre/techniques/T1559.md) | Inter-Process Communication | Execution | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1559.001`](/mitre/techniques/T1559-001.md) | Inter-Process Communication: Component Object Model | Execution | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1559.002`](/mitre/techniques/T1559-002.md) | Inter-Process Communication: Dynamic Data Exchange | Execution | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1560`](/mitre/techniques/T1560.md) | Archive Collected Data | Collection | APT28; Dragonfly; Ember Bear | AA24-249A (2024-09-05); AA25-141A (2025-05) | [51] [55] [80] [84] [86] [101] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive Collected Data: Archive via Utility | Collection | APT28; Turla; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA25-141A (2025-05) | [55] [80] [83] [94] [97] [101] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive Collected Data: Archive via Custom Method | Collection | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Wipe: Disk Content Wipe | Impact | Gamaredon Group; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [85] [94] [97] [101] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Wipe: Disk Structure Wipe | Impact | Sandworm Team; Ember Bear | Not named in the advisories opened | [82] [86] [101] |
| [`T1564`](/mitre/techniques/T1564.md) | Hide Artifacts | Stealth | Not recorded for these groups or campaigns | AA23-129A (2023-05-09); AA23-347A (2023-12-12) | [38] [42] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hide Artifacts: Hidden Files and Directories | Stealth | APT28 | AA23-347A (2023-12-12) | [42] [80] [101] |
| [`T1564.002`](/mitre/techniques/T1564-002.md) | Hide Artifacts: Hidden Users | Stealth | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1564.003`](/mitre/techniques/T1564-003.md) | Hide Artifacts: Hidden Window | Stealth | APT28; Gamaredon Group | Not named in the advisories opened | [80] [85] [101] |
| [`T1564.012`](/mitre/techniques/T1564-012.md) | Hide Artifacts: File/Path Exclusions | Stealth | Turla | Not named in the advisories opened | [83] [101] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | Initial Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Phishing: Spearphishing Attachment | Initial Access | APT28; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Star Blizzard; C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-341A (2023-12-07); AA25-141A (2025-05) | [40] [55] [80] [81] [82] [84] [85] [87] [94] [101] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Phishing: Spearphishing Link | Initial Access | Turla; APT29; Sandworm Team | AA23-341A (2023-12-07); AA25-141A (2025-05) | [40] [55] [81] [82] [83] [101] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Phishing: Spearphishing via Service | Initial Access | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1566.004`](/mitre/techniques/T1566-004.md) | Phishing: Spearphishing Voice | Initial Access | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1567`](/mitre/techniques/T1567.md) | Exfiltration Over Web Service | Exfiltration | APT28; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA23-347A (2023-12-12) | [42] [80] [94] [97] [101] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | Turla; Ember Bear | AA24-249A (2024-09-05) | [51] [83] [86] [101] |
| [`T1568`](/mitre/techniques/T1568.md) | Dynamic Resolution | Command and Control | APT29; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-347A (2023-12-12) | [42] [81] [85] [94] [101] |
| [`T1568.001`](/mitre/techniques/T1568-001.md) | Dynamic Resolution: Fast Flux DNS | Command and Control | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | System Services: Service Execution | Execution | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | Lateral Movement | Turla; Sandworm Team; Ember Bear; C0025 2016 Ukraine Electric Power Attack (2016-12); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA23-129A (2023-05-09) | [38] [82] [83] [86] [94] [101] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | Command and Control | Sandworm Team; Gamaredon Group; Ember Bear; C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [82] [85] [86] [94] [101] |
| [`T1572`](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | Ember Bear; C0032 Triton IT foothold (2014-10 to 2017-01); C0034 2022 Ukraine Electric Power Attack (2022-06 to 2022-10) | AA23-129A (2023-05-09); AA23-347A (2023-12-12); AA24-249A (2024-09-05) | [38] [42] [51] [86] [94] [101] |
| [`T1573`](/mitre/techniques/T1573.md) | Encrypted Channel | Command and Control | APT29; C0030 Triton SIS Attack (2017-06 to 2017-08) | AA23-129A (2023-05-09); AA25-141A (2025-05) | [38] [55] [81] [94] [101] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Encrypted Channel: Symmetric Cryptography | Command and Control | APT28 | AA23-129A (2023-05-09) | [38] [80] [101] |
| [`T1573.002`](/mitre/techniques/T1573-002.md) | Encrypted Channel: Asymmetric Cryptography | Command and Control | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | Hijack Execution Flow: DLL | Stealth, Execution | Not recorded for these groups or campaigns | AA23-347A (2023-12-12, stated as `T1574.002`); AA25-141A (2025-05) | [42] [55] |
| [`T1583`](/mitre/techniques/T1583.md) | Acquire Infrastructure | Resource Development | Sandworm Team; Ember Bear; Star Blizzard | Not named in the advisories opened | [82] [86] [87] [101] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Acquire Infrastructure: Domains | Resource Development | APT28; Sandworm Team; Dragonfly; Gamaredon Group; Star Blizzard; C0023 Operation Ghost (2013-09 to 2019-10); C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA23-341A (2023-12-07) | [40] [80] [82] [84] [85] [87] [94] [101] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Acquire Infrastructure: Virtual Private Server | Resource Development | APT28; Dragonfly; Gamaredon Group; Ember Bear; C0032 Triton IT foothold (2014-10 to 2017-01) | AA24-249A (2024-09-05) | [51] [80] [84] [85] [86] [94] [101] |
| [`T1583.004`](/mitre/techniques/T1583-004.md) | Acquire Infrastructure: Server | Resource Development | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Acquire Infrastructure: Web Services | Resource Development | APT28; Turla; APT29; Gamaredon Group | Not named in the advisories opened | [80] [81] [83] [85] [101] |
| [`T1584`](/mitre/techniques/T1584.md) | Compromise Infrastructure | Resource Development | C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | AA23-129A (2023-05-09) | [38] [94] [97] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Compromise Infrastructure: Domains | Resource Development | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1584.003`](/mitre/techniques/T1584-003.md) | Compromise Infrastructure: Virtual Private Server | Resource Development | Turla | Not named in the advisories opened | [83] [101] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Compromise Infrastructure: Server | Resource Development | Turla; Sandworm Team; Dragonfly | Not named in the advisories opened | [82] [83] [84] [101] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Compromise Infrastructure: Botnet | Resource Development | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1584.006`](/mitre/techniques/T1584-006.md) | Compromise Infrastructure: Web Services | Resource Development | Turla | Not named in the advisories opened | [83] [101] |
| [`T1584.008`](/mitre/techniques/T1584-008.md) | Compromise Infrastructure: Network Devices | Resource Development | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1585`](/mitre/techniques/T1585.md) | Establish Accounts | Resource Development | Ember Bear | Not named in the advisories opened | [86] [101] |
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Establish Accounts: Social Media Accounts | Resource Development | Sandworm Team; Star Blizzard; C0023 Operation Ghost (2013-09 to 2019-10) | AA23-341A (2023-12-07) | [40] [82] [87] [94] [101] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Establish Accounts: Email Accounts | Resource Development | Sandworm Team; Star Blizzard | AA23-341A (2023-12-07) | [40] [82] [87] [101] |
| [`T1586.001`](/mitre/techniques/T1586-001.md) | Compromise Accounts: Social Media Accounts | Resource Development | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1586.002`](/mitre/techniques/T1586-002.md) | Compromise Accounts: Email Accounts | Resource Development | APT28; APT29; Star Blizzard | AA23-341A (2023-12-07); AA25-141A (2025-05) | [40] [55] [80] [81] [87] [101] |
| [`T1586.003`](/mitre/techniques/T1586-003.md) | Compromise Accounts: Cloud Accounts | Resource Development | APT29 | AA25-141A (2025-05) | [55] [81] [101] |
| [`T1587.001`](/mitre/techniques/T1587-001.md) | Develop Capabilities: Malware | Resource Development | Turla; APT29; Sandworm Team; C0023 Operation Ghost (2013-09 to 2019-10); C0024 SolarWinds Compromise (2019-08 to 2021-01); C0030 Triton SIS Attack (2017-06 to 2017-08) | AA22-011A (2022-01-11); AA23-129A (2023-05-09) | [26] [38] [81] [82] [83] [94] [101] |
| [`T1587.003`](/mitre/techniques/T1587-003.md) | Develop Capabilities: Digital Certificates | Resource Development | APT29; Gamaredon Group | Not named in the advisories opened | [81] [85] [101] |
| [`T1588`](/mitre/techniques/T1588.md) | Obtain Capabilities | Resource Development | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1588.001`](/mitre/techniques/T1588-001.md) | Obtain Capabilities: Malware | Resource Development | Turla; Ember Bear | AA24-249A (2024-09-05) | [51] [83] [86] [101] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Obtain Capabilities: Tool | Resource Development | APT28; Turla; APT29; Sandworm Team; Dragonfly; Gamaredon Group; Star Blizzard; C0030 Triton SIS Attack (2017-06 to 2017-08); C0032 Triton IT foothold (2014-10 to 2017-01) | Not named in the advisories opened | [80] [81] [82] [83] [84] [85] [87] [94] [101] |
| [`T1588.005`](/mitre/techniques/T1588-005.md) | Obtain Capabilities: Exploits | Resource Development | Ember Bear | AA24-249A (2024-09-05) | [51] [86] [101] |
| [`T1588.006`](/mitre/techniques/T1588-006.md) | Obtain Capabilities: Vulnerabilities | Resource Development | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1588.007`](/mitre/techniques/T1588-007.md) | Obtain Capabilities: Artificial Intelligence | Resource Development | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1589`](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | Star Blizzard | AA23-341A (2023-12-07) | [40] [87] [101] |
| [`T1589.001`](/mitre/techniques/T1589-001.md) | Gather Victim Identity Information: Credentials | Reconnaissance | APT28; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [80] [94] [101] |
| [`T1589.002`](/mitre/techniques/T1589-002.md) | Gather Victim Identity Information: Email Addresses | Reconnaissance | Sandworm Team | AA25-141A (2025-05) | [55] [82] [101] |
| [`T1589.003`](/mitre/techniques/T1589-003.md) | Gather Victim Identity Information: Employee Names | Reconnaissance | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1590`](/mitre/techniques/T1590.md) | Gather Victim Network Information | Reconnaissance | Not recorded for these groups or campaigns | AA23-347A (2023-12-12) | [42] |
| [`T1590.001`](/mitre/techniques/T1590-001.md) | Gather Victim Network Information: Domain Properties | Reconnaissance | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1590.002`](/mitre/techniques/T1590-002.md) | Gather Victim Network Information: DNS | Reconnaissance | Not recorded for these groups or campaigns | AA24-249A (2024-09-05) | [51] |
| [`T1590.004`](/mitre/techniques/T1590-004.md) | Gather Victim Network Information: Network Topology | Reconnaissance | Not recorded for these groups or campaigns | AA23-347A (2023-12-12) | [42] |
| [`T1591`](/mitre/techniques/T1591.md) | Gather Victim Org Information | Reconnaissance | APT28 | AA25-141A (2025-05) | [55] [80] [101] |
| [`T1591.002`](/mitre/techniques/T1591-002.md) | Gather Victim Org Information: Business Relationships | Reconnaissance | Sandworm Team; Dragonfly | AA25-141A (2025-05) | [55] [82] [84] [101] |
| [`T1591.004`](/mitre/techniques/T1591-004.md) | Gather Victim Org Information: Identify Roles | Reconnaissance | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1592`](/mitre/techniques/T1592.md) | Gather Victim Host Information | Reconnaissance | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1592.002`](/mitre/techniques/T1592-002.md) | Gather Victim Host Information: Software | Reconnaissance | Sandworm Team | AA23-347A (2023-12-12) | [42] [82] [101] |
| [`T1593`](/mitre/techniques/T1593.md) | Search Open Websites/Domains | Reconnaissance | Sandworm Team; Star Blizzard | AA23-341A (2023-12-07) | [40] [82] [87] [101] |
| [`T1594`](/mitre/techniques/T1594.md) | Search Victim-Owned Websites | Reconnaissance | Sandworm Team | Not named in the advisories opened | [82] [101] |
| [`T1595`](/mitre/techniques/T1595.md) | Active Scanning | Reconnaissance | C0030 Triton SIS Attack (2017-06 to 2017-08) | AA24-249A (2024-09-05) | [51] [94] |
| [`T1595.001`](/mitre/techniques/T1595-001.md) | Active Scanning: Scanning IP Blocks | Reconnaissance | Ember Bear | AA24-249A (2024-09-05) | [51] [86] [101] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Active Scanning: Vulnerability Scanning | Reconnaissance | APT28; APT29; Sandworm Team; Dragonfly; Ember Bear | AA22-011A (2022-01-11); AA24-249A (2024-09-05) | [26] [51] [80] [81] [82] [84] [86] [101] |
| [`T1596`](/mitre/techniques/T1596.md) | Search Open Technical Databases | Reconnaissance | APT28 | Not named in the advisories opened | [80] [101] |
| [`T1596.005`](/mitre/techniques/T1596-005.md) | Search Open Technical Databases: Scan Databases | Reconnaissance | Not recorded for these groups or campaigns | AA24-249A (2024-09-05) | [51] |
| [`T1598`](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | APT28 | AA22-011A (2022-01-11) | [26] [80] [101] |
| [`T1598.002`](/mitre/techniques/T1598-002.md) | Phishing for Information: Spearphishing Attachment | Reconnaissance | Dragonfly; Star Blizzard | Not named in the advisories opened | [84] [87] [101] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Phishing for Information: Spearphishing Link | Reconnaissance | APT28; Sandworm Team; Dragonfly; Star Blizzard | Not named in the advisories opened | [80] [82] [84] [87] [101] |
| [`T1606.001`](/mitre/techniques/T1606-001.md) | Forge Web Credentials: Web Cookies | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1606.002`](/mitre/techniques/T1606-002.md) | Forge Web Credentials: SAML Tokens | Credential Access | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1608`](/mitre/techniques/T1608.md) | Stage Capabilities | Resource Development | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Stage Capabilities: Upload Malware | Resource Development | Sandworm Team; Gamaredon Group; Star Blizzard | Not named in the advisories opened | [82] [85] [87] [101] |
| [`T1608.004`](/mitre/techniques/T1608-004.md) | Stage Capabilities: Drive-by Target | Resource Development | Dragonfly | Not named in the advisories opened | [84] [101] |
| [`T1610`](/mitre/techniques/T1610.md) | Deploy Container | Execution | Not recorded for these groups or campaigns | AA23-129A (2023-05-09) | [38] |
| [`T1615`](/mitre/techniques/T1615.md) | Group Policy Discovery | Discovery | Turla | Not named in the advisories opened | [83] [101] |
| [`T1620`](/mitre/techniques/T1620.md) | Reflective Code Loading | Stealth | Gamaredon Group | Not named in the advisories opened | [85] [101] |
| [`T1621`](/mitre/techniques/T1621.md) | Multi-Factor Authentication Request Generation | Credential Access | APT29 | AA24-057A (2024-02-26) | [45] [81] [101] |
| [`T1649`](/mitre/techniques/T1649.md) | Steal or Forge Authentication Certificates | Credential Access | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1651`](/mitre/techniques/T1651.md) | Cloud Administration Command | Execution | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1654`](/mitre/techniques/T1654.md) | Log Enumeration | Discovery | Ember Bear | AA24-249A (2024-09-05) | [51] [86] [101] |
| [`T1659`](/mitre/techniques/T1659.md) | Content Injection | Initial Access, Command and Control | Not recorded for these groups or campaigns | AA25-141A (2025-05) | [55] |
| [`T1665`](/mitre/techniques/T1665.md) | Hide Infrastructure | Command and Control | APT29; C0024 SolarWinds Compromise (2019-08 to 2021-01) | AA25-141A (2025-05) | [55] [81] [94] [101] |
| [`T1669`](/mitre/techniques/T1669.md) | Wi-Fi Networks | Initial Access | APT28; C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [80] [94] [97] [101] |
| [`T1680`](/mitre/techniques/T1680.md) | Local Storage Discovery | Discovery | C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [94] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Social Engineering: Impersonation | Stealth | APT28; Star Blizzard | Not named in the advisories opened | [80] [87] [101] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | Turla; Gamaredon Group; C0024 SolarWinds Compromise (2019-08 to 2021-01); C0028 2015 Ukraine Electric Power Attack (2015-12 to 2016-01) | AA23-347A (2023-12-12, stated as `T1562.001`) | [42] [83] [85] [94] [100] [101] |
| [`T1685.001`](/mitre/techniques/T1685-001.md) | Disable or Modify Tools: Disable or Modify Windows Event Log | Defense Impairment | C0024 SolarWinds Compromise (2019-08 to 2021-01); C0025 2016 Ukraine Electric Power Attack (2016-12) | Not named in the advisories opened | [94] |
| [`T1685.002`](/mitre/techniques/T1685-002.md) | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment | APT29 | Not named in the advisories opened | [81] [101] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Disable or Modify Tools: Clear Windows Event Logs | Defense Impairment | APT28; Dragonfly | AA25-141A (2025-05, stated as `T1070.001`) | [55] [80] [84] [100] [101] |
| [`T1686`](/mitre/techniques/T1686.md) | Disable or Modify System Firewall | Defense Impairment | Dragonfly; C0024 SolarWinds Compromise (2019-08 to 2021-01) | Not named in the advisories opened | [84] [94] [101] |
| [`T1686.003`](/mitre/techniques/T1686-003.md) | Disable or Modify System Firewall: Windows Host Firewall | Defense Impairment | C0051 APT28 Nearest Neighbor (2022-02 to 2024-11) | Not named in the advisories opened | [94] [97] |

### Enterprise techniques inferred by this study

These are this study's mappings from a dated narrative to a technique. They are **Inferred**, carry the lowest score in the Navigator layer, and should not be quoted as ATT&CK or advisory mappings.

| ID | Technique | Tactic (v20) | Narrative it rests on (source, date) | Sources |
|---|---|---|---|---|
| [`T1602.002`](/mitre/techniques/T1602-002.md) | Data from Configuration Repository: Network Device Configuration Dump | Collection | FSB Center 16 collected configuration files from thousands of US networking devices (FBI PSA, 2025-08-20) and copied router configurations worldwide (AA26-194A, 2026-07-13) | [56] [62] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | Credential Access, Collection | Secret Blizzard used an ISP-level adversary-in-the-middle position against embassies in Moscow (Microsoft, 2025-07-31); APT28 hijacked DHCP and DNS on SOHO routers for adversary-in-the-middle attacks on Outlook Web Access (FBI PSA, 2026-04-07) | [77] [59] |

### ATT&CK for ICS

ATT&CK records ICS techniques for three of the groups at group level (**Confirmed** [95] [100]). The ICS techniques of the Ukraine grid campaigns (C0028, C0025, C0034) are bound in `case-studies/SANDWORM_OPERATIONS.md`, and the Triton campaign's are on the generated campaign pages [`C0030`](/mitre/campaigns/C0030.md) and [`C0032`](/mitre/campaigns/C0032.md). The library has no generated ICS technique pages, so IDs link to attack.mitre.org; the [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md) groups them by tactic.

| ID | Technique | Tactic | Recorded for | Sources |
|---|---|---|---|---|
| [`T0819`](https://attack.mitre.org/techniques/T0819/) | Exploit Public-Facing Application | Initial Access | Sandworm Team | [82] [100] |
| [`T0884`](https://attack.mitre.org/techniques/T0884/) | Connection Proxy | Command and Control | Sandworm Team | [82] [100] |
| [`T1701.001`](https://attack.mitre.org/techniques/T1701/001/) | Command and Scripting Interpreter: PowerShell | Execution | Sandworm Team | [82] [100] |
| [`T1701.002`](https://attack.mitre.org/techniques/T1701/002/) | Command and Scripting Interpreter: Windows Command Shell | Execution | Sandworm Team | [82] [100] |
| [`T0817`](https://attack.mitre.org/techniques/T0817/) | Drive-by Compromise | Initial Access | Dragonfly; TEMP.Veles | [84] [100] |
| [`T0862`](https://attack.mitre.org/techniques/T0862/) | Supply Chain Compromise | Initial Access | Dragonfly; TEMP.Veles | [84] [100] |
| [`T0840`](https://attack.mitre.org/techniques/T0840/) | Network Connection Enumeration | Discovery | Stated in the AA23-129A table for Snake (2023-05-09); no group record | [38] [100] |

ALLANITE's four ICS techniques (`T0817`, `T0852`, `T0859`, `T0865`) are in the library's ICS data, but the group has no generated page and no government attribution was opened for it, so it is listed here only for completeness (**Reported** [95]).

### Mobile

| ID | Technique | Tactic | Recorded for or stated by | Sources |
|---|---|---|---|---|
| [`T1409`](https://attack.mitre.org/techniques/T1409/) | Stored Application Data | Collection | Sandworm Team | [82] [100] |
| [`T1660`](https://attack.mitre.org/techniques/T1660/) | Phishing | Initial Access | Sandworm Team | [82] [100] |
| [`T1676`](https://attack.mitre.org/techniques/T1676/) | Linked Devices | Collection, Persistence | Sandworm Team; Star Blizzard | [82] [87] [100] |
| [`T1627`](https://attack.mitre.org/techniques/T1627/) | Execution Guardrails | Defense Evasion (Mobile) | Stated in AA25-141A (2025-05) | [55] [100] |
| [`T1627.001`](https://attack.mitre.org/techniques/T1627/001/) | Execution Guardrails: Geofencing | Defense Evasion (Mobile) | Stated in AA25-141A (2025-05) | [55] [100] |

The Mobile domain still uses the Defense Evasion tactic name in v20.0 (**Confirmed** [100]).

### Groups, campaigns and software

| Object | ID | Relationship in ATT&CK v20.0 and the record | Sources |
|---|---|---|---|
| APT28 | [`G0007`](/mitre/groups/G0007.md) | GRU Unit 26165; 93 techniques; campaign C0051 | [80] |
| Sandworm Team | [`G0034`](/mitre/groups/G0034.md) | GRU Unit 74455; 79 Enterprise, 4 ICS, 3 Mobile techniques; campaigns C0028, C0025, C0034 | [82] |
| Ember Bear | [`G1003`](/mitre/groups/G1003.md) | GRU Unit 29155; 47 techniques | [86] |
| APT29 | [`G0016`](/mitre/groups/G0016.md) | SVR; 66 techniques; campaigns C0023, C0024 | [81] |
| Turla | [`G0010`](/mitre/groups/G0010.md) | FSB; 68 techniques; no campaigns | [83] |
| Dragonfly | [`G0035`](/mitre/groups/G0035.md) | FSB Center 16; 56 Enterprise, 2 ICS techniques | [84] |
| Star Blizzard | [`G1033`](/mitre/groups/G1033.md) | Russia (governments: FSB Centre 18); 20 Enterprise, 1 Mobile technique | [87] [40] |
| Gamaredon Group | [`G0047`](/mitre/groups/G0047.md) | Suspected Russian (Ukraine: FSB Center 18); 70 techniques | [85] |
| TEMP.Veles | [`G0088`](/mitre/groups/G0088.md) | Russia-based (AA22-110A: TsNIIKhM); 2 ICS techniques; campaigns C0030, C0032 | [94] [30] |
| Saint Bear | [`G1031`](/mitre/groups/G1031.md) | Russian-nexus; distinct from Ember Bear | [88] |
| Winter Vivern | [`G1035`](/mitre/groups/G1035.md) | No explicit state attribution | [89] |
| Wizard Spider | [`G0102`](/mitre/groups/G0102.md) | Russia-based criminal | [93] |
| Indrik Spider | [`G0119`](/mitre/groups/G0119.md) | Russia-based criminal (Evil Corp) | [93] |
| ALLANITE | `G1000` | ATT&CK for ICS only; no library page | [95] |
| Operation Ghost | [`C0023`](/mitre/campaigns/C0023.md) | APT29, 2013-09 to 2019-10 | [94] |
| SolarWinds Compromise | [`C0024`](/mitre/campaigns/C0024.md) | APT29, 2019-08 to 2021-01; home study SOLARWINDS_SUNBURST.md | [94] |
| 2015 Ukraine Electric Power Attack | [`C0028`](/mitre/campaigns/C0028.md) | Sandworm Team, 2015-12 to 2016-01 | [94] |
| 2016 Ukraine Electric Power Attack | [`C0025`](/mitre/campaigns/C0025.md) | Sandworm Team, 2016-12 | [94] |
| 2022 Ukraine Electric Power Attack | [`C0034`](/mitre/campaigns/C0034.md) | Sandworm Team, 2022-06 to 2022-10 | [94] |
| APT28 Nearest Neighbor Campaign | [`C0051`](/mitre/campaigns/C0051.md) | APT28, 2022-02 to 2024-11 | [97] |
| C0032 | [`C0032`](/mitre/campaigns/C0032.md) | TEMP.Veles, 2014-10 to 2017-01; the Triton IT foothold before the safety-system attack | [94] |
| Triton Safety Instrumented System Attack | [`C0030`](/mitre/campaigns/C0030.md) | TEMP.Veles, 2017-06 to 2017-08 | [94] |
| 2025 Poland Wiper Attacks | [`C0063`](/mitre/campaigns/C0063.md) | No group associated; ATT&CK cites FSB Dragonfly and GRU Sandworm assessments; 53 techniques in the library data | [90] [98] [94] |

| Software | ID | Used by (library data and the record) | Sources |
|---|---|---|---|
| CHOPSTICK | [`S0023`](/mitre/software/S0023.md) | APT28 | [93] |
| Zebrocy | [`S0251`](/mitre/software/S0251.md) | APT28 | [93] |
| LoJax | [`S0397`](/mitre/software/S0397.md) | APT28 | [93] |
| Drovorub | [`S0502`](/mitre/software/S0502.md) | APT28 | [93] |
| LAMEHUG | [`S9035`](/mitre/software/S9035.md) | APT28 | [93] [80] |
| BlackEnergy | [`S0089`](/mitre/software/S0089.md) | Sandworm Team | [93] |
| Industroyer, Industroyer2 | [`S0604`](/mitre/software/S0604.md), [`S1072`](/mitre/software/S1072.md) | Sandworm Team | [93] |
| NotPetya | [`S0368`](/mitre/software/S0368.md) | Sandworm Team | [93] |
| Olympic Destroyer | [`S0365`](/mitre/software/S0365.md) | Sandworm Team | [93] |
| VPNFilter, Cyclops Blink | [`S1010`](/mitre/software/S1010.md), [`S0687`](/mitre/software/S0687.md) | Sandworm Team | [93] |
| AcidRain, AcidPour | [`S1125`](/mitre/software/S1125.md), [`S1167`](/mitre/software/S1167.md) | Sandworm Team | [93] |
| Prestige, Kapeka, CaddyWiper | [`S1058`](/mitre/software/S1058.md), [`S1190`](/mitre/software/S1190.md), [`S0693`](/mitre/software/S0693.md) | Sandworm Team (CaddyWiper on the live page only) | [93] [82] |
| WhisperGate | [`S0689`](/mitre/software/S0689.md) | Ember Bear; not unique to Unit 29155 per AA24-249A | [86] [51] |
| SUNBURST, SUNSPOT, TEARDROP | [`S0559`](/mitre/software/S0559.md), [`S0562`](/mitre/software/S0562.md), [`S0560`](/mitre/software/S0560.md) | APT29 (SolarWinds) | [93] |
| GoldMax, FoggyWeb | [`S0588`](/mitre/software/S0588.md), [`S0661`](/mitre/software/S0661.md) | APT29 | [93] |
| WellMess, WellMail | [`S0514`](/mitre/software/S0514.md), [`S0515`](/mitre/software/S0515.md) | APT29 (vaccine campaign, 2020) | [12] [93] |
| Uroburos, Carbon, Kazuar, ComRAT, LightNeuron, TinyTurla | [`S0022`](/mitre/software/S0022.md), [`S0335`](/mitre/software/S0335.md), [`S0265`](/mitre/software/S0265.md), [`S0126`](/mitre/software/S0126.md), [`S0395`](/mitre/software/S0395.md), [`S0668`](/mitre/software/S0668.md) | Turla | [93] |
| Spica | [`S1140`](/mitre/software/S1140.md) | Star Blizzard | [87] |
| Saint Bot, OutSteel | [`S1018`](/mitre/software/S1018.md), [`S1017`](/mitre/software/S1017.md) | Saint Bear | [88] |
| DynoWiper, LazyWiper | [`S9038`](/mitre/software/S9038.md), [`S9039`](/mitre/software/S9039.md) | Campaign C0063 | [98] |
| Mimikatz, PsExec | [`S0002`](/mitre/software/S0002.md), [`S0029`](/mitre/software/S0029.md) | Six of the groups each | [93] |
| Net, Impacket, reGeorg, Reg | [`S0039`](/mitre/software/S0039.md), [`S0357`](/mitre/software/S0357.md), [`S1187`](/mitre/software/S1187.md), [`S0075`](/mitre/software/S0075.md) | Five, four, three and three groups | [93] |
| TrickBot, Conti, Ryuk | [`S0266`](/mitre/software/S0266.md), [`S0575`](/mitre/software/S0575.md), [`S0446`](/mitre/software/S0446.md) | Wizard Spider | [93] |
| Dridex, BitPaymer, WastedLocker | [`S0384`](/mitre/software/S0384.md), [`S0570`](/mitre/software/S0570.md), [`S0612`](/mitre/software/S0612.md) | Indrik Spider | [93] |
| Emotet, Black Basta | [`S0367`](/mitre/software/S0367.md), [`S1070`](/mitre/software/S1070.md) | Criminal ecosystem named in AA22-110A and AA24-131A | [30] [49] |

The shared layer of tooling is commodity and living-off-the-land software (Mimikatz, PsExec, Net, Impacket); the bespoke implants are group-specific (**Inferred** from [93]). Triton (`S1009`) is an ICS-domain software object without a library page (**Confirmed** [100]).

### CWE and CAPEC

CWE IDs come from the `cwes` field of the KEV feed for each exploited CVE (Part 5). CAPEC IDs come from the library's own data: `data/weaknesses/cwe.jsonl` for weakness-to-pattern links, and the `capec` field of `data/attack/technique_profiles.jsonl` for technique-to-pattern links (**Confirmed** [92] [105] [100]). The broad classes CWE-20, CWE-74, CWE-119 and CWE-284 are not expanded, because their pattern lists say nothing specific about these flaws. See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

| Weakness | CVEs in this record | CAPEC patterns linked in the library data |
|---|---|---|
| CWE-22 Path Traversal | CVE-2018-13379, CVE-2019-11510, CVE-2019-19781, CVE-2020-5902 | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal; [CAPEC-64](/mitre/capec/CAPEC-64.md); [CAPEC-76](/mitre/capec/CAPEC-76.md); [CAPEC-78](/mitre/capec/CAPEC-78.md); [CAPEC-79](/mitre/capec/CAPEC-79.md) |
| CWE-78 OS Command Injection | CVE-2019-10149, CVE-2020-4006, CVE-2020-12641 | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection; [CAPEC-6](/mitre/capec/CAPEC-6.md); [CAPEC-15](/mitre/capec/CAPEC-15.md); [CAPEC-43](/mitre/capec/CAPEC-43.md); [CAPEC-108](/mitre/capec/CAPEC-108.md) |
| CWE-79 Cross-site Scripting | CVE-2020-35730 | [CAPEC-63](/mitre/capec/CAPEC-63.md); [CAPEC-85](/mitre/capec/CAPEC-85.md); [CAPEC-209](/mitre/capec/CAPEC-209.md); [CAPEC-588](/mitre/capec/CAPEC-588.md); [CAPEC-591](/mitre/capec/CAPEC-591.md); [CAPEC-592](/mitre/capec/CAPEC-592.md) |
| CWE-89 SQL Injection | CVE-2021-44026 | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection; [CAPEC-7](/mitre/capec/CAPEC-7.md); [CAPEC-108](/mitre/capec/CAPEC-108.md); [CAPEC-109](/mitre/capec/CAPEC-109.md); [CAPEC-110](/mitre/capec/CAPEC-110.md); [CAPEC-470](/mitre/capec/CAPEC-470.md) |
| CWE-94 Code Injection | CVE-2019-7609, CVE-2022-3236 | [CAPEC-242](/mitre/capec/CAPEC-242.md) Code Injection; [CAPEC-35](/mitre/capec/CAPEC-35.md); [CAPEC-77](/mitre/capec/CAPEC-77.md) |
| CWE-611 XML External Entity | CVE-2019-9670 | [CAPEC-221](/mitre/capec/CAPEC-221.md) |
| CWE-287 Improper Authentication | CVE-2020-0688, CVE-2021-33044, CVE-2021-33045 | [CAPEC-114](/mitre/capec/CAPEC-114.md) Authentication Abuse; [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass; [CAPEC-151](/mitre/capec/CAPEC-151.md); [CAPEC-194](/mitre/capec/CAPEC-194.md); [CAPEC-22](/mitre/capec/CAPEC-22.md); [CAPEC-57](/mitre/capec/CAPEC-57.md); [CAPEC-593](/mitre/capec/CAPEC-593.md); [CAPEC-633](/mitre/capec/CAPEC-633.md); [CAPEC-650](/mitre/capec/CAPEC-650.md); [CAPEC-94](/mitre/capec/CAPEC-94.md) |
| CWE-288 Authentication Bypass Using an Alternate Path | CVE-2023-42793 | [CAPEC-127](/mitre/capec/CAPEC-127.md); [CAPEC-665](/mitre/capec/CAPEC-665.md) |
| CWE-294 Authentication Bypass by Capture-replay | CVE-2023-23397 | [CAPEC-102](/mitre/capec/CAPEC-102.md); [CAPEC-509](/mitre/capec/CAPEC-509.md); [CAPEC-555](/mitre/capec/CAPEC-555.md); [CAPEC-561](/mitre/capec/CAPEC-561.md); [CAPEC-60](/mitre/capec/CAPEC-60.md); [CAPEC-644](/mitre/capec/CAPEC-644.md) Pass the Hash; [CAPEC-645](/mitre/capec/CAPEC-645.md); [CAPEC-652](/mitre/capec/CAPEC-652.md); [CAPEC-701](/mitre/capec/CAPEC-701.md); [CAPEC-94](/mitre/capec/CAPEC-94.md) |
| CWE-290 Authentication Bypass by Spoofing | CVE-2023-50224 | [CAPEC-21](/mitre/capec/CAPEC-21.md); [CAPEC-22](/mitre/capec/CAPEC-22.md); [CAPEC-459](/mitre/capec/CAPEC-459.md); [CAPEC-461](/mitre/capec/CAPEC-461.md); [CAPEC-473](/mitre/capec/CAPEC-473.md); [CAPEC-476](/mitre/capec/CAPEC-476.md); [CAPEC-59](/mitre/capec/CAPEC-59.md); [CAPEC-60](/mitre/capec/CAPEC-60.md); [CAPEC-667](/mitre/capec/CAPEC-667.md); [CAPEC-94](/mitre/capec/CAPEC-94.md) |
| CWE-798 Hard-coded Credentials | CVE-2022-26138 | [CAPEC-191](/mitre/capec/CAPEC-191.md); [CAPEC-70](/mitre/capec/CAPEC-70.md) |
| CWE-918 Server-Side Request Forgery | CVE-2021-26855 | [CAPEC-664](/mitre/capec/CAPEC-664.md) |
| CWE-330 Insufficiently Random Values | CVE-2020-1472 | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force; [CAPEC-485](/mitre/capec/CAPEC-485.md); [CAPEC-59](/mitre/capec/CAPEC-59.md) |
| CWE-352 Cross-Site Request Forgery | CVE-2008-4128 | [CAPEC-62](/mitre/capec/CAPEC-62.md) Cross Site Request Forgery; [CAPEC-111](/mitre/capec/CAPEC-111.md); [CAPEC-462](/mitre/capec/CAPEC-462.md); [CAPEC-467](/mitre/capec/CAPEC-467.md) |
| CWE-917 Expression Language Injection; CWE-351 Insufficient Type Distinction | CVE-2022-26134; CVE-2023-38831 | None in the library data |

| Technique (use in this record) | CAPEC patterns linked in the library data |
|---|---|
| `T1110` Brute Force; `T1110.003` Password Spraying (SVR, GRU) | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force; [CAPEC-565](/mitre/capec/CAPEC-565.md) Password Spraying |
| `T1078` Valid Accounts | [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials |
| `T1133` External Remote Services; `T1114.002` Remote Email Collection | [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials |
| `T1566.001`, `T1566.002` Spearphishing (APT28, Star Blizzard) | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing |
| `T1539` Steal Web Session Cookie; `T1528` Steal Application Access Token | [CAPEC-21](/mitre/capec/CAPEC-21.md); [CAPEC-31](/mitre/capec/CAPEC-31.md) (cookie only) |
| `T1550.004` Web Session Cookie (Star Blizzard) | [CAPEC-60](/mitre/capec/CAPEC-60.md) Reusing Session IDs |
| `T1550.002` Pass the Hash (Unit 29155) | [CAPEC-644](/mitre/capec/CAPEC-644.md) Use of Captured Hashes |
| `T1505.003` Web Shell | [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server |
| `T1014` Rootkit (Snake) | [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit |
| `T1195.002` Compromise Software Supply Chain (SolarWinds) | [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update; [CAPEC-442](/mitre/capec/CAPEC-442.md); [CAPEC-443](/mitre/capec/CAPEC-443.md); [CAPEC-523](/mitre/capec/CAPEC-523.md); [CAPEC-669](/mitre/capec/CAPEC-669.md); [CAPEC-673](/mitre/capec/CAPEC-673.md); [CAPEC-678](/mitre/capec/CAPEC-678.md); [CAPEC-691](/mitre/capec/CAPEC-691.md) |
| `T1557` Adversary-in-the-Middle (Inferred) | [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle |
| `T1602` Data from Configuration Repository, parent of the inferred `T1602.002` | [CAPEC-150](/mitre/capec/CAPEC-150.md) Collect Data from Common Resource Locations |

### D3FEND countermeasures

D3FEND countermeasures below come from the library's `data/attack/technique_to_d3fend.jsonl`, and each links to its library page; the table lists the countermeasures that match the advisories' own recommendations, not every row the library holds (**Confirmed** [102]). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

| Behavior in the record | Techniques | D3FEND countermeasures in the library data |
|---|---|---|
| Password spraying and credential theft (SVR, GRU) | `T1110.003` | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (`D3-MFA`), [Credential Hardening](/mitre/d3fend/credential-hardening.md) (`D3-CH`), [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (`D3-SPP`), [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (`D3-CAA`), [Decoy User Credential](/mitre/d3fend/decoy-user-credential.md) (`D3-DUC`), [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) (`D3-UGLPA`) |
| Valid and dormant accounts, cloud accounts | `T1078`, `T1078.004` | [Account Locking](/mitre/d3fend/account-locking.md) (`D3-AL`), [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (`D3-UAP`) |
| Session-cookie and token theft (Star Blizzard, SVR) | `T1539`, `T1550.004`, `T1528` | [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md) (`D3-ANCI`), [Credential Revocation](/mitre/d3fend/credential-revocation.md) (`D3-CR`), [Credential Rotation](/mitre/d3fend/credential-rotation.md) (`D3-CRO`), [Token Binding](/mitre/d3fend/token-binding.md) (`D3-TB`, `T1528` only) |
| Mail forwarding rules (Star Blizzard) | `T1114.003` | [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) (`D3-ACH`), [Configuration Inventory](/mitre/d3fend/configuration-inventory.md) (`D3-CI`), [Disable Remote Access](/mitre/d3fend/disable-remote-access.md) (`D3-DRA`) |
| Exploiting internet-facing applications | `T1190` | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (`D3-ITF`), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (`D3-NTF`), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (`D3-NTSA`), [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md) (`D3-APCA`) |
| Spearphishing | `T1566.001`, `T1566.002` | [Email Filtering](/mitre/d3fend/email-filtering.md) (`D3-EF`), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (`D3-DA`), [Content Quarantine](/mitre/d3fend/content-quarantine.md) (`D3-CQ`), [Homoglyph Detection](/mitre/d3fend/homoglyph-detection.md) (`D3-HD`), [URL Analysis](/mitre/d3fend/url-analysis.md) (`D3-UA`, links only) |
| Forced NTLM authentication (CVE-2023-23397) | `T1187` | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (`D3-FIM`); the advisory's own control, blocking outbound SMB and NTLM, matches [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`), which the library does not map to `T1187` (**Inferred**) |
| Proxy networks and tunnels (EdgeRouters, SOHO routers, Snake) | `T1090.003`, `T1572` | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (`D3-OTF`), [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md) (`D3-RPA`), [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) (`D3-PMAD`) |
| Web shells (Unit 29155) | `T1505.003` | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (`D3-FIM`), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (`D3-EAL`), [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`), [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md) (`D3-PLA`) |
| LSASS credential dumping | `T1003.001` | [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (`D3-PSA`), [System Call Filtering](/mitre/d3fend/system-call-filtering.md) (`D3-SCF`) |
| Kernel rootkit (Snake) | `T1014` | [Firmware Verification](/mitre/d3fend/firmware-verification.md) (`D3-FV`), [Software Inventory](/mitre/d3fend/software-inventory.md) (`D3-SWI`), [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`) |
| Software supply chain | `T1195.002` | [Software Update](/mitre/d3fend/software-update.md) (`D3-SU`), [Software Inventory](/mitre/d3fend/software-inventory.md) (`D3-SWI`), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (`D3-AVE`) |
| Disk wipers (WhisperGate, NotPetya) | `T1561.002` | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (`D3-DKP`) |
| External remote services | `T1133` | [Session Termination](/mitre/d3fend/session-termination.md) (`D3-ST`), the only row in the library data |
| No countermeasure in the library data | `T1059.001`, `T1588.002`, `T1595.002`, `T1098.005`, `T1110`, `T1485`, `T1550.002`, `T1606.002`, `T1685.005` | See Part 7 |

Some library rows pair a technique with countermeasures that do not fit it closely (for example, `T1621` MFA Request Generation maps to process-isolation countermeasures), so the table above picks the rows that match an advisory's recommendation (**Inferred** from [102]).

### Navigator layer

The study's techniques are collected in an ATT&CK Navigator layer, [`navigator/library-layers/threat-actors-russia.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-russia.json), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/threat-actors-russia.json). It holds the 330 techniques of the Enterprise table and the two inferred techniques, each shown under all its v20 tactics. Scores mean evidence basis, not frequency or severity: 100 for techniques named in a joint government advisory, 60 for techniques ATT&CK records for one of the nine groups or eight campaigns but no verified advisory names, and 30 for this study's inferences. Each technique's comment names the study's source numbers. Campaign C0063 is left out because ATT&CK associates it with no group.

### Notices

ATT&CK content in this study: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE. CAPEC, CWE and D3FEND material is used under their terms as recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

## Cross-cutting themes

- **Attribution is a ladder, and this record reaches its top rungs.** Governments name units, grand juries name officers and sanctions name organisations. Even so, the rungs differ: a grand jury's allegation, a government's "almost certainly", a vendor's "medium confidence", ATT&CK's "suspected". Carry the rung with the name. See the [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md).
- **Services compete and overlap.** Three GRU units, two FSB centers and the SVR run parallel programs, sometimes against the same targets, and the Poland 2025 attack shows experienced analysts assigning one event to two services. Merging indicators across those names without checking the source's boundary produces false confidence (**Inferred** from [79] [58] [61] [51]).
- **The edge is the battlefield.** Routers, VPNs, mail servers, cameras and CI servers appear in nearly every advisory from 2018 to 2026, and the network-device campaigns of the GRU and the FSB run in parallel (**Inferred** from Part 5).
- **Identity is the SVR's main door.** The SVR's recent record at Microsoft, HPE and in AA24-057A is password spraying, dormant accounts, tokens, OAuth applications and device registration, alongside opportunistic exploitation such as TeamCity (**Confirmed** [68] [43] [45] [42]). See the [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md).
- **Fronts and criminals blur the line.** Unit 74455 likely supported a hacktivist front; Treasury links Trickbot members to the intelligence services; KillNet's ties are unconfirmed. For a hospital, the distinction between a state unit and a state-tolerated crew matters less than the controls that stop both (**Confirmed** [57] [34] [33]; the conclusion is **Inferred**). See the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
- **Legal action has not stopped the tempo.** Six rounds of US indictments since 2018, multiple sanctions packages, two domain seizures and a router-network takedown sit in the record alongside continuing operations into 2026 (**Inferred** from the timeline).
- **The library's own data has edges worth knowing.** The library lacks a generated page for ALLANITE and for the ICS software Triton; its copy of the APT28 and Sandworm software lists differs slightly from the live pages; and its D3FEND mapping leaves several common techniques without a countermeasure. Readers comparing tools against this layer should know which counts they are using (**Confirmed** [80] [82] [96] [102]).

### What is overstated and what is understated

- **Overstated: Russian state units as the attackers of hospitals.** None of the government documents opened for this study attributes a disruptive attack on a hospital to a Russian state unit. The state record on healthcare is espionage, collateral damage and sector lists; the attacks that disrupted care came from criminal ransomware crews and pro-Russia hacktivists (**Inferred** from [12] [32] [51] [62] [33] [34]; see "What the record does not show" in Part 6).
- **Overstated: vendor names as units.** AA24-249A warns that vendor names may not map one-to-one to its own attribution, and the FBI calls Berserk Bear and Dragonfly separate but related clusters (**Confirmed** [51] [56]). A vendor name marks a cluster of activity, not a unit (**Inferred**).
- **Overstated: KillNet's own claims.** HC3 says KillNet's ties to the FSB or SVR are unconfirmed and advises treating its claims "with a grain of salt" (**Confirmed** [33]). The January 2023 DDoS wave on hospitals is in the record; a claimed compromise is a lead to check, not an incident (**Inferred** from [33] [35]).
- **Understated: patch debt on old KEV entries.** CVE-2018-0171 has been in KEV since 3 November 2021, and the FBI reported FSB Center 16 exploiting it in August 2025 (**Confirmed** [92] [56]). Attention goes to new flaws, while this record runs on old, known ones (**Inferred**).
- **Understated: end-of-life network devices.** TA18-106A warned in 2018 about Smart Install, SNMP and GRE on routers; the FBI's 2025 notice reports Smart Install and SNMP exploitation on end-of-life devices, and AA26-194A asked for router hygiene again in 2026 (**Confirmed** [6] [56] [62]). Devices that no longer receive firmware fall outside a CVE-driven patch program (**Inferred**).
- **Understated: identity conditions over CVEs.** The SVR's access paths in AA24-057A are password spraying, dormant accounts, tokens and device registration, and Midnight Blizzard entered Microsoft through a legacy test tenant account (**Confirmed** [45] [69]). None of those conditions has a CVE, so a CVE-only backlog does not show them (**Inferred**).

## Sources

Every source below was opened on 3 November 2026. Grades apply to the source type: Confirmed for a primary (the publisher of the fact), Reported for a secondary account or a summary of a document that was not itself opened.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | WADA, WADA Confirms Attack by Russian Cyber Espionage Group (2016-09-13) | https://www.wada-ama.org/en/news/wada-confirms-attack-russian-cyber-espionage-group | 2026-11-03 | Confirmed |
| 2 | DHS and FBI, Joint Analysis Report JAR-16-20296A, GRIZZLY STEPPE: Russian Malicious Cyber Activity (2016-12-29) | https://www.cisa.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf | 2026-11-03 | Confirmed |
| 3 | The White House (archived), Statement from the Press Secretary on NotPetya (2018-02-15) | https://trumpwhitehouse.archives.gov/briefings-statements/statement-press-secretary-25/ | 2026-11-03 | Confirmed |
| 4 | GOV.UK, Foreign Office Minister condemns Russia for NotPetya attacks (2018-02-15) | https://www.gov.uk/government/news/foreign-office-minister-condemns-russia-for-notpetya-attacks | 2026-11-03 | Confirmed |
| 5 | DHS and FBI, Alert TA18-074A, Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors (2018-03-15) | https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors | 2026-11-03 | Confirmed |
| 6 | DHS, FBI and NCSC, Alert TA18-106A, Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices (2018-04-16, updated 2018-04-19) | https://www.cisa.gov/news-events/alerts/2018/04/16/russian-state-sponsored-cyber-actors-targeting-network-infrastructure-devices | 2026-11-03 | Confirmed |
| 7 | FBI, Russian Interference in 2016 U.S. Elections (wanted notice for the 2018-07-13 indictment) | https://www.fbi.gov/wanted/cyber/russian-interference-in-2016-u-s-elections | 2026-11-03 | Confirmed |
| 8 | FBI, wanted notice for Aleksey Viktorovich Lukashev | https://www.fbi.gov/wanted/cyber/aleksey-viktorovich-lukashev | 2026-11-03 | Confirmed |
| 9 | FBI, GRU Hacking to Undermine Anti-Doping Efforts (wanted notice for the 2018-10-03 indictment) | https://www.fbi.gov/wanted/cyber/gru-hacking-to-undermine-anti-doping-efforts | 2026-11-03 | Confirmed |
| 10 | US Department of State (archived), The United States Condemns Russian Cyber Attack Against the Country of Georgia (2020-02-20) | https://2017-2021.state.gov/the-united-states-condemns-russian-cyber-attack-against-the-country-of-georgia/index.html | 2026-11-03 | Confirmed |
| 11 | GOV.UK, UK condemns Russia's GRU over Georgia cyber-attacks (2020-02-20) | https://www.gov.uk/government/news/uk-condemns-russias-gru-over-georgia-cyber-attacks | 2026-11-03 | Confirmed |
| 12 | NCSC and CSE, with NSA and CISA, Advisory: APT29 targets COVID-19 vaccine development, v1.1 (2020-07-16), PDF; also served at https://www.ncsc.gov.uk/files/Advisory-APT29-targets-COVID-19-vaccine-development-V1-1.pdf | https://www.ncsc.gov.uk/sites/default/files/documents/Advisory-APT29-targets-COVID-19-vaccine-development-V1-1.pdf | 2026-11-03 | Confirmed |
| 13 | NCSC, Advisory: APT29 targets COVID-19 vaccine development (news page, 2020-07-16) | https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development | 2026-11-03 | Confirmed |
| 14 | FBI, GRU Hackers' Destructive Malware and International Cyber Attacks (wanted notice for the 2020-10-15 indictment) | https://www.fbi.gov/wanted/cyber/gru-hackers-destructive-malware-and-international-cyber-attacks | 2026-11-03 | Confirmed |
| 15 | GOV.UK, UK exposes series of Russian cyber attacks against Olympic and Paralympic Games (2020-10-19) | https://www.gov.uk/government/news/uk-exposes-series-of-russian-cyber-attacks-against-olympic-and-paralympic-games | 2026-11-03 | Confirmed |
| 16 | FBI and CISA, AA20-296A, Russian State-Sponsored Advanced Persistent Threat Actor Compromises U.S. Government Targets (2020-10-22) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-296a | 2026-11-03 | Confirmed |
| 17 | US Treasury, press release sm1162, designation of TsNIIKhM (2020-10-23) | https://home.treasury.gov/news/press-releases/sm1162 | 2026-11-03 | Confirmed |
| 18 | CISA, FBI and HHS, AA20-302A, Ransomware Activity Targeting the Healthcare and Public Health Sector (2020-10-28) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a | 2026-11-03 | Confirmed |
| 19 | The White House (archived), Fact Sheet: Imposing Costs for Harmful Foreign Activities by the Russian Government (2021-04-15) | https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/ | 2026-11-03 | Confirmed |
| 20 | US Treasury, press release jy0127, sanctions on Russian technology companies (2021-04-15) | https://home.treasury.gov/news/press-releases/jy0127 | 2026-11-03 | Confirmed |
| 21 | GOV.UK, Russia: UK exposes Russian involvement in SolarWinds cyber compromise (2021-04-15) | https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise | 2026-11-03 | Confirmed |
| 22 | FBI, DHS and CISA, AA21-116A, Russian SVR Targets U.S. and Allied Networks (2021-04-26) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a | 2026-11-03 | Confirmed |
| 23 | FBI FLASH CP-000147-MW, Conti Ransomware Attacks Impact Healthcare and First Responder Networks (2021-05-20) | https://www.ic3.gov/Media/News/2021/210521.pdf | 2026-11-03 | Confirmed |
| 24 | CISA bulletin announcing the NSA, CISA, FBI and NCSC advisory on a GRU 85th GTsSS brute-force campaign (2021-07-01) | https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2e66dc2 | 2026-11-03 | Confirmed |
| 25 | HSE and PwC, Conti cyber attack on the HSE: Independent Post Incident Review (2021-12-03) | https://about.hse.ie/api/v2/download-file/file_based_publications/conti_cyber_attack_on_the_hse_full_report.pdf | 2026-11-03 | Confirmed |
| 26 | CISA, FBI and NSA, AA22-011A, Understanding and Mitigating Russian State-Sponsored Cyber Threats to U.S. Critical Infrastructure (2022-01-11) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a | 2026-11-03 | Confirmed |
| 27 | GOV.UK, UK assess Russian involvement in cyber attacks on Ukraine (2022-02-18) | https://www.gov.uk/government/news/uk-assess-russian-involvement-in-cyber-attacks-on-ukraine | 2026-11-03 | Confirmed |
| 28 | GOV.UK, UK exposes Russian spy agency behind cyber incidents (2022-03-24) | https://www.gov.uk/government/news/uk-exposes-russian-spy-agency-behind-cyber-incidents | 2026-11-03 | Confirmed |
| 29 | FBI, wanted notice for Evgeny Viktorovich Gladkikh (case announced 2022-03-24) | https://www.fbi.gov/wanted/cyber/evgeny-viktorovich-gladkikh | 2026-11-03 | Confirmed |
| 30 | CISA and Five Eyes partners, AA22-110A, Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure (2022-04-20, revised 2022-05-09) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a | 2026-11-03 | Confirmed |
| 31 | GOV.UK, Russia behind cyber-attack with Europe-wide impact an hour before Ukraine invasion (2022-05-10) | https://www.gov.uk/government/news/russia-behind-cyber-attack-with-europe-wide-impact-an-hour-before-ukraine-invasion | 2026-11-03 | Confirmed |
| 32 | HHS HC3, Major Cyber Organizations of the Russian Intelligence Services (2022-05-19), AHA copy | https://www.aha.org/system/files/media/file/2022/06/Major-Cyber-Organizations-of-Russian-Intelligence-Services.pdf | 2026-11-03 | Confirmed |
| 33 | HHS HC3, Analyst Note: Pro-Russian Hacktivist Group KillNet Threat to HPH Sector (2023-01-30), AHA copy | https://www.aha.org/system/files/media/file/2023/01/hc3-tlp-clear-analyst-note-pro-russian-hacktivist-group-killnet-threat-to-hph-sector-1-30-23.pdf | 2026-11-03 | Confirmed |
| 34 | US Treasury, press release jy1256, Trickbot sanctions (2023-02-09) | https://home.treasury.gov/news/press-releases/jy1256 | 2026-11-03 | Confirmed |
| 35 | HHS HC3, Analyst Note: KillNet's Targeting of the HPH Sector, December 2022 to March 2023 (2023-04-05), AHA copy | https://www.aha.org/system/files/media/file/2023/04/hc3-tlp-clear-analyst-note-killnets-targeting-of-the-hph-sector-december-2022-march-2023.pdf | 2026-11-03 | Confirmed |
| 36 | CISA, APT28 Exploits Known Vulnerability to Carry Out Reconnaissance and Deploy Malware on Cisco Routers (2023-04-18) | https://www.cisa.gov/news-events/alerts/2023/04/18/apt28-exploits-known-vulnerability-carry-out-reconnaissance-and-deploy-malware-cisco-routers | 2026-11-03 | Confirmed |
| 37 | NCSC, APT28 exploits known vulnerability to carry out reconnaissance and deploy malware on Cisco routers (2023-04-18) | https://www.ncsc.gov.uk/news/apt28-exploits-known-vulnerability-to-carry-out-reconnaissance-and-deploy-malware-on-cisco-routers | 2026-11-03 | Confirmed |
| 38 | CISA and partners, AA23-129A, Hunting Russian Intelligence "Snake" Malware (2023-05-09) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a | 2026-11-03 | Confirmed |
| 39 | FBI, wanted notice for Ruslan Aleksandrovich Peretyatko (indictment 2023-12-05) | https://www.fbi.gov/wanted/cyber/ruslan-aleksandrovich-peretyatko | 2026-11-03 | Confirmed |
| 40 | NCSC, CISA and partners, AA23-341A, Russian FSB Cyber Actor Star Blizzard Continues Worldwide Spear-phishing Campaigns (2023-12-07) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-341a | 2026-11-03 | Confirmed |
| 41 | GOV.UK, UK exposes attempted Russian cyber interference in politics and democratic processes (2023-12-07) | https://www.gov.uk/government/news/uk-exposes-attempted-russian-cyber-interference-in-politics-and-democratic-processes | 2026-11-03 | Confirmed |
| 42 | FBI, CISA, NSA, SKW, CERT Polska and NCSC, AA23-347A, Russian Foreign Intelligence Service (SVR) Exploiting JetBrains TeamCity CVE Globally (2023-12-12, revised 2023-12-13) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a | 2026-11-03 | Confirmed |
| 43 | Hewlett Packard Enterprise, Form 8-K (2024-01-19), SEC EDGAR | `https://www.sec.gov/Archives/edgar/data/1645590/000164559024000009/hpe-20240119.htm` | 2026-11-03 | Confirmed |
| 44 | US Department of Justice, court-authorized disruption of a botnet controlled by the Russian GRU (2024-02-15), read from an archived copy of this URL | https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian | 2026-11-03 | Confirmed |
| 45 | NCSC and partners, AA24-057A, SVR Cyber Actors Adapt Tactics for Initial Cloud Access (2024-02-26) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a | 2026-11-03 | Confirmed |
| 46 | FBI, NSA, US Cyber Command and partners, Russian Cyber Actors Use Compromised Routers to Facilitate Cyber Operations (2024-02-27) | https://www.ic3.gov/CSA/2024/240227.pdf | 2026-11-03 | Confirmed |
| 47 | Ministry of Foreign Affairs of the Czech Republic, Statement on the cyberattacks carried out by Russian actor APT28 (2024-05-03) | https://mzv.gov.cz/jnp/en/issues_and_press/press_releases/statement_of_the_mfa_on_the_cyberattacks.html | 2026-11-03 | Confirmed |
| 48 | US Treasury, press release jy2326, designation of LockBit leader Dmitry Khoroshev (2024-05-07) | https://home.treasury.gov/news/press-releases/jy2326 | 2026-11-03 | Confirmed |
| 49 | CISA, FBI, HHS and MS-ISAC, AA24-131A, #StopRansomware: Black Basta (2024-05-10) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a | 2026-11-03 | Confirmed |
| 50 | HHS HC3, Threat Actor Profile: Midnight Blizzard (2024-06-06), AHA copy | https://www.aha.org/system/files/media/file/2024/10/hc3-threat-actor-profile-tlp-clear-midnight-blizzard-6-6-2024.pdf | 2026-11-03 | Confirmed |
| 51 | FBI, CISA, NSA and partners, AA24-249A, Russian Military Cyber Actors Target US and Global Critical Infrastructure (2024-09-05) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a | 2026-11-03 | Confirmed |
| 52 | FBI, GRU Unit 29155 Cyber Actors (wanted notice, 2024-09-05) | https://www.fbi.gov/wanted/cyber/gru-29155-cyber-actors | 2026-11-03 | Confirmed |
| 53 | France, Ministry for Europe and Foreign Affairs, attribution of cyberattacks against France to the Russian military intelligence service (2025-04-29) | https://www.diplomatie.gouv.fr/en/presse-et-ressources/decouvrir-et-informer/actualites/russie-attribution-de-cyberattaques-contre-la-france-au-service-de-renseignement-militaire-russe | 2026-11-03 | Confirmed |
| 54 | ANSSI (CERT-FR), CERTFR-2025-CTI-007, targeting and compromise of French entities by the APT28 intrusion set (2025-04-29); landing page also at https://cert.ssi.gouv.fr/cti/CERTFR-2025-CTI-007/ | https://cert.cyber.gouv.fr/cti/CERTFR-2025-CTI-007/ | 2026-11-03 | Confirmed |
| 55 | NSA, FBI, CISA and partner agencies, 11 countries in all, AA25-141A, Russian GRU Targeting Western Logistics Entities and Technology Companies (May 2025, corrected 2026-04-17) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a | 2026-11-03 | Confirmed |
| 56 | FBI, PSA I-082025-PSA, Russian Government Cyber Actors Targeting Networking Devices, Critical Infrastructure (2025-08-20) | https://www.ic3.gov/PSA/2025/PSA250820 | 2026-11-03 | Confirmed |
| 57 | CISA, FBI, NSA and partners, AA25-343A, on pro-Russia hacktivists CARR, NoName057(16), Z-Pentest and Sector16 (2025-12-09) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a | 2026-11-03 | Confirmed |
| 58 | CERT Polska, Incident report: energy sector 2025 (2026-01-30) | https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/ | 2026-11-03 | Confirmed |
| 59 | FBI, PSA I-040726-PSA, on Russian GRU exploitation of SOHO routers (2026-04-07) | https://www.ic3.gov/PSA/2026/PSA260407 | 2026-11-03 | Confirmed |
| 60 | GOV.UK, Profile: GRU cyber and hybrid threat operations (updated 2026-07-13) | https://www.gov.uk/government/publications/profile-gru-cyber-and-hybrid-threat-operations/profile-gru-cyber-and-hybrid-threat-operations | 2026-11-03 | Confirmed |
| 61 | GOV.UK, UK and EU strike Russian cyber networks with new sanctions (2026-07-13) | https://www.gov.uk/government/news/uk-and-eu-strike-russian-cyber-networks-with-new-sanctions | 2026-11-03 | Confirmed |
| 62 | CISA and 18 partner agencies, AA26-194A, Improve Router Hygiene to Protect Against Russian State-Sponsored Targeting (2026-07-13) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a | 2026-11-03 | Confirmed |
| 63 | NCSC, UK and allies urge critical sectors to improve defences against Russian intelligence targeting (2026-07-13) | https://www.ncsc.gov.uk/news/uk-and-allies-urge-critical-sectors-to-improve-defences-against-russian-intelligence-targeting | 2026-11-03 | Confirmed |
| 64 | Kaspersky Securelist, The Epic Turla operation (2014-08-07) | https://securelist.com/the-epic-turla-operation/65545/ | 2026-11-03 | Confirmed |
| 65 | FireEye (Google Cloud archive), APT28: A Window into Russia's Cyber Espionage Operations? (2014-10-27) | https://cloud.google.com/blog/topics/threat-intelligence/apt28-a-window-into-russias-cyber-espionage-operations | 2026-11-03 | Confirmed |
| 66 | CrowdStrike, Bears in the Midst: Intrusion into the Democratic National Committee (2016-06-14) | https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/ | 2026-11-03 | Confirmed |
| 67 | Microsoft, Cyberattacks targeting health care must stop (November 2020) | https://www.microsoft.com/security/blog/2020/11/18/cyberattacks-targeting-health-care-must-stop | 2026-11-03 | Confirmed |
| 68 | Microsoft Security Response Center, Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard (2024-01-19) | https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard | 2026-11-03 | Confirmed |
| 69 | Microsoft Threat Intelligence, Midnight Blizzard: Guidance for responders on nation-state attack (2024-01-25) | https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/ | 2026-11-03 | Confirmed |
| 70 | Microsoft Security Response Center, Update on Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard (2024-03-08) | https://www.microsoft.com/en-us/msrc/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard | 2026-11-03 | Confirmed |
| 71 | Mandiant (Google Cloud), APT44: Unearthing Sandworm (2024-04-17) | https://cloud.google.com/blog/topics/threat-intelligence/apt44-unearthing-sandworm | 2026-11-03 | Confirmed |
| 72 | Microsoft On the Issues, Protecting democratic institutions from cyber threats (2024-10-03) | https://blogs.microsoft.com/on-the-issues/2024/10/03/protecting-democratic-institutions-from-cyber-threats/ | 2026-11-03 | Confirmed |
| 73 | Microsoft Threat Intelligence, Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files (2024-10-29) | https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/ | 2026-11-03 | Confirmed |
| 74 | Microsoft Threat Intelligence, Frequent freeloader part I: Secret Blizzard compromising Storm-0156 infrastructure for espionage (2024-12-04) | https://www.microsoft.com/en-us/security/blog/2024/12/04/frequent-freeloader-part-i-secret-blizzard-compromising-storm-0156-infrastructure-for-espionage/ | 2026-11-03 | Confirmed |
| 75 | Microsoft Threat Intelligence, Storm-2372 conducts device code phishing campaign (2025-02-13, updated 2026-07-31) | https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/ | 2026-11-03 | Confirmed |
| 76 | Microsoft Threat Intelligence, New Russia-affiliated actor Void Blizzard targets critical sectors for espionage (2025-05-27) | https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/ | 2026-11-03 | Confirmed |
| 77 | Microsoft Threat Intelligence, Frozen in transit: Secret Blizzard's AiTM campaign against diplomats (2025-07-31) | https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/ | 2026-11-03 | Confirmed |
| 78 | Google Threat Intelligence Group, New malware attributed to Russia state-sponsored COLDRIVER (2025-10-20) | https://cloud.google.com/blog/topics/threat-intelligence/new-malware-russia-coldriver | 2026-11-03 | Confirmed |
| 79 | ESET Research, Sandworm cyberattack on Poland's power grid in late 2025 (2026-01-23) | https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/ | 2026-11-03 | Confirmed |
| 80 | MITRE ATT&CK, Group G0007 APT28 (last modified 31 July 2026; ATT&CK v20.0) | https://attack.mitre.org/groups/G0007/ | 2026-11-03 | Confirmed |
| 81 | MITRE ATT&CK, Group G0016 APT29 (version 6.2, modified 31 July 2026) | https://attack.mitre.org/groups/G0016/ | 2026-11-03 | Confirmed |
| 82 | MITRE ATT&CK, Group G0034 Sandworm Team (version 4.2, modified 31 July 2026) | https://attack.mitre.org/groups/G0034/ | 2026-11-03 | Confirmed |
| 83 | MITRE ATT&CK, Group G0010 Turla (version 5.1, modified 31 July 2026) | https://attack.mitre.org/groups/G0010/ | 2026-11-03 | Confirmed |
| 84 | MITRE ATT&CK, Group G0035 Dragonfly (version 4.0, modified 31 July 2026) | https://attack.mitre.org/groups/G0035/ | 2026-11-03 | Confirmed |
| 85 | MITRE ATT&CK, Group G0047 Gamaredon Group (version 3.4, modified 1 October 2026) | https://attack.mitre.org/groups/G0047/ | 2026-11-03 | Confirmed |
| 86 | MITRE ATT&CK, Group G1003 Ember Bear (version 2.1, modified 31 July 2026) | https://attack.mitre.org/groups/G1003/ | 2026-11-03 | Confirmed |
| 87 | MITRE ATT&CK, Group G1033 Star Blizzard (version 2.0, created 14 June 2024) | https://attack.mitre.org/groups/G1033/ | 2026-11-03 | Confirmed |
| 88 | MITRE ATT&CK, Group G1031 Saint Bear (version 1.0, created 25 May 2024) | https://attack.mitre.org/groups/G1031/ | 2026-11-03 | Confirmed |
| 89 | MITRE ATT&CK, Group G1035 Winter Vivern (version 1.0, modified 31 July 2026) | https://attack.mitre.org/groups/G1035/ | 2026-11-03 | Confirmed |
| 90 | MITRE ATT&CK, Campaign C0063 2025 Poland Wiper Attacks (version 1.0, created 22 April 2026) | https://attack.mitre.org/campaigns/C0063/ | 2026-11-03 | Confirmed |
| 91 | MITRE D3FEND, D3-MFA Multi-factor Authentication | https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/ | 2026-11-03 | Confirmed |
| 92 | CISA, Known Exploited Vulnerabilities catalog, JSON feed (catalogVersion 2026.11.03, 1,767 entries) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |
| 93 | TeamStarWolf library data, `data/attack/group_profiles.jsonl` at commit e85b5594 (ATT&CK v20.0 descriptions, aliases and software lists) | https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/group_profiles.jsonl | 2026-11-03 | Reported where it summarizes an indictment or report; Confirmed for the data itself |
| 94 | TeamStarWolf library data, `data/attack/campaign_profiles.jsonl` at commit e85b5594 | https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/campaign_profiles.jsonl | 2026-11-03 | Confirmed (data); Reported for TEMP.Veles descriptions |
| 95 | TeamStarWolf library data, `data/attack/ics/groups.jsonl` at commit e85b5594 | https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/ics/groups.jsonl | 2026-11-03 | Reported |
| 96 | TeamStarWolf library, generated group pages under `mitre/groups/` at commit e85b5594 (page inventory and live-page comparison) | https://github.com/TeamStarWolf/TeamStarWolf/tree/e85b5594301fe061043fe92040135252c97b695d/mitre/groups | 2026-11-03 | Confirmed |
| 97 | TeamStarWolf library, generated page `mitre/campaigns/C0051.md` (APT28 Nearest Neighbor Campaign) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/campaigns/C0051.md | 2026-11-03 | Confirmed |
| 98 | TeamStarWolf library, generated page `mitre/campaigns/C0063.md` (2025 Poland Wiper Attacks) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/campaigns/C0063.md | 2026-11-03 | Confirmed |
| 99 | TeamStarWolf library, generated page `mitre/groups/G0047.md` (Gamaredon Group) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/groups/G0047.md | 2026-11-03 | Reported |
| 100 | TeamStarWolf library data, `data/attack/` at main (technique_profiles, superseded_by, ics and mobile files; the study's technique union) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-03 | Confirmed |
| 101 | TeamStarWolf library data, `data/attack/group_to_technique.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/group_to_technique.jsonl | 2026-11-03 | Confirmed |
| 102 | TeamStarWolf library data, `data/attack/technique_to_d3fend.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl | 2026-11-03 | Confirmed |
| 103 | Security Affairs, Russia-linked APT Laundry Bear linked to 2024 Dutch police attack (press account) | https://securityaffairs.com/178338/uncategorized/russia-linked-apt-laundry-bear-linked-to-2024-dutch-police-attack.html | 2026-11-03 | Reported |
| 104 | Claims Journal, N.J. appeals court on the war exclusion and the NotPetya attack on Merck (2023-05-04) | https://www.claimsjournal.com/news/east/2023/05/04/316786.htm | 2026-11-03 | Reported |
| 105 | TeamStarWolf library data, `data/weaknesses/cwe.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-03 | Confirmed |

## Related references

- [Threat Actors](/THREAT_ACTORS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md)
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Case studies: [All case studies](/case-studies/README.md); companion studies on Sandworm operations (`case-studies/SANDWORM_OPERATIONS.md`), [SolarWinds and SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), Change Healthcare 2024 (`case-studies/CHANGE_HEALTHCARE_2024.md`) and APT41 (`case-studies/APT41_PUBLIC_RECORD.md`)
- Generated MITRE pages: groups [APT28 `G0007`](/mitre/groups/G0007.md), [APT29 `G0016`](/mitre/groups/G0016.md), [Sandworm Team `G0034`](/mitre/groups/G0034.md), [Turla `G0010`](/mitre/groups/G0010.md), [Dragonfly `G0035`](/mitre/groups/G0035.md), [Gamaredon Group `G0047`](/mitre/groups/G0047.md), [Ember Bear `G1003`](/mitre/groups/G1003.md), [Star Blizzard `G1033`](/mitre/groups/G1033.md), [TEMP.Veles `G0088`](/mitre/groups/G0088.md), [Saint Bear `G1031`](/mitre/groups/G1031.md), [Winter Vivern `G1035`](/mitre/groups/G1035.md), [Wizard Spider `G0102`](/mitre/groups/G0102.md) and [Indrik Spider `G0119`](/mitre/groups/G0119.md); campaigns [`C0023`](/mitre/campaigns/C0023.md), [`C0024`](/mitre/campaigns/C0024.md), [`C0025`](/mitre/campaigns/C0025.md), [`C0028`](/mitre/campaigns/C0028.md), [`C0030`](/mitre/campaigns/C0030.md), [`C0032`](/mitre/campaigns/C0032.md), [`C0034`](/mitre/campaigns/C0034.md), [`C0051`](/mitre/campaigns/C0051.md) and [`C0063`](/mitre/campaigns/C0063.md); software [WhisperGate `S0689`](/mitre/software/S0689.md), [NotPetya `S0368`](/mitre/software/S0368.md), [Uroburos `S0022`](/mitre/software/S0022.md), [WellMess `S0514`](/mitre/software/S0514.md), [SUNBURST `S0559`](/mitre/software/S0559.md), [Spica `S1140`](/mitre/software/S1140.md) and [LAMEHUG `S9035`](/mitre/software/S9035.md); techniques [Exploit Public-Facing Application `T1190`](/mitre/techniques/T1190.md), [External Remote Services `T1133`](/mitre/techniques/T1133.md), [Password Spraying `T1110.003`](/mitre/techniques/T1110-003.md), [Valid Accounts `T1078`](/mitre/techniques/T1078.md), [Steal Web Session Cookie `T1539`](/mitre/techniques/T1539.md), [Multi-hop Proxy `T1090.003`](/mitre/techniques/T1090-003.md) and [Rootkit `T1014`](/mitre/techniques/T1014.md)
