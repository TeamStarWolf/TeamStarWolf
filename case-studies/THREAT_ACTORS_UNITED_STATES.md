# United States-Attributed Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Stuxnet](/case-studies/STUXNET.md), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [Equation group page](/mitre/groups/G0020.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, threat hunters, vulnerability managers and healthcare security teams

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 63 min (14,569 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a graded account of what the public record does and does not show about intrusions linked to United States agencies, which claims come from vendors, leaks or adversary governments, and what the leaked-exploit reuse of 2017 means for patching, firmware and trust-store defense

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: identity and aliases](#part-1-identity-and-aliases), [Part 8: the defender view](#part-8-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Defenders who track China, Russia, Iran and North Korea have indictments, joint advisories and sanctions notices to work from. Anyone who tries to build the same file on the United States finds a different record. There are no self-indictments, no advisories naming American operations, and no sanctions. What exists is a set of malware platforms that security researchers took apart in technical depth between 2011 and 2023 (Equation, Regin, Flame and Gauss, Duqu and Duqu 2.0, the Lamberts, Operation Triangulation), a run of leaks from 2013 to 2017 (the Snowden documents, the Shadow Brokers dumps, WikiLeaks Vault 7 and Vault 8), accusations by the governments of China and Russia, an Iranian acknowledgment of centrifuge damage that named no culprit, and a body of United States law and strategy that describes offensive cyber operations in general terms without acknowledging any intrusion a vendor has named.

This study sets that record out and grades every piece of it. The single most important finding is a negative one, and it is easy to lose in the retelling: **no vendor report this study opened attributes any of these platforms to the United States, and the ATT&CK knowledge base attributes none of them to any country.** The nearest exception is Microsoft's May 2017 statement that the WannaCrypt exploits were stolen from the NSA [32], which concerns leaked exploits, not any of these platforms. Kaspersky says a nation-state is likely behind Regin and Flame and names none. Symantec, the closest any vendor comes, says the indicators behind its Longhorn group point to an English-speaking North American country, and stops there. National attribution in the public record rests on three other pillars: journalism built on leaked documents, statements by adversary governments that published little or no testable evidence, and one United States court case that convicted the former CIA engineer who passed the Vault 7 material to WikiLeaks.

The second finding is about consequences. **Inferred:** the heaviest harm in the opened record came not from these platforms acting as designed but from reuse. Exploits the Shadow Brokers published in April 2017, which Microsoft had fixed a month earlier in MS17-010, were picked up within weeks by WannaCry and NotPetya. WannaCry reached at least 81 of the 236 NHS trusts in England and hundreds of GP practices, and cost thousands of cancelled appointments. The United States government later attributed WannaCry to North Korea and NotPetya to the Russian military. **Inferred** (L4-C3): for the healthcare sector, that downstream path, not direct targeting, is the whole of the United States-linked story in the opened record.

Evidence grade: the technical findings in the vendor reports are **Confirmed** (primaries opened); every claim that names the United States, the NSA, the CIA or GCHQ as the operator of a specific intrusion is **Reported** or rests on an adversary government's statement, and is graded and attributed to its speaker wherever it appears.

### Key facts at a glance

| Field | Value |
|---|---|
| Subject | Intrusion sets and malware platforms that leaked documents, journalists or foreign governments have linked to United States agencies, and the overt United States record on offensive cyber operations |
| ATT&CK objects | [G0020 Equation](/mitre/groups/G0020.md), [S0019 Regin](/mitre/software/S0019.md), [S0038 Duqu](/mitre/software/S0038.md), [S0143 Flame](/mitre/software/S0143.md), [S0603 Stuxnet](/mitre/software/S0603.md), [S0690 Green Lambert](/mitre/software/S0690.md) |
| ATT&CK sponsor attribution | None. No group, software or campaign description in ATT&CK v20.0 names the United States or a Five Eyes government as sponsor (**Confirmed**, [1] to [6], [9]) |
| Vendor sponsor attribution | None named. Kaspersky: a likely nation-state, none named; Symantec (Longhorn): indicators point to an English-speaking North American country (**Confirmed** for Kaspersky, [22]; **Reported** for Symantec, [23], [24]) |
| Earliest dated activity | Equation command-and-control domain registered August 2001, possibly some from 1996; samples compiled from 2002 (**Confirmed**, [15], [16]) |
| Long-running platform | Regin, with sample timestamps back to 2003 and a 64-bit infection still active in spring 2014 (**Confirmed**, [22]) |
| Court record | A former CIA software engineer convicted in July 2022 of passing the Vault 7 material, sentenced to 40 years on 1 February 2024 (**Reported**, [50]) |
| United States acknowledgment | No named intrusion acknowledged. Acknowledged in general: defend-forward strategy (2018, 2023), the Vulnerabilities Equities Process (2017 charter), statutes on military cyber operations (2017, 2018), declassified Operation Glowing Symphony against ISIS (2016), hunt-forward missions (**Confirmed**, [65], [67] to [70], [73], [75]) |
| Most consequential downstream event | EternalBlue and related SMBv1 exploits from the April 2017 Shadow Brokers release, reused by WannaCry (12 May 2017) and NotPetya (27 June 2017) (**Confirmed**, [30], [31], [35], [36]) |
| Healthcare | No healthcare sector in any opened victimology for Equation, Regin or the Lamberts; NHS harm from WannaCry is the downstream case (**Confirmed**, [15], [22], [25], [39]; the link between them is **Inferred**) |
| Library basis | ATT&CK v20.0 data in the library at main `e85b559` |

### Key findings

- **The technical record is deep and the attribution record is thin.** Kaspersky and CrySyS documented hard-drive firmware implants, an encrypted virtual file system in the Windows registry, a GSM base station controller log and an iOS chain using four zero-days, and Microsoft explained the MD5 collision behind Flame's forged code-signing certificate. None of these reports named a country for the platforms (**Confirmed**, [15] to [22], [25], [28], [29], [34]).
- **ATT&CK is more cautious than the library's own hand-written pages.** ATT&CK describes Equation as "a sophisticated threat group that employs multiple remote access tools" and names no sponsor [1]. The library's MALWARE_FAMILIES.md attributes Stuxnet to the NSA and Unit 8200 and Regin to the NSA and GCHQ without a citation, and CVE_REFERENCE.md gives EternalBlue's origin as the NSA, also uncited (**Confirmed**, [10], [83]). Those lines need citations or softer wording.
- **The leaks are the backbone of national attribution.** Leaks and leak journalism supply most of the specific links between a platform and an agency: the Shadow Brokers' own claim about Equation, Symantec's match of Longhorn tools to Vault 7, and The Intercept's reporting (from unnamed sources, since the Snowden documents did not name Regin) on Regin and Belgacom. Kaspersky found the first Shadow Brokers dump related to Equation code with high confidence; Symantec, looking at the same dump, treated the link as not proven (**Confirmed**, [26]; **Reported**, [27]).
- **Adversary governments fill the remaining space, with little testable evidence.** China (2022 onward) and Russia (2023) have accused the NSA of specific intrusions. SecurityWeek notes the Chinese university allegations remain unverified by independent sources, and Kaspersky could not confirm the FSB's findings beyond matching indicators (**Reported**, [54], [62]).
- **The overt United States record describes a posture, not incidents.** The 2017 VEP charter, the 2018 and 2023 Defense Department strategies, the 2023 National Cybersecurity Strategy and 10 U.S.C. 394 and 395 describe how offensive operations are authorized, reviewed and reported to Congress. None names a vendor-reported intrusion (**Confirmed**, [65], [67] to [69], [73], [74]; the framing is **Inferred**).
- **Leaked exploits outlived their makers.** MS17-010 shipped on 14 March 2017; WannaCry hit 59 days later and NotPetya 105 days later. CISA's Known Exploited Vulnerabilities catalog listed CVE-2017-0144 only on 10 February 2022 (**Confirmed**, [30], [37]; the day counts are arithmetic on those dates).
- **Healthcare is downstream.** Kaspersky's sector lists for Equation and Regin do not include healthcare. The NHS lost thousands of appointments to WannaCry, which used the leaked exploit and which the United States government attributes to North Korea (**Confirmed**, [15], [22], [35], [39]).

### Top recommendations

1. **Treat a public exploit leak as an out-of-cycle patch trigger.** When a leak maps exploits to fixed bulletins, as MSRC did one day after the April 2017 dump [31], **Inferred:** move those fixes to emergency service levels the same week. Do not wait for a catalog listing that may come years later [37].
2. **Turn off SMBv1 and keep SMB off the internet boundary.** CISA's WannaCry alert lists disabling SMBv1 and blocking TCP 445, UDP 137 to 138 and TCP 139 at the boundary [35]. That is an exposure finding whatever the patch state.
3. **Add firmware, drivers and trust stores to the inventory.** **Inferred:** Equation's firmware implants, Stuxnet's and Duqu's signed drivers and Flame's forged certificate sit outside most vulnerability scanners. Use the Microsoft vulnerable driver blocklist [40], baseline firmware versions under NIST SP 800-193's protect, detect and recover model [41], and alert on changes to trusted roots.
4. **Hunt for long dwell, not just indicators.** **Inferred:** platforms with a decade of activity (Regin samples from 2003, Equation infrastructure from 2001) favour integrity baselines and behaviour hunting over one-off IOC sweeps [16], [22].
5. **Plan memory-only eviction as a coordinated event.** Duqu 2.0 lived almost entirely in memory and re-infected from high-uptime servers [21]. **Inferred:** eviction means a domain-wide coordinated reboot or reimage together with credential resets.
6. **Grade attribution by speaker.** Keep vendor technical findings, leaked-document journalism and adversary-government accusations in separate columns of your own threat model, as this study does.

## Scope and method

This study covers the platforms and intrusion sets that leaked documents, journalists or foreign governments have linked to United States agencies, from the earliest dated Equation infrastructure (2001) through China's October 2025 allegation about the National Time Service Center. It also covers the overt United States record: strategy, statute, declassified operations and testimony. It draws on six kinds of source: the ATT&CK knowledge base and the library's own data; vendor research (Kaspersky, Symantec, CrySyS); vendor and government security bulletins and alerts (Microsoft, CISA, NVD, NIST, the UK National Audit Office); leaked-document journalism and leak publishers; statements by foreign governments; and United States law, strategy and congressional research.

Each claim carries one of four grades.

| Grade | Meaning |
|---|---|
| Confirmed | The primary source that published the fact (the vendor, agency, court, statute, or MITRE page) was opened on 3 November 2026 and says it. For an attribution, Confirmed means the source makes that attribution, at the confidence it states. For a foreign government statement opened at its source, Confirmed means the government said it; the allegation itself is not verified |
| Reported | Only a secondary source (press coverage, a publisher's description of leaked material, or commentary) was available |
| Demonstrated | A public reproduction exists. No claim in this study rests on one |
| Inferred | This study's own reasoning from Confirmed facts, labelled where it appears |

This study grades by source type (primary opened versus secondary only), the scheme used by the newer case studies; under the README's original scheme, single-vendor reports would read as Reported.

Four rules govern the record.

1. **Two layers, kept apart.** The record has a technical layer (what a vendor found on a disk or in a network) and an attribution layer (who a source says did it). A vendor report can be Confirmed on the first and silent on the second. This study never lets the first upgrade the second.
2. **The speaker travels with the claim.** Every sponsor claim names who made it: The Intercept from the Snowden documents, Microsoft in a policy blog, China's CVERC, Russia's FSB. None is restated as fact.
3. **ATT&CK's wording is quoted, not strengthened.** Where ATT&CK says "security researchers assess", this study says the same.
4. **No runnable detail.** Tradecraft appears at the level of technique names and identifiers, as the advisories use them. Exploit internals, payload strings and command lines are left out.

Two topics have a home elsewhere in the library. Stuxnet is covered in depth in [Stuxnet: The Case Study](/case-studies/STUXNET.md), and NotPetya and the Sandworm Team in [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md). Each gets a summary paragraph here and a link.

Kaspersky compares the Lamberts to ProjectSauron [25], but no source this study opened attributes ProjectSauron (ATT&CK's Strider group) to any state, so it is out of scope. Individuals named in foreign government wanted notices are not named here, because their identities were not verified [58].

Some sources did not load on 3 November 2026 and are not cited as opened: the Symantec Regin report of November 2014, the 2018 Defense Department Cyber Strategy summary PDF (quoted here through Lawfare), the Justice Department press release on the Vault 7 sentencing, the Symantec Longhorn post (loaded once, then failed; figures carried with CyberScoop [24]), the Washington Post originals on the 2018 and 2020 Cyber Command operations (used through Lawfare, NBC News and Krebs on Security), and the original Chinese-language CVERC reports (used through state media and secondary coverage). The 2023 Defense Department strategy summary returned an error at defense.gov and was read from an identical Internet Archive capture of the same PDF.

## Part 1: identity and aliases

### What ATT&CK records

ATT&CK holds one group object and five software objects that the wider record connects to United States agencies. It attributes none of them to any country.

| ID | Name | Aliases in ATT&CK | Years in ATT&CK's text | Enterprise techniques | ICS techniques | Page version | What ATT&CK says about who |
|---|---|---|---|---|---|---|---|
| [G0020](/mitre/groups/G0020.md) | Equation | none | none stated | 4 | 0 | v1.2, modified 31 July 2026 | "a sophisticated threat group that employs multiple remote access tools"; no country or agency [1] |
| [S0603](/mitre/software/S0603.md) | Stuxnet | W32.Stuxnet | discovered 2010; components as early as November 2008 | 44 | 25 | v1.5, modified 24 April 2026 | no country, no group [2] |
| [S0143](/mitre/software/S0143.md) | Flame | Flamer, sKyWIper | since at least 2010 | 10 | 2 | v1.1, modified 16 April 2025 | largely targeting Middle East countries; no sponsor, no group [3] |
| [S0038](/mitre/software/S0038.md) | Duqu | none | none stated | 21 | 3 | v1.2, modified 16 April 2025 | no sponsor; Stuxnet appears only in the title of a Symantec reference [4] |
| [S0019](/mitre/software/S0019.md) | Regin | none | timestamps back to 2003 | 11 | 0 | v1.2, modified 1 October 2023 | no sponsor; the only state wording is in the title of Kaspersky's reference [5] |
| [S0690](/mitre/software/S0690.md) | Green Lambert | none (group named Longhorn and The Lamberts in the text) | first reported 2017; Windows variant possibly 2008; macOS sample uploaded September 2014 | 18 | 0 | v1.0, created 21 March 2022 | "security researchers assess has been used by an advanced threat group"; no CIA, Vault 7, WikiLeaks or country [6] |

All six rows are **Confirmed** from the live pages [1] to [6].

ATT&CK's Equation entry rests on two Kaspersky publications: "Equation Group: Questions and Answers" (2015) and "Gauss: Abnormal Distribution" (2012). It lists no aliases and no software (**Confirmed**, [1]). Its Stuxnet entry calls the worm "the first publicly reported malware to specifically target industrial control systems devices" and cites Symantec's W32.Stuxnet Dossier v1.4 (February 2011), CISA advisory ICSA-10-272-01, ESET's "Stuxnet Under the Microscope" and Langner's "To Kill a Centrifuge" (November 2013) (**Confirmed**, [2]). Green Lambert, a modular backdoor for Windows, iOS, macOS and Linux, cites Kaspersky GReAT's "Unraveling the Lamberts Toolkit" (2017) and Sandvik's "Made In America: Green Lambert for OS X" (2021) (**Confirmed**, [6]).

### What ATT&CK does not hold

A scan of the library's ATT&CK v20.0 data (groups, group profiles, software profiles, campaign profiles, and the ICS and Mobile group files) found no group, software or campaign description that names the United States or a Five Eyes government as sponsor, and none that mentions Vault 7, WikiLeaks, the Shadow Brokers, the NSA or the CIA as an operator. Every "United States" hit is a target country (**Confirmed**, [9]). There is no group object for Longhorn or the Lamberts, Vault 7 or the Shadow Brokers, and no campaign object for Stuxnet, Flame, Regin or Equation (**Confirmed**, [9]). Equation-era tool names such as EquationDrug, GrayFish, DoubleFantasy and Fanny have no ATT&CK software entries. Operation Triangulation has no campaign page in the library's `mitre/campaigns/` folder (**Confirmed**, [9]).

The only leak-adjacent text in ATT&CK is in two ransomware entries that sit outside this study's actors. WannaCry ([S0366](/mitre/software/S0366.md)) names the SMBv1 exploit EternalBlue but not the NSA or the Shadow Brokers, and its linked group is Lazarus Group ([G0032](/mitre/groups/G0032.md)). NotPetya ([S0368](/mitre/software/S0368.md)), used by Sandworm Team ([G0034](/mitre/groups/G0034.md)) from 27 June 2017, names EternalBlue and EternalRomance, again without the NSA or the Shadow Brokers (**Confirmed**, [7], [8]).

### What the vendors call it

| Vendor name | Vendor | First public report | Vendor's attribution wording |
|---|---|---|---|
| Equation group | Kaspersky GReAT | 16 February 2015 | No country named; the Q&A's section on who is behind the group lists only leftover codewords and build timestamps (**Confirmed**, [15], [16]) |
| Regin | Kaspersky | 24 November 2014 | Says the platform is "supported by a nation-state"; names none; warns that timestamps could be a false flag (**Confirmed**, [22]) |
| Flame (Flamer, sKyWIper) | Kaspersky | 28 May 2012 | A likely nation-state; no state named (**Confirmed**, [18]) |
| Gauss | Kaspersky | 9 August 2012 | Attributed only to the Flame developers and a likely nation-state (**Confirmed**, [17]) |
| Duqu | CrySyS Lab | 14 October 2011 | CrySyS believes Duqu's author had access to Stuxnet source code; no state (**Confirmed**, [19]) |
| Duqu 2.0 | Kaspersky | 10 June 2015 | No state named (**Confirmed**, [20]) |
| Longhorn | Symantec | 10 April 2017 | Tools match Vault 7 documents; indicators point to an English-speaking North American country; no country named (**Reported**, [23], [24]) |
| The Lamberts | Kaspersky GReAT | 11 April 2017 | The same actor Symantec calls Longhorn; no government named (**Confirmed**, [25]) |
| Operation Triangulation | Kaspersky | 1 June 2023 | No actor or country named, then or in the final report of 27 December 2023 (**Confirmed**, [28], [29]) |

### How the boundaries differ

The vendors' clusters do not line up neatly with ATT&CK's objects. Kaspersky treats Equation as a group that "interacted" with the Stuxnet and Flame groups, through shared zero-days and through Equation infections of some of Stuxnet's first victims [15], [16]. ATT&CK keeps Equation as a group with four techniques and no software, and keeps Stuxnet, Flame, Duqu and Regin as standalone software with no group (**Confirmed**, [1] to [5]). Kaspersky ties the Lamberts to Symantec's Longhorn and compares the toolkit to Regin, ProjectSauron, Equation and Duqu 2.0 [25]; ATT&CK carries only Green Lambert, one of six colour-named families, as software with no group [6]. Readers should not merge these names into a single "NSA" or "CIA" bucket: no primary opened does so.

## Part 2: where the record comes from

The record comes from four kinds of source, and each carries a different weight for attribution.

| Source type | Examples in this study | What it can establish | What it cannot |
|---|---|---|---|
| Vendor research | Kaspersky on Equation, Regin, Flame, Gauss, Duqu 2.0, the Lamberts, Triangulation; Symantec on Longhorn and the Shadow Brokers dump; CrySyS on Duqu | Tooling, victimology, timelines, links between toolsets | A sponsor: none names a country [15] to [29] |
| Leaks and leak journalism, 2013 to 2017 | The Guardian and Der Spiegel on the Snowden documents; The Intercept on Regin and Belgacom; the Shadow Brokers; WikiLeaks Vault 7 and Vault 8 | What internal documents, as published, say about programs and tools | That a specific intrusion was carried out by a named agency, except where a document says so and the publisher reports it |
| Foreign government statements | China's CVERC and Foreign Ministry (2022), Harbin police (2025), the Ministry of State Security (2025); Russia's FSB (2023); Iran's president (2010, an acknowledgment of damage, not an accusation) | What the government alleges, and when | The allegation itself: none published evidence an independent party has confirmed |
| United States overt record | The VEP charter, Defense Department strategies, the National Cybersecurity Strategy, statutes, CRS reports, declassified after-action reports, testimony, and operations described by named outlets from unnamed officials | Policy, authority, oversight, and a small set of acknowledged or credibly reported operations against non-state or adversary targets | Any named vendor-reported intrusion: the United States has neither confirmed nor denied one |

The one court-tested piece of the leak record is the Vault 7 case. A United States jury convicted the former CIA software engineer who passed the material, at a July 2022 trial that followed a 2020 trial deadlocked on the top counts, and Judge Jesse M. Furman sentenced him to 40 years on 1 February 2024 (**Reported**, [50]). **Inferred:** the conviction is the closest the record comes to official confirmation that the Vault 7 material was genuine CIA material.

**Inferred.** Taken together, no vendor primary opened attributes Flame, Gauss, Duqu, Regin, Equation, Duqu 2.0 or Triangulation to the United States. National attribution rests on leaked-document journalism, on adversary governments, or, for overt operations only, on United States acknowledgment [15] to [29].

## Part 3: the operational record

One row per dated event, report or statement the verified record supports. "Event date" is when the activity happened or the source was published, as the source gives it.

| Event date | Event | Who says so | Grade | Sources |
|---|---|---|---|---|
| 1996 to August 2001 | Equation command-and-control domains: the first registered August 2001, some possibly from 1996 | Kaspersky | Confirmed | [15], [16] |
| 2002 | Earliest Equation samples compiled | Kaspersky | Confirmed | [15] |
| 2003 | Earliest Regin sample timestamps | Kaspersky | Confirmed | [22] |
| April to May 2008 | Regin activity log from a large GSM operator's base station controller, covering 136 cells | Kaspersky | Confirmed | [22] |
| 2008 | Lamberts toolkit active from at least this year; a Green Lambert Windows variant may date to 2008 | Kaspersky; ATT&CK | Confirmed | [25], [6] |
| November 2008 | Earliest Stuxnet components in use | ATT&CK (from Symantec) | Confirmed | [2] |
| 2009 | Attendees of a scientific conference in Houston later receive a trojanized conference CD-ROM by mail; Kaspersky calls the technique interdiction | Kaspersky | Confirmed | [16] |
| 2010 | Equation's EquationDrug firmware module (v3.0.1) compiled | Kaspersky | Confirmed | [16] |
| February to March 2010 | Flame in the wild | Kaspersky | Confirmed | [18] |
| 2010 | Stuxnet discovered | ATT&CK | Confirmed | [2] |
| 2010 to 2011 | GCHQ's "Operation Socialist" against Belgacom and its BICS roaming arm, in stages; sources differ on whether it began in 2010 or 2011 | The Intercept, NRC Handelsblad and De Standaard, from Snowden documents | Reported | [43], [44] |
| 29 November 2010 | Iran's president acknowledges malicious software caused problems for a limited number of centrifuges, naming no worm and no culprit | Iran's president, via the Christian Science Monitor | Reported | [64] |
| 2011 | Symantec's Longhorn group active from at least this year | Symantec | Reported | [23] |
| 14 October 2011 | CrySyS publishes "Duqu: A Stuxnet-like malware found in the wild" (v0.93) | CrySyS Lab | Confirmed | [19] |
| 28 May 2012 | Kaspersky discloses Flame after the ITU asks for help finding data-wiping malware in the Middle East | Kaspersky | Confirmed | [18] |
| 3 June 2012 | Microsoft Security Advisory 2718704 moves three intermediate certificate authorities to the Untrusted store | Microsoft | Confirmed | [33] |
| 6 June 2012 | MSRC explains the MD5 chosen-prefix collision behind Flame's code-signing certificate | Microsoft | Confirmed | [34] |
| 9 August 2012 | Kaspersky discloses Gauss, a toolkit on the Flame platform; about 2,500 unique PCs by 31 July 2012 | Kaspersky | Confirmed | [17] |
| 2013 | Equation's GrayFish firmware module (v4.2.0) compiled; Lamberts activity peaks 2013 to 2014 | Kaspersky | Confirmed | [16], [25] |
| 25 April 2013 | FISA Court order granted requiring Verizon to give the NSA call records daily (published 6 June 2013) | The Guardian, from a leaked order | Reported | [45] |
| 6 June 2013 | The Guardian publishes the PRISM presentation; the named companies deny knowledge | The Guardian | Reported | [46] |
| June 2013 | Belgacom finds the malware in its network | The Intercept | Reported | [43] |
| 29 December 2013 | Der Spiegel describes NSA Tailored Access Operations from internal documents: shipment interdiction, the QUANTUM toolbox, GCHQ use against Belgacom staff | Der Spiegel | Reported | [47] |
| February 2014 | Belgian cryptographer Jean-Jacques Quisquater discloses an intrusion that Kaspersky later matches to Regin | Kaspersky | Confirmed | [22] |
| September 2014 | A Green Lambert macOS sample is uploaded | ATT&CK | Confirmed | [6] |
| 24 November 2014 | Kaspersky publishes its Regin analysis: 27 victims in 14 countries | Kaspersky | Confirmed | [22] |
| 24 November 2014 | The Intercept reports Regin as the suspected technology behind the Belgacom and EU intrusions; the NSA calls it speculation | The Intercept | Reported | [42] |
| 13 December 2014 | The Intercept's inside story of the Belgacom intrusion, attributed to GCHQ from Snowden documents | The Intercept | Reported | [43] |
| 16 February 2015 | Kaspersky discloses the Equation group | Kaspersky | Confirmed | [15], [16] |
| 10 to 11 June 2015 | Kaspersky discloses Duqu 2.0, which breached Kaspersky itself with kernel zero-day CVE-2015-2360 (patched 9 June 2015) | Kaspersky | Confirmed | [20], [21] |
| 13 August 2016 | The Shadow Brokers post a sample archive they say came from Equation Group and announce an auction | Kaspersky and Symantec (the original posts were not opened) | Reported | [26], [27] |
| 16 August 2016 | Kaspersky finds the dump related to Equation code with high confidence; Symantec treats the link as not proven | Kaspersky; Symantec | Confirmed; Reported | [26], [27] |
| 10 November 2016 | Operation Glowing Symphony against ISIS online media authorized, run by JTF-ARES | Declassified USCYBERCOM documents | Confirmed | [75] |
| 7 March 2017 | WikiLeaks publishes Vault 7 "Year Zero" | WikiLeaks | Reported | [48] |
| 14 March 2017 | Microsoft publishes MS17-010 (Critical), fixing CVE-2017-0143 to CVE-2017-0148 | Microsoft | Confirmed | [30] |
| 10 to 11 April 2017 | Symantec ties Vault 7 tooling to Longhorn; Kaspersky publishes the Lamberts toolkit | Symantec; Kaspersky | Reported; Confirmed | [23], [24], [25] |
| 15 April 2017 | MSRC maps the April Shadow Brokers exploits to existing fixes | Microsoft | Confirmed | [31] |
| 12 May 2017 | WannaCry spreads with the MS17-010 (EternalBlue) exploit; CISA issues TA17-132A; NHS bodies in England are hit | CISA; UK National Audit Office | Confirmed | [35], [39] |
| 14 May 2017 | Microsoft says WannaCrypt used exploits stolen from the NSA and argues that governments should report vulnerabilities to vendors rather than stockpile them | Microsoft | Confirmed (as Microsoft's statement) | [32] |
| 27 June 2017 | NotPetya, used by Sandworm Team, spreads with EternalBlue and EternalRomance and harvested credentials | ATT&CK; CISA TA17-181A (1 July 2017) | Confirmed | [8], [36] |
| 9 November 2017 | WikiLeaks begins Vault 8 with Hive source code and development logs | WikiLeaks | Reported | [49] |
| 15 November 2017 | The White House publishes the unclassified VEP charter | White House | Confirmed | [65], [66] |
| 12 December 2017 | Pub. L. 115-91 sec. 1631 enacts the 48-hour notice rule for sensitive military cyber operations (10 U.S.C. 395) | Statute | Confirmed | [69] |
| 15 February 2018 | CISA revises TA17-181A to add the United States attribution of NotPetya to the Russian military | CISA | Confirmed | [36] |
| 17 February 2018 | The Intercept reports the Belgian Belgacom probe unresolved after four years; the UK never acknowledged a role | The Intercept | Reported | [44] |
| 7 June 2018 | CISA revises TA17-132A to add the North Korea attribution of WannaCry | CISA | Confirmed | [35] |
| 13 August 2018 | FY2019 NDAA (Pub. L. 115-232): sec. 1632 on clandestine military cyber activities, sec. 1642 on action against Russia, China, North Korea or Iran | Statute | Confirmed | [67], [68] |
| September 2018 | Defense Department Cyber Strategy summary: "defend forward"; the White House acknowledges NSPM-13 replaced PPD-20 | Lawfare (strategy text); CRS (NSPM-13) | Reported; Confirmed | [71], [72], [70] |
| 6 November 2018 | Cyber Command reportedly cuts the Internet Research Agency's internet access on Election Day and for days after | Washington Post via Lawfare; NBC News (26 February 2019), both from unnamed officials | Reported | [76], [77] |
| 22 September and 1 October 2020 | Trickbot disruption with a bogus configuration and fake victim records, reportedly by Cyber Command; Cyber Command declines comment | Washington Post via Krebs on Security | Reported | [78] |
| 12 October 2020 | Microsoft announces its parallel Trickbot disruption under an Eastern District of Virginia court order | Microsoft | Confirmed | [79] |
| 3 November 2021 | CISA KEV adds CVE-2017-0143 | CISA | Confirmed | [37] |
| 10 February 2022 | CISA KEV adds CVE-2017-0144 and CVE-2017-0145 | CISA | Confirmed | [37] |
| 1 June 2022 | Gen. Nakasone tells Sky News the United States conducted offensive, defensive and information operations supporting Ukraine | The Register | Reported | [80] |
| 22 June 2022 | Northwestern Polytechnical University discloses a phishing attack | China Daily, citing CVERC and 360 | Reported | [51] |
| July 2022 | Former CIA software engineer convicted of leaking the Vault 7 material | NPR via MPR News | Reported | [50] |
| 5 September 2022 | CVERC and 360 accuse NSA Tailored Access Operations of the NWPU attack | China Daily | Reported | [51] |
| 8 September 2022 | China's Foreign Ministry lodges representations with the US Embassy over the NWPU attack | China's Foreign Ministry | Confirmed (as a statement) | [52] |
| 15 September 2022 | CISA KEV adds CVE-2010-2568, the LNK flaw used by Fanny and Stuxnet | CISA | Confirmed | [37] |
| 1 March 2023 | National Cybersecurity Strategy: disruption of threat actors with all instruments of national power | White House | Confirmed | [74] |
| 1 June 2023 | Kaspersky discloses Operation Triangulation; the FSB, the same day, blames US intelligence for an iPhone operation (link to Triangulation unverified) and alleges Apple cooperation; Apple denies | Kaspersky; FSB; The Record; The Register | Confirmed; Confirmed (as a statement); Reported | [28], [61], [62], [63] |
| 12 September 2023 | 2023 Defense Department Cyber Strategy summary: supersedes the 2018 strategy | Defense Department | Confirmed | [73] |
| 27 December 2023 | Kaspersky's final Triangulation report: four zero-days, an undocumented hardware feature, still no attribution | Kaspersky | Confirmed | [29] |
| 1 February 2024 | The Vault 7 leaker is sentenced to 40 years | NPR via MPR News | Reported | [50] |
| 10 April 2024 | Gen. Haugh tells the Senate Armed Services Committee of 22 hunt-forward missions in 17 countries in 2023 | The Record | Reported | [81] |
| 8 July 2024 | CVERC claims Volt Typhoon is a US intelligence fabrication; ThreatMon and Trellix reject the use of their research | The Record | Reported | [56] |
| October 2024 | SentinelLABS assesses the third CVERC Volt Typhoon report as offering no new evidence | SentinelLABS | Reported | [57] |
| February 2025 | Researcher Lina Lau reviews the Chinese NWPU reports as unverified allegations with redacted indicators | Inversecos | Reported | [55] |
| 21 February 2025 | SecurityWeek summarizes the CVERC and 360 NWPU attribution and calls it unverified by independent sources | SecurityWeek | Reported | [54] |
| 15 April 2025 | Harbin police put three alleged NSA staff on a wanted list over attacks during the February 2025 Asian Winter Games | Xinhua via Nextgov and Al Jazeera | Reported | [58], [59] |
| 19 October 2025 | China's Ministry of State Security alleges an NSA campaign against the National Time Service Center | The Record | Reported | [60] |
| 31 July 2026 | ATT&CK's Equation page (v1.2) last modified, still naming no sponsor | ATT&CK | Confirmed | [1] |

### Reading the record by era

- **2001 to 2010: the silent decade.** Everything dated in these years was dated later, from timestamps, domain registrations and logs that vendors recovered in 2011 to 2015. Most of this activity became public only years later, although some victims (Belgacom in 2013, Quisquater in 2014) found intrusions while Regin was still active [22], [43].
- **2010 to 2015: the vendor era.** Stuxnet's discovery started a run of disclosures: Duqu (2011), Flame and Gauss (2012), Regin (2014), Equation and Duqu 2.0 (2015). The reports are technically rich and attribute nothing.
- **2013 to 2017: the leak era.** The Snowden documents, the Shadow Brokers and Vault 7 supplied names, programs and agencies. The Shadow Brokers also put working exploits into public hands, and WannaCry and NotPetya reused exploits from their April 2017 release [31], [35], [36].
- **2017 to 2024: the policy era.** The United States wrote down how it decides on vulnerabilities, authorizes military cyber operations and reports them to Congress, and moved to a defend-forward posture.
- **2022 to 2025: the accusation era.** China and Russia began naming the NSA in public, without evidence an independent party has confirmed [54], [62].

## Part 4: tooling

### Equation

Kaspersky describes a group active for almost two decades, with thousands or perhaps tens of thousands of victims (**Confirmed**, [15]). The Q&A counts more than 500 victims and suggests tens of thousands of infections over time (**Confirmed**, [16]). The pieces Kaspersky documents:

- **Hard-drive firmware reprogramming.** Two modules were recovered: EquationDrug v3.0.1 (compiled 2010, six drive categories) and GrayFish v4.2.0 (compiled 2013, twelve). Their hidden-sector storage gives persistence that survives disk formatting and an operating system reinstall. The module was seen on only a few victims (**Confirmed**, [16]). ATT&CK maps this to T1542.002 Component Firmware for G0020 [1].
- **A file system in the registry.** GrayFish lives in the registry, relies on a bootkit and implements an encrypted virtual file system inside the Windows registry. ATT&CK maps this as T1564.005 Hidden File System (**Confirmed**, [16], [1]).
- **Victim validation.** DoubleFantasy is a validator-style implant that confirms the target before later stages are delivered; ATT&CK records Equation's environmental keying as T1480.001 (**Confirmed**, [16], [1]).
- **Air-gap mapping.** The Fanny worm used two zero-days later found in Stuxnet (the LNK flaw CVE-2010-2568 and the MS09-025 kernel privilege escalation) and mapped air-gapped networks through a hidden storage area on USB sticks. Kaspersky says Equation had these exploits before the Stuxnet group (**Confirmed**, [16]).
- **Interdiction.** The Houston conference CD-ROM of 2009 is Kaspersky's example of shipped goods being intercepted and replaced, a physical supply-chain substitution (**Confirmed**, [16]).

### Regin

Regin is a multi-stage platform whose later stages hide in NTFS extended attributes, the registry or raw disk, inside encrypted virtual file systems (**Confirmed**, [22]). Kaspersky counts 27 victims in 14 countries and recovered, from an encrypted component, a 2008 activity log from a GSM base station controller at a large mobile operator, covering 136 cells (**Confirmed**, [22]). ATT&CK records eleven techniques, including T1564.004 NTFS File Attributes and T1564.005 Hidden File System [5].

The Intercept reported Regin as the suspected technology behind the Belgacom and EU intrusions that the Snowden documents attributed to GCHQ and the NSA. Its sourcing was unnamed people close to the investigations and Fox-IT's Ronald Prins; the NSA called it speculation; the Snowden documents did not name Regin (**Reported**, [42]). Kaspersky's own paper links the February 2014 Quisquater intrusion to Regin and does not mention Belgacom (**Confirmed**, [22]).

### Flame and Gauss

Kaspersky describes Flame as a parallel project to Stuxnet and Duqu, built without their Tilded platform, sharing the autorun.inf spreading method and the print spooler vulnerability (**Confirmed**, [18]). ATT&CK records lateral movement through MS10-061 (T1210), USB autorun spread (T1091), Authentication Package persistence (T1547.002), Bluetooth exfiltration through the BeetleJuice module (T1011.001) and audio capture (T1123) (**Confirmed**, [3]).

Flame's most consequential trick was a certificate. It used unauthorized certificates derived from the Terminal Server Licensing hierarchy, which chained to the Microsoft Root. Microsoft moved three intermediate certificate authorities to the Untrusted store [33], and MSRC explained that an MD5 chosen-prefix collision made the certificate valid for code signing on all Windows versions. Microsoft then invalidated the whole licensing hierarchy and reissued it on a chain that cannot be used for code signing (**Confirmed**, [34]).

Gauss, disclosed on 9 August 2012, runs on the Flame platform. About 2,500 unique PCs were infected by 31 July 2012, Lebanon most of all (more than 1,600), and it stole credentials for Bank of Beirut, Byblos Bank and Fransabank customers. One encrypted payload remained undecrypted when Kaspersky published (**Confirmed**, [17]). ATT&CK has no Gauss software object; Gauss appears only as a reference title on the Equation page [1].

### Duqu and Duqu 2.0

CrySyS found that Stuxnet's driver was signed with Realtek's key and, after that certificate was revoked, with JMicron's, and that Duqu's driver carried a valid C-Media signature. CrySyS believes Duqu's author had access to Stuxnet source code (**Confirmed**, [19]). ATT&CK records a service-loaded driver signed with a valid private key (T1543.003), spread to shares with stolen credentials and scheduled tasks (T1078, T1021.002, T1053.005) and token theft (T1134) (**Confirmed**, [4]).

Duqu 2.0 breached Kaspersky itself using the kernel zero-day CVE-2015-2360. It survives almost entirely in memory, re-infecting machines from high-uptime servers, and places traffic-tunnelling drivers on a few internet-facing servers. Kaspersky contrasts this with Equation and Turla, which piggybacked on third-party signed drivers. Some infections were linked to venues of the P5+1 negotiations with Iran and to an Auschwitz anniversary event (**Confirmed**, [20], [21]).

### Stuxnet, in one paragraph

Stuxnet was discovered in 2010 with components in use from November 2008, and ATT&CK maps it to 44 Enterprise and 25 ICS techniques with no group and no sponsor (**Confirmed**, [2]). ATT&CK's procedure rows include a driver signed with a compromised Realtek certificate (T1553.002), exploitation of MS10-061 and MS08-067 (T1210), USB spread through autorun or CVE-2010-2568 (T1091), privilege escalation through MS10-073 and a Task Scheduler flaw (T1068), a rootkit (T1014), a boot-start driver service (T1543.003) and network shares (T1021.002) (**Confirmed**, [2]). Kaspersky reports that some of Stuxnet's first victims appear to have been infected by Equation [16]. Iran's president acknowledged in November 2010 that malware had caused problems for a limited number of centrifuges (**Reported**, [64]). The technical record, the timeline, the attribution reporting and the defender lessons are in [Stuxnet: The Case Study](/case-studies/STUXNET.md).

### The Lamberts, Longhorn and Vault 7

Kaspersky's Lamberts report describes six colour-named malware families active from at least 2008, with a peak in 2013 and 2014, a small set of high-profile victims worldwide (including a European organization in 2014), and Black Lambert first exposed through CVE-2014-4148 (**Confirmed**, [25]). Symantec's Longhorn report counts 40 targets in 16 countries across the Middle East, Europe, Asia and Africa, plus one computer in the United States that may have been hit unintentionally. It says the Corentry tool matches the Fluxwire changelog in Vault 7 and Plexor matches Fire and Forget (**Reported**, [23], [24]).

WikiLeaks published Vault 7 "Year Zero" on 7 March 2017: 8,761 documents and files it said came from an isolated network in the CIA's Center for Cyber Intelligence, covering 2013 to 2016 (**Reported**, [48]). On 9 November 2017 it began Vault 8 with Hive source code and development logs, described as a CIA implant command-and-control system using cover domains, and said the build examples generated a fake certificate impersonating Kaspersky Lab (**Reported**, [49]). The 2022 conviction and 2024 sentencing of the former CIA engineer who leaked the material is in Part 2 (**Reported**, [50]).

### The Shadow Brokers tools

The Shadow Brokers began on 13 August 2016 with a sample archive they said came from Equation Group (**Reported**, [26], [27]). Kaspersky concluded "with a high degree of confidence" that the tools are related to Equation malware: the free archive holds 347 RC5/RC6 implementations, and more than 300 files implement an RC6 variant seen before only in Equation malware (**Confirmed**, [26]). Symantec described the dump as 256 MB and about 4,000 files, mostly router and firewall exploits dated about 2010 to 2013. Cisco confirmed CVE-2016-6366 as new and CVE-2016-6367 as fixed in 2011, Fortinet advised on old FortiGate firmware, and Symantec treated the Equation link as not proven (**Reported**, [27]).

The April 2017 release was the one that mattered. One day later, MSRC mapped EternalBlue, EternalChampion, EternalRomance and EternalSynergy to MS17-010, EmeraldThread to MS10-061, EclipsedWing to MS08-067, EsikmoRoll to MS14-068 and EducatedScholar to MS09-050. EnglishmanDentist, EsteemAudit and ExplodingCan did not reproduce on supported platforms (**Confirmed**, [31]). Microsoft had published MS17-010 on 14 March 2017 with none of the flaws listed as publicly disclosed or exploited (**Confirmed**, [30]).

WannaCry and NotPetya picked the exploits up within weeks. The library's data maps T1210 Exploitation of Remote Services to both (**Confirmed**, [11]); this study treats that as downstream reuse, not as part of the actor layer. NotPetya is covered in [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md).

### Operation Triangulation

Kaspersky disclosed on 1 June 2023 a zero-click iMessage compromise of iOS devices on its own corporate network, with the earliest traces in 2019 and targets up to iOS 15.7 (**Confirmed**, [28]). The final report of 27 December 2023 documented four zero-days, CVE-2023-41990, CVE-2023-32434, CVE-2023-38606 and CVE-2023-32435, including an undocumented hardware MMIO feature used to bypass the Page Protection Layer, and still made no attribution (**Confirmed**, [29]). The same day as the first disclosure, the FSB, with the FSO, said it had uncovered a US intelligence operation (whether it is the Triangulation activity is unverified) using Apple phones that infected several thousand devices, including SIMs registered to diplomatic missions in Russia, and alleged that Apple cooperates with the NSA (**Confirmed** as the FSB's statement, [61]). Apple denied ever inserting a backdoor, the NSA declined comment, and Kaspersky said it could not verify the FSB's findings beyond matching indicators (**Reported**, [62], [63]).

## Part 5: exploited vulnerabilities

| Vulnerability | Used by (per the source) | Fix | KEV listing | Sources |
|---|---|---|---|---|
| CVE-2010-2568 (Windows LNK) | Fanny before Stuxnet; Stuxnet USB spread | 2010 | Added 15 September 2022 | [16], [2], [37] |
| MS09-025 (kernel privilege escalation) | Fanny before Stuxnet | MS09-025 | not checked | [16] |
| CVE-2010-2729 (Print Spooler, MS10-061) | Stuxnet and Flame lateral movement; EmeraldThread in the April 2017 dump | MS10-061 | not checked | [2], [3], [31], [38] |
| MS08-067 | Stuxnet lateral movement; EclipsedWing in the April 2017 dump | MS08-067 | not checked | [2], [31] |
| MS10-073 and a Task Scheduler flaw | Stuxnet privilege escalation | MS10-073 | not checked | [2] |
| MS12-034 and MS13-081 (TrueType font flaws), CVE-2013-3918 (Internet Explorer), CVE-2012-1723 and CVE-2012-4681 (Java) | Equation exploit list; at least four used as zero-days | as listed | not checked | [16] |
| Terminal Server Licensing certificate hierarchy (MD5 collision) | Flame code signing | Advisory 2718704, 3 June 2012 | not applicable | [33], [34] |
| CVE-2014-4148 | Black Lambert | 2014 | not checked | [25] |
| CVE-2015-2360 (Windows kernel) | Duqu 2.0 against Kaspersky | 9 June 2015 | not checked | [21] |
| CVE-2016-6366, CVE-2016-6367 (Cisco ASA and PIX) | August 2016 Shadow Brokers dump | CVE-2016-6367 fixed in 2011; CVE-2016-6366 new | not checked | [27] |
| MS09-050, MS14-068 | EducatedScholar and EsikmoRoll in the April 2017 dump | as listed | not checked | [31] |
| CVE-2017-0143, -0144, -0145, -0146, -0148 (SMBv1 remote code execution), CVE-2017-0147 (information disclosure) | EternalBlue, EternalChampion, EternalRomance, EternalSynergy; then WannaCry and NotPetya | MS17-010, 14 March 2017 | -0143: 3 November 2021; -0144 and -0145: 10 February 2022; -0146: 25 March 2022; -0148: 6 April 2022; all flagged for known ransomware use | [30], [31], [35], [36], [37] |
| CVE-2023-41990, CVE-2023-32434, CVE-2023-38606, CVE-2023-32435 | Operation Triangulation chain | Apple, 2023 | not checked | [29] |

Two notes on this table. First, NVD lists CVE-2017-0144 (published 17 March 2017) and CVE-2010-2568 as NVD-CWE-noinfo, with no CWE assigned, while CVE-2010-2729 carries CWE-20. No CWE should be claimed for EternalBlue (**Confirmed**, [38]). Second, the KEV dates are the catalog's addition dates, not exploitation dates: EternalBlue was used at internet scale in May 2017 and listed nearly five years later (**Confirmed**, [37]).

## Part 6: targets by sector and geography

### Sectors

| Platform | Sectors in the vendor's victimology | Healthcare listed? | Source |
|---|---|---|---|
| Equation | Governments and diplomatic institutions, telecoms, aerospace, energy, nuclear research, oil and gas, military, nanotechnology, Islamic activists and scholars, mass media, transportation, financial institutions, cryptography developers | No | [15] (**Confirmed**) |
| Regin | Telecom operators, government institutions, multinational political bodies, financial and research institutions, individuals in advanced mathematics or cryptography | No | [22] (**Confirmed**) |
| Longhorn | Not checked (Symantec primary did not reliably load) | No | [23] (**Reported**) |
| The Lamberts | A small set of high-profile targets worldwide | Not stated | [25] (**Confirmed**) |
| Flame | Individuals to state-related bodies and education | No | [18] (**Confirmed**) |
| Gauss | Bank customers (Bank of Beirut, Byblos Bank, Fransabank) | No | [17] (**Confirmed**) |
| Duqu 2.0 | A security vendor (Kaspersky), venues of the P5+1 Iran talks, an Auschwitz anniversary event | No | [20] (**Confirmed**) |
| Triangulation | Kaspersky's own staff; per the FSB (link to Triangulation unverified), diplomatic SIMs in Russia | No | [28], [61] |

### Geography

- **Equation:** more than 30 countries, including Iran, Russia, Syria, Afghanistan, Pakistan, India and Hong Kong, United States allies (the United Kingdom, France, Germany, Belgium) and the United States itself (**Confirmed**, [16]).
- **Regin:** 27 victims in 14 countries: Algeria, Afghanistan, Belgium, Brazil, Fiji, Germany, Iran, India, Indonesia, Kiribati, Malaysia, Pakistan, Russia and Syria (**Confirmed**, [22]).
- **Flame:** affected countries include Iran, Lebanon, Syria and Israel; ATT&CK says it largely targeted Middle East countries (**Confirmed**, [18], [3]).
- **Gauss:** Lebanon most affected (**Confirmed**, [17]).
- **Longhorn:** 16 countries across the Middle East, Europe, Asia and Africa, plus one possibly unintended computer in the United States (**Reported**, [23]).
- **The FSB-described operation (link to Triangulation unverified):** diplomatic missions in Russia from NATO and post-Soviet states, Israel, Syria and China (**Confirmed** as the FSB's statement, [61]).

### Healthcare

Healthcare readers asked a direct question: do United States-linked actors target hospitals? In the record this study opened, no opened source records direct targeting of healthcare, and one large indirect harm appears.

The indirect harm is WannaCry. The UK National Audit Office reports that WannaCry affected at least 81 of 236 NHS trusts in England (37 of them infected) and 603 other NHS organisations, including 595 GP practices. It cost 6,912 cancelled appointments, with an estimated total over 19,000, and diverted patients at five A&E departments. Infected bodies ran unpatched or unsupported Windows despite NHS Digital patch alerts in March and April 2017, and the NAO says basic practice, including managing internet-facing firewalls, would have prevented it. The NAO page names no actor and does not mention the NSA (**Confirmed**, [39]). Microsoft wrote two days after the attack that hospitals were among those hit and that WannaCrypt used exploits stolen from the NSA (**Confirmed** as Microsoft's statement, [32]). CISA's alert, revised in June 2018, adds the United States attribution of WannaCry to North Korea, and ATT&CK links WannaCry to Lazarus Group (**Confirmed**, [35], [7]).

The 2023 National Cybersecurity Strategy also says ransomware operators have disrupted hospitals. That passage describes criminal activity, not United States state activity (**Confirmed**, [74]).

**Inferred.** In the opened record, healthcare enters the United States-attributed story only as downstream harm from a leaked exploit that another actor reused: the Shadow Brokers release, then WannaCry, then the NHS. No opened victimology for Equation, Regin or the Lamberts lists healthcare [15], [22], [25], [26], [39].

## Part 7: the government record

### The United States: law, policy and oversight

**The Vulnerabilities Equities Process.** The unclassified VEP charter of 15 November 2017 says the process exists mainly to serve the public's interest in cybersecurity by disclosing vulnerabilities the government finds. The exception is "a demonstrable, overriding interest" in using a vulnerability for lawful intelligence, law enforcement or national security purposes (**Confirmed**, [65]). The choice is not only to disclose or restrict: the charter also allows sharing mitigation information without revealing the flaw, limiting government use, telling United States and allied government entities at a classified level, and informing the vendor indirectly (**Confirmed**, [65]). The process traces to paragraph 49 of NSPD-54/HSPD-23 and is coordinated by NSC staff so that no single agency leads it. The Equities Review Board meets monthly; its members are OMB, ODNI, Treasury, State, Justice (including the FBI), DHS, Energy, Defense (including the NSA and USCYBERCOM), Commerce and the CIA. The NSA serves as Executive Secretariat. The board reassesses each restricted vulnerability every year, partner agreements and sensitive operations can constrain its decisions, and some limited categories may be excluded from review. An annual report covers 1 October to 30 September, with at least an unclassified executive summary, and the charter says "annual reporting may be provided to the Congress" (**Confirmed**, [65]). Rob Joyce's note published the same day lists four classes of interest the process weighs (defensive, intelligence and law enforcement, commercial, and international partnership), promises an annual report with metrics, and calls claims of "massive stockpiles" untrue, without giving figures (**Confirmed**, [66]).

**Defend forward.** The 2018 Defense Department Cyber Strategy summary says the department will "defend forward to disrupt or halt malicious cyber activity at its source", including below the level of armed conflict (**Reported**, quoted through Lawfare, [71], [72]). Chesney notes the summary never defines the phrase and reads it as covering out-of-network operations, often on third-country systems (**Reported**, [72]). Weinstein reports that the fact sheet names China and Russia as priorities and that 133 Cyber Mission Teams had been activated (**Reported**, [71]). The 2023 summary says the classified 2023 strategy supersedes the 2018 one, and that since 2018 the department has conducted "a significant number of cyberspace operations" under defend forward, mainly by USCYBERCOM with interagency and allied coordination, notably in defense of United States elections (**Confirmed**, [73]). It describes campaigning below armed conflict through persistent engagement while managing the risk of unintended escalation, draws on Russia's 2022 war on Ukraine, commits to continuing hunt forward operations, and calls the PRC the "pacing challenge in cyberspace" and Russia "an acute threat" (**Confirmed**, [73]).

**The national strategy.** Pillar Two of the 1 March 2023 National Cybersecurity Strategy commits to using all instruments of national power, including "military (both kinetic and cyber)", to disrupt and dismantle threat actors. It says defend forward "helped generate insights on threat actors", exposed malware and disrupted activity, and directs the Defense Department to update its strategy (**Confirmed**, [74]).

**Presidential authority.** CRS reports that the White House acknowledged in September 2018 that NSPM-13 replaced PPD-20 (2012). NSPM-13 "reportedly offers more authority to the commander of USCYBERCOM" and remains classified; the authority point is CRS reporting, not text from the memorandum (**Confirmed** as CRS's account, [70]). Chesney reports that under PPD-20, out-of-network operations against third-country systems needed substantial interagency vetting, that the 2018 change removed at least some of it, and that public reporting does not show how much (**Reported**, [72]).

**Statute and congressional oversight.** 10 U.S.C. 395, enacted by Pub. L. 115-91 sec. 1631, requires written notice to the congressional defense committees "no later than 48 hours following" a sensitive military cyber operation against a country or foreign terrorist organization where the United States is not in acknowledged hostilities; covert action is excluded (**Confirmed**, [69]). 10 U.S.C. 394, as amended by sec. 1632 of the FY2019 NDAA, treats clandestine military cyber activities as traditional military activities under the covert-action statute, says they may occur short of hostilities, and requires quarterly briefings (**Confirmed**, [67], [68]). Sec. 1642 of the same law applies when Russia, China, North Korea or Iran is found running an "active, systematic, and ongoing campaign" of attacks; the Secretary of Defense, acting through Cyber Command, may then take "appropriate and proportional action in foreign cyberspace", with notice and quarterly reports (**Confirmed**, [67], [68]). CRS adds that covert action needs a presidential finding and notice to the intelligence committees, that traditional military activities are exempt, and that the FY2018 NDAA requires notice when cyber weapons are used (**Confirmed**, [70]).

### The United States: operations on the record

| Operation | Date | What is on the record | Grade | Sources |
|---|---|---|---|---|
| Operation Glowing Symphony | Authorized 10 November 2016 | JTF-ARES against ISIS online media, described as the most complex offensive cyberspace operation USCYBERCOM had conducted; six Top Secret assessments released under FOIA (November 2016 to April 2017) | Confirmed | [75] |
| Internet Research Agency | November 2018 midterms | Cyber Command, with NSA intelligence, reportedly cut the troll farm's internet access; Cyber Command said it does not discuss classified operations; Buchanan argued the effect cannot be judged publicly | Reported | [76], [77] |
| Trickbot | 22 September and 1 October 2020 | A bogus configuration sent infected machines to a dead-end address and fake victim records were added, attributed by four anonymous officials to Cyber Command; Trickbot recovered quickly; Chesney calls it a possible extension of persistent engagement to a non-state actor | Reported | [78] |
| Trickbot (civil action) | 12 October 2020 | Microsoft's own disruption under an Eastern District of Virginia order on copyright claims, with FS-ISAC, ESET, Lumen Black Lotus Labs, NTT and Symantec | Confirmed | [79] |
| Support to Ukraine | 2018 onward; interview 1 June 2022 | Gen. Nakasone said the United States ran offensive, defensive and information operations supporting Ukraine; nine hunt-forward operations in 2021; the first Ukraine hunt-forward in 2018 | Reported | [80] |
| Hunt forward | 2023; testimony 10 April 2024 | 22 missions in 17 countries in 2023, in every geographic combatant command at once for the first time, releasing about 90 malware samples; about 50 deployments since 2018 as of September 2023 | Reported | [81] |

**Inferred.** The public United States policy record (the VEP charter, the 2018 and 2023 strategies, the 2023 national strategy, NSPM-13 as described, and 10 U.S.C. 394 and 395) frames offensive activity as disrupting adversaries below armed conflict under congressional notice and interagency review. It does not acknowledge any intrusion that vendors have named [65] to [74].

### The leaks

| Disclosure | Date | What the publisher reported | Grade | Sources |
|---|---|---|---|---|
| Verizon order | 6 June 2013 | A top-secret FISA Court order (granted 25 April 2013) requiring Verizon to give the NSA call records for all calls daily | Reported | [45] |
| PRISM | 6 June 2013 | A 41-slide presentation claiming collection directly from the servers of Google, Facebook, Apple and others; the companies denied knowledge | Reported | [46] |
| Tailored Access Operations | 29 December 2013 | Shipment interdiction to implant devices, the QUANTUM toolbox, GCHQ QUANTUMINSERT use against Belgacom staff and NSA use against OPEC staff, exploitation of weaknesses in products from Microsoft to Cisco and Huawei | Reported | [47] |
| Belgacom | 13 December 2014; 17 February 2018 | GCHQ's Operation Socialist; Belgian investigation "Trinity" unresolved after four years; sources call GCHQ responsibility beyond doubt; the UK never acknowledged a role; no NSA role established | Reported | [43], [44] |
| Shadow Brokers | 13 August 2016 onward | Tools they said came from Equation Group | Reported (leak); Confirmed (Kaspersky's code link) | [26], [27] |
| Vault 7 and Vault 8 | 7 March and 9 November 2017 | CIA Center for Cyber Intelligence documents (2013 to 2016); Hive source code | Reported | [48], [49] |

Microsoft's 14 May 2017 post is the most quoted company statement on the leaks. It says WannaCrypt used exploits stolen from the NSA, notes that CIA-held vulnerabilities had appeared on WikiLeaks, argues that governments should report vulnerabilities to vendors rather than stockpile them, and repeats Microsoft's call for a Digital Geneva Convention (**Confirmed** as Microsoft's statement, [32]). It is a vendor's statement, not a United States government confirmation.

### China

China's accusations began with Northwestern Polytechnical University (NWPU) in Xi'an. The university disclosed a phishing attack on 22 June 2022; on 5 September 2022 China's National Computer Virus Emergency Response Center (CVERC), with the company 360, accused NSA Tailored Access Operations of more than 40 cyber weapons, tens of thousands of attacks on Chinese targets and more than 140 GB taken (**Reported**, via China Daily, [51]). On 8 September 2022 Director-General Yang Tao lodged representations with the US Embassy, citing the CVERC and 360 reports; the Foreign Ministry statement gives no numbers (**Confirmed** as a statement, [52]). Secondary coverage lists tool names from the Chinese report (Fox Acid, Stoic Surgeon, Cunning Heretics, Fury Spray, OPEN Trojan) and two SunOS zero-days, several of them already public from the Snowden and Shadow Brokers material (**Reported**, [53]). SecurityWeek's 2025 summary of the case (360 tracks the actor as APT-C-40) describes four IP addresses acquired through cover entities, activity in US working hours and holidays, English keyboards, an operator error, and 41 tools of which 16 matched leaked TAO tools, and states that the allegations remain unverified by independent sources (**Reported**, [54]). Lina Lau's review frames the reports as unverified allegations with redacted indicators and lists a CVERC FoxAcid report dated 29 June 2022 and a second report around 27 September 2022 (**Reported**, [55]).

In July 2024 CVERC claimed Volt Typhoon was a fabrication of US intelligence and that the activity belonged to the Dark Power ransomware gang; ThreatMon and Trellix, whose research CVERC cited, rejected that use of their work (**Reported**, [56]). SentinelLABS assessed the third CVERC Volt Typhoon report as offering no new evidence and mainly rehashing old leaked US intelligence documents in a state-directed amplification loop (**Reported**, [57]).

In April 2025 Harbin police, via Xinhua, accused the NSA of attacks during the February 2025 Asian Winter Games and on Heilongjiang energy, transport, water, communications and defence research, put three alleged NSA staff on a wanted list and named two US universities. A CVERC report cited about 170,000 attacks during the Games. The NSA and the US Embassy did not respond (**Reported**, [58], [59]). In October 2025 China's Ministry of State Security alleged an NSA campaign against the National Time Service Center aimed at prepositioning in its ground-based timing system; an NSA official said the agency does not confirm or deny such allegations, and no allied or private-sector source corroborated it (**Reported**, [60]).

The record of China-attributed intrusions, Volt Typhoon included, has its home in [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md).

### Russia

The FSB's 1 June 2023 statement on Apple devices is described in Part 4 under Operation Triangulation (**Confirmed** as the FSB's statement, [61]; **Reported** for the responses, [62], [63]). Kaspersky attributes the chain to no one. The FSB attributes the iPhone operation it describes to US intelligence, with no technical detail, and Kaspersky said it could not verify that the two are the same activity. The record of Russia-attributed intrusions has its home in [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md).

### Iran

Iran's president acknowledged on 29 November 2010 that malicious software had caused problems for a limited number of centrifuges, without naming Stuxnet or a culprit, after earlier officials had denied harm at Natanz (**Reported**, [64]). The full Stuxnet attribution record is in [Stuxnet: The Case Study](/case-studies/STUXNET.md).

**Inferred.** The targeting record has two separate layers: vendor victimology that names no sponsor (Kaspersky on Equation, Regin, the Lamberts and Triangulation) and adversary-government attribution (the FSB, CVERC, the Ministry of State Security). A defender's threat model should keep the two apart and grade sponsor claims accordingly [15], [22], [25], [28], [61].

## Part 8: the defender view

### What the record means for a defender

Most organizations will never face a platform of Equation's or Regin's class directly, and the record shows most of these platforms used against selected targets (27 Regin victims; a small set of high-profile Lamberts targets), although Kaspersky estimates Equation's infections in the thousands or tens of thousands [15], [16], [22], [25]. The practical lessons come from three places: the tradecraft classes these platforms proved out (firmware persistence, signed-driver abuse, trust-store abuse, memory-only residence, removable-media bridging of air gaps), the downstream reuse of leaked exploits, and the long dwell times. Each of the lessons below is labelled with its basis.

### Vulnerability and exposure management

1. **A leak is a patch trigger.** MS17-010 existed 59 days before WannaCry and 105 days before NotPetya, but the KEV listings came in 2021 and 2022 [30], [35], [36], [37]. **Inferred:** an exploit-leak event that a vendor maps to existing fixes, as MSRC did within a day [31], should start an out-of-cycle remediation clock.
2. **SMBv1 is an exposure finding.** CISA's WannaCry mitigations are to patch, disable SMBv1, and block TCP 445, UDP 137 to 138 and TCP 139 at the boundary (**Confirmed**, [35]). The NAO's finding that managing internet-facing firewalls would have prevented the NHS harm points the same way (**Confirmed**, [39]). **Inferred:** SMBv1 enabled, or SMB reachable at the boundary, is a finding whatever the patch state.
3. **Credentials spread faster than exploits.** CISA calls NotPetya's harvested credentials, used through WMIC or PsExec, the first and usually most effective spreading method. Its mitigations include segmentation, blocking workstation-to-workstation traffic, least privilege and tested backups (**Confirmed**, [36]).
4. **Unsupported systems carry the risk.** The NHS bodies that were infected ran unpatched or unsupported Windows despite patch alerts in March and April 2017 (**Confirmed**, [39]). Out-of-support patches for Windows XP, Server 2003 and Windows 8 shipped on 13 May 2017, the day after WannaCry (**Confirmed**, [35]).

### Firmware, drivers and trust stores

5. **Firmware needs its own baseline.** Equation's firmware modules give persistence that survives formatting and reinstall [16]. NIST SP 800-193 frames firmware defense as protection, detection and recovery (**Confirmed**, [41]). The library's D3FEND mappings for T1542.002 Component Firmware include Firmware Verification, Firmware Behavior Analysis, Firmware Embedded Monitoring Code, Software Update, Software Inventory, Asset Vulnerability Enumeration and Restore Software (**Confirmed**, [12]).
6. **Signed is not safe.** Stuxnet's and Duqu's drivers carried valid signatures from Realtek, JMicron and C-Media [19]. Microsoft's vulnerable driver blocklist targets drivers with known kernel privilege-escalation flaws, malware, or certificates used to sign malware. It has been on by default since the Windows 11 2022 update and is enforced under HVCI, Smart App Control or S mode, and Microsoft also recommends the attack surface reduction rule that blocks abuse of exploited vulnerable signed drivers (**Confirmed**, [40]). The library has no D3FEND rows for T1553.002 Code Signing (**Confirmed**, [12]), so this control comes from the vendor, not the mapping.
7. **Watch the roots.** Flame's certificate chained to the Microsoft Root through the Terminal Server Licensing hierarchy, which Microsoft then reissued on a chain that cannot be used for code signing [33], [34]. **Inferred:** changes to trusted roots and intermediates belong in change monitoring alongside software inventory.

### Hunting and eviction

8. **Hunt for dwell.** Regin samples date back to 2003 and Equation infrastructure to 2001 [15], [22]. Both platforms hid stages in encrypted virtual file systems, in the registry, in NTFS extended attributes or on raw disk [16], [22]. **Inferred:** integrity baselines and behaviour hunting find this class of implant; indicator sweeps from a single report rarely do.
9. **Coordinate memory-only eviction.** Duqu 2.0 lived almost entirely in memory and re-infected from high-uptime servers [21]. **Inferred:** eviction needs a domain-wide coordinated reboot or reimage together with credential resets, or the survivors re-infect the cleaned hosts.
10. **Removable media still crosses air gaps.** Fanny mapped air-gapped networks through hidden storage on USB sticks, and Flame and Stuxnet spread by removable media [16], [3], [2]. The library's D3FEND mappings for T1091 are IO Port Restriction and Hardware Component Inventory (**Confirmed**, [12]).

### For healthcare organizations

The NHS case is the healthcare playbook in miniature: an exploit leaked by one party, weaponized by another, and landing on unsupported and unpatched Windows behind poorly managed boundaries [39]. **Inferred:** a hospital's priorities from this record are an inventory of unsupported Windows (including medical-device hosts), SMBv1 shutdown, boundary SMB blocking, segmentation that stops workstation-to-workstation spread, and an emergency patch process that starts when a leak is mapped to fixes, not when a catalog catches up.

### Library corrections

Three hand-written library pages state attribution more strongly than any source this study opened, without a citation:

- MALWARE_FAMILIES.md line 257 gives Stuxnet's actor as "Equation Group (attributed US NSA / Israel Unit 8200)", and line 258 gives Regin's as "Attributed NSA / GCHQ (Five Eyes)" (**Confirmed**, [10]).
- NOTABLE_INCIDENTS.md's 2016 to 2017 Shadow Brokers section names the target as the NSA's Equation Group (TAO division) (**Confirmed**, [82]).
- CVE_REFERENCE.md's EternalBlue entry gives its origin as the NSA and the leak date as 14 April 2017 (**Confirmed**, [83]).

These should either cite the source of the attribution (for example the leak journalism or Microsoft's statement, graded as such) or adopt ATT&CK's neutral wording. The library's THREAT_ACTORS.md does not mention Equation, Regin, Duqu, Flame or EternalBlue at all (**Confirmed**, checked in the library at main `e85b559`); this study fills that gap.

### What is overstated and what is understated

- **Overstated: "NSA malware" labels on Stuxnet and Regin.** No vendor primary this study opened names a country for either platform, and ATT&CK names no sponsor (**Confirmed**, [1] to [6], [15] to [29]).
- **Overstated: adversary-government accusations as evidence.** The Chinese and Russian statements published no evidence an independent party has confirmed, and SentinelLABS finds the Chinese reports rehash old leaked documents (**Reported**, [54], [57], [62]).
- **Understated: downstream reuse of leaked exploits against healthcare.** The NHS harm in May 2017 came from WannaCry's reuse of a leaked exploit, not from any platform in this study (**Confirmed** for the NHS harm, [39]; the weight it deserves is **Inferred**).
- **Understated: firmware and trust-store persistence outside scanner coverage.** Equation's firmware implants, signed drivers and Flame's forged certificate sit where most vulnerability programs do not look (**Confirmed** for the techniques, [16], [19], [34]; the coverage gap is **Inferred**).

## Part 9: MITRE mappings

The tables below bind every technique, object, weakness, attack pattern and countermeasure this study discusses to an ATT&CK, CAPEC, CWE or D3FEND id. Every ATT&CK id was checked against the library's v20.0 data, and every Enterprise id has a generated page; none is in `data/attack/superseded_by.jsonl` (**Confirmed**, [9]). No technique below is an attribution claim: ATT&CK attributes none of these objects to any country.

### Enterprise techniques recorded by ATT&CK

The 85 Enterprise techniques ATT&CK v20.0 records for the six objects in Part 1 (112 technique and tactic pairs). Equation contributes 4, Regin 11, Duqu 21, Flame 10, Stuxnet 44 and Green Lambert 18. Two techniques are recorded for three objects: T1016 System Network Configuration Discovery (Duqu, Stuxnet, Green Lambert) and T1021.002 SMB/Windows Admin Shares (Regin, Duqu, Stuxnet). Nineteen are recorded for two. Stealth is the busiest tactic (25 pairs), then privilege escalation (16), persistence (15), discovery (14) and command and control (13) (**Confirmed**, computed from [9], [11]). "Dated reference" is the dated source ATT&CK cites for the object; ATT&CK does not say which reference supports each individual technique.

| ID | Technique | Tactic (v20.0) | Recorded for | Dated reference ATT&CK cites for the object | Sources |
|---|---|---|---|---|---|
| [T1001.002](/mitre/techniques/T1001-002.md) | Steganography | Command and Control | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1005](/mitre/techniques/T1005.md) | Data from Local System | Collection | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1008](/mitre/techniques/T1008.md) | Fallback Channels | Command and Control | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1010](/mitre/techniques/T1010.md) | Application Window Discovery | Discovery | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1011.001](/mitre/techniques/T1011-001.md) | Exfiltration Over Bluetooth | Exfiltration | Flame | vendor reports, May 2012 | [3] [18] |
| [T1012](/mitre/techniques/T1012.md) | Query Registry | Discovery | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1014](/mitre/techniques/T1014.md) | Rootkit | Stealth | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1016](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | Duqu, Stuxnet, Green Lambert | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 / Green Lambert: Kaspersky, Apr 2017; Sandvik, 2021 | [2] [4] [6] [25] |
| [T1021](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1021.002](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | Lateral Movement | Regin, Duqu, Stuxnet | Regin: Kaspersky, Nov 2014 / Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] [5] [22] |
| [T1027](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1027.013](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | Stealth | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1036.001](/mitre/techniques/T1036-001.md) | Invalid Code Signature | Stealth | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1036.004](/mitre/techniques/T1036-004.md) | Masquerade Task or Service | Stealth | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1036.005](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | Stealth | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1036.010](/mitre/techniques/T1036-010.md) | Masquerade Account Name | Stealth | Flame | vendor reports, May 2012 | [3] [18] |
| [T1037.004](/mitre/techniques/T1037-004.md) | RC Scripts | Persistence, Privilege Escalation | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1041](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1047](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1049](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1053.005](/mitre/techniques/T1053-005.md) | Scheduled Task | Execution, Persistence, Privilege Escalation | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1055.001](/mitre/techniques/T1055-001.md) | Dynamic-link Library Injection | Stealth, Privilege Escalation | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1055.012](/mitre/techniques/T1055-012.md) | Process Hollowing | Stealth, Privilege Escalation | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1056.001](/mitre/techniques/T1056-001.md) | Keylogging | Collection, Credential Access | Regin, Duqu | Regin: Kaspersky, Nov 2014 / Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] [5] [22] |
| [T1057](/mitre/techniques/T1057.md) | Process Discovery | Discovery | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1059.004](/mitre/techniques/T1059-004.md) | Unix Shell | Execution | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1068](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1070](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1070.004](/mitre/techniques/T1070-004.md) | File Deletion | Stealth | Stuxnet, Green Lambert | Stuxnet: Symantec dossier, Feb 2011 / Green Lambert: Kaspersky, Apr 2017; Sandvik, 2021 | [2] [6] [25] |
| [T1070.006](/mitre/techniques/T1070-006.md) | Timestomp | Stealth | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1071](/mitre/techniques/T1071.md) | Application Layer Protocol | Command and Control | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1071.001](/mitre/techniques/T1071-001.md) | Web Protocols | Command and Control | Regin, Stuxnet | Regin: Kaspersky, Nov 2014 / Stuxnet: Symantec dossier, Feb 2011 | [2] [5] [22] |
| [T1071.002](/mitre/techniques/T1071-002.md) | File Transfer Protocols | Command and Control | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1071.004](/mitre/techniques/T1071-004.md) | DNS | Command and Control | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1074.001](/mitre/techniques/T1074-001.md) | Local Data Staging | Collection | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1078.001](/mitre/techniques/T1078-001.md) | Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1078.002](/mitre/techniques/T1078-002.md) | Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1080](/mitre/techniques/T1080.md) | Taint Shared Content | Lateral Movement | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1082](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | Stuxnet, Green Lambert | Stuxnet: Symantec dossier, Feb 2011 / Green Lambert: Kaspersky, Apr 2017; Sandvik, 2021 | [2] [6] [25] |
| [T1083](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1087.001](/mitre/techniques/T1087-001.md) | Local Account | Discovery | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1087.002](/mitre/techniques/T1087-002.md) | Domain Account | Discovery | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1090](/mitre/techniques/T1090.md) | Proxy | Command and Control | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1090.001](/mitre/techniques/T1090-001.md) | Internal Proxy | Command and Control | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1090.002](/mitre/techniques/T1090-002.md) | External Proxy | Command and Control | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1091](/mitre/techniques/T1091.md) | Replication Through Removable Media | Lateral Movement, Initial Access | Flame, Stuxnet | Flame: vendor reports, May 2012 / Stuxnet: Symantec dossier, Feb 2011 | [2] [3] [18] |
| [T1095](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | Command and Control | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1106](/mitre/techniques/T1106.md) | Native API | Execution | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1112](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | Regin, Stuxnet | Regin: Kaspersky, Nov 2014 / Stuxnet: Symantec dossier, Feb 2011 | [2] [5] [22] |
| [T1113](/mitre/techniques/T1113.md) | Screen Capture | Collection | Flame | vendor reports, May 2012 | [3] [18] |
| [T1120](/mitre/techniques/T1120.md) | Peripheral Device Discovery | Discovery | Equation, Stuxnet | Equation: Kaspersky Q&A, Feb 2015 / Stuxnet: Symantec dossier, Feb 2011 | [1] [2] [16] |
| [T1123](/mitre/techniques/T1123.md) | Audio Capture | Collection | Flame | vendor reports, May 2012 | [3] [18] |
| [T1124](/mitre/techniques/T1124.md) | System Time Discovery | Discovery | Stuxnet, Green Lambert | Stuxnet: Symantec dossier, Feb 2011 / Green Lambert: Kaspersky, Apr 2017; Sandvik, 2021 | [2] [6] [25] |
| [T1129](/mitre/techniques/T1129.md) | Shared Modules | Execution | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1132.001](/mitre/techniques/T1132-001.md) | Standard Encoding | Command and Control | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1134](/mitre/techniques/T1134.md) | Access Token Manipulation | Stealth, Privilege Escalation | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1134.001](/mitre/techniques/T1134-001.md) | Token Impersonation/Theft | Stealth, Privilege Escalation | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1135](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1136.001](/mitre/techniques/T1136-001.md) | Local Account | Persistence | Flame | vendor reports, May 2012 | [3] [18] |
| [T1140](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | Stuxnet, Green Lambert | Stuxnet: Symantec dossier, Feb 2011 / Green Lambert: Kaspersky, Apr 2017; Sandvik, 2021 | [2] [6] [25] |
| [T1210](/mitre/techniques/T1210.md) | Exploitation of Remote Services | Lateral Movement | Flame, Stuxnet | Flame: vendor reports, May 2012 / Stuxnet: Symantec dossier, Feb 2011 | [2] [3] [18] |
| [T1218.007](/mitre/techniques/T1218-007.md) | Msiexec | Stealth | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1218.011](/mitre/techniques/T1218-011.md) | Rundll32 | Stealth | Flame | vendor reports, May 2012 | [3] [18] |
| [T1480](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1480.001](/mitre/techniques/T1480-001.md) | Environmental Keying | Stealth | Equation | Kaspersky Q&A, Feb 2015 | [1] [16] |
| [T1505.001](/mitre/techniques/T1505-001.md) | SQL Stored Procedures | Persistence | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1518.001](/mitre/techniques/T1518-001.md) | Security Software Discovery | Discovery | Flame, Stuxnet | Flame: vendor reports, May 2012 / Stuxnet: Symantec dossier, Feb 2011 | [2] [3] [18] |
| [T1542.002](/mitre/techniques/T1542-002.md) | Component Firmware | Stealth, Persistence | Equation | Kaspersky Q&A, Feb 2015 | [1] [16] |
| [T1543.001](/mitre/techniques/T1543-001.md) | Launch Agent | Persistence, Privilege Escalation | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1543.003](/mitre/techniques/T1543-003.md) | Windows Service | Persistence, Privilege Escalation | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1543.004](/mitre/techniques/T1543-004.md) | Launch Daemon | Persistence, Privilege Escalation | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1546.004](/mitre/techniques/T1546-004.md) | Unix Shell Configuration Modification | Privilege Escalation, Persistence | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1547.002](/mitre/techniques/T1547-002.md) | Authentication Package | Persistence, Privilege Escalation | Flame | vendor reports, May 2012 | [3] [18] |
| [T1547.015](/mitre/techniques/T1547-015.md) | Login Items | Persistence, Privilege Escalation | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1553.002](/mitre/techniques/T1553-002.md) | Code Signing | Defense Impairment | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1555.001](/mitre/techniques/T1555-001.md) | Keychain | Credential Access | Green Lambert | Kaspersky, Apr 2017; Sandvik, 2021 | [6] [25] |
| [T1560.003](/mitre/techniques/T1560-003.md) | Archive via Custom Method | Collection | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1564.004](/mitre/techniques/T1564-004.md) | NTFS File Attributes | Stealth | Regin | Kaspersky, Nov 2014 | [5] [22] |
| [T1564.005](/mitre/techniques/T1564-005.md) | Hidden File System | Stealth | Equation, Regin | Equation: Kaspersky Q&A, Feb 2015 / Regin: Kaspersky, Nov 2014 | [1] [5] [16] [22] |
| [T1570](/mitre/techniques/T1570.md) | Lateral Tool Transfer | Lateral Movement | Stuxnet | Symantec dossier, Feb 2011 | [2] |
| [T1572](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | Duqu | Symantec, Nov 2011; Kaspersky, Jun 2015 | [4] |
| [T1573.001](/mitre/techniques/T1573-001.md) | Symmetric Cryptography | Command and Control | Duqu, Stuxnet | Duqu: Symantec, Nov 2011; Kaspersky, Jun 2015 / Stuxnet: Symantec dossier, Feb 2011 | [2] [4] |
| [T1685](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | Stuxnet | Symantec dossier, Feb 2011 | [2] |

### Enterprise techniques stated by vendor and government primaries

These are the procedures a primary describes in its own words for a technique ATT&CK also records. They tie the table above to dated events.

| ID | Procedure as the primary describes it | Dated event or report | Sources |
|---|---|---|---|
| [T1542.002](/mitre/techniques/T1542-002.md) | EquationDrug and GrayFish hard-drive firmware reprogramming modules, compiled 2010 and 2013 | Kaspersky Q&A, February 2015 | [16] |
| [T1564.005](/mitre/techniques/T1564-005.md) | GrayFish's encrypted virtual file system inside the Windows registry; Regin's encrypted virtual file systems | Kaspersky, February 2015 and November 2014 | [16], [22] |
| [T1564.004](/mitre/techniques/T1564-004.md) | Regin stages hidden in NTFS extended attributes | Kaspersky, 24 November 2014 | [22] |
| [T1480.001](/mitre/techniques/T1480-001.md) | DoubleFantasy validates the target before later stages | Kaspersky Q&A, February 2015 | [16] |
| [T1553.002](/mitre/techniques/T1553-002.md) | Stuxnet driver signed with Realtek's, then JMicron's key | CrySyS, 14 October 2011 | [19], [2] |
| [T1210](/mitre/techniques/T1210.md) | MS10-061 and MS08-067 (Stuxnet), MS10-061 (Flame); (downstream reuse, not the actor layer) EternalBlue and EternalRomance (WannaCry and NotPetya reuse) | Symantec dossier, February 2011; May 2012; CISA, 12 May and 1 July 2017 | [2], [3], [35], [36] |
| [T1091](/mitre/techniques/T1091.md) | Stuxnet USB spread through autorun or CVE-2010-2568; Flame USB autorun | February 2011; May 2012 | [2], [3] |
| [T1068](/mitre/techniques/T1068.md) | Stuxnet privilege escalation through MS10-073 and a Task Scheduler flaw | Symantec dossier, February 2011 | [2] |
| [T1021.002](/mitre/techniques/T1021-002.md) | Duqu spread to shares with stolen credentials and scheduled tasks; Stuxnet network shares | November 2011; February 2011 | [4], [2] |
| [T1011.001](/mitre/techniques/T1011-001.md) | Flame's BeetleJuice Bluetooth module | May 2012 | [3] |

### Enterprise techniques inferred by this study

| ID | Technique | Basis | Grade |
|---|---|---|---|
| [T1195](/mitre/techniques/T1195.md) | Supply Chain Compromise | Kaspersky's account of a trojanized conference CD-ROM substituted in the mail (2009) [16], and Der Spiegel's account of leaked TAO documents on intercepting shipments to implant devices [47]. ATT&CK records this technique for none of the six objects | Inferred |
| [T1553.002](/mitre/techniques/T1553-002.md) | Code Signing (for Flame) | Flame's forged code-signing certificate from the Terminal Server Licensing hierarchy [33], [34]. ATT&CK records T1553.002 for Stuxnet, not Flame | Inferred |
| [T1553.002](/mitre/techniques/T1553-002.md) | Code Signing (for Duqu) | Duqu's driver carried a C-Media signature (CrySyS, 14 October 2011) [19]. ATT&CK records T1553.002 for Stuxnet, not Duqu | Inferred |
| [T1068](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation (for Duqu 2.0 and Fanny) | Duqu 2.0's kernel zero-day CVE-2015-2360 [21] and Fanny's MS09-025 kernel flaw [16]. Neither has its own ATT&CK object | Inferred |
| [T1091](/mitre/techniques/T1091.md) | Replication Through Removable Media (for Fanny) | Fanny's USB-borne mapping of air-gapped networks [16] | Inferred |

### ICS techniques

ATT&CK records three ICS techniques for Duqu and two for Flame (**Confirmed**, [3], [4]). The library has no generated ICS technique pages, so these link to ATT&CK.

| ID | Technique | ICS tactic | Recorded for | Sources |
|---|---|---|---|---|
| [T0811](https://attack.mitre.org/techniques/T0811/) | Data from Information Repositories | Collection | Duqu | [4] |
| [T0893](https://attack.mitre.org/techniques/T0893/) | Data from Local System | Collection | Duqu, Flame | [3], [4] |
| [T0882](https://attack.mitre.org/techniques/T0882/) | Theft of Operational Information | Impact | Duqu, Flame | [3], [4] |

Stuxnet's 25 ICS techniques, all present in the library's `data/attack/ics/technique_profiles.jsonl`, are T1701.002, T0885, T0866, T0874, T0877, T1694.002, T0867, T0835, T0831, T0832, T0849, T0821, T0836, T0889, T0801, T0834, T0842, T0843, T0873.001, T0886, T0888, T0847, T0851, T0869 and T0863 (**Confirmed**, [2], [9]). Their names, tactics and procedures are tabled in [Stuxnet: The Case Study](/case-studies/STUXNET.md), which is the home for that mapping. No ATT&CK for Mobile object covers Operation Triangulation in the library's data (**Confirmed**, [9]).

### Groups, campaigns and software

| Object | ATT&CK id | Library page | Role in this study |
|---|---|---|---|
| Equation | G0020 | [/mitre/groups/G0020.md](/mitre/groups/G0020.md) | Group; 4 techniques; no aliases, no software, no sponsor [1], [14] |
| Regin | S0019 | [/mitre/software/S0019.md](/mitre/software/S0019.md) | Software; 11 techniques; no group [5] |
| Duqu | S0038 | [/mitre/software/S0038.md](/mitre/software/S0038.md) | Software; 21 Enterprise and 3 ICS techniques; no group [4] |
| Flame | S0143 | [/mitre/software/S0143.md](/mitre/software/S0143.md) | Software; 10 Enterprise and 2 ICS techniques; no group [3] |
| Stuxnet | S0603 | [/mitre/software/S0603.md](/mitre/software/S0603.md) | Software; 44 Enterprise and 25 ICS techniques; no group; home study [Stuxnet](/case-studies/STUXNET.md) [2] |
| Green Lambert | S0690 | [/mitre/software/S0690.md](/mitre/software/S0690.md) | Software; 18 techniques; the Lamberts and Longhorn named in the text, no group object [6] |
| WannaCry | S0366 | [/mitre/software/S0366.md](/mitre/software/S0366.md) | Context only: reused EternalBlue; linked to Lazarus Group [7] |
| Lazarus Group | G0032 | [/mitre/groups/G0032.md](/mitre/groups/G0032.md) | Context only: ATT&CK's group for WannaCry [7] |
| NotPetya | S0368 | [/mitre/software/S0368.md](/mitre/software/S0368.md) | Context only: reused EternalBlue and EternalRomance [8] |
| Sandworm Team | G0034 | [/mitre/groups/G0034.md](/mitre/groups/G0034.md) | Context only: ATT&CK's group for NotPetya; home study [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) [8] |
| Campaigns | none | none | ATT&CK has no campaign object for Stuxnet, Flame, Regin, Equation or Triangulation in the library's data [9] |

### CWE and CAPEC

NVD assigns no CWE to CVE-2017-0144 or CVE-2010-2568 (NVD-CWE-noinfo) and assigns CWE-20 (Improper Input Validation) to CVE-2010-2729, the MS10-061 Print Spooler flaw used by Stuxnet and Flame (**Confirmed**, [38]). See the library's [CWE Reference](/CWE_REFERENCE.md).

The library maps these CAPEC attack patterns to the study's techniques (**Confirmed**, [13]):

| CAPEC | Name | Technique |
|---|---|---|
| [CAPEC-638](/mitre/capec/CAPEC-638.md) | Altered Component Firmware | T1542.002 |
| [CAPEC-68](/mitre/capec/CAPEC-68.md) | Subvert Code-signing Facilities | T1553.002 |
| [CAPEC-206](/mitre/capec/CAPEC-206.md) | Signing Malicious Code | T1553.002 |
| [CAPEC-473](/mitre/capec/CAPEC-473.md) | Signature Spoof | T1036.001, T1553.002 |
| [CAPEC-457](/mitre/capec/CAPEC-457.md) | USB Memory Attacks | T1091 |
| [CAPEC-552](/mitre/capec/CAPEC-552.md) | Install Rootkit | T1014 |
| [CAPEC-561](/mitre/capec/CAPEC-561.md) | Windows Admin Shares with Stolen Credentials | T1021.002 |
| [CAPEC-478](/mitre/capec/CAPEC-478.md) | Modification of Windows Service Configuration | T1543.003 |

### D3FEND countermeasures

The library's `technique_to_d3fend.jsonl` maps these countermeasures to the techniques the defender view relies on (**Confirmed**, [12]). T1553.002 Code Signing and T1021.002 SMB/Windows Admin Shares have no D3FEND rows in the library's data, and none are invented here.

| Technique | D3FEND countermeasures (library pages) |
|---|---|
| T1542.002 Component Firmware | [Firmware Verification](/mitre/d3fend/firmware-verification.md), [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md), [Firmware Embedded Monitoring Code](/mitre/d3fend/firmware-embedded-monitoring-code.md), [Software Update](/mitre/d3fend/software-update.md), [Software Inventory](/mitre/d3fend/software-inventory.md), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), [Restore Software](/mitre/d3fend/restore-software.md) |
| T1210 Exploitation of Remote Services | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), and others in the library's data |
| T1091 Replication Through Removable Media | [IO Port Restriction](/mitre/d3fend/io-port-restriction.md), [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) |
| T1036.001 Invalid Code Signature | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md), [Executable Denylisting](/mitre/d3fend/executable-denylisting.md), [File Analysis](/mitre/d3fend/file-analysis.md) |
| T1014 Rootkit | [Firmware Verification](/mitre/d3fend/firmware-verification.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Software Update](/mitre/d3fend/software-update.md) |

### Navigator layer

The study's techniques are collected in an ATT&CK Navigator layer, [`navigator/library-layers/threat-actors-united-states.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-united-states.json), listed with the library's other curated layers on the [Navigator layers page](/navigator/index.md). Open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/threat-actors-united-states.json). Scores mean membership, not frequency or severity: the number of the six objects ATT&CK v20.0 records the technique for (1 to 3), and 0 for T1195, the one inferred technique that ATT&CK records for none of the six objects. Each technique's comment names the objects and the study's source numbers. The layer is not an attribution claim, and WannaCry and NotPetya are left out because they are downstream reuse.

## Cross-cutting themes

1. **Attribution by absence.** The library's studies of [China](/case-studies/THREAT_ACTORS_CHINA.md), [Russia](/case-studies/THREAT_ACTORS_RUSSIA.md), Iran and North Korea can point to indictments or joint advisories. This one cannot, and the honest summary is that the United States record is a technical record with an attribution gap filled by leaks and adversaries. Readers who see "NSA" or "CIA" attached to a malware name should ask who said so and what grade that source deserves.
2. **Leaks change who holds the weapon.** The heaviest harm in this record came after tools left their makers: the April 2017 release fed WannaCry and NotPetya, which the United States itself attributes to North Korea and Russia [35], [36]. The VEP charter weighs disclosure against operational use [65]; Microsoft's 2017 argument is that leaks make that weighing a public safety question [32].
3. **Trust infrastructure is the target.** Firmware, signed drivers, a Microsoft certificate hierarchy, a GSM base station controller, Apple's hardware protections: the platforms in this record went after the layers defenders rely on to decide what is trustworthy [16], [19], [22], [29], [34].
4. **Accusations as policy.** SentinelLABS describes China's Volt Typhoon reports as a state-directed amplification loop that rehashes old leaked documents [57]; Russia's 2023 statement likewise gave no technical detail [62]. They may be right about some intrusions; the point for a defender is that none has been independently verified [54], [62].
5. **Patching is not the end of the story.** The fix for EternalBlue existed before the leak, yet the exploit hit unpatched and unsupported systems, including NHS hospitals, in May 2017 [39], and KEV still flags these CVEs for known ransomware use [37]. Exposure (SMBv1 on, SMB at the boundary, unsupported Windows) mattered as much as the CVE.

## Sources

All sources were opened on 3 November 2026. Grades follow the scheme in Scope and method: a primary opened is Confirmed for what it says; press, commentary and publishers' descriptions of leaked material are Reported. The two Symantec posts ([23], [27]) are graded Reported: the Longhorn post did not load on a second attempt the same day, so its figures are carried alongside CyberScoop [24], and the August 2016 post is used only alongside Kaspersky's analysis of the same dump [26].

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | MITRE ATT&CK, G0020 Equation (v1.2, modified 31 July 2026) | https://attack.mitre.org/groups/G0020/ | 2026-11-03 | Confirmed |
| 2 | MITRE ATT&CK, S0603 Stuxnet (v1.5, modified 24 April 2026) | https://attack.mitre.org/software/S0603/ | 2026-11-03 | Confirmed |
| 3 | MITRE ATT&CK, S0143 Flame (v1.1, modified 16 April 2025) | https://attack.mitre.org/software/S0143/ | 2026-11-03 | Confirmed |
| 4 | MITRE ATT&CK, S0038 Duqu (v1.2, modified 16 April 2025) | https://attack.mitre.org/software/S0038/ | 2026-11-03 | Confirmed |
| 5 | MITRE ATT&CK, S0019 Regin (v1.2, modified 1 October 2023) | https://attack.mitre.org/software/S0019/ | 2026-11-03 | Confirmed |
| 6 | MITRE ATT&CK, S0690 Green Lambert (v1.0, created 21 March 2022) | https://attack.mitre.org/software/S0690/ | 2026-11-03 | Confirmed |
| 7 | MITRE ATT&CK, S0366 WannaCry | https://attack.mitre.org/software/S0366/ | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, S0368 NotPetya | https://attack.mitre.org/software/S0368/ | 2026-11-03 | Confirmed |
| 9 | TeamStarWolf library, ATT&CK v20.0 data under data/attack (main e85b559) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-03 | Confirmed |
| 10 | TeamStarWolf library, MALWARE_FAMILIES.md | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/MALWARE_FAMILIES.md | 2026-11-03 | Confirmed |
| 11 | TeamStarWolf library, data/attack/software_to_technique.jsonl | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software_to_technique.jsonl | 2026-11-03 | Confirmed |
| 12 | TeamStarWolf library, data/attack/technique_to_d3fend.jsonl | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl | 2026-11-03 | Confirmed |
| 13 | TeamStarWolf library, data/weaknesses/capec.jsonl | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/capec.jsonl | 2026-11-03 | Confirmed |
| 14 | TeamStarWolf library, generated page mitre/groups/G0020.md | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/groups/G0020.md | 2026-11-03 | Confirmed |
| 15 | Kaspersky GReAT, "Equation: The Death Star of Malware Galaxy", 16 February 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-03 | Confirmed |
| 16 | Kaspersky GReAT, "Equation Group: Questions and Answers" v1.5, February 2015 (PDF) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-03 | Confirmed |
| 17 | Kaspersky, "Gauss: Abnormal Distribution", 9 August 2012 | https://securelist.com/gauss-abnormal-distribution/36620/ | 2026-11-03 | Confirmed |
| 18 | Kaspersky, "The Flame: Questions and Answers", 28 May 2012 | https://securelist.com/the-flame-questions-and-answers/34344/ | 2026-11-03 | Confirmed |
| 19 | CrySyS Lab, "Duqu: A Stuxnet-like malware found in the wild" v0.93, 14 October 2011 (PDF) | https://static.crysys.hu/publications/files/bencsathPBF11duqu.pdf | 2026-11-03 | Confirmed |
| 20 | Kaspersky, "The Mystery of Duqu 2.0", 10 June 2015 | https://securelist.com/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/70504/ | 2026-11-03 | Confirmed |
| 21 | Kaspersky, "The Mystery of Duqu 2.0" technical paper, 11 June 2015 (PDF) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07205202/The_Mystery_of_Duqu_2_0_a_sophisticated_cyberespionage_actor_returns.pdf | 2026-11-03 | Confirmed |
| 22 | Kaspersky, "Regin: nation-state ownage of GSM networks", 24 November 2014 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-03 | Confirmed |
| 23 | Symantec, "Longhorn: Tools used by cyberespionage group linked to Vault 7", 10 April 2017 | https://www.security.com/threat-intelligence/longhorn-cyberespionage-vault7 | 2026-11-03 | Reported |
| 24 | CyberScoop, on Symantec's Longhorn report, 10 April 2017 | https://cyberscoop.com/symantec-links-cia-mysterious-espionage-group-hacked-40-organizations-globally/ | 2026-11-03 | Reported |
| 25 | Kaspersky GReAT, "Unraveling the Lamberts Toolkit", 11 April 2017 | https://securelist.com/unraveling-the-lamberts-toolkit/77990/ | 2026-11-03 | Confirmed |
| 26 | Kaspersky, "The Equation giveaway", 16 August 2016 | https://securelist.com/the-equation-giveaway/75812/ | 2026-11-03 | Confirmed |
| 27 | Symantec, on the Equation cyberespionage group breach, 16 August 2016 | https://www.security.com/threat-intelligence/equation-cyberespionage-group-breached | 2026-11-03 | Reported |
| 28 | Kaspersky, "Operation Triangulation", 1 June 2023 | https://securelist.com/operation-triangulation/109842/ | 2026-11-03 | Confirmed |
| 29 | Kaspersky, "Operation Triangulation: The last (hardware) mystery", 27 December 2023 | https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/ | 2026-11-03 | Confirmed |
| 30 | Microsoft Security Bulletin MS17-010, 14 March 2017 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010 | 2026-11-03 | Confirmed |
| 31 | MSRC, "Protecting customers and evaluating risk", 15 April 2017 | https://www.microsoft.com/en-us/msrc/blog/2017/04/protecting-customers-and-evaluating-risk | 2026-11-03 | Confirmed |
| 32 | Microsoft On the Issues, "The need for urgent collective action to keep people safe online", 14 May 2017 | https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/ | 2026-11-03 | Confirmed |
| 33 | Microsoft Security Advisory 2718704, 3 June 2012 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704 | 2026-11-03 | Confirmed |
| 34 | MSRC, "Flame malware collision attack explained", 6 June 2012 | https://www.microsoft.com/en-us/msrc/blog/2012/06/flame-malware-collision-attack-explained | 2026-11-03 | Confirmed |
| 35 | CISA alert TA17-132A, Indicators Associated With WannaCry Ransomware, 12 May 2017 (revised 7 June 2018) | https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware | 2026-11-03 | Confirmed |
| 36 | CISA alert TA17-181A, Petya Ransomware, 1 July 2017 (revised 15 February 2018) | https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware | 2026-11-03 | Confirmed |
| 37 | CISA Known Exploited Vulnerabilities catalog (JSON feed) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-03 | Confirmed |
| 38 | NVD API record, CVE-2017-0144 (with CVE-2010-2568 and CVE-2010-2729) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144 | 2026-11-03 | Confirmed |
| 39 | UK National Audit Office, "Investigation: WannaCry cyber attack and the NHS" | https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/ | 2026-11-03 | Confirmed |
| 40 | Microsoft Learn, "Microsoft recommended driver block rules" (updated 8 October 2026) | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules | 2026-11-03 | Confirmed |
| 41 | NIST SP 800-193, Platform Firmware Resiliency Guidelines, May 2018 | https://csrc.nist.gov/pubs/sp/800/193/final | 2026-11-03 | Confirmed |
| 42 | The Intercept (Marquis-Boire, Guarnieri, Gallagher), on Regin, Belgacom and the NSA and GCHQ, 24 November 2014 | https://theintercept.com/2014/11/24/secret-regin-malware-belgacom-nsa-gchq/ | 2026-11-03 | Reported |
| 43 | The Intercept, inside story of the Belgacom hack, 13 December 2014 | https://theintercept.com/2014/12/13/belgacom-hack-gchq-inside-story/ | 2026-11-03 | Reported |
| 44 | The Intercept, on the Belgian Belgacom investigation, 17 February 2018 | https://theintercept.com/2018/02/17/gchq-belgacom-investigation-europe-hack/ | 2026-11-03 | Reported |
| 45 | The Guardian (Greenwald), on the Verizon FISA Court order, 6 June 2013 | https://www.theguardian.com/world/2013/jun/06/nsa-phone-records-verizon-court-order | 2026-11-03 | Reported |
| 46 | The Guardian (Greenwald, MacAskill), on PRISM, 6 June 2013 | https://www.theguardian.com/world/2013/jun/06/us-tech-giants-nsa-data | 2026-11-03 | Reported |
| 47 | Der Spiegel, on NSA Tailored Access Operations tooling, 29 December 2013 | https://www.spiegel.de/international/world/the-nsa-uses-powerful-toolbox-in-effort-to-spy-on-global-networks-a-940969.html | 2026-11-03 | Reported |
| 48 | WikiLeaks, Vault 7 "Year Zero", 7 March 2017 | https://wikileaks.org/ciav7p1/ | 2026-11-03 | Reported |
| 49 | WikiLeaks, Vault 8, 9 November 2017 | https://wikileaks.org/vault8/ | 2026-11-03 | Reported |
| 50 | NPR via MPR News, on the Vault 7 leaker's 40-year sentence, 1 February 2024 | https://www.mprnews.org/story/2024/02/01/npr-former-cia-engineer-sentenced-40-years-wikileaks | 2026-11-03 | Reported |
| 51 | China Daily, on the CVERC and 360 NWPU report, 5 September 2022 | https://enapp.chinadaily.com.cn/a/202209/05/AP6315a262a310a1c5959c4062.html | 2026-11-03 | Reported |
| 52 | Ministry of Foreign Affairs of the People's Republic of China, statement on the NWPU attack, 8 September 2022 | https://www.mfa.gov.cn/eng/wjb/zzjg_663340/bmdyzs_664814/xwlb_664816/202209/t20220913_10765505.html | 2026-11-03 | Confirmed (as a statement) |
| 53 | The Hacker News, on China's accusation against the NSA's TAO unit, 12 September 2022 | https://thehackernews.com/2022/09/china-accuses-nsas-tao-unit-of-hacking.html | 2026-11-03 | Reported |
| 54 | SecurityWeek, "How China pinned university cyberattacks on NSA hackers", 21 February 2025 | https://www.securityweek.com/how-china-pinned-university-cyberattacks-on-nsa-hackers/ | 2026-11-03 | Reported |
| 55 | Lina Lau (Inversecos), review of the Chinese NWPU reports, February 2025 | https://www.inversecos.com/2025/02/an-inside-look-at-nsa-equation-group.html | 2026-11-03 | Reported |
| 56 | The Record, on CVERC's Volt Typhoon claims, 8 July 2024 | https://therecord.media/china-cyber-agency-claims-us-interference-volt-typhoon-research | 2026-11-03 | Reported |
| 57 | SentinelLABS (Dakota Cary), on China's Volt Typhoon influence operations, October 2024 | https://www.sentinelone.com/labs/chinas-influence-ops-twisting-tales-of-volt-typhoon-at-home-and-abroad/ | 2026-11-03 | Reported |
| 58 | Nextgov, on Harbin police and the Asian Winter Games, 15 April 2025 | https://www.nextgov.com/cybersecurity/2025/04/chinese-police-say-nsa-hacked-networks-asian-winter-games/404569 | 2026-11-03 | Reported |
| 59 | Al Jazeera, on China's Asian Winter Games accusation, 15 April 2025 | https://www.aljazeera.com/news/2025/4/15/china-accuses-us-of-launching-cyberattacks-during-asian-winter-games | 2026-11-03 | Reported |
| 60 | The Record, on the National Time Service Center allegation, October 2025 | https://therecord.media/china-attack-national-time-center | 2026-11-03 | Reported |
| 61 | FSB of Russia, press statement, 1 June 2023 | http://www.fsb.ru/fsb/press/message/single.htm!id=10439739@fsbMessage.html | 2026-11-03 | Confirmed (as a statement) |
| 62 | The Record, on Russia's accusation over Apple devices, 1 June 2023 | https://therecord.media/russia-accusses-us-of-hacking-apple-devices-to-spy-on-diplomats | 2026-11-03 | Reported |
| 63 | The Register, on the FSB, Apple and Kaspersky, 1 June 2023 | https://www.theregister.com/2023/06/01/fsb_apple_nsa_spyware_kaspersky/ | 2026-11-03 | Reported |
| 64 | Christian Science Monitor, on Ahmadinejad and Stuxnet, 30 November 2010 | https://www.csmonitor.com/USA/2010/1130/Stuxnet-Ahmadinejad-admits-cyberweapon-hit-Iran-nuclear-program | 2026-11-03 | Reported |
| 65 | White House, Vulnerabilities Equities Policy and Process for the United States Government (unclassified VEP charter), 15 November 2017 (PDF) | https://trumpwhitehouse.archives.gov/sites/whitehouse.gov/files/images/External%20-%20Unclassified%20VEP%20Charter%20FINAL.PDF | 2026-11-03 | Confirmed |
| 66 | White House (Rob Joyce), on improving and making the VEP transparent, 15 November 2017 | https://trumpwhitehouse.archives.gov/articles/improving-making-vulnerability-equities-process-transparent-right-thing/ | 2026-11-03 | Confirmed |
| 67 | Public Law 115-232, John S. McCain National Defense Authorization Act for Fiscal Year 2019, 13 August 2018 | https://www.congress.gov/115/plaws/publ232/PLAW-115publ232.htm | 2026-11-03 | Confirmed |
| 68 | 10 U.S.C. 394 with statutory notes (Cornell LII) | https://www.law.cornell.edu/uscode/text/10/394 | 2026-11-03 | Confirmed |
| 69 | 10 U.S.C. 395 (Cornell LII) | https://www.law.cornell.edu/uscode/text/10/395 | 2026-11-03 | Confirmed |
| 70 | Congressional Research Service, IF10537, Defense Primer: Cyberspace Operations (v12, 29 November 2024), via the everycrsreport.com mirror | https://www.everycrsreport.com/reports/IF10537.html | 2026-11-03 | Confirmed |
| 71 | Lawfare (Dave Weinstein), "The Pentagon's New Cyber Strategy: Defend Forward", 21 September 2018 | https://www.lawfaremedia.org/article/pentagons-new-cyber-strategy-defend-forward | 2026-11-03 | Reported |
| 72 | Lawfare (Robert Chesney), on the 2018 DoD Cyber Strategy, the NDAA and PPD-20 changes, 25 September 2018 | https://www.lawfaremedia.org/article/2018-dod-cyber-strategy-understanding-defense-forward-light-ndaa-and-ppd-20-changes | 2026-11-03 | Reported |
| 73 | Department of Defense, 2023 Cyber Strategy Summary, 12 September 2023 (PDF; the original at media.defense.gov returned 403, so the identical file was read from this Internet Archive capture) | https://web.archive.org/web/20241226235705id_/https://media.defense.gov/2023/Sep/12/2003299076/-1/-1/1/2023_DOD_Cyber_Strategy_Summary.PDF | 2026-11-03 | Confirmed |
| 74 | White House, National Cybersecurity Strategy, 1 March 2023 (PDF) | https://bidenwhitehouse.archives.gov/wp-content/uploads/2023/03/National-Cybersecurity-Strategy-2023.pdf | 2026-11-03 | Confirmed |
| 75 | National Security Archive, briefing book 693, USCYBERCOM after-action assessments of Operation Glowing Symphony, 21 January 2020 | https://nsarchive.gwu.edu/briefing-book/cyber-vault/2020-01-21/uscybercom-after-action-assessments-operation-glowing-symphony | 2026-11-03 | Confirmed |
| 76 | Lawfare (Ben Buchanan), on Cyber Command's operation against the Internet Research Agency, February 2019 | https://www.lawfaremedia.org/article/what-make-cyber-commands-operation-against-internet-research-agency | 2026-11-03 | Reported |
| 77 | NBC News, on the 2018 midterm operation against the Internet Research Agency, 26 February 2019 | https://www.nbcnews.com/politics/national-security/trump-approved-operation-disabled-russian-troll-farm-during-2018-midterms-n976381 | 2026-11-03 | Reported |
| 78 | Krebs on Security, "Report: U.S. Cyber Command Behind Trickbot Tricks", October 2020 | https://krebsonsecurity.com/2020/10/report-u-s-cyber-command-behind-trickbot-tricks/ | 2026-11-03 | Reported |
| 79 | Microsoft On the Issues (Tom Burt), on the Trickbot disruption, 12 October 2020 | https://blogs.microsoft.com/on-the-issues/2020/10/12/trickbot-ransomware-cyberthreat-us-elections/ | 2026-11-03 | Confirmed |
| 80 | The Register, on Gen. Nakasone and operations supporting Ukraine, 2 June 2022 | https://www.theregister.com/2022/06/02/nakasone_us_hacking_russia/ | 2026-11-03 | Reported |
| 81 | The Record, on Cyber Command's 2023 hunt-forward missions and Gen. Haugh's testimony, April 2024 | https://therecord.media/cyber-command-hunt-forward-missions-2023-haugh-senate | 2026-11-03 | Reported |
| 82 | TeamStarWolf library, NOTABLE_INCIDENTS.md | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/NOTABLE_INCIDENTS.md | 2026-11-03 | Confirmed |
| 83 | TeamStarWolf library, CVE_REFERENCE.md | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/CVE_REFERENCE.md | 2026-11-03 | Confirmed |

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
- [CWE Reference](/CWE_REFERENCE.md)
- [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- ATT&CK group page: [G0020 Equation](/mitre/groups/G0020.md)
- ATT&CK software pages: [S0019 Regin](/mitre/software/S0019.md), [S0038 Duqu](/mitre/software/S0038.md), [S0143 Flame](/mitre/software/S0143.md), [S0603 Stuxnet](/mitre/software/S0603.md), [S0690 Green Lambert](/mitre/software/S0690.md), [S0366 WannaCry](/mitre/software/S0366.md), [S0368 NotPetya](/mitre/software/S0368.md)
- Key technique pages: [T1542.002 Component Firmware](/mitre/techniques/T1542-002.md), [T1564.005 Hidden File System](/mitre/techniques/T1564-005.md), [T1480.001 Environmental Keying](/mitre/techniques/T1480-001.md), [T1553.002 Code Signing](/mitre/techniques/T1553-002.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1091 Replication Through Removable Media](/mitre/techniques/T1091.md), [T1021.002 SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md)
- [Navigator layers](/navigator/index.md)
- [All case studies](/case-studies/README.md)
