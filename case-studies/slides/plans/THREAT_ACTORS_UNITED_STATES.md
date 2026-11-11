# Slide plan: United States-Attributed Threat Actors: The Public Record

- Study: case-studies/THREAT_ACTORS_UNITED_STATES.md
- Cover title: United States-Attributed / Threat Actors / The Public Record
- Subtitle: Deep technical reports, no named sponsor, and leaked exploits that did the most harm
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/THREAT_ACTORS_UNITED_STATES.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The technical record is deep, and the attribution record is thin

- No vendor report this study opened attributes these platforms to the United States, and ATT&CK attributes none to any country.
- Kaspersky says a likely nation-state for Regin and Flame and names none; Symantec points only to an English-speaking North American country.
- National attribution rests on leak journalism, adversary-government statements and one Vault 7 conviction.
- The heaviest harm came from reuse: April 2017 Shadow Brokers exploits fed WannaCry and NotPetya (Inferred).
- For healthcare, that downstream path is the whole United States-linked story in the opened record (Inferred).
Caption: Grades: vendor technical findings are Confirmed; every claim naming a US agency as operator is Reported or an adversary statement.
Notes: Platforms and vendor wording [15] to [29]; ATT&CK [1] to [6] [9]. Microsoft's statement that WannaCrypt used exploits stolen from the NSA concerns leaked exploits, not these platforms [32]. Symantec Longhorn [23][24]. Conviction [50]. Reuse [31][35][36]; NHS [39].

## KEY FACTS | Six ATT&CK objects, 85 techniques and no named sponsor

Stat: 6 | ATT&CK objects: one group, five software
Stat: 0 | sponsors named by ATT&CK or the vendors
Stat: 85 | Enterprise techniques ATT&CK records for them
Stat: 81 of 236 | NHS trusts in England hit by WannaCry
- Earliest dated activity: an Equation C2 domain registered August 2001; samples compiled from 2002.
- Regin sample timestamps reach back to 2003; a 64-bit infection was still active in spring 2014.
- Court record: a former CIA engineer convicted in July 2022 and sentenced to 40 years (Reported).
- The United States acknowledges no named intrusion; its strategy, statute and Glowing Symphony are on record.
Notes: Objects and sponsor wording [1] to [6] [9] [22] [23] [24]. 85 techniques in 112 technique and tactic pairs [9][11]. Earliest [15][16]; Regin [22]. Sentencing 1 February 2024 [50]. Overt record [65][67] to [70][73][75]. NHS [39].

## PART 1 | ATT&CK holds one group and five tools, and no sponsor for any

| Id | Name | Enterprise / ICS | What ATT&CK says about who |
|---|---|---|---|
| G0020 | Equation | 4 / 0 | "a sophisticated threat group"; no country |
| S0603 | Stuxnet | 44 / 25 | No country, no group |
| S0143 | Flame | 10 / 2 | Largely Middle East targets; no sponsor |
| S0038 | Duqu | 21 / 3 | No sponsor |
| S0019 | Regin | 11 / 0 | No sponsor |
| S0690 | Green Lambert | 18 / 0 | "an advanced threat group"; no country |
Caption: No group object for Longhorn, Vault 7 or the Shadow Brokers, and no campaign object for Stuxnet, Flame, Regin or Equation.
Notes: Live pages [1] to [6]; library scan [9]. Vendor first reports: Duqu 14 Oct 2011 (CrySyS), Flame 28 May 2012, Gauss 9 Aug 2012, Regin 24 Nov 2014, Equation 16 Feb 2015, Duqu 2.0 10 Jun 2015, Longhorn 10 Apr 2017 (Symantec, Reported), Lamberts 11 Apr 2017, Triangulation 1 Jun 2023 [15] to [29]. No primary opened merges these names into one NSA or CIA bucket.

## PART 2 | Four kinds of source, and only some of them can name a sponsor

| Source type | What it can establish | What it cannot |
|---|---|---|
| Vendor research | Tooling, victims, timelines, links between toolsets | A sponsor: none names a country |
| Leaks and leak journalism, 2013 to 2017 | What the documents, as published, say | That a named agency ran a given intrusion |
| Foreign government statements | What a government alleges or admits, and when | The allegation: none independently confirmed |
| United States overt record | Policy, authority, oversight, a few operations | Any vendor-named intrusion |
Caption: The Vault 7 conviction is the closest the record comes to official confirmation the material was genuine (Inferred).
Notes: Vendors [15] to [29]; leaks [42] to [49]; foreign statements [51] to [64]; overt record [65] to [81]. Conviction at a July 2022 trial after a 2020 trial deadlocked on the top counts; Judge Jesse M. Furman imposed 40 years on 1 February 2024 [50].

## PART 3 | From an Equation domain in 2001 to a Chinese allegation in 2025

| Date | Event |
|---|---|
| Aug 2001 | First Equation command-and-control domain registered |
| 2010 | Stuxnet discovered; components in use from November 2008 |
| 28 May 2012 | Kaspersky discloses Flame |
| 24 Nov 2014 | Kaspersky's Regin analysis: 27 victims in 14 countries |
| 16 Feb 2015 | Kaspersky discloses the Equation group |
| 13 Aug 2016 | Shadow Brokers post a sample archive (Reported) |
| 7 Mar 2017 | WikiLeaks publishes Vault 7 "Year Zero" (Reported) |
| 12 May 2017 | WannaCry spreads with the MS17-010 exploit |
| 1 Jun 2023 | Triangulation disclosed; the FSB blames US intelligence |
| 19 Oct 2025 | China's MSS alleges an NSA time-center campaign (Reported) |
Caption: Eras: the silent decade, vendors (2010 to 2015), leaks (2013 to 2017), policy (2017 to 2024), accusations (2022 to 2025).
Notes: Rows [15][16][2][18][22][26][27][48][35][28][61][60]. Era reading from the study's own Part 3 summary. Most of the 2001 to 2010 activity was dated later from timestamps, registrations and logs [22][43].

## PART 4 | The platforms went after firmware, registries and a GSM network

Left: Equation and Regin
- Equation firmware modules: EquationDrug (2010, six drive categories) and GrayFish (2013, twelve).
- GrayFish keeps an encrypted file system inside the Windows registry.
- Fanny mapped air-gapped networks with two zero-days later seen in Stuxnet.
- Regin: 27 victims in 14 countries and a GSM base station controller log of 136 cells.
Right: Flame, Duqu and Triangulation
- Flame's MD5 collision forged a code-signing certificate chained to the Microsoft Root.
- Gauss, on the Flame platform: about 2,500 PCs, more than 1,600 in Lebanon.
- Duqu 2.0 breached Kaspersky with CVE-2015-2360 and lived almost entirely in memory.
- Triangulation: four iOS zero-days and an undocumented hardware feature.
Caption: Kaspersky counts more than 500 Equation victims and suggests tens of thousands of infections over time.
Notes: Equation and Fanny [15][16]; Regin [22]; Flame certificate [33][34]; Gauss [17]; Duqu and Duqu 2.0 [19][20][21]; Triangulation [28][29]. Stuxnet is summarized from its home study STUXNET.md [2].

## PART 4 | Leaks put working exploits in public hands, and reuse followed

Stat: 1 day | for MSRC to map the April 2017 dump to fixes
Stat: 59 days | from MS17-010 to WannaCry
Stat: 105 days | from MS17-010 to NotPetya
Stat: 8,761 | Vault 7 documents and files (Reported)
- Kaspersky linked the August 2016 dump to Equation code with high confidence; Symantec treated it as not proven.
- MSRC mapped EternalBlue, EternalChampion, EternalRomance and EternalSynergy to MS17-010.
- Symantec matched Longhorn's Corentry and Plexor tools to Vault 7 documents (Reported).
- Vault 8, from 9 November 2017, published Hive source code (Reported).
Caption: WannaCry and NotPetya are downstream reuse; the US attributes them to North Korea and the Russian military.
Notes: MS17-010 published 14 March 2017 [30]; MSRC mapping 15 April 2017 [31]; WannaCry 12 May 2017 [35]; NotPetya 27 June 2017 [8][36]; day counts are arithmetic on those dates. Dump analysis: 347 RC5/RC6 implementations, more than 300 files with an Equation-only RC6 variant [26][27]. Longhorn [23][24]. Vault 7 and 8 [48][49].

## PART 5 | The EternalBlue fixes came first, and KEV listed them years later

Stat: 6 | MS17-010 CVEs in KEV, all flagged for ransomware use
Stat: ~5 yrs | from use at scale to EternalBlue's KEV listing
Stat: 4 | iOS zero-days in the Triangulation chain
- Fanny and Stuxnet shared CVE-2010-2568, the LNK flaw KEV added on 15 September 2022.
- Stuxnet and Flame both used the MS10-061 print spooler flaw, CVE-2010-2729.
- Equation's exploit list held TrueType, Internet Explorer and Java flaws, at least four as zero-days.
- NVD assigns EternalBlue no CWE (NVD-CWE-noinfo), so claim none for it.
Caption: KEV dates are catalog additions, not exploitation dates: EternalBlue was used at internet scale in May 2017.
Notes: KEV additions: CVE-2017-0143 on 3 Nov 2021; -0144 and -0145 on 10 Feb 2022; -0146 on 25 Mar 2022; -0148 on 6 Apr 2022; -0147 on 24 May 2022 [37]. MS17-010 [30]. LNK and spooler [16][2][3][37][84][85]. Equation exploits [16]. NVD CWE [38][84][85]. Triangulation [29].

## PART 6 | Healthcare enters only downstream, through WannaCry and the NHS

Stat: 81 of 236 | NHS trusts in England affected
Stat: 595 | GP practices among 603 other NHS bodies
Stat: 6,912 | appointments cancelled; estimate 19,000+
Stat: 5 | A&E departments diverting patients
- No opened victimology for Equation, Regin or the Lamberts lists healthcare.
- Infected bodies ran unpatched or unsupported Windows despite March and April 2017 patch alerts.
- The NAO says basic practice, including managing internet-facing firewalls, would have prevented it.
- CISA attributes WannaCry to North Korea, and ATT&CK links it to Lazarus Group.
Caption: The opened sources record no direct targeting of healthcare; the harm came from reuse (Inferred).
Notes: NAO figures, 37 of the 81 trusts infected [39]. Sector lists [15][22][25]. Attribution [35][7]. Microsoft named hospitals among those hit [32]. The 2023 strategy's ransomware passage describes criminals [74].

## PART 7 | Washington writes down a posture and admits no named intrusion

Left: Law and policy
- VEP charter, 15 Nov 2017: disclose unless a "demonstrable, overriding interest".
- 10 U.S.C. 395: notice to Congress within 48 hours of a sensitive military cyber operation.
- 2018 and 2023 strategies: defend forward; the PRC is the "pacing challenge in cyberspace".
- 2023 national strategy: disrupt threat actors with all instruments of national power.
Right: Operations on the record
- Glowing Symphony against ISIS media, authorized 10 Nov 2016 (declassified).
- The troll farm's internet access reportedly cut on 2018 Election Day (Reported).
- Trickbot disruption, reportedly by Cyber Command, Sep to Oct 2020 (Reported).
- 22 hunt-forward missions in 17 countries in 2023 (Reported).
Caption: NSPM-13 replaced PPD-20 in 2018 and is classified; CRS reports it gives Cyber Command more authority.
Notes: VEP [65][66]; statutes [67][68][69]; strategies [71][72][73]; national strategy [74]; NSPM-13 [70][72]. Glowing Symphony [75]; Internet Research Agency [76][77]; Trickbot [78] with Microsoft's civil action [79]; hunt forward [81]; Ukraine support [80].

## PART 7 | China and Russia accuse the NSA; no independent party confirms it

| Date | Accuser | Allegation | Independent view |
|---|---|---|---|
| 5 Sep 2022 | CVERC and 360 | NSA TAO behind the NWPU attack | Unverified, per SecurityWeek |
| 1 Jun 2023 | FSB | US iPhone operation; Apple cooperation | Kaspersky cannot verify; Apple denies |
| 8 Jul 2024 | CVERC | Volt Typhoon is a US fabrication | ThreatMon and Trellix reject it |
| 15 Apr 2025 | Harbin police | NSA attacks on the Asian Winter Games | No NSA or embassy response |
| 19 Oct 2025 | MSS | NSA campaign on the time center | NSA neither confirms nor denies |
Caption: Iran's president acknowledged centrifuge damage in November 2010 and named no worm and no culprit (Reported).
Notes: NWPU [51][52][53][54][55]; China's Foreign Ministry statement of 8 Sep 2022 gives no numbers [52]; SecurityWeek counts 41 tools, 16 matching leaked TAO tools [54]. FSB [61][62][63]. Volt Typhoon [56]; SentinelLABS on the third report, October 2024 [57]. Harbin [58][59]. Time center [60]. Iran [64].

## MITRE MAPPINGS | 85 techniques for six objects, and none is an attribution claim

| Id | Technique | Recorded for |
|---|---|---|
| T1016 | System Network Configuration Discovery | Duqu, Stuxnet, Green Lambert |
| T1021.002 | SMB/Windows Admin Shares | Regin, Duqu, Stuxnet |
| T1542.002 | Component Firmware | Equation |
| T1564.005 | Hidden File System | Equation, Regin |
| T1553.002 | Code Signing | Stuxnet; Flame and Duqu inferred |
| T1091 | Replication Through Removable Media | Flame, Stuxnet |
Caption: Stealth leads with 25 technique-tactic pairs; layer scores count objects, 1 to 3, and 0 for T1195. MITRE notice in notes.
Notes: 85 techniques in 112 pairs: Equation 4, Regin 11, Duqu 21, Flame 10, Stuxnet 44, Green Lambert 18; then privilege escalation 16, persistence 15, discovery 14, command and control 13 [9][11]. ICS: Duqu 3, Flame 2, Stuxnet 25 [2][3][4]. Inferred T1195, T1553.002 for Flame and Duqu, T1068 and T1091 for Fanny [16][47][33][34][19][21]. CAPEC-638 for T1542.002 [13]; no D3FEND rows for T1553.002 [12]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Treat a leak as a patch trigger and inventory what scanners miss

Left: Exposure and patching
- Move fixes a vendor maps to a leak to emergency service levels that week.
- Disable SMBv1; block TCP 445, UDP 137 to 138 and TCP 139 at the boundary.
- Segment, block workstation-to-workstation traffic and test backups.
- Inventory unsupported Windows, including medical-device hosts.
Right: Firmware, drivers and hunting
- Baseline firmware under NIST SP 800-193: protect, detect, recover.
- Enforce the Microsoft vulnerable driver blocklist.
- Alert on changes to trusted roots and intermediates.
- Evict memory-only implants with a coordinated reboot and credential resets.
Caption: SMBv1 enabled, or SMB reachable at the boundary, is a finding whatever the patch state (Inferred).
Notes: Leak trigger, Inferred from [31][37]. SMB [35]. Credentials and segmentation [36]. Unsupported Windows [39][35]. Firmware [41][16]; drivers [40][19]; roots, Inferred from [33][34]; memory-only eviction, Inferred from [21]. Hunt for dwell [15][22].

## CROSS-CUTTING THEMES | Ask who said so, then patch what leaked

- **Attribution by absence.** No indictments or advisories, just a technical record with a gap that leaks and adversaries fill.
- **Leaks change who holds the weapon.** The April 2017 release fed WannaCry and NotPetya.
- **Trust infrastructure is the target.** Firmware, signed drivers, a certificate hierarchy, a base station, Apple hardware.
- **Accusations as policy.** None of the Chinese or Russian claims has been independently verified.
- **Patching is not the end.** Exposure mattered as much as the CVE.
Notes: Themes [35][36][65][32][16][19][22][29][34][57][54][62][39][37]. Library corrections: MALWARE_FAMILIES.md, NOTABLE_INCIDENTS.md and CVE_REFERENCE.md state attribution without a citation [10][82][83]. Overstated: "NSA malware" labels and adversary accusations as evidence; understated: downstream reuse against healthcare and firmware outside scanner coverage.
