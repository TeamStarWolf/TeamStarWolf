# Slide plan: The Dot-Com Era: Cyber Events, 1994 to 2003

- Study: case-studies/DOTCOM_ERA_CYBER_EVENTS.md
- Cover title: The Dot-Com Era / Cyber Events, / 1994 to 2003
- Subtitle: From Citibank to Blaster: the decade the profession learned to patch, name and notify
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/DOTCOM_ERA_CYBER_EVENTS.md, told from the CERT/CC, Microsoft, NVD, DOJ, statute, SEC, Senate and CAIDA record. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The decade's worms used holes that already had a fix

- **Code Red, Slammer and Blaster** each followed a Microsoft bulletin by 26 days to six months.
- **Melissa used no vulnerability:** it needed a person to open a document.
- **Speed outran people:** Slammer doubled about every 8.5 seconds in its first minute.
- **The institutions came fast:** CVE, PDD-63, Budapest, Trustworthy Computing, SB 1386, CAN-SPAM.
- **The quiet story was espionage:** Moonlight Maze ran from 1996 and is still only partly public.
Caption: Grades: worms, fixes, prosecutions, statutes and filings Confirmed; CAIDA data Demonstrated; most damage figures Reported.
Notes: Bulletins [32][38][43], advisories [21][33][40], CAIDA and Moore et al. [35][41][42], institutions [59][72][70][67][92][77], Moonlight Maze [13]. The fix-to-outbreak gaps are computed from the dated records and graded Inferred.

## KEY FACTS | Three worm CVEs, three fixes, and one very fast doubling time

Stat: 359,104 | hosts infected by Code Red v2 in under 14 hours
Stat: 10 min | for Slammer to reach over 90% of vulnerable hosts
Stat: 26 days | from MS03-026 to the Blaster advisory
Stat: 321 | records in the CVE List at its September 1999 launch
- CVE-2001-0500 (Code Red, MS01-033), CVE-2002-0649 (Slammer, MS02-039), CVE-2003-0352 (Blaster, MS03-026).
- NVD lists CWE-119 for CVE-2002-0649 only; the other two carry NVD-CWE-Other.
- NASDAQ Composite: 5,048.62 peak close on 10 March 2000, 1,114.11 low close on 9 October 2002.
Notes: CAIDA [34][35], Moore et al. [41], CAIDA Sapphire analysis [42], bulletins [32][38][43], NVD [39], CVE history [59], FRED [79].

## PART 1 | From Citibank to CAN-SPAM in ten years

| Date | Event | Grade |
|---|---|---|
| 1994 | Levin's Citibank transfers begin | Reported |
| 1996 | Moonlight Maze intrusions begin | Confirmed |
| Feb 1998 | Solar Sunrise on DoD networks | Reported |
| 26 Mar 1999 | Melissa reports begin | Confirmed |
| 7 to 8 Feb 2000 | Yahoo, Amazon, eBay, CNN floods | Reported |
| 19 Jul 2001 | Code Red v2 | Confirmed |
| 25 Jan 2003 | Slammer | Confirmed |
| 11 Aug 2003 | Blaster advisory CA-2003-20 | Confirmed |
Caption: The full timeline in the study runs from a 1978 DEC message to the 2005 Blaster sentence.
Notes: Part 1. Citibank [1], Moonlight Maze [13], Solar Sunrise [10], Melissa [21], February 2000 [23][24], Code Red [34], Slammer [41][40], Blaster [40].

## PART 2 | The intrusions: teenagers in the headlines, espionage in the logs

Left: Loud
- Solar Sunrise, 1998: two California teenagers and one Israeli teenager.
- DOJ: no sign of a state campaign.
- Mitnick: 46 months on the 1999 plea.
Right: Quiet
- Moonlight Maze from 1996: military, research and university networks.
- Relayed through hacked servers; SPARC Solaris and MIPS IRIX binaries.
- A Turla link is premature, in the researchers' own words.
Caption: The Mitnick record lives in its own study; this deck summarizes it in one line.
Notes: DOJ release on Tenenbaum [9], GlobalSecurity profile [10], Mitnick sentencing [3], Kaspersky and King's College London [13], ATT&CK G0010 and S0587 pages [14].

## PART 2 | Hackers testified and Back Orifice needed no flaw

- **19 May 1998:** seven L0pht members testify to the Senate under their handles, three days before PDD-63.
- **21 July 1998:** cDc announces Back Orifice, a remote-control tool for Windows.
- **The tool hides** from the task list, reruns at startup and can log keystrokes.
- **Microsoft, 4 August 1998:** it exploits no Windows flaw and must be installed to work.
Caption: Both statements are true at once: no vulnerability, and full remote control running unseen.
Notes: Senate hearing record [15] and Thompson's statement [16]; PDD-63 [72]; cDc press release and tool page [17][18]; MS98-010 [19], the vendor's position. The reading is Inferred.

## PART 3 | Mail and macros: Melissa, ILOVEYOU and the law that came too late

Left: Melissa, 1999
- Word macro mailed to 50 contacts.
- No new vulnerability used.
- Smith: 20 months in 2002.
- $80 million was his plea figure.
Right: ILOVEYOU, 2000
- VBScript worm, 4 May 2000.
- 500,000 systems reported by 8 May.
- RA 8792 passed 14 June 2000.
- Charges dismissed in August.
Notes: CA-1999-04 [21], DOJ sentencing [22], CA-2000-04 [29], RA 8792 [30], New York Times on the dismissal [31], Reported.

## PART 3 | Code Red, Nimda, Slammer and Blaster rode known, fixed flaws

| Worm | Fix | Outbreak | Gap |
|---|---|---|---|
| Code Red | MS01-033, 18 Jun 2001 | Jul 2001 | About 4 weeks |
| Slammer | MS02-039, 24 Jul 2002 | 25 Jan 2003 | About 6 months |
| Blaster | MS03-026, 16 Jul 2003 | 11 Aug 2003 | 26 days |
Caption: Nimda added five paths at once, including the backdoors other worms left behind.
Notes: Bulletins [32][38][43], CERT/CC advisories [33][40][50], CAIDA [35]. Gaps computed from the dated records, Inferred. Nimda per CA-2001-26 [33].

## PART 3 | Patching came only after the pain

Stat: 32 to 64% | infected hosts patched, before and after the 1 August resurgence
Stat: 37 min | Code Red doubling time
Stat: 8.5 sec | Slammer doubling time in its first minute
- **CAIDA's conclusion in 2002:** techniques other than host patching are required to mitigate worms.
- **Defaults multiplied the damage:** IIS on by default, RPCSS on by default, null Administrator passwords.
Notes: CAIDA patch survey [35], Moore et al. [41], CAIDA Sapphire [42], MS01-033 [32], MS03-026 [43], CA-2003-08 [40].

## PART 4 | E-commerce learned that it carried the fraud bill

- **CD Universe, 1999 to 2000:** stolen card data, an extortion demand, then a public posting.
- **eUniverse could not say** whether its insurance covered the theft.
- **Egghead.com, 2000:** merchants bear card-not-present losses even when issuers approve.
- **The Invita sting:** Gorshkov got 36 months and Ivanov 48 for theft and extortion.
- **Spam became an industry:** over half of all email by 2003, per Congress.
Notes: eUniverse filings [82][83][84], Egghead.com 10-K and 8-K [85][86], DOJ releases [87][88], CAN-SPAM findings [77].

## PART 5 | The law and policy record was built in a five-year burst

| Year | Instrument |
|---|---|
| 1998 | PDD-63: critical infrastructure and ISACs |
| 2001 | Budapest Convention, ETS 185 |
| 2002 | Homeland Security Act and FISMA |
| 2003 | National Strategy to Secure Cyberspace |
| 2003 | California SB 1386 operative |
| 2003 | CAN-SPAM Act approved |
Caption: The CFAA was amended in 1994, 1996, 2001 and 2002 as well.
Notes: PDD-63 [72], Budapest [70][71], Homeland Security Act [73], DHS [74], National Strategy [75][76], SB 1386 [92], CAN-SPAM [77], CFAA notes [69].

## MITRE MAPPINGS | 36 ATT&CK techniques read back onto a pre-ATT&CK decade

| Id | Technique | Where |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Melissa, Love Letter |
| T1190 | Exploit Public-Facing Application | Code Red, Slammer |
| T1210 | Exploitation of Remote Services | Blaster |
| T1495 | Firmware Corruption | CIH |
| T1498.001 | Direct Network Flood | TFN2K, Code Red, Blaster |
| T1219 | Remote Access Tools | Back Orifice |
| T1078.001 | Default Accounts | CA-2003-08 |
Caption: Layer scores: 100 a Confirmed primary record, 60 Reported only, 40 the id choice stretches the record.
Notes: Part 7. T1562.001 was revoked in v20.0 and maps to T1685 through data/attack/superseded_by.jsonl [96]. CWE-119 [39]; CAPEC-100 [96]. Not an official MITRE mapping. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | What the era still teaches a vulnerability program

Left: Close the known hole
- Patch on a clock, not an outbreak.
- Track time from fix to deploy.
- Use CVE ids in every ticket.
- Publish a disclosure timeline.
Right: Assume it lands anyway
- Segment so one host cannot reach all.
- Filter spoofed traffic at the edge.
- Change default and weak passwords.
- Treat macros as an execution path.
Notes: Bulletins [32][38][43]; CERT/CC filtering advice [51][54][29]; CA-2003-08 [40]; CA-1999-04 [49]; CVE proposal [58]; CERT/CC disclosure policy [64]. The program framing is Inferred.

## CROSS-CUTTING THEMES | Overstated damage, understated defaults

- **Overstated:** the damage figures, Solar Sunrise as a state attack, Moonlight Maze as Turla.
- **Overstated:** Back Orifice as a Windows flaw, and the breach as the cause of Egghead's bankruptcy.
- **Understated:** patching and defaults as the root cause of the big worms.
- **Understated:** Moonlight Maze itself, and ILOVEYOU's effect on Philippine law.
- **Understated:** the government's own counts, such as 150,000 Code Red systems against 359,104.
Notes: The overstated and understated passage of the study [22][35][27][28][9][10][13][14][19][86][30][31][75]. The reading is the study's own judgment, graded Inferred.
