# Slide plan: The Year 1995 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1995.md
- Cover title: The Year 1995 / in Intrusions / A Dated Record
- Subtitle: Forged addresses, a public scanner and the first macro virus on shipped media
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1995.md, told from the CERT/CC advisories, CIAC bulletins, GAO reports, Justice Department releases, FBI histories, court records, statutes and the NIST, RFC, BSI and NVD records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year trust by network address failed in public

- **Spoofing:** CERT warned in January that forged addresses beat host trust and hijacked sessions.
- **Infrastructure:** by June, 170 spoofing attacks, at least 80 against routers and name servers.
- **Automation:** a public scanner in April, mass scanning of known flaws in December.
- **Documents:** Concept, the first Word macro virus seen spreading, shipped on vendor media.
- **Defenders:** SSH 1.0, S/KEY, IPsec, SHA-1 and BS 7799 all date to 1995.
Caption: Grades: CERT, CIAC, GAO, Justice, FBI, courts, NIST, RFC, BSI and NVD records Confirmed; Virus Bulletin and press Reported.
Notes: CA-95:01 [1][3]. Spoofing heads-up [13]. SATAN [69][70]. CA-95:18 [1]. Concept [18][19][20], Reported. SSH [77], S/KEY [78], IPsec [66], FIPS 180-1 [61], BS 7799 [82].

## KEY FACTS | Four numbers from the primary record

Stat: 18 | CERT/CC advisories, CA-95:01 to CA-95:18
Stat: 170 | IP spoofing attacks reported in a few weeks
Stat: 559 | attacks on Defense systems reported in 1995
Stat: 4% | of DISA's successful test intrusions detected
- CERT/CC logged 2,412 incident reports in 1995, against 2,341 in 1994.
- DISA's extrapolation of as many as 250,000 attacks is an estimate, not a count.
- No identifier system defenders use today existed: CVE began in 1999, ATT&CK in 2015.
Notes: CERT compilation [1][2]. Heads-up [13]. DISA figures via GAO [40][41]. CERT statistics [44]. CVE history [72], ATT&CK design paper [85].

## PART 1 | The year in date order, from spoofing to the December wave

| Date | Event |
|---|---|
| 23 Jan | CA-95:01 IP spoofing and hijacked sessions |
| 15 Feb | FBI arrests Kevin Mitnick |
| 15 Feb | BS 7799-1 published |
| 5 Apr | SATAN released |
| 17 Apr | FIPS 180-1, SHA-1, issued |
| 29 Jun | CERT heads-up: spoofing hits infrastructure |
| 12 Jul | SSH 1.0 announced |
| 15 Aug | Export-grade SSL challenge broken |
| Sep | Concept analysed in Virus Bulletin |
| 11 Oct | Netscape announces a Bugs Bounty |
| 18 Dec | CA-95:18 Widespread Attacks |
Notes: CA-95:01 [1][3]. Mitnick [5][6]. BS 7799 [82]. SATAN [69][11]. FIPS 180-1 [61]. Heads-up [13]. SSH [77]. SSL break [35][14]. Concept [18], Reported. Bounty [36][37], Reported. CA-95:18 [1].

## PART 2 | Exploits were public before the advisories

- **Published first:** NCSA httpd, Solaris ps, loadmodule and rpc.ypupdated exploits circulated.
- **Actively exploited:** Sun sendmail -oR, syslog via sendmail, SGI accounts, wu-ftpd builds.
- **December wave:** hundreds of sites, many root compromises, all through advised flaws.
- **CVE records came later:** NVD's 25 records dated 1995 are back-dated CVE-1999 ids.
Caption: The December wave as the earliest record of patch latency at scale is the study's reading (Inferred).
Notes: Part 2. The 18 advisories [1]. Spoofing heads-up [13]. NVD date query [73]. CVE pairings by date and description [74][75], Inferred.

## PART 2 | SATAN made scanning a public, dual-use tool

Left: The tool
- Released 5 April.
- Probes finger, NFS, NIS, ftp, rexd.
- Can wander outside its domain.
- Needed its own fix, CA-95:07a.
Right: The answer
- CERT reviewed it in advance.
- COPS, ISS, TCP wrappers, Swatch.
- CIAC's Courtney flags probes.
- Port-scan detectors at COAST.
Caption: CERT said the flaws SATAN checks were not new; an easy tool raised the threat to unpatched sites.
Notes: CA-95:06 and CA-95:07a [1]. SATAN authors' summary [70]. Release [11], Reported; CIAC F-20 [69]. COAST archive [71].

## PART 3 | A Navy detection led to the first computer wiretap

- **Late August:** a Navy center traced an intrusion to a Harvard host with 16,500 accounts.
- **Targets:** the Naval Research Laboratory, NASA JPL and Ames, Los Alamos and the Navy center.
- **November and December:** a court-ordered wiretap watched the Harvard host.
- **28 December:** Argentine authorities seized the intruder's equipment in Buenos Aires.
- **May 1998:** he pleaded guilty in Boston; the record calls him an individual, not a state actor.
Caption: Rome Laboratory was a 1994 event; its home is the 1994 chronicle.
Notes: Part 3. Justice Department releases [16][15][17]. GAO/AIMD-96-84 [40][41].

## PART 4 | Crime cases tested the law one at a time

Left: Cases
- Mitnick arrested 15 Feb.
- Levin arrested in London.
- Cybersnare sting, 11 Sep.
- Agent Steal gets 41 months.
Right: Law
- Protected-computer bill.
- Czubinski reversed in 1997.
- Mail bomb charged under 1030.
- anon.penet.fi unmasked.
Caption: The Mitnick arrest's home is the Mitnick study; the bank transfers' home is the dot-com era study.
Notes: Mitnick [5][6]. Levin [10]. Cybersnare [25]. Petersen [29]. Bill [12]. Czubinski [27][28]. Monmouth [26]. anon.penet.fi [7], with [8] Reported.

## PART 5 | Viruses moved from disks into documents

- **Concept:** spreads through Word's auto-run macros and the NORMAL.DOT template.
- **Trusted media:** a ServerWare CD, a Microsoft test CD for OEMs, a DEC conference disk.
- **Nuclear:** a second macro virus, hidden in a fake Microsoft file about Concept.
- **The WildList:** fixed the CARO name Concept in October with nine participants.
- **The Black Baron:** 18 months, described as the first UK prison sentence for virus writing.
Notes: Virus Bulletin on Concept [18], media [19][20], Pile [21][22][23], all Reported. WildList [24].

## PART 6 | Commerce cryptography was broken by volunteers

| Date | Event | Grade |
|---|---|---|
| 21 Feb | Bernstein export case filed | Confirmed |
| 15 Aug | 40-bit export SSL challenge broken | Demonstrated |
| 17 Sep | Netscape's random seed shown predictable | Demonstrated |
| 11 Oct | Netscape Bugs Bounty announced | Reported |
| 10 Dec | Kocher's timing attacks released | Demonstrated |
Caption: No record opened shows live customer traffic decrypted (Inferred).
Notes: Bernstein [9]. SSL break [35][14]. Goldberg and Wagner [32][33][34]. Bounty [36][37][38]. Kocher [39].

## PART 7 | The state story was law and doctrine, not intrusions

- **Russia:** the FSB law adopted on 22 February, dated 3 April.
- **Venona:** the CIA released the first 49 translations on 11 July.
- **Crypto AG:** the Baltimore Sun suggested NSA rigging in December.
- **Doctrine:** the Air Force's Cornerstones of Information Warfare and PDD-39.
- **ATT&CK:** no group, software or campaign activity recorded in 1995.
Caption: No opened record attributes a 1995 computer intrusion to a state (Inferred).
Notes: FSB law [47]. Venona [52]. Crypto AG [50][51], Reported. Cornerstones [55][56]. PDD-39 [67]. Library ATT&CK data [91].

## PART 8 | Law and standards built the defender's program

- **Authentication:** RFC 1760 S/KEY in February and SSH 1.0 in July.
- **Network layer:** IPsec RFCs 1825 to 1829 in August; RFC 1858 on fragments.
- **Hashing:** FIPS 180-1, SHA-1, issued 17 April.
- **Management:** BS 7799-1 and the NIST computer security handbook.
- **Law:** the Paperwork Reduction Act and the EU data protection directive.
Notes: RFC 1760 [78]. SSH [77]. IPsec [66]. RFC 1858 [79]. FIPS 180-1 [61][62]. BS 7799 [82]. SP 800-12 [64]. Pub. L. 104-13 [63]. Directive 95/46/EC [60].

## MITRE MAPPINGS | 18 Enterprise techniques, every one a later mapping

| Id | Technique | 1995 use |
|---|---|---|
| T1563 | Remote Service Session Hijacking | CA-95:01 |
| T1595.002 | Vulnerability Scanning | SATAN, CA-95:18 |
| T1190 | Exploit Public-Facing Application | httpd, sendmail, wu-ftpd |
| T1068 | Exploitation for Privilege Escalation | Local root flaws |
| T1078.001 | Default Accounts | SGI IRIX |
| T1040 | Network Sniffing | CA-95:18, Harvard |
| T1137.001 | Office Template Macros | Concept |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 10. Rows [1][3][4][69][16][18]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1995 fixes are still the first fixes

Left: What 1995 taught
- Never trust an address.
- Filter forged traffic.
- Patch what is advised.
- Change default passwords.
Right: What still applies
- Encrypt whole sessions.
- Detect the scan.
- Treat documents as code.
- Assume most attacks go unseen.
Notes: Top recommendations and Part 9. CA-95:01 [1][3]. CA-95:18 [1]. CA-95:15 [1]. SSH [77], S/KEY [78], IPsec [66]. Courtney [69]. Concept [18]. DISA tests [41].

## OVERSTATED AND UNDERSTATED | Headline numbers outran the record

Left: Overstated
- 250,000 Pentagon attacks.
- SSL breaks as shopper theft.
- Concept on the retail CD.
- CVE records dated 1995.
Right: Understated
- Spoofing on infrastructure.
- The December wave.
- The Harvard wiretap case.
- A bug bounty in 1995.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [40][41][35][32][19][20][73][76]. Understated [13][1][16][15][38][39][93]. Cross-cutting themes and the overstated and understated passage.
