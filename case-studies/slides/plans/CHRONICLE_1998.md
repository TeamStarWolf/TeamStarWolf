# Slide plan: The Year 1998 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1998.md
- Cover title: The Year 1998 / in Intrusions / A Dated Record
- Subtitle: Scripted mass exploitation, a remote control tool and a government that organized around infrastructure
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1998.md, told from the CERT/CC advisories and incident notes, Microsoft bulletins, F-Secure descriptions, Justice Department releases, White House directives, GAO reports, statutes, Federal Register rules and the NIST, RFC Editor, NVD and CVE records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year the script replaced the intruder

- **Automation:** CERT's notes run from default-account logins in May to a full script in December.
- **Root daemons:** BIND, NIS+, qpopper, IMAP, ToolTalk and mountd gave remote privileged access.
- **Remote control:** Back Orifice exploited no Windows flaw; the user installed it.
- **Attribution:** Solar Sunrise looked like a state attack and was not, by DOJ's account.
- **Defenders:** NIPC, PDD-63, RFC 2267, StackGuard and a revised PKCS #1 all date to 1998.
Caption: Grades: CERT, Microsoft, Justice, GAO, White House, statutes, NIST and RFC records Confirmed; press Reported.
Notes: Incident notes [2][3]. Advisories [1]. MS98-010 [19], cDc [22][23]. DOJ 98-125 [27]; GlobalSecurity.org [31], Reported. NIPC [28]. PDD-63 [38]. RFC 2267 [61]. StackGuard [67]. RFC 2437 [63].

## KEY FACTS | Four numbers from the primary record

Stat: 13 | CERT/CC advisories, CA-1998-01 to CA-1998-13
Stat: 7 | CERT/CC incident notes, IN-98.01 to IN-98-07
Stat: 20 | Microsoft bulletins, MS98-001 to MS98-020
Stat: 186,126 | accounts on one compromised host, 47,642 cracked
- GAO found significant weaknesses in each of the 24 largest federal agencies.
- No 1998 record carries a CVE id: the 1998 flaws carry CVE-1999 ids assigned later.
- CWE, CAPEC and ATT&CK came later still: 2006, 2007 and 2013.
Notes: CERT compilations [1][2]. Microsoft count [13], Demonstrated. IN-98.03 [2]. GAO/AIMD-98-92 [41]. CVE history [78][79]; CWE [80]; CAPEC [81]; ATT&CK [82].

## PART 1 | The year in date order, from smurf to scripted mountd

| Date | Event |
|---|---|
| 5 Jan | CA-1998-01 continuing smurf floods |
| Feb | Solar Sunrise intrusions |
| 27 Feb | NIPC unveiled |
| 13 May | IN-98.01 IRIX default-account sweeps |
| 22 May | PDD-63 and PDD-62 |
| 26 Jun | PKCS #1 advisory and MS98-002 |
| 16 Jul | IN-98.03 password haul |
| 1 Aug | Back Orifice released |
| 12 Oct | CA-1998-12 mountd |
| 28 Oct | DMCA signed |
| 9 Dec | IN-98-06 scripted mountd attacks |
Notes: CA-1998-01 [1][4]. Solar Sunrise [31], Reported, and [27]. NIPC [28]. IN-98.01 [2]. PDD-63 [38][39], PDD-62 [40]. CA-1998-07 [1], MS98-002 [14]. IN-98.03 [2]. Back Orifice [22][23]. CA-1998-12 [1][9]. DMCA [47]. IN-98-06 [2].

## PART 2 | Root daemons were the way in

- **Remote root:** BIND, NIS+, qpopper, IMAP, ToolTalk and mountd in one year.
- **Exploited in the wild:** qpopper in July, ToolTalk in September, mountd in October.
- **Availability:** smurf at the start of the year, BSD stack crashes at the end.
- **Microsoft:** the first numbered bulletin year, MS98-001 on 1 June to MS98-020.
- **CVE came later:** the 1998 flaws carry CVE-1999 ids, with two dating systems.
Caption: That root daemons were the year's main way in is the study's reading of the advisories (Inferred).
Notes: Part 2. The 13 advisories [1]. Microsoft bulletins [13][14][15][16][17][18][19][20][21]. NVD records [4][5][7][8][9]; CVE Services [12].

## PART 3 | Scanning turned into mass exploitation

Left: The tools
- May: tcpmux sweeps.
- June: mscan released.
- July: a cracked password haul.
- December: a full script.
Right: What CERT saw
- Default IRIX logins.
- A large number of sites.
- 47,642 cracked passwords.
- Linux hosts taken and logged.
Caption: The gap between the mountd advisory and December's script was under two months.
Notes: Part 3. IN-98.01, IN-98.02, IN-98.03, IN-98.04, IN-98-05, IN-98-06 [2]. IN-99-01 names mscan [3]. CA-1998-12 [1].

## PART 4 | Malware rode trusted channels

- **Back Orifice:** a Windows remote control with keystroke logging and screen capture.
- **MS98-010:** no Windows flaw; the user has to install it.
- **CIH:** found in Taiwan in June; tries to overwrite the flash BIOS.
- **Marburg:** on magazine cover CDs and a game's master CD.
- **Remote Explorer:** an NT service that impersonates later logons.
Caption: No ATT&CK software object exists for any of these; the techniques are bound instead.
Notes: cDc [22][23]. MS98-010 [19]. F-Secure on Back Orifice [24], CIH [25], Marburg [26]. IN-98-07 [2]. Library software data [85].

## PART 5 | The state record: one scare, one campaign

Left: Solar Sunrise
- February, during an Iraq crisis.
- At least eleven attacks.
- An arrest in Israel.
- No state sponsor, per DOJ.
Right: Moonlight Maze
- FBI case named in July.
- A UK relay, HRTest.
- Monitored for six months.
- Turla link called premature.
Caption: Equation is not placed in 1998; Kaspersky's dates are a vendor estimate.
Notes: Solar Sunrise [27] Confirmed, [31][32] Reported. Moonlight Maze [72] Confirmed, [73] Reported. Turla [75], Penquin [76]. Equation [74] Reported, [77].

## PART 6 | The government built its answer

- **NIPC:** unveiled by the Attorney General on 27 February.
- **L0pht:** seven members testified to the Senate on 19 May.
- **PDD-63:** the critical infrastructure structure, 22 May.
- **GAO:** weaknesses at all 24 largest agencies; testers reached State Department data.
- **HHS:** Medicare managed care production files could be modified.
Caption: The authorized tests are the best-documented compromises of the year (Inferred).
Notes: NIPC [28]. Hearing [35][36]. PDD-63 [38][39]. GAO/AIMD-98-92 [41], AIMD-98-145 [43], AIMD-98-155 [42].

## PART 7 | Law, privacy and cryptography

| Date | Event | Grade |
|---|---|---|
| 26 Jun | Bleichenbacher's PKCS #1 attack advised | Confirmed |
| 16 Jul | UK Data Protection Act 1998 | Confirmed |
| 17 Jul | EFF DES Cracker result released | Confirmed |
| 20 Aug | Fifteen AES candidates announced | Confirmed |
| 21 Oct | COPPA enacted | Confirmed |
| 28 Oct | Digital Millennium Copyright Act | Confirmed |
| 30 Oct | Identity theft made a federal crime | Confirmed |
| 4 Dec | UN resolution 53/70 | Confirmed |
| 31 Dec | 56-bit export rule | Confirmed |
Notes: CA-1998-07 [1], MS98-002 [14]. UK DPA [50]. DES Cracker [51]. AES [53]. Pub. L. 105-277 [46]. DMCA [47]. ITADA [48]. UN 53/70 [60]. Export rule [55].

## PART 8 | Research reached standards fast

- **PKCS #1:** RFC 2437 recommends OAEP for new applications, October.
- **TLS 1.0:** servers behave the same whether or not the RSA block is valid.
- **StackGuard:** stack canaries at the 7th USENIX Security Symposium.
- **Ingress filtering:** RFC 2267 drops forged-source packets at the edge.
- **Response and planning:** RFC 2350, IPsec RFC 2401 and NIST SP 800-18.
Notes: RFC 2437 [63]. RFC 2246 [65]. StackGuard [67]. RFC 2267 [61]. RFC 2350 [62]. RFC 2401 [64]. SP 800-18 [66]. DARPA evaluation [68].

## MITRE MAPPINGS | 29 Enterprise techniques, every one a later mapping

| Id | Technique | 1998 use |
|---|---|---|
| T1498.002 | Reflection Amplification | Smurf, CA-1998-01 |
| T1595.002 | Vulnerability Scanning | mscan, IN-98-06 |
| T1078.001 | Default Accounts | IRIX, IN-98.01 |
| T1190 | Exploit Public-Facing Application | qpopper, ToolTalk, mountd |
| T1110.002 | Password Cracking | IN-98.03 |
| T1219 | Remote Access Tools | Back Orifice |
| T1495 | Firmware Corruption | CIH |
| T1090.003 | Multi-hop Proxy | Moonlight Maze relay |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 11. Rows [1][2][3][19][22][25][72][73]. Basis scores in the layer: 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1998 fixes are still the first fixes

Left: What 1998 taught
- Filter spoofed traffic.
- Patch root daemons.
- Close default accounts.
- Assume hashes get cracked.
Right: What still applies
- No error-message oracles.
- Canaries in the compiler.
- Block unsigned programs.
- Verify trusted media.
Notes: Top recommendations and Part 10. CA-1998-01 [1], RFC 2267 [61]. IN-98.01 and IN-98.03 [2]. RFC 2437 [63], RFC 2246 [65]. StackGuard [67]. MS98-010 [19]. CIH and Marburg [25][26].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Solar Sunrise as a state attack.
- Moonlight Maze "is Turla".
- Tidy "firsts".
- "1998 CVEs".
Right: Understated
- Unix and Linux automation.
- The audit record.
- Standards work.
- Gaps in the breach record.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [27][31][72][73][75][76][71][70][4][12]. Understated [2][3][41][43][61][62][66][45]. Cross-cutting themes and the overstated and understated passage.
