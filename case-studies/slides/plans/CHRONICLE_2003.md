# Slide plan: The Year 2003 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2003.md
- Cover title: The Year 2003 / in Intrusions / A Dated Record
- Subtitle: The patch came first, the worms came in minutes, and the archives held
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2003.md, told from the CERT/CC advisories and incident notes, Microsoft bulletins and announcements, CVE and NVD records, CAIDA's Slammer analysis, the US-Canada task force reports, the Debian project's report, Justice Department releases, statutes, UK, UN and Council of Europe texts, NIST and RFC Editor records, the joint advisory AA23-129A and Kaspersky's Regin and Equation reports. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The fix came first, and it was not enough

- **Worms:** Slammer came six months after its fix, Blaster 26 days after.
- **Speed:** CERT/CC said worm spread fell from hours to minutes.
- **Archives:** GNU's FTP server and four Debian machines were root compromised.
- **Grid:** Slammer reached Davis-Besse; the blackout had no malicious cause.
- **Law:** CAN-SPAM, FACTA, SB 1386 in force, HSPD-7 and the UK's PECR.
Caption: Grades: CERT, Microsoft, CAIDA, task force, Debian, Justice and statute records Confirmed; press Reported.
Notes: MS02-039 [5], MS03-026 [8], Slammer and Blaster [1][30]; the intervals are Inferred. Speed [2]. GNU [1]; Debian [38]. Davis-Besse [35][36], path Reported [37]; blackout [35][36]. CAN-SPAM [60]; FACTA [61]; SB 1386 [62]; HSPD-7 [59]; PECR [63].

## KEY FACTS | Four numbers from the primary record

Stat: 28 | CERT/CC advisories, CA-2003-01 to CA-2003-28
Stat: 8.5 s | Slammer's doubling time in its first minutes
Stat: 75,000 | hosts Slammer infected, at least
Stat: 26 days | from MS03-026 to CERT/CC's Blaster advisory
- CVE ids were still issued in the candidate form CAN-2003-xxxx.
- NVD names a specific CWE for only two of the eight 2003-era CVEs checked.
- CWE, CAPEC and ATT&CK came later: every Enterprise id is a later mapping.
Notes: CERT advisories [1]. CAIDA [30]. MS03-026 [8]; CA-2003-20 [1]; the interval is Inferred. CAN form [1][8]. NVD records [18][24]. CWE [73]; CAPEC [74].

## PART 1 | The year in date order, from Slammer to CAN-SPAM

| Date | Event |
|---|---|
| 25 Jan | Slammer; CA-2003-04 |
| 11 Mar | CA-2003-08 weak passwords |
| 17 Mar | MS03-007 WebDAV exploited |
| 1 Jul | SB 1386 operative |
| 16 Jul | MS03-026 DCOM RPC |
| 11 Aug | CA-2003-20 Blaster |
| 13 Aug | CA-2003-21 GNU FTP server |
| 14 Aug | The Northeast blackout |
| 22 Aug | IN-2003-03 Sobig.F |
| 15 Oct | First monthly patch batch |
| 19 Nov | Debian machines compromised |
| 16 Dec | CAN-SPAM approved |
Notes: Slammer [30][1]. CA-2003-08 [1]. MS03-007 [7][1]. SB 1386 [62]. MS03-026 [8]. CA-2003-20 [1]. CA-2003-21 [1]. Blackout [36]. IN-2003-03 [2]. Monthly batch [10]. Debian [38]. CAN-SPAM [60].

## PART 2 | The vulnerability record

- **CERT/CC:** 28 advisories, CA-2003-01 on 15 January to CA-2003-28 on 11 November.
- **Microsoft:** MS03-001 to MS03-051; monthly releases began on 15 October.
- **Cisco IOS:** a public exploit two days after the blocked-interface advisory.
- **Defender tools:** remotely exploitable flaws in Snort and in OpenSSL's ASN.1 parsing.
- **Mail:** two separate Sendmail overflows, in March.
Caption: The count of 51 bulletins is Inferred from the absent MS03-052.
Notes: Part 2. Advisories [1]. Bulletins [6][13]; monthly cycle [14][10]. Cisco [1][27]. Snort [1][23]; OpenSSL [1][24]. Sendmail [1][25][26].

## PART 3 | The worm year

Left: Network worms
- Slammer: SQL Server, UDP 1434.
- CA-2003-08 bots on SMB shares.
- Blaster and two variants.
- Welchia through the same flaw.
Right: Mass mailers
- Sobig and Sobig.F.
- Fizzer kills anti-virus tasks.
- Mimail as an expiry notice.
- Swen in September.
Caption: No ATT&CK software object exists for these worms; the techniques are bound instead.
Notes: Part 3. Slammer [30][1]. CA-2003-08 [1]. Blaster [1][44][45][48]. Welchia [33], Reported; CVE record [21][22]. Sobig [31] Reported, [15]; Sobig.F [2]. Fizzer [32] Reported. Mimail [2]. Swen [34] Reported. Library software data [89][93].

## PART 4 | The compromised project servers

| When | Server | What was found |
|---|---|---|
| Reportedly March | GNU's primary FTP server | Root compromise, no distribution believed modified |
| 13 August | CERT/CC CA-2003-21 | Announcement, five months on |
| 19 November | Four Debian machines | Sniffed password, do_brk() flaw, rootkits |
| 20 November | Debian | Found through kernel crashes and AIDE |
Caption: Both archives were verified; T1195.002 is recorded as a risk, not bound as observed.
Notes: Part 4. GNU [1]; the five-month span is Inferred. Debian [38]. The comparison is Inferred. No exploit detail is reproduced.

## PART 5 | The grid and the plant

- **Davis-Besse:** Slammer took down monitoring computers at the idled plant in January.
- **The path:** a contractor link around a firewall that did block the port (Reported).
- **14 August:** the Northeast blackout, about 50 million people.
- **Finding:** no evidence that attackers or worms caused or contributed to it.
- **Policy:** HSPD-7 on 17 December superseded PDD-63.
Caption: The task force called the claims of responsibility inconsistent with its findings.
Notes: Part 5. Davis-Besse [35][36]; path [37], Reported. Blackout [36]. Finding [35][36]. HSPD-7 [59].

## PART 6 | The state record is written in hindsight

Left: Dated later
- Snake development, late 2003.
- Regin timestamps from 2003.
- EQUATIONDRUG from 2003.
- No state named for Regin.
Right: Reported only
- Storm Cloud in the press.
- Titan Rain since 2003.
- Iraq war network attacks.
- No 2003 campaign object.
Caption: Uroburos S0022, Regin S0019, Equation G0020 and Turla G0010 are bound with dating caveats.
Notes: Part 6. Snake [76][77]; Turla [78]. Regin [79][80]. EQUATIONDRUG [81][82]. Storm Cloud [83]. Titan Rain [84][85][86][87]. Iraq [88]. Library data [89][96].

## PART 7 | Crime and prosecutions

- **Extortion from abroad:** Zezev convicted in February; Ivanov sentenced in July.
- **Blaster:** Parson arrested on 29 August; a juvenile for RPCSDBOT in September.
- **Domain hijack:** Racine took over Aljazeera.net with a forged ID.
- **Insiders:** Amato at NASA Glenn, Baas at Acxiom, Wiggs at a county hotline.
- **Stores:** a Lowe's store's wireless network, October to November.
Caption: The charging releases are allegations; pleas and sentences are the record.
Notes: Part 7. Zezev [39]; Ivanov [43]. Parson [44][45]; juvenile [48]. Racine [41]. Amato [40]; Baas [55]; Wiggs [52]. Lowe's [50][51].

## PART 8 | Law, policy and standards

| Date | Event | Grade |
|---|---|---|
| 28 Jan | Council of Europe ETS 189 | Confirmed |
| Feb | National Strategy to Secure Cyberspace | Confirmed |
| Jun | RFC 3546, TLS Extensions | Confirmed |
| 1 Jul | California SB 1386 operative | Confirmed |
| Oct | NIST SP 800-42 and SP 800-50 | Confirmed |
| 4 Dec | FACTA | Confirmed |
| 11 Dec | UK PECR in force | Confirmed |
| 16 Dec | CAN-SPAM | Confirmed |
| 17 Dec | HSPD-7 | Confirmed |
| 23 Dec | UN A/RES/58/199 | Confirmed |
Notes: Part 8. ETS 189 [64]. National Strategy [58]. RFC 3546 [72]. SB 1386 [62]. SP 800-42 [67]; SP 800-50 [68]. FACTA [61]. PECR [63]. CAN-SPAM [60]. HSPD-7 [59]. A/RES/58/199 [65].

## MITRE MAPPINGS | 35 Enterprise techniques, every one a later mapping

| Id | Technique | 2003 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Slammer, WebDAV |
| T1210 | Exploitation of Remote Services | Blaster, Welchia |
| T1078.001 | Default Accounts | CA-2003-08 |
| T1498.001 | Direct Network Flood | Blaster's SYN flood |
| T1014 | Rootkit | Debian |
| T1669 | Wi-Fi Networks | Lowe's |
| T1056.001 | Keylogging | Kinko's |
Caption: ATT&CK v20.0 ids; Davis-Besse's two ICS techniques are in their own table and layer.
Notes: Part 10. Rows [1][7][21][33][38][42][50]. Basis scores in the layers: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2003 lessons still apply

Left: What 2003 taught
- Measure fix to worm.
- Filter, then look inside.
- Host firewalls first.
- Remove weak passwords.
Right: What still applies
- Verify what you download.
- Watch build servers' files.
- Map every control link.
- Patch on a calendar.
Notes: Top recommendations and Part 9. Fix to worm [5][8][1]. Filtering [1][4][3]. Host firewall [8][1]. Passwords [1][55]. Verification [1]. Integrity [38]. Control links [37] Reported, [36]. Monthly cycle [14][10].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- 2003 as only a worm year.
- The blackout as a cyberattack.
- Davis-Besse as a safety event.
- Titan Rain as confirmed.
Right: Understated
- Quiet intrusions.
- Defender cost.
- Weak passwords.
- Paths around the firewall.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][21][35][36][37][85]. Understated [1][55][37]. Cross-cutting themes and the overstated and understated passage.
