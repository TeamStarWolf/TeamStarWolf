# Slide plan: The Year 1994 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1994.md
- Cover title: The Year 1994 / in Intrusions / A Dated Record
- Subtitle: Sniffed passwords, Trojaned software and an Air Force lab broken into from abroad
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1994.md, told from the CERT/CC advisories, the GAO and Senate records, FBI histories, court opinions, statutes, Federal Register notices and the NIST, RFC and NVD records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year cleartext passwords failed at Internet scale

- **Sniffers:** CERT said access information for tens of thousands of systems had been captured.
- **Trojaned software:** binaries built to fool the old checksum, and two back-doored source releases.
- **Rome Laboratory:** two intruders, one of them 16, made over 150 known intrusions in 26 days.
- **The biggest theft was off the Internet:** $10 million moved through stolen bank passwords.
- **Policy:** Clipper, CALEA, a computer-fraud amendment and the first federal firewall primer.
Caption: Grades: CERT, GAO, Senate, FBI, courts, statutes, NIST, RFC and NVD records Confirmed; press and Virus Bulletin Reported.
Notes: CA-94:01 [1][3]. CA-94:05, CA-94:07, CA-94:14 [6][8][17]. Rome Laboratory [24][22]. Bank transfers [27]. FIPS 185 [34], CALEA [45], Pub. L. 103-322 [46], NIST SP 800-10 [44].

## KEY FACTS | Four numbers from the primary record

Stat: 15 | CERT/CC advisories, CA-94:01 to CA-94:15
Stat: 150+ | known intrusions at Rome Laboratory in 26 days
Stat: 255 | attacks on Defense sites reported in 1994
Stat: 12,000+ | Naval Academy passwords changed in December
- Rome Laboratory: 30 systems and more than 100 accounts compromised through sniffers.
- The Air Force put the Rome loss at $211,722; GAO cites an estimate over $500,000.
- No identifier system defenders use today existed: CVE began in 1999, ATT&CK in 2015.
Notes: CERT compilation [1][2]. Rome Laboratory [24][22]. DISA figures via GAO [22]. Naval Academy [22][23]. CVE history [81], ATT&CK design paper [103].

## PART 1 | The year in date order, from sniffers to Christmas Day

| Date | Event |
|---|---|
| 3 Feb | CA-94:01 warns of network monitoring attacks |
| 9 Feb | FIPS 185, the Clipper standard, published |
| 21 Feb | FBI arrests CIA officer Aldrich Ames |
| 18 Mar | CA-94:05 publishes MD5 checksums |
| 23 Mar | Rome Laboratory first penetrated |
| 6 Apr | CA-94:07 wuarchive ftpd Trojan horse |
| 12 May | Datastream Cowboy arrested in the UK |
| 13 Sep | Computer-fraud amendment enacted |
| 19 Oct | CA-94:14 ircII Trojan horse |
| 25 Oct | CALEA enacted |
| 25 Dec | IP spoofing attack on Shimomura begins |
Notes: CA-94:01 [1][3]. FIPS 185 [34]. Ames [28]. CA-94:05 [6]. Rome [24]. CA-94:07 [8]. Arrest [24]. Pub. L. 103-322 [46][47]. CA-94:14 [17]. CALEA [45]. Shimomura [53][54].

## PART 2 | Root first, then a sniffer, then the next host

- **Six advisories** say attackers were already using the flaw: mountd, rdist, utmp, sendmail, ircII, NFS.
- **Local root flaws** in AIX, SunOS, IRIX and sendmail were how sniffers got installed.
- **Remote flaws** in ftpd, login, Majordomo and NFS opened hosts from outside.
- **CVE records came later:** NVD's 1994-dated entries are CVE-1999 ids, back-dated.
Caption: The root, sniffer, next-host pattern is the study's reading of CERT's text (Inferred).
Notes: Part 2. Advisory statements [1][4][7][14][17][18][21]. Widely known flaws [9][16]. NVD date query [82], CVE-1999-0113 [84].

## PART 2 | Attackers replaced the software defenders trusted

Left: Trojaned binaries
- CA-94:01: Trojan system programs.
- CA-94:05: built to match "sum".
- CERT answer: MD5 and Tripwire.
- Compare against a clean baseline.
Right: Trojaned source
- wuarchive ftpd 2.2 and 2.1f, April.
- ircII 2.2.9, corrupt since May.
- Notice came in October.
- Later grouped in CVE-1999-0661.
Caption: The same class of attack runs through the npm, xz Utils and SolarWinds studies decades later.
Notes: CA-94:01 [3]. CA-94:05 [6]. CA-94:07 [8]. CA-94:14 [17]. CVE-1999-0661 [85]. The lineage to later studies is Inferred.

## PART 3 | Rome Laboratory: two intruders, one never identified

- **23 March:** first penetration, found five days later when staff spotted a sniffer.
- **April:** onward to an aerospace contractor, NASA Goddard, Wright-Patterson and a NATO site.
- **A scare:** Korean nuclear research data looked North Korean for hours; it was South Korean.
- **12 May:** New Scotland Yard arrested the 16-year-old Datastream Cowboy.
- **June 1996:** the Senate record still had not identified Kuji.
Caption: Officials told GAO at least one intruder "may have been working for a foreign country"; no record confirms it.
Notes: Part 3. Senate PSI minority staff statement [24]. GAO/AIMD-96-84 [22][23]. Names in the study rest on a 2024 retrospective, Reported [26].

## PART 4 | Crime ran over phone lines and through insiders

Left: Theft
- $10M+ in about 40 transfers.
- Valid IDs and passwords.
- FBI: not the Internet.
- Levin arrested in 1995.
Right: People
- LaMacchia indicted, dismissed.
- Poulsen pleads guilty.
- MCI and BT insider cases.
- Default passwords at Lillehammer.
Caption: The bank case's home is the dot-com era study; the Christmas Day intrusion's home is the Mitnick study.
Notes: FBI history [27]. LaMacchia [51][52]. Poulsen [57], Reported. MCI [76] and BT [60], Reported. Lillehammer [58], Reported.

## PART 5 | Viruses went polymorphic and a hoax went viral

- **Pathogen:** a polymorphic virus signed "The Black Baron"; a suspected author was arrested in July.
- **One_Half:** MBR infector that encrypts two more disk cylinders on each boot.
- **KAOS4:** posted to a Usenet binaries group on 24 July.
- **The WildList:** 16 virus professionals charted viruses in the wild from 1 September.
- **Good Times:** CIAC said reading mail alone cannot infect a computer.
Notes: Virus Bulletin on Pathogen [69] and Bates [72], Reported. F-Secure on One_Half [74]. KAOS4 [73]. WildList [75]. CIAC Notes 94-04 [63][62].

## PART 6 | The state story was a mole and an encryption fight

| Date | Event | Grade |
|---|---|---|
| 21 Feb | Ames arrested; life sentence in April | Confirmed |
| 28 Feb | Joint Security Commission report | Confirmed |
| 20 Aug | Blaze dates the Clipper protocol failure | Confirmed |
| Sep | OTA report criticizes key escrow | Confirmed |
| 16 Sep | PDD-29 signed | Confirmed |
| 25 Oct | CALEA enacted | Confirmed |
Caption: No opened record attributes a 1994 computer intrusion to a state (Inferred).
Notes: Ames [28]. Joint Security Commission [29][30]. Blaze [37]. OTA [32][33]. PDD-29 [31]. CALEA [45]. No ATT&CK object covers the 1990s [109].

## PART 7 | Law and standards built the defender's toolkit

- **Law:** the 18 U.S.C. 1030 amendment and civil action; Steve Jackson Games on appeal.
- **Authentication:** FIPS 190 said password-only authentication often fails to protect.
- **Firewalls:** RFC 1579, the IAB workshop and NIST SP 800-10 in December.
- **Cryptography:** FIPS 140-1, FIPS 186, RSA-129 factored, Shor's algorithm.
- **Commerce:** Netscape announced a Commerce Server with SSL in December.
Notes: Pub. L. 103-322 [46][47]. Fifth Circuit [49][50]. FIPS 190 [41]. RFC 1579 [90], RFC 1636 [91], SP 800-10 [44]. FIPS 140-1 [40], FIPS 186 [38]. RSA-129 [98]. Shor [99]. Netscape [97].

## MITRE MAPPINGS | 19 Enterprise techniques, every one a later mapping

| Id | Technique | 1994 use |
|---|---|---|
| T1040 | Network Sniffing | CA-94:01, Rome, Annapolis |
| T1078 | Valid Accounts | Bank transfers, Rome |
| T1195.002 | Compromise Software Supply Chain | ftpd, ircII |
| T1554 | Compromise Host Software Binary | CA-94:05 Trojans |
| T1068 | Exploitation for Privilege Escalation | Local root flaws |
| T1090.003 | Multi-hop Proxy | Rome via Latvia |
| T1563 | Remote Service Session Hijacking | 25 December |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 9. Rows [1][3][24][22][27][8][17][6][54]. Basis scores in the layer: 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1994 fixes are still the first fixes

Left: What 1994 taught
- No reusable passwords in the clear.
- Keep a trusted baseline of binaries.
- Verify the source you build from.
- Filter what outsiders can reach.
Right: What still applies
- Remove needless privileges.
- Banner and plan monitoring early.
- Hunt for unseen intrusions.
- Check warnings before forwarding.
Notes: Top recommendations. CA-94:01 [1][3], FIPS 190 [41], CA-94:05 [6], CA-94:07 and CA-94:14 [8][17], CA-94:15 [18], CA-94:03 and CA-94:06 [5][7], Rome banner [24], GAO [22], CIAC [63].

## OVERSTATED AND UNDERSTATED | Headline numbers outran the record

Left: Overstated
- Rome as foreign espionage.
- Press counts of stolen passwords.
- The bank fraud as Internet crime.
- CVE records dated 1994.
Right: Understated
- The sniffer wave itself.
- The two source Trojans.
- The Naval Academy compromise.
- Local root flaws.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [23][24][58][59][1][27][82][86]. Understated [1][3][8][17][22]. Cross-cutting themes and the overstated and understated passage.
