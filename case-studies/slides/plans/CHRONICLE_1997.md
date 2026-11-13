# Slide plan: The Year 1997 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1997.md
- Cover title: The Year 1997 / in Intrusions / A Dated Record
- Subtitle: Mass scans, root on the network edge and documents that became programs
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1997.md, told from the CERT/CC advisories and annual report, Cisco's advisory, the CVE and NVD records, court opinions, statutes, White House, GAO and Justice Department records, declassified Joint Staff documents, the NIST, RFC and IETF records and Virus Bulletin. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year scale replaced the single intruder

- **Scans:** automated scans for one IMAP and POP flaw ran all year.
- **Root on the edge:** sendmail, INN, talkd and statd gave remote root.
- **Web scripts:** four CGI advisories; CERT blamed how scripts were written.
- **Macro viruses:** about half of Virus Bulletin's named reports by October.
- **The state record:** an exercise, a commission and a campaign nobody saw yet.
Caption: Grades: CERT, Cisco, NVD, court, statute, White House, GAO, Justice, Joint Staff, NIST and RFC records Confirmed; press relayed in RISKS Reported.
Notes: CERT/CC annual report [3]. CA-97.05, CA-97.08, CA-97.04, CA-97.26 [1]. CA-97.07, CA-97.12, CA-97.24, CA-97.25 [1]. Prevalence table [24], Demonstrated sum. Eligible Receiver [37][38], Critical Foundations [34][35][36], Moonlight Maze [42].

## KEY FACTS | Four numbers from the primary record

Stat: 28 | CERT/CC advisories, CA-97.01 to CA-97.28
Stat: 2,134 | incidents CERT/CC handled in 1997
Stat: 146,484+ | sites affected, against 10,700+ in 1996
Stat: 13% | of fourth-quarter incidents with root compromise
- The site count rose fourteen-fold while incidents fell; the report does not define it.
- NVD's 253 records with 1997 dates are all CVE-1999 ids assigned later.
- No identifier system defenders use today existed: CVE began in 1999, ATT&CK in 2015.
Notes: CERT compilation [1][2]. CERT/CC 1997 annual report and summary [3][4]. NVD queries [9], Demonstrated. CVE history [11], ATT&CK [80].

## PART 1 | The year in date order, from talkd to Teardrop

| Date | Event |
|---|---|
| 27 Jan | CA-97.04 talkd remote root |
| 28 Jan | CA-97.05 sendmail MIME overflow |
| 20 Feb | CA-97.08 INN control messages |
| 7 Apr | CA-97.09 IMAP and POP overflow |
| 10 Jun | Eligible Receiver 97 J-5 tasking |
| 26 Jun | Reno v. ACLU decided |
| 13 Aug | CA-97.22 BIND cache poisoning |
| 1 Sep | nmap published in Phrack 51 |
| Oct | Critical Foundations issued |
| 10 Nov | CA-97.25 CGI input |
| 16 Dec | CA-97.28 Teardrop and Land |
Notes: CA-97.04, CA-97.05, CA-97.08, CA-97.09, CA-97.22, CA-97.25, CA-97.28 [1]. J-5 tasking [38]. Reno v. ACLU [51]. Phrack 51 [13]. Critical Foundations [34][35][36].

## PART 2 | Remote root came through daemons doing their job

- **Mail:** sendmail 8.8.3 and 8.8.4 overflowed on MIME conversion, even behind firewalls.
- **News:** INN ran commands from crafted control messages; numerous exploitation reports.
- **Mail access:** the IMAP and POP login overflow was scanned for all year.
- **Names:** talkd turned crafted DNS data into root; BIND cache poisoning was exploited.
- **RPC:** statd gave root locally and remotely without an account.
Caption: CERT's advice for each was to patch or upgrade, and otherwise to disable the service.
Notes: Part 2. CA-97.05, CA-97.08, CA-97.09, CA-97.04, CA-97.22, CA-97.26 [1]. Annual report activity list [3]. Later CVE records [6][8][10].

## PART 2 | Local root and the web script

Left: Set-uid programs
- newgrp, rlogin, xlock.
- suidperl actively exploited.
- at and lpr overflows.
- Six IRIX overflows.
Right: Web scripts
- nph-test-cgi in February.
- webdist.cgi in May.
- Count.cgi in November.
- CA-97.25 on user input.
Caption: Many daily root compromises were on systems whose advisories were already published.
Notes: CA-97.02, CA-97.06, CA-97.13, CA-97.17, CA-97.18, CA-97.19, CA-97.21 [1][3]. CA-97.07, CA-97.12, CA-97.24, CA-97.25 [1]. Patching gap [3].

## PART 3 | Scanning became a tool anyone could run

- **All year:** large-scale, automated scans against many networks for one IMAP and POP flaw.
- **1 September:** Phrack 51 introduces nmap and its scan types, FTP bounce among them.
- **10 December:** CERT advises on FTP bounce, a protocol behavior discussed for years.
- **After root:** intruders installed IRC clients or servers on compromised hosts.
Caption: Public scripts existed for talkd, newgrp, lpr and most of the local root flaws.
Notes: Part 3. CERT/CC annual report [3]. Phrack 51 [13], described at title level only. CA-97.27 [1]. Public exploit information [1][3].

## PART 4 | Crime, insiders and defaced front pages

Left: Crime and courts
- Card data sold to FBI.
- AOL phishing e-mail.
- Czubinski reversed.
- Mitnick sentenced.
Right: Web incidents
- NASA page replaced.
- Microsoft site disrupted.
- Crack a Mac broken.
- Yahoo page altered.
Caption: The card-data, phishing, insider and defacement rows rest on press relayed in RISKS and are graded Reported; Mitnick's home is the Mitnick study.
Notes: Salgado [69][73], AOL [73], Reported. Czubinski [25]. Mitnick [27][28][29]. NASA [65], Microsoft [70], Crack a Mac [72], Yahoo [77], all Reported. Forbes [75] and California [63] insiders, Reported.

## PART 6 | Documents became programs

- **16 January:** Office 97 ships with VBA5 in every application.
- **February:** ShareFun mails itself to three Microsoft Mail aliases; Bliss reported on Linux.
- **June:** WM/CAP.A reported across major French corporations.
- **October:** WM/CAP.A leads the table at 20.8 percent; macro viruses about half.
- **November:** Win32.Cabanas, the first Win32 virus to work under Windows NT.
Notes: Virus Bulletin [19][20][22][23][24]; F-Secure [14][16][17]. The prevalence sum is Demonstrated [24]. WM/CAP in France is Reported [22].

## PART 7 | An exercise, a commission and a hidden campaign

| Date | Event | Grade |
|---|---|---|
| Feb | GAO names federal information security high-risk | Confirmed |
| 9 to 11 Jun | Eligible Receiver 97 documents | Confirmed |
| Jun | NSA Red Team plays scenario adversaries | Reported |
| Oct | PCCIP issues Critical Foundations | Confirmed |
| 1996 to 1999 | Moonlight Maze, no dated 1997 event | Confirmed |
| 9 to 10 Dec | G8 high-tech crime meeting | Confirmed |
| 16 Dec | No Electronic Theft Act | Confirmed |
Caption: Iran, North Korea and Cuba were scenario roles in the exercise; no opened primary attributes a 1997 intrusion to a state.
Notes: GAO [36]. Joint Staff documents [37][38]. Archive account [37][39], Reported. PCCIP [34][35][36]. Moonlight Maze [42]; home is the dot-com era study. G8 [55][56]. NET Act [30][31].

## PART 8 | Law and standards moved with the network

| Date | Event | Grade |
|---|---|---|
| 2 Jan | NIST starts AES development | Confirmed |
| 18 Feb | FIPS 196 published | Confirmed |
| 21 Feb | Czubinski conviction reversed | Confirmed |
| 1 Jul | Framework for Global Electronic Commerce | Confirmed |
| 25 Aug | Bernstein export ruling | Confirmed |
| Sep | RFC 2196 Site Security Handbook | Confirmed |
| 12 Sep | NIST calls for AES algorithms | Confirmed |
Caption: The court stayed the Bernstein ruling on 28 August and limited it to the plaintiff pending appeal.
Notes: Part 8 and Part 9. AES [48]. FIPS 196 [61]. Czubinski [25]. Framework [52][53]. Bernstein [49][50]. RFC 2196 [57].

## MITRE MAPPINGS | 22 Enterprise techniques, every one a later mapping

| Id | Technique | 1997 use |
|---|---|---|
| T1595.002 | Vulnerability Scanning | IMAP scans |
| T1190 | Exploit Public-Facing Application | Mail, news, CGI |
| T1068 | Exploitation for Privilege Escalation | Set-uid root |
| T1499.004 | Application or System Exploitation | Teardrop, Land |
| T1557 | Adversary-in-the-Middle | BIND poisoning |
| T1204.002 | Malicious File | ShareFun, CAP |
| T1491.002 | External Defacement | NASA, Yahoo |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 11. Rows [1][3][5][14][17][65][77]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1997 fixes are still the first fixes

Left: What 1997 taught
- Patch root daemons first.
- Remove unneeded scripts.
- Sanitize script input.
- Filter spoofed traffic.
Right: What still applies
- Audit set-uid programs.
- Limit active content.
- Scan documents as code.
- Look for intrusion signs.
Notes: Top recommendations and Part 10. CA-97.05, CA-97.08, CA-97.09, CA-97.22, CA-97.07, CA-97.25, CA-97.28, CA-97.11, CA-97.20 [1]. Office 97 [19]. Intruder Detection Checklist and security improvement modules [3].

## OVERSTATED AND UNDERSTATED | Counts and firsts outran the record

Left: Overstated
- 146,484 sites affected.
- CVE records dated 1997.
- Eligible Receiver as attack.
- First-virus claims.
Right: Understated
- Microsoft platforms.
- The CGI layer.
- Macro viruses.
- What was not seen.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [3][4][9][10][11][37][38][39][20][15][23]. Understated [1][9][12][24][14][17][42][37]. Cross-cutting themes and the overstated and understated passage.
