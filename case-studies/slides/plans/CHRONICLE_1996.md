# Slide plan: The Year 1996 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1996.md
- Cover title: The Year 1996 / in Intrusions / A Dated Record
- Subtitle: SYN floods, exploited web servers and a government that could not see its own attacks
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1996.md, told from the CERT/CC advisories, the GAO report and Senate hearings, Justice Department releases and court records, statutes, executive orders and the NIST, RFC, IETF and NVD records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year staying online became the problem

- **Floods:** CERT said SYN flooding code was in use and had no complete solution.
- **The web:** phf and CGI interpreters let intruders run commands on servers.
- **Applets:** Java flaws let a hostile page reach past the firewall.
- **Defense:** GAO said about 4 percent of successful test attacks were detected.
- **Policy:** EO 13010, HIPAA and the protected-computer amendment, all in one year.
Caption: Grades: CERT, GAO, Senate, Justice, statutes, NIST, RFC and NVD records Confirmed; press and Virus Bulletin Reported.
Notes: CA-96.21 [1]. CA-96.06 and CA-96.11 [1]. CA-96.05 and CA-96.07 [1], Princeton [49]. GAO/AIMD-96-84 [7][8]. EO 13010 [17][18], HIPAA [25], Pub. L. 104-294 [20].

## KEY FACTS | Four numbers from the primary record

Stat: 27 | CERT/CC advisories, CA-96.01 to CA-96.27
Stat: 2,573 | incidents CERT/CC handled in 1996
Stat: 559 | attacks on Defense systems reported in 1995
Stat: 4% | of DISA's successful test attacks detected
- GAO's "as many as 250,000 attacks" is an extrapolation from test attacks.
- The Harvard intruder was traced by the first court-ordered network wiretap.
- No identifier system defenders use today existed: CVE began in 1999, ATT&CK in 2015.
Notes: CERT compilation [1][2]. CERT/CC 1996 summary [3]. GAO [7][8][10]. Justice Department [4][5]. CVE history [81], ATT&CK [93].

## PART 1 | The year in date order, from packet storms to the ping of death

| Date | Event |
|---|---|
| 8 Feb | CA-96.01 UDP packet storm |
| 20 Mar | CA-96.06: phf actively exploited |
| 29 Mar | Harvard intruder charged |
| 22 May | GAO/AIMD-96-84 released |
| 15 Jul | Executive Order 13010 |
| 30 Jul | Omega Engineering time bomb |
| 16 Aug | Justice Department site defaced |
| 19 Sep | CA-96.21 SYN flooding |
| 11 Oct | Pub. L. 104-294 enacted |
| 8 Nov | Smashing the Stack published |
| 18 Dec | CA-96.26 oversized ping |
Notes: CA-96.01, CA-96.06, CA-96.21, CA-96.26 [1]. Ardita [4][5]. GAO [7][9]. EO 13010 [17][18]. Omega [38]. Justice defacement [55][75], Reported. Pub. L. 104-294 [20]. Phrack 49 [74].

## PART 2 | Denial of service in three steps

- **February:** chargen and echo answering each other until the network fills.
- **September:** SYN flood code in two magazines, in use, with no complete fix.
- **December:** oversized ping packets crash, freeze or reboot systems.
- **In practice:** Panix knocked out in September, WebCom down 40 hours in December.
Caption: CERT's only named control against spoofed floods was filtering at the edge, and it said that would not stop them all.
Notes: Part 2. CA-96.01, CA-96.21, CA-96.26 [1]. Project Neptune [73]. Panix [57] and WebCom [63], Reported. Later CVE records [80][83].

## PART 2 | The web opened in both directions

Left: Server side
- phf example CGI exploited.
- NCSA httpd and Apache.
- Interpreters in CGI bin.
- Vendor docs advised it.
Right: Client side
- Applets reach any host.
- Princeton showed it.
- Bytecode verifier flaws.
- No exploitation reported.
Caption: About half the year's advisories were local root flaws, most with public scripts; sendmail alone took three.
Notes: CA-96.06 and CA-96.11 [1], CVE-1999-0067 [85]. Dean's post [49]. CA-96.05 and CA-96.07 [1]. Local root cluster and sendmail [1]. Phrack 49 [74].

## PART 3 | The Defense record and the Harvard case

- **GAO, 22 May:** 38,000 DISA test attacks, 65 percent successful, about 4 percent detected.
- **Reported incidents:** 53 in 1992, rising to 559 in 1995.
- **Harvard:** an intruder from Buenos Aires staged into Navy, NASA and Los Alamos systems.
- **The wiretap:** a court order was needed because the host showed no monitoring banner.
- **Senate:** three hearings; the DCI feared a coordinated attack on infrastructure.
Caption: Rome Laboratory, a 1994 intrusion, was retold in the 1996 hearings; no state is named.
Notes: Part 3. GAO/AIMD-96-84 [7][8][9][10]. Justice Department [4][5]. PSI hearings [11][14][15]. DCI testimony [12]. Rome Laboratory [7][14].

## PART 4 | Crime, insiders and three defaced front pages

Left: Crime and insiders
- Omega time bomb, 30 July.
- $10M+ loss by indictment.
- BerkshireNet data erased.
- Cambridge password reset.
Right: Defacements
- Justice Department, Aug.
- CIA, Sep.
- Air Force site, Dec.
- 80 DTIC servers shut.
Caption: The transfer ring's home is the dot-com era study; Mitnick's plea and indictment are in the Mitnick study.
Notes: Omega [38]. BerkshireNet [50], Cambridge [51], Reported. Justice [55][75], CIA [58][76][77], Air Force [64][79], all Reported. Home studies: dot-com era [47], Mitnick [39].

## PART 5 | Viruses followed the new platforms

- **Boza:** the first Windows 95 virus, in Virus Bulletin's words, and not in the wild.
- **Hare.7610:** multipartite, set to overwrite hard drives on 22 August and 22 September.
- **Laroux:** the first Excel macro virus, found already in the wild with no payload.
- **Wazzu:** shipped on a Microsoft CD and on a trade-show CD.
- **October:** macro viruses about a quarter of Virus Bulletin's prevalence reports.
Notes: Boza [66][67], Hare [69], Laroux [69][70], Wazzu [71][60], all Reported. Prevalence sum [72], Demonstrated.

## PART 6 | Cryptography, law and standards caught up

| Date | Event | Grade |
|---|---|---|
| 10 Jan | Export-grade SSL session broken | Reported |
| 8 Feb | Telecommunications Act and CDA | Confirmed |
| 15 Jul | EO 13010 names cyber threats | Confirmed |
| 21 Aug | HIPAA security standards | Confirmed |
| 11 Oct | Economic espionage and 1030 | Confirmed |
| 18 Nov | SSL 3.0, later the TLS basis | Confirmed |
| 6 Dec | Bernstein: ITAR provisions invalid | Confirmed |
Caption: No opened record attributes a 1996 intrusion to a state; Moonlight Maze is dated to 1996 only by later research.
Notes: Export SSL [48]. Pub. L. 104-104 [27]. EO 13010 [17][18]. HIPAA [25][26]. Pub. L. 104-294 [20][23]. SSL 3.0 [86]. Bernstein [33][34]. DCI [12]. Moonlight Maze [40], Reported.

## MITRE MAPPINGS | 20 Enterprise techniques, every one a later mapping

| Id | Technique | 1996 use |
|---|---|---|
| T1499.001 | OS Exhaustion Flood | SYN floods |
| T1498.001 | Direct Network Flood | UDP storm |
| T1190 | Exploit Public-Facing Application | phf, CGI |
| T1189 | Drive-by Compromise | Java applets |
| T1068 | Exploitation for Privilege Escalation | Local root |
| T1078 | Valid Accounts | Harvard case |
| T1491.002 | External Defacement | Federal sites |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 11. Rows [1][4][5][55][57][63][95]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1996 fixes are still the first fixes

Left: What 1996 taught
- Filter spoofed sources.
- Turn off unused services.
- Strip sample web code.
- Do not trust names.
Right: What still applies
- Patch local root fast.
- Treat crashes as attacks.
- Detect, report, count.
- Watch insiders at exit.
Notes: Top recommendations and Part 10. CA-96.21, CA-96.01, CA-96.06, CA-96.11, CA-96.02, CA-96.04, CA-96.26 [1]. GAO [8]. Omega [38]. Harvard banner [5].

## OVERSTATED AND UNDERSTATED | Headline numbers outran the record

Left: Overstated
- 250,000 Pentagon attacks.
- Extortion and EU claims.
- Defacements as breaches.
- CVE records dated 1996.
Right: Understated
- Denial of service.
- How little was seen.
- Local root flaws.
- The insider time bomb.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [7][8][52][53][54][62][76][64][79][82][84]. Understated [1][73][63][8][38]. Cross-cutting themes and the overstated and understated passage.
