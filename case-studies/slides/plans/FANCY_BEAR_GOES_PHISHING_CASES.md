# Slide plan: Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing

- Study: case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md
- Cover title: Five Hacks and Why They Worked / The Cases in / Fancy Bear Goes Phishing
- Subtitle: From the Morris worm to Mirai, the record behind each chapter
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md, told from the court, government, vendor and research record behind Scott J. Shapiro's 2023 book rather than from the book, whose text was not opened. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Five cases, and in most of them a default did the work

- **The book's thesis:** hacking is a human-interest story about people, not only defective code.
- **The record mostly bears it out,** and adds that the people were let down by defaults.
- **Sendmail debug on, `gets()` in fingerd** and guessable passwords carried the 1988 worm.
- **One fake Google page** opened the Clinton campaign chairman's mailbox in 2016.
- **Factory passwords** on cameras and recorders built Mirai, 28 years after the worm.
Caption: Grades: worm, DNC and Mirai mechanics Confirmed; the 2005 victim and phone call Reported; the patterns Inferred.
Notes: Publisher copy and reviews for the thesis [1][3], Reported. Defaults [11][12][14], phishing [46][49], factory credentials [59][62]. The book text was not opened, so nothing rests on it except claims labelled as the book's own.

## KEY FACTS | Thirty years of cases, from one MIT computer to 600,000 bots

Stat: 4 | entry methods the court found for the 1988 worm
Stat: 2 | Russian services in the DNC network
Stat: 50,000+ | emails taken from the chairman's account
Stat: ~600,000 | Mirai infections at the November 2016 peak
- The worm was released about 8:30 p.m. on 2 November 1988 from a computer at MIT.
- Twelve GRU officers were indicted in the District of Columbia on 13 July 2018.
- Three men pleaded guilty in Alaska in the Mirai and clickfraud cases, filed 5 December 2017.
Notes: Worm release [7][15]; four methods [8]. APT29 and APT28 [48][49]. Chairman's mailbox and indictment [46]. Mirai peak [59]. Alaska informations [65][66][71]. No ATT&CK object covers the worm, the Dark Avenger, the 2005 case or Mirai [26][58][75].

## PART 1 | The 1988 worm got in by debug mode, gets() and weak passwords

- **Sendmail debug mode,** on by default in 4.3BSD and Sun releases, let a message reach a shell.
- **fingerd read requests with `gets()`** into a 512-byte stack buffer; only VAX hosts fell to it.
- **Trusted-host files** such as `.rhosts` and `hosts.equiv` turned one host into many.
- **Password guessing** ran from null and account names to a 432-word list and the dictionary.
- **One copy in seven** ignored the reinfection check, so machines crashed or went catatonic.
Notes: Part 1.2 and 1.3 from the MIT, Purdue and Utah analyses and the court record [7][8][11][12][14]. NVD carries CVE-1999-0095 for the sendmail debug command [16]; a fingerd keyword search finds no record of the 1988 bug [17], Inferred from absence.

## PART 1 | Mail lists answered the worm, and a court set the sentence

| Date | Event | Grade |
|---|---|---|
| 2 Nov 1988 | Worm released from MIT, about 8:30 p.m. | Confirmed |
| 3 Nov 1988 | Bostic posts sendmail, then fingerd fixes | Confirmed |
| 8 Nov 1988 | NCSC post-mortem; no vendors attended | Confirmed |
| Dec 1988 | CERT/CC advisory CA-1988-01 | Confirmed |
| 4 May 1990 | Sentence announced, per the Cornell Chronicle | Reported |
| 16 May 1990 | Judgment: probation, service, $10,050 fine | Confirmed |
| 7 Mar 1991 | Second Circuit affirms | Confirmed |
Caption: The 6,000-machine figure began as an on-camera guess; the court found $200 to $53,000+ per site.
Notes: Response chronology [10][11][18]. CERT/CC [15][21]. Trial and judgment [7]; first convicted under the 1986 Act per the FBI [15], Confirmed; first tried per the Cornell Chronicle [23], Reported; 4 May announcement [77], Reported. Size [10][22][7].

## PART 2 | The Dark Avenger wrote viruses and turned them on the defenders

- **Bulgaria had no law** against writing or spreading viruses, and piracy carried them abroad.
- **The 1989 virus** overwrote a random sector every 16th run, so backups were already bad.
- **V2000 and V2100** claimed authorship by Bontchev; V2100-B trojanized a McAfee scanner.
- **A fake "UScan"** uploaded under Bontchev's name infected every file it scanned.
- **The Mutation Engine (1992)** let any virus mutate; Leech, not MtE, shows he was not first to mutate.
Notes: Bontchev's 1991 paper [28], Virus Bulletin [30][31][33], Gordon's interview [29]. Authorship of the viruses is Bontchev's judgment. No opened source says who uploaded UScan or establishes the Dark Avenger's identity. The book site's "first" holds only for the engine [1][28][33], Inferred.

## PART 3 | The 2005 phone case rests on one DOJ release and a richer story

Left: The DOJ record, 2004 to 2005
- Entry to an ISP via a remote-access program.
- A telephone provider's internal system searched.
- Accounts at an identity-data company.
- About $1 million in damages; 11 months juvenile term.
Right: The popular story
- The book's author names the victim and carrier.
- A pretext call to a store, by his account.
- Wired's date falls outside the DOJ window.
- Press accounts disagree on dates and counts.
Notes: DOJ release, District of Massachusetts, 8 September 2005 [37], Confirmed; it names no victim and no method of entry to the provider. Author interview [38], Wired [39], other press [40][45], all Reported. The study does not name the juvenile.

## PART 4 | Two Russian services shared the DNC, with no collaboration found

- **APT29 from summer 2015:** a link phish to over 1,000 recipients, PowerShell, WMI and Mimikatz.
- **APT28 from April 2016:** GRU Unit 26165, which also phished the campaign chairman.
- **The DCCC was the bridge:** credentials keylogged there opened the DNC on 18 April 2016.
- **X-Agent and X-Tunnel** collected keystrokes and screens and moved gigabytes out.
- **A Linux X-Agent survived** the June 2016 eviction until about October.
Notes: CrowdStrike [48] and GRIZZLY STEPPE [49] for the two actors. The July 2018 indictment [46] and the Special Counsel's report [47] for APT28 and Unit 26165. ATT&CK G0007 and G0016 [50][53][54]. Unit 74455's wider operations are in the Sandworm study.

## PART 4 | The GRU ran the leak as an operation on the same paid plumbing

| Date | Event | Grade |
|---|---|---|
| 19 Mar 2016 | Spoofed Google notice phishes the chairman | Confirmed |
| 12 Apr 2016 | DCCC entered with phished credentials | Confirmed |
| 18 Apr 2016 | DNC entered from the DCCC network | Confirmed |
| 13 May 2016 | Event logs cleared on a DNC computer | Confirmed |
| 14 Jun 2016 | DNC announces the intrusion | Confirmed |
| 15 Jun 2016 | Guccifer 2.0 persona created | Confirmed |
| 22 Jul 2016 | Over 20,000 DNC emails released | Confirmed |
Caption: Bitcoin that paid for dcleaks.com also funded the phishing domains; no opened source measures an election effect.
Notes: All rows from the indictment [46], with CrowdStrike [48] for the announcement. Laundering of more than $95,000 and the shared infrastructure [46], Confirmed as charged. The election-effect gap [3][46][47].

## PART 5 | Mirai needed 62 factory passwords and a Telnet scan

Stat: 76 min | doubling time after scanning began on 1 August 2016
Stat: 62 | default credentials in the bot's list
Stat: 623 Gbps | the 20 September 2016 attack on Krebs on Security
- **Bots scanned Telnet** on ports 23 and 2323 and tried 10 pairs per device.
- **Cameras, DVRs and routers** made up most of the botnet.
- **Source released 30 September 2016;** the variant ecosystem exploded.
- **Dyn was hit by cluster 6,** a post-leak botnet; nothing on the record ties it to the authors.
Notes: USENIX Security 2017 paper [59], US-CERT TA16-288A [62], Krebs [61][73]. Charged conduct ends about 4 October 2016 and never mentions Dyn [65]. Sentencing on 18 September 2018 [74], Reported. Carna, not Mirai, was the first default-credential IoT botnet [59].

## PART 6 | Four library rows say more than the record supports

| Library row | Record says | Grade |
|---|---|---|
| 1988: 6,000 machines crashed | A guess the Commission could not confirm | Inferred |
| 1988: up to $10M damage | Court gives per-site costs only | Inferred |
| DNC: APT28 only | Two actors, APT29 and APT28 | Inferred |
| DNC: measurable election effect | No opened source measures one | Inferred |
| Mirai: first IoT botnet | The paper names Carna first | Confirmed |
| Mirai: authors hit Dyn | Dyn traced to a post-leak cluster | Inferred |
| APT28: SolarWinds suspected | ATT&CK puts C0024 under APT29 | Inferred |
Notes: Part 6 table. Notable Incidents rows [7][10][22][25][48][49][59][73]. Threat Actors APT28 entry [54]. None is fixed by this study; each is graded.

## MITRE MAPPINGS | 73 techniques, and only the DNC has ATT&CK objects

| Id | Technique | Case |
|---|---|---|
| T1210 | Exploitation of Remote Services | Morris worm |
| T1110.002 | Password Cracking | Morris worm |
| T1027.014 | Polymorphic Code | Dark Avenger |
| T1598.004 | Spearphishing Voice | Phone case |
| T1598.003 | Spearphishing Link | DNC, APT28 |
| T1199 | Trusted Relationship | DNC, APT28 |
| T1078.001 | Default Accounts | Mirai |
| T1498.001 | Direct Network Flood | Mirai |
Caption: ATT&CK v20.0 layer: 18 techniques stated by the record (score 100), 55 by mapping (50); not an official MITRE mapping.
Notes: Objects G0007, G0016, S0023, S0117, S0002, S0053; no campaign object [50][51][53][54][55][56]. The phone-call row is Reported [38]. CWE-1392 fits Mirai [76]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Change the defaults, harden logins, and assume a second intruder

Left: Close the doors
- Remove default and guessable credentials.
- Use phishing-resistant MFA for webmail.
- Give support and recovery flows login rigor.
- Turn off debug features before shipping.
Right: Watch and recover
- After one eviction, hunt for a second actor.
- Forward logs off the host as they are written.
- Test restores against old offline copies.
- Keep channels open during an incident.
Caption: The library maps no D3FEND countermeasure to T1598.003, so the MFA case is argued from the record.
Notes: Part 7 and the top recommendations [11][18][28][37][46][48][49][57][59]. Change Default Password, Account Locking, Strong Password Policy and Credential Hardening are library mappings [57].

## CROSS-CUTTING THEMES | Defaults, rational attackers and numbers that travel

- **Defaults, not genius:** debug on, `gets()`, readable password files and factory passwords.
- **Attackers as businesses:** underpaid programmers, laundered bitcoin and rented DDoS.
- **Responders as a community:** a 1988 mailing list and phone tree, then shared analyses.
- **Numbers travel:** the 6,000-machine guess and a Dyn size no primary carries.
- **Overstated:** the worm's size and Mirai's Dyn link; understated: defaults and the second intruder.
Notes: Themes from the reviewers [3][5] and the record [10][11][14][18][28][37][46][59][65][74]. The overstated and understated reading is the study's own judgment, graded Inferred.
