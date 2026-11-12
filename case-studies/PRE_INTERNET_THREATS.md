# Before the Internet: Computer Threats, 1960 to 1990

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Malware Families](/MALWARE_FAMILIES.md), [Threat Actors](/THREAT_ACTORS.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md) · Related studies: [The Cuckoo's Egg Intrusion, 1986](/case-studies/CUCKOOS_EGG_1986.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [Five Hacks and Why They Worked](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [The Ransomware Ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md), [Case study timeline](/case-studies/TIMELINE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security historians, threat intelligence analysts, educators and anyone who wants the primary record behind the field's origin stories

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 66 min (15,110 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the computer threats of 1960 to 1990 as the government reports, statutes, court records, RFCs, CERT advisories and the early Virus Bulletin record them, you need to check a famous first or a famous number, or you want the roots of today's credential, media and supply-chain lessons

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the timeline](#part-2-the-timeline), [Part 9: what is overstated and what is understated](#part-9-what-is-overstated-and-what-is-understated)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Malware Families](/MALWARE_FAMILIES.md), [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Most of us learned the history of our field as a short list of firsts: a cereal-box whistle, a schoolboy's Apple II virus, a worm that overloaded the early Internet. The stories are worth telling, and the people who lived them told many of them first, on mailing lists like RISKS, in hacker newsletters and in the early virus trade press. This study goes back to the record those people and their institutions left: the phone company's own journal, the Air Force and Defense Science Board reports on time-sharing, the first incident write-ups, the court records, the statutes, the CERT advisories and the early issues of *Virus Bulletin*. It covers the thirty years from 1960, when the Bell System published how its long-distance network signaled, to 1990, when national computer-crime laws were in force in the United States and the United Kingdom and the first incident-response teams were coordinating.

The record tells a steadier story than the list of firsts. By 1972 an Air Force planning study already said that experienced programmers had little difficulty penetrating off-the-shelf systems, and it defined the Trojan horse [4] (**Confirmed**). Air Force evaluators planted trap doors in Multics in 1972 and 1973, and decades later they wrote that one of those trap doors was distributed by the vendor to another site [5] [6] (**Confirmed** that they report it; the attack itself was an evaluation, **Demonstrated**). In 1976 the US General Accounting Office found that most computer-related crimes in federal programs were committed by system users with limited technical knowledge, "contrary to widespread belief" [12] (**Confirmed**). In 1979 Morris and Thompson found that 86 percent of the UNIX passwords they studied were short strings or dictionary words [14] (**Confirmed**). When the Morris worm ran in November 1988, two of its four ways in were trusted hosts and password guessing [47] [50] (**Confirmed**), and the WANK worm of October 1989 spread by trying blank passwords and passwords equal to the account name [58] (**Confirmed**).

Personal computers added a second channel: people carrying floppy disks. Brain (first detected January 1986, by F-Secure's account), the Lehigh virus of November 1987, nVIR on the Macintosh and the boot-sector virus Disk Killer all moved on disks [34] [37] [63] [68] (**Confirmed**), and people carrying those disks were the network (**Inferred**). The AIDS Information disk of December 1989, posted to several thousand recipients, combined that channel with extortion [68] (**Confirmed**). The law and the defenders caught up in the same years: Florida's Computer Crimes Act in 1978 [26], the federal statute in 1984 and the Computer Fraud and Abuse Act in 1986 [27] [29], the Computer Security Act of 1987 [31], the UK Computer Misuse Act in 1990 [79], CERT/CC in December 1988 [53], and FIRST in 1990 [56] (all **Confirmed**).

Evidence grade: the government studies, the statutes, the court records, the RFCs, the CERT advisories and the *Virus Bulletin* analyses are **Confirmed**. The phreaks' methods and nicknames, Creeper, Elk Cloner and the 414s are known here only from journalism, interviews and an encyclopedia, and are **Reported**; the Bell System paper and the Draper court papers are **Confirmed**. Every ATT&CK, CWE and CAPEC mapping is this study's retrospective reading of the record, because the events predate the frameworks by decades (Part 10).

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1960 (the Bell System's published signaling description) to 1990 (the UK Computer Misuse Act, the Steve Jackson Games search, Operation Sundevil and the first FIRST teams) [1] [79] [77] [76] [56] |
| Earliest government threat model opened | Defense Science Board task force report (Ware), 11 February 1970; task force formed October 1967 at ARPA's request [2] [3] |
| First published definition of the Trojan horse opened | Anderson report, ESD-TR-73-51 Vol. II, October 1972, crediting D. J. Edwards [4] |
| Planted trap doors in a government evaluation | Air Force penetration of Multics, March 1972 to June 1973, reported June 1974 [5] |
| Dominant intrusion vector in the primary record | Weak, default, blank or shared credentials and implicit host trust: RFC 602 (1973), the Morris worm (1988), WANK (1989), CA-1989-03 (1989) [13] [50] [58] (**Inferred** from the record) |
| Earliest virus experiment dated in a primary opened | Fred Cohen, conceived 3 November 1983, demonstrated 10 November 1983 [24] |
| PC-era viruses with a technical record | Brain (January 1986), Jerusalem (1986 to 1987), Lehigh (November 1987), nVIR, Disk Killer (June 1989) [34] [36] [37] [63] [68] |
| Network worms | CHRISTMA EXEC on BITNET and IBM's VNET (9 to 14 December 1987); Morris worm (2 November 1988); WANK on SPAN (16 October 1989) [39] [47] [58] |
| Extortion by mailed disk | AIDS Information disks posted from London, 8 to 12 December 1989; estimates rose from about 10,000 to nearer 20,000 disks [68] |
| Statutes | Florida ch. 78-92 (1978); Pub. L. 98-473 (12 October 1984); Pub. L. 99-474 (16 October 1986); Pub. L. 100-235 (8 January 1988); UK Computer Misuse Act 1990 c. 18 (Royal Assent 29 June 1990) [26] [27] [29] [31] [79] |
| Incident response | CERT/CC established December 1988 by DARPA, operated by the SEI [53]; first advisory CA-1988-01 [57]; FIRST formed 1990 [56] |
| ATT&CK record | No ATT&CK group, software or campaign object covers any 1960 to 1990 event; no ATT&CK for ICS technique is supported; this study maps 31 Enterprise techniques retrospectively (Part 10) [95] |

### Key findings

- **The threat was written down before the personal computer.** The Ware report of 1970 named deliberate penetration, trap doors left by system programmers, a terminal taking over a legitimate session and an agent inside the organization [3] (**Confirmed**). The Anderson report of 1972 defined the Trojan horse and the clandestine code change [4] (**Confirmed**). Histories that begin with Elk Cloner or Brain miss a decade of documented penetration work (**Inferred**).
- **Credentials and trust were the front door for thirty years.** RFC 602 warned in December 1973 that ARPANET users chose easy passwords and that dial-in terminals required no identification [13] (**Confirmed**). The Morris worm guessed passwords with a 432-word list and moved through `hosts.equiv` and `.rhosts` trust [50] (**Confirmed**). WANK tried blank and account-name passwords and left a privileged FIELD account behind [58] (**Confirmed**).
- **Insiders and clerks, not wizards.** GAO's 1976 review of 69 cases found most offenders were system users with limited technical knowledge, and that inadequate separation of duties was a major weakness in 7 of 12 cases reviewed in detail [12] (**Confirmed**). Anderson's 1980 report said internal penetration was in many installations more frequent than external penetration [9] (**Confirmed**).
- **Supply-chain subversion was demonstrated in the 1970s and 1980s.** The Multics evaluators' trap door went to another site through the vendor [6], and Ken Thompson's 1984 Turing lecture showed a compiler that inserts a back door absent from any source [23] (**Confirmed** that they report it; **Demonstrated**, not observed in an attack).
- **People were the network for PC viruses.** Lehigh spread through disks at public sites, nVIR reached a printing firm on a client's own software copy, and the AIDS Trojan arrived by post [37] [63] [68] (**Confirmed**). None of these needed a modem (**Inferred**).
- **The defenders organized quickly once the worm hit.** CERT/CC was established in December 1988 [53], its first advisory followed that month [57], and FIRST's own history puts CERT/CC's formation weeks after the worm and FIRST's founding in 1990 [56] (**Confirmed**). That the worm caused CERT/CC is a reading that no single opened source states as cause (**Inferred**).
- **Many of the famous numbers are guesses.** The 6,000-machine figure for the Morris worm began as an extrapolation from MIT [51] (**Confirmed** that it was an extrapolation), and the only cost figure in the court record is per installation, $200 to more than $53,000 [48] (**Confirmed**).
- **"First" is usually a later label.** *Virus Bulletin* in January 1990 called the AIDS disk an attempt to extort money [68]; CNN in 2021 called it the first act of ransomware [70] (**Reported**). It encrypted file names, not file contents [68] (**Confirmed**).

### Top recommendations

1. **Remove default, blank and account-name passwords.** WANK entered through blank and account-name passwords [58]; the Cuckoo's Egg intruder mostly through default account names and guessed passwords [94]; and the 414s, by an encyclopedia's account, through common or default passwords [21] (**Reported**). D3FEND [Change Default Password](/mitre/d3fend/change-default-password.md) is one of the countermeasures the library maps to `T1078.001` [95].
2. **Block dictionary passwords and slow down guessing.** A five-minute dictionary search found about a third of the passwords Morris and Thompson studied in 1979 [14], and the 1988 worm used a 432-word list [50]. Use [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Account Locking](/mitre/d3fend/account-locking.md) and [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) [95].
3. **Check system binaries against known-good copies.** CERT told sites in August 1989 to compare checksums of network programs with the originals after trojaned telnet binaries logged credentials [58], and *Virus Bulletin* found only checksumming programs revealed the AIDS disk's change to `AUTOEXEC.BAT` [68]. See [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md).
4. **Treat host trust as an attack path.** RFC 1135 concluded that defenses must sit at the host, because the worm's flaws were in applications and trust features, not the network [50]. Inventory trust files and remote-execution services; see [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) and [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md).
5. **Control removable media and the software people bring in.** Brain, Lehigh, nVIR and the AIDS disk all arrived on media [34] [37] [63] [68]. See [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) and [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md).
6. **Plan for subverted suppliers and tools.** The Multics trap door and the Thompson compiler show that a trusted source can carry the attack [6] [23]. Keep a [Software Inventory](/mitre/d3fend/software-inventory.md) and know where each build and update comes from.
7. **Enforce separation of duties and audit legitimate users.** GAO's 1976 cases turned on controls that existed but were not enforced [12], and Anderson's 1980 audit-trail proposal is an early statement of user-behavior detection [9] (**Inferred** as a lineage).
8. **Know whom to call before you need them.** RFC 1244 records that CERT/CC was set up to address the security concerns of Internet research users [53]; today every organization should have its national CERT and sector contacts written into its incident plan (**Inferred**).

## Scope and method

This study covers threats to computers and to the telephone network from 1960 to 1990: what was attacked, how, by whom where the record names them, how law and defense responded, and which popular claims the record does and does not support. It follows the method in the [case studies README](/case-studies/README.md): primary sources first, every claim graded, numbers given as the source states them, and an explicit passage on what is overstated and what is understated (Part 9). Every source in the Sources table was opened on 11 November 2026. Quotations are kept under 15 words. Tradecraft is described at the level the period's advisories and court records use; no virus code, signature strings, signaling values, commands or ransom text appear here.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: a government report, statute or court record, an RFC, a CERT advisory, an author's own paper, a participant's own published statement, a vendor's own technical description, a contemporaneous trade-journal analysis, or the MITRE page or library data file itself |
| Reported | Stated only in journalism, an interview, an encyclopedia, a book excerpt, a vendor's claim of priority or a superlative about itself ("first", "oldest"), or a secondhand account relayed by a primary; attributed by name |
| Demonstrated | Shown in a controlled evaluation or experiment (the Multics penetration, Cohen's experiments, Thompson's compiler), not observed in an attack |
| Inferred | This study's own reasoning from the cited facts, labelled where it appears |

Where two library studies cover the same event, one is the home and the other summarizes in a paragraph and links. The homes on main [93] for events in this period are: the [Cuckoo's Egg study](/case-studies/CUCKOOS_EGG_1986.md) for the Lawrence Berkeley Laboratory intrusions and the Hannover KGB case; the [Kevin Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) for Mitnick; the [Five Hacks study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) for the Morris worm and the Dark Avenger; the [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) for Operation Sundevil, the Legion of Doom and Steve Jackson Games. This study is the home for the AIDS Trojan; the library's [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) covers the record from 2019 to 2026 and does not discuss the AIDS disk. This study is the home for everything else here: the government studies, the phone phreaks, Creeper, Elk Cloner, the 414s, Cohen's experiments, the PC viruses, the BITNET and SPAN worms, the statutes and the early anti-virus trade. The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) picks up the record in 1994.

Some primaries were read as faithful copies: the Ware, Anderson and Karger reports and the Orange Book in NIST's collection of early papers [11], the Draper court papers as scanned from the National Archives [16] [17], the Operation Sundevil press release as reprinted in *Computer Underground Digest* [76], and the Steve Jackson Games opinion as reproduced on the company's site [77]. They are graded Confirmed with that caveat. Mitnick's memoir, the *New York Times* reports on the 414s and the House of Lords judgment in the Gold and Schifreen case were not opened, so every claim resting on them is Reported and attributed to the source that relays it.

## Part 1: before the personal computer, 1960 to 1979

### 1.1 The telephone network

In November 1960 the *Bell System Technical Journal* published Breen and Dahlbom's "Signaling Systems for Control of Telephone Switching", the phone company's own public description of its in-band trunk signaling [1] (**Confirmed**). That design choice, control signals on the same channel as the call, is the weakness the phreaks used (**Inferred**).

In October 1971 *Esquire* published Ron Rosenbaum's "Secrets of the Little Blue Box". It describes "blue boxes" that take over long-distance trunks through that in-band signaling, and says the signaling frequencies had been published in a technical journal [15] (**Reported**, *Esquire*). Whether the article meant the 1960 paper is this study's guess (**Inferred**). The article introduces "Captain Crunch", named for a cereal-box toy whistle said to produce the control tone and described as using it while posted to England with an Air Force unit, and profiles Joe Engressia, who whistled the tone [15] (**Reported**).

The court record opened here is narrower. In *United States v. John Thomas Draper* (N.D. Cal. No. CR-72-973), Draper pleaded nolo contendere on 29 November 1972 to one count of wire fraud under 18 USC 1343 and received a suspended sentence, a $1,000 fine and five years of probation [16] (**Confirmed**). A second federal wire fraud complaint concerned conduct on or about 20 February 1976 in Menlo Park (CR-76-223) [17] (**Confirmed**). The court papers opened do not describe the conduct, and this study does not identify Draper with the *Esquire* nickname from the record opened (**Inferred**).

Phone phreaking has no ATT&CK technique: ATT&CK models computing systems, not a carrier's in-band signaling (**Inferred**). Its lasting lesson is architectural: when control travels with data, whoever controls the data controls the system (**Inferred**).

### 1.2 Time-sharing and the government studies

In June 1967 ARPA asked for a study of security safeguards for multi-access, resource-sharing computer systems, and the Defense Science Board formed a task force in October 1967 [2] (**Confirmed**). Its report, chaired by Willis H. Ware, was published by RAND in February 1970, classified Confidential, and declassified on 10 October 1975 as R-609 [2] (**Confirmed**). The report itself is dated 11 February 1970 [3] (**Confirmed**).

The Ware report set out much of the modern threat model:

- It sorts threats into accidental disclosure, deliberate penetration and physical attack [3] (**Confirmed**).
- It names active infiltration by a legitimate user reaching parts of the system he is not authorized for, trap-door entry points left by system programmers, an illegal terminal taking over a legitimate session, and an agent operating inside the organization [3] (**Confirmed**).
- It names the communication links as a threat, including wiretapping land lines and intercepting microwave links, and lists radiation and crosstalk taps [3] (**Confirmed**).
- It says security is a system design problem that needs a combination of hardware, software, communication, physical, personnel and administrative-procedural safeguards, and that software safeguards alone are not sufficient [3] (**Confirmed**).
- It says contemporary technology could secure a closed environment, with cleared users and protected consoles and circuits, but could not provide a secure system in an open environment [3] (**Confirmed**).

The report was classified Confidential overall to control dissemination, although it said it held nothing that was not available in a well-stocked technical library [3] (**Confirmed**).

Anderson's *Computer Security Technology Planning Study* (ESD-TR-73-51 Vol. II, October 1972) went further. It states that experienced programmers had little difficulty penetrating off-the-shelf systems, and that attempts to certify systems through penetration generally ended in denial of certification [4] (**Confirmed**). It defines the "Trojan Horse" attack, a useful program carrying trap doors, credited to D. J. Edwards, and the "clandestine code change", in which rigged system changes are sent to operators [4] (**Confirmed**). It framed the core threat as the malicious user of an open-use system, an internal threat distinct from external ones [4] (**Confirmed**). The same report introduced the reference monitor: a reference validation mechanism that is tamper proof, always invoked, and small enough to be analyzed and tested, as section 6.1 of the later Orange Book records [10] (**Confirmed**).

Karger and Schell's *Multics Security Evaluation: Vulnerability Analysis* (ESD-TR-74-193 Vol. II, June 1974) reports an Air Force penetration exercise that ran from March 1972 to June 1973 [5] (**Confirmed**). Aiming at one vulnerability in each control area, the evaluators changed access fields, changed protected identities, inserted trap doors into system libraries and reached the system password file, and concluded that Multics "is not now secure" [5] (**Demonstrated**). One live penetration attempt crashed the system, and maintenance staff, unaware of the penetration, blamed a disk read error [5] (**Confirmed**). The report says the internal controls of then-current systems had repeatedly been shown insecure in penetration exercises and could not be corrected by patches, fix-ups or add-ons [5] (**Confirmed**), and it treats trap door insertion as a class of attack [5] (**Confirmed**).

In 2002 Karger and Schell looked back. They wrote that the key result was subverting protection with malicious software, trap doors and Trojan horses; that a trap door they planted was later distributed by Honeywell to another site and found only afterward; and that they had predicted distributing malicious software would become the attack of choice [6] (**Confirmed** that they report it).

In September 1975 Saltzer and Schroeder published "The Protection of Information in Computer Systems" in the *Proceedings of the IEEE* (vol. 63, no. 9, pp. 1278 to 1308), an invited tutorial [7] [8] (**Confirmed**). It set out eight design principles: economy of mechanism, fail-safe defaults, complete mediation, open design, separation of privilege, least privilege, least common mechanism and psychological acceptability, plus work factor and compromise recording, which the authors said apply imperfectly to computer systems [7] (**Confirmed**).

### 1.3 The ARPANET and Creeper

In 1971 Bob Thomas at BBN wrote Creeper, a demonstration of the RSEXEC capability for moving programs between TENEX hosts on the ARPANET, and Ray Tomlinson wrote Reaper to find and remove it [18] (**Reported**, Tomlinson interview). Tomlinson said no more than about 28 TENEX sites could have been visited, called Creeper technically a worm, and said it was "more like an allergy test" than an infection [18] (**Reported**). No contemporaneous BBN record was opened.

The first ARPANET abuse warning opened here is RFC 602 (December 1973). It says the network was open to abuse because sites had not secured remote use, many users chose easy-to-guess passwords, and TIP dial-in terminals required no user identification while their phone numbers circulated publicly [13] (**Confirmed**). It reports that two major serving hosts had crashed under suspicious circumstances and that a third system's privileged wheel password had been compromised by two Los Angeles high school students [13] (**Confirmed**).

### 1.4 Computer crime as clerical fraud

On 27 April 1976 the US General Accounting Office reported on *Computer-Related Crimes in Federal Programs* (FGMSD-76-27). It found 69 cases of improper computer use in federal programs, with losses over $2 million, and said the count is incomplete because agencies did not classify these as computer crimes [12] (**Confirmed**). Most offenders were system users with limited technical knowledge, not programmers, operators or analysts, which GAO called "contrary to widespread belief" [12] (**Confirmed**). Many crimes may have gone undetected or unreported: in one inventory system, military investigators estimated that only a fifth of losses were reported and that 80 percent of all thefts may have been computer related [12] (**Confirmed** as the investigators' estimate). The weaknesses were basic management controls: inadequate separation of duties was a major weakness in 7 of the 12 cases reviewed in detail, and in 7 of the 12 the controls existed but were not enforced [12] (**Confirmed**).

### 1.5 Passwords

In November 1979 Morris and Thompson published "Password Security: A Case History". Of 3,289 user-chosen UNIX passwords they examined, 2,831 (86 percent) were short strings or dictionary and name words, and a five-minute dictionary search found about a third [14] (**Confirmed**). The 1988 worm used the same weakness (Part 4.3).

## Part 2: the timeline

| Date | Event | Grade | Sources |
|---|---|---|---|
| Nov 1960 | *Bell System Technical Journal* 39(6) publishes Breen and Dahlbom on in-band trunk signaling | Confirmed | [1] |
| Jun to Oct 1967 | ARPA requests a study; the Defense Science Board task force on computer security forms | Confirmed | [2] |
| 11 Feb 1970 | Ware report: threat taxonomy, trap doors, insider infiltration; classified Confidential | Confirmed | [2] [3] |
| 1971 | Creeper (Bob Thomas, BBN) and Reaper (Ray Tomlinson) on TENEX hosts | Reported | [18] |
| Oct 1971 | *Esquire*, "Secrets of the Little Blue Box" | Reported | [15] |
| Mar 1972 to Jun 1973 | Air Force penetration of Multics; trap doors planted | Demonstrated | [5] |
| Oct 1972 | Anderson report: penetration is easy, the Trojan horse defined, the reference monitor introduced | Confirmed | [4] [10] |
| 29 Nov 1972 | *US v. Draper*, CR-72-973: nolo contendere plea to one count of wire fraud | Confirmed | [16] |
| Dec 1973 | RFC 602 warns of ARPANET abuse, easy passwords and unidentified dial-in terminals | Confirmed | [13] |
| Jun 1974 | Karger and Schell, *Multics Security Evaluation: Vulnerability Analysis* | Confirmed | [5] |
| Sep 1975 | Saltzer and Schroeder publish the eight design principles | Confirmed | [7] [8] |
| 10 Oct 1975 | Ware report declassified as R-609 | Confirmed | [2] |
| 20 Feb 1976 | Conduct charged in a second federal wire fraud complaint against Draper, CR-76-223 | Confirmed | [17] |
| 27 Apr 1976 | GAO FGMSD-76-27: 69 federal cases, mostly by users with limited technical knowledge | Confirmed | [12] |
| 1978 | Florida Computer Crimes Act, ch. 78-92 | Confirmed | [26] |
| Nov 1979 | Morris and Thompson, "Password Security: A Case History" | Confirmed | [14] |
| 15 Apr 1980 | Anderson, *Computer Security Threat Monitoring and Surveillance* (revised): masquerader, legitimate user, clandestine user | Confirmed | [9] |
| Jan 1981 | DoD Computer Security Center formed | Confirmed | [10] |
| 1981 | Chaos Computer Club founded | Confirmed | [74] |
| Early 1982 | Elk Cloner circulates on Apple II floppy disks around Mt. Lebanon, Pennsylvania | Reported | [19] [20] |
| 1982 to 1983 | The 414s enter systems at Los Alamos, Sloan-Kettering and Security Pacific | Reported | [21] |
| 3 Jun 1983 | 414s intrusion at Sloan-Kettering; about $1,500 of billing records deleted | Reported | [21] |
| 15 Aug 1983 | CSC-STD-001-83, the 1983 Trusted Computer System Evaluation Criteria (later superseded by the Orange Book) | Confirmed | [10] |
| 26 Sep 1983 | Neal Patrick of the 414s testifies before the US House | Reported | [21] |
| 1983 | 98th Congress, first session: hearings on the 414s; six computer-crime bills introduced in the House | Reported | [22] |
| 3 to 10 Nov 1983 | Fred Cohen's first experimental virus, conceived, built and demonstrated | Confirmed | [24] |
| By Mar 1984 | Three 414s members plead guilty to two counts of making harassing telephone calls (date of the cited NYT report) | Reported | [21] |
| Aug 1984 | Thompson, "Reflections on Trusting Trust" | Confirmed | [23] |
| 1984 | Cohen, "Computer Viruses: Theory and Experiments" | Confirmed | [24] [25] |
| 1984 | First Chaos Communication Congress | Confirmed | [74] |
| 12 Oct 1984 | Pub. L. 98-473 creates 18 U.S.C. 1030 | Confirmed | [27] |
| 17 Nov 1985 | Phrack issue 1 | Confirmed | [32] |
| 26 Dec 1985 | DoD 5200.28-STD, the Orange Book | Confirmed | [10] |
| Jan 1986 | Brain first detected, by F-Secure's account; NCSA (1989) also dates its origin to January 1986 | Reported | [34] [35] |
| 1986 to 1987 | First version of Jerusalem written, by F-Secure's account | Reported | [36] |
| Aug 1986 | Intrusions at Lawrence Berkeley Laboratory begin (home: Cuckoo's Egg study) | Confirmed | [43] [94] |
| 25 Sep 1986 | Phrack issue 7 publishes "The Conscience of a Hacker" | Confirmed | [33] |
| 16 Oct 1986 | Pub. L. 99-474, Computer Fraud and Abuse Act of 1986 | Confirmed | [29] |
| 1987 to 1988 | Mitnick and Lenny DiCicco intrude into DEC's Palo Alto laboratory (home: Mitnick study) | Reported | [45] |
| 23 Nov 1987 | Lehigh University warns of a COMMAND.COM virus | Confirmed | [37] |
| 9 Dec 1987 | First known CHRISTMA EXEC infection, about 1300 GMT | Confirmed | [39] |
| 11 Dec 1987 | BITNET warning relayed to RISKS; IBM internal mail reported jammed | Confirmed; Reported | [38] |
| 11 Dec 1987 | IBM's VNET mostly cleaned by a massive network shutdown | Confirmed | [39] |
| 14 Dec 1987 | CHRISTMA EXEC stamped out on BITNET | Confirmed | [39] |
| 16 Dec 1987 | EARN traces CHRISTMA EXEC to Clausthal-Zellerfeld | Confirmed | [40] |
| 7 Jan 1988 | AP: virus at Hebrew University, discovered the previous week | Reported | [41] |
| 8 Jan 1988 | Israeli press: virus also found in an IDF unit | Reported | [42] |
| 8 Jan 1988 | Computer Security Act of 1987 approved (Pub. L. 100-235) | Confirmed | [31] |
| Spring 1988 | Brain at the *Providence Journal-Bulletin*, 100 machines | Reported | [35] |
| May 1988 | Stoll, "Stalking the Wily Hacker", *Communications of the ACM* | Confirmed | [43] |
| 2 Nov 1988 | Morris worm released from an MIT computer (home: Five Hacks study) | Confirmed | [47] [48] [50] |
| 30 Nov 1988 | NSF issues an ethical network use statement | Confirmed | [50] |
| Dec 1988 | CERT/CC established by DARPA at the SEI; CA-1988-01 issued | Confirmed | [53] [57] |
| Dec 1988 | Mitnick indicted (counts covering DEC and Leeds University) | Reported | [44] |
| Jan 1989 | RFC 1087, IAB "Ethics and the Internet" | Confirmed | [52] |
| 2 Mar 1989 | Three West German hackers arrested over KGB espionage (home: Cuckoo's Egg study) | Reported | [60] |
| 10 Mar 1989 | Hans Huebner's statement on RISKS | Confirmed (his statement) | [61] |
| 15 Mar 1989 | Mitnick pleads guilty to possessing MCI codes and to computer fraud | Reported | [44] |
| 12 Jun 1989 | GAO IMTEC-89-57 on the Internet virus; released 20 July 1989 | Confirmed | [59] |
| Jun 1989 | Disk Killer first reported in the US | Confirmed | [68] |
| Jul 1989 | *Virus Bulletin*'s first editorial; 14 known MS-DOS viruses | Confirmed | [63] [69] |
| 16 Aug 1989 | CERT CA-1989-03, trojaned telnet binaries | Confirmed | [58] |
| Sep 1989 | *Virus Bulletin* reviews Cohen's Advanced Systems Protection | Confirmed | [65] |
| Oct 1989 | Law Commission Report No. 186 on computer misuse | Confirmed | [82] |
| 16 to 17 Oct 1989 | WANK worm on SPAN; CERT CA-1989-04 | Confirmed | [58] |
| Dec 1989 | RFC 1135, "The Helminthiasis of the Internet" | Confirmed | [50] |
| 8 to 12 Dec 1989 | AIDS Information disks posted from London | Confirmed | [68] |
| 12 Dec 1989 | First CIX message calling the AIDS disk a Trojan | Reported | [68] |
| 14 Dec 1989 | Disinfectant 1.5 for the Macintosh released | Confirmed | [68] |
| Jan 1990 | *Virus Bulletin*: 46 known MS-DOS viruses; AIDS disk analysis | Confirmed | [68] [69] |
| 9 Feb 1990 | Commons second reading of the Computer Misuse Bill | Confirmed | [82] |
| 15 Feb 1990 | Celle court convicts three men of selling data to the KGB | Reported | [62] |
| 1 Mar 1990 | Secret Service searches Steve Jackson Games (home: four books study) | Confirmed | [77] [78] |
| Mar 1990 | Keith Jackson proposes an international virus-naming body | Confirmed | [69] |
| 7 to 8 May 1990 | Operation Sundevil warrants executed in 13 cities (home: four books study) | Confirmed | [76] |
| 16 May 1990 | Morris convicted under 18 U.S.C. 1030(a)(5)(A), N.D.N.Y. | Confirmed | [47] |
| 29 Jun 1990 | Computer Misuse Act 1990 receives Royal Assent; in force about two months later | Confirmed | [79] |
| 1990 | FIRST formed | Confirmed | [56] |
| 7 Mar 1991 | Second Circuit affirms the Morris conviction | Confirmed | [47] [48] |
| 12 Mar 1993 | Steve Jackson Games judgment against the Secret Service | Confirmed | [77] |

## Part 3: personal computers and the first viruses, 1982 to 1990

### 3.1 Elk Cloner

In a 2007 AP interview Rich Skrenta, then a student at Mt. Lebanon Senior High School near Pittsburgh, said he wrote a self-copying program on his Apple II that spread to floppy disks, and began circulating it in early 1982 among friends at school and at a local computer club [19] (**Reported**, AP). Salon (2007) says he was a ninth grader who got the Apple II for Christmas 1981 and spread Elk Cloner by putting it on the school computer, so that it copied onto students' floppy disks [20] (**Reported**, Salon). No contemporaneous record of Elk Cloner was opened.

### 3.2 Fred Cohen and the word "virus"

Cohen's paper says the first virus was conceived on 3 November 1983 as an experiment for a weekly computer security seminar; Len Adleman suggested the name "virus"; it was built in 8 hours on a heavily loaded VAX 11/750 running Unix and demonstrated to the seminar on 10 November 1983 [24] (**Confirmed**). Cohen ran five controlled experiments with permission. In each, all system rights were obtained in under an hour, on average in under 30 minutes and at shortest in under 5, after which administrators banned further security experiments on the system [24] (**Confirmed** that the paper reports it; the result is **Demonstrated**). His paper, "Computer Viruses: Theory and Experiments", copyright 1984, defines a virus as a program able to attach itself to other programs and make them viruses too [25] (**Confirmed**), and shows that precise detection of a virus by its appearance is undecidable [24] (**Confirmed**). The anti-virus trade of 1989 already supplemented signature lists with integrity checkers and behavior monitors (Part 7.5); no source opened links that to Cohen's result (**Inferred** as a connection).

### 3.3 Ken Thompson's compiler

In his August 1984 Turing Award lecture, "Reflections on Trusting Trust", Ken Thompson showed that a compiler can carry a self-reproducing Trojan horse that inserts a back door into `login` and does not appear in any source code [23] (**Demonstrated**). His moral was that you cannot trust code you did not totally create yourself, and he credited the idea to an Air Force critique of Multics [23] (**Confirmed**), which ties the lecture to the evaluation in Part 1.2 (**Inferred**).

### 3.4 Brain

F-Secure describes Brain as possibly the oldest DOS virus and says it was first detected in January 1986 [34] (**Reported**: the date and the "oldest" claim are F-Secure's, which was founded in 1988). Its technical description is firm: Brain is a boot-sector virus that checks for its own signature, so that disks can be inoculated; it hooks INT 13 to show the clean original boot sector when an infected one is read, an early stealth technique; it relabels the volume; and it carries its authors' names and their shop address in Lahore, Pakistan [34] (**Confirmed**). A 1989 NCSA analysis by David Stang says Brain originated in January 1986 in Lahore, infects 5.25-inch floppies but not hard disks, did no known intentional damage, and caused its first noticeable infections in 1988, including 100 machines at the *Providence Journal-Bulletin* in spring 1988 [35] (**Reported**, NCSA). *Virus Bulletin*'s first editorial (July 1989) said Brain drew fascination rather than alarm, that by 1989 hundreds of businesses had been hit, and that floppy disks let viruses spread exponentially through unsuspecting users [63] (**Confirmed**).

### 3.5 Jerusalem and the Israeli virus

F-Secure says Jerusalem infects `.COM` and `.EXE` files, activates on every Friday the 13th by deleting programs run that day, and that its first version was written as early as 1986 [36] (**Confirmed** for the technical description; **Reported** for the 1986 date). An AP report of 7 January 1988, reprinted in RISKS 6.6, said a virus had infected Hebrew University computers; senior programmer Yisrael Radai said it was discovered the previous week, that an antidote had been developed and that other Israeli institutions were affected [41] (**Reported**, AP). An Israeli newspaper of 8 January 1988, translated in RISKS 6.12, said the "Israeli virus" was also found in an IDF unit and that the university was distributing immunization programs [42] (**Reported**). The sources opened here do not tie the Hebrew University virus to the virus F-Secure calls Jerusalem, so this study keeps them apart (**Inferred**).

### 3.6 Lehigh, nVIR and the vendor's demo disk

On 23 November 1987 Lehigh University warned of a virus that rode in `COMMAND.COM`, spread when an infected PC accessed another disk, and erased all disks after four infections; many disks at public sites were hit within days [37] (**Confirmed**). *Virus Bulletin* described a 15-person printing firm whose Macintosh II network caught nVIR from a client's own copy of software; it was cleaned with Disinfectant 1.0 and checked with Virus Detective [63] (**Confirmed**). The same issue relays a second-hand account, from a conference in Turin in May 1989, of an Israeli anti-virus vendor whose graphics demo diskette carried a self-erasing virus after its sales pitch failed [63] (**Reported**, as relayed by *Virus Bulletin*). If accurate, it is an early vendor-seeded supply-chain incident (**Inferred**).

### 3.7 Disk Killer

Disk Killer (also called Ogre) was first reported in the US in June 1989. It is a boot-sector virus that infects hard disks and diskettes, spreads only by booting from an infected diskette, and encrypts the bootable partition after 48 hours of uptime; *Virus Bulletin* groups it with Brain, Italian and New Zealand and published Fridrik Skulason's analysis [68] (**Confirmed**). Of the period's malware with a technical record opened here, it is the clearest case of encryption used for impact (**Inferred**).

### 3.8 The AIDS Information disk

This study is the home for the AIDS Trojan; the library's [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) begins in 2019. Several thousand "AIDS Information Version 2.0" disks from "PC Cyborg Corporation" were posted from London between 8 and 12 December 1989 to recipients in the UK, Europe, Africa, Scandinavia and Australia; the UK mailing used *PC Business World*'s subscriber list, obtained by deception [68] (**Confirmed**). Estimates rose from about 10,000 disks to nearer 20,000, and *Virus Bulletin* relays that delegates to the October 1988 Stockholm AIDS congress had also been targeted and that the WHO issued an alert [68] (**Reported**, as relayed). Jim Bates' disassembly found that the installer rewrote `AUTOEXEC.BAT` to run itself at each boot and, after a count of reboots, hid directories and encrypted file names in the root directory, not file contents, then printed an invoice for "leasing" the software payable to a PO box in Panama [68] (**Confirmed**). Bates wrote the AIDSOUT removal and CLEARAID recovery programs, and New Scotland Yard's Computer Crime Unit led the investigation [68] (**Confirmed**). *Virus Bulletin*'s editorial said only checksumming programs revealed the `AUTOEXEC.BAT` change, and virus-specific software was useless against the unknown threat [68] (**Confirmed**). CNN (2021) says the disk demanded $189, that the scheme was traced to Joseph Popp, who was arrested and charged with blackmail, and calls it the first act of ransomware [70] (**Reported**, CNN). The contemporaneous analysis calls it an attempt to extort money from PC users [68], so the "ransomware" label is retrospective (**Inferred**).

### 3.9 How many viruses

*Virus Bulletin* counted known MS-DOS viruses rising from 14 in July 1989 to 46 in January 1990 [69] (**Confirmed** as the journal's count). The same journal's naming troubles (Part 7.6) mean the counts depended on how variants were grouped (**Inferred**).

## Part 4: networks and worms, 1986 to 1990

### 4.1 The Cuckoo's Egg (summary)

The [Cuckoo's Egg study](/case-studies/CUCKOOS_EGG_1986.md) is the home for this case. Clifford Stoll's "Stalking the Wily Hacker" (*Communications of the ACM*, May 1988) traces a German intruder on US military networks who used operating-system security holes, and asks whether it was espionage [43] (**Confirmed**). The library study records the intruder trying about 450 computers and entering more than 30, mostly through default account names and guessed passwords, arriving through X.25, Tymnet and dial-out modems [94] (**Confirmed** as the library study's record). On 2 March 1989, according to ARD *Panorama* as relayed by Klaus Brunnstein, three hackers were arrested in Berlin, Hamburg and Hannover and accused of computer espionage for the KGB [60] (**Reported**). On 10 March 1989 Hans Huebner ("Pengo") wrote that a circle he had belonged to tried to make deals with an eastern secret service, that he gave German authorities detailed information in summer 1988, and that the Chaos Computer Club as an organization was in no way connected [61] (**Confirmed** as his statement). On 15 February 1990 a court in Celle convicted Peter Carl, Markus Hess and Dirk Brzezinski of selling the KGB information from Western military databases for $54,000, with suspended terms of up to two years; the judge said no serious damage to West Germany had arisen [62] (**Reported**, Los Angeles Times).

### 4.2 CHRISTMA EXEC

The Christmas Tree EXEC was a REXX program for IBM VM/CMS. It was sent as a file rather than as mail, drew a tree, and picked its next targets from the user's NAMES and NETLOG files [39] [38] (**Confirmed**). Ross Patterson's account in RISKS 5.80 puts the first known infection at about 1300 GMT on Wednesday 9 December 1987; it was stamped out on BITNET by Monday 14 December, and on IBM's internal VNET, which it reached a day later, it was mostly killed by a massive network shutdown on the Friday [39] (**Confirmed**). A BITNET warning relayed to RISKS told CMS sites not to run it because it was stressing BITNET and spool systems [38] (**Confirmed**), and a newspaper item quoted there said IBM's internal mail was jammed and links were turned off for 45 to 90 minutes to purge it [38] (**Reported**). An EARN statement of 16 December 1987 traced it to node DCZTU1 at Clausthal-Zellerfeld: a student wrote it to send Christmas greetings and another student, not knowing what he was doing, started the spread [40] (**Confirmed**). It spread because each recipient ran it, which makes it the period's clearest user-execution worm (**Inferred**).

### 4.3 The Morris worm (summary)

The [Five Hacks study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) is the home for the Morris worm. Morris released the worm on 2 November 1988 from a computer at MIT, chosen to hide its Cornell origin; the Second Circuit lists four methods: a hole in sendmail, a bug in the finger daemon, the trusted-hosts feature and password guessing [47] [48] (**Confirmed**). RFC 1135 adds that the sendmail route used its debug command, that the fingerd attack overflowed a buffer read with `gets()` and hit only 4.3BSD VAX machines, that the worm infected VAX and Sun-3 systems running 4.2 and 4.3 BSD, that it chose targets from `hosts.equiv`, `.rhosts` and `.forward` files, routing-table gateways, point-to-point peers and random addresses on first-hop networks, and that its cracking phase used clues from `/etc/passwd`, a 432-word list and the system dictionary before posing as the legitimate user [50] (**Confirmed**). It hid itself and left little evidence; users saw overloaded systems and filled file space [50] (**Confirmed**). Its reinfection design, copying on every seventh "yes", caused far more copying than Morris expected, and machines crashed or became "catatonic" [47] [48] (**Confirmed**). The court records his goal as showing the inadequacy of network security measures of the day [48] (**Confirmed**). Per-installation costs ranged from $200 to more than $53,000 [48] [49] (**Confirmed**), and the widely quoted 6,000 infected machines was an extrapolation: MIT staff guessed a 10 percent infection rate for MIT's 2,000 hosts, against an estimate of 60,000 Internet hosts, and the press turned it into "at least 6,000 machines" [51] (**Confirmed**). RFC 1135 concludes that defenses must be at the host level and that most sites were cleaned within 48 to 72 hours [50] (**Confirmed**). The conviction is in Part 6.3.

### 4.4 WANK on SPAN

CERT advisory CA-1989-04 (17 October 1989; CERT notified on 16 October) reports the WANK worm on the SPAN network of DEC VAX/VMS machines. It spread only over DECnet, exploited passwords that were blank or equal to the account name, created an account, reset the default DECNET password, left the FIELD account as a privileged trap door and appended code to `.com` files [58] (**Confirmed**). CERT called it similar to the previous year's HI.COM ("Father Christmas") worm [58] (**Confirmed**). FIRST's history says WANK showed the need for coordination among response teams [56] (**Confirmed**).

### 4.5 The telnet logger

CERT advisory CA-1989-03 (16 August 1989) warned that telnet binaries on many UNIX hosts had been replaced with versions that logged outgoing usernames and passwords, and that intruders then reached the hosts in those logs [58] (**Confirmed**). It said guest accounts and trivial passwords were common targets, warned that TFTP and anonymous FTP could expose `/etc/passwd`, and advised comparing checksums of critical network programs against the originals [58] (**Confirmed**).

### 4.6 The first CERT advisory and an early phish

CERT/CC's first advisory, CA-1988-01 "ftpd Vulnerability" (December 1988), followed "several problems or attacks" in recent weeks; it advised sendmail 5.59 with debug disabled, the ftpd patches, and checking `/etc/passwd` for bogus uid 0 accounts [57] (**Confirmed**). Just after this study's window, RFC 1244 cites CERT advisory CA-91:03 (April 1991): messages posing as local administrators told users to change their passwords to a value given in the message [53] (**Confirmed**). It is an early CERT-recorded credential phish and shows the Mitnick-style pretext moving into written messages (**Inferred**; the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for pretext calls [94]).

## Part 5: the people and the scene

### 5.1 The 414s and Congress

The 414s, a group from Milwaukee, broke into systems at Los Alamos National Laboratory, Sloan-Kettering (on 3 June 1983, deleting about $1,500 of billing records) and Security Pacific in 1982 and 1983; the systems ran DEC VMS and RSTS/E, and they got in with common or default passwords [21] (**Reported**, encyclopedia). Neal Patrick testified before the US House on 26 September 1983, and three members later pleaded guilty to two counts of making harassing telephone calls, according to the encyclopedia's citation of the *New York Times* of March 1984, which was not opened [21] (**Reported**). The abstract of Bailey's paper at the IEEE Symposium on Security and Privacy (30 April 1984) says several days of hearings in the first session of the 98th Congress covered the 414s and others, and six computer-crime bills were introduced in the House [22] (**Reported**). In his 1984 lecture Thompson criticized the press for making heroes of "hackers" such as the 414 gang and the Dalton gang, and called their acts vandalism at best and trespass and theft at worst [23] (**Confirmed** as his view).

### 5.2 The newsletter scene and war dialing

Phrack issue 1 (17 November 1985) carried an article on a dial-up security system and a list of school and college computer dial-up numbers [32] (**Confirmed**), which shows modem numbers being traded on bulletin boards (**Inferred**). Lists like that could be compiled by war dialing, sweeping blocks of numbers with an autodialer for answering modems; no primary naming the practice was opened, so this is the study's reading (**Inferred**). The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) covers social engineering for modem numbers and a modem line redirected to a log-in simulator, as testimony [94] (**Confirmed** as the library study's record).

Phrack Vol. One, Issue 7 (released 25 September 1986, editor Taran King), file 3 of 10, is "The Conscience of a Hacker" by The Mentor, the text later known as the "Hacker's Manifesto"; the text is dated 8 January 1986 and its preface says it was written shortly after the author's arrest [33] (**Confirmed** as publication). Its claims about hackers' motives and about the authorities are the scene's self-description and polemic, not evidence of fact (**Inferred**), and the same issue mixed it with how-to files that this study does not describe [33] (**Confirmed**). The popular identification of The Mentor with an employee named in the 1990 Steve Jackson Games warrant is made by no source opened here, and this study does not make it (**Inferred**).

The Chaos Computer Club was founded in 1981 and has held the Chaos Communication Congress since 1984 [74] (**Confirmed**).

### 5.3 Kevin Mitnick (summary)

The [Kevin Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for Mitnick. In 1987 and 1988 Mitnick and Lenny DiCicco made repeated intrusions into Digital Equipment's Palo Alto laboratory from a Calabasas company; DiCicco confessed to his employer, who notified DEC and the FBI, and DEC claimed several million dollars in stolen software [45] (**Reported**, *Takedown* excerpt). On 15 March 1989 Mitnick pleaded guilty to possessing 16 unauthorized MCI long-distance codes and to one count of computer fraud for copying a DEC security program; the prosecutor estimated $100,000 to $200,000 in DEC computer downtime; two counts from the December 1988 indictment (DEC, Leeds University) were to be dropped; and the agreed terms were 12 months plus three years of supervision before Judge Pfaelzer [44] (**Reported**, UPI). The Ninth Circuit's 1998 opinion in *US v. Mitnick* addresses only supervised-release conditions restricting computers and cellular telephones [46] (**Confirmed**).

## Part 6: the law

### 6.1 Florida, 1978

Florida Statutes chapter 815 carries the short title "Florida Computer Crimes Act", with the history note "s. 1, ch. 78-92" (Laws of Florida 1978) [26] (**Confirmed**). The 1978 act created sections 815.04 (offenses against intellectual property), 815.06 (offenses against computer users) and 815.07 [26] (**Confirmed**). Section 815.02 states a legislative finding that computer-related crime is a growing problem in government and the private sector, with per-incident losses exceeding other white-collar crime; the current text was amended in 2014, so its 1978 wording is not checked here [26] (**Confirmed** for the current text). No source opened says Florida's act was the first state computer-crime law, so this study calls it one of the first (**Inferred**). Florida later added section 815.062 on ransomware-type attacks on governmental entities (s. 6, ch. 2022-220) [26] (**Confirmed**), outside this study's window.

### 6.2 The federal statute: 1984 and 1986

Public Law 98-473 (12 October 1984), a continuing-appropriations joint resolution for fiscal year 1985, carries in Chapter XXI the "Counterfeit Access Device and Computer Fraud and Abuse Act of 1984" (98 Stat. 2190) [27] (**Confirmed**). Section 2102(a) created 18 U.S.C. 1030 with three offenses: unauthorized access to obtain protected national-defense or foreign-relations information or restricted data; obtaining financial-institution or consumer-reporting records; and misuse of, or preventing use of, US Government computers [27] (**Confirmed**). The 1984 text used "knowingly", reached authorized users who used their access for purposes beyond the authorization, and excepted mere use of the computer from (a)(2) and (a)(3) [27] (**Confirmed**). Penalties for (a)(1) ran to 10 years and the greater of $10,000 or twice the value obtained, with 20 years and $100,000 for repeat offenses; (a)(2) and (a)(3) carried a lower tier starting at the greater of $5,000 or twice the value or loss [27] (**Confirmed**). The Justice Department says Congress put the computer-access provisions in the 1984 crime control act because the wire and mail fraud statutes lacked the needed tools [28] (**Confirmed**).

Public Law 99-474 (H.R. 4718, 16 October 1986, 100 Stat. 1213), the "Computer Fraud and Abuse Act of 1986", amended section 1030 [29] (**Confirmed**). It changed "knowingly" to "intentionally" in (a)(2), replaced the "uses the opportunity" wording with "exceeds authorized access", rewrote (a)(3) and struck the "It is not an offense" language [29] (**Confirmed**). It added (a)(4), fraud through a Federal interest computer; (a)(5), unauthorized access that damages information or prevents use, causing a loss of $1,000 or more in a year or impairing medical care; and (a)(6), trafficking in passwords with intent to defraud [29] [30] (**Confirmed**). It struck the section's own conspiracy offense in 1030(b) and replaced fixed fines with fines "under this title" [30] (**Confirmed**). The Justice Department says the 1986 act followed 1985 House and Senate hearings and limited federal jurisdiction to cases of compelling federal interest, to balance state law [28] (**Confirmed**), and that Congress amended the CFAA again in 1988, 1989, 1990, 1994, 1996, 2001, 2002 and 2008 [28] (**Confirmed**). The Morris opinion records that the Senate Report aimed (a)(3) and (a)(5) at "outsiders" with no authorization to any federal interest computer [48] (**Confirmed**).

The Computer Security Act of 1987 (Public Law 100-235, approved 8 January 1988) gave the National Bureau of Standards responsibility for federal computer security standards, required security plans for federal systems holding sensitive information and mandatory periodic security training, with the aim of preventing computer-related fraud and misuse [31] (**Confirmed**).

### 6.3 The Morris conviction

After a jury trial in the Northern District of New York, Morris was convicted under 18 U.S.C. 1030(a)(5)(A), added by section 2(d) of the 1986 act, by judgment of 16 May 1990, and sentenced to three years of probation, 400 hours of community service, a $10,050 fine and the costs of his supervision [47] [48] (**Confirmed**). The Second Circuit (argued 4 December 1990, decided 7 March 1991, 928 F.2d 504) held that the provision does not require intent to prevent authorized use or to cause loss, found sufficient evidence of access without authorization, and affirmed [47] [48] [49] (**Confirmed**). OpenJurist's editorial summary, not the opinion, calls this the first conviction under the CFAA [47] (**Reported**). RFC 1135 quotes an American Bar Association survey that put known computer-crime losses "as high as $730 million" [50] (**Reported**: a survey estimate relayed in a secondary quotation).

### 6.4 The United Kingdom: Computer Misuse Act 1990

On 9 February 1990 Michael Colvin MP moved the Commons second reading of the Computer Misuse Bill, naming three categories: unauthorized access, access with ulterior intent and unauthorized modification [82] (**Confirmed**). He said the bill was closely based on Law Commission Report No. 186 (October 1989) and drew on Scottish Law Commission Report No. 106 (1987) [82] (**Confirmed**). A member in the debate cited the penetration of the Duke of Edinburgh's Prestel mailbox, which the speaker dated to 1987, and the Gold and Schifreen ruling in the House of Lords that the conduct was not forgery [82] (**Reported**, as the speaker's account; the judgment was not opened). The Computer Misuse Act 1990 (c. 18), "an Act to secure computer material against unauthorised access or modification", received Royal Assent on 29 June 1990 [79] (**Confirmed**) and came into force at the end of two months beginning with that day, which is late August 1990 by this study's computation [79] (**Confirmed** for the rule). Its original offenses were section 1, unauthorized access; section 2, access with intent to commit further offenses; and section 3, unauthorized modification; section 1 was summary-only, with up to six months and/or a level 5 fine [80] (**Confirmed**). Sections 3ZA (serious damage) and 3A (articles for use in offenses) are later amendments, not 1990 text [81] (**Confirmed**).

### 6.5 Operation Sundevil and Steve Jackson Games (summary)

The [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home for these cases. A press release from the US Attorney for the District of Arizona dated 9 May 1990, reprinted in *Computer Underground Digest* 1.09, says about 27 search warrants were executed on 7 and 8 May 1990 by 150 Secret Service agents with state and local officers in 13 listed cities, as part of Operation Sundevil, a two-year investigation of credit card and long-distance code abuse and computer intrusions; three people were arrested on collateral state charges [76] (**Confirmed**). The *Chicago Tribune* of 10 May 1990, reprinted in the same issue, reported no arrests for computer crime and about 40 computers and 23,000 disks seized nationwide [76] (**Reported**). Separately, on 1 March 1990, Secret Service agents searched Steve Jackson Games under an affidavit of 28 February 1990 seeking evidence of violations of 18 U.S.C. 1030 and 2314, and seized the "Illuminati" bulletin board computer holding 162 unread private e-mails [77] [78] (**Confirmed**). The district court (signed 12 March 1993) found violations of the Privacy Protection Act and the Stored Communications Act, awarded $42,259 in damages and assessed $1,000 in statutory damages for each plaintiff [77] (**Confirmed**); the Fifth Circuit's opinion records $51,040 in Privacy Protection Act damages and held on 31 October 1994 that seizing stored, unread e-mail was not an "intercept" under the Wiretap Act as amended by the ECPA of 1986 (Pub. L. 99-508), and affirmed [78] (**Confirmed**). The two opinions as opened state the damages differently, $42,259 in the district court text and $51,040 in Privacy Protection Act actual damages in the Fifth Circuit's account, and this study reports both as stated (**Inferred** that they need reconciling). The search came two months before the Sundevil warrants and the 1993 decision never mentions Sundevil, so accounts that place the raid inside Sundevil overstate the link [77] [76] (**Inferred**).

## Part 7: the defense that grew up

### 7.1 Design principles and evaluation criteria

The defense began as theory. The reference monitor (1972) and the Saltzer and Schroeder principles (1975) are the design ideas the later criteria built on (Part 1.2); the Orange Book cites Anderson [10] (**Confirmed**), while a text search found no citation of Saltzer and Schroeder by name [10]. The DoD Computer Security Center was formed in January 1981, and the Orange Book says its criteria evolved from earlier NBS and MITRE evaluation material [10] (**Confirmed**). DoD 5200.28-STD, the Trusted Computer System Evaluation Criteria or "Orange Book", is dated 26 December 1985 and supersedes CSC-STD-001-83 of 15 August 1983 [10] (**Confirmed**). It has four divisions (D, C, B, A) and the classes C1, C2, B1, B2, B3 and A1; class C2, Controlled Access Protection, requires individual accountability through login, auditing of security-relevant events, and resource isolation [10] (**Confirmed**). The higher classes require enforced least privilege and a trusted computing base that makes significant use of layering, abstraction and data hiding; the Orange Book cites Ware and Anderson, and a text search found no citation of Saltzer and Schroeder by name [10] (**Confirmed**). NIST hosts the UC Davis compilation *Early Computer Security Papers (1970-1985)*, which says computer security was first studied as a discipline in the early 1970s [11] (**Confirmed**).

### 7.2 Defense in depth, before the phrase

The current NIST glossary defines defense-in-depth as integrating people, technology and operations to create barriers across multiple layers, and in the industrial sense as layered countermeasures [83] (**Confirmed**). None of the 1970 to 1985 primaries opened here uses the phrase; the idea appears as Ware's combination of safeguards and the Orange Book's layering [3] [10] (**Inferred**). This study does not date the phrase before 1990.

### 7.3 Watching users: an early design for intrusion detection

Anderson's *Computer Security Threat Monitoring and Surveillance* (26 February 1980, revised 15 April 1980) says internal penetration is in many installations more frequent than external penetration, and that an external penetrator becomes an internal threat once past the access controls [9] (**Confirmed**). It defines three internal threat classes (the masquerader, the legitimate user and the clandestine user), calls legitimate-user misuse misfeasance, and proposes detecting masqueraders by abnormal time, frequency, data volume and reference patterns in audit trails [9] (**Confirmed**). Anderson's masquerader, someone using another user's ID and password, is the class ATT&CK now names `T1078` Valid Accounts [84] (**Inferred**); insider misfeasance has no ATT&CK technique of its own (**Inferred**).

### 7.4 Incident response after the worm

RFC 1135 records the Internet Activities Board and NSF responses to the worm, including an NSF ethical network use statement of 30 November 1988, and suggests a central repository for security fixes [50] (**Confirmed**). RFC 1087, the IAB's "Ethics and the Internet" (January 1989), deems unethical any activity that purposely seeks unauthorized access, disrupts use, wastes resources, destroys the integrity of information or compromises privacy, and calls negligent Internet-wide experiments irresponsible [52] (**Confirmed**). RFC 1244 (July 1991) states that CERT/CC was established in December 1988 by DARPA to address the security concerns of Internet research users, operated by the Software Engineering Institute at Carnegie Mellon, and by 1991 describes a "CERT System" of response teams coordinated by NIST [53] (**Confirmed**). The SEI says Richard Pethia was CERT's founding director, serving from 1988 to 2016, and that the division grew from the CERT Coordination Center, a small incident-response group, into a research organization of more than 200 people; it calls CERT "the birthplace of cybersecurity", which is the organization's own framing [55] (**Confirmed** as the SEI's statement). RFC 1281 (November 1991), written by authors at `cert.sei.cmu.edu`, points operators to computer emergency response centers [54] (**Confirmed**). FIRST's history says the CERT Coordination Center formed weeks after the November 1988 worm, that the Department of Energy then formed CIAC, that the October 1989 WANK worm showed the need for coordination, and that FIRST formed in 1990 with five member teams that year [56] (**Confirmed** as FIRST's history). The GAO's June 1989 report on the worm recommended an interagency Internet security focal point under the Office of Science and Technology Policy; the recommendation is recorded as Closed, Not Implemented, and the product page gives no infection count or cost figure [59] (**Confirmed**).

### 7.5 The anti-virus trade

By 1989 there was a market. *Virus Bulletin*'s July 1989 Macintosh list included Vaccine, Gatekeeper, Warning, Virus Detective, Disinfectant, Virus Rx (described as Apple's own) and Interferon, and warned that old versions missed new strains; updates came by disk or from the `comp.virus` archive [63] (**Confirmed**). Its first product review covered Dr. Solomon's Anti-Virus Toolkit v2.2 (49 pounds): identification, disk utilities, write-protection, per-virus inoculation and a checksum checker the reviewer judged cryptographically weak [63] (**Confirmed**). Its table of known IBM PC viruses published a search pattern and offset for each virus so that readers could look for them with general tools such as the Norton Utilities, a form of signature scanning before dedicated scanners [63] (**Confirmed**). In November 1989 it reviewed FLUSHOT+, a memory-resident MS-DOS monitor that intercepts illegal disk operations and asks the user, which is behavior blocking, and listed Macintosh products by license: SAM and Virex commercial, Disinfectant free, Virus Detective shareware [66] (**Confirmed**). In September 1989 it reviewed Fred Cohen's commercial Advanced Systems Protection; the August issue had noted its award and announced a review of Symantec Antivirus for Macintosh [65] (**Confirmed**). By January 1990 it was publishing dissections from Abingdon, England, and recorded Disinfectant 1.5 for the Macintosh, released on 14 December 1989 [68] (**Confirmed**). After the AIDS disk, firms offered "AIDS clearing" and protection services, an opportunist market around outbreaks [68] (**Confirmed**).

The companies date themselves to these years. G DATA says it was founded in Bochum in 1985 [71] (**Confirmed** as the company's history) and that it developed the world's first anti-virus program in 1987 [71] (**Reported**: a contested vendor claim). Avast's own history says Pavel Baudis and Eduard Kucera founded Alwil in Prague in 1988 [72] (**Confirmed** as the company's history). WithSecure, formerly F-Secure, says it was founded in Helsinki in 1988 as Data Fellows by Petri Allas and Risto Siilasmaa, and claims the first heuristic anti-virus scanner in 1991 [73] (**Confirmed** for the founding; the "first" is **Reported**).

### 7.6 Naming

*Virus Bulletin*'s first tables already carried aliases, for example Peace also known as Drew or MacMag, and nVIR relatives Hpat, AIDS and MEV# [63] (**Confirmed**). In August 1989 it stopped using infective length as an alias because it caused confusion [64] (**Confirmed**). Its December 1989 editorial set out the problem: the first examiner names a virus with no consensus, length-based names (Jerusalem as 1813, Datacrime as 1168 or 1280) compete with descriptive names, and it was unclear whether 1701, Cascade, Fall, Hailstorm and 1704 were one virus; it called for a common glossary [67] (**Confirmed**). In March 1990 Keith Jackson proposed an international naming body modeled on the International Astronomical Union and on biological taxonomy, with neutral names assigned first and classification later [69] (**Confirmed**). Microsoft today names malware according to the CARO malware naming scheme [75] (**Confirmed**); CARO's founding date and early scheme were not opened, so this study gives no year for them.

## Part 8: the defender view

### 8.1 Credentials are the perimeter

From RFC 602 in 1973 to WANK in 1989, the intrusions in the primary record mostly entered through weak, default, blank or shared credentials and implicit host trust, not novel code [13] [50] [58] (**Inferred**). Every default account, blank password and dictionary password the period's advisories named is still the first thing to find and fix today; the library's [industrial control systems study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) records default credentials used against exposed HMIs and decoys in 2025 [96] (**Confirmed** as that study's record).

### 8.2 Trust relationships are lateral-movement paths

The Morris worm needed no exploit to move between hosts that trusted each other through `hosts.equiv` and `.rhosts` [50] (**Confirmed**). The modern form is any credential, key or token that one system accepts from another without re-authentication (**Inferred**).

### 8.3 Integrity checking finds what signatures miss

Cohen proved that detection by appearance is undecidable [24], CERT asked for checksums of network binaries in 1989 [58], and *Virus Bulletin* found that only checksumming caught the AIDS disk [68] (all **Confirmed**). File integrity monitoring remains the control that finds an unknown change (**Inferred**).

### 8.4 Media and imported software are an entry point

Boot-sector viruses rode on floppies; nVIR rode on a client's software copy; the AIDS Trojan arrived in the post [34] [63] [68] (**Confirmed**). The library's [Stuxnet study](/case-studies/STUXNET.md) maps removable-media spread to `T1091` in 2009 and 2010 [96] (**Confirmed** as that study's record), twenty years after Brain.

### 8.5 Trusted sources can be subverted

The Multics trap door went out through the vendor and Thompson's compiler hid its back door from the source [6] [23] (**Demonstrated**). The library's studies of [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md), [XZ Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) record the same class of attack carried out in practice decades later (**Inferred** as a lineage).

### 8.6 Insiders and controls that exist on paper

GAO's 1976 finding that controls existed but were not enforced in 7 of 12 cases [12], and Anderson's 1980 point that internal penetration was more frequent than external [9], are still the case for separation of duties and for auditing what legitimate users do (**Inferred**).

### 8.7 Coordination is a control

The worm was cleaned in 48 to 72 hours by an informal Berkeley and MIT response [50], and the institutions that followed (CERT/CC, CIAC, FIRST) made that coordination permanent [53] [56] (**Confirmed**). Knowing whom to call is part of the defense (**Inferred**).

## Part 9: what is overstated and what is understated

### 9.1 Overstated

- **"Firsts".** "First virus", "first anti-virus" and "first ransomware" are contested, often vendor marketing, and usually later labels: G DATA's "world's first anti-virus program" is its own claim [71]; F-Secure calls Brain possibly the oldest DOS virus [34]; CNN's "first act of ransomware" dates from 2021 [70], while *Virus Bulletin* in 1990 called the AIDS disk an attempt to extort money [68]. The 1989 trade press itself shows names and counts were inconsistent [67] (**Inferred**).
- **The AIDS disk as file encryption.** It encrypted file names in the root directory, not file contents [68] (**Confirmed**). Calling it ransomware that encrypted files overstates it (**Inferred**).
- **The size of the Morris worm.** The 6,000-machine figure is an extrapolation [51] (**Confirmed**), and the court record gives costs only per installation [48] (**Confirmed**). Aggregate damage figures often repeated for the worm appear in none of the primaries opened here (**Inferred**).
- **The first CFAA conviction.** That label for Morris comes from OpenJurist's summary, not the opinion [47] (**Reported**).
- **Florida as the first state law.** No source opened says so; "one of the first" is what the record supports [26] (**Inferred**).
- **The 1979 "Ark" intrusion.** No court record or other document opened records a 1979 intrusion into DEC by Mitnick; the court-side record opened covers the December 1988 indictment and 1987 to 1988 conduct [44] [46]. The episode rests on Mitnick's memoir, which was not opened, so any use of it must be graded Reported to the memoir (**Inferred**).
- **Steve Jackson Games as part of Sundevil.** The search preceded the Sundevil warrants by two months and the 1993 decision never mentions Sundevil [77] [76] (**Inferred**).
- **The whiz-kid hacker.** GAO in 1976 found most offenders were users with limited technical knowledge, "contrary to widespread belief" [12], and Thompson in 1984 rejected the heroic press image [23] (**Confirmed**).
- **Survey loss totals.** The ABA's "as high as $730 million" is a survey estimate relayed in a quotation [50] (**Reported**).
- **The worm as the cause of CERT/CC.** RFC 1244 gives December 1988 [53] and FIRST says CERT/CC formed weeks after the November worm [56]. Neither states that the worm caused it, so accounts that say it did, or that date CERT/CC to November 1988, go beyond the record opened (**Inferred**).

### 9.2 Understated

- **The 1970s threat record.** Government reports from 1970 to 1974 already documented routine penetration of time-sharing systems, trap doors and Trojan horses [3] [4] [5]. Histories that begin with Elk Cloner or Brain miss it (**Inferred**).
- **Credentials and trust as the main vector.** From RFC 602 to WANK and CA-1989-03, the primary record shows weak, default or shared credentials and implicit host trust far more often than novel code [13] [50] [58] (**Inferred**).
- **People as the network.** Hand-carried floppies, public lab disks, client software and mailed demo disks carried viruses to business machines with no modem at all [37] [63] [68] (**Inferred**).
- **Unreported insider fraud.** In one inventory system investigators estimated only a fifth of losses were reported, and agencies did not classify computer crime as such [12] (**Confirmed**).
- **How early supply-chain subversion was shown.** Karger and Schell predicted in the 1970s that distributing malicious software would become the attack of choice [6] (**Confirmed** that they report the prediction).
- **The defenders' own early work.** Integrity checkers, behavior blockers and shared signature tables were all in print by 1989 [63] [66] (**Confirmed**), well before the anti-virus industry's later marketing (**Inferred**).

## Part 10: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every event here predates ATT&CK by decades, so every row is this study's retrospective mapping of behavior the cited source describes, not a mapping MITRE publishes. Every technique id was checked against the library's `data/attack/technique_profiles.jsonl` and `superseded_by.jsonl` on 11 November 2026, and each has a generated page on main [95]; `T1078`, `T1210`, `T1554`, `T1098`, `T1486`, `T1091` and `T1684` were also opened on the live ATT&CK site [84] [85] [86] [87] [88] [89] [90]. Tactic names are the v20.0 tactics in the library's data. Ids that could not be checked are left out.

### 10.1 Objects

| Object | ATT&CK id | Library page | Relationship |
|---|---|---|---|
| Group | none | none | ATT&CK has no group object for the 414s, the Hannover hackers, the phreaks or any 1960 to 1990 actor [95] |
| Software | none | none | No software object covers Creeper, Elk Cloner, Brain, Jerusalem, Lehigh, nVIR, Disk Killer, the AIDS Trojan, CHRISTMA EXEC, the Morris worm or WANK; a name search of `data/attack/software.jsonl` found none [95] |
| Campaign | none | none | No campaign object covers any event in this study [95] |

### 10.2 ATT&CK Enterprise techniques the record describes (21)

The grade is the grade of the underlying record. The mapping itself is this study's reading.

| ID | Name | Tactic(s) | Dated event or report | Grade | Sources |
|---|---|---|---|---|---|
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | Lateral Movement | Morris worm: sendmail debug and the fingerd `gets()` overflow, 2 Nov 1988 | Confirmed | [47] [48] [50] [85] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Brute Force: Password Guessing | Credential Access | Morris worm, 2 Nov 1988; WANK blank and account-name passwords, 16 Oct 1989 | Confirmed | [48] [50] [58] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Brute Force: Password Cracking | Credential Access | Morris worm 432-word list and system dictionary, 1988; Morris and Thompson's dictionary search, Nov 1979 | Confirmed; Demonstrated (1979 study) | [50] [14] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | CA-1989-03: logged credentials reused on other hosts, 16 Aug 1989 | Confirmed | [58] [84] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Valid Accounts: Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | WANK and the FIELD and DECNET accounts, Oct 1989; the 414s' default passwords, 1982 to 1983 (Reported) | Confirmed; Reported | [58] [21] |
| [`T1078.003`](/mitre/techniques/T1078-003.md) | Valid Accounts: Local Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Morris worm poses as the legitimate user after guessing a password, 1988 | Confirmed | [50] |
| [`T1021`](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | Morris worm over rsh and rexec to trusted hosts, 1988; parent only, because no sub-technique fits rsh | Confirmed | [48] [50] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | Discovery | Morris worm reads `hosts.equiv`, `.rhosts` and `.forward`, 1988 | Confirmed | [50] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | Morris worm reads routing-table gateways and point-to-point peers, 1988 | Confirmed | [50] |
| [`T1554`](/mitre/techniques/T1554.md) | Compromise Host Software Binary | Persistence | Trojaned telnet binaries logging credentials, CA-1989-03, 16 Aug 1989 | Confirmed | [58] [86] |
| [`T1136`](/mitre/techniques/T1136.md) | Create Account | Persistence | WANK creates an account, Oct 1989 | Confirmed | [58] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | WANK resets the default DECNET password and leaves FIELD privileged, Oct 1989 | Confirmed | [58] [87] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | Lateral Movement, Initial Access | Brain (Jan 1986); Lehigh (Nov 1987); nVIR (1989); Disk Killer (Jun 1989); Elk Cloner (1982, Reported) | Confirmed; Reported | [34] [37] [63] [68] [19] [89] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Pre-OS Boot: Bootkit | Stealth, Persistence | Brain boot-sector infection (1986); Disk Killer (1989) | Confirmed | [34] [68] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | Impact | Jerusalem deletes programs run on Friday the 13th (1986 to 1987) | Confirmed | [36] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | Disk Killer encrypts the bootable partition (Jun 1989); the AIDS disk encrypts file names, not contents (Dec 1989) | Confirmed | [68] [88] |
| [`T1037`](/mitre/techniques/T1037.md) | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation | AIDS installer rewrites `AUTOEXEC.BAT`, Dec 1989 | Confirmed | [68] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hide Artifacts: Hidden Files and Directories | Stealth | AIDS disk hides directories, Dec 1989 | Confirmed | [68] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | User Execution: Malicious File | Execution | AIDS INSTALL run by recipients, Dec 1989; CHRISTMA EXEC run by recipients, Dec 1987 | Confirmed | [68] [38] [39] |
| [`T1598`](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | CA-91:03, messages posing as administrators asking for a password change, Apr 1991 (just after the window) | Confirmed | [53] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Social Engineering: Impersonation | Stealth | CA-91:03, the same messages, Apr 1991 | Confirmed | [53] [90] |

Notes. `T1684.001` is the v20.0 home of the revoked `T1656` Impersonation, per `data/attack/superseded_by.jsonl`; `T1684` Social Engineering sits under the Stealth tactic in v20.0 [90] [95]. The AIDS disk fits `T1486` only loosely, because it scrambled names rather than data [68] (**Inferred**). `T1598` fits CA-91:03 loosely: the messages planted a password chosen by the intruder rather than asking for one (**Inferred**).

### 10.3 Demonstrated and Inferred mappings (10)

| ID | Name | Tactic(s) | What the record says | Grade | Sources |
|---|---|---|---|---|---|
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | Multics trap door distributed onward by the vendor (evaluation, 1972 to 1974, reported 2002); the Israeli vendor's demo diskette (Reported, 1989) | Demonstrated; Reported | [5] [6] [63] |
| [`T1195.001`](/mitre/techniques/T1195-001.md) | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Initial Access | Thompson's self-reproducing compiler Trojan, Aug 1984 | Demonstrated | [23] |
| [`T1003.008`](/mitre/techniques/T1003-008.md) | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | Morris worm uses `/etc/passwd` clues; CA-1989-03 warns TFTP and anonymous FTP expose `/etc/passwd` | Inferred | [50] [58] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | Morris worm sends a bootstrap, then the main program | Inferred | [50] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | Morris worm hid itself and left little evidence | Inferred | [50] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | Impact | Morris worm overloads hosts until they crash or become catatonic; an unintended effect | Inferred | [47] [50] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | Stealth | Brain hooks INT 13 to show the clean boot sector | Inferred | [34] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | Lateral Movement | Lehigh virus spreads through disks at public sites (1987); Cohen's virus spreads through shared programs (1983, Demonstrated) | Inferred | [37] [24] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Wipe: Disk Content Wipe | Impact | Lehigh virus erases disks after four infections (1987) | Inferred | [37] |
| [`T1036`](/mitre/techniques/T1036.md) | Masquerading | Stealth | AIDS disk presented as health information software (1989) | Inferred | [68] |

Left out (**Inferred**): phone phreaking, because ATT&CK does not model a carrier's in-band signaling; `T1199` Trusted Relationship, because the Morris worm's host trust is better described by `T1021`; and any technique for Creeper, whose behavior the record opened does not describe in enough detail.

### 10.4 ATT&CK for ICS

No ATT&CK for ICS technique is supported. The period record opened here has no industrial-control-system event, and the telephone network's signaling is not an ICS asset in ATT&CK's model [95] (**Inferred**).

### 10.5 CAPEC, CWE and D3FEND

No CVE exists for any flaw in this study, so every CWE and CAPEC assignment is this study's classification (**Inferred**), checked against `data/weaknesses/cwe.jsonl` and `capec.jsonl` [95]. Where the library's data links a CAPEC entry to one of the techniques above, the link is noted.

| CAPEC | Name | Where it meets the record | Library link to ATT&CK |
|---|---|---|---|
| [CAPEC-100](/mitre/capec/CAPEC-100.md) | Overflow Buffers | fingerd `gets()` overflow, 1988 | none |
| [CAPEC-16](/mitre/capec/CAPEC-16.md) | Dictionary-based Password Attack | Morris worm word list; Morris and Thompson, 1979 | none |
| [CAPEC-49](/mitre/capec/CAPEC-49.md) | Password Brute Forcing | Morris worm and WANK guessing | `T1110.001` |
| [CAPEC-112](/mitre/capec/CAPEC-112.md) | Brute Force | the guessing and cracking above | `T1110` (parent) |
| [CAPEC-70](/mitre/capec/CAPEC-70.md) | Try Common or Default Usernames and Passwords | WANK; the 414s (Reported) | `T1078.001` |
| [CAPEC-555](/mitre/capec/CAPEC-555.md) | Remote Services with Stolen Credentials | telnet-logger credentials reused on other hosts, 1989 | `T1021` |
| [CAPEC-441](/mitre/capec/CAPEC-441.md) | Malicious Logic Insertion | trap doors in the Ware, Anderson and Multics reports | none |
| [CAPEC-442](/mitre/capec/CAPEC-442.md) | Infected Software | the vendor demo diskette; the Multics trap door | `T1195.001`, `T1195.002` |
| [CAPEC-523](/mitre/capec/CAPEC-523.md) | Malicious Software Implanted | the Multics trap door distributed onward | `T1195.002` |
| [CAPEC-447](/mitre/capec/CAPEC-447.md) | Design Alteration | Anderson's clandestine code change; Thompson's compiler | none |
| [CAPEC-407](/mitre/capec/CAPEC-407.md) | Pretexting | CA-91:03 messages posing as administrators [92] | `T1589` only, which this study does not map |
| [CAPEC-416](/mitre/capec/CAPEC-416.md) | Manipulate Human Behavior | CA-91:03 | none |

CWE (names from `data/weaknesses/cwe.jsonl` [95]; MITRE's CWE-242 page uses `gets()` as its example [91]):

| CWE | Name | Where it meets the record |
|---|---|---|
| CWE-242 | Use of Inherently Dangerous Function | fingerd read input with `gets()` [50] |
| CWE-120 | Buffer Copy without Checking Size of Input | the same fingerd overflow [50]; CWE-121 is not used, because RFC 1135 does not say the buffer was on the stack |
| CWE-489 | Active Debug Code | sendmail's debug command [50] |
| CWE-521 | Weak Password Requirements | dictionary passwords: Morris and Thompson, the Morris worm [14] [50] |
| CWE-1392 | Use of Default Credentials | WANK's FIELD and DECNET accounts; the 414s (Reported) [58] [21] |
| CWE-1393 | Use of Default Password | the same |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | unlimited guessing by the worms [50] [58] |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | the viruses and worms of Parts 3 and 4 |
| CWE-506 | Embedded Malicious Code | trap doors and the Thompson compiler [5] [23] |
| CWE-912 | Hidden Functionality | trap doors left by system programmers [3] [5] |

See the [CWE Reference](/CWE_REFERENCE.md) and the [CAPEC Reference](/CAPEC_REFERENCE.md).

D3FEND. The library's `data/attack/technique_to_d3fend.jsonl` maps these countermeasures to the techniques above, and each has a library page [95] (**Confirmed** for the rows, except where a row says otherwise).

| D3FEND countermeasure | Techniques it counters (library data) | Where it meets the record |
|---|---|---|
| [Change Default Password](/mitre/d3fend/change-default-password.md) (D3-CDP) | `T1078.001`, `T1136`, `T1098`, `T1110.001` | WANK's FIELD and DECNET accounts; the 414s |
| [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (D3-SPP) | `T1110.001`, `T1110.002` | 86 percent weak passwords in 1979; the worm's word list |
| [Account Locking](/mitre/d3fend/account-locking.md) (D3-AL) | `T1078`, `T1078.001`, `T1136`, `T1098` | accounts created and left privileged by WANK |
| [Credential Hardening](/mitre/d3fend/credential-hardening.md) (D3-CH) | `T1110.001`, `T1110.002`, `T1003.008` | readable password files in 1988 and 1989 |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (D3-MFA) | `T1110.001`, `T1110.002` | a guessed or logged password was the only factor |
| [Local Account Monitoring](/mitre/d3fend/local-account-monitoring.md) (D3-LAM) | `T1078.003` | the worm posing as the account owner |
| [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (D3-SFCV) | `T1210` | the fingerd overflow |
| [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (D3-PSEP) | `T1210` | the fingerd overflow |
| [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (D3-CAA) | `T1210`, `T1021` | the worm's probing of trusted and random hosts |
| [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (D3-RTSD) | `T1210`, `T1021` | rsh and rexec sessions between trusted hosts |
| [Software Update](/mitre/d3fend/software-update.md) (D3-SU) | `T1554`, `T1542.003`, `T1195.001`, `T1195.002` | sendmail 5.59 and the ftpd patches of CA-1988-01 [57] |
| [Software Inventory](/mitre/d3fend/software-inventory.md) (D3-SWI) | `T1554`, `T1195.001`, `T1195.002` | knowing which binaries and suppliers a site runs |
| [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (D3-FIM) | `T1486`, `T1204.002`, `T1003.008` | checksumming revealed the AIDS disk's change [68]; for `T1554` the pairing with CERT's 1989 checksum advice is **Inferred**, because the library does not map D3-FIM to `T1554` [58] |
| [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md) (D3-BA) | `T1542.003` | Brain and Disk Killer |
| [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (D3-IOPR) | `T1091` | floppy-borne viruses |
| [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL) | `T1204.002` | the AIDS INSTALL program and CHRISTMA EXEC |
| [Restore File](/mitre/d3fend/restore-file.md) (D3-RF) | `T1486` | CLEARAID's recovery of the AIDS disk's damage [68] |
| [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) (D3-NRAM) | `T1080` | shared disks and programs at public sites |

[Kernel-based Process Isolation](/mitre/d3fend/kernel-based-process-isolation.md) (D3-KBPI) is the closest modern countermeasure to the reference monitor of 1972 (**Inferred**; the library does not map it to a technique in this study). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### 10.6 ATLAS

MITRE ATLAS does not apply: no AI or machine-learning system is involved (**Inferred**).

### 10.7 Navigator layer

- Enterprise: [`navigator/library-layers/pre-internet-threats.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/pre-internet-threats.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/pre-internet-threats.json)), domain `enterprise-attack`, ATT&CK version 20, the 31 techniques of Parts 10.2 and 10.3, each shown under its tactics with a comment naming the event and the source numbers of this study. It is listed in the [Navigator layer index](/navigator/index.md).

Scores rank the record, not the mapping: 100 for behavior a Confirmed primary describes (Part 10.2), 70 for a controlled evaluation or experiment that was not an observed attack, and 40 for an Inferred id choice (Part 10.3). Rows that add a Reported example (the 414s, Elk Cloner, the vendor demo diskette) keep the score of their strongest record. The layer is a retrospective, curated mapping, not an official MITRE mapping. No ATT&CK for ICS layer is published, because no ICS technique is supported (Part 10.4).

## Cross-cutting themes

- **The same weakness, thirty years apart.** RFC 602 in 1973, Morris and Thompson in 1979, the 1988 worm and WANK in 1989 all turn on guessable, default or blank credentials [13] [14] [50] [58] (**Confirmed**). The library's [industrial control systems study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) shows the pattern in 2025 (**Inferred** as a lineage).
- **Control on the same channel as data.** In-band trunk signaling [1] and trap doors in system libraries [5] share a design flaw: the attacker's input can carry instructions the system obeys. Later injection classes, such as the lookup at the heart of [Log4Shell](/case-studies/LOG4SHELL.md), are the software form (**Inferred**).
- **Trust in the supplier.** The Multics evaluators [6] and Thompson [23] showed in the 1970s and 1984 what the library's [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md), [XZ Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) studies record in practice, and the library's [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) records software supply-chain compromise as a repeated entry point for one state-aligned group [96] (**Confirmed** as that study's record; the lineage is **Inferred**).
- **Law follows the headline.** The 414s hearings in 1983 preceded the 1984 statute [22] [27]; the Morris worm produced the 1990 conviction under a provision added in 1986 [47]; the UK act followed the Gold and Schifreen ruling and the Law Commission's report [82] (**Reported** for the ruling; **Confirmed** for the report). The sequence is this study's reading (**Inferred**).
- **Classification versus the open literature.** The Ware report was classified although it said it held nothing beyond a well-stocked technical library [3], while the phone company's signaling and the phreaks' knowledge were in print [1] [15]. Secrecy did not protect the systems; design and configuration did or did not (**Inferred**).
- **Overstated and understated.** Overstated: "firsts", the AIDS disk as file encryption, the Morris worm's aggregate numbers, the 1979 "Ark" story and the whiz-kid image. Understated: the 1970s government record, credentials and trust as the main vector, people carrying disks, unreported insider fraud and the early defenders' integrity tools (Part 9) (**Inferred**).

## Sources

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Breen and Dahlbom, "Signaling Systems for Control of Telephone Switching", *Bell System Technical Journal* 39(6), pp. 1381 to 1444, Nov 1960 (Internet Archive record) | [archive.org/details/bstj39-6-1381](https://archive.org/details/bstj39-6-1381) | 2026-11-11 | Confirmed |
| 2 | RAND, R-609-1, *Security Controls for Computer Systems* (Ware), report page | `https://www.rand.org/pubs/reports/R609-1.html` | 2026-11-11 | Confirmed |
| 3 | Ware (ed.), *Security Controls for Computer Systems*, Report of Defense Science Board Task Force on Computer Security, 11 Feb 1970 (NIST copy; also served at https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/ware70.pdf) | [csrc.nist.gov/.../ware70.pdf](https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/ware70.pdf) | 2026-11-11 | Confirmed |
| 4 | Anderson, *Computer Security Technology Planning Study*, ESD-TR-73-51 Vol. II, Oct 1972 (NIST copy; also served under the files/pubs path) | [csrc.nist.gov/.../ande72.pdf](https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/ande72.pdf) | 2026-11-11 | Confirmed |
| 5 | Karger and Schell, *Multics Security Evaluation: Vulnerability Analysis*, ESD-TR-74-193 Vol. II, Jun 1974 (NIST copy; also served under the files/pubs path) | [csrc.nist.gov/.../karg74.pdf](https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/karg74.pdf) | 2026-11-11 | Confirmed |
| 6 | Karger and Schell, "Thirty Years Later: Lessons from the Multics Security Evaluation", ACSAC 2002 | [acsac.org/2002/papers/classic-multics.pdf](https://www.acsac.org/2002/papers/classic-multics.pdf) | 2026-11-11 | Confirmed |
| 7 | Saltzer and Schroeder, "The Protection of Information in Computer Systems", section I.A.3 | [web.mit.edu/Saltzer/www/publications/protection/Basic.html](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html) | 2026-11-11 | Confirmed |
| 8 | Saltzer, publications list (citation of source 7) | [web.mit.edu/Saltzer/www/publications/pubs.html](https://web.mit.edu/Saltzer/www/publications/pubs.html) | 2026-11-11 | Confirmed |
| 9 | Anderson, *Computer Security Threat Monitoring and Surveillance*, 26 Feb 1980, rev. 15 Apr 1980 (NIST copy) | [csrc.nist.gov/.../ande80.pdf](https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/ande80.pdf) | 2026-11-11 | Confirmed |
| 10 | DoD 5200.28-STD, *Trusted Computer System Evaluation Criteria*, 26 Dec 1985 (NIST copy) | [csrc.nist.gov/.../dod85.pdf](https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/dod85.pdf) | 2026-11-11 | Confirmed |
| 11 | NIST, NISSC 1998, *Early Computer Security Papers (1970-1985)* collection index | [csrc.nist.gov/.../early-cs-papers-1970-1985.pdf](https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/early-cs-papers-1970-1985.pdf) | 2026-11-11 | Confirmed |
| 12 | GAO, *Computer-Related Crimes in Federal Programs*, FGMSD-76-27, 27 Apr 1976 | `https://www.gao.gov/assets/fgmsd-76-27.pdf` | 2026-11-11 | Confirmed |
| 13 | RFC 602, Dec 1973 | [rfc-editor.org/rfc/rfc602.txt](https://www.rfc-editor.org/rfc/rfc602.txt) | 2026-11-11 | Confirmed |
| 14 | Morris and Thompson, "Password Security: A Case History", Nov 1979 | [rist.tech.cornell.edu/6431papers/MorrisThompson1979.pdf](https://rist.tech.cornell.edu/6431papers/MorrisThompson1979.pdf) | 2026-11-11 | Confirmed |
| 15 | Ron Rosenbaum, "Secrets of the Little Blue Box", *Esquire*, Oct 1971 (archive scan) | [historyofphonephreaking.org/docs/rosenbaum1971.pdf](http://www.historyofphonephreaking.org/docs/rosenbaum1971.pdf) | 2026-11-11 | Reported |
| 16 | *US v. John Thomas Draper*, N.D. Cal. CR-72-973, judgment of 29 Nov 1972 (archive scan) | [explodingthephone.com/docs/dbx1029.pdf](https://explodingthephone.com/docs/dbx1029.pdf) | 2026-11-11 | Confirmed |
| 17 | *US v. Draper*, N.D. Cal. CR-76-223, complaint (National Archives court papers) | [explodingthephone.com/docs/dbx0346.pdf](https://explodingthephone.com/docs/dbx0346.pdf) | 2026-11-11 | Confirmed |
| 18 | OSNews, interview with Ray Tomlinson on Creeper and Reaper | [osnews.com/.../interview-with-ray-tomlinson-on-creep...](https://www.osnews.com/story/29157/interview-with-ray-tomlinson-on-creeperreaper/) | 2026-11-11 | Reported |
| 19 | AP via *Sydney Morning Herald*, Elk Cloner interview with Rich Skrenta, 1 Sep 2007 | [smh.com.au/articles/2007/09/01/1188671795625.html](http://www.smh.com.au/articles/2007/09/01/1188671795625.html) | 2026-11-11 | Reported |
| 20 | Salon, "Happy birthday, virus", 12 Jul 2007 | [salon.com/2007/07/12/virus_birthday/](https://www.salon.com/2007/07/12/virus_birthday/) | 2026-11-11 | Reported |
| 21 | Wikipedia, "The 414s" | [en.wikipedia.org/wiki/The_414s](https://en.wikipedia.org/wiki/The_414s) | 2026-11-11 | Reported |
| 22 | OSTI 5208082, abstract of Bailey's paper, IEEE Symposium on Security and Privacy, 30 Apr 1984 | [osti.gov/biblio/5208082](https://www.osti.gov/biblio/5208082) | 2026-11-11 | Reported |
| 23 | Ken Thompson, "Reflections on Trusting Trust", Turing Award lecture, Aug 1984 | [cs.cmu.edu/.../Thompson_1984_ReflectionsonTrustingTr...](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf) | 2026-11-11 | Confirmed |
| 24 | Fred Cohen, "Computer Viruses: Theory and Experiments" (course copy) | [web.eecs.umich.edu/~aprakash/eecs588/handouts/cohen-viruses.html](https://web.eecs.umich.edu/~aprakash/eecs588/handouts/cohen-viruses.html) | 2026-11-11 | Confirmed |
| 25 | Fred Cohen, "Computer Viruses - Theory and Experiments" (author's site) | [all.net/books/virus/index.html](https://all.net/books/virus/index.html) | 2026-11-11 | Confirmed |
| 26 | Florida Statutes, chapter 815, Florida Computer Crimes Act | [leg.state.fl.us/.../0815.html](http://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0800-0899/0815/0815.html) | 2026-11-11 | Confirmed |
| 27 | Public Law 98-473, 98 Stat. 1837, 12 Oct 1984 | [govinfo.gov/content/pkg/STATUTE-98/pdf/STATUTE-98-Pg1837.pdf](https://www.govinfo.gov/content/pkg/STATUTE-98/pdf/STATUTE-98-Pg1837.pdf) | 2026-11-11 | Confirmed |
| 28 | US Department of Justice, *Prosecuting Computer Crimes* manual | [justice.gov/criminal/file/442156/dl](https://www.justice.gov/criminal/file/442156/dl) | 2026-11-11 | Confirmed |
| 29 | Public Law 99-474, Computer Fraud and Abuse Act of 1986, 100 Stat. 1213, 16 Oct 1986 | [govinfo.gov/content/pkg/STATUTE-100/pdf/STATUTE-100-Pg1213.pdf](https://www.govinfo.gov/content/pkg/STATUTE-100/pdf/STATUTE-100-Pg1213.pdf) | 2026-11-11 | Confirmed |
| 30 | Cornell LII, 18 U.S.C. 1030 and its amendment notes | [law.cornell.edu/uscode/text/18/1030](https://www.law.cornell.edu/uscode/text/18/1030) | 2026-11-11 | Confirmed |
| 31 | Public Law 100-235, Computer Security Act of 1987, 101 Stat. 1724, 8 Jan 1988 | [govinfo.gov/content/pkg/STATUTE-101/pdf/STATUTE-101-Pg1724.pdf](https://www.govinfo.gov/content/pkg/STATUTE-101/pdf/STATUTE-101-Pg1724.pdf) | 2026-11-11 | Confirmed |
| 32 | Phrack issue 1, introduction, 17 Nov 1985 | [phrack.org/issues/1/introduction.html](https://phrack.org/issues/1/introduction.html) | 2026-11-11 | Confirmed |
| 33 | Phrack issue 7, phile 3, "The Conscience of a Hacker", 25 Sep 1986 | [phrack.org/issues/7/hackers-manifesto.html](https://phrack.org/issues/7/hackers-manifesto.html) | 2026-11-11 | Confirmed (publication) |
| 34 | F-Secure, Brain description | [f-secure.com/v-descs/brain.shtml](https://www.f-secure.com/v-descs/brain.shtml) | 2026-11-11 | Confirmed (technical); Reported (date and "oldest") |
| 35 | David Stang, NCSA, Brain analysis, 1989 (textfiles.com copy) | [textfiles.com/virus/braininf.vir](http://www.textfiles.com/virus/braininf.vir) | 2026-11-11 | Reported |
| 36 | F-Secure, Jerusalem description | [f-secure.com/v-descs/jerusale.shtml](https://www.f-secure.com/v-descs/jerusale.shtml) | 2026-11-11 | Confirmed |
| 37 | RISKS Digest 5.67: Lehigh University virus warning, 23 Nov 1987 | [catless.ncl.ac.uk/Risks/5/67](https://catless.ncl.ac.uk/Risks/5/67) | 2026-11-11 | Confirmed |
| 38 | RISKS Digest 5.72: BITNET warning on CHRISTMA EXEC and a newspaper item on IBM, 11 Dec 1987 | [catless.ncl.ac.uk/Risks/5/72](https://catless.ncl.ac.uk/Risks/5/72) | 2026-11-11 | Confirmed (warning); Reported (newspaper item) |
| 39 | RISKS Digest 5.80: Ross Patterson on CHRISTMA EXEC | [catless.ncl.ac.uk/Risks/5/80](https://catless.ncl.ac.uk/Risks/5/80) | 2026-11-11 | Confirmed |
| 40 | RISKS Digest 5.81: EARN statement (Michael Hebgen), 16 Dec 1987 | [catless.ncl.ac.uk/Risks/5/81](https://catless.ncl.ac.uk/Risks/5/81) | 2026-11-11 | Confirmed |
| 41 | RISKS Digest 6.6: AP report on the Hebrew University virus, 7 Jan 1988 | [catless.ncl.ac.uk/Risks/6/6](https://catless.ncl.ac.uk/Risks/6/6) | 2026-11-11 | Reported |
| 42 | RISKS Digest 6.12: translated Israeli press report of 8 Jan 1988, 22 Jan 1988 | [catless.ncl.ac.uk/Risks/6/12](https://catless.ncl.ac.uk/Risks/6/12) | 2026-11-11 | Reported |
| 43 | Clifford Stoll, "Stalking the Wily Hacker", *Communications of the ACM*, May 1988 (landing page) | [cacm.acm.org/research/stalking-the-wily-hacker/](https://cacm.acm.org/research/stalking-the-wily-hacker/) | 2026-11-11 | Confirmed |
| 44 | UPI, "Computer hacker pleads guilty", 15 Mar 1989 | [upi.com/.../4340605941200](https://www.upi.com/Archives/1989/03/15/Computer-hacker-pleads-guilty/4340605941200/) | 2026-11-11 | Reported |
| 45 | *Takedown*, Mitnick biography excerpt | [takedown.com/bio/index.html](https://www.takedown.com/bio/index.html) | 2026-11-11 | Reported |
| 46 | *United States v. Mitnick*, 145 F.3d 1342 (9th Cir. 1998) (Justia) | [law.justia.com/.../470528](https://law.justia.com/cases/federal/appellate-courts/F3/145/1342/470528/) | 2026-11-11 | Confirmed |
| 47 | *United States v. Morris*, 928 F.2d 504 (2d Cir. 1991) (OpenJurist) | [openjurist.org/928/f2d/504/united-states-v-morris](https://openjurist.org/928/f2d/504/united-states-v-morris) | 2026-11-11 | Confirmed (opinion); Reported (site summary) |
| 48 | *United States v. Morris*, 928 F.2d 504 (Caselaw Access Project JSON) | [static.case.law/f2d/928/cases/0504-01.json](https://static.case.law/f2d/928/cases/0504-01.json) | 2026-11-11 | Confirmed |
| 49 | *United States v. Morris*, 928 F.2d 504 (Justia) | [law.justia.com/cases/federal/appellate-courts/F2/928/504/452673/](https://law.justia.com/cases/federal/appellate-courts/F2/928/504/452673/) | 2026-11-11 | Confirmed |
| 50 | RFC 1135, "The Helminthiasis of the Internet", Dec 1989 (also served at https://www.rfc-editor.org/rfc/rfc1135.html) | [rfc-editor.org/rfc/rfc1135.txt](https://www.rfc-editor.org/rfc/rfc1135.txt) | 2026-11-11 | Confirmed (its ABA quotation Reported) |
| 51 | Eichin and Rochlis, "With Microscope and Tweezers" (MIT, 1988), chronology | [web.mit.edu/eichin/www/virus/chronology.html](https://web.mit.edu/eichin/www/virus/chronology.html) | 2026-11-11 | Confirmed |
| 52 | RFC 1087, "Ethics and the Internet", Jan 1989 | [rfc-editor.org/rfc/rfc1087.txt](https://www.rfc-editor.org/rfc/rfc1087.txt) | 2026-11-11 | Confirmed |
| 53 | RFC 1244, Site Security Handbook, Jul 1991 | [rfc-editor.org/rfc/rfc1244.txt](https://www.rfc-editor.org/rfc/rfc1244.txt) | 2026-11-11 | Confirmed |
| 54 | RFC 1281, Guidelines for the Secure Operation of the Internet, Nov 1991 | [rfc-editor.org/rfc/rfc1281.txt](https://www.rfc-editor.org/rfc/rfc1281.txt) | 2026-11-11 | Confirmed |
| 55 | SEI, CERT Division page | [sei.cmu.edu/divisions/cert/](https://www.sei.cmu.edu/divisions/cert/) | 2026-11-11 | Confirmed |
| 56 | FIRST, "FIRST History" | [first.org/about/history](https://www.first.org/about/history) | 2026-11-11 | Confirmed |
| 57 | SEI, 1988 CERT advisories, CA-1988-01 (PDF; index at https://www.sei.cmu.edu/library/1988-cert-advisories/) | [sei.cmu.edu/documents/512/1988_019_001_496232.pdf](https://www.sei.cmu.edu/documents/512/1988_019_001_496232.pdf) | 2026-11-11 | Confirmed |
| 58 | SEI, 1989 CERT advisories, CA-1989-03 and CA-1989-04 (PDF; index at https://www.sei.cmu.edu/library/1989-cert-advisories/) | [sei.cmu.edu/documents/513/1989_019_001_496236.pdf](https://www.sei.cmu.edu/documents/513/1989_019_001_496236.pdf) | 2026-11-11 | Confirmed |
| 59 | GAO, IMTEC-89-57, *Computer Security: Virus Highlights Need for Improved Internet Management*, 12 Jun 1989 | `https://www.gao.gov/products/imtec-89-57` | 2026-11-11 | Confirmed |
| 60 | RISKS Digest 8.35: Klaus Brunnstein, arrests report, 2 Mar 1989 | [catless.ncl.ac.uk/Risks/8/35](https://catless.ncl.ac.uk/Risks/8/35) | 2026-11-11 | Reported |
| 61 | RISKS Digest 8.37: Hans Huebner ("Pengo"), 10 Mar 1989 | [catless.ncl.ac.uk/Risks/8/37](https://catless.ncl.ac.uk/Risks/8/37) | 2026-11-11 | Confirmed (his statement) |
| 62 | Reuters via *Los Angeles Times*, Celle verdict, 16 Feb 1990 | [latimes.com/archives/la-xpm-1990-02-16-mn-667-story.html](https://www.latimes.com/archives/la-xpm-1990-02-16-mn-667-story.html) | 2026-11-11 | Reported |
| 63 | *Virus Bulletin*, July 1989 | [virusbulletin.com/uploads/pdf/magazine/1989/198907.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1989/198907.pdf) | 2026-11-11 | Confirmed (its Turin account Reported) |
| 64 | *Virus Bulletin*, August 1989 | [virusbulletin.com/uploads/pdf/magazine/1989/198908.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1989/198908.pdf) | 2026-11-11 | Confirmed |
| 65 | *Virus Bulletin*, September 1989 | [virusbulletin.com/uploads/pdf/magazine/1989/198909.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1989/198909.pdf) | 2026-11-11 | Confirmed |
| 66 | *Virus Bulletin*, November 1989 | [virusbulletin.com/uploads/pdf/magazine/1989/198911.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1989/198911.pdf) | 2026-11-11 | Confirmed |
| 67 | *Virus Bulletin*, December 1989 | [virusbulletin.com/uploads/pdf/magazine/1989/198912.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1989/198912.pdf) | 2026-11-11 | Confirmed |
| 68 | *Virus Bulletin*, January 1990 | [virusbulletin.com/uploads/pdf/magazine/1990/199001.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1990/199001.pdf) | 2026-11-11 | Confirmed (analysis); Reported (relayed counts and WHO alert) |
| 69 | *Virus Bulletin*, March 1990 | [virusbulletin.com/uploads/pdf/magazine/1990/199003.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/1990/199003.pdf) | 2026-11-11 | Confirmed |
| 70 | CNN, on Joseph Popp and the AIDS disk, 16 May 2021 | [cnn.com/2021/05/16/tech/ransomware-joseph-popp/index.html](https://www.cnn.com/2021/05/16/tech/ransomware-joseph-popp/index.html) | 2026-11-11 | Reported |
| 71 | G DATA, about the company | [gdata.de/ueber-g-data](https://www.gdata.de/ueber-g-data) | 2026-11-11 | Confirmed (own history); Reported ("first") |
| 72 | Avast, about | [avast.com/about](https://www.avast.com/about) | 2026-11-11 | Confirmed (own history) |
| 73 | WithSecure, about us | [withsecure.com/en/about-us](https://www.withsecure.com/en/about-us) | 2026-11-11 | Confirmed (own history); Reported ("first") |
| 74 | Chaos Computer Club, about the club | [ccc.de/en/club](https://www.ccc.de/en/club) | 2026-11-11 | Confirmed |
| 75 | Microsoft Learn, malware naming | [learn.microsoft.com/en-us/defender-xdr/malware-naming](https://learn.microsoft.com/en-us/defender-xdr/malware-naming) | 2026-11-11 | Confirmed |
| 76 | *Computer Underground Digest* 1.09: US Attorney (D. Ariz.) release of 9 May 1990 and *Chicago Tribune* of 10 May 1990 (Exploit-DB archive copy) | [exploit-db.com/ezines/kr5hou2zh4qtebqk.onion/CUD/CUD109.TXT](https://www.exploit-db.com/ezines/kr5hou2zh4qtebqk.onion/CUD/CUD109.TXT) | 2026-11-11 | Confirmed (release); Reported (Tribune) |
| 77 | *Steve Jackson Games v. US Secret Service*, W.D. Tex., 12 Mar 1993 (decision text on the company's site) | [sjgames.com/SS/decision-text.html](https://www.sjgames.com/SS/decision-text.html) | 2026-11-11 | Confirmed |
| 78 | *Steve Jackson Games v. US Secret Service*, 36 F.3d 457 (5th Cir. 1994) (OpenJurist) | [openjurist.org/.../steve-jackson-games-incorporated-v-un...](https://openjurist.org/36/f3d/457/steve-jackson-games-incorporated-v-united-states-secret-service) | 2026-11-11 | Confirmed (opinion); Reported (headnote) |
| 79 | Computer Misuse Act 1990 c. 18, as enacted | [legislation.gov.uk/ukpga/1990/18/enacted](https://www.legislation.gov.uk/ukpga/1990/18/enacted) | 2026-11-11 | Confirmed |
| 80 | Computer Misuse Act 1990, section 1, as enacted | [legislation.gov.uk/ukpga/1990/18/section/1/enacted](https://www.legislation.gov.uk/ukpga/1990/18/section/1/enacted) | 2026-11-11 | Confirmed |
| 81 | Computer Misuse Act 1990, contents (current) | [legislation.gov.uk/ukpga/1990/18/contents](https://www.legislation.gov.uk/ukpga/1990/18/contents) | 2026-11-11 | Confirmed |
| 82 | Hansard, Commons, Computer Misuse Bill, second reading, 9 Feb 1990 | [api.parliament.uk/.../computer-misuse-bill](https://api.parliament.uk/historic-hansard/commons/1990/feb/09/computer-misuse-bill) | 2026-11-11 | Confirmed (debate); Reported (speakers' accounts of cases) |
| 83 | NIST CSRC glossary, defense-in-depth | [csrc.nist.gov/glossary/term/defense_in_depth](https://csrc.nist.gov/glossary/term/defense_in_depth) | 2026-11-11 | Confirmed |
| 84 | MITRE ATT&CK v20, T1078 Valid Accounts | [attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/) | 2026-11-11 | Confirmed |
| 85 | MITRE ATT&CK v20, T1210 Exploitation of Remote Services | [attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/) | 2026-11-11 | Confirmed |
| 86 | MITRE ATT&CK v20, T1554 Compromise Host Software Binary | [attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/) | 2026-11-11 | Confirmed |
| 87 | MITRE ATT&CK v20, T1098 Account Manipulation | [attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/) | 2026-11-11 | Confirmed |
| 88 | MITRE ATT&CK v20, T1486 Data Encrypted for Impact | [attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/) | 2026-11-11 | Confirmed |
| 89 | MITRE ATT&CK v20, T1091 Replication Through Removable Media | [attack.mitre.org/techniques/T1091/](https://attack.mitre.org/techniques/T1091/) | 2026-11-11 | Confirmed |
| 90 | MITRE ATT&CK v20, T1684 Social Engineering (T1656 redirects to T1684.001) | [attack.mitre.org/techniques/T1684/](https://attack.mitre.org/techniques/T1684/) | 2026-11-11 | Confirmed |
| 91 | MITRE CWE, CWE-242 | [cwe.mitre.org/data/definitions/242.html](https://cwe.mitre.org/data/definitions/242.html) | 2026-11-11 | Confirmed |
| 92 | MITRE CAPEC, CAPEC-407 Pretexting | [capec.mitre.org/data/definitions/407.html](https://capec.mitre.org/data/definitions/407.html) | 2026-11-11 | Confirmed |
| 93 | TeamStarWolf library, `case-studies/` on main | [github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies) | 2026-11-11 | Confirmed |
| 94 | TeamStarWolf library studies on main: `CUCKOOS_EGG_1986.md`, `MITNICK_INTRUSIONS.md` (and their Navigator layers) | [github.com/.../CUCKOOS_EGG_1986.md](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/CUCKOOS_EGG_1986.md) | 2026-11-11 | Confirmed |
| 95 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `superseded_by.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, the groups, software and campaigns files, `data/weaknesses/cwe.jsonl` and `capec.jsonl`, and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |
| 96 | TeamStarWolf library studies on main: `ICS_ATTACKS_AND_ADVISORIES_2024_2026.md`, `STUXNET.md`, `APT41_PUBLIC_RECORD.md`, `SOLARWINDS_SUNBURST.md`, `XZ_UTILS_BACKDOOR_2024.md`, `NPM_SUPPLY_CHAIN_ATTACKS.md`, `HUGGING_FACE_SUPPLY_CHAIN.md`, `LOG4SHELL.md` | [github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies) | 2026-11-11 | Confirmed (as each study's record) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md) and [Malware Families](/MALWARE_FAMILIES.md): no ATT&CK group or software object exists for any event in this study
- [CVE Reference](/CVE_REFERENCE.md): no CVE exists for any flaw in this study
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) and [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md)
- Home studies for events summarized here: [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md), [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md), [Five Hacks and Why They Worked](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) (the Morris worm), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Operation Sundevil and Steve Jackson Games)
- What came next: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) and [The Ransomware Ecosystem, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- Later echoes: [Stuxnet](/case-studies/STUXNET.md), [SolarWinds and SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [XZ Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [Log4Shell](/case-studies/LOG4SHELL.md), [APT41](/case-studies/APT41_PUBLIC_RECORD.md), [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- Technique pages: [T1210](/mitre/techniques/T1210.md), [T1110.001](/mitre/techniques/T1110-001.md), [T1110.002](/mitre/techniques/T1110-002.md), [T1078](/mitre/techniques/T1078.md), [T1078.001](/mitre/techniques/T1078-001.md), [T1078.003](/mitre/techniques/T1078-003.md), [T1021](/mitre/techniques/T1021.md), [T1018](/mitre/techniques/T1018.md), [T1016](/mitre/techniques/T1016.md), [T1554](/mitre/techniques/T1554.md), [T1136](/mitre/techniques/T1136.md), [T1098](/mitre/techniques/T1098.md), [T1091](/mitre/techniques/T1091.md), [T1542.003](/mitre/techniques/T1542-003.md), [T1485](/mitre/techniques/T1485.md), [T1486](/mitre/techniques/T1486.md), [T1037](/mitre/techniques/T1037.md), [T1564.001](/mitre/techniques/T1564-001.md), [T1204.002](/mitre/techniques/T1204-002.md), [T1598](/mitre/techniques/T1598.md), [T1684.001](/mitre/techniques/T1684-001.md), [T1195.002](/mitre/techniques/T1195-002.md), [T1195.001](/mitre/techniques/T1195-001.md), and the Inferred rows of Part 10.3
- [Navigator layers](/navigator/index.md), including this study's layer, [pre-internet-threats.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/pre-internet-threats.json)
- [All case studies](/case-studies/README.md) and the [case study timeline](/case-studies/TIMELINE.md)
