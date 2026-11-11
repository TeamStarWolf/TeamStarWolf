# Slide plan: The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986

- Study: case-studies/CUCKOOS_EGG_1986.md
- Cover title: The Cuckoo's Egg Intrusion / Lawrence Berkeley / Laboratory, 1986
- Subtitle: From an accounting error at Berkeley to a trace into West Germany
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CUCKOOS_EGG_1986.md, told from Clifford Stoll's May 1988 paper rather than the book. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An accounting check found him, and printers kept him in view

- **From August 1986** an intruder used LBL as a way station into ARPANET and MILNET.
- **LBL let him stay** while it printed virtually every session and traced him, for nearly a year.
- **Ordinary weaknesses at scale:** default accounts, guessed passwords and password files cracked offline.
- **Alarmed SDI bait files** held him on the line for more than an hour while the trace to West Germany finished.
- **The KGB story came later,** from West German press reports of the 1989 arrests and the 1990 verdict.
Caption: Grades: the methods and the trace Confirmed from Stoll's paper; the book's details and the KGB sale Reported.
Notes: Stoll, "Stalking the Wily Hacker", CACM 31(5), May 1988 [1][2][3]. The paper declines to speculate whether the intrusions were espionage [1]. Arrests, indictment and Celle verdict [8][15][17][18], all Reported; no German court document was opened.

## KEY FACTS | About 450 machines tried, and more than 30 entered

Stat: ~450 | computers he tried from LBL over MILNET
Stat: ~220 | of them reachable for a login attempt
Stat: 30+ | computers he got into
Stat: $100,000+ | liability for computing, network and tracing costs
- About 10 months of observation; the trace took nearly a year and many organizations.
- About 5 percent of the machines he tried let him in with common account names and passwords.
- The book is The Cuckoo's Egg, Doubleday, 1989; its text was not opened for this study.
Notes: Scale, duration and cost from the paper [1]. The book's bibliographic record [4][7]. No ATT&CK group, software or campaign object covers this intrusion [51].

## PART 1 | Default accounts and dictionary passwords opened the doors

| Outcome of about 220 login attempts | Share |
|---|---|
| Connection refused | 5% |
| Login failed | 82% |
| Status information given | 8% |
| Limited access | 1% |
| User access | 2% |
| System-manager access | 2% |
- Names such as root, guest, system and field, with default or common passwords.
- A dictionary cracker broke 20 percent of LBL users' passwords; he logged in within a week.
Notes: All figures from the paper, Part 1.2 and 1.5 [1]. Most targets were MILNET addresses (26.i.j.k) [1]. Retrospective mappings T1110.001, T1078.001, T1003.008, T1110.002 (Part 9).

## PART 1 | One set-user-ID helper turned a user into a system manager

- **GNU Emacs movemail** ran set-user-ID root and did not stop moves into the systems area.
- **He planted a script** that passed for a utility the system ran periodically, and became system manager.
- **He also tried** holes in /usr/spool/at and vi, both already patched at LBL.
- **Hidden programs outlived the patch:** he reused them in system libraries almost a year later.
- **A privileged gateway account** sat unused for six months; he preferred stealing unused accounts.
Notes: Part 1.3 and 1.6 from the paper [1]. Mappings T1068, T1036.005, T1136.001, T1078.003; T1548.001 and T1053 Inferred, with no At or Cron sub-technique because the paper does not name the scheduler (Part 9).

## PART 1 | He chained five hops to reach Berkeley from West Germany

Left: The route
- A public dial-up in West Germany.
- The Bremen and Karlsruhe university X.25 links.
- Tymnet, then a McLean, Virginia, contractor's dial-out modems.
- LBL, then ARPANET, MILNET and linked LAN machines.
Right: Staying unseen
- Disabled accounting and audit trails where he could.
- Left if a system manager was logged in.
- Read email for signs that he had been found.
- Searched files for nuclear, sdi, kh-11 and norad.
Notes: Route and behaviour from the paper, Part 1.4, 1.7 and 1.8 [1]. At Bremen he held system-manager privileges [1]. Mappings T1090.003, T1685, T1033, T1114.001, T1083 (Part 9). He reached unclassified abstracts of US Army NBC plans for central Europe [1].

## PART 2 | Three and a half years from an accounting error to a verdict

| Date | Event | Grade |
|---|---|---|
| Aug 1986 | LBL's accounting program fails to balance | Confirmed |
| 8 Dec 1986 | US request for help reaches the Bundespost | Reported |
| 1987 | Bait files hold him for over an hour; trace completes | Confirmed |
| May 1988 | "Stalking the Wily Hacker" published in CACM | Confirmed |
| 2 Nov 1988 | Internet worm; Stoll posts an early RISKS warning | Confirmed |
| Dec 1988 | CERT/CC established at the SEI | Confirmed |
| 2 Mar 1989 | Three arrests after house searches | Reported |
| 15 Feb 1990 | Celle verdict: suspended sentences | Reported |
Notes: Paper [1][2][3]. Bundespost request [9]. Worm [36][37][40]. CERT/CC [34]. Arrests [8][12][16]. Verdict [17][18]. Diskette handovers in East Berlin from May to November 1986 began before detection [9], Reported.

## PART 3 | Off-host printers watched him without his knowing

- **Printers and PCs on RS-232 lines** recorded both directions of his X.25 sessions.
- **The monitoring was off-line,** invisible to an intruder who held system privileges.
- **Line alarms** watched for his stolen account names and paged the operator by modem.
- **Staff used the telephone** because he read their email, and planted false emails to reassure him.
- **Soon after, the NCSC reported** that someone at LBL had tried to break into one of its computers.
Notes: Part 3.1 to 3.3 from the paper [1]. Denning's 1986 model notes Berkeley 4.2 UNIX audited commands but not file access [29]; that this shaped LBL's choice is Inferred. The paper never names the NSA or the CIA [1]; DER SPIEGEL calls the NCSC an NSA division [9], Reported.

## PART 3 | Alarmed SDI bait held him for an hour while the trace finished

- **The trace** went from a Tymnet port in Oakland to a McLean contractor's modem pool, by court order.
- **Tymnet's X.25 addresses** then pointed to Bremen, Karlsruhe and a German public dial-up.
- **Fictitious SDI memos,** a mailing list and a non-existent secretary sat on an obscure LBL computer.
- **He read them for more than an hour,** long enough for the technicians to finish.
- **A letter later asked for the bait material;** LBL passed it to the FBI as attempted espionage.
Notes: Trace and bait from the paper, Part 3.4 and 3.5 [1]. The contractor is unnamed in the paper and the 1988 press [1][5]; Stoll named it in 2016 [20], Reported. The NYT dates the sting to January 1987 [5]. "Operation Showerhead" only from the 2016 interview [20].

## PART 4 | The KGB link rests on press reports, not court records

Left: What the press reported
- Diskettes handed to the KGB in East Berlin for about $54,000.
- Arrests on 2 March 1989; an indictment in August 1989.
- Celle, 15 February 1990: Carl, Hess and Brzezinski convicted.
- Suspended terms; the judge cited no serious damage.
Right: What tempers it
- The paper declines to say the intrusions were espionage.
- A prosecutor's spokesman: certainly not a top espionage case.
- The German press describes a group of four or five.
- No judgment, indictment or official statement was opened.
Notes: KGB sale [18][9]. Arrests and indictment [8][12][15][16]. Verdict and sentences [17][18]. Paper [1]. taz quote [10]. Group [9][12]. Huebner's own RISKS statement [11] is Confirmed as his statement. All German proceedings graded Reported.

## PART 5 | The book's popular details drift from the 1988 paper

| Popular detail | What the opened record says |
|---|---|
| A 75-cent accounting error | The paper names no amount: a new account had no billing address |
| The contractor was MITRE | Unnamed in the paper and 1988 press; Stoll named it in 2016 |
| One lone hacker | The German press describes a group of four or five |
| Hundreds of machines entered | About 450 attempted, about 220 reachable, more than 30 entered |
| A Bulgarian spy wrote in | 1988 press: a self-described Hungarian refugee |
| Light sentences because the Wall fell | Reuters in 1990: the judge cited no serious damage |
Notes: Part 5 table [1][5][7][9][12][18][20]. Stoll's 2019 WIRED courthouse account could not be confirmed with Hess [22]. The "first honeypot" and "first espionage" labels are later characterisations, Inferred.

## PART 6 | A practice case between theory and tools, not the origin

Left: Detection and deception
- Anderson's 1980 report: audit trails can detect penetration.
- Denning's 1986 model: violations show as abnormal use.
- Cheswick's 1991 Berferd jail cites Stoll as having done it before.
- RFC 4949 defined "honey pot" in 2007.
Right: Incident response
- RFC 1244 (1991): protect and proceed, or pursue and prosecute.
- The paper asked for a central clearinghouse for reports.
- The 1988 worm, not LBL, is CERT/CC's documented trigger.
- CIAC followed, and FIRST formed in 1990.
Notes: Anderson [28]. Denning [29]. Berferd [30]. RFC 4949 [32]. RFC 1244 and RFC 2196 [34][35]. Clearinghouse [1]. Worm and CERT/CC [34][36][37][44]. FIRST and the WANK worm [44]. The lineage is Inferred; only Berferd was seen to cite Stoll.

## MITRE MAPPINGS | 25 retrospective techniques, and no ATT&CK object for the case

| Id | Technique | Grade |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Direct |
| T1110.001 | Password Guessing | Direct |
| T1110.002 | Password Cracking | Direct |
| T1078.001 | Default Accounts | Direct |
| T1036.005 | Match Legitimate Resource Name or Location | Direct |
| T1685 | Disable or Modify Tools | Direct |
| T1090.003 | Multi-hop Proxy | Direct |
| T1548.001 | Setuid and Setgid | Inferred |
Caption: ATT&CK v20.0: 16 direct and 9 Inferred rows; layer scores 100 and 40; not an official MITRE mapping.
Notes: Part 9.2 and 9.3 [1][48][51]. T1685 is the v20.0 home of the revoked T1562 [51]. Operation CuckooBees (C0012) and Cuckoo Stealer (S1153) are false friends, not linked [51]. D3FEND: Change Default Password, Strong Password Policy, File Integrity Monitoring, Decoy File [47][51]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Forty years on, the same basics still decide the outcome

Left: Close the doors
- Remove default credentials everywhere.
- Block guessable passwords with a blocklist check.
- Inventory set-user-ID and other privileged helpers.
- Compare system utilities with known-good copies.
- Review and remove dormant accounts.
Right: Watch and prepare
- Ship session and audit records off the host.
- Plant alarmed decoys that detect and hold.
- Report failed logins; know whom to call.
- Keep clocks synchronised and log formats documented.
- Decide in advance: protect and proceed, or pursue.
Caption: CISA asked manufacturers to eliminate default passwords on 15 December 2023; NIST SP 800-63B requires a blocklist.
Notes: Part 7 and the top recommendations [1][34][47][49][50]. Only five sites, 1 to 2 percent, reported his failed logins [1]. The modern forms of LBL's practices are Inferred. Library corrections, Part 7.7 [51][52].

## CROSS-CUTTING THEMES | The basics carried the attack, and watching had a cost

- **No novel exploit:** default names, dictionary passwords, passwords in files and one privileged helper.
- **Watching had costs:** liability above $100,000 and lost physics data; RFC 1244 made it a policy choice.
- **Sensor placement decided it:** he disabled host audit trails, but never saw the off-line printers.
- **Jurisdiction lagged the network:** no US agency had clear responsibility, and arrests took two years.
- **Overstated:** "first cyber espionage case" and "first honeypot"; understated: the cooperation it took.
Notes: Themes from the paper [1], RFC 1244 [34], DER SPIEGEL [9], the NYT and RISKS reports [5][8] and the trial report [17]. CISA and NIST show the same weaknesses are still being addressed [49][50], Inferred.
