# Slide plan: Before the Internet: Computer Threats, 1960 to 1990

- Study: case-studies/PRE_INTERNET_THREATS.md
- Cover title: Before the Internet / Computer Threats, / 1960 to 1990
- Subtitle: Trap doors, guessed passwords and floppy disks, read from the record
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/PRE_INTERNET_THREATS.md, told from the government reports, statutes, court records, RFCs, CERT advisories and the early issues of Virus Bulletin. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The threat was written down before the personal computer

- **1970 to 1974:** the Ware, Anderson and Multics reports named trap doors, Trojan horses and insiders.
- **Credentials and trust** were the front door from RFC 602 in 1973 to WANK in 1989.
- **People carried the viruses:** Brain, Lehigh, nVIR and the AIDS disk moved on media.
- **The defenders organized fast:** CERT/CC in December 1988, FIRST in 1990.
- **Many famous numbers are guesses,** and most "firsts" are later labels.
Caption: Grades: reports, statutes, court records, RFCs and advisories Confirmed; phreaks, Creeper, Elk Cloner and the 414s Reported.
Notes: Ware [3], Anderson [4], Karger and Schell [5][6], RFC 602 [13], WANK [58], media-borne viruses [34][37][63][68], CERT/CC [53][57], FIRST [56], the 6,000 figure [51].

## KEY FACTS | Four numbers from the primary record

Stat: 86% | of 3,289 UNIX passwords short or dictionary (1979)
Stat: 69 | federal computer-crime cases GAO counted in 1976
Stat: 432 | words in the Morris worm's password list (1988)
Stat: 46 | known MS-DOS viruses by January 1990
- GAO: most offenders were system users with limited technical knowledge.
- The 6,000 machines figure for the Morris worm began as an extrapolation from MIT.
- The only cost figure in the Morris court record is per installation: $200 to over $53,000.
Notes: Morris and Thompson [14], GAO FGMSD-76-27 [12], RFC 1135 [50], Virus Bulletin counts [69], Eichin and Rochlis [51], the Second Circuit opinion [48].

## PART 2 | Thirty years from Bell's journal to the Computer Misuse Act

| Date | Event | Grade |
|---|---|---|
| Nov 1960 | Bell System journal on in-band signaling | Confirmed |
| 11 Feb 1970 | Ware report for the Defense Science Board | Confirmed |
| Oct 1972 | Anderson report defines the Trojan horse | Confirmed |
| 27 Apr 1976 | GAO on computer crime in federal programs | Confirmed |
| Nov 1983 | Cohen's first experimental virus | Confirmed |
| Jan 1986 | Brain first detected, by F-Secure's account | Reported |
| 2 Nov 1988 | Morris worm | Confirmed |
| 29 Jun 1990 | Computer Misuse Act receives Royal Assent | Confirmed |
Caption: The full timeline in the study runs to the 1993 Steve Jackson Games judgment.
Notes: Part 2. Breen and Dahlbom [1], Ware [2][3], Anderson [4], GAO [12], Cohen [24], Brain [34], Morris worm [47][50], Computer Misuse Act [79].

## PART 1 | Government studies found penetration easy by 1972

- **Ware, 1970:** deliberate penetration, trap doors left by system programmers, an agent inside.
- **Anderson, 1972:** experienced programmers had little difficulty penetrating systems.
- **Anderson also** defined the Trojan horse and introduced the reference monitor.
- **Multics, 1972 to 1973:** Air Force evaluators planted trap doors in system libraries.
- **Karger and Schell, 2002:** one trap door went to another site through the vendor.
Caption: The Multics work was an evaluation, graded Demonstrated, not an observed attack.
Notes: Ware report [2][3], Anderson [4], the Orange Book on the reference monitor [10], Karger and Schell 1974 [5] and 2002 [6].

## PART 1 | Computer crime began as clerical fraud and guessable passwords

Left: GAO, 1976
- 69 cases, over $2 million lost.
- Most offenders were users, not programmers.
- Separation of duties failed in 7 of 12.
- Controls existed but were not enforced.
Right: Passwords, 1973 to 1979
- RFC 602: easy passwords, open dial-ins.
- Two students took a wheel password.
- Morris and Thompson: 86% weak.
- A five-minute search found a third.
Notes: GAO FGMSD-76-27 [12], RFC 602 [13], Morris and Thompson [14].

## PART 3 | People carrying floppy disks were the network

- **Brain (January 1986):** boot-sector virus with an early stealth trick, by F-Secure's account.
- **Lehigh (November 1987):** rode in COMMAND.COM and erased disks after four infections.
- **nVIR:** reached a printing firm's Macintosh network on a client's own software copy.
- **Disk Killer (June 1989):** encrypted the bootable partition after 48 hours.
Caption: None of these needed a modem. That reading is the study's own (Inferred).
Notes: F-Secure on Brain [34], NCSA [35], RISKS 5.67 on Lehigh [37], Virus Bulletin on nVIR [63] and Disk Killer [68].

## PART 3 | The AIDS disk scrambled file names, not file contents

Stat: 8 to 12 Dec | 1989: disks posted from London
Stat: 20,000 | the upper estimate of disks sent, relayed
- The installer rewrote AUTOEXEC.BAT and, after a count of reboots, hid directories.
- It encrypted file names in the root directory, then printed an invoice to a Panama PO box.
- Only checksumming programs revealed the change; virus-specific tools missed it.
- Virus Bulletin called it extortion in 1990; CNN called it the first ransomware in 2021.
Notes: Virus Bulletin January 1990 analysis by Jim Bates [68], CNN 2021 [70], Reported. The ransomware label is retrospective (Inferred).

## PART 4 | The worms ran on trust and weak passwords

Left: 1987 to 1988
- CHRISTMA EXEC: each recipient ran it.
- Morris worm: sendmail, fingerd, trusted hosts, guessed passwords.
- Most sites clean in 48 to 72 hours.
Right: 1989
- Telnet binaries replaced to log passwords.
- WANK: blank and account-name passwords.
- WANK left FIELD as a privileged trap door.
Caption: The Morris worm's home study is Five Hacks and Why They Worked; this deck summarizes it.
Notes: RISKS 5.72, 5.80 and 5.81 [38][39][40], the Second Circuit [47][48], RFC 1135 [50], CERT CA-1989-03 and CA-1989-04 [58].

## PART 6 | The law followed the headlines

| Year | Statute | Grade |
|---|---|---|
| 1978 | Florida Computer Crimes Act, ch. 78-92 | Confirmed |
| 1984 | Pub. L. 98-473 creates 18 U.S.C. 1030 | Confirmed |
| 1986 | Computer Fraud and Abuse Act, Pub. L. 99-474 | Confirmed |
| 1988 | Computer Security Act of 1987, Pub. L. 100-235 | Confirmed |
| 1990 | UK Computer Misuse Act, c. 18 | Confirmed |
Caption: Morris was convicted under 1030(a)(5)(A) on 16 May 1990; the Second Circuit affirmed in 1991.
Notes: Florida [26], Pub. L. 98-473 [27], DOJ manual [28], Pub. L. 99-474 [29][30], Pub. L. 100-235 [31], Morris [47][48], Computer Misuse Act [79][80], Hansard [82].

## PART 7 | The defenders built response teams and an anti-virus trade

- **CERT/CC:** established December 1988 by DARPA at the SEI; first advisory CA-1988-01.
- **FIRST:** formed in 1990 after WANK showed teams needed to coordinate.
- **By 1989:** signature tables, integrity checkers and behavior blockers were in print.
- **Naming was already a problem:** Virus Bulletin called for a common glossary in 1989.
Caption: No opened source states that the worm caused CERT/CC; that link is Inferred.
Notes: RFC 1244 [53], CA-1988-01 [57], FIRST history [56], Virus Bulletin July, November and December 1989 [63][66][67], March 1990 naming proposal [69].

## DEFENDER VIEW | The fixes of the 1980s are still the first fixes

- **Remove default, blank and account-name passwords:** WANK used all three.
- **Block dictionary passwords and slow guessing:** add lockout and MFA.
- **Check binaries against known-good copies,** as CERT advised in 1989.
- **Treat host trust as an attack path:** inventory trust files and remote services.
- **Control removable media and imported software.**
- **Plan for subverted suppliers and tools,** as Multics and Thompson showed.
Notes: Part 8 and the top recommendations. WANK [58], Morris and Thompson [14], RFC 1135 [50], CA-1989-03 [58], AIDS disk [68], Karger and Schell [6], Thompson [23].

## OVERSTATED AND UNDERSTATED | Most famous firsts and numbers are later labels

Left: Overstated
- First virus, first anti-virus, first ransomware.
- The AIDS disk as file encryption.
- 6,000 machines for the Morris worm.
- The whiz-kid hacker image.
Right: Understated
- The 1970s government threat record.
- Credentials and trust as the main vector.
- People carrying disks.
- Unreported insider fraud.
Notes: Part 9. G DATA [71], F-Secure [34], CNN [70], Virus Bulletin [67][68], Eichin and Rochlis [51], GAO [12], Thompson [23], Ware, Anderson and Multics [3][4][5].

## MITRE MAPPINGS | Thirty-one techniques mapped in retrospect

Stat: 21 | techniques the Confirmed record describes
Stat: 10 | Demonstrated or Inferred mappings
Stat: 0 | ATT&CK group, software or campaign objects
- Credential guessing and cracking, valid and default accounts, trusted remote services.
- Removable media, bootkits, data destruction and encryption, user execution.
- Supply chain compromise from the Multics trap door and Thompson's compiler.
- Every row is this study's reading; the events predate ATT&CK by decades.
Caption: The study's Navigator layer scores 100 for a Confirmed record, 70 for an evaluation and 40 for an Inferred id.
Notes: Part 10. Library data [95], ATT&CK pages [84] to [90], CWE-242 [91], CAPEC-407 [92].

## CROSS-CUTTING THEMES | The same weaknesses, thirty years apart

- **Guessable credentials** link RFC 602, Morris and Thompson, the worm and WANK.
- **Control on the data channel** links in-band signaling to later injection flaws.
- **Trust in the supplier** links Multics and Thompson to SolarWinds and XZ Utils.
- **Law follows the headline:** the 414s hearings, the 1984 statute, the Morris conviction.
- **Secrecy did not protect the systems;** design and configuration did or did not.
Caption: Each lineage is the study's own reading and is graded Inferred.
Notes: Cross-cutting themes. RFC 602 [13], Morris and Thompson [14], RFC 1135 [50], WANK [58], Bell System journal [1], Karger and Schell [6], Thompson [23], library studies [96], the 1983 hearings [22], Pub. L. 98-473 [27], Morris [47], Ware [3].
