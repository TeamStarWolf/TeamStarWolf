# Kevin Mitnick: Ghost in the Wires and The Art of Intrusion

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date, with the external links and the library data in source 35 rechecked on 11 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md) · Related studies: [The Cuckoo's Egg Intrusion, 1986](/case-studies/CUCKOOS_EGG_1986.md), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md), [Healthcare Threat Actor Watchlist, 2023 to 2026](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security awareness leads, help desk and identity managers, threat intelligence analysts and anyone who has read Ghost in the Wires or The Art of Intrusion and wants the primary record behind them

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 37 min (8,480 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want what Kevin Mitnick admitted, was sentenced for and testified to, as the court and government record tells it, you need to know what the record says about the Christmas Day 1994 intrusion, or you want the help desk lessons that run from the 1990s pretext call to Scattered Spider

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 3: the admitted conduct, 1992 to 1995](#part-3-the-admitted-conduct-1992-to-1995), [Part 7: the defender view, from pretext calls to help desk vishing](#part-7-the-defender-view-from-pretext-calls-to-help-desk-vishing)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Two books on the library's reading list carry most of what the security community remembers about Kevin Mitnick. *Ghost in the Wires* (2011) is his own memoir of the years he spent breaking into phone companies and technology vendors, much of it while a federal fugitive. *The Art of Intrusion* (2005) is a collection of other people's break-ins, told to Mitnick and written up with William L. Simon, each followed by advice on countermeasures. Both are good reading. Neither is a primary record, and this study reads them against the documents that are: the Justice Department's 1999 sentencing release, the Ninth Circuit's 1998 ruling, Tsutomu Shimomura's January 1995 technical account of the Christmas Day intrusion on his systems, Mitnick's own Senate testimony in March 2000, an FCC administrative ruling from 2002, and the DOJ records for two of the *Art of Intrusion* stories.

The record is narrower than the legend. In a March 1999 global plea, Mitnick admitted breaking into systems and stealing proprietary software from Motorola, Novell, Fujitsu, Sun Microsystems and others, using social engineering, cloned cellular phones, sniffers and hacker software, and impersonating employees of victim companies, including Nokia Mobile Phones (Confirmed [1]). His combined 68 months in prison was, in DOJ's words at the time, the longest sentence any computer hacker had received, yet restitution was set at a nominal sum of just over $4,125 against victim claims in the hundreds of millions (Confirmed [1]; Reported [8]). The best-known technical episode, the 1994 IP-spoofing attack on Shimomura, is not described as part of any charge in the records opened here, Shimomura's own account names no attacker, and Mitnick's memoir credits someone else with writing and running it (Confirmed [3]; Reported [11]; Inferred).

What carries forward is the method. Mitnick told the Senate in 2000 that he got taxpayer data from IRS and Social Security staff by posing as a fellow employee on the phone, and that callbacks are weak verification because the caller may control the phone line (Confirmed as testimony [5]). Twenty-three years later CISA and the FBI described Scattered Spider posing as employees to get help desks to reset passwords and move MFA to attacker devices (Confirmed [24]), and HHS warned the health sector of the same play in 2024 (Confirmed [25]). The pretext call never went away; the payoff grew from one phone switch to a whole single sign-on identity (Inferred).

Evidence grade: the plea, sentence, appellate ruling, FCC ruling, the 1994 intrusion mechanics, and the modern advisories are **Confirmed** from primary documents. Mitnick's testimony is **Confirmed** as a record of what he told the committee, not as independent proof of the events he described. Everything known only from the books, from *Takedown* (the account by Shimomura, the victim of the 1994 intrusion, and John Markoff), or from press coverage is **Reported** and attributed. The study's own reasoning is labelled **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Subject | Kevin Mitnick, died 16 July 2023 aged 59; amateur radio call sign N6NHG [31][33] |
| Books | *Ghost in the Wires: My Adventures as the World's Most Wanted Hacker*, Kevin Mitnick with William L. Simon, foreword by Steve Wozniak, Little, Brown, 15 August 2011 [12]; *The Art of Intrusion*, Kevin D. Mitnick and William L. Simon, John Wiley and Sons, March 2005 [16] |
| First federal conviction | 1989, computer fraud (DOJ [1]); per UPI, the plea covered copying a DEC security program and possession of 16 unauthorized MCI long-distance codes, before Judge Mariana Pfaelzer (Reported [6]) |
| Fugitive period | From late 1992, after a warrant for violating his 1989 supervised release, to his arrest in North Carolina in February 1995 [1][10] |
| Admitted victims (1999 plea) | Motorola, Novell, Fujitsu, Sun Microsystems "and other companies"; Nokia Mobile Phones by impersonation; University of Southern California systems altered for storage [1] |
| Admitted methods | Social engineering, cloned cellular telephones, sniffer programs on victim systems, hacker software, stolen e-mail, system monitoring, employee impersonation [1] |
| 1999 plea | Four counts of wire fraud, two of computer fraud, one of illegally intercepting a wire communication [1] |
| Sentence | 46 months (agreed term), on top of an earlier 22 months; 68 months combined [1] |
| Restitution | Just over $4,125, called nominal; book and film profits to victims for seven years after release [1] |
| Supervised release | 21 January 2000 to 20 January 2003, with computer, cellular phone and industry-employment restrictions [31][1][2] |
| Christmas Day 1994 intrusion | IP source spoofing and TCP sequence prediction against Shimomura's x-terminal, from about 14:09 PST; attacker not named in the victim's account [3] |
| Modern counterpart | Scattered Spider (ATT&CK G1015) help desk impersonation, CISA and FBI AA23-320A [24]; HHS HC3 health sector help desk note, 3 April 2024 [25] |
| Later life | KnowBe4 Chief Hacking Officer and part owner from November 2011; died 16 July 2023, aged 59 [33] |

### Key findings

- **The plea record is the anchor, and it is mostly about people.** Social engineering heads the list of methods Mitnick admitted in 1999, ahead of cloned phones, sniffers and hacker software, and he separately admitted impersonating employees of victim companies (Confirmed [1]). His codefendant Lewis De Payne pleaded guilty to one wire fraud count for posing as a Nokia employee to get Nokia staff in Florida to ship a program worth about $240,000 (Confirmed [1]). Wired reported that four of the five Central District counts it described involved impersonating employees of cellular phone makers (Reported [8]).
- **The famous hack is the least documented part of the record.** Shimomura's 25 January 1995 post lays out the Christmas Day attack in detail: reconnaissance, a SYN flood to silence a trusted host, sequence-number prediction, a forged `rsh` command that opened `/.rhosts`, and a kernel module that hijacked a live session (Confirmed [3]). It does not name the attacker (Confirmed [3]). *Ghost in the Wires* (p. 326, via a review) credits an Israeli hacker known as JSZ with writing the code and carrying it out (Reported [11]). None of the charges summarized in the DOJ release, the Ninth Circuit memorandum or the *Takedown* timeline is described as covering it (Inferred [1][2][9]).
- **Losses were never settled.** DEC claimed several million dollars in software in 1989 (Reported [10]); victim letters published by 2600 in 1999 claimed nearly $300 million combined, which 2600 disputed (Reported [8]); Wired reported prosecutors sought about $1.5 million (Reported [29]); the court ordered just over $4,125 and rejected both Mitnick's claim that no restitution was owed and his claim that losses were overstated (Confirmed [1]).
- **Supervised release became the fight.** The Ninth Circuit in an unpublished 1998 memorandum upheld conditions barring computers, cellular phones and computer-industry work without probation officer approval, rejecting First Amendment, vagueness and delegation challenges (Confirmed [2]). Mitnick told the Senate they were the most restrictive conditions ever imposed in federal court (Reported [32]).
- **The Art of Intrusion is mostly unverifiable, with one documented thread and one probable match.** Its subjects are anonymous or pseudonymous and no review opened says the stories were checked (Reported [18][19]). Adrian Lamo's 2002 intrusion into the New York Times has a DOJ record (Confirmed [23]); the Florida teenager in the "terrorists" chapter matches the juvenile in DOJ release 00-555 by inference only (Confirmed [22]; Inferred match). The Lockheed Martin and Boeing claims in that chapter have no primary record found (Reported [21]).
- **The modern help desk attack is the same move.** AA23-320A describes Scattered Spider posing as employees to help desks and as help desk staff to employees, making repeated calls to learn reset procedures, and using SIM swaps and MFA fatigue (Confirmed [24]). HC3 describes callers with local area codes who supplied partial Social Security numbers and corporate IDs, claimed a broken phone, and got a new MFA device enrolled, then diverted payer ACH payments (Confirmed [25]).

### Top recommendations

1. **Treat every inbound call that claims to be an employee as unauthenticated.** Password resets and MFA device enrollment should require proof the caller cannot supply from reconnaissance: supervisor verification or in-person verification, as some hospitals already do (Confirmed [25]; Inferred as a general rule).
2. **Do not rely on a callback to the number on record alone.** Mitnick warned in 2000 that whoever controls the line controls the callback (Confirmed as testimony [5]); SIM swapping is the current form of that problem (Confirmed [24]; Inferred link). Verify the number out of band before trusting it (Inferred).
3. **Move to phishing-resistant MFA.** AA23-320A recommends FIDO/WebAuthn or PKI-based MFA, which it says resists push bombing and SIM swap (Confirmed [24]).
4. **Train with real calls.** Mitnick's own 2000 recommendations were extensive user training, a training videotape showing a phone manipulation, vigorous monitoring and auditing, and rewards and accountability (Confirmed as testimony [5]); AA23-320A calls for vishing training and HC3 for staff training (Confirmed [24][25]).
5. **Watch the downstream signals.** Alert on new MFA device enrollment after a help desk reset and on changes to payment routing such as ACH details (Confirmed for ACH monitoring [25]; Inferred for the enrollment alert).
6. **Read the books as testimony, not evidence.** When a book is the only source for a claim, say so and attribute it, as this study does (Inferred).

## Scope and method

This study covers Mitnick's own intrusions from the 1981 Pacific Bell episode to his 2000 release and testimony, the stories in *The Art of Intrusion*, the legal aftermath, and the line from his methods to the help desk vishing of 2023 and 2024. It does not retell the books. The books themselves were not opened; their content enters this study only through the publishers' pages and excerpts, contemporaneous reviews, and Mitnick's own interviews and testimony, and every such claim is graded Reported and attributed by title and author. Every source cited was opened on 3 November 2026. Quotations are kept to a few words.

| Grade | Meaning |
|---|---|
| Confirmed | A primary source was opened: a DOJ release, a court ruling, an FCC ruling, a statute, congressional testimony (as a record of what was said), the victim's own technical account, a government advisory, a publisher's own page for publication data, or the MITRE record and the library's data files |
| Reported | Known only through a secondary source: the books (via publisher text or reviews), *Takedown* and its companion site, press coverage, reviews and interviews |
| Demonstrated | A public reproduction exists. No item here is graded Demonstrated |
| Inferred | This study's own reasoning from the cited facts, labelled where it appears |

Two cautions apply throughout. *Takedown*, by Shimomura and Markoff, and its companion site were written by Shimomura, the victim of the 1994 intrusion [3], with John Markoff, so the biography and timeline are graded Reported and used mainly for dates (Reported [9][10]). Mitnick's testimony is a primary record of his own account and is self-serving by nature; it is graded Confirmed only for the fact that he said it.

## Part 1: the two books and the record

### Ghost in the Wires

*Ghost in the Wires: My Adventures as the World's Most Wanted Hacker* is by Kevin Mitnick with William L. Simon, with a foreword by Steve Wozniak, published by Little, Brown on 15 August 2011 (Confirmed [12]); the paperback went on sale on 24 April 2012 as a 448-page edition (Confirmed [13]). The publisher frames it around social engineering, quoting Publishers Weekly on that point, and its description names no victims (Confirmed [13]). Mitnick's plea agreement assigned any profits from books or films about his crimes to his victims for seven years after his release (Confirmed [1]), and the release date of 21 January 2000 puts the 2011 publication after that window (Inferred [31]).

What the memoir adds to the record is mainly its own account of the Shimomura attack. Richard Bejtlich's early review cites page 326 for Mitnick's statement that an Israeli hacker nicknamed JSZ wrote the code for and carried out the Christmas Day 1994 attack, and page 334 for the claim that the same spoofing attack worked against a second host; Bejtlich suggests Mitnick may have run that one himself, which is the reviewer's opinion (Reported [11]).

### The Art of Intrusion

*The Art of Intrusion* is by Kevin D. Mitnick and William L. Simon, John Wiley and Sons, March 2005 (hardcover ISBN 978-0-7645-6959-3), in eleven chapters (Confirmed [16]); Wiley lists the paperback, ISBN 978-0-471-78266-7, as December 2005 (Confirmed [17]). The publisher frames each chapter as a real break-in told to Mitnick by the hacker involved, followed by commentary on countermeasures, which is publisher framing rather than verification (Reported [16]). Chapter 10, "Social Engineers: How They Work and How to Stop Them," begins on page 221 (Confirmed [14]). The publisher's index shows coverage of dumpster diving, phony badges and tailgating, help desk hacking, and the social psychology of compliance with training guidelines (Confirmed for the index [15]); what those pages say is the book's own claim (Reported [15]). Publishers Weekly describes the subjects as pseudonymous hackers, and none of the three reviews opened states the stories were independently checked (Reported [18][19][20]).

Mitnick's other books on the reading list, *The Art of Deception* and *The Art of Invisibility*, are outside this study.

## Part 2: the timeline

| Date | Event | Grade | Source |
|---|---|---|---|
| Memorial Day weekend 1981 | Mitnick and two friends physically enter Pacific Bell's COSMOS center in downtown Los Angeles and take passwords, central-office lock combinations and manuals; arrested at 17, three months juvenile detention and a year of probation. Other secondary accounts differ on the year and penalty | Reported | [10] |
| 1987 to 1988 | With Lenny DiCicco, repeated intrusions into Digital Equipment's Palo Alto lab seeking VMS, launched from a Calabasas company where DiCicco worked; DiCicco confesses to his employer, which notifies DEC and the FBI | Reported | [10] |
| December 1988 | A US magistrate orders Mitnick held without bail as a danger to the community when armed with a keyboard; the case is believed to be the first under the federal law against accessing an interstate network for criminal purposes (LA Times, via RISKS Digest) | Reported | [30] |
| 15 March 1989 | Guilty plea to possessing 16 unauthorized MCI long-distance codes and one count of computer fraud for copying a DEC security program; two counts (DEC, Leeds University) to be dropped; prosecutor estimates $100,000 to $200,000 of DEC downtime; agreed terms 12 months and three years supervision, before Judge Pfaelzer | Reported | [6] |
| 1989 | Conviction for computer fraud with supervised release to follow (DOJ). *Takedown* gives the sentence as one year plus six months of counseling and DEC's claims as several million dollars in software and about $200,000 in costs | Confirmed; Reported | [1]; [10] |
| Before 1992 | By his own testimony, Mitnick obtains IRS and Social Security Administration data by phoning employees, "without even touching a computer" | Confirmed as testimony | [4][5] |
| September to November 1992 | An FBI search; about two months later a federal warrant for violating the 1989 release (illegally accessing a phone company computer, associating with a former co-arrestee); Mitnick disappears before the FBI arrives | Reported | [10] |
| 1992 to February 1995 | The fugitive intrusion series against technology companies that DOJ's investigation tracked; DOJ calls it a 2.5-year hacking spree | Confirmed | [1] |
| Fugitive period | By his own testimony, from a Denver law firm and using only pretext calls, he obtains Motorola "ultra-light" phone firmware source code in about 15 to 20 minutes and has an employee send it to a server in Colorado | Confirmed as testimony | [4][5] |
| 25 December 1994, 14:09 PST | Intrusion on Shimomura's systems begins with probes from toad.com; session hijack about 14:51 PST | Confirmed | [3] |
| 11 and 25 January 1995 | Shimomura presents the attack at CMAD 3 and posts the technical details to Usenet; he names no attacker | Confirmed | [3] |
| February 1995 | Arrest in North Carolina | Confirmed | [1] |
| 15 February 1995 | Initial federal court appearance in Raleigh | Reported | [9] |
| 9 March 1995 | North Carolina indictment, 23 counts of access device fraud | Reported | [9] |
| 26 September 1996 | Los Angeles indictment, 25 counts of access device, wire and computer fraud; De Payne charged on 14 counts | Reported | [9] |
| 27 June 1997 | 22 months: 14 for the 1989 supervised release violation and 8 for the North Carolina access device fraud | Reported | [9] |
| 20 May 1998 | Ninth Circuit (No. 97-50365) affirms the sentence on the 18 U.S.C. 1029(a)(3) plea and the supervised release conditions | Confirmed | [2] |
| March 1999 | Global plea in the Central District of California: four counts wire fraud, two computer fraud, one interception of a wire communication. The *Takedown* timeline dates it 16 March; CNN reported it on Friday 26 March | Confirmed; Reported for the dates | [1]; [9][7] |
| 5 May 1999 | Wired reports victim letters published by 2600 claiming nearly $300 million combined losses, disputed by 2600 | Reported | [8] |
| 4 June 1999 | "Free Kevin" demonstrations organized by 2600 in 15 US cities and Moscow; courtrooms picketed | Reported | [27][28] |
| 9 August 1999 | Senior Judge Mariana R. Pfaelzer sentences him to 46 months; restitution just over $4,125 | Confirmed | [1] |
| 21 January 2000 | Released; supervised release runs to 20 January 2003 | Confirmed | [31] |
| 2 March 2000 | Testimony to the Senate Committee on Governmental Affairs | Confirmed | [4][5] |
| December 2001 | Wiley book contract signed (as cited in the FCC ruling) | Confirmed | [31] |
| 20 December 2002 | FCC Chief Administrative Law Judge finds him rehabilitated and grants renewal of station N6NHG | Confirmed | [31] |
| March 2005 | *The Art of Intrusion* published | Confirmed | [16] |
| 15 August 2011 | *Ghost in the Wires* published | Confirmed | [12] |
| November 2011 | Becomes Chief Hacking Officer and part owner of KnowBe4 | Confirmed | [33] |
| 16 July 2023 | Dies aged 59 after a 14-month illness with pancreatic cancer (release dated 20 July 2023) | Confirmed | [33] |
| 16 November 2023 | CISA and FBI publish AA23-320A on Scattered Spider | Confirmed | [24] |
| 3 April 2024 | HHS HC3 analyst note on social engineering of health sector IT help desks | Confirmed | [25] |

## Part 3: the admitted conduct, 1992 to 1995

### What the plea record says

The Justice Department's 9 August 1999 release is the closest primary to the plea agreement itself, which was not found online. It says the investigation began in 1992 when Mitnick, then a fugitive, started a series of intrusions and thefts from technology companies, and that he was arrested in North Carolina in February 1995 (Confirmed [1]). In the global plea he admitted:

- breaking into computer systems and stealing proprietary software belonging to Motorola, Novell, Fujitsu, Sun Microsystems and other companies (Confirmed [1]);
- using social engineering, cloned cellular telephones, sniffer programs placed on victim systems, and hacker software (Confirmed [1]);
- altering University of Southern California systems and using them to store misappropriated programs (Confirmed [1]);
- stealing e-mail, monitoring systems, and impersonating employees of victim companies, including Nokia Mobile Phones, to obtain software under development (Confirmed [1]).

He also admitted violating his supervised release by hacking into PacBell voicemail and other systems and by associating with De Payne (Confirmed [1]). The 22 months he had already received covered the cloned phones found at his 1995 arrest and that violation (Confirmed [1]); *Takedown* breaks it into 14 months for the violation and 8 for the North Carolina access device fraud (Reported [9]). The Ninth Circuit memorandum confirms a guilty plea to possession of unauthorized access devices under 18 U.S.C. 1029(a)(3) (Confirmed [2]).

CNN reported the plea deal as including a three-year bar on computers or cellular phones without approval and the assignment of story proceeds to victims for seven years (Reported [7]). The *Takedown* timeline says the deal also carried transactional immunity for conduct from February 1992 to February 1995 (Reported [9]).

### What Mitnick said about it

Mitnick's testimony to the Senate Committee on Governmental Affairs on 2 March 2000 is his own account, on the hearing record, of how the method worked (Confirmed as testimony [4][5]):

- **Pretext calls first.** His first step against a dial-up system would be social engineering to find the modem number (Confirmed as testimony [5]).
- **Posing as an insider.** He posed as "a fellow employee having computer problems" to get IRS and SSA staff to run commands, before 1992 (Confirmed as testimony [5]).
- **Information mining.** Innocuous questions asked across an organization, assembled into intelligence (Confirmed as testimony [5]).
- **Speed.** Unplanned pretext calls got Motorola staff to send firmware source code to a server he named within 15 to 20 minutes (Confirmed as testimony [4][5]).
- **Hiding.** He used illegitimate cellular numbers and electronic serial numbers to mask his location, and said he never profited (Confirmed as testimony [4]).
- **Owning the phone line.** Callbacks are weak verification because an attacker with telephone-switch access can route the callback number to himself; he also described redirecting a modem line to a log-in simulator to capture passwords (Confirmed as testimony [5]).

The publisher frames the memoir around social engineering (Confirmed [13]); this study did not check specific episodes against the book's text (Reported, *Ghost in the Wires*, Kevin Mitnick and William L. Simon).

## Part 4: the Christmas Day 1994 intrusion

### The technical record

Shimomura's post, written from his 11 January 1995 CMAD 3 talk and sent to Usenet on 25 January 1995, is the victim's own account and the primary for the attack mechanics (Confirmed [3]). The targets were a diskless SPARCstation called "x-terminal" and a host it trusted called "server" (Confirmed [3]).

| Time (PST) | Step | Source |
|---|---|---|
| 14:09 | `finger`, `showmount` and `rpcinfo` probes from toad.com, apparently looking for an exploitable trust relationship | [3] |
| Shortly after | SYN flood of server's port 513 (`login`) so it could not answer for itself | [3] |
| Shortly after | About 20 connection probes from apollo.it.luc.edu to learn how x-terminal's initial sequence numbers incremented | [3] |
| Shortly after | A connection spoofed from server, with the predicted sequence number, uses `rsh` on x-terminal to add a wildcard entry to root's `.rhosts` file, so it trusts every host and user | [3] |
| After root | A kernel STREAMS module, `tap-2.01`, is installed | [3] |
| About 14:51 | The module takes over an already authenticated login session to a host called "target" | [3] |

The attack was blind: the intruder never saw x-terminal's replies, which is why the sequence numbers had to be predicted and the real server silenced (Inferred from [3]).

### Who did it

The post does not name the attacker (Confirmed [3]). Public attribution of the intrusion to Mitnick is not supported by any primary opened here (Inferred), and *Ghost in the Wires* itself credits JSZ (Reported [11]). This study found no charge in the DOJ release, the Ninth Circuit memorandum, the CNN plea report, the Wired loss report or the *Takedown* timeline described as covering the intrusion; the indictment texts were not opened, so this is a reading of the summaries only (Inferred [1][2][7][8][9]). The intrusion Mitnick is best known for is therefore not one the record shows he was convicted of (Inferred).

## Part 5: The Art of Intrusion against the record

| Chapter | Story, as the publisher, reviewers or Mitnick describe it | Primary record found | Grade | Source |
|---|---|---|---|---|
| 1, Hacking the Casinos for a Million Bucks | Friends reverse-engineer gambling machines and win nearly a million dollars in Las Vegas; never caught; the exploit is predictable random-number behavior | None; participants anonymous | Reported | [16][19][20] |
| 2, When Terrorists Come Calling | Two teenagers persuaded to hack Lockheed Martin. In a radio interview Mitnick said a man from India recruited a Canadian and a Florida hacker who reached Chinese universities, an Indian atomic research centre, Lockheed Martin and Boeing (747 nose schematics), and that the sponsor may have been tied to Osama bin Laden. Arthur's review calls the sponsor's identity unclear and the account loose-ended; the hackers were caught | For the Florida teenager, by inference: DOJ release 00-555. For Lockheed Martin, Boeing and the Indian centre: none | Reported; Confirmed for 00-555; Inferred match | [16][21][19][22] |
| 3, The Texas Prison Hack | Two convicts become hackers inside a Texas prison with nearly unlimited computer access and communicate outside unnoticed | None; prison and inmates unnamed | Reported | [16][18][19] |
| 5, The Robin Hood Hacker | Adrian Lamo's intrusion into the New York Times | DOJ SDNY plea release, 2004 | Reported for the chapter (chapter 5 identified by inference from the publisher's description); Confirmed for the intrusion | [19][23] |
| 10, Social Engineers | How social engineers work and how to stop them, from p. 221; dumpster diving, phony badges and tailgating, help desk hacking, the psychology of compliance | Not applicable (method chapter) | Confirmed for the index; Reported for content | [14][15] |
| Stories reviewers and Mitnick mention without a chapter number | Reviewers describe, without chapter numbers: a hacker who stole and posted film-software source code; a team that broke into a security firm's prisoner-transport system and told no one; a city WAN intrusion; hardware exploits; SQL injection on an e-commerce site; a hacker's trail through Boeing again. Mitnick also told of an intruder who walked into a conference room and planted a wireless access point used later for remote attacks | None | Reported | [19][20][21] |

### The Florida teenager and DOJ release 00-555

DOJ release 00-555 of 21 September 2000 records that an unnamed 16-year-old from Miami pleaded guilty to two acts of juvenile delinquency for intrusions into a Defense Threat Reduction Agency network from 23 August to 27 October 1999, including a hidden program on a router in Dulles, Virginia that intercepted more than 3,300 messages and at least 19 usernames and passwords; he was sentenced to six months in a detention facility (Confirmed [22]). On 29 and 30 June 1999 he accessed 13 computers at NASA's Marshall Space Flight Center and downloaded proprietary software valued at about $1.7 million that supported the International Space Station's environmental control; NASA shut systems for 21 days in July 1999 at a cost of about $41,000 (Confirmed [22]).

The book's Florida teenager matches that juvenile in state, age and period. The DOJ release names no one and the book uses handles, so the link is this study's reasoning, not record (Inferred [22][21]).

### Adrian Lamo and the New York Times

Lamo pleaded guilty before Judge Naomi Reice Buchwald in the Southern District of New York to hacking the Times' internal network on 26 February 2002, where he reached a database of more than 3,000 Op-Ed contributors, including Social Security numbers and home phone numbers, and added an entry about himself (Confirmed [23]). He created five fictitious user IDs on the Times' LexisNexis account and ran more than 3,000 searches over three months (Confirmed [23]). He also acknowledged intrusions into Excite@Home (May 2001), Yahoo (September 2001), Microsoft (October 2001), MCI WorldCom (November 2001), SBC Ameritech (December 2001) and Cingular (May 2003) (Confirmed [23]). His sentence was not checked.

## Part 6: the court record and its legacy

### Sentence and restitution

Senior Judge Mariana R. Pfaelzer imposed the 46 months the parties had agreed, on top of the earlier 22 months, and DOJ called the combined 68 months the longest sentence given to any computer hacker (Confirmed [1]). Restitution was set at just over $4,125, a nominal order given his limited future earnings; the court rejected his claim that no restitution was owed and his claim that the government had overstated losses (Confirmed [1]). He was ordered to three years of supervised release with computer access and computer-industry employment severely restricted (Confirmed [1]).

The loss claims ranged from about $1.5 million sought by prosecutors to nearly $300 million in victim letters, and the court's nominal order was about $4,125 (Reported [8][29]; Confirmed [1]). Victim letters published by 2600 claimed nearly $300 million, including $80 million for Sun tied to the Solaris acquisition price and $120 million in lost revenue for Nokia, and 2600 disputed them (Reported [8]). Wired reported prosecutors sought about $1.5 million (Reported [29]). At sentencing defence attorney Don Randolph alleged the government had manipulated and inflated loss figures, including to support detention without bail; Judge Pfaelzer denied an investigation and sanctions, and the filings were sealed over the defence's objection (Reported [29]).

### The supervised release fight

The Ninth Circuit's 20 May 1998 memorandum upheld conditions barring Mitnick from computers, computer equipment and cellular phones without probation officer approval and restricting computer and telecom employment, and rejected First Amendment, vagueness and delegation challenges (Confirmed [2]). In 2000 Mitnick called them the most restrictive conditions ever imposed in US federal court; Wired reported he was limited to a land line and barred from consulting on computer-related work (Reported [32]). The 1998 ruling set the template Mitnick attacked in that testimony; the debate concerns computer-use conditions on release, not a change to the computer crime statute (Inferred [2][32]).

### Free Kevin

In June 1999, 2600 organized demonstrations in 15 US cities and Moscow against his continued imprisonment, with yellow "Free Kevin" stickers and a plane banner naming freekevin.com; supporters framed the case as a civil rights matter (Reported [27]). Courtrooms were picketed, and a Free Kevin statement objected that prosecutors wanted another year in prison plus three years of supervised release (Reported [28]).

### Testimony, licence, career

Six weeks after release Mitnick told the Senate Committee on Governmental Affairs that the human side of computer security is easily exploited and urged user training (Confirmed as testimony [4]). He called a pending federal information security bill a good first step and urged an audit program and a numeric trust ranking, before a committee chaired by Senator Fred Thompson (Reported [32]). The FCC designated his amateur radio licence renewal for a character hearing; in December 2002 the Chief Administrative Law Judge found him rehabilitated and renewed station N6NHG, citing the Senate testimony, his consulting, a 2001 radio show and the Wiley book contract (Confirmed [31]). In November 2011 he became Chief Hacking Officer and part owner of KnowBe4 (Confirmed [33]). He died on 16 July 2023 (Confirmed [33]).

### The statute

18 U.S.C. 1030 was enacted in 1984 and amended in 1986, 1996 and 2001; its definition of loss, in section 1030(e)(11), covers any reasonable cost to any victim, including response, damage assessment and restoration (Confirmed [34]). The 1999 restitution dispute shows the loss-valuation problem that definition addresses, but no source opened says the Mitnick case caused the amendment (Inferred [34][1]).

## Part 7: the defender view, from pretext calls to help desk vishing

### The same call, a bigger prize

AA23-320A, published by CISA and the FBI on 16 November 2023, says Scattered Spider poses as IT or help desk staff to employees and as employees to help desks, to get passwords reset and MFA moved to attacker devices; it makes multiple calls to learn reset procedures, abuses contracted help desks, and uses SIM swapping and MFA fatigue (Confirmed [24]). The HHS HC3 analyst note of 3 April 2024 describes callers with local area codes posing as revenue-cycle or administrator staff, supplying the last four digits of Social Security numbers and corporate IDs, claiming a broken phone, and getting help desks to enroll a new MFA device, then diverting payer ACH payments; it notes possible AI voice impersonation and ties the tactics to the September 2023 hospitality and entertainment intrusion that Scattered Spider (UNC3944) claimed, which used ALPHV ransomware (Confirmed [25]). The sector-wide record of Scattered Spider, ALPHV affiliates and the other actors that reach hospitals through the help desk is the home topic of the [Healthcare Threat Actor Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), and the ALPHV affiliate attack of February 2024 is the subject of [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md); this study keeps to the line from the 1990s pretext call.

Set beside Mitnick's testimony, the 1990s insider-caller pretext and the 2023 to 2024 help desk pretext are the same move (Inferred [5][24][25]). What changed is the payoff. A reset or MFA re-enrollment now yields an identity that opens every application behind single sign-on, where Mitnick's calls yielded a modem number, a command run on his behalf, or one source tree (Inferred).

### Where the advice falls short

AA23-320A recommends phishing-resistant MFA (FIDO/WebAuthn or PKI), vishing training, risky-login monitoring, and long unique passwords with lockout, but gives no step-by-step help desk identity verification procedure (Confirmed [24]). HC3 fills part of that gap: call back the number on record before a reset or device enrollment (attackers may claim to be too busy), verify in person as some hospitals do, require supervisor verification, monitor ACH changes, and train (Confirmed [25]). Mitnick's 2000 warning applies to the callback step: if the attacker controls the number, a callback confirms the attacker (Confirmed as testimony [5]). SIM swapping is that warning's modern form, so a callback to the number on record is only as good as the carrier account behind it (Inferred [5][24]).

### A help desk checklist

- Require a verification factor the caller cannot learn by calling around: an in-person check, a manager's confirmation through a separate channel, or an existing phishing-resistant authenticator (Confirmed for in-person and supervisor checks [25]; Inferred for the rest).
- Treat partial Social Security numbers, employee IDs and knowledge of internal procedures as public; the HC3 callers had them (Confirmed [25]).
- Enforce a hold period and an alert on any new MFA device enrolled after a help desk reset (Inferred from [25]).
- Limit what staff disclose about roles and procedures to unverified callers, since information mining is the first step (Confirmed as testimony [5]; Inferred as a control).
- Run phone-based exercises, not only e-mail phishing tests; Mitnick proposed recorded phone manipulations as training material in 2000 (Confirmed as testimony [5]).

## Part 8: MITRE mappings

This Part binds the record to MITRE ATT&CK v20.0, CAPEC and D3FEND, with every id checked against the library's data files on 3 November 2026 and, for T1684.001, the live ATT&CK page (Confirmed [26][35]). No source in the Mitnick record cites an ATT&CK id; those mappings are this study's reading of Confirmed facts (Inferred). The modern comparison rows carry ids that AA23-320A and HC3 cite themselves (Confirmed [24][25]). There is no ATT&CK for ICS or Mobile mapping in this study.

ATT&CK revoked T1656 Impersonation in v19.0; the library's `data/attack/superseded_by.jsonl` maps it to T1684.001 Impersonation, a sub-technique of T1684 Social Engineering under the Stealth tactic, created on 14 April 2026, whose procedure examples include help desk impersonation by Scattered Spider, LAPSUS$ and Storm-1811 (Confirmed [26][35]). Where AA23-320A cites T1656, this study shows T1684.001.

### ATT&CK Enterprise techniques: Mitnick's own record

| Id | Name | Tactic (v20.0) | Where it appears in the record | Source |
|---|---|---|---|---|
| [T1684.001](/mitre/techniques/T1684-001.md) | Impersonation | Stealth | 1999 plea: impersonating Nokia Mobile Phones employees; De Payne posing as a Nokia employee; testimony on posing as a fellow employee to IRS and SSA staff (before 1992) | [1][4][5] |
| [T1598.004](/mitre/techniques/T1598-004.md) | Spearphishing Voice | Reconnaissance | Testimony: pretext calls to find modem numbers; Motorola firmware calls (fugitive period); plea admission of social engineering | [1][4][5] |
| [T1589](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | Testimony: information mining across an organization (2000) | [5] |
| [T1591](/mitre/techniques/T1591.md) | Gather Victim Org Information | Reconnaissance | Testimony: learning the target organization by phone before an intrusion | [5] |
| [T1591.004](/mitre/techniques/T1591-004.md) | Identify Roles | Reconnaissance | Testimony: information mining to learn who holds which role | [5] |
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | 1999 plea: sniffer programs placed on victim systems (1992 to 1995) | [1] |
| [T1114](/mitre/techniques/T1114.md) | Email Collection | Collection | 1999 plea: stealing e-mail | [1] |
| [T1584.004](/mitre/techniques/T1584-004.md) | Server | Resource Development | 1999 plea: altering USC systems to store misappropriated programs | [1] |
| [T1074.002](/mitre/techniques/T1074-002.md) | Remote Data Staging | Collection | 1999 plea: storing programs on USC systems | [1] |
| [T1595](/mitre/techniques/T1595.md) | Active Scanning | Reconnaissance | 25 December 1994: `finger`, `showmount`, `rpcinfo` from toad.com | [3] |
| [T1046](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | 25 December 1994: `showmount` and `rpcinfo` probes | [3] |
| [T1499.001](/mitre/techniques/T1499-001.md) | OS Exhaustion Flood | Impact | 25 December 1994: SYN flood of server's `login` port, used to silence it rather than for impact (loose fit) | [3] |
| [T1199](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | 25 December 1994: abuse of the `rsh` trust between x-terminal and server; ATT&CK's technique concerns third-party relationships, so the fit is loose | [3] |
| [T1098](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | 25 December 1994: a wildcard trust entry added to root's `.rhosts` file | [3] |
| [T1563](/mitre/techniques/T1563.md) | Remote Service Session Hijacking | Lateral Movement | 25 December 1994, about 14:51: `tap-2.01` takes over an authenticated login session | [3] |

Cloned cellular phones, which Mitnick admitted and the North Carolina case charged, have no Enterprise technique and are left unmapped (Confirmed for the conduct [1]; Reported for the North Carolina access device charges [9]; Inferred for the gap). The 1981 physical entry to Pacific Bell's COSMOS center is Reported only and is not mapped.

### ATT&CK Enterprise techniques: Art of Intrusion threads with a DOJ record

| Id | Name | Tactic (v20.0) | Where it appears in the record | Source |
|---|---|---|---|---|
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | DOJ 00-555: router program in Dulles intercepting more than 3,300 messages (1999) | [22] |
| [T1005](/mitre/techniques/T1005.md) | Data from Local System | Collection | DOJ 00-555: software downloaded from 13 NASA Marshall computers (29 and 30 June 1999) | [22] |
| [T1213](/mitre/techniques/T1213.md) | Data from Information Repositories | Collection | DOJ SDNY: Lamo's access to the Times' Op-Ed contributor database (26 February 2002) | [23] |
| [T1136](/mitre/techniques/T1136.md) | Create Account | Persistence | DOJ SDNY: five fictitious user IDs on the Times' LexisNexis account (2002) | [23] |

T1078 is not mapped: the release records captured credentials, not their use. The casino random-number exploit has no clean Enterprise technique and is not mapped.

### ATT&CK Enterprise techniques: the modern comparison

| Id | Name | Tactic (v20.0) | Where it appears | Source |
|---|---|---|---|---|
| [T1598](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | AA23-320A (16 November 2023) | [24] |
| [T1598.004](/mitre/techniques/T1598-004.md) | Spearphishing Voice | Reconnaissance | AA23-320A | [24] |
| [T1566.004](/mitre/techniques/T1566-004.md) | Spearphishing Voice | Initial Access | AA23-320A; HC3 (3 April 2024) | [24][25] |
| [T1684.001](/mitre/techniques/T1684-001.md) | Impersonation | Stealth | AA23-320A, cited as T1656 | [24][26][35] |
| [T1621](/mitre/techniques/T1621.md) | Multi-Factor Authentication Request Generation | Credential Access | AA23-320A (MFA fatigue) | [24] |
| [T1078.002](/mitre/techniques/T1078-002.md) | Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | AA23-320A | [24] |
| [T1589](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | AA23-320A | [24] |
| [T1556.006](/mitre/techniques/T1556-006.md) | Multi-Factor Authentication | Defense Impairment, Persistence, Credential Access | AA23-320A (moving MFA to attacker devices) | [24] |

AA23-320A also cites a Mobile SIM swap technique; it is outside the library's generated pages and is left out.

### ATT&CK groups, software and campaigns

| Object | Id and library page | Tie to this study | Source |
|---|---|---|---|
| Scattered Spider | [G1015](/mitre/groups/G1015.md) | The modern comparison object. The library's group data lists, among others, T1598, T1598.003, T1598.004, T1589, T1621, T1078, T1078.004, T1684.001 and T1556.006 for it, but not T1566.004, which AA23-320A cites; the live ATT&CK G1015 page was not checked | [35][24] |

ATT&CK has no group, software or campaign object for Mitnick's activity and no matching page exists in the library's `mitre/` tree, so this study maps techniques only (Confirmed for the tree [35]; Inferred for the conclusion). ALPHV, which HC3 names, is ATT&CK software [S1068 BlackCat](/mitre/software/S1068.md) (Confirmed [35]).

### Mitigations

| Mitigation | Library page | Techniques here it covers in the library's data | Source |
|---|---|---|---|
| User Training | [M1017](/mitre/mitigations/M1017.md) | T1598, T1598.004, T1566.004, T1684.001, T1621, T1078, T1078.002, T1213 | [35] |
| Multi-factor Authentication | [M1032](/mitre/mitigations/M1032.md) | T1040, T1078, T1078.002, T1098, T1114, T1136, T1199, T1213, T1556.006, T1621 | [35] |
| Threat Intelligence Program | [M1019](/mitre/mitigations/M1019.md) | T1684.001 | [35] |
| Pre-compromise | [M1056](/mitre/mitigations/M1056.md) | T1589, T1591, T1591.004, T1595, T1584.004 | [35] |

M1017 matches Mitnick's own 2000 recommendation of extensive user training (Confirmed as testimony [5]); M1032 in its phishing-resistant form is AA23-320A's main recommendation (Confirmed [24]).

### CAPEC and CWE

| CAPEC | Name | Where it fits | Source |
|---|---|---|---|
| [CAPEC-407](/mitre/capec/CAPEC-407.md) | Pretexting | Plea impersonation of Nokia employees; testimony on posing as a fellow employee; the library links it to T1589 | [1][5][35] |
| [CAPEC-410](/mitre/capec/CAPEC-410.md) | Information Elicitation | Testimony: information mining | [5][35] |
| [CAPEC-413](/mitre/capec/CAPEC-413.md) | Pretexting via Tech Support | AA23-320A: posing as IT or help desk staff to employees | [24][35] |
| [CAPEC-416](/mitre/capec/CAPEC-416.md) | Manipulate Human Behavior | *The Art of Intrusion*, chapter 10: the social psychology of compliance | [15][35] |
| [CAPEC-406](/mitre/capec/CAPEC-406.md) | Dumpster Diving | *The Art of Intrusion* index; no ATT&CK technique fits it | [15][35] |
| [CAPEC-593](/mitre/capec/CAPEC-593.md) | Session Hijacking | 25 December 1994: the `tap-2.01` takeover of an authenticated session; the library links it to T1563 | [3][35] |
| [CAPEC-482](/mitre/capec/CAPEC-482.md) | TCP Flood | 25 December 1994: the SYN flood that silenced server; the library links it to T1499.001 | [3][35] |

The pairings are this study's reading (Inferred); the ids and pages are Confirmed in the library's CAPEC 3.9 data, which assigns no CWE to the five social engineering entries and lists CWE-287 for CAPEC-593 and CWE-770 for CAPEC-482; this study does not bind those two CWEs to the 1994 record (Confirmed [35]; Inferred for the choice). No CWE id is bound for the 1994 predictable sequence numbers, because none was checked against the library's data.

### D3FEND countermeasures

| Countermeasure | Library mapping in `technique_to_d3fend.jsonl` | Where it fits | Source |
|---|---|---|---|
| [Account Locking](/mitre/d3fend/account-locking.md), [Restore User Account Access](/mitre/d3fend/restore-user-account-access.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md), [Agent Authentication](/mitre/d3fend/agent-authentication.md), [Access Modeling](/mitre/d3fend/access-modeling.md) | T1078 and T1098 | Locking and restoring accounts after a fraudulent reset; restricting what a reset account can reach (Inferred pairing) | [35] |
| [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md), [Session Termination](/mitre/d3fend/session-termination.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md) | T1563 and T1199 | The 1994 session hijack and trust abuse (Inferred pairing) | [35] |
| [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) | T1040 (the library's only D3FEND row for it) | Weak fit for sniffers on victim hosts (Inferred) | [35] |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | Not mapped to these techniques | AA23-320A's phishing-resistant MFA recommendation (Inferred pairing) | [35][24] |

The library's D3FEND data has no rows for T1598.004, T1566.004 or T1684.001, so D3FEND coverage of the voice-pretext step itself is a gap (Confirmed [35]).

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer, [navigator/library-layers/mitnick-intrusions.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/mitnick-intrusions.json), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 and scores each technique by the strength of the record behind it, not the certainty of the mapping: 100 for conduct Mitnick admitted in the 1999 plea or described in testimony, 75 for the Christmas Day 1994 intrusion whose attacker the primary record does not name, 50 for *Art of Intrusion* stories with a DOJ record, and 25 for techniques that appear only in the modern comparison. Each entry's comment names the source numbers above.

## Cross-cutting themes

- **People were the vulnerability then and are now.** The admitted methods lead with social engineering, and the plea separately records employee impersonation (Confirmed [1]), and the 2023 and 2024 advisories describe the same play against help desks (Confirmed [24][25]). See the [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md).
- **Verification channels are attack surface.** Mitnick's point about callbacks (Confirmed as testimony [5]) is the same point SIM swapping makes about phone-based recovery (Confirmed [24]; Inferred link). See the [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md) and the [Telecom and 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md).
- **Voice is getting easier to fake.** HC3 already flags possible AI voice impersonation in help desk calls (Confirmed [25]). See [Deepfake and Synthetic-Media Defense](/DEEPFAKE_DEFENSE_REFERENCE.md).
- **Loss numbers are claims.** Victims claimed nearly $300 million and prosecutors sought about $1.5 million, while the court ordered a nominal $4,125 because of his limited future earnings (Reported [8][29]; Confirmed [1]). Breach-cost figures need the same scepticism today (Inferred).
- **Memoir is evidence of what someone says.** *Ghost in the Wires* disowns the most famous intrusion attributed to its author (Reported [11]); *The Art of Intrusion* is mostly anonymous stories with no primary record (Reported [18][19]). Both are useful for method; neither should be cited for facts without a primary (Inferred).

### What is overstated and what is understated

- **Overstated: the Shimomura attack as Mitnick's crime.** The victim's account names no attacker, the memoir names someone else, and no charge summary opened covers it (Confirmed [3]; Reported [11]; Inferred [1][2][9]).
- **Overstated: the case as the origin of computer crime law.** The library's [Notable Incidents](/NOTABLE_INCIDENTS.md) table says the arrest shaped the interpretation of the Computer Fraud and Abuse Act. No source opened here says the case changed the statute; the clearest legal legacy in the record is the 1998 ruling on computer-use conditions of release (Confirmed [2][34]; Inferred).
- **Overstated: the losses.** The victims' combined claim of nearly $300 million was disputed at the time and the court ordered a nominal sum (Reported [8]; Confirmed [1]).
- **Understated: how little technical skill the core method needed.** By his own testimony he got source code in 15 to 20 minutes of phone calls and taxpayer data without touching a computer (Confirmed as testimony [4][5]).
- **Understated: the codefendant.** Lewis De Payne's guilty plea for posing as a Nokia employee is the most concrete single act of impersonation in the primary record, and it is rarely mentioned (Confirmed [1]).

## Sources

All sources were opened on 3 November 2026. "Primary" means the organization that published the fact; grades apply to the source as used here.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | US Department of Justice, US Attorney's Office, Central District of California, "Kevin Mitnick Sentenced to Nearly Four Years in Prison," 9 Aug 1999 (archived copies; the original justice.gov page no longer resolves) | [web.archive.org copy of usdoj.gov/criminal/cybercrime/mitnick.htm](https://web.archive.org/web/20001213003500/http://www.usdoj.gov/criminal/cybercrime/mitnick.htm); [UNT End of Term copy](https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/mitnick.htm); [UNT copy 2](https://webarchive.library.unt.edu/eot2008/20080916032623/http://www.cybercrime.gov/mitnick.htm) | 2026-11-03 | Confirmed |
| 2 | United States v. Mitnick, 145 F.3d 1342 (9th Cir. 1998), No. 97-50365, unpublished memorandum, 20 May 1998 | [law.justia.com/cases/federal/appellate-courts/F3/145/1342/470528/](https://law.justia.com/cases/federal/appellate-courts/F3/145/1342/470528/) | 2026-11-03 | Confirmed |
| 3 | Tsutomu Shimomura, technical details of the attack, Usenet, 25 Jan 1995 (two mirrors) | [pld.cs.luc.edu/courses/447/sum08/class7/shimomura.text](https://pld.cs.luc.edu/courses/447/sum08/class7/shimomura.text); [aeb.win.tue.nl/linux/hh/shimomura-25jan95.txt](https://aeb.win.tue.nl/linux/hh/shimomura-25jan95.txt) | 2026-11-03 | Confirmed |
| 4 | Kevin Mitnick, testimony to the Senate Committee on Governmental Affairs, 2 Mar 2000 (PBS Frontline reproduction) | [pbs.org/wgbh/pages/frontline/shows/hackers/whoare/testimony.html](https://www.pbs.org/wgbh/pages/frontline/shows/hackers/whoare/testimony.html) | 2026-11-03 | Confirmed (as testimony) |
| 5 | US Senate Committee on Governmental Affairs hearing record, 106th Congress (CHRG-106shrg63639), 2 Mar 2000 | [govinfo.gov/content/pkg/CHRG-106shrg63639/html/CHRG-106shrg63639.htm](https://govinfo.gov/content/pkg/CHRG-106shrg63639/html/CHRG-106shrg63639.htm) | 2026-11-03 | Confirmed (as testimony) |
| 6 | UPI, "Computer hacker pleads guilty," 15 Mar 1989 | [upi.com/Archives/1989/03/15/Computer-hacker-pleads-guilty/4340605941200/](https://www.upi.com/Archives/1989/03/15/Computer-hacker-pleads-guilty/4340605941200/) | 2026-11-03 | Reported |
| 7 | CNN, Mitnick plea report, 26 Mar 1999 | [cnn.com/US/9903/26/mitnick.plea/index.html](https://www.cnn.com/US/9903/26/mitnick.plea/index.html) | 2026-11-03 | Reported |
| 8 | Wired, "How Much Damage Did Mitnick Do?", 5 May 1999 (mirror) | [wirednews.pages.dev/1999/05/how-much-damage-did-mitnick-do](https://wirednews.pages.dev/1999/05/how-much-damage-did-mitnick-do) | 2026-11-03 | Reported |
| 9 | Takedown.com timeline, 1995 to 2000 (companion site to *Takedown* by Tsutomu Shimomura and John Markoff) | [takedown.com/timeline/index_current.html](https://www.takedown.com/timeline/index_current.html) | 2026-11-03 | Reported |
| 10 | Takedown.com biography (excerpt of *Takedown*, Shimomura and Markoff) | [takedown.com/bio/index.html](https://www.takedown.com/bio/index.html) | 2026-11-03 | Reported |
| 11 | Richard Bejtlich, "Early Review of Ghost in the Wires," TaoSecurity, Apr 2011 | [taosecurity.blogspot.com/2011/04/early-review-of-ghost-in-wires.html](https://taosecurity.blogspot.com/2011/04/early-review-of-ghost-in-wires.html) | 2026-11-03 | Reported |
| 12 | Hachette Book Group, *Ghost in the Wires*, hardcover (ISBN 9780316134477) | [hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/](https://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/) | 2026-11-03 | Confirmed (publication data) |
| 13 | Hachette Book Group, *Ghost in the Wires*, paperback (ISBN 9780316037723) | [hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316037723/](https://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316037723/) | 2026-11-03 | Confirmed (publication data); Reported (book content) |
| 14 | Wiley, *The Art of Intrusion* excerpt, table of contents | [media.wiley.com/product_data/excerpt/97/07645695/0764569597-1.pdf](https://media.wiley.com/product_data/excerpt/97/07645695/0764569597-1.pdf) | 2026-11-03 | Confirmed |
| 15 | Wiley, *The Art of Intrusion* excerpt, index | [media.wiley.com/product_data/excerpt/97/07645695/0764569597-2.pdf](https://media.wiley.com/product_data/excerpt/97/07645695/0764569597-2.pdf) | 2026-11-03 | Confirmed (index); Reported (content) |
| 16 | Wiley-VCH, *The Art of Intrusion* product page (ISBN 978-0-7645-6959-3) | [wiley-vch.de/de/fachgebiete/computer-und-informatik/the-art-of-intrusion-978-0-7645-6959-3](https://www.wiley-vch.de/de/fachgebiete/computer-und-informatik/the-art-of-intrusion-978-0-7645-6959-3) | 2026-11-03 | Confirmed (publication data); Reported (story descriptions) |
| 17 | Wiley, *The Art of Intrusion* product page (ISBN 9780471782667) | [wiley.com product page](https://www.wiley.com/en-us/The+Art+of+Intrusion%3A+The+Real+Stories+Behind+the+Exploits+of+Hackers%2C+Intruders+and+Deceivers-p-9780471782667) | 2026-11-03 | Confirmed (publication data) |
| 18 | Publishers Weekly review of *The Art of Intrusion*, 14 Feb 2005 | [www2.publishersweekly.com/9780764569593](https://www2.publishersweekly.com/9780764569593) | 2026-11-03 | Reported |
| 19 | Charles Arthur, review of *The Art of Intrusion*, The Register, 29 Mar 2005 (ISN mailing list copy) | [seclists.org/isn/2005/Mar/149](https://seclists.org/isn/2005/Mar/149) | 2026-11-03 | Reported |
| 20 | David Norfolk, review of *The Art of Intrusion*, The Register, 26 Jan 2006 | [theregister.com/2006/01/26/art_intrusion/](https://www.theregister.com/2006/01/26/art_intrusion/) | 2026-11-03 | Reported |
| 21 | Coast to Coast AM, show page for 26 Mar 2005 (Mitnick interview) | [coasttocoastam.com/show/2005-03-26-show](https://www.coasttocoastam.com/show/2005-03-26-show) | 2026-11-03 | Reported |
| 22 | US Department of Justice, release 00-555, juvenile sentenced for NASA and DTRA intrusions, 21 Sep 2000 | [justice.gov/archive/opa/pr/2000/September/555crm.htm](https://www.justice.gov/archive/opa/pr/2000/September/555crm.htm) | 2026-11-03 | Confirmed |
| 23 | US Department of Justice, Southern District of New York, Adrian Lamo plea release, 8 Jan 2004 | [justice.gov/archive/criminal/cybercrime/press-releases/2004/lamoPlea.htm](https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/lamoPlea.htm) | 2026-11-03 | Confirmed |
| 24 | CISA and FBI, AA23-320A, Scattered Spider, 16 Nov 2023 (page as currently published, dated 29 Jul 2025) | [cisa.gov/news-events/cybersecurity-advisories/aa23-320a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) | 2026-11-03 | Confirmed |
| 25 | HHS Health Sector Cybersecurity Coordination Center (HC3), analyst note on social engineering attacks targeting IT help desks in the health sector, 3 Apr 2024 (AHA-hosted copy) | [aha.org hosted PDF](https://www.aha.org/system/files/media/file/2024/04/hc3-tlp-clear-analyst-note-social-engineering-attacks-targeting-it-help-desks-in-the-health-sector-4-3-2024.pdf) | 2026-11-03 | Confirmed |
| 26 | MITRE ATT&CK, T1684.001 Impersonation | [attack.mitre.org/techniques/T1684/001/](https://attack.mitre.org/techniques/T1684/001/) | 2026-11-03 | Confirmed |
| 27 | Wired, pro-Mitnick demonstrations in the US and Russia, 4 Jun 1999 | [wired.com/1999/06/pro-mitnick-demos-in-us-russia/](https://www.wired.com/1999/06/pro-mitnick-demos-in-us-russia/) | 2026-11-03 | Reported |
| 28 | The Register, "US hackers picket for Mitnick," 8 Jun 1999 | [theregister.com/1999/06/08/us_hackers_picket_for_mitnick/](https://www.theregister.com/1999/06/08/us_hackers_picket_for_mitnick/) | 2026-11-03 | Reported |
| 29 | Wired, "Mitnick Could Go Free in January," Aug 1999 | [wired.com/1999/08/mitnick-could-go-free-in-january/](https://www.wired.com/1999/08/mitnick-could-go-free-in-january/) | 2026-11-03 | Reported |
| 30 | RISKS Digest 7.95 (LA Times excerpt), Dec 1988 | [catless.ncl.ac.uk/Risks/7/95](https://catless.ncl.ac.uk/Risks/7/95) | 2026-11-03 | Reported |
| 31 | Federal Communications Commission, initial decision of the Chief Administrative Law Judge, FCC 02D-02, 20 Dec 2002 | [docs.fcc.gov/public/attachments/FCC-02D-02A1.pdf](https://docs.fcc.gov/public/attachments/FCC-02D-02A1.pdf) | 2026-11-03 | Confirmed |
| 32 | Wired, "Mr. Mitnick Goes to Washington," Mar 2000 | [wired.com/2000/03/mr-mitnick-goes-to-washington/](https://www.wired.com/2000/03/mr-mitnick-goes-to-washington/) | 2026-11-03 | Reported |
| 33 | KnowBe4 and the Mitnick family, release on his life and legacy, 20 Jul 2023 | [knowbe4.com/press/knowbe4-and-the-mitnick-family-honor-the-life-and-legacy-of-kevin-mitnick](https://knowbe4.com/press/knowbe4-and-the-mitnick-family-honor-the-life-and-legacy-of-kevin-mitnick) | 2026-11-03 | Confirmed |
| 34 | 18 U.S.C. 1030, Legal Information Institute, Cornell Law School | [law.cornell.edu/uscode/text/18/1030](https://www.law.cornell.edu/uscode/text/18/1030) | 2026-11-03 | Confirmed |
| 35 | TeamStarWolf library data at main on 3 Nov 2026 and at main `fdb0bf9f` (11 Nov 2026): `data/attack/technique_profiles.jsonl`, `data/attack/superseded_by.jsonl`, `data/attack/group_to_technique.jsonl`, `data/attack/mitigation_to_technique.jsonl`, `data/attack/technique_to_d3fend.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-03; 2026-11-11 | Confirmed (library data) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Insider Threat Reference](/INSIDER_THREAT_REFERENCE.md)
- [Deepfake and Synthetic-Media Defense](/DEEPFAKE_DEFENSE_REFERENCE.md), [Telecom and 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md) (no CVE identifier is attached to any event in this record)
- [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md)
- Related case studies: [The Cuckoo's Egg Intrusion, 1986](/case-studies/CUCKOOS_EGG_1986.md), the other book-derived study of an intrusion of the same decade; [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md), whose *Hacker Crackdown* part covers the 1990 federal crackdown on computer intrusion in the same years; [Healthcare Threat Actor Watchlist, 2023 to 2026](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) and [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), for the help desk and ALPHV record in the sector
- Group: [G1015 Scattered Spider](/mitre/groups/G1015.md)
- Techniques: [T1684 Social Engineering](/mitre/techniques/T1684.md), [T1684.001 Impersonation](/mitre/techniques/T1684-001.md), [T1598.004 Spearphishing Voice](/mitre/techniques/T1598-004.md), [T1566.004 Spearphishing Voice](/mitre/techniques/T1566-004.md), [T1589 Gather Victim Identity Information](/mitre/techniques/T1589.md), [T1591.004 Identify Roles](/mitre/techniques/T1591-004.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1563 Remote Service Session Hijacking](/mitre/techniques/T1563.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1621 Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md)
- Mitigations: [M1017 User Training](/mitre/mitigations/M1017.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md)
- CAPEC: [CAPEC-407 Pretexting](/mitre/capec/CAPEC-407.md), [CAPEC-410 Information Elicitation](/mitre/capec/CAPEC-410.md), [CAPEC-413 Pretexting via Tech Support](/mitre/capec/CAPEC-413.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [mitnick-intrusions.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/mitnick-intrusions.json)
- [All case studies](/case-studies/README.md)
