# Slide plan: Kevin Mitnick: Ghost in the Wires and The Art of Intrusion

- Study: case-studies/MITNICK_INTRUSIONS.md
- Cover title: Kevin Mitnick / Ghost in the Wires and / The Art of Intrusion
- Subtitle: The court and government record behind two books, and the help desk call that never went away
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/MITNICK_INTRUSIONS.md, told from the DOJ, court, Senate, FCC and advisory record rather than from the books, whose text was not opened. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The record is narrower than the legend, and mostly about people

- **The 1999 global plea** admits social engineering, cloned phones, sniffers and hacker software.
- **68 months combined** in prison, but restitution of just over $4,125 against huge claims.
- **The famous 1994 hack** names no attacker in the victim's account; the memoir credits someone else.
- **The method carries forward:** the 1990s pretext call is the 2023 Scattered Spider help desk call.
- **The books are testimony,** not evidence: every claim known only from them is graded Reported.
Caption: Grades: plea, sentence, rulings, 1994 mechanics and advisories Confirmed; book content Reported; links Inferred.
Notes: DOJ sentencing release [1], Ninth Circuit memorandum [2], Shimomura's post [3], Senate testimony [4][5], Bejtlich's review of the memoir [11], AA23-320A [24] and the HC3 note [25]. The books themselves were not opened.

## KEY FACTS | Four counts of wire fraud, 68 months and a nominal $4,125

Stat: 68 months | combined term, called the longest for a hacker
Stat: ~$4,125 | restitution ordered, called nominal
Stat: ~$300M | combined losses claimed in victim letters, disputed
Stat: 15-20 min | of calls for Motorola source, per his testimony
- Fugitive from late 1992 to his arrest in North Carolina in February 1995.
- Supervised release ran from 21 January 2000 to 20 January 2003.
- He died on 16 July 2023, aged 59.
Notes: Sentence and restitution [1]. Victim letters via Wired [8], Reported. Motorola calls [4][5], Confirmed as testimony. Release dates from the FCC ruling [31]. Death [33]. ATT&CK has no group, software or campaign object for his activity [35].

## PART 1 | Two books, neither of them a primary record

Left: Ghost in the Wires (2011)
- His own memoir, with William L. Simon.
- Little, Brown, 15 August 2011.
- Framed around social engineering.
- Credits JSZ with the 1994 attack (p. 326).
Right: The Art of Intrusion (2005)
- Other people's break-ins, told to him.
- John Wiley and Sons, March 2005.
- Subjects anonymous or pseudonymous.
- No review says the stories were checked.
Notes: Publisher pages [12][13][16][17], Confirmed for publication data. JSZ claim from Bejtlich's review [11], Reported. Reviews [18][19][20], Reported. The plea assigned book profits to victims for seven years after release [1]; the 2011 date falls after that window [31], Inferred.

## PART 2 | From a phone company in 1981 to a federal plea in 1999

| Date | Event | Grade |
|---|---|---|
| 1981 | Physical entry to Pacific Bell's COSMOS center | Reported |
| 15 Mar 1989 | Plea: MCI codes and copying a DEC program | Reported |
| Late 1992 | Release-violation warrant; he disappears | Reported |
| 25 Dec 1994 | Intrusion on Shimomura's systems | Confirmed |
| Feb 1995 | Arrest in North Carolina | Confirmed |
| 20 May 1998 | Ninth Circuit affirms; upholds release terms | Confirmed |
| 9 Aug 1999 | Sentenced to 46 months on the global plea | Confirmed |
Caption: Dates graded Reported come from Takedown, written by the victim of the 1994 intrusion with John Markoff.
Notes: Part 2 timeline. COSMOS and the 1992 warrant from the Takedown biography [10]; 1989 plea from UPI [6]; 1994 intrusion [3]; arrest and sentence [1]; Ninth Circuit memorandum [2].

## PART 3 | He admitted social engineering first, then phones and sniffers

- **Stolen software** from Motorola, Novell, Fujitsu, Sun Microsystems and other companies.
- **Methods:** social engineering, cloned cellular phones, sniffer programs and hacker software.
- **Impersonating employees** of victim companies, including Nokia Mobile Phones.
- **USC systems altered** and used to store the misappropriated programs.
- **Codefendant Lewis De Payne** pleaded guilty for posing as a Nokia employee.
Notes: All from the DOJ release of 9 August 1999 [1], the closest primary to the plea agreement, which was not found online. The Ninth Circuit confirms a plea under 18 U.S.C. 1029(a)(3) [2]. Wired reported four of five Central District counts involved impersonation [8], Reported.

## PART 3 | His Senate testimony describes the pretext call step by step

- **Pretext calls first,** to find a dial-up modem number.
- **Posing as a fellow employee** with computer problems, to get IRS and SSA staff to run commands.
- **Information mining:** innocuous questions across an organization, assembled into intelligence.
- **Owning the phone line:** a callback fails when the attacker controls the number.
- **Speed:** Motorola firmware source sent to his server within 15 to 20 minutes of calls.
Caption: Testimony is Confirmed as a record of what he told the committee, not as proof of the events.
Notes: Senate Committee on Governmental Affairs, 2 March 2000: PBS Frontline reproduction [4] and the govinfo hearing record [5]. Self-serving by nature; graded Confirmed as testimony only.

## PART 4 | The Christmas Day 1994 attack was blind spoofing and a hijack

| Time (PST) | Step |
|---|---|
| 14:09 | finger, showmount and rpcinfo probes from toad.com |
| Shortly after | SYN flood silences the trusted host |
| Shortly after | About 20 probes learn the sequence numbers |
| Shortly after | Spoofed rsh opens root's .rhosts to all |
| After root | Kernel STREAMS module tap-2.01 installed |
| About 14:51 | Authenticated login session taken over |
Caption: The intruder never saw the replies, so sequence numbers had to be predicted and the real host silenced.
Notes: Shimomura's Usenet post of 25 January 1995, written from his CMAD 3 talk [3], Confirmed. The blind-attack reading is Inferred from [3].

## PART 4 | The intrusion he is best known for is not on his record

- **The victim's post names no attacker;** a mirror host's preface names Mitnick.
- **Ghost in the Wires credits an Israeli hacker** known as JSZ with the code and the attack.
- **No charge summary opened covers it:** DOJ, the Ninth Circuit, CNN, Wired or Takedown.
- **The indictment texts were not opened,** so this is a reading of the summaries only.
Notes: Post [3], Confirmed; Loyola mirror preface [3], Reported; memoir via review [11], Reported. Charge summaries [1][2][7][8][9]; the conclusion is Inferred.

## PART 5 | The Art of Intrusion: one documented thread, one likely match

| Chapter | Primary record found | Grade |
|---|---|---|
| 1, Hacking the Casinos | None; participants anonymous | Reported |
| 2, When Terrorists Come Calling | DOJ 00-555, by inference only | Inferred match |
| 3, The Texas Prison Hack | None; prison unnamed | Reported |
| 5, The Robin Hood Hacker | DOJ plea release, 2004 | Confirmed |
| 10, Social Engineers | Index only; a method chapter | Reported |
Caption: Lamo admitted reaching the Times' database of more than 3,000 Op-Ed contributors in 2002.
Notes: Part 5. DOJ 00-555 records a 16-year-old from Miami and NASA and DTRA intrusions [22]; the match to the book is Inferred. Lamo [23], Confirmed. Lockheed Martin and Boeing claims [21] have no primary record found.

## PART 6 | Losses were never settled, and release terms became the fight

Left: Restitution
- Victim letters: nearly $300 million.
- Prosecutors sought about $1.5 million.
- Court ordered just over $4,125.
- Both of his loss challenges rejected.
Right: Supervised release
- No computers or cellular phones.
- No computer-industry work.
- Each needs probation approval.
- Upheld by the Ninth Circuit in 1998.
Caption: No source opened says the case changed 18 U.S.C. 1030; its clearest legal legacy is the 1998 release ruling.
Notes: Victim letters via Wired [8] and the $1.5 million figure [29], Reported. Order and rejected claims [1]. Ninth Circuit memorandum [2], which rejected First Amendment, vagueness and delegation challenges. Statute [34]. The legacy reading is Inferred.

## MITRE MAPPINGS | 24 ATT&CK techniques, scored by the strength of the record

| Id | Technique | Where |
|---|---|---|
| T1684.001 | Impersonation | Plea, testimony, AA23-320A |
| T1598.004 | Spearphishing Voice | Testimony, AA23-320A |
| T1591.004 | Identify Roles | Testimony |
| T1040 | Network Sniffing | Plea; DOJ 00-555 |
| T1499.001 | OS Exhaustion Flood | 1994 SYN flood |
| T1563 | Remote Service Session Hijacking | 1994 hijack |
| T1621 | Multi-Factor Authentication Request Generation | AA23-320A |
Caption: ATT&CK v20.0 layer scores: 100 plea or testimony, 75 the 1994 intrusion, 50 DOJ-backed stories, 25 modern only.
Notes: Part 8. T1656 was revoked in v19.0 and maps to T1684.001 through data/attack/superseded_by.jsonl [26][35]. Comparison object G1015 Scattered Spider [35][24]. CAPEC-407, CAPEC-410, CAPEC-413 and CAPEC-593 [35]. Not an official MITRE mapping. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The pretext call now buys a whole single sign-on identity

- **AA23-320A (2023):** Scattered Spider poses as employees to help desks to reset passwords and move MFA.
- **HC3 (2024):** callers with partial SSNs and corporate IDs got new MFA devices enrolled.
- **Then they diverted** payer ACH payments in the health sector.
- **The payoff grew:** one modem number in the 1990s, every SSO application today.
Caption: Help desk and ALPHV records for hospitals are in the Healthcare Threat Actor Watchlist study.
Notes: CISA and FBI AA23-320A [24] and the HHS HC3 analyst note [25], Confirmed. The same-move reading and the payoff comparison with his testimony [5] are Inferred.

## DEFENDER VIEW | A help desk checklist built from both eras

Left: Verify the caller
- Use a factor no call can supply.
- Treat partial SSNs and IDs as public.
- Do not trust a bare callback.
- Prefer phishing-resistant MFA.
Right: Watch what follows
- Alert on new MFA device enrollment.
- Hold changes after a help desk reset.
- Monitor ACH and payment routing.
- Run phone-based exercises.
Notes: In-person and supervisor checks and ACH monitoring [25]; FIDO/WebAuthn or PKI MFA [24]; callback weakness [5], Confirmed as testimony; SIM swap link [24], Inferred. The enrollment alert and hold period are Inferred from [25].

## CROSS-CUTTING THEMES | People were the vulnerability, and memoir is not evidence

- **People then and now:** the plea leads with social engineering; the advisories show the same play.
- **Verification channels are attack surface:** callbacks then, SIM swaps now.
- **Loss numbers are claims:** nearly $300 million claimed, about $4,125 ordered.
- **Overstated:** the 1994 attack as his crime, the case as the origin of computer crime law, the losses.
- **Understated:** how little technical skill the core method needed, and the codefendant's plea.
Notes: Cross-cutting themes and the overstated and understated passage [1][3][5][8][11][24][25][34]. The overstated and understated reading is the study's own judgment, graded Inferred.
