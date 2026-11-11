# Slide plan: Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown

- Study: case-studies/CYBERCRIME_FOUR_BOOKS.md
- Cover title: Cybercrime and Hacktivism / in Four Books
- Subtitle: Kingpin, Fatal System Error, We Are Anonymous and The Hacker Crackdown, rebuilt from the court and government record
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CYBERCRIME_FOUR_BOOKS.md. Only The Hacker Crackdown was read directly, in the free Project Gutenberg edition [41]; the other three books are known here through Poulsen's Wired feature [7], publisher pages and reviews [10][11][12][13][16]. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Four books, thirty years, and a record that mostly holds up

- **Four books, 1984 to 2014:** carding markets, DDoS extortion, Anonymous and LulzSec, and the 1990 crackdown.
- **Rebuilt from primaries:** DOJ and Secret Service releases, indictments, court opinions, an SEC filing and AT&T's report.
- **The books hold up on events,** but several numbers appear in two or three versions.
- **The technical lessons are old:** SQL injection, fast hashes, password reuse and one over-privileged admin.
- **Investigators won from the inside:** informants, financial trails and court-authorized intercepts.
Caption: Grades: indictments, pleas, sentences, rulings and AT&T's report Confirmed; book-only claims Reported; mappings Inferred.
Notes: Executive summary and key findings. Butler totals [5][6]; E911 valuations [41][42][49]; Sundevil city counts [41][44]; EFF founding date [41][48]. HBGary chain from Ars Technica [29], Reported; Monsegur's cooperation from the government memorandum [25], Confirmed; the Shadowcrew informant from Poulsen [7], Reported. The informant pattern is the study's inference.

## KEY FACTS | 1.8 million cards, a 13-year sentence and 300 hacks prevented

Stat: 13 years | Butler's sentence, 12 February 2010
Stat: $86.4M | fraud on Butler's cards, per the card brands
Stat: 300+ | hacks disrupted or prevented, per the FBI
Stat: ~860,000 | Stratfor subscriber or client accounts taken
- Shadowcrew: about 4,000 members and at least 1.7 million stolen card numbers.
- Russian bookmaker gang: eight years each; up to $4 million taken from UK firms.
- The EFF was founded in 1990 in response to the Steve Jackson Games raid.
Notes: Butler's sentence, the 1.8 million card numbers and the $86.4 million [5]. Monsegur estimate [25]. Stratfor [24]. Shadowcrew [1]. Bookmaker gang [14], Reported. EFF [48]. Part 7 maps 19 Enterprise techniques; no ATT&CK group, software or campaign object names these actors [54].

## PART 1 | Shadowcrew fell to intercepts and, Poulsen says, an inside man

- **28 October 2004:** a 62-count indictment of 19 people who ran the Shadowcrew site.
- **The market:** about 4,000 members, 1.7 million card numbers, losses over $4 million.
- **Operation Firewall:** begun July 2003, intercepts from early 2004, 28 arrests in eight states and six countries.
- **How it ran:** vetted vendors, drop addresses, and payment by Western Union, E-Gold and Web Money.
- **Poulsen's inside story:** an administrator ran a VPN he could watch, and was exposed as an informant.
Caption: Butler, logging in as Iceman, distrusted the VPN offer and escaped the arrests, per Poulsen (Reported).
Notes: DOJ release of 28 October 2004 [1] and the Secret Service release of the same day [2], Confirmed. Plea release of 17 November 2005 for the market's workings [3], Confirmed. The "Cumbajohny" VPN and Butler's escape from Poulsen's Wired feature [7], Reported.

## PART 1 | Max Butler went from a BIND worm to a 13-year sentence

| Date | Event | Grade |
|---|---|---|
| Jun 1998 | A worm patches BIND and leaves a back door on military and contractor computers | Reported |
| 21 May 2001 | Sentenced to 18 months as Max Vision | Reported |
| Aug 2006 | Takes over rival carding forums and folds them into CardersMarket | Reported |
| 29 Sep 2006 | Capital One lure: about 125 of 500 employees click | Reported |
| 5 Sep 2007 | Arrested by the Secret Service in San Francisco | Confirmed |
| 12 Feb 2010 | 13 years and $27.5 million in restitution | Confirmed |
Caption: Prosecutors called 13 years believed to be the longest to date in the US for a computer hacker, a claim of the time.
Notes: The Register on the 1998 worm and 2001 sentence [8]. Poulsen on the forum takeover and the Capital One lure [7]. Arrest and indictment [4][5]. Sentence and restitution [5]. The lure domain shared a registration account with CardersMarket.com, which pointed investigators at Iceman [7], Reported.

## PART 1 | The fraud totals do not agree, even inside the Justice Department

| Item | Version A | Version B |
|---|---|---|
| Fraud on Butler's cards | About $86.4 million (12 Feb 2010) | More than $87 million, 10,000+ banks (8 Dec 2010) |
| Shadowcrew losses | Over $4 million (DOJ) | Exceeded $4.3 million (Secret Service) |
| Firewall arrests | 21 in the US plus several abroad (DOJ) | 28 in eight states and six countries (Secret Service) |
| CardersMarket size | About 4,500 members at peak (court record) | About 6,000 users after the takeover (Poulsen) |
Caption: Both Butler totals are Confirmed; the later release may round up or add later reports (Inferred). Prefer the court figure.
Notes: Discrepancies table in Part 1: [5] against [6]; [1] against [2]; [5] against [7]. The restitution of $27.5 million was also described as the largest in a computer crime case [6], the prosecutors' own superlative.

## PART 2 | DDoS extortion was a business by 2003, and so was the defense

Left: The bookmaker extortion
- Botnets built in 2003 and 2004 hit UK and Irish gambling firms; payment went to Latvian accounts.
- Up to $4 million taken; 54 attacks in 30 countries in about six months.
- Canbet refused a $10,000 demand and lost over $200,000 a day offline.
- Riga arrests in November 2003 led along the money trail; a Russian court gave three men eight years.
Right: Prolexic and the RBN
- Lyon's Prolexic was one of the first DDoS protection firms.
- Akamai bought it on 18 February 2014: about $337.1 million plus $50.4 million in escrow.
- The RBN sold bulletproof hosting; Kaspersky told Menn he doubted state attacks on Georgia.
- This study does not adopt the RBN attribution.
Caption: In the US, the FBI calls Operation Cyberslam, begun in 2003, the first successful large-scale commercial DDoS investigation.
Notes: Bookmaker case from Out-Law [14], Virus Bulletin [21] and The Register [22], all Reported; no court record was opened. Prolexic per Howard's review [16], Reported; sale per Akamai's Form 8-K [17], Confirmed. RBN from Krebs [18] and Network World [13], Reported. Cyberslam [19], Confirmed.

## PART 3 | Payback's floods moved from anti-piracy targets to PayPal

- **September 2010:** Anonymous hits Aiplex, the MPAA, the RIAA, the BPI and ACS:Law (Reported).
- **December 2010 to June 2011:** claimed DDoS on Visa, MasterCard and PayPal over WikiLeaks donations.
- **6 to 10 December 2010:** "Operation Avenge Assange" floods PayPal with a free open source tool.
- **19 July 2011:** 16 arrests; 14 charged in San Jose; more than 35 search warrants.
- **December 2013:** 13 PayPal defendants plead guilty, three to misdemeanors only (Reported).
Caption: The Register named the tool as LOIC; its flood mode is not recorded, so the mapping stops at T1498.
Notes: Operation Payback per The Next Web [23], Reported. Payment-processor attacks [24][37] and Monsegur's admission [25], Confirmed. FBI release on the PayPal case [36], Confirmed. LOIC [26] and the pleas [27], Reported. A separate 3 October 2013 indictment of 13 over Operation Payback [28], Reported.

## PART 3 | HBGary Federal fell to a chain of ordinary failures

| Step | What happened |
|---|---|
| 1 | SQL injection in the hbgaryfederal.com CMS yields unsalted MD5 hashes |
| 2 | Simple passwords of the CEO and COO cracked with rainbow tables |
| 3 | The same passwords reused on e-mail, Twitter and LinkedIn |
| 4 | ssh on support.hbgary.com, then a privilege escalation flaw |
| 5 | The CEO's account was the Google Apps mail administrator |
| 6 | From a real colleague's mailbox, the rootkit.com admin opens ssh |
| 7 | E-mails published, site defaced, rootkit.com users posted |
Caption: The chain is Ars Technica's reconstruction (Reported); Monsegur's part in the hack is Confirmed by the government.
Notes: Chain from Ars Technica [29], Reported. Internet Feds, active December 2010 to May 2011, hacked HBGary Inc. and HBGary Federal, with data on about 80,000 user accounts across its targets [24][37], Confirmed. Monsegur directly participated [25], Confirmed.

## PART 3 | One informant took LulzSec apart, and the courts followed

Stat: ~7 Jun 2011 | FBI approaches Monsegur; he cooperates that night
Stat: 8 | major co-conspirators convicted with his help
Stat: 259 to 317 | months, his Guidelines range
- **LulzSec** formed about May 2011; its spree lasted 50 days that summer.
- **Southwark, 16 May 2013:** Cleary 32 months, Ackroyd 30, Davis 24, Al-Bassam suspended.
- **Jeremy Hammond,** who hacked Stratfor with AntiSec, drew 10 years on 15 November 2013.
- **Monsegur,** 27 May 2014: time served; the judge called his cooperation "truly extraordinary".
Notes: Government sentencing memorandum [25], Confirmed: cooperation, the eight co-conspirators, the Guidelines range and the UK sentences. Spree length [35], Reported. Stratfor and the charges [24]. Hammond [33]. Monsegur's sentence [34], Confirmed; [38], Reported.

## PART 4 | The 1990 crash that framed the crackdown was AT&T's own bug

- **15 January 1990, about 2:30 p.m. EST:** a New York 4ESS switch enters routine fault recovery.
- **The flaw:** a mid-December 1989 update to all 4ESS switches let the failure cascade.
- **Cleared at 11:30 p.m.;** the next day AT&T pulled the update and reproduced the flaw in the lab.
- **Sterling's scale:** 60,000 people lost service and some 70 million calls failed (Reported).
- **At first widely suspected** to be hackers, which shaped the year that followed (Reported).
Caption: Not mapped to ATT&CK: it was a software defect, not an attack.
Notes: AT&T's incident report as reprinted in RISKS Digest 9.63 [39], Confirmed. Larry Seese on all 114 4ESS systems, as quoted in RISKS 9.62 [40], Confirmed. Sterling's figures, the break statement and the suspicion [41], Reported.

## PART 4 | The E911 document's value fell from $79,449 to $13

| Valuation | Who and where | Grade |
|---|---|---|
| $79,449 | BellSouth security to the Chicago task force, per Sterling | Reported |
| $24,639.05 | BellSouth Security, in the Atlanta sentencing memorandum | Confirmed |
| $23,900 | The government's value at the Neidorf trial, per Denning | Reported |
| $13 | A more detailed published version, per the defense | Reported |
- **Neidorf's trial** began 23 July 1990 and ended in a mistrial on 27 July, when the prosecution moved to dismiss.
- **The Atlanta Three** drew 21 and 14 months on 16 November 1990, with about $233,000 restitution each.
Notes: Valuations [41][42][49]. Neidorf trial and mistrial [41][49], Reported; his legal fees over $100,000 and the 1991 expungement [41], Reported. Atlanta sentences [42], Confirmed, from the CuD 2.16 reprint.

## PART 4 | Sundevil and the Steve Jackson Games raid produced lasting law

Left: Operation Sundevil, May 1990
- About 27 warrants on 7 and 8 May.
- 150 Secret Service agents.
- 13 warrant cities in the release.
- Sterling counts 12; Jenkins about 15.
Right: Steve Jackson Games, 1990 to 1994
- Searched 1 March 1990; board seized.
- 162 unread e-mails read and deleted.
- 1993: PPA and SCA violations found.
- 1994: stored e-mail is not intercepted.
Caption: The EFF says it was founded in July 1990 in response to the raid; Sterling dates the founding to June.
Notes: Sundevil release of 9 May 1990 as reprinted [44], Confirmed; Sterling's count [41], Reported; Jenkins' remarks [44], Confirmed as a reprint. District court, 12 March 1993 [45]; Fifth Circuit, 31 October 1994 [46][50], Confirmed. EFF [48], Confirmed; Sterling [41], Reported.

## MITRE MAPPINGS | 19 retrospective techniques, and no ATT&CK object for any actor

| Id | Technique | Where it appears |
|---|---|---|
| T1190 | Exploit Public-Facing Application | PBS, HBGary CMS, Sony Pictures claim |
| T1078 | Valid Accounts | BellSouth logins, Tribune, HBGary |
| T1110.002 | Password Cracking | HBGary hashes and rainbow tables |
| T1040 | Network Sniffing | Point-of-sale sniffers, 2005 to 2007 |
| T1498 | Network Denial of Service | Bookmakers, Cyberslam, PayPal |
| T1491.002 | External Defacement | PBS, HBGary, Internet Feds |
| T1657 | Financial Theft | Butler, bookmakers, Stratfor |
Caption: Layer scores: 100 primary record and direct fit, 75 book or press only, 40 analogies and weak fits.
Notes: Part 7. Every mapping is the study's own reading (Inferred), checked against the library's technique pages and data at main cb085a91 [51][53][54]. CWE-89 and CWE-916; CAPEC-66 and CAPEC-125; D3FEND from the library's data [52][54]. No group, software or campaign object names Anonymous, LulzSec, AntiSec, Shadowcrew, CardersMarket, Agobot or LOIC [54]. Not an official MITRE mapping. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Decide on DDoS before the flood, and break the HBGary chain

Left: Availability attacks
- Contract upstream mitigation and test the failover first.
- Write the no-pay policy down, with legal and police contacts.
- Report extortion demands: the case was solved by following payments.
- Watch point-of-sale terminals and segment them.
Right: The HBGary chain
- Parameterized queries (CWE-89).
- Slow, salted password hashes (CWE-916).
- Unique passwords and multi-factor login.
- Separate, protected admin identities.
- Verify any access request out of band.
Caption: Legal teams: get a scope review before imaging or seizing a server that holds other people's messages.
Notes: Part 6 and the top recommendations. DDoS lessons Inferred from [14][21][22][36]. The HBGary chain control by control: Reported for the chain [29], Inferred for the controls. Card fraud at the merchant edge [4][5][7]. The Steve Jackson Games lesson from [45][50], Inferred for the advice.

## CROSS-CUTTING THEMES | Administrators get turned, and numbers move in the retelling

- **Markets are run by administrators,** and administrators can be turned: Shadowcrew, CardersMarket, LulzSec.
- **Motive changes, mechanics do not:** extortion and protest floods used the same techniques.
- **Numbers move:** E911 from $79,449 to $13; Sony Pictures from a million accounts to about 100,000.
- **Officials overreach** when they do not check the material or the law.
- **Overstated:** the AT&T crash as a hack. **Understated:** the 300 hacks the informant case prevented.
Notes: Cross-cutting themes and the overstated and understated passage [7][24][25][31][39][41][45][46][48][49]. The patterns are the study's own reading, graded Inferred.
