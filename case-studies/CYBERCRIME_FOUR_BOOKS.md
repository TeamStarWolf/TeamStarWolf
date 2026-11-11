# Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown

*A TeamStarWolf case study. Published 3 November 2026; sources checked on that date, with source 25 reopened and the library data in source 54 rechecked on 11 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md), [Threat Actors](/THREAT_ACTORS.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md) · Related studies: [The Cuckoo's Egg Intrusion, 1986](/case-studies/CUCKOOS_EGG_1986.md), [The Zero-Day Trade and Its Fallout](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, incident responders, investigators and anyone who has read Kingpin, Fatal System Error, We Are Anonymous or The Hacker Crackdown and wants the primary record behind them

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 52 min (11,920 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the carding markets, DDoS extortion, Anonymous and LulzSec, or the 1990 crackdown as the court and government record tells them, you need to know which numbers in the books differ from the record, or you want the defender lessons on DDoS extortion, the HBGary chain and card fraud at the merchant edge

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 5: the combined timeline](#part-5-the-combined-timeline), [Part 6: the defender view](#part-6-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md), [Threat Actors](/THREAT_ACTORS.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Four books on the library's reading list tell the story of the criminal and activist internet before ransomware and state espionage took over the headlines. Bruce Sterling's *The Hacker Crackdown* covers the 1990 collision between phone phreaks, the Secret Service and a young civil liberties movement. Joseph Menn's *Fatal System Error* follows a network engineer, Barrett Lyon, and a British detective chasing a Russian gang that extorted online bookmakers with floods of traffic. Kevin Poulsen's *Kingpin* is the story of Max Butler, a security researcher who co-founded CardersMarket, a carding forum that peaked at about 4,500 members. *We Are Anonymous* (Parmy Olson) is an account of Anonymous and LulzSec in 2010 and 2011. Together they cover about 30 years, from the Legion of Doom in 1984 to Hector Monsegur's sentencing in 2014.

The books are secondary sources, and this study treats them that way. Almost every event they describe left a primary record: Department of Justice and Secret Service press releases, an indictment, a government sentencing memorandum, a district court opinion, a Fifth Circuit opinion, an SEC filing and AT&T's own incident report. This study rebuilds each story from that record first, and grades a claim Reported, attributed to the book or the press outlet by name, only where the record is silent. The result largely supports the books on what happened and corrects them on several numbers. The Butler fraud total, the value of the BellSouth E911 document, the count of Operation Sundevil cities and the date of the Electronic Frontier Foundation's founding each appear in two or three different versions, and this study sets them side by side.

The technical lessons are older than most defenders realize. The 2011 HBGary Federal breach ran on a SQL injection, fast unsalted password hashes, password reuse and one over-privileged mail administrator account. The bookmaker extortion and Operation Payback used the same flooding mechanics for opposite motives. Where investigators won, they used informants, financial trails and court-authorized intercepts. The government credits an informant with taking LulzSec apart (Confirmed), and Poulsen reports the same of a Shadowcrew administrator (Reported) (Inferred as a pattern).

Evidence grade: the indictments, pleas, sentences, court findings and incident report are **Confirmed** from primary documents opened on 3 November 2026. Anything that rests only on a book, a book's precursor article or a news report is **Reported**. The ATT&CK mappings and the defender lessons are this study's reasoning, labelled **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Books | *Kingpin*, Kevin Poulsen (Crown, ISBN 978-0-307-58868-5) [10]; *Fatal System Error*, Joseph Menn (PublicAffairs; 2010 in the library's list) [12][54]; *We Are Anonymous*, Parmy Olson (2012 in the library's list; the book's own pages were not opened) [54]; *The Hacker Crackdown*, Bruce Sterling (1992 in the library's list; consulted in the free Project Gutenberg edition, eBook #101) [41][54] |
| Span of events | 1984 (Legion of Doom formed, per Sterling) to 27 May 2014 (Monsegur sentenced) [41][34] |
| Largest criminal market | Shadowcrew: about 4,000 members, at least 1.7 million stolen card numbers [1] |
| Largest single fraud total | Butler's computers held over 1.8 million card numbers; the card brands reported about $86.4 million in fraud on them [5] |
| Longest sentence | Butler, 13 years (12 February 2010), described by prosecutors at the time as believed to be the longest to date in the US for a computer hacker [5] |
| Hacktivist record | LulzSec formed about May 2011; Monsegur cooperated from about 7 June 2011; FBI estimate of at least 300 hacks disrupted or prevented [25] |
| Largest hacktivist data theft | Stratfor, December 2011: account data for about 860,000 subscribers or clients and card data for about 60,000 users [24] |
| Extortion DDoS | Russian gang sentenced to eight years each; prosecutors put the take at up to $4 million from UK bookmakers and casinos [14] |
| Landmark rulings | *Steve Jackson Games v. US Secret Service*: Privacy Protection Act and Stored Communications Act violations (12 March 1993); stored, unread e-mail is not "intercepted" under the Wiretap Act (Fifth Circuit, 31 October 1994) [45][46] |
| Institutional legacy | The Electronic Frontier Foundation, founded in 1990 in response to the Steve Jackson Games raid [48] |
| MITRE | 19 Enterprise techniques mapped; no group, software or campaign page in the library names these actors (Part 7) |

### Key findings

- **The carding underground was broken from the inside, Poulsen reports.** The Secret Service's Operation Firewall ran from July 2003, used court-authorized intercepts from early 2004 and produced 28 arrests in eight US states and six countries, announced on 28 October 2004 (Confirmed [2]). Poulsen reports that a Shadowcrew administrator steered members onto a private VPN he could watch and was exposed as an informant when the arrests came (Reported, Poulsen in Wired [7]).
- **Kingpin's subject was a hacker before he was a thief.** Max Butler was sentenced in 2001 for a 1998 worm that patched a BIND hole and left a back door on hundreds of military and defense contractor computers (Reported [8]). He went on to run CardersMarket, which peaked at about 4,500 members, and drew 13 years and $27.5 million in restitution (Confirmed [5]).
- **The fraud totals do not agree.** The sentencing release gives about $86.4 million in fraud on Butler's cards; a December 2010 Justice Department release says more than $87 million and more than 10,000 US banks (Confirmed, both [5][6]). Shadowcrew's losses are "over $4 million" in the DOJ release and "exceeded $4.3 million" in the Secret Service release (Confirmed [1][2]).
- **DDoS extortion was a business by 2003.** Prosecutors counted 54 similar attacks in 30 countries over about six months, and a Russian court gave three men eight years each (Reported [14]). The FBI called Operation Cyberslam, begun in 2003, the first successful US investigation of a large-scale commercial DDoS (Confirmed [19]).
- **The HBGary breach was a chain of ordinary failures.** SQL injection in the hbgaryfederal.com CMS, unsalted MD5 hashes, password reuse across services, a privilege escalation flaw on a support server and a Google Apps administrator account turned one bad web form into the loss of the company's mail (Reported, Ars Technica [29]). Monsegur's participation is Confirmed by the government's memorandum [25].
- **The government credits one informant with taking LulzSec apart.** Monsegur agreed to cooperate the night the FBI approached him, induced co-conspirators to hand over logs that were later found on their seized computers, and, the government said, contributed to the convictions of eight major co-conspirators including Jeremy Hammond (Confirmed [25]). Judge Preska called his cooperation "truly extraordinary" and sentenced him to time served (Confirmed [34]).
- **The 1990 crash that framed the crackdown was AT&T's own bug.** A mid-December 1989 software update to all 4ESS switches let a flaw cascade across the network on 15 January 1990 (Confirmed, AT&T report [39]). Sterling writes that the outage was at first widely suspected to be hacker action and shaped the year that followed (Reported [41]).
- **The government lost two of the cases that defined the era.** Craig Neidorf's prosecution over the E911 document collapsed mid-trial on 27 July 1990 after the defense showed that more detailed material was on sale for $13 (Reported, Sterling and Denning [41][49]). A federal court later held the Secret Service liable for its seizure at Steve Jackson Games (Confirmed [45][46]).

### Top recommendations

1. **Arrange DDoS mitigation before you need it, and decide in advance not to pay.** The extortion gangs and the protest floods used the same mechanics; upstream scrubbing capacity and a written no-pay policy are the controls this study draws from both stories (Inferred, from [14][21][36]).
2. **Treat injectable forms and fast hashes as breach precursors.** Use parameterized queries (CWE-89) and slow, salted password hashing (CWE-916); HBGary Federal had neither (Reported [29]; Inferred for the control).
3. **Kill password reuse and over-broad mail administrator rights.** Two cracked passwords, reused everywhere, opened e-mail, social media, a support server and the mail administrator account at HBGary (Reported [29]). Require multi-factor authentication and separate administrator identities (Inferred).
4. **Verify credential requests out of band.** The rootkit.com administrator opened access because an e-mail came from a trusted colleague's real mailbox (Reported [29]). A phone call to a known number would have stopped it (Inferred).
5. **Watch point-of-sale and card processing paths for sniffers.** Butler's card supply came from sniffers on small merchants' terminals and from intrusions at processors (Reported [7]; Confirmed as alleged in the indictment [4] and as stated at sentencing [5]).
6. **For investigators and counsel: know the statutes that govern seized data.** The Secret Service lost on the Privacy Protection Act, because its agent did not know the Act and the agency kept the publisher's materials after it was on notice, and on the Stored Communications Act, because it seized the board's stored e-mail (Confirmed [45]). Evidence handling for any system that stores other people's communications needs a legal check before the warrant (Inferred).

## Scope and method

This study covers the events at the centre of four books on the library's [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md). It follows the library's [case study method](/case-studies/README.md): primary sources first, an evidence grade on every claim, numbers as the source states them, and hype kept apart from evidence. The book text was consulted only for *The Hacker Crackdown*, which its author released as a free electronic text [41]. For *Kingpin*, Poulsen's December 2008 Wired feature on Butler, the reporting that preceded the book, stands in for book-only claims [7]; for *Fatal System Error*, the publisher's description and two reviews do [12][13][16]; for *We Are Anonymous*, every claim in this study rests on the court record or contemporary press, not on the book.

Every source in the Sources table was opened on 3 November 2026; source 25 was reopened and the library data in source 54 rechecked on 11 November 2026. Some primaries were read as faithful reprints: AT&T's incident report as reprinted in RISKS Digest 9.63, the Atlanta sentencing memorandum and the Operation Sundevil press release as reprinted in Computer Underground Digest, the Steve Jackson Games opinions as reproduced on the company's own site, and the Monsegur sentencing memorandum as a PDF hosted by SecurityWeek. They are graded Confirmed with that caveat noted.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary document that was opened: an indictment, plea or sentencing release, a court opinion, a government memorandum, an SEC filing, or the victim's own incident report |
| Reported | Stated only by a book, a book's precursor article, a publisher's description, a review or a news report; attributed to it by name |
| Demonstrated | A public reproduction exists. No claim in this study carries this grade |
| Inferred | This study's own reasoning, including every ATT&CK, CWE, CAPEC and D3FEND mapping, labelled as such |

Quotations are kept under 15 words. Where two studies in this run cover the same event, the home study is named: this study is the home for Shadowcrew and Operation Firewall (Part 1); Part 2 summarizes them in one paragraph and links back.

## Part 1: Kingpin (Max Butler, Shadowcrew and CardersMarket)

### The book

*Kingpin* is Kevin Poulsen's account of Max Ray Butler, published by Crown (ISBN 978-0-307-58868-5); Publishers Weekly, reviewing it on 20 December 2010, says it draws on extensive interviews with Butler (Confirmed for the bibliographic record [10]). The publisher describes a white-hat persona, "Max Vision", that included FBI consulting, a habit of hacking fellow fraudsters to take their gains, and fraud methods that included browser exploits, phishing and Trojans (Reported, Penguin Random House [11]). Poulsen's December 2008 Wired feature on Butler was the reporting that preceded the book, and this study uses it for the book's account [7].

### Shadowcrew and Operation Firewall

Shadowcrew was the market Butler's story starts beside. On 28 October 2004 the Justice Department announced that a Newark federal grand jury had returned a 62-count indictment, one conspiracy count plus 61 others, against 19 people who ran the Shadowcrew site (Confirmed [1]). The release named the administrators as Andrew Mantovani of Scottsdale, Arizona, David Appleyard of Linwood, New Jersey, and Anatoly Tyukanov of Moscow (Confirmed [1]). Shadowcrew had about 4,000 members and trafficked at least 1.7 million stolen card numbers along with counterfeit identity documents, with losses over $4 million; 21 people were arrested in the US on criminal complaints and several more abroad (Confirmed [1]).

The Secret Service's release of the same day put the operation's arrests at 28 in eight US states and six foreign countries, under the name Operation Firewall, and named three targets: Shadowcrew, Carderplanet and Darkprofits (Confirmed [2]). Firewall began in July 2003 as an access device fraud probe, court-authorized intercepts began in early 2004, about two terabytes of information were gathered, and losses exceeded $4.3 million (Confirmed [2]). The foreign partners included the UK National Hi-Tech Crime Unit, the Royal Canadian Mounted Police, the Vancouver Police, Europol and police in Belarus, Poland, Sweden, the Netherlands, Ukraine and Bulgaria (Confirmed [2]).

By 17 November 2005 six Shadowcrew defendants including Mantovani had pleaded guilty, and 12 of the 21 US arrestees had pleaded guilty by then (Confirmed [3]). Mantovani admitted using phishing and spamming to steal card data and acquiring about 18 million e-mail accounts (Confirmed [3]). The plea release also describes how the market ran: vendors were vetted by administrators or moderators, goods went to drop addresses, and payments ran through Western Union, E-Gold and Web Money (Confirmed [3]).

Poulsen's account adds the inside story. He reports that a Shadowcrew administrator using the handle "Cumbajohny" steered members to an invitation-only VPN that let him watch them, and was exposed as an informant when Firewall struck (Reported, Poulsen [7]). Butler, who logged in to Shadowcrew as Iceman, grew suspicious of the VPN offer, kept his distance and escaped the arrests (Reported, Poulsen [7]).

### Max Vision, 1998 to 2001

Before Iceman there was Max Vision. On 21 May 2001 Judge James Ware sentenced Butler, then using the name Max Vision, to 18 months in prison, $60,000 in restitution and three years of supervised release for a June 1998 worm that closed a hole in BIND but left a back door on hundreds of military and defense contractor computers (Reported, The Register [8]). The Register reported that Butler had briefly worked as an undercover FBI informant before the sentencing and that the judge gave him no credit for it (Reported [8]).

### CardersMarket and the takeover

The Pittsburgh indictment alleged that from about June 2005 Butler hacked systems at financial institutions and card processing centers and sold the card data, including sales to a buyer in the Western District of Pennsylvania on or about 14 October 2006 and 6 December 2006 (Confirmed [4]). It alleged he created CardersMarket as a haven for carding with thousands of members worldwide, and used it to recruit helpers (Confirmed [4]). The 2010 sentencing release fills in the partnership: Butler and Christopher Aragon of the Los Angeles area created CardersMarket, Aragon's crew used the cards to buy merchandise, Butler sold the rest, and at its peak the site had about 4,500 members (Confirmed [5]).

Poulsen describes how CardersMarket grew. In August 2006, over about two days, Butler broke into rival carding forums by SQL injection or a hacked password, copied their member data, wiped their databases and folded their members into CardersMarket, which reached about 6,000 users (Reported, Poulsen [7]). The exact list of four forums appears only in secondary summaries and is left out here. Poulsen also reports that Butler sold under the names Digits and Darkest, planted sniffers on point-of-sale terminals at small restaurants and retailers, and published card price lists (Reported [7]).

Butler also turned his skills on law enforcement. Poulsen reports that an FBI agent using the handle "Master Splynter" held an administrator role on the rival DarkMarket forum ahead of a planned sting, and that Iceman traced the agent's IP address to the offices of the National Cyber-Forensics and Training Alliance (NCFTA) and warned the underground (Reported, Poulsen [7]).

### How he was found

Poulsen's account of the investigation turns on three threads (all Reported, Poulsen [7]):

- **A lure that pointed home.** On 29 September 2006 about 500 Capital One employees received a lure e-mail from a fake reporter; about 125 clicked and received a hidden payload. The lure domain shared a registration account with CardersMarket.com, which pointed the FBI and NCFTA at Iceman.
- **An informant and a partner.** CardersMarket administrator "Zebra" was convicted after Secret Service informant "Gollumfun", Brett Shannon Johnson, bought from him; Zebra then named Iceman's San Francisco base and his partner Aragon (the date given is 8 March 2007). Local police arrested Aragon at a Bloomingdale's on 12 May 2007, and seven more arrests followed from his records.
- **Surveillance.** From 7 June 2007 the Secret Service watched Butler move into a corporate-apartment safe house in San Francisco; investigators believed he used his neighbours' Wi-Fi.

The record confirms the end. Butler was arrested by the Secret Service in San Francisco on a Pittsburgh criminal complaint on 5 September 2007 (Confirmed [4][5]). On 11 September 2007 a Pittsburgh grand jury returned a five-count wire fraud and identity theft indictment against Max Ray Butler, 35, of San Francisco, alias Iceman, with a maximum exposure on all counts of 70 years and $1.5 million (Confirmed [4]).

### Plea, sentence and the numbers

Butler pleaded guilty on 30 June 2009 to two wire fraud counts; the plea agreement was sealed and the remaining counts were left for sentencing (Reported, The Register [9]). On 12 February 2010 Senior US District Judge Maurice B. Cohill in Pittsburgh sentenced him to 13 years in prison, five years of supervised release and $27.5 million in restitution (Confirmed [5]). A search of the computers in his apartment found over 1.8 million stolen card numbers, and the card brands reported about $86.4 million in fraud on those cards, borne by the issuing banks (Confirmed [5]). The US Attorney's Office said the 13-year term was believed to be the longest to date in the US for a computer hacker, a claim of the time rather than a settled record (Confirmed that it was said [5]). The Secret Service led the investigation, assisted by the Justice Department's Computer Crime and Intellectual Property Section, the FBI, the Vancouver Police Department, the Newport Beach Police Department and the Orange County Sheriff, with the Northern District of California assisting the arrest (Confirmed [5]).

### Discrepancies in the Kingpin record

| Item | Version A | Version B | Reading |
|---|---|---|---|
| Fraud on Butler's cards | About $86.4 million (sentencing release, 12 Feb 2010) [5] | More than $87 million, more than 10,000 US banks (DOJ release, 8 Dec 2010) [6] | Both Confirmed; the later release may round up or add later reports (Inferred) |
| Restitution | $27.5 million [5] | Described as the largest restitution award in a computer crime case [6] | Same figure; the superlative is the prosecutors' own |
| Shadowcrew losses | Over $4 million (DOJ) [1] | Exceeded $4.3 million (Secret Service) [2] | Consistent; DOJ rounds down |
| Firewall arrests | 21 in the US plus several abroad (DOJ) [1] | 28 in eight states and six countries (Secret Service) [2] | The Secret Service count includes the foreign arrests (Inferred) |
| CardersMarket size | About 4,500 members at peak [5] | About 6,000 users after the takeover (Poulsen) [7] | Confirmed figure preferred |

## Part 2: Fatal System Error (DDoS extortion and the Russian connection)

### The book

*Fatal System Error* by Joseph Menn was published by PublicAffairs; the paperback listing went on sale on 26 October 2010 (Reported, publisher [12]). The publisher's description says that in 2004 Barrett Lyon traced a hacker attacking business websites to the Russian mob, and that London's National Hi-Tech Crime Unit recruited Lyon and sent detective Andrew Crocker to Russia (Reported [12]). Lyon and Crocker are the book's central figures, and the capture of Ivan Maksakov, Alexander Petrov and Denis Stepanov is its main thread (Reported, Wikipedia [15]). A Network World review published when the hardcover came out says the book follows DDoS extortion of online gambling firms, the Russian arrest of Maksakov, a British investigator working with Russian police, and the Russian Business Network (Reported [13]).

### The bookmaker extortion

The gang's method was simple and profitable. Botnets built in 2003 and 2004 and controlled from Russia via the US launched demonstration attacks on UK and Irish online gambling firms, and the gang demanded payment to Latvian accounts (Reported, Virus Bulletin [21]). Prosecutors said the group took up to $4 million from UK bookmakers and casinos and counted 54 similar attacks in 30 countries over about six months (Reported, Out-Law [14]). One victim, Canbet Sports Bookmakers, refused a $10,000 demand and was knocked offline during the Breeders' Cup; the prosecutor put its losses above $200,000 per day of downtime (Reported [14]). Some later accounts give a different demand figure; it was not checked.

The investigation crossed borders. The NHTCU ran a joint investigation with Interpol, the FBI, the Russian Interior Ministry and the Prosecutor General's Office; Maksakov and Stepanov were arrested in September 2004 and Petrov in mid 2005 (Reported [14]). The Register reported in July 2004 that ten members arrested in Riga, Latvia, in November 2003 had led investigators along the financial trail to the Russian arrests (Reported [22]).

A court in Balakovo, in the Saratov region, sentenced Maksakov of Balakovo, Petrov of Astrakhan and Stepanov of St Petersburg to eight years each, with fines of about $3,700 (Reported [14]); Virus Bulletin gives the fines as 100,000 rubles (Reported [21]). No court record was opened, and the 2006 date in the news reports conflicts with the 2007 date on Wikipedia's page for the book [14][15].

### Barrett Lyon and Prolexic

In the book, Lyon builds Prolexic Technologies, one of the first DDoS protection companies, and is drawn into protecting offshore gambling and pornography sites (Reported, Rick Howard's review [16]). When the book came out, Prolexic's chief operating officer called its events ancient history and said company attorneys would review it (Reported, Network World [13]). The company's later value is a matter of record: Akamai completed its acquisition of Prolexic on 18 February 2014 under a merger agreement dated 2 December 2013, paying about $337.1 million in cash at closing plus $50.4 million placed in escrow (Confirmed, Akamai Form 8-K [17]).

### The Russian Business Network

The book's larger argument concerns the Russian Business Network. It portrays the RBN as an early and largely untouchable syndicate whose owner was the son of a high-ranking official, with senior Kremlin figures making his arrest unwise (Reported, Howard [16]; not independently verified). The contemporary press gives the outline. Brian Krebs reported in the Washington Post in October 2007 that the St Petersburg-based RBN had no registration or website, sold bulletproof hosting (about $600 a month, according to VeriSign) and hosted sites tied to child abuse material, spam and identity theft (Reported [18]). Security experts told him groups using the RBN were behind about half of the previous year's phishing incidents, and VeriSign tied the Rock phishing group to about $150 million stolen through the network (Reported [18]). Kaspersky's Alexander Gostev said the RBN itself breaks no law and that its customers mostly target non-Russian victims; the Russian Interior Ministry declined to discuss it, and the FBI declined to address the RBN specifically (Reported [18]).

The book's Russian government thread is hedged even in the book. Network World reports that the book says RBN services were used in the DoS attacks, data theft and defacements against Georgia's government networks in August 2008, and that Kaspersky told Menn he doubted the Russian government would attack Georgia for political ends (Reported [13]). And Menn's own research shows disagreement over which part of the Russian government, and how senior a part, was connected to the RBN (Reported [13]). This study does not adopt the attribution.

### The US context

Two US records from the same years show DDoS sold as a commercial service at home; whether the book covers them, and whether the 2008 indictment belongs to the Cyberslam case, was not checked. The FBI's wanted notice for Saad (Jay R.) Echouafni says he was indicted in Los Angeles on 25 August 2004 for hiring hackers to DDoS his competitors, in an investigation code-named Operation Cyberslam that began in 2003; the FBI calls it the first successful US investigation of a large-scale commercial DDoS (Confirmed [19]). A 2008 Central District of California release records the indictment of Lee Graham Walker of England and Axel Gembe of Germany, whose botnet was built with Agobot, with Gembe named as its developer; the Weaknees site was down nearly two weeks in October 2003 with losses over $200,000, Rapid Satellite was also hit, and a co-defendant, Paul Ashley, pleaded guilty and served two years (Confirmed [20]).

### Shadowcrew, in brief

Menn's subject is the origin of the underground economy, and Shadowcrew is part of that story. The Justice Department's 28 October 2004 release describes a 62-count indictment of 19 people, about 4,000 members, 21 US arrests, at least 1.7 million stolen card numbers and over $4 million in losses after a year-long Secret Service undercover case (Confirmed [1]). [Part 1 of this study](#shadowcrew-and-operation-firewall) is the home for Shadowcrew and Operation Firewall, and tells that story in full.

## Part 3: We Are Anonymous (Anonymous, LulzSec and AntiSec, 2010 to 2012)

### The book

*We Are Anonymous* by Parmy Olson is listed in the library's book list for 2012 [54]. Its text and publisher pages were not opened for this study; every claim below rests on the court record or on contemporary press, graded accordingly.

### Operation Payback and Operation Avenge Assange

Operation Payback began in September 2010 as an anti-piracy DDoS campaign after Aiplex Software, working for rights holders, took down The Pirate Bay. Within a week Anonymous hit Aiplex, the MPAA, the RIAA, the British Phonographic Industry and ACS:Law, and in October it hit targets including the UK Intellectual Property Office and the US Copyright Office (Reported, The Next Web [23]).

The campaign then turned to WikiLeaks' payment processors. Between December 2010 and June 2011 Monsegur and other Anonymous members claimed denial-of-service attacks against Visa, MasterCard and PayPal in retaliation for their refusal to process WikiLeaks donations (Confirmed [24][37]). After his arrest Monsegur admitted taking part in the PayPal, MasterCard and Visa attacks, which the government had not previously known (Confirmed [25]).

On 19 July 2011 the FBI arrested 16 people. Fourteen were charged in a San Jose indictment over the 6 to 10 December 2010 DDoS on PayPal, called "Operation Avenge Assange", in retaliation for PayPal suspending WikiLeaks' account, using a free open source tool; more than 35 search warrants were executed and one UK and four Dutch arrests were made (Confirmed, FBI [36]). The Register named the tool as LOIC, distributed by Anonymous members, and reported the charges as conspiracy and intentional damage to a protected computer (Reported [26]). The same sweep charged Scott Arciszewski in Tampa with accessing an Infragard website on 21 June 2011 and uploading three files, and Lance Moore in New Jersey with taking AT&T confidential data in April 2011 that LulzSec later released (Reported [26]). In December 2013 thirteen PayPal defendants pleaded guilty in San Jose, ten to felony and misdemeanor counts and three to misdemeanors, with the felonies to be dropped if they stayed out of trouble (Reported, phys.org [27]). Separately, on 3 October 2013 a US grand jury indicted 13 people over Operation Payback attacks coordinated in IRC channels against targets including the MPAA, RIAA, Visa, MasterCard, PayPal and Bank of America (Reported, CBS News [28]).

### HBGary Federal

The HBGary Federal breach followed chief executive Aaron Barr's claim that he had unmasked Anonymous (Reported, Ars Technica [29]). Ars Technica's reconstruction is the most detailed public account of the chain (all Reported [29]):

1. Attackers exploited a SQL injection flaw in the content management system behind hbgaryfederal.com and recovered unsalted MD5 password hashes.
2. They cracked the simple passwords of Barr and chief operating officer Ted Vera with rainbow tables.
3. Barr and Vera reused their passwords across e-mail, Twitter and LinkedIn.
4. Vera's password opened an ssh account on support.hbgary.com, where a privilege escalation flaw gave full access; gigabytes of backups and research data were purged.
5. Barr's account was the administrator for the company's Google Apps mail.
6. From the hijacked mailbox of HBGary owner Greg Hoglund, the attackers persuaded the rootkit.com administrator to open ssh and confirm the root password.
7. HBGary e-mails were published, its website was defaced, and rootkit.com's user database was published.

The government record confirms the participants and the scale. The SDNY release says the crew known as Internet Feds, active from December 2010 to May 2011, hacked Fine Gael, HBGary Inc. and HBGary Federal, stealing data on about 80,000 user accounts, and Fox Broadcasting, stealing data on more than 70,000 potential X-Factor contestants (Confirmed [24]); the FBI's copy adds that the crew hijacked e-mail and Twitter accounts and defaced websites (Confirmed [37]). Monsegur directly participated in the HBGary hack, which involved theft of e-mails and company data, in response to the firm's claim that it had identified Anonymous members (Confirmed [25]).

### LulzSec

LulzSec formed in approximately May 2011 (Confirmed [25]). The government's sentencing memorandum lists the core roles: Sabu as the "rooter" analyzing code for vulnerabilities, Kayla specializing in social engineering, T-Flow as organizer, Topiary as the public face, AVUnit providing servers, and Pwnsauce (Confirmed [25]). The FBI names Ackroyd, Davis, Martyn and Monsegur as the founders (Confirmed [37]). The crew's spree lasted 50 days in the summer of 2011 (Reported, The Register [35]).

| Target | Date | What happened | Grade and source |
|---|---|---|---|
| PBS | Late on 29 May 2011 | A fake story claiming Tupac Shakur was alive was posted and PBS staff usernames and passwords published, as retaliation for the Frontline episode "WikiSecrets"; PBS confirmed the hack | Reported [30] |
| PBS | May 2011 | Monsegur helped identify a vulnerability and installed multiple back doors; the hack compromised PBS servers and defaced its website | Confirmed [25] |
| Sony Pictures | 2 June 2011 (claim) | LulzSec claimed one "very simple" SQL injection exposed over 1,000,000 accounts with plaintext passwords; unverified at the time | Reported [31] |
| Sony Pictures | 2011 | DOJ puts the theft at data on about 100,000 website users | Confirmed [24] |
| Bethesda Softworks | 2011 | Data on about 200,000 users stolen | Confirmed [24] |
| Tribune Company, Sony BMG Belgium and Netherlands, Nintendo, Infragard/Unveillance (Atlanta) | 2011 | Monsegur took part; the Tribune intrusion used credentials a journalist supplied; he researched the Senate.gov hack and knew of co-conspirators' hacks of Fine Gael and the Sony PlayStation Network | Confirmed [25] |

Cody Kretsinger, "Recursion", pleaded guilty in April 2012 and was sentenced in April 2013 to one year in prison, home detention and 1,000 hours of community service for the 2011 Sony Pictures breach; prosecutors put damages above $600,000 (Reported, NBC News [32]).

### Sabu turns

On or about 7 June 2011 the FBI approached Monsegur at home. He admitted his conduct, agreed to cooperate immediately, reviewed his files with agents that night, and appeared the next morning on a credit card fraud and identity theft complaint (Confirmed [25]). He pleaded guilty on 15 August 2011 under a cooperation agreement to a 12-count information covering hacking conspiracy, hacking, hacking in furtherance of fraud, access device fraud conspiracy, bank fraud conspiracy and aggravated identity theft, with a maximum of 124 years and six months; the plea was unsealed on 6 March 2012 (Confirmed [24]).

At law enforcement direction Monsegur chatted with co-conspirators to confirm their identities and locations, and induced members to hand over hacking logs that were later found on their seized computers, linking nicknames to real identities (Confirmed [25]). The FBI estimated that his cooperation disrupted or prevented at least 300 hacks, including against the US armed forces, Congress, the courts and NASA; he also reported vulnerabilities at a US city water utility, which was secured, and at a foreign energy company (Confirmed [25]).

### AntiSec and Stratfor

The cooperation ran in parallel with new crimes by others. In December 2011 AntiSec, an Anonymous offshoot that included Jeremy Hammond, hacked Stratfor in Austin, Texas, stealing employee e-mails, account data for about 860,000 subscribers or clients and card data for about 60,000 users, some of it used for more than $700,000 in unauthorized charges; the data was posted under the title "Anonymous Lulzxmas rooting you proud" (Confirmed [24]). Donncha O'Cearrbhail accessed an Irish Garda officer's personal e-mail, learned the details of a 17 January 2012 conference call between the Garda, the FBI and partner agencies about Anonymous investigations, and secretly recorded and disseminated the call (Confirmed [24][37]).

### Charges and sentences

On 6 March 2012 the Southern District of New York unsealed charges against Ryan Ackroyd (kayla), Jake Davis (topiary), Darren Martyn (pwnsauce), Donncha O'Cearrbhail (palladium) and Jeremy Hammond (Anarchaos), who had been arrested in Chicago on 5 March 2012 (Confirmed [24]).

| Defendant | Court and date | Outcome | Grade and source |
|---|---|---|---|
| Ryan Cleary | Southwark Crown Court, 16 May 2013 | 32 months (Confirmed [25]); he supplied a botnet of about 100,000 machines (Reported [35]) | Confirmed [25]; Reported [35] |
| Ryan Ackroyd | Southwark Crown Court, 16 May 2013 | 30 months | Confirmed [25]; Reported [35] |
| Jake Davis | Southwark Crown Court, 16 May 2013 | 24 months in a young offenders' institution | Confirmed [25]; Reported [35] |
| Mustafa Al-Bassam | Southwark Crown Court, 16 May 2013 | 20 months suspended, 300 hours of community service | Confirmed [25]; Reported [35] |
| Darren Martyn | Ireland | Pleaded guilty; probation and a fine | Confirmed [25] |
| Jeremy Hammond | SDNY, 15 November 2013 | Pleaded guilty in May 2013 to one count of computer hacking conspiracy; 10 years from Chief Judge Loretta Preska; at his plea he admitted other 2011 to 2012 intrusions including the FBI Virtual Academy, the Arizona Department of Public Safety, the Jefferson County (Alabama) Sheriff's Office, the Boston Police Patrolmen's Association and Combined Systems | Confirmed [33] |
| Hector Monsegur | SDNY, 27 May 2014 | Time served, one year of supervised release and a $1,200 assessment | Confirmed [34]; Reported [38] |

Monsegur's own path was not smooth. His bail was revoked in May 2012 over unauthorized online postings and he served about seven months until December 2012; his Guidelines range was 259 to 317 months, and the government said his cooperation contributed to the convictions of eight major co-conspirators including Hammond (Confirmed [25]).

## Part 4: The Hacker Crackdown (1984 to 1994)

### The book

Bruce Sterling's *The Hacker Crackdown* is the only one of the four books consulted directly for this study, in the free Project Gutenberg edition its author released (eBook #101) [41]. It weaves four threads: the AT&T crash of January 1990, the Legion of Doom and the BellSouth E911 document, the Secret Service's Operation Sundevil, and the raid on Steve Jackson Games that led to the founding of the Electronic Frontier Foundation.

### The AT&T crash, 15 January 1990

AT&T's official report is precise. At about 2:30 p.m. EST on 15 January 1990 a New York City 4ESS toll switch had a minor hardware problem and entered its normal fault recovery of four to six seconds (Confirmed [39]). A software flaw in the 4ESS Direct Link Node, the CCS7 link processor, meant that two call attempts arriving within a hundredth of a second during a vulnerable window damaged data, and the failure cascaded across the switches (Confirmed [39]). The flaw had been introduced into all 4ESS switches by a mid-December 1989 software update intended to speed access to a backup signaling network (Confirmed [39]). The last link was cleared at 11:30 p.m. EST that Monday; the next day the faulty update was removed and the flaw reproduced in the lab (Confirmed [39]). Telephony quoted AT&T's Larry Seese a week later saying the fault was in new code loaded into the front-end processors of all 114 4ESS systems (Confirmed, as quoted in RISKS 9.62 [40]).

Sterling supplies the scale and the code. He writes that 60,000 people lost service completely and some 70 million calls went uncompleted during nine hours of restoration, with half of AT&T's network gone haywire (Reported [41]). He puts the C-level cause in a `break` statement inside an `if` clause that exited the enclosing `switch` statement; AT&T's official report does not describe the code (Reported [41]). The crash fell on Martin Luther King Day, and Sterling writes that it was at first widely suspected to be hacker action, which shaped the crackdown that followed, although AT&T attributed it to its own software (Reported [41]).

This study does not map the crash to any ATT&CK technique: it was a software defect, not an attack.

### The Legion of Doom and the E911 document

According to Sterling, the Legion of Doom formed in 1984, named after comic-book villains and founded by "Lex Luthor" (Reported [41]). In September 1988 a member using the handle "Prophet" cracked BellSouth's AIMSX network, downloaded the E911 Document and also stored it on the Jolnet system (Reported [41]). The government's sentencing memorandum confirms the core: Riggs, Prophet, stole the E911 file from AIMSX, BellSouth's centralized automation system, and obtained root privileges there (Confirmed [42]).

The Atlanta case was larger than one file. From September 1987 to 21 July 1989 the Atlanta defendants broke into telephone company computers and stole about $233,880 worth of logins, passwords and connect addresses from BellSouth; BellSouth spent about $1.5 million identifying the intruders and about $3 million more securing its network (Confirmed [42]). A court-authorized dial number recorder on the three defendants' lines from 11 to 21 July 1989 showed calls looped through carriers and Telenet, often starting via Georgia Tech, into BellSouth using stolen access information (Confirmed [42]). Seized materials included tutorials on blue boxes, loops, root access on BellSouth systems and planting UNIX trojan horses, along with password hacking programs (Confirmed [42]).

Sterling dates the Secret Service raids on Prophet, Leftist and Urvile in Georgia to 22 July 1989 (Reported [41]). On 16 November 1990 Riggs was sentenced to 21 months, and Darden and Grant to 14 months each, seven of them in a half-way house, with about $233,000 in restitution each and about $700,000 jointly (Confirmed, CuD 2.16 summary [42]). Sterling adds that the Atlanta Three were barred from computers except for work or under supervision, and that the EFF filed an amicus brief calling the condition unconstitutional (Reported [41]).

### Craig Neidorf and Phrack

Knight Lightning, Craig Neidorf, published the E911 Document in Phrack, dated 25 February 1989 by Sterling (Reported [41]). The Secret Service's search-warrant affidavit alleges that Neidorf transported the file on or about 24 February 1989 (Confirmed [43]).

Dorothy Denning's March 1991 account in *Communications of the ACM* gives the prosecution's course. Neidorf was first indicted on 1 February 1990; a June 1990 superseding indictment brought ten felony counts, wire fraud and interstate transportation of stolen property, with a 65-year maximum; and the government valued the document at $23,900 (Reported, Denning [49]). The trial began on 23 July 1990 in the Northern District of Illinois, and the defense showed Bellcore E911 pamphlets sold by phone for $13 and $21 that contained more detail than the Phrack file (Reported [49]). Sterling describes the same point as a BellSouth publication with more detail sold for $13 by catalog (Reported [41]). On 27 July 1990 the prosecution moved to dismiss and Judge Nicholas J. Bua declared a mistrial; Neidorf owed over $100,000 in legal fees, and his record was expunged on 9 September 1991 (Reported, Sterling [41]).

The value of the document is the clearest example of a number that moved:

| Valuation | Who and where | Grade |
|---|---|---|
| $79,449 | BellSouth security to the Chicago task force, per Sterling | Reported [41] |
| $24,639.05 | BellSouth Security, based on research and development costs, quoted in the Atlanta sentencing memorandum | Confirmed [42] |
| $23,900 | The government's value at the Neidorf trial, per Denning | Reported [49] |
| $13 | The price of a more detailed published version, per the defense | Reported [41][49] |

### Operation Sundevil

The US Attorney for the District of Arizona announced on 9 May 1990 that about 27 search warrants had been executed on 7 and 8 May 1990 by 150 Secret Service agents with state and local police, under Operation Sundevil, a two-year investigation into credit card, long-distance code and unauthorized access crimes (Confirmed [44]). The release lists 13 warrant cities (Chicago, Cincinnati, Detroit, Los Angeles, Miami, Newark, New York, Phoenix, Pittsburgh, Plano, Richmond, San Diego and San Jose) and three arrests on collateral or independent state charges (Confirmed [44]). It estimated losses that "may run into the millions of dollars" and credited technical assistance from AT&T, Bellcore, BellSouth, MCI, Sprint and other telephone companies (Confirmed [44]). Contemporary press excerpts reprinted in the same issue reported about 42 computers and 23,000 disks seized (Reported [44]). Sterling counts "twelve" cities (Reported [41]); Secret Service Assistant Director Garry M. Jenkins' prepared remarks, reprinted in the same issue, give approximately fifteen (Confirmed, reprint [44]), and a press excerpt there gives 28 warrants in 16 cities (Reported [44]).

### Steve Jackson Games

The raid that produced the era's most lasting law began with a Bell security inquiry. The Fifth Circuit records that the investigation traced to an October 1988 inquiry into a copied file on the emergency call system, and that the warrant was applied for on 28 February 1990 under 18 U.S.C. 1030 and 2314 (Confirmed [50]). The Foley search-warrant affidavit of that date relied on Bellcore's Henry Kluepfel and targeted Loyd Blankenship, The Mentor, his home and his workplace, Steve Jackson Games (Confirmed [43]).

The search on 1 March 1990 seized three computers, over 300 disks, the Illuminati bulletin board system with its public and private e-mail, the draft of *GURPS Cyberpunk* and business records (Confirmed, district court [45]). The board held 162 unread private e-mails, and the district court found that Secret Service personnel or delegates read and deleted them (Confirmed [50]). No one at the company was arrested or charged (Reported, Sterling [41]); the EFF says the Secret Service returned the computers without pressing charges and that the company laid off nearly half its staff (Reported [48]).

The district court, Judge Sparks presiding, ruled on 12 March 1993 (all Confirmed [45]):

- **Privacy Protection Act.** Agent Foley, although an attorney, did not know the Act and did no investigation; several hours would have shown that the company was a legitimate publisher. From 2 March 1990 the Secret Service was on notice, and its continued retention violated the Act. The company was awarded $8,781 in expenses and $42,259 in lost profit.
- **Stored Communications Act.** Illuminati was a "remote computing service" under 18 U.S.C. 2711, the seizure of its stored communications violated Title II of the Electronic Communications Privacy Act, and each plaintiff received $1,000 in statutory damages.
- **Wiretap Act.** No liability under Title I, following *United States v. Turk*.

On 31 October 1994 the Fifth Circuit (No. 93-8661, 36 F.3d 457) affirmed, holding that seizing a computer that stores unread e-mail is not an "intercept" under the Wiretap Act; it records $51,040 in Privacy Protection Act damages, $1,000 per individual plaintiff, $195,000 in attorneys' fees and about $57,000 in costs (Confirmed [46][50]). The company's own summary gives over $50,000 in damages and over $250,000 in fees and costs combined, which matches the court's figures (Reported [47]).

### The Electronic Frontier Foundation

The EFF states that it was founded in July 1990 by Mitch Kapor, John Perry Barlow and John Gilmore, with help from Steve Wozniak, in response to the Steve Jackson Games raid (Confirmed [48]). Sterling tells it as a meeting between Kapor and Barlow in Pinedale, Wyoming, in June 1990, followed by Barlow's essay "Crime and Puzzlement", Wozniak's offer of matching funds, Gilmore joining, Kapor becoming president and the WELL hosting the new group; his chronology dates the founding to June 1990 (Reported [41]). The EFF, Steve Jackson and others filed suit on 1 May 1991, per Sterling's chronology (Reported [41]).

## Part 5: the combined timeline

| Date | Event | Book | Grade and source |
|---|---|---|---|
| 1984 | Legion of Doom formed, founded by "Lex Luthor" | Hacker Crackdown | Reported [41] |
| Sep 1987 to 21 Jul 1989 | Atlanta defendants break into telephone company computers; about $233,880 in access information stolen from BellSouth | Hacker Crackdown | Confirmed [42] |
| Sep 1988 | Prophet takes the E911 file from BellSouth's AIMSX system with root access | Hacker Crackdown | Confirmed [42]; Reported [41] |
| Oct 1988 | Bell security inquiry into the copied emergency-system file begins | Hacker Crackdown | Confirmed [50] |
| 24 to 25 Feb 1989 | Neidorf transports the file (affidavit); Phrack publishes it (Sterling) | Hacker Crackdown | Confirmed [43]; Reported [41] |
| 11 to 21 Jul 1989 | Dial number recorder on the Atlanta defendants' lines | Hacker Crackdown | Confirmed [42] |
| 22 Jul 1989 | Secret Service raids Prophet, Leftist and Urvile | Hacker Crackdown | Reported [41] |
| Mid Dec 1989 | AT&T update loads the flawed code into all 4ESS switches | Hacker Crackdown | Confirmed [39][40] |
| 15 Jan 1990 | AT&T long-distance crash, about 2:30 p.m. to 11:30 p.m. EST | Hacker Crackdown | Confirmed [39] |
| 1 Feb 1990 | Neidorf first indicted | Hacker Crackdown | Reported [49] |
| 28 Feb 1990 | Foley affidavit and warrant application | Hacker Crackdown | Confirmed [43][50] |
| 1 Mar 1990 | Steve Jackson Games searched; Illuminati BBS seized | Hacker Crackdown | Confirmed [45] |
| 7 to 8 May 1990 | Operation Sundevil: about 27 warrants, 150 agents, 13 cities | Hacker Crackdown | Confirmed [44] |
| Jun to Jul 1990 | EFF founded (July per the EFF; June per Sterling) | Hacker Crackdown | Confirmed [48]; Reported [41] |
| 23 to 27 Jul 1990 | Neidorf trial; prosecution moves to dismiss, mistrial | Hacker Crackdown | Reported [41][49] |
| 16 Nov 1990 | Atlanta Three sentenced | Hacker Crackdown | Confirmed [42] |
| 1 May 1991 | Steve Jackson Games and others file suit | Hacker Crackdown | Reported [41] |
| 9 Sep 1991 | Neidorf's record expunged | Hacker Crackdown | Reported [41] |
| 12 Mar 1993 | District court rules for Steve Jackson Games on the PPA and SCA claims | Hacker Crackdown | Confirmed [45] |
| 31 Oct 1994 | Fifth Circuit affirms | Hacker Crackdown | Confirmed [46][50] |
| Jun 1998 | Butler's BIND worm | Kingpin | Reported [8] |
| 21 May 2001 | Butler sentenced to 18 months | Kingpin | Reported [8] |
| Jul 2003 | Operation Firewall begins | Kingpin | Confirmed [2] |
| 2003 | Operation Cyberslam investigation begins | US context | Confirmed [19] |
| Oct 2003 | Agobot botnet takes Weaknees offline for nearly two weeks | US context | Confirmed [20] |
| Nov 2003 | Ten gang members arrested in Riga | Fatal System Error | Reported [22] |
| 2003 to 2004 | Bookmaker extortion: 54 attacks in 30 countries | Fatal System Error | Reported [14][21] |
| Early 2004 | Court-authorized intercepts in Firewall begin | Kingpin | Confirmed [2] |
| 25 Aug 2004 | Echouafni indicted in Los Angeles | US context | Confirmed [19] |
| Sep 2004 | Maksakov and Stepanov arrested | Fatal System Error | Reported [14] |
| 28 Oct 2004 | Shadowcrew indictment; Firewall's 28 arrests | Kingpin | Confirmed [1][2] |
| Mid 2005 | Petrov arrested | Fatal System Error | Reported [14] |
| About Jun 2005 | Butler's alleged intrusions at financial institutions begin | Kingpin | Confirmed [4] |
| 17 Nov 2005 | Six Shadowcrew defendants including Mantovani plead guilty | Kingpin | Confirmed [3] |
| Aug 2006 | Butler takes over rival forums | Kingpin | Reported [7] |
| 29 Sep 2006 | Capital One lure e-mail | Kingpin | Reported [7] |
| Oct 2006 | Russian court sentences Maksakov, Petrov and Stepanov to eight years | Fatal System Error | Reported [14][21] |
| 14 Oct and 6 Dec 2006 | Card sales to a buyer in the Western District of Pennsylvania | Kingpin | Confirmed [4] |
| 12 May 2007 | Aragon arrested at a Bloomingdale's | Kingpin | Reported [7] |
| 5 Sep 2007 | Butler arrested in San Francisco | Kingpin | Confirmed [4][5] |
| 11 Sep 2007 | Butler indicted in Pittsburgh | Kingpin | Confirmed [4] |
| 13 Oct 2007 | Krebs reports on the Russian Business Network | Fatal System Error | Reported [18] |
| 2 Oct 2008 | Walker and Gembe indicted (Agobot) | US context | Confirmed [20] |
| 30 Jun 2009 | Butler pleads guilty to two wire fraud counts | Kingpin | Reported [9] |
| 12 Feb 2010 | Butler sentenced to 13 years | Kingpin | Confirmed [5] |
| Sep to Oct 2010 | Operation Payback against anti-piracy targets | We Are Anonymous | Reported [23] |
| 6 to 10 Dec 2010 | "Operation Avenge Assange" DDoS on PayPal | We Are Anonymous | Confirmed [36] |
| Dec 2010 to May 2011 | Internet Feds hacks (Fine Gael, HBGary, Fox) | We Are Anonymous | Confirmed [24] |
| Feb 2011 | HBGary Federal breach | We Are Anonymous | Confirmed [25]; Reported for the chain [29] |
| About May 2011 | LulzSec formed | We Are Anonymous | Confirmed [25] |
| 29 May 2011 | PBS hack and defacement | We Are Anonymous | Confirmed [25]; Reported [30] |
| 2 Jun 2011 | Sony Pictures leak claimed | We Are Anonymous | Reported [31] |
| About 7 Jun 2011 | FBI approaches Monsegur; he agrees to cooperate | We Are Anonymous | Confirmed [25] |
| 19 Jul 2011 | 16 arrests in the US over the PayPal DDoS and related cases | We Are Anonymous | Confirmed [36] |
| 15 Aug 2011 | Monsegur pleads guilty under seal | We Are Anonymous | Confirmed [24] |
| Dec 2011 | AntiSec hacks Stratfor | We Are Anonymous | Confirmed [24] |
| 17 Jan 2012 | Garda and FBI call recorded and leaked | We Are Anonymous | Confirmed [24] |
| 5 to 6 Mar 2012 | Hammond arrested; SDNY charges unsealed | We Are Anonymous | Confirmed [24] |
| May 2012 | Monsegur's bail revoked | We Are Anonymous | Confirmed [25] |
| 16 May 2013 | LulzSec members sentenced at Southwark Crown Court | We Are Anonymous | Reported [35]; Confirmed in part [25] |
| 3 Oct 2013 | 13 indicted over Operation Payback | We Are Anonymous | Reported [28] |
| 15 Nov 2013 | Hammond sentenced to 10 years | We Are Anonymous | Confirmed [33] |
| 5 Dec 2013 | 13 PayPal defendants plead guilty in San Jose | We Are Anonymous | Reported [27] |
| 18 Feb 2014 | Akamai completes its acquisition of Prolexic | Fatal System Error | Confirmed [17] |
| 27 May 2014 | Monsegur sentenced to time served | We Are Anonymous | Confirmed [34] |

## Part 6: the defender view

These cases are between 12 and more than 35 years old, and every failure in them is still in incident reports today (Inferred).

### Availability attacks are a business problem first

The bookmaker gang and Operation Payback used the same mechanics for opposite motives: one wanted money, the other wanted attention (Inferred, from [14][21][36]). In both, the victim's choice was set before the flood arrived. Canbet refused to pay and lost more than $200,000 a day of downtime, per the prosecutor (Reported [14]); one answer was Prolexic, which Howard's review describes as one of the first DDoS protection companies (Reported [16]; Confirmed for Prolexic's later sale [17]). The defensive lessons:

- Contract upstream mitigation and test the failover before an incident, not during it (Inferred).
- Write the no-pay policy down, with the legal and law enforcement contacts it names, so the decision is not made under a live flood (Inferred).
- Report extortion demands. The 2003 to 2006 case was solved by following payments through Latvia, which only works when victims report (Reported [22]; Inferred for the lesson).

### The HBGary chain, control by control

| Step in the chain | Control that breaks it | Grade |
|---|---|---|
| SQL injection in the hbgaryfederal.com CMS | Parameterized queries; database query string analysis | Reported [29]; Inferred for the control |
| Unsalted MD5 hashes cracked with rainbow tables | Slow, salted password hashing (CWE-916) | Reported [29]; Inferred |
| Password reuse across e-mail, Twitter, LinkedIn | Unique passwords; a password manager; multi-factor authentication | Reported [29]; Inferred |
| ssh on a support server with a reused password | Key-only ssh; no internet-facing ssh on support hosts | Reported [29]; Inferred |
| Privilege escalation on the support server | Patching; separation of research data from support hosts | Reported [29]; Inferred |
| Chief executive as mail administrator | Separate, MFA-protected administrator identities | Reported [29]; Inferred |
| Social engineering of the rootkit.com administrator from a real mailbox | Out-of-band verification for any credential or access request | Reported [29]; Inferred |

### Card fraud runs on the merchant edge

Butler's supply chain, per Poulsen, ran through sniffers on point-of-sale terminals at small restaurants and retailers, alongside intrusions at financial institutions and processing centers that the indictment alleges (Reported [7]; Confirmed for the allegation [4]). The issuing banks bore the $86.4 million (Confirmed [5]). Small merchants rarely have the monitoring that would find a sniffer; payment terminal integrity checks, network segmentation of point-of-sale systems and processor-side fraud analytics are where this is caught (Inferred).

### Investigators win from the inside

Three of the four stories turn on an informant or an intercept, and the fourth on a financial trail (Inferred). Firewall used court-authorized intercepts and an administrator who ran a VPN he could watch (Confirmed [2]; Reported [7]). Butler was found through an informant's purchase from Zebra, who then named Iceman's San Francisco base, and through a shared domain registration account (Reported [7]). LulzSec unravelled when its "rooter" cooperated the night he was approached (Confirmed [25]). The Atlanta case rested on a dial number recorder (Confirmed [42]). For defenders, the practical point is that the operational security failures attackers make, shared registration accounts, reused handles and trusted insiders, are also the intelligence leads that let defenders and investigators link activity (Inferred).

### Investigators can also lose

The Steve Jackson Games ruling is a lesson for anyone who seizes or holds systems that store other people's communications. The agent did not know the Privacy Protection Act, the agency kept the material after notice, and e-mail on the seized board was read and deleted (Confirmed [45][50]). Incident responders and legal teams handling a server that holds customer or user messages should get a legal review of the scope before imaging or seizure (Inferred).

## Part 7: MITRE mappings

Most of these events predate ATT&CK, and none of the actors has an object in the library's ATT&CK data. Every mapping in this Part is therefore this study's reading of the behaviour in the record (Inferred), not a mapping MITRE or a vendor has published. T1498.001, T1499.002, T1190, T1110.002, T1078, T1068, T1114.002, T1598, T1491.002, T1584.005, T1657 and T1189 were verified against the live ATT&CK pages; every id, including those, was checked against the library's technique pages and `data/attack/technique_profiles.jsonl` on 3 November 2026, and every technique, CWE, CAPEC and D3FEND id was rechecked against the same files at main `cb085a91` on 11 November 2026 [51][53][54]. Tactic names follow ATT&CK v20.0, in which the former Defense Evasion tactic is split into Stealth and Defense Impairment. The grade column gives the grade of the underlying behaviour; the fit column says how direct the mapping is.

### ATT&CK Enterprise techniques

| Id | Name | Tactic (v20.0) | Where it appears in the record | Behaviour grade | Fit | Source |
|---|---|---|---|---|---|---|
| [T1566](/mitre/techniques/T1566.md) | Phishing | Initial Access | Mantovani admits phishing and spamming for card data (plea, 17 Nov 2005) | Confirmed | Direct | [3] |
| [T1566.002](/mitre/techniques/T1566-002.md) | Spearphishing Link | Initial Access | Capital One lure e-mail, about 125 of 500 employees clicked (29 Sep 2006) | Reported | Direct | [7] |
| [T1189](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | Hidden payload on the Capital One lure; browser exploits in the publisher's description of *Kingpin* | Reported | Weak | [7][11] |
| [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | PBS vulnerability (May 2011); HBGary CMS SQL injection (Feb 2011); Sony Pictures SQL injection claim (2 Jun 2011); rival carding forums (Aug 2006); Butler's alleged intrusions at processors (vector not named) | Confirmed (PBS); Reported (others) | Direct | [25][29][31][7][4] |
| [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | Stolen BellSouth logins (1987 to 1989); Tribune credentials from a journalist (2011); HBGary password reuse (Feb 2011); hijacked e-mail and Twitter accounts (Internet Feds); a hacked password into a rival forum (Aug 2006) | Confirmed (BellSouth, Tribune, Internet Feds); Reported (others) | Direct; analogy for 1987 to 1989 | [42][25][37][29][7] |
| [T1133](/mitre/techniques/T1133.md) | External Remote Services | Initial Access, Persistence | ssh on support.hbgary.com with Vera's password (Feb 2011); dial-in access to BellSouth via Telenet (1989) | Reported (HBGary); Confirmed (BellSouth) | Direct (HBGary); analogy (BellSouth) | [29][42] |
| [T1598](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | rootkit.com administrator persuaded to confirm the root password (Feb 2011) | Reported | Direct | [29] |
| [T1584.005](/mitre/techniques/T1584-005.md) | Botnet | Resource Development | Agobot botnet (Oct 2003, indictment 2 Oct 2008); bookmaker botnets built 2003 to 2004; Cleary's botnet of about 100,000 machines (2011) | Confirmed (Agobot); Reported (others) | Direct | [20][21][35] |
| [T1110.002](/mitre/techniques/T1110-002.md) | Password Cracking | Credential Access | HBGary hashes cracked with rainbow tables (Feb 2011); password hacking programs seized in Atlanta (Jul 1989) | Reported (HBGary); Confirmed (seizure) | Direct (HBGary); analogy for Atlanta (tools seized, use not recorded) | [29][42] |
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | Sniffers on point-of-sale terminals (2005 to 2007) | Reported | Direct | [7] |
| [T1068](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | Privilege escalation flaw on support.hbgary.com (Feb 2011) | Reported | Direct | [29] |
| [T1090.003](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | Command and Control | Calls looped through carriers and Telenet, often via Georgia Tech (Jul 1989) | Confirmed | Analogy | [42] |
| [T1114.002](/mitre/techniques/T1114-002.md) | Remote Email Collection | Collection | HBGary mailboxes via the Google Apps administrator account (Feb 2011); a Garda officer's personal e-mail (Jan 2012) | Reported (HBGary); Confirmed (Garda) | Direct (HBGary); weak (Garda, method not stated) | [29][24][37] |
| [T1005](/mitre/techniques/T1005.md) | Data from Local System | Collection | The E911 file copied from AIMSX (Sep 1988) | Confirmed | Analogy | [42] |
| [T1213](/mitre/techniques/T1213.md) | Data from Information Repositories | Collection | The E911 file from BellSouth's centralized automation system (Sep 1988) | Confirmed | Analogy | [42] |
| [T1485](/mitre/techniques/T1485.md) | Data Destruction | Impact | Rival forum databases wiped (Aug 2006); HBGary backups and research data purged (Feb 2011) | Reported | Direct | [7][29] |
| [T1491.002](/mitre/techniques/T1491-002.md) | External Defacement | Impact | PBS website defaced (May 2011); HBGary site defaced (Feb 2011); Internet Feds defacements | Confirmed (PBS, Internet Feds); Reported (HBGary) | Direct | [25][37][29] |
| [T1498](/mitre/techniques/T1498.md) | Network Denial of Service | Impact | Bookmaker extortion (2003 to 2004); Operation Cyberslam (2003 to 2004); PayPal, Visa and MasterCard DDoS (Dec 2010) | Confirmed (PayPal, Cyberslam); Reported (bookmakers) | Direct | [36][24][19][14][21] |
| [T1657](/mitre/techniques/T1657.md) | Financial Theft | Impact | Butler's card sales (2005 to 2007); bookmaker extortion (2003 to 2004); Stratfor cards used for over $700,000 in charges (Dec 2011) | Confirmed (Butler, Stratfor); Reported (bookmakers) | Direct | [5][24][14] |

Left out on purpose: the AT&T crash (a software defect, not an attack); Butler's 1998 back door and the PBS back doors (the type of back door is not recorded, so no persistence technique can be chosen); T1534 Internal Spearphishing for the rootkit.com step (the administrator sat outside HBGary, so T1598 fits better); T1583.005 Acquire Infrastructure: Botnet (every botnet in the record was built from compromised machines); and T1498.001 and T1499.002 for the PayPal DDoS (LOIC's flood mode is not recorded), which is mapped to T1498 only. The bookmaker floods are mapped to the parent T1498 only, because no source opened describes the flood type.

There is no ATT&CK for ICS or Mobile mapping in this record.

### ATT&CK groups, software and campaigns

None. The library's generated group, software and campaign pages, built from ATT&CK, contain no object for Anonymous, LulzSec, AntiSec, Shadowcrew, CardersMarket, Agobot or LOIC (Confirmed for the library data [54]); the live ATT&CK site was not searched. A search of the library's generated `mitre/groups`, `mitre/software` and `mitre/campaigns` pages at main `e85b5594` on 3 November 2026 found no page naming Anonymous, LulzSec, Agobot or LOIC, and a repeat search at main `cb085a91` on 11 November 2026 found none naming those four, AntiSec, Shadowcrew or CardersMarket (Confirmed for the library data [54]). The library's [Threat Actors](/THREAT_ACTORS.md) page carries a short entry for Anonymous.

### CWE and CAPEC

| Weakness or pattern | Name | Where it appears | Library page | Source |
|---|---|---|---|---|
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | HBGary CMS (Feb 2011); Sony Pictures claim (Jun 2011); rival carding forums (Aug 2006) | Listed in `data/weaknesses/cwe.jsonl`; related to CAPEC-66 | [52][29][31][7][54] |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | HBGary's unsalted MD5 hashes (Feb 2011) | Listed in `data/weaknesses/cwe.jsonl` | [52][29][54] |
| CAPEC-66 | SQL Injection | As CWE-89 | [CAPEC-66](/mitre/capec/CAPEC-66.md) | [52][54] |
| CAPEC-125 | Flooding | Bookmaker extortion, Cyberslam, Operation Payback and Avenge Assange | [CAPEC-125](/mitre/capec/CAPEC-125.md) | [52][54] |

No CVE is cited: The Register does not identify the BIND flaw Butler's 1998 worm used, the HBGary injection was in the hbgaryfederal.com CMS, and no other intrusion names a product vulnerability.

### D3FEND countermeasures

The library's `data/attack/d3fend_countermeasures.jsonl` maps the following countermeasures to this study's techniques (Confirmed for the data [54]); pairing them with these events is this study's reading (Inferred).

| Countermeasure | Id | Mapped in the library to | Where it would have helped |
|---|---|---|---|
| [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) | D3-DQSA | T1190 | The HBGary and Sony Pictures SQL injections |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | D3-ITF | T1190, T1566.002 | Upstream filtering of the floods; web request filtering |
| [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) | D3-ISVA | T1190, T1566.002 | Spotting the floods early |
| [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) | D3-NTSA | T1190, T1566.002 | Signatures for known flood tools |
| [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) | D3-SPP | T1110.002 | The simple HBGary passwords |
| [Credential Hardening](/mitre/d3fend/credential-hardening.md) | D3-CH | T1110.002 | Salted, slow hashes |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | D3-MFA | T1110.002 | Password reuse at HBGary |
| [User Account Permissions](/mitre/d3fend/user-account-permissions.md) | D3-UAP | T1078 | The chief executive as mail administrator |
| [Session Termination](/mitre/d3fend/session-termination.md) | D3-ST | T1133 | Cutting the ssh session on the support server |
| [Email Filtering](/mitre/d3fend/email-filtering.md) | D3-EF | T1566.002 | The Capital One lure |
| [URL Analysis](/mitre/d3fend/url-analysis.md) | D3-UA | T1566.002 | The Capital One lure |

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer, [navigator/library-layers/cybercrime-four-books.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/cybercrime-four-books.json), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 and scores each technique by the strength of the evidence: 100 where a primary document records the behaviour and the fit is direct, 75 where only a book or news report records it, and 40 for analogies and weak fits. Each entry's comment names the source numbers above.

## Cross-cutting themes

- **Markets are run by administrators, and administrators can be turned.** Shadowcrew's VPN, CardersMarket's informant purchase and LulzSec's "rooter" all show the same pattern: the person with the most access to the community is the most valuable cooperator (Inferred, from Confirmed [25] and Reported [7]).
- **Motive changes, mechanics do not.** Extortion and protest floods, card theft and hacktivist data dumps used the same techniques (Inferred, Part 7). Defenders who classify incidents by motive before mechanism lose time.
- **Numbers grow and shrink in the retelling.** The E911 document ran from $79,449 to $13; Sony Pictures' leak from a million accounts to about 100,000; the Butler fraud from $86.4 million to more than $87 million (Part 1, Part 3, Part 4). Prefer the court figure and say which one you use (Inferred).
- **Officials overreach when they do not check the material or the law.** A Secret Service agent did not know the Privacy Protection Act (Confirmed [45]), and the Neidorf case collapsed after the defense showed the document was on sale for $13 (Reported [41][49]); the common cause is this study's reading (Inferred).
- **Civil liberties law grew out of these cases.** The EFF and the Fifth Circuit's reading of stored e-mail under the Wiretap Act are direct products of the 1990 crackdown (Confirmed [46][48]).

### What is overstated and what is understated

- **Overstated: the AT&T crash as a hacker attack.** AT&T's own report puts it on a software update (Confirmed [39]); the suspicion Sterling describes was wrong (Reported [41]).
- **Overstated: the RBN as the hand behind the 2008 Georgia attacks.** The book says RBN services were used, Kaspersky told Menn he doubted state involvement, and Menn himself reports disagreement over which arm of government was connected (Reported [13]).
- **Overstated: the Sony Pictures leak.** The million-account claim became about 100,000 users in the DOJ record (Reported [31]; Confirmed [24]).
- **Understated: how ordinary the HBGary chain was.** A security firm fell to SQL injection, fast hashes and reused passwords (Reported [29]).
- **Understated: how much the informant cases prevented.** The FBI's estimate of at least 300 hacks disrupted, including a water utility, is rarely part of the LulzSec story (Confirmed for the estimate [25]; Inferred that it is rarely told).

## Sources

All sources were opened on 3 November 2026; source 25 was reopened and the library data in source 54 rechecked on 11 November 2026. "Confirmed" marks a primary document, or a faithful reprint of one, as used here; "Reported" marks a book, review or news report. Sources 5, 17, 27, 36 and 37 refuse automated link checkers, so their addresses are given as plain text.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | US Department of Justice, Shadowcrew indictment press release, 28 Oct 2004 | [justice.gov/archive/opa/pr/2004/October/04_crm_726.htm](https://www.justice.gov/archive/opa/pr/2004/October/04_crm_726.htm) | 2026-11-03 | Confirmed |
| 2 | US Secret Service, Operation Firewall nets 28 arrests, 28 Oct 2004 | [secretservice.gov/press/releases/2004/10/...](https://secretservice.gov/press/releases/2004/10/us-secret-services-operation-firewall-nets-28-arrests-international) | 2026-11-03 | Confirmed |
| 3 | DOJ CCIPS, six Shadowcrew defendants plead guilty, 17 Nov 2005 | [justice.gov/archive/criminal/cybercrime/press-releases/2005/mantovaniPlea.htm](https://www.justice.gov/archive/criminal/cybercrime/press-releases/2005/mantovaniPlea.htm) | 2026-11-03 | Confirmed |
| 4 | DOJ CCIPS and USAO W.D. Pa., Butler indicted, 11 Sep 2007 | [justice.gov/archive/criminal/cybercrime/press-releases/2007/butlerIndict.htm](https://www.justice.gov/archive/criminal/cybercrime/press-releases/2007/butlerIndict.htm) | 2026-11-03 | Confirmed |
| 5 | FBI Pittsburgh archive (USAO W.D. Pa. release), Butler sentenced to 13 years, 12 Feb 2010 | `https://archives.fbi.gov/archives/pittsburgh/press-releases/2010/pt021210b.htm` | 2026-11-03 | Confirmed |
| 6 | USAO W.D. Pa., release of 8 Dec 2010 on the Butler prosecution | [justice.gov/archive/usao/paw/news/2010/2010_december/2010_12_08_01.html](https://www.justice.gov/archive/usao/paw/news/2010/2010_december/2010_12_08_01.html) | 2026-11-03 | Confirmed |
| 7 | Kevin Poulsen, Wired feature on Max Butler, December 2008 (the precursor to *Kingpin*) | [wired.com/2008/12/ff-max-butler/](https://www.wired.com/2008/12/ff-max-butler/) | 2026-11-03 | Reported |
| 8 | The Register, Max Vision sentenced to 18 months, 22 May 2001 | [theregister.com/2001/05/22/whitehat_max_vision_gets/](https://www.theregister.com/2001/05/22/whitehat_max_vision_gets/) | 2026-11-03 | Reported |
| 9 | The Register, Max Vision guilty plea, 30 Jun 2009 | [theregister.com/2009/06/30/max_vision_guilty_plea/](https://www.theregister.com/2009/06/30/max_vision_guilty_plea/) | 2026-11-03 | Reported |
| 10 | Publishers Weekly, review of *Kingpin*, 20 Dec 2010 | [publishersweekly.com/9780307588685](https://www.publishersweekly.com/9780307588685) | 2026-11-03 | Confirmed (bibliographic) |
| 11 | Penguin Random House, *Kingpin* book page | [penguinrandomhouse.com/books/197890/kingpin-by-kevin-poulsen/](https://www.penguinrandomhouse.com/books/197890/kingpin-by-kevin-poulsen/) | 2026-11-03 | Reported |
| 12 | Hachette Book Group, *Fatal System Error* book page | [hachettebookgroup.com/titles/joseph-menn/fatal-system-error/9781586489076/](https://www.hachettebookgroup.com/titles/joseph-menn/fatal-system-error/9781586489076/) | 2026-11-03 | Reported |
| 13 | Ellen Messmer, Network World, review of *Fatal System Error*, 26 Jan 2010 | [networkworld.com/article/771585/...](https://www.networkworld.com/article/771585/security-book-examines-how-u-s-mobsters-russian-gangsters-have-rampaged-across-the-internet.html) | 2026-11-03 | Reported |
| 14 | Out-Law (Pinsent Masons), Russian bookmaker hackers jailed for eight years, Oct 2006 | [pinsentmasons.com/out-law/news/russian-bookmaker-hackers-jailed-for-eight-years](https://www.pinsentmasons.com/out-law/news/russian-bookmaker-hackers-jailed-for-eight-years) | 2026-11-03 | Reported |
| 15 | Wikipedia, *Fatal System Error* | [en.wikipedia.org/wiki/Fatal_System_Error](https://en.wikipedia.org/wiki/Fatal_System_Error) | 2026-11-03 | Reported |
| 16 | Rick Howard, Cybersecurity Canon review of *Fatal System Error*, Palo Alto Networks blog | [paloaltonetworks.com/blog/?p=4767](https://www.paloaltonetworks.com/blog/?p=4767) | 2026-11-03 | Reported |
| 17 | Akamai Technologies, Form 8-K on the Prolexic closing, Feb 2014 | `https://www.sec.gov/Archives/edgar/data/0001086222/000126643214000049/form8-kprolexicclosing.htm` | 2026-11-03 | Confirmed |
| 18 | Brian Krebs, Washington Post, on the Russian Business Network, 13 Oct 2007 (InfoSec News reprint) | [seclists.org/isn/2007/Oct/66](https://seclists.org/isn/2007/Oct/66) | 2026-11-03 | Reported |
| 19 | FBI wanted notice for Saad (Jay R.) Echouafni, archived Oct 2004 | [webharvest.gov/peth04/20041015032315/http:/www.fbi.gov/mostwant/alert/echouafni.htm](https://webharvest.gov/peth04/20041015032315/http:/www.fbi.gov/mostwant/alert/echouafni.htm) | 2026-11-03 | Confirmed |
| 20 | USAO C.D. Cal., release 08-135, Walker and Gembe indicted, 2 Oct 2008 | [justice.gov/archive/usao/cac/Pressroom/pr2008/135.html](https://www.justice.gov/archive/usao/cac/Pressroom/pr2008/135.html) | 2026-11-03 | Confirmed |
| 21 | Virus Bulletin, eight years for Russian DoS blackmailers, Oct 2006 | [virusbulletin.com/blog/2006/10/eight-years-russian-dos-blackmailers](https://www.virusbulletin.com/blog/2006/10/eight-years-russian-dos-blackmailers) | 2026-11-03 | Reported |
| 22 | The Register, NHTCU and the Russian extortion arrests, 21 Jul 2004 | [theregister.com/2004/07/21/cyber_shakedown_taken_down/](https://www.theregister.com/2004/07/21/cyber_shakedown_taken_down/) | 2026-11-03 | Reported |
| 23 | The Next Web, how DDoS attacks became a frontline tool | [thenextweb.com/news/how-ddos-attacks-became-the-frontline-tool-of-cyber-war](https://thenextweb.com/news/how-ddos-attacks-became-the-frontline-tool-of-cyber-war) | 2026-11-03 | Reported |
| 24 | USAO S.D.N.Y., six hackers charged, 6 Mar 2012 | [justice.gov/archive/usao/nys/pressreleases/March12/ackroyd.html](https://www.justice.gov/archive/usao/nys/pressreleases/March12/ackroyd.html) | 2026-11-03 | Confirmed |
| 25 | Government sentencing memorandum, *US v. Monsegur*, 11 Cr. 666 (LAP), S.D.N.Y., filed May 2014 (PDF hosted by SecurityWeek) | [securityweek.com/sites/default/files/features/monsegur-029-030.pdf](https://www.securityweek.com/sites/default/files/features/monsegur-029-030.pdf) | 2026-11-03; 2026-11-11 | Confirmed |
| 26 | The Register, FBI arrests over Anonymous attacks, 19 Jul 2011 | [theregister.com/2011/07/19/anonymous_hacking_arrests/](https://www.theregister.com/2011/07/19/anonymous_hacking_arrests/) | 2026-11-03 | Reported |
| 27 | phys.org, guilty pleas in the PayPal attack case, Dec 2013 | `https://phys.org/news/2013-12-guilty-paypal-servers.html` | 2026-11-03 | Reported |
| 28 | CBS News, 13 indicted over Operation Payback, Oct 2013 | [cbsnews.com/news/13-members-of-hacking-group-anonymous-indicted-over-operation-payback/](https://www.cbsnews.com/news/13-members-of-hacking-group-anonymous-indicted-over-operation-payback/) | 2026-11-03 | Reported |
| 29 | Ars Technica, the inside story of the HBGary hack, Feb 2011 | [arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/](https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/) | 2026-11-03 | Reported |
| 30 | NBC News, PBS hacked, May 2011 | [nbcnews.com/news/amp/wbna43214259](https://www.nbcnews.com/news/amp/wbna43214259) | 2026-11-03 | Reported |
| 31 | The Next Web, hackers claim release of Sony Pictures user data, 2 Jun 2011 | [thenextweb.com/news/hackers-claim-release-of-1-million-sony-pictures-users-information-in-torrent-file](https://thenextweb.com/news/hackers-claim-release-of-1-million-sony-pictures-users-information-in-torrent-file) | 2026-11-03 | Reported |
| 32 | NBC News, LulzSec hacker gets a year in prison for the Sony Pictures breach, Apr 2013 | [nbcnews.com/tech/tech-news/lulzsec-hacker-gets-year-prison-sony-pictures-breach-flna1c9511589](https://www.nbcnews.com/tech/tech-news/lulzsec-hacker-gets-year-prison-sony-pictures-breach-flna1c9511589) | 2026-11-03 | Reported |
| 33 | USAO S.D.N.Y., Hammond sentenced to 10 years, 15 Nov 2013 | [justice.gov/archive/usao/nys/pressreleases/November13/HammondJeremySentencingPR.php](https://www.justice.gov/archive/usao/nys/pressreleases/November13/HammondJeremySentencingPR.php) | 2026-11-03 | Confirmed |
| 34 | USAO S.D.N.Y., Monsegur sentenced to time served, 27 May 2014 | [justice.gov/archive/usao/nys/pressreleases/May14/MonsegurHectorSentencingPR.php?print=1](https://www.justice.gov/archive/usao/nys/pressreleases/May14/MonsegurHectorSentencingPR.php?print=1) | 2026-11-03 | Confirmed |
| 35 | The Register, LulzSec sentencing at Southwark Crown Court, 16 May 2013 | [theregister.com/2013/05/16/lulzsec_sentencing/](https://www.theregister.com/2013/05/16/lulzsec_sentencing/) | 2026-11-03 | Reported |
| 36 | FBI archive (DOJ), sixteen individuals arrested for alleged roles in cyber attacks, 19 Jul 2011 | `https://archives.fbi.gov/archives/news/pressrel/press-releases/sixteen-individuals-arrested-in-the-united-states-for-alleged-roles-in-cyber-attacks` | 2026-11-03 | Confirmed |
| 37 | FBI New York archive, six hackers charged, 6 Mar 2012 | `https://archives.fbi.gov/archives/newyork/press-releases/2012/six-hackers-in-the-united-states-and-abroad-charged-for-crimes-affecting-over-one-million-victims` | 2026-11-03 | Confirmed |
| 38 | NPR, former LulzSec hacker turned informant avoids further jail time, 27 May 2014 | [npr.org/sections/thetwo-way/2014/05/27/316337873/...](https://www.npr.org/sections/thetwo-way/2014/05/27/316337873/former-lulzsec-hacker-turned-informant-avoids-further-jail-time) | 2026-11-03 | Reported |
| 39 | AT&T, official report on the 15 Jan 1990 crash, reprinted in RISKS Digest 9.63 | [catless.ncl.ac.uk/Risks/9/63/](https://catless.ncl.ac.uk/Risks/9/63/) | 2026-11-03 | Confirmed (reprint) |
| 40 | RISKS Digest 9.62, quoting Telephony, 22 Jan 1990 | [catless.ncl.ac.uk/Risks/9/62/](https://catless.ncl.ac.uk/Risks/9/62/) | 2026-11-03 | Confirmed (as quoted) |
| 41 | Bruce Sterling, *The Hacker Crackdown*, Project Gutenberg eBook #101 (text at gutenberg.org/cache/epub/101/pg101.txt) | [gutenberg.org/ebooks/101](https://www.gutenberg.org/ebooks/101) | 2026-11-03 | Reported (book) |
| 42 | Government sentencing memorandum, Atlanta Three (N.D. Ga.), reprinted in Computer Underground Digest 2.16 | [exploit-db.com/ezines/.../CUD/CUD_2_16.TXT](https://www.exploit-db.com/ezines/kr5hou2zh4qtebqk.onion/CUD/CUD_2_16.TXT) | 2026-11-03 | Confirmed (reprint) |
| 43 | Foley search-warrant affidavit, 28 Feb 1990, as reproduced by Steve Jackson Games | [sjgames.com/SS/affidavit.html](https://www.sjgames.com/SS/affidavit.html) | 2026-11-03 | Confirmed (reprint) |
| 44 | US Attorney, D. Ariz., Operation Sundevil press release of 9 May 1990, reprinted in Computer Underground Digest 1.09 | [exploit-db.com/ezines/.../CUD/CUD109.TXT](https://www.exploit-db.com/ezines/kr5hou2zh4qtebqk.onion/CUD/CUD109.TXT) | 2026-11-03 | Confirmed (reprint) |
| 45 | *Steve Jackson Games v. US Secret Service*, W.D. Tex., decision of 12 Mar 1993, as reproduced by Steve Jackson Games | [sjgames.com/SS/decision-text.html](https://www.sjgames.com/SS/decision-text.html) | 2026-11-03 | Confirmed (reprint) |
| 46 | *Steve Jackson Games v. US Secret Service*, 5th Cir. No. 93-8661, 31 Oct 1994, as reproduced by Steve Jackson Games | [sjgames.com/SS/appeal-opinion.html](https://www.sjgames.com/SS/appeal-opinion.html) | 2026-11-03 | Confirmed (reprint) |
| 47 | Steve Jackson Games, summary of the Secret Service case | [sjgames.com/SS/](https://www.sjgames.com/SS/) | 2026-11-03 | Reported |
| 48 | Electronic Frontier Foundation, history page | [eff.org/about/history](https://www.eff.org/about/history) | 2026-11-03 | Confirmed (founding); Reported (layoffs) |
| 49 | Dorothy Denning, on *US v. Craig Neidorf*, *Communications of the ACM*, Mar 1991, EFF archive copy | [w2.eff.org/Net_culture/Hackers/us_v_craig_neidoff.article](https://w2.eff.org/Net_culture/Hackers/us_v_craig_neidoff.article) | 2026-11-03 | Reported |
| 50 | *Steve Jackson Games v. US Secret Service*, 36 F.3d 457 (5th Cir. 1994), Justia | [law.justia.com/cases/federal/appellate-courts/F3/36/457/563168/](https://law.justia.com/cases/federal/appellate-courts/F3/36/457/563168/) | 2026-11-03 | Confirmed |
| 51 | MITRE ATT&CK, T1498.001 Direct Network Flood (checked, left out of the mapping) and the other live-checked technique pages in Part 7 | [attack.mitre.org/techniques/T1498/001/](https://attack.mitre.org/techniques/T1498/001/) | 2026-11-03 | Confirmed (ids) |
| 52 | MITRE CAPEC, CAPEC-66 SQL Injection (with CAPEC-125, CWE-89 and CWE-916) | [capec.mitre.org/data/definitions/66.html](https://capec.mitre.org/data/definitions/66.html) | 2026-11-03 | Confirmed (ids) |
| 53 | TeamStarWolf library, generated technique pages | [github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques) | 2026-11-03 | Confirmed (library data) |
| 54 | TeamStarWolf library data at main `e85b5594` (3 Nov 2026) and `cb085a91` (11 Nov 2026): `data/attack/technique_profiles.jsonl`, `data/attack/d3fend_countermeasures.jsonl`, `data/weaknesses/cwe.jsonl`, the `mitre/` pages and [CYBERSECURITY_BOOK_LIST.md](/CYBERSECURITY_BOOK_LIST.md) | [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) | 2026-11-03; 2026-11-11 | Confirmed (library data) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Cybersecurity Book List](/CYBERSECURITY_BOOK_LIST.md), the source list for this study
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md)
- Related case studies: [The Cuckoo's Egg Intrusion, 1986](/case-studies/CUCKOOS_EGG_1986.md), the other book-derived study of an early intrusion; [The Zero-Day Trade and Its Fallout](/case-studies/ZERO_DAY_MARKET_EVENTS.md), the book-derived study of the exploit market that followed; [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md), for the attributed Russian state record; this study does not tie the Russian Business Network to it
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- Techniques: [T1566 Phishing](/mitre/techniques/T1566.md), [T1566.002 Spearphishing Link](/mitre/techniques/T1566-002.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1598 Phishing for Information](/mitre/techniques/T1598.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1114.002 Remote Email Collection](/mitre/techniques/T1114-002.md), [T1005 Data from Local System](/mitre/techniques/T1005.md), [T1213 Data from Information Repositories](/mitre/techniques/T1213.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1657 Financial Theft](/mitre/techniques/T1657.md)
- CAPEC: [CAPEC-66 SQL Injection](/mitre/capec/CAPEC-66.md), [CAPEC-125 Flooding](/mitre/capec/CAPEC-125.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [cybercrime-four-books.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/cybercrime-four-books.json)
- [All case studies](/case-studies/README.md)
