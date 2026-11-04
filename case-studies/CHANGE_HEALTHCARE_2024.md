# The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Healthcare Security](/HEALTHCARE_SECURITY_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [Identity Security](/IDENTITY_SECURITY_REFERENCE.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Log4Shell](/case-studies/LOG4SHELL.md)

## Executive summary

In late February 2024, pharmacists across the United States found they could not run insurance claims, and practice managers found that the payments they lived on had stopped arriving. Military pharmacies fell back to manual checks and offline procedures (Confirmed [60]). Within three weeks, 94 percent of the hospitals the American Hospital Association surveyed reported a financial hit, and 74 percent reported an effect on direct patient care (Confirmed [55]). More than half of the respondents to an American Medical Association survey, most of them from practices of ten or fewer physicians, had paid practice expenses out of their own pockets (Confirmed [58]). The cause was a single company most patients had never heard of: Change Healthcare, a claims and payments clearinghouse owned by UnitedHealth Group (UHG), whose systems had been encrypted by ransomware on the morning of 21 February (Confirmed [14][17]).

The entry was ordinary. On 12 February 2024 someone logged in to a Change Healthcare Citrix remote-access portal with compromised credentials. The portal did not require a second factor (Confirmed [14][17]). The intruder moved laterally, copied data out between 17 and 20 February, and deployed ransomware nine days after getting in (Confirmed [14][17][19]). An actor calling itself ALPHV or BlackCat claimed the attack (Confirmed [14][28]). UHG paid the $22 million ransom it was asked for, in Bitcoin (Confirmed [17]). The payment did not end the extortion: ALPHV disappeared behind what researchers judged a fake law-enforcement seizure notice, an affiliate complained that it had been cheated of its share, and in April a second group, RansomHub, posted samples of Change data and set a deadline to sell it (Reported [64][65][67]; Confirmed that screenshots were posted [6]).

The data loss became the largest in the history of the federal health breach portal. Change Healthcare's first report to the HHS Office for Civil Rights (OCR) in July 2024 listed a 500-person placeholder; the count rose to about 100 million notices in October 2024, about 190 million affected people in January 2025 and about 192.7 million in July 2025 (Confirmed [20]). The portal row today reads 192,700,000, far ahead of the next-largest entry, Anthem's 78.8 million in 2015 (Confirmed [22]). UHG's 2024 annual report put direct response costs for the year at $2.2 billion, plus $867 million of lost business at Optum Insight (Confirmed [11]), and the company advanced more than $9 billion in accelerated funding and interest-free loans to providers whose payments had stopped (Confirmed [11][12]). The cost was still moving in late 2025, when UHG raised its reserves against those loans and other customer balances by $799 million (Confirmed [12]).

This study is the library's home for the Change Healthcare record. It also answers a practical question: when someone says "the big healthcare attack last year", which one do they mean? Part 9 lists the largest healthcare breaches reported in 2025 and 2026 so the events can be told apart.

### Key facts at a glance

| Item | Detail | Grade |
|---|---|---|
| Victim | Change Healthcare, a business associate clearinghouse owned by UnitedHealth Group (acquired late 2022) | Confirmed [17][22] |
| Initial access | 12 Feb 2024: compromised credentials on a Citrix remote-desktop portal with no multifactor authentication | Confirmed [14][17] |
| Alleged credential source | A low-level support employee's Citrix username and password posted in a Telegram group on or about 11 Feb 2024 (State of Nebraska's allegation) | Confirmed as an allegation [46] |
| Dwell time | Nine days from the 12 Feb login to the 21 Feb ransomware deployment, with lateral movement and exfiltration in between | Confirmed [14][17] |
| Exfiltration window | 17 to 20 Feb 2024 | Confirmed [17][19] |
| Encryption | Morning of 21 Feb 2024; UHG severed connectivity to Change data centers and called the FBI within hours | Confirmed [14][17] |
| Claimed by | An actor calling itself ALPHV or BlackCat; the first SEC filing said "suspected nation-state", corrected to cybercrime actors on 8 Mar 2024 | Confirmed [1][2][14][28] |
| Ransom | $22 million in Bitcoin, paid by UHG; a matching 350 BTC transfer to an ALPHV-linked address on 1 Mar 2024 | Confirmed [17]; Reported for the transfer [65][64] |
| Second extortion | RansomHub listed Change data in April 2024 with a sale deadline; UHG says an actor it did not name posted 22 screenshots for about a week | Reported [61][67]; Confirmed for the screenshots [6] |
| People affected | About 192.7 million (notice to OCR, 31 Jul 2025); 192,700,000 on the HHS breach portal | Confirmed [20][22] |
| Rank | Largest entry on the HHS OCR breach portal, ahead of Anthem (78.8 million, 2015) and Conduent (62.2 million, 2025) | Confirmed [22] |
| Restoration | Pharmacy claims first (99 percent of pharmacies by 7 Mar 2024), payments from 15 Mar, medical claims from 18 Mar; "majority" of services restored by mid-2024 | Confirmed [3][5][9][17] |
| 2024 cost | $2.2 billion direct response costs plus $867 million business disruption | Confirmed [11] |
| Provider relief | More than $9 billion in interest-free loans and accelerated funding from UHG; CMS paid more than $2.55 billion to Part A providers and $717.18 million to Part B suppliers (about $3.27 billion together, this study's sum) | Confirmed [11][53]; Inferred for the sum |
| CVE | None. The record describes stolen credentials on a portal without MFA, not a software flaw | Confirmed [14][17]; Inferred that no CVE applies |
| ATT&CK objects | Software S1068 BlackCat; S1212 RansomHub (second extortion); no ATT&CK group or campaign object for ALPHV or this attack | Confirmed [30][31][33] |
| Litigation | MDL No. 3108 in the District of Minnesota (centralized 7 Jun 2024); Nebraska's state suit survived a motion to dismiss in November 2025 | Confirmed [48][47] |

### Key findings

- **One missing control opened the door.** UHG's own policy required MFA on external-facing systems; the portal was a legacy Change server that had not yet been brought up to that standard (Confirmed [17]). The record describes no exploit, only a password (Confirmed [14][17]).
- **The early attribution was wrong, and the filing said so two weeks later.** "Suspected nation-state" on 22 February became "cybercrime threat actors" on 8 March and never came back in later filings (Confirmed [1][2]). No primary source opened ties the attack to a state, to China, or to Scattered Spider (Inferred from [14][18][25][27]; Reported for the unverified China claim [73]).
- **Paying did not buy the data back.** UHG paid $22 million (Confirmed [17]); ALPHV apparently kept the whole sum and vanished, and a second group surfaced with the data within five weeks (Reported [64][65][67]). The House committee staff could not confirm whether UHG paid that second group (Confirmed [18]).
- **The outage was a sector outage.** Change carries roughly 15 billion transactions a year by the Senate Finance chairman's count, and about 6 percent of all U.S. health care payments by UHG's (Confirmed [17][6]). Senator Wyden said exclusive contracts kept more than a third of providers from switching (Confirmed that he said so [17]); two-thirds of surveyed hospitals found switching difficult (Confirmed [56]).
- **Backups were inside the blast radius.** Witty testified that the attack reached both the primary and backup environments, built before the acquisition, and called that the root cause of the slow restoration (Confirmed [17]).
- **The count grew for a year.** From a 500-person placeholder in July 2024 to 192.7 million in July 2025 (Confirmed [20]). Early figures in policy documents, such as the 112 million cited in the 2025 HIPAA proposal, are superseded (Confirmed [37][20]).
- **The cost outran the incident year.** About $3.1 billion in 2024 cost lines, more than $9 billion in funding and loans, and a $799 million reserve increase in the fourth quarter of 2025 (Confirmed [11][12]; Inferred for the sum).
- **Policy proposals followed; rules did not.** The HIPAA Security Rule proposal of January 2025 cites this breach and would require MFA, segmentation and 72-hour restoration procedures, but no final rule exists and the agenda now targets July 2027 (Confirmed [37][39]). A Senate bill requiring minimum practices such as MFA passed the Senate in September 2026 and is held at the House desk (Confirmed [44]).

### Top recommendations

1. **Find every internet-facing remote-access service and require phishing-resistant MFA on all of them,** starting with acquired companies' estates on day one (Confirmed [23][35]; Inferred for the acquisition point from [17]).
2. **Isolate backups from the production identity and network planes,** and test restoration into a clean environment on a schedule; the January 2025 proposal would require written procedures to restore critical systems and data within 72 hours and backup testing at least every six months (Confirmed [37]).
3. **Watch the quiet days, not only the loud one.** Alleged new privileged accounts, nine days of lateral movement and four days of data exfiltration came before the encryption that was actually detected (Confirmed as an allegation [46]; Confirmed [14][17]; Inferred for the detection plan).
4. **Keep a tested second clearinghouse or payments path,** and do not sign exclusivity clauses that prevent one (Confirmed [17]; Inferred for the continuity plan from [56]).
5. **Plan for the extortion after the ransom.** Assume a payment does not end data exposure, and prepare notification, credit monitoring and partner communications before the next incident (Inferred from [6][17][67]).

## Scope and method

This study covers the Change Healthcare intrusion from the alleged credential posting of 11 February 2024 through the court, regulatory and financial record to 3 November 2026: the technical record, the timeline, the actors and the attribution, the ransom and the second extortion, the effect on care and payments, the data breach and its count, the costs, the government, legal and policy response, and the defender and vulnerability-management views. It draws on UHG's SEC filings and press releases, Andrew Witty's written testimony to the House Energy and Commerce Committee and the printed Senate Finance Committee hearing record with its answers for the record, the House committee staff memo, Change Healthcare's HIPAA substitute notice and status page, the HHS OCR FAQ and breach portal, CISA and FBI advisories, CMS notices, AHA and AMA surveys, the Nebraska Attorney General's complaint and court order, the federal multidistrict litigation record, the Federal Register and Unified Agenda, Congress.gov, the disclosures of later breach victims, and press reporting where no primary exists. Every source was opened on 3 November 2026. Quotations are kept to a few words. MITRE ids were checked against the live ATT&CK site or the library's data files.

The study is the library's home for this event. Ransomware-as-a-service in general, ALPHV's other victims and the RansomHub operation are summarized only as far as they explain this case. For a contrast between a credential-driven breach and a vulnerability-driven one, see [the Log4Shell study](/case-studies/LOG4SHELL.md); for data-theft extortion at scale without encryption, see [the Cl0p MOVEit study](/case-studies/CL0P_FILE_TRANSFER_2023.md).

| Grade | Meaning |
|---|---|
| Confirmed | A primary source was opened: UHG or Change Healthcare, a government agency, a court record, an SEC filing, a hearing record, a breach notice, or the MITRE record itself |
| Reported | Known only through a secondary source, such as press coverage, or a document quoted by another party whose original could not be opened |
| Demonstrated | A public reproduction or tool exists |
| Inferred | This study's own reasoning from the cited facts, labelled where it appears |

Three rules matter for this incident. First, statements in the Nebraska complaint are allegations in a pleading; the opened complaint is the primary record of what the State alleged, so they are graded "Confirmed as an allegation". Second, attribution words are carried exactly as each source used them: "suspected nation-state", "cybercrime threat actors", "represented itself to us as ALPHV/Blackcat" and "it has been reported" are different claims. Third, the dollar figures are UHG's own reported line items; any total that adds them is marked as this study's arithmetic.

## Part 1: the technical record

### Entry: a password and no second factor

Witty's written testimony to the House is the anchor. On 12 February 2024, criminals used compromised credentials to remotely access a Change Healthcare Citrix portal, an application used for remote access to desktops (Confirmed [14]). His statement is blunt: "The portal did not have multi-factor authentication" (Confirmed [14]). The prepared statement printed in the Senate record says the same, and in the Senate hearing he described the portal as not protected by multifactor authentication (Confirmed [17]).

The Nebraska Attorney General's complaint adds detail the company has not stated. It alleges that on or about 11 February 2024 the username and password of a low-level customer-support employee's Citrix account were posted in a Telegram group that sells stolen credentials (Confirmed as an allegation [46]). No opened source says how the credentials were first stolen, and no opened source names a Citrix vulnerability as the vector (Inferred from [14][17][46]).

### Nine days inside

After getting in, the actor moved laterally and exfiltrated data; "Ransomware was deployed nine days later" (Confirmed [14]). The testimony names no protocol, tool or channel for either step (Confirmed [14][15]). The Nebraska complaint alleges that the intruder moved from the user-level virtual-desktop account to the server hosting the SelectRX medication-management application and created privileged accounts with administrator capabilities, and that none of this was detected until encryption more than a week later (Confirmed as an allegation [46]). The House committee staff memo relays Wall Street Journal reporting that the hackers moved laterally between 12 and 21 February (Confirmed that the memo says so [18]; the WSJ article was not opened).

UHG's answer for the record to Senator Grassley dates the theft of protected health information to 17 through 20 February 2024 (Confirmed [17]). Change Healthcare's substitute notice gives the same window and says Change learned of the ransomware on 21 February (Confirmed [19]).

### Encryption and severance

On the morning of 21 February, an actor calling itself ALPHV or BlackCat deployed ransomware inside Change Healthcare's environments and encrypted its systems (Confirmed [14][17]). UHG severed connectivity with Change's data centers, contacted the FBI within hours and shared indicators of compromise and the method of attack (Confirmed [14][15][17]). UHG reports no evidence that the attack spread beyond Change to Optum, UnitedHealthcare or the rest of UHG (Confirmed [14]). In answers for the record, UHG said it knew of no ransomware attack after the one ALPHV/BlackCat claimed on 21 February (Confirmed [17]).

### Why recovery took so long

Witty told the Senate that the attack reached both the primary and the backup environments, partly because the affected technology was aging and largely not in the cloud; cloud-hosted elements were restored almost at once (Confirmed [17]). He said the attack locked up backup systems that had been built inside Change before the acquisition and called that the root cause of the slow restoration (Confirmed [17]). Asked why backups were not segregated, UHG answered that redundancy existed across servers and data centers and that it was mid-upgrade of primary and redundant servers; the answer does not say the backups were segregated (Confirmed [17]). The Nebraska complaint alleges the backups were not isolated from the primary environment and that the lack of segmentation let the intruder move among systems freely (Confirmed as an allegation [46]).

### The rebuild

The response team replaced thousands of laptops, rotated credentials, and rebuilt the data center network and core services (Confirmed [14]). UHG reissued about 11,000 clean devices, most within two weeks (Confirmed [17]). Each service came back from pre-incident backups into a newly built environment, and each needed key and credential rotation, restoration, remediation, scanning by at least two vendors, security testing and validation before reconnection (Confirmed [17]). Mandiant and Palo Alto Networks were on site, and by the afternoon of 21 February experts from Google, Microsoft, Cisco, Amazon and others were on their way to Change's Nashville operations center (Confirmed [14][17]). Pharmacy came back first (Confirmed [17]).

### What the record does not say

The public record does not identify the malware build, the lateral movement method, the exfiltration channel, the volume taken, or the affiliate who did the work (Inferred from [14][17][18][46]). The data volumes in circulation are actors' claims: ALPHV claimed about 6 TB on 28 February, and the affiliate and RansomHub each claimed about 4 TB (Reported [63][64][67]). No primary source opened confirms any of these figures.

## Part 2: the timeline

| Date | Event | Source | Grade |
|---|---|---|---|
| Late 2022 | UHG acquires Change Healthcare; legacy Change servers are still being brought to UHG standards in 2024 | [17] | Confirmed |
| Feb 2023 | ALPHV announces its "Sphynx" update, able to encrypt Windows, Linux and VMware instances | [23] | Confirmed |
| 16 Nov 2023 | FBI and CISA advisory on Scattered Spider says the group has been known to use BlackCat/ALPHV ransomware | [25] | Confirmed |
| 19 Dec 2023 | FBI disruption of ALPHV: a decryptor offered to about 500 victims and 946 key pairs for ALPHV Tor sites obtained; AA23-353A first published | [71][23] | Reported for the operation details; Confirmed for the advisory |
| Dec 2023 | After the disruption, an ALPHV administrator urges affiliates to target hospitals; ALPHV lifts most affiliate restrictions and raises the affiliate share to 90 percent | [23][71] | Confirmed for the urging; Reported for the terms |
| 24 or 25 Jan 2024 | HHS releases voluntary healthcare cybersecurity performance goals, including MFA and network segmentation | [41][36] | Confirmed (sources differ by one day) |
| Early Feb 2024 | RansomHub launched on the RAMP forum with a 10 percent operator split | [67] | Reported |
| About 11 Feb 2024 | A support employee's Citrix credentials allegedly posted in a Telegram group | [46] | Confirmed as an allegation |
| 12 Feb 2024 | Login to the Citrix portal with compromised credentials; no MFA | [14][17] | Confirmed |
| 12 to 21 Feb 2024 | Lateral movement; privileged accounts allegedly created on the SelectRX server | [14][46] | Confirmed; Confirmed as an allegation |
| 17 to 20 Feb 2024 | Exfiltration of protected health information | [17][19] | Confirmed |
| 21 Feb 2024 | Ransomware deployed and systems encrypted; connectivity severed; FBI contacted within hours; Defense Health Agency pharmacies lose claims processing | [14][17][60] | Confirmed |
| 22 Feb 2024 | Form 8-K, Item 1.05: "suspected nation-state associated" actor; no estimate of the disruption's length; not yet judged material | [1] | Confirmed |
| 27 Feb 2024 | AA23-353A update: healthcare the most victimized sector among nearly 70 leaked ALPHV victims since mid-December 2023 | [23] | Confirmed |
| 28 Feb 2024 | ALPHV leak-site post claims about 6 TB of Change data; UHG does not confirm BlackCat | [63] | Reported |
| 29 Feb 2024 | Status page: the actor "has represented itself to us as ALPHV/Blackcat" | [28] | Confirmed |
| 1 Mar 2024 | Optum launches a Temporary Funding Assistance Program; 350 BTC (about $22 million) reaches an ALPHV-linked address | [3][4][65][64] | Confirmed; Reported for the transfer |
| 3 Mar 2024 | Affiliate "notchy" posts on RAMP that ALPHV kept the payment; Nebraska alleges UHG paid on or about this date | [64][46] | Reported; Confirmed as an allegation |
| 5 Mar 2024 | ALPHV shuts down behind a seizure banner researchers judge fake | [64] | Reported |
| 6 Mar 2024 | CMS memo lets Medicare Advantage and Part D plans relax prior authorization and encourages relaxed timely filing | [54] | Confirmed |
| 7 Mar 2024 | E-prescribing fully working; pharmacy claims and payment available; 99 percent of pharmacy network services restored | [3][4][5] | Confirmed |
| 8 Mar 2024 | Form 8-K/A replaces the attribution with "cybercrime threat actors" | [2] | Confirmed |
| 9 Mar 2024 | CMS makes CHOPD accelerated (Part A) and advance (Part B) payments available | [51][52] | Confirmed |
| 9 to 12 Mar 2024 | AHA survey of about 1,000 hospitals fielded (published 15 Mar) | [55][56] | Confirmed |
| 13 Mar 2024 | OCR Dear Colleague letter; investigations of Change Healthcare and UHG opened | [20][57] | Confirmed for the investigations [20]; Reported for the 13 Mar date (HHS release URL, which returned 403, and the AHA and FAH letter [57]) |
| 15 Mar 2024 | Electronic payments platform restored | [5] | Confirmed |
| 18 Mar 2024 | Medical claims software release begins; more than $2 billion advanced to providers | [5] | Confirmed |
| 21 Mar 2024 | AHA and FAH ask OCR to spare hospitals duplicate breach notifications | [57] | Confirmed |
| 26 Mar to 3 Apr 2024 | AMA survey of more than 1,400 practices | [58] | Confirmed |
| 27 Mar 2024 | Rewards for Justice offer of up to $10 million on ALPHV BlackCat (page undated) | [29] | Confirmed for the offer [29]; date not checked |
| 7 to 8 Apr 2024 | RansomHub lists Change Healthcare, claims 4 TB, sets a deadline (20 Apr) | [61][67][68] | Reported |
| 19 to 24 Apr 2024 | AMA follow-up survey (published 29 Apr) | [59] | Confirmed |
| 22 Apr 2024 | UHG: data could cover "a substantial proportion of people in America"; 22 screenshots posted for about a week; 86 percent of payment processing restored | [6][7] | Confirmed |
| 24 Apr 2024 | Form 8-K/A Amendment No. 2 files the 22 April release | [7] | Confirmed |
| 25 Apr 2024 | Defense Health Agency announces full military pharmacy operations restored | [60] | Confirmed |
| 26 Apr 2024 | More than $6.5 billion advanced to providers | [17] | Confirmed |
| 29 Apr 2024 | House committee staff memo | [18] | Confirmed |
| 1 May 2024 | Witty testifies to the Senate Finance Committee and the House Energy and Commerce oversight subcommittee | [14][16][17] | Confirmed |
| 7 Jun 2024 | JPML centralizes the cases as MDL No. 3108 in the District of Minnesota | [48] | Confirmed |
| 17 Jun 2024 | CMS announces CHOPD will close; new applications end 12 Jul | [53] | Confirmed |
| 20 Jun 2024 | Substitute notice; notification of customer entities begins | [19][9] | Confirmed |
| 19 Jul 2024 | Breach report filed with OCR with a 500-person placeholder | [20][22] | Confirmed |
| Late Jul 2024 | Notification of individuals begins | [9] | Confirmed |
| 29 Aug 2024 | CISA AA24-242A on RansomHub (does not mention Change) | [24] | Confirmed |
| 25 Sep 2024 | S.5218 introduced (Wyden) | [42] | Confirmed |
| 22 Oct 2024 | About 100 million individual notices sent | [20] | Confirmed |
| 21 Nov 2024 | S.5390 introduced (Cassidy) | [43] | Confirmed |
| 16 Dec 2024 | Nebraska sues Change Healthcare, UHG and Optum | [45][46] | Confirmed |
| 6 Jan 2025 | HIPAA Security Rule proposal published; comments close 7 Mar 2025 | [37] | Confirmed |
| 24 Jan 2025 | About 130 million notices sent; about 190 million affected | [20] | Confirmed |
| 27 Feb 2025 | FY2024 Form 10-K: about 190 million; no known misuse | [11] | Confirmed |
| 29 Jul 2025 | AA23-320A revision names DragonForce as Scattered Spider's latest ransomware and drops ALPHV | [26] | Confirmed |
| 31 Jul 2025 | About 192.7 million affected | [20][21] | Confirmed |
| 10 Nov 2025 | Nebraska court overrules the motion to dismiss | [47] | Confirmed |
| 2 Dec 2025 | S.3315 introduced (Cassidy) | [44] | Confirmed |
| 19 Dec 2025 | MDL motions to dismiss granted in part and denied in part | [49] | Confirmed |
| Q4 2025 | $799 million reserve increase on provider loans and other balances | [12] | Confirmed |
| 23 Feb 2026 | AHA urges HHS to withdraw the HIPAA proposal | [40] | Confirmed |
| 23 Mar 2026 | HELP Committee reports S.3315 | [44] | Confirmed |
| 30 Apr 2026 | Two U.S. incident responders who worked as BlackCat affiliates sentenced to four years each (not the Change case) | [72] | Reported |
| 16 Jul 2026 | MDL court orders lead counsel to propose mediators | [50] | Confirmed |
| 18 Sep 2026 | Pretrial Order No. 40 denies a separate health-insurer track | [50] | Confirmed |
| 30 Sep 2026 | S.3315 passes the Senate by unanimous consent; the quarter closes with $282 million of loan repayments in nine months and no new cyberattack cost line (Q3 2026 10-Q) | [44][13] | Confirmed |
| 5 Oct 2026 | S.3315 held at the House desk | [44] | Confirmed |
| 8 Oct 2026 | Pretrial Order No. 42 modifies the schedule; no settlement or class certification shown | [50] | Confirmed |
| 19 Nov 2026 | Next MDL status conference | [50] | Confirmed |

## Part 3: the actors and the attribution

### From "nation-state" to "cybercrime"

UHG's first filing, made the day after the encryption, said it had identified a "suspected nation-state associated cyber security threat actor" (Confirmed [1]). The word "suspected" was the filer's own hedge. On 29 February the company's status page said the actor had represented itself as ALPHV/Blackcat (Confirmed [28]); on 8 March the amended filing replaced the attribution with "cybercrime threat actors" (Confirmed [2]). The nation-state wording does not return in later 10-Q or 10-K filings (Confirmed [9][11]). The lesson for response teams is that an attribution in the first public filing can be wrong, so playbooks should not hinge on it (Inferred from [1][2]).

Every later company statement describes self-identification, not independent attribution: the actor represented itself as ALPHV (Confirmed [28]), and Witty described "a cybercriminal calling themselves ALPHV or BlackCat" (Confirmed [15]). The House staff memo says only that ALPHV's responsibility "has been reported" (Confirmed [18]). This study found no public FBI or CISA statement attributing the Change attack specifically (Inferred from absence; the search was not exhaustive [23][24]).

### ALPHV/BlackCat as the government describes it

The joint FBI, CISA and HHS advisory AA23-353A describes ALPHV Blackcat as ransomware as a service (Confirmed [23]). The State Department's Rewards for Justice page describes it as first deployed in 2021, with members who develop the ransomware, recruit affiliates and share in paid ransoms (Confirmed [29]). The House staff memo relays the Justice Department's description of a prolific, Russia-based ransomware group (Confirmed [18]). ATT&CK records it as software [S1068 BlackCat](/mitre/software/S1068.md), with aliases ALPHV and Noberus, and lists one group user, [G1015 Scattered Spider](/mitre/groups/G1015.md); there is no ATT&CK group object for ALPHV itself (Confirmed [30][33]).

The advisory's 27 February 2024 update, six days after the encryption, says that since mid-December 2023 healthcare was the most victimized sector among nearly 70 leaked ALPHV victims, likely because an ALPHV administrator urged affiliates to target hospitals after law enforcement action against the group in early December (Confirmed [23]). The advisory does not name Change Healthcare (Confirmed [23]). Press reporting of the December operation says the FBI got into ALPHV infrastructure, offered a decryptor to about 500 victims, avoided an estimated $68 million in ransom demands and obtained 946 key pairs for ALPHV Tor sites, and that ALPHV answered by "unseizing" its site, lifting affiliate restrictions except on CIS countries and raising the affiliate share to 90 percent (Reported [71]; the Justice Department release could not be opened).

The advisory's general description of ALPHV affiliates: they pose as IT or help desk staff by phone or SMS to get credentials, use Evilginx2 to capture MFA codes and session cookies, deploy remote tools such as AnyDesk, Mega sync, Splashtop and ScreenConnect, use Plink and Ngrok, claim to use Brute Ratel C4 and Cobalt Strike as command-and-control beacons, use Metasploit, and use POORTRY and STONESTOP to kill security processes (Confirmed [23]). None of this is documented at Change (Inferred from [14][17]).

### The affiliate and the exit

In ransomware as a service, the operators develop the ransomware and recruit affiliates, who carry out the intrusions and share the ransom (Confirmed [29] for ALPHV). The prevailing account of what happened next comes from researchers and the press. On 1 March 2024 a Bitcoin address that Recorded Future and TRM Labs tie to ALPHV received 350 BTC, about $22 million (Reported [65][64]). On 3 March an affiliate posting as "notchy" on the RAMP forum said Change had paid, that ALPHV had kept the affiliate's share, and that the affiliate still held the data (Reported [64]). Affiliates normally earn 60 to 90 percent of a ransom (Reported [64]). On 5 March ALPHV's site went down behind a seizure banner that Emsisoft's Fabian Wosar said was copied from the December 2023 notice, pointing to an exit scam rather than a takedown; the FBI did not comment (Reported [64]). SecurityWeek called the shutdown "likely an exit scam" (Reported [62]).

The prevailing theory is that the affiliate kept the data and took it to RansomHub. The Register says no hard evidence links the two groups, and no primary source opened establishes who the affiliate was (Reported [61]). The House staff memo describes RansomHub as reportedly an offshoot ALPHV affiliate that was not paid from the $22 million (Confirmed that the memo says so [18]).

### Claims this study does not support

- **China.** Menlo Security claimed the affiliate may be tied to a Chinese state-sponsored group but withheld its evidence, and its own post says the allegations lack validation (Reported [73]). Unverified; not adopted.
- **Scattered Spider.** The original Scattered Spider advisory says the group has been known to use BlackCat/ALPHV and may have used it to encrypt VMware ESXi servers (Confirmed [25]); the 2025 revision names DragonForce instead and no longer mentions ALPHV (Confirmed [26]). An HHS HC3 note on help-desk social engineering in health says there was then no public attribution for the health-sector incidents and does not mention Change (Confirmed [27]). Change's documented entry was a login with compromised credentials to a portal without MFA (Confirmed [14]); no opened source says how the credentials were obtained, so nothing in the record ties the entry to help-desk vishing (Inferred from [14][17][46]). Scattered Spider was one ALPHV affiliate among many, so a Scattered Spider attribution for Change is unsupported (Inferred from [14][25][27][30]).
- **A state hand behind ALPHV in this case.** The Rewards for Justice offer seeks information on ALPHV actors acting at a foreign government's direction against U.S. critical infrastructure (Confirmed [29]). That is the reward's legal framing, not a finding about Change (Inferred).

For a record where state attribution is built from indictments and vendor reporting, compare the library's separate APT41 public-record case study.

### RansomHub

CISA's AA24-242A describes RansomHub as ransomware as a service, formerly known as Cyclops and Knight, emerging in February 2024 and drawing affiliates from LockBit and ALPHV, with at least 210 victims including healthcare; it does not mention Change (Confirmed [24]). ATT&CK records it as [S1212 RansomHub](/mitre/software/S1212.md), whose operators may have bought and rebranded Knight resources (Confirmed [31]). According to KELA as quoted by CyberScoop, a user called "koley" launched it on RAMP in early February 2024 with a 10 percent operator split, and RansomHub said many ALPHV affiliates were joining (Reported [67]).

## Part 4: the ransom and the second extortion

Witty's written testimony: "the decision to pay a ransom was mine" (Confirmed [14]). The written House testimony gives no amount (Confirmed [14]). UHG's answer to Senator Warren in the printed Senate record does: "UHG paid the demanded $22 million ransom in Bitcoin" (Confirmed [17]). UHG gave no payment date (Confirmed [17]). The 1 March blockchain transfer is the press-reported match (Reported [65][64]); the Nebraska complaint alleges payment on or about 3 March (Confirmed as an allegation [46]). The two dates are not reconciled in any primary source opened.

In April, RansomHub listed Change Healthcare on its leak site, claimed more than 4 TB of data and set a deadline before selling it: The Register reported a 12-day clock and CyberScoop a 20 April date (Reported [61][67]). RansomHub posted nearly two dozen screenshots and later removed the listing for unknown reasons (Reported [68]). It sent WIRED alleged samples and said it got the data from the cheated affiliates (Reported [66]). UHG's 22 April release confirms that an unnamed threat actor posted 22 screenshots on the dark web for about a week, allegedly taken from exfiltrated files, some containing protected health information and personal information (Confirmed [6][7]). Whether UHG paid RansomHub was not confirmed by the House committee staff (Confirmed [18]). UHG has not said it did (Inferred from the opened filings).

The practical result: one ransom paid, data still offered for sale five weeks later (Reported [61][67]; Confirmed for the screenshots [6]). No opened source says whether the payment produced a working decryptor or whether one was used; the core restoration ran from pre-incident backups into newly built infrastructure (Confirmed [17]).

## Part 5: impact on care and payments

### Scale of the dependency

At the Senate hearing, Chairman Wyden said Change processes roughly 15 billion health care transactions a year and that a third of American patient records pass through it; Senator Crapo called it the largest clearinghouse, processing $1.5 trillion in claims a year (Confirmed [17]). These are the senators' figures, not the company's. UHG's own figure is that Change's payment processing is about 6 percent of all U.S. health care payments (Confirmed [6]).

### What stopped and when it came back

| Function | Down | Restored | Source |
|---|---|---|---|
| Pharmacy claims and e-prescribing | 21 Feb 2024 | E-prescribing fully working and pharmacy claims available 7 Mar; 99 percent of pre-incident pharmacies processing by then | [3][4][5][17] |
| Military pharmacies (TRICARE) | 21 Feb 2024; offline downtime procedures and manual checks | Full operations announced 25 Apr 2024 | [60] |
| Electronic payments platform | 21 Feb 2024 | Open for connection from 15 Mar 2024 | [3][5] |
| Medical claims network | 21 Feb 2024 | Testing and reconnection from 18 Mar 2024 | [3][5] |
| Payment processing volume | | About 86 percent of pre-incident levels on 22 Apr 2024 | [6][7] |
| Overall functionality | | About 80 percent restored on the major platforms on 22 Apr 2024 | [6][7] |
| Services in general | | "Restored the majority" by the Q2 2024 10-Q; "restored or replaced the majority" in the FY2024 10-K | [9][11] |

UHG also suspended most Medicare Advantage outpatient prior authorizations until 31 March (Confirmed [4]) and suspended some care management activities, which added $340 million to its first-quarter medical costs (Confirmed [8]).

### The providers

The AHA survey of nearly 1,000 hospitals, fielded 9 to 12 March 2024, found that 94 percent reported a financial impact, more than half of them "significant or serious"; more than 80 percent said cash flow was affected, and of those nearly 60 percent put the revenue impact at $1 million a day or more; 74 percent reported effects on direct patient care; 67 percent found switching clearinghouses difficult or very difficult and 81 percent found workarounds only somewhat successful (Confirmed [55][56]).

The AMA's informal survey of 26 March to 3 April 2024 drew more than 1,400 responses, 1,097 from practices of ten or fewer physicians: 80 percent lost revenue from unpaid claims, 55 percent used personal funds to cover expenses, 44 percent could not buy supplies, 31 percent could not make payroll and 48 percent moved to alternative clearinghouses (Confirmed [58]). Its follow-up of 19 to 24 April, with more than 590 responses, found 85 percent still had claim payment disruptions, 79 percent could not receive electronic remittance advice, 84 percent said UHG's restoration information was missing or inaccurate, and 26 percent had seen the previous week's revenue fall by more than 70 percent (Confirmed [59]).

### Relief money

Optum launched a Temporary Funding Assistance Program on 1 March 2024 with no fees or interest (Confirmed [3][4]). UHG had advanced more than $2 billion by 18 March (Confirmed [5]) and more than $6.5 billion by 26 April, about 34 percent of it to safety-net hospitals and federally qualified health centers (Confirmed [17]). The 10-Qs report about $3.9 billion through 31 March, more than $6.5 billion through 30 April, more than $9 billion through 30 June and nearly $9 billion through 30 September 2024 (Confirmed [8][9][10]).

CMS told Medicare Administrative Contractors to speed clearinghouse changes and accept paper claims, urged Medicaid managed care plans to pay impacted providers prospectively (Confirmed [52]) and let Medicare Advantage and Part D plans remove or relax prior authorization and encouraged them to relax timely filing (Confirmed [54]). From 9 March 2024 it offered Change Healthcare/Optum Payment Disruption (CHOPD) accelerated payments to Part A providers and advance payments to Part B suppliers, sized at up to 30 days of claims and recouped automatically from Medicare claims over 90 days (Confirmed [51]). By 17 June more than 4,200 Part A providers had received more than $2.55 billion and 4,722 Part B advance payments totaled more than $717.18 million, over 96 percent of it already recovered; new applications closed after 12 July 2024 (Confirmed [53]).

## Part 6: the data breach and the count

### What was taken

UHG's 22 April release said initial sampling found files with protected health information or personal information that "could cover a substantial proportion of people in America", and no evidence that doctors' charts or full medical histories were taken (Confirmed [6]). The substitute notice lists the data types: contact details; health insurance identifiers; health information such as diagnoses, medicines, test results and images; billing and payment data; Social Security numbers; and driver's license and passport numbers (Confirmed [19]). The FY2024 10-K says Change is "not aware of any misuse" of individuals' information and has not seen electronic medical record databases in the data (Confirmed [11]). UHG offered two years of free credit monitoring and offered to make notifications on behalf of providers and customers (Confirmed [7]).

### How the count grew

| Date | Figure | Source | Grade |
|---|---|---|---|
| 19 Jul 2024 | 500 individuals, a placeholder (the minimum that triggers a portal posting) | [20] | Confirmed |
| 22 Oct 2024 | About 100 million individual notices sent | [20][69] | Confirmed |
| 6 Jan 2025 | HIPAA proposal cites an earlier UHG estimate of about 112 million | [37] | Confirmed |
| 24 Jan 2025 | About 130 million notices sent; about 190 million affected | [20] | Confirmed |
| 27 Feb 2025 | FY2024 10-K repeats about 190 million | [11] | Confirmed |
| 31 Jul 2025 | About 192.7 million affected | [20][21] | Confirmed |
| 3 Nov 2026 | Portal: 192,700,000; the FY2025 10-K shows no later revision | [22][12] | Confirmed |

The 31 July 2025 date is what the OCR FAQ states (Confirmed [20][21]). Secondary reporting also gives 31 July 2025 (Reported [70]). The December 2025 MDL order cites the FAQ with a 14 March 2025 date, which matches the FAQ's own 'Updated as of March 14, 2025' header rather than the date of Change's notice (Confirmed [20][49]), so the revision date is cited inconsistently.

### On the portal

The portal row reads "Change Healthcare, Inc.", Minnesota, Business Associate, 192,700,000 individuals, submitted 19 July 2024, Hacking/IT Incident, Network Server (Confirmed [22]). It sits in the portal's archive list, not the list of cases under investigation (Confirmed [22]). That suggests OCR no longer lists the matter as under investigation, but the portal's definition of the archive was not opened and no OCR resolution document was found (Inferred [22]; not checked).

The Change row is about two-thirds of the 290.1 million individuals in all 741 reports submitted in 2024 (Confirmed for the year total [22]; Inferred for the share).

## Part 7: the financial record

| Period | Direct response costs | Optum Insight business disruption | Provider loans and funding | Other | Source |
|---|---|---|---|---|---|
| Q1 2024 | $593 million | $279 million | About $3.9 billion through 31 Mar; more than $6.5 billion through 30 Apr | Suspended care management added $340 million in medical costs | [8] |
| Q2 2024 | $776 million (quarter); $1.4 billion (six months) | $334 million (quarter); $613 million (six months) | More than $9 billion through 30 Jun | | [9] |
| Q3 2024 | $341 million (quarter); $1.7 billion (nine months), now including loan costs and notifications | $134 million (quarter); $747 million (nine months) | Nearly $9 billion through 30 Sep; cash flow shows $8,904 million lent and $3,189 million repaid | | [10] |
| FY2024 | $2.2 billion | $867 million | More than $9 billion through 31 Dec; $9,033 million lent and $4,514 million repaid in the year | | [11][12] |
| FY2025 | | | $1,680 million repaid in the year | Reserves for provider loans and other balances raised by $799 million in Q4 (operating costs, Optum Insight) | [12] |
| Nine months to 30 Sep 2026 | No new cyberattack cost line found | | $282 million repaid (against $1,543 million in the same 2025 period) | | [13] |

The two 2024 cost lines add up to about $3.07 billion (Inferred: this study's arithmetic, not a total UHG reported [11]). The cash flow lines show $6,476 million of the $9,033 million lent repaid through 30 September 2026 (Inferred: this study's sum of [11][12][13]). The difference, about $2.56 billion, is not a reported balance: loans may also be settled outside these lines, and the $799 million reserve shows that UHG expects some will not be collected (Inferred from [12]).

The library's [Notable Incidents](/NOTABLE_INCIDENTS.md) entry carries an older range of $872 million to $2.7 billion; the FY2024 10-K figures above supersede it (Confirmed [11]).

## Part 8: the government, legal and policy record

### Regulators

OCR issued a Dear Colleague letter and opened investigations into whether a breach of protected health information occurred and whether Change Healthcare and UHG complied with HIPAA; its interest in partner covered entities was described as secondary, though they were reminded of their business associate and breach notification duties (Confirmed [20]; Reported for the letter's wording as quoted by the AHA and FAH [57]). The 13 March 2024 date comes from the HHS release address and the AHA and FAH letter; the release itself could not be opened (Reported [57]). The AHA and the Federation of American Hospitals asked OCR on 21 March to confirm that hospitals need not send duplicate notices if Change notified (Confirmed [57]).

### Congress

Witty testified on 1 May 2024 before the Senate Finance Committee ("Hacking America's Health Care") and the House Energy and Commerce oversight subcommittee ("Examining the Change Healthcare Cyberattack") (Confirmed [16]). Beyond the facts used in Parts 1 to 5, the hearing record carries three admissions that matter to defenders: all of UHG's external-facing systems had MFA as of that day (Confirmed [17]); some legacy Change contracts had exclusivity clauses, which UHG was releasing and agreed not to use in future (Confirmed [17]); and UHG had rerouted some clients to competitors and now encourages clients to keep at least two alternative channels (Confirmed [17]). Wyden said the exclusive contracts kept more than a third of providers from switching clearinghouses, and Senator Hassan said such terms create single points of failure (Confirmed [17]). UHG holds HITRUST certifications across many applications, including certain Change systems; its answer does not say whether those audits found the missing MFA (Confirmed [17]).

Bills followed. S.5218, the Health Infrastructure Security and Accountability Act of 2024 (Wyden), and S.5390, the Health Care Cybersecurity and Resiliency Act of 2024 (Cassidy), died in committee in the 118th Congress (Confirmed [42][43]). S.3315, the Health Care Cybersecurity and Resiliency Act of 2026, passed the Senate by unanimous consent on 30 September 2026 and has been held at the House desk since 5 October 2026; per the CRS summary it would have HHS require minimum cybersecurity practices such as MFA, coordinate HHS and CISA, add rural guidance and require breach notices to state the number of people affected (Confirmed [44]).

### The courts

| Case | Event | Source | Grade |
|---|---|---|---|
| In re Change Healthcare, Inc. Customer Data Security Breach Litigation, MDL No. 3108 (D. Minn., Judge Donovan W. Frank) | Centralized 7 Jun 2024 | [48] | Confirmed |
| MDL 3108 | 19 Dec 2025: motions to dismiss granted in part and denied in part on both the individual and provider tracks; Optum Pay terminated as a party; home-state-law briefing ordered | [49] | Confirmed |
| MDL 3108 | 16 Jul 2026 mediator order; 18 Sep 2026 PTO 40 (no health-insurer track); 8 Oct 2026 PTO 42 (schedule); next status conference 19 Nov 2026; no settlement or class certification shown | [50] | Confirmed |
| State of Nebraska v. Change Healthcare, UHG and Optum (Lancaster County, CI 24-4356) | Filed 16 Dec 2024 under Nebraska consumer protection and data security laws | [45][46] | Confirmed |
| Nebraska | 10 Nov 2025: Judge Susan I. Strong overrules the motion to dismiss; the AG says nearly 900,000 Nebraskans were affected | [47] | Confirmed |

The Nebraska release lists outdated, poorly segmented systems and the failure to detect access for more than a week among the alleged failures (Confirmed as an allegation [45]).

### Regulation

HHS released voluntary Healthcare and Public Health (HPH) Cybersecurity Performance Goals in January 2024, weeks before the attack, in Essential and Enhanced tiers informed by HICP, the NIST Cybersecurity Framework and the national strategy (Confirmed [41][36]). Essential goals include Multifactor Authentication, Mitigate Known Vulnerabilities and Vendor/Supplier Cybersecurity Requirements; Enhanced goals include Asset Inventory, Network Segmentation and Third Party Incident Reporting (Confirmed [35][36]).

The HIPAA Security Rule proposal (RIN 0945-AA22, 90 FR 898), published 6 January 2025, cites this breach and, in footnote 252, the CEO's account of a remote-access application without MFA (Confirmed [37]). It would require, among other things, MFA on all technology assets in relevant systems and for any privilege change, network segmentation, written procedures to restore critical systems and data within 72 hours, backup testing at least every six months, an asset inventory and network map reviewed at least yearly, vulnerability scans every six months, penetration tests every 12 months, patching of critical risks in 15 days and high risks in 30, and annual written verification of business associates' safeguards with a 24-hour report of contingency-plan activation (Confirmed [37]). As of 3 November 2026 the Federal Register lists only the proposal, with no final rule; the Spring 2025 agenda targeted final action in May 2026, and the later agenda entry moved the rule to Long-Term Actions with final action in July 2027 (Confirmed [38][39]). The AHA urged HHS to withdraw the proposal, calling the 72-hour restoration requirement infeasible (Confirmed [40]).

## Part 9: which attack? The largest healthcare breaches of 2024, 2025 and 2026

A request for "the big healthcare organization that got hit last year" can point at more than one event. Counting from 2026, "last year" is 2025, and the largest healthcare breach reported to OCR in 2025 was Conduent's, not Change's. The tables below come from the HHS OCR breach portal export of 3 November 2026 and sort each year's largest reports by people affected (Confirmed [22]). The year is the year the report was submitted, which can differ from the year of the intrusion: Aesto's 2026 report covers access in December 2025 (Confirmed [80]).

### Totals by submission year

| Year | Reports | Individuals | Share from Hacking/IT incidents | Source |
|---|---|---|---|---|
| 2024 | 741 | 290.1 million | 94.4 percent | [22] |
| 2025 | 810 | 141.2 million | 95.6 percent | [22] |
| 2026 to 3 Nov | 618 | 87.7 million | 97.6 percent | [22] |

### 2024: Change and the rest

| Entity | Type | Individuals | Submitted | What happened | Source | Grade |
|---|---|---|---|---|---|---|
| Change Healthcare | Business associate | 192,700,000 | 19 Jul 2024 | This study | [22] | Confirmed |
| Kaiser Foundation Health Plan | Health plan | 13,400,000 | 12 Apr 2024 | Unauthorized access or disclosure through third-party tracking technologies, per the portal description (not a hack) | [22] | Confirmed |
| Ascension Health | Provider | 5,466,931 | 03 Jul 2024 | Ransomware on 8 May 2024; hospitals on downtime procedures and diverting EMS; 5,599,699 per Ascension's notice to the Maine AG; Black Basta named by CNN's sources but never claimed | [22][85] | Confirmed for the portal row; Reported for the rest |
| HealthEquity | Business associate | 4,300,000 | 09 Aug 2024 | Hacking/IT | [22] | Confirmed |
| Concentra Health Services | Provider | 3,998,163 | 09 Jan 2024 | Hacking at a business associate, per the portal description | [22] | Confirmed |
| Centers for Medicare & Medicaid Services | Health plan | 3,112,815 | 06 Sep 2024 | Business associate software application, per the portal description | [22] | Confirmed |
| Acadian Ambulance Service | Provider | 2,896,985 | 20 Aug 2024 | Hacking/IT | [22] | Confirmed |
| Sav-Rx (A&A Services) | Business associate | 2,812,336 | 24 May 2024 | Hacking/IT | [22] | Confirmed |
| WebTPA Employer Services | Business associate | 2,518,533 | 08 May 2024 | VPN access, per the portal description | [22] | Confirmed |

### 2025

| Entity | Type | Individuals | Submitted | What happened | Source | Grade |
|---|---|---|---|---|---|---|
| Conduent Business Services | Business associate | 62,224,658 | 08 Oct 2025 | A threat actor got into part of its environment on 13 Jan 2025, causing an operational disruption, and exfiltrated client files | [22][74] | Confirmed |
| Aflac | Health plan | 13,924,906 | 08 Aug 2025 | Unauthorized network access found 12 Jun 2025, contained within hours; no ransomware | [22][75] | Confirmed |
| Episource | Business associate | 6,725,572 | 06 Jun 2025 | A "cybercriminal" viewed and copied data 27 Jan to 6 Feb 2025; ransomware reported by some outlets, unclaimed | [22][76] | Confirmed for the portal row; Reported for the rest |
| Yale New Haven Health System | Provider | 5,556,702 | 11 Apr 2025 | March 2025 attack in which hackers copied patient data; a spokesperson did not dispute a ransomware link | [22][77] | Confirmed for the portal row; Reported for the rest |
| Blue Shield of California | Business associate | 4,700,000 | 09 Apr 2025 | Google Analytics configured so that health information may have gone to Google: a tracking misconfiguration, not a hack | [22] | Confirmed |
| PIH Health | Provider | 2,947,264 | 31 Jan 2025 | Hacking/IT | [22] | Confirmed |
| DaVita | Provider | 2,689,826 | 01 Aug 2025 | Ransomware that encrypted parts of its network, discovered 12 Apr 2025 | [22][78] | Confirmed |
| Veradigm | Business associate | 2,672,036 | 22 Sep 2025 | Hacking/IT | [22] | Confirmed |
| Anne Arundel Dermatology | Provider | 1,905,000 | 11 Jul 2025 | Hacking/IT | [22] | Confirmed |
| Kettering Adventist Healthcare | Provider | 1,695,382 | 21 Jul 2025 | Hacking/IT | [22] | Confirmed |

### 2026 to date

| Entity | Type | Individuals | Submitted | What happened | Source | Grade |
|---|---|---|---|---|---|---|
| DentaQuest | Health plan | 15,000,000 | 16 Jul 2026 | Social engineering tricked one employee into giving credentials and an MFA code; activity 17 to 19 May 2026; data taken from a network file share; no malware or ransomware found | [22][79] | Confirmed |
| Aesto | Business associate (data migration and archiving) | 9,540,683 | 31 Jul 2026 | Access to part of its Amazon Web Services infrastructure about 2 to 18 Dec 2025, confirmed 26 May 2026 | [22][80] | Confirmed |
| iRhythm Technologies | Provider | 8,179,772 | 03 Oct 2026 | Unauthorized activity in third-party-hosted business applications found 8 Jun 2026; data obtained through social engineering; extortion demand 9 Jun | [22][81] | Confirmed |
| Lumexa Imaging | Provider | 5,830,949 | 15 May 2026 | A non-clinical support vendor's network accessed and documents taken 31 Mar to 9 Apr 2026 | [22][82] | Confirmed |
| AdaptHealth | Provider | 4,115,802 | 14 Aug 2026 | Cloud business applications accessed; data including a stored insurance-billing password file exfiltrated; actor contact 15 Jun 2026 | [22][83] | Confirmed |
| Unlimited Technology Systems | Business associate | 3,803,750 | 21 Jul 2026 | Hacking/IT | [22] | Confirmed |
| CareCloud | Business associate | 3,756,469 | 24 Jul 2026 | Network disruption on 16 Mar 2026 affecting one of six EHR environments for about 8 hours | [22][84] | Confirmed |
| TriZetto Provider Solutions | Business associate | 3,433,965 | 06 Feb 2026 | Hacking/IT | [22] | Confirmed |
| QualDerm Partners | Provider | 2,951,318 | 22 Feb 2026 | Hacking/IT | [22] | Confirmed |
| Baylor Genetics | Provider | 2,810,878 | 14 Aug 2026 | Hacking/IT | [22] | Confirmed |

### How to tell them apart

- **If the event stopped pharmacies and claims nationwide for weeks, it is Change Healthcare (2024).** No 2025 or 2026 portal entry combines a weeks-long national claims and pharmacy outage with a count above 100 million (Inferred from [22]).
- **If it is the biggest 2025 healthcare breach, it is Conduent** (62.2 million, a business associate whose January 2025 intrusion also disrupted operations), about a third the size of Change (Confirmed [22][74]; Inferred for the ratio).
- **If it is the biggest 2026 breach, it is DentaQuest** (15 million, one employee socially engineered out of credentials and an MFA code) (Confirmed [79]).
- **If it is a hospital system, the candidates are Ascension (2024) and Yale New Haven (2025)** (Confirmed [22]; Reported for the details [85][77]).
- The later pattern is vendors and business associates, single-employee or SaaS social engineering, and mostly data theft without system-wide clinical downtime (Inferred from [22][74][79][81][83]).

## Part 10: the vulnerability-management view

There is no CVE in this story. The entry point was an internet-facing remote-access portal reachable with a password alone; the record says compromised credentials, not a software flaw, so this was a configuration exposure that a CVE-driven scanning program would not surface (Inferred from [14][17]). No opened source supports naming a Citrix CVE as the vector (Inferred from [14][17][46]). The library's [CVE Reference](/CVE_REFERENCE.md) therefore has nothing to bind here; for the opposite case, a single CVE exploited at internet scale, see [the Log4Shell study](/case-studies/LOG4SHELL.md).

The frameworks already pointed at the gap. The HPH goal Mitigate Known Vulnerabilities targets internet-accessible assets and maps to CISA CPG 2.W, No Exploitable Services on the Internet, and to the KEV catalog; the HIPAA proposal names NVD and KEV as authoritative vulnerability sources (Confirmed [35][37]). Read together with the Essential MFA goal for internet-facing accounts, which maps to CISA CPG 2.H and HICP 3.M.D (Confirmed [35]), the goals describe exactly the exposure that was missed (Inferred).

What an exposure program would have needed:

| Need | Why it matters here | Source |
|---|---|---|
| An inventory of every externally reachable login surface, with authentication strength recorded as an attribute | The portal was external, single-factor and outside policy | [14][17]; Inferred for the inventory design |
| The acquired company's estate inside that inventory from day one | Change was acquired in late 2022, roughly 14 to 16 months before the attack by this study's count, and its legacy servers, some systems going back 40 years by Witty's account, were still being brought to UHG standards | [17]; Inferred for the month count and the lesson |
| Testing that checks controls, not just versions | UHG now uses continuous penetration tests and outside support to enforce MFA | [17] |
| Audit scope that covers the edge | HITRUST certifications covered certain Change systems; whether they caught the missing MFA is not stated | [17]; Inferred that scope missed it |
| Cadence the proposal would set | Asset inventory and network map yearly, scans every six months, penetration tests every 12 months, critical patches in 15 days | [37] |

See the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) and [CTEM Reference](/CTEM_REFERENCE.md) for the program models.

## Part 11: the defender view

### Close the single-factor doors

The ALPHV advisory, AA23-353A, which covers ALPHV affiliates in general, recommends phishing-resistant MFA (FIDO/WebAuthn or PKI-based) and application controls for remote access software, and warns that ALPHV affiliates use push bombing and SIM swaps (Confirmed [23]). HHS's 405(d) program places MFA for remote access in HICP practice 2.S.A of Technical Volume 1 and practices 1.M.B and 3.M.D of Technical Volume 2 (Confirmed [34]). The HICP volumes themselves were not opened. The 2026 DentaQuest case shows why the second factor needs to resist phishing: there, an employee handed over both a password and an MFA code (Confirmed [79]).

### Segment, and keep backups out of reach

The backups were reached and locked (Confirmed [17]). The Nebraska complaint alleges the backups were not isolated and the network was not segmented (Confirmed as an allegation [46]). The HPH Enhanced goal Network Segmentation (CISA CPG 2.F, HICP 6.M.B) exists to limit lateral movement (Confirmed [35]). The advisory notes that ALPHV affiliates harvest passwords from domain controllers, the local network and deleted backup servers (Confirmed [23]). Keep backup systems on separate credentials and networks, and test restoring into a clean environment (Inferred from [17][37]).

### Watch the quiet days

| Window | Signal in the record | What to watch for | Source |
|---|---|---|---|
| About 11 Feb | Credentials allegedly posted in a Telegram group | Credential-exposure monitoring for staff accounts | [46]; Inferred for the control |
| 12 Feb | Single-factor login to the Citrix portal | Logins to external remote access without a second factor; new source locations | [14][17] |
| 12 to 21 Feb | Privileged administrator accounts allegedly created on the SelectRX server | Alerts on new privileged accounts outside change control | [46] |
| 12 to 21 Feb | Lateral movement in the nine days before ransomware (no method stated) | Internal remote-session baselines; EDR telemetry | [14][23] |
| 17 to 20 Feb | Exfiltration of protected health information | Egress volume baselines; outbound transfer alerts | [17] |
| 21 Feb | Encryption: the point at which the attack was actually detected | | [17] |

The window column is the record; reading it as a detection plan is this study's inference (Inferred [17][46]). AA23-353A's detection guidance matches: log all network traffic including lateral movement, deploy EDR, baseline traffic, and look for remote tools such as AnyDesk, Mega sync, Splashtop, Plink and Ngrok, with ScreenConnect and SimpleHelp among its indicators (Confirmed [23]). The HPH Enhanced goals Detect and Respond to Relevant Threats and TTPs (CISA CPG 3.A) and Centralized Log Collection (CISA CPG 2.T) set the same baseline (Confirmed [35]).

### Rebuild, do not clean

Change came back by building new environments from pre-incident backups, rotating keys and credentials for every service, scanning each with at least two vendors and testing before reconnection, and it reissued about 11,000 clean devices (Confirmed [17]). The HPH Essential goal Basic Incident Planning and Preparedness points to HICP 4.M.D Backup Strategies, and the Enhanced goal asks organizations to drill and update their plans (Confirmed [35]).

### Plan for the clearinghouse to disappear

For providers, the Change outage was a vendor incident that became a cash-flow crisis (Confirmed [55][58]). Keep a tested second clearinghouse connection, know the paper-claim and downtime procedures, and avoid contracts that forbid redundant pathways (Inferred from [17][56][60]). The HPH goals ask for vendor cybersecurity requirements and third-party incident reporting (Confirmed [35]); the HIPAA proposal would require business associates to report contingency-plan activation within 24 hours (Confirmed [37]).

## Part 12: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every id was checked against the live ATT&CK site or the library's data files on 3 November 2026 (Confirmed [30][31][32][33]). The Change record has no ICS techniques, so there is no ATT&CK for ICS table.

### ATT&CK Enterprise techniques: the Change Healthcare record

The record supports few techniques because the testimony names steps, not methods. Tactics follow the library's technique profiles for v20.0 (Confirmed [33]).

| Id | Name | Tactic (v20.0) | Where it appears in the record | Source | Grade |
|---|---|---|---|---|---|
| [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Compromised credentials used to log in, 12 Feb 2024 (Witty, House and Senate, 1 May 2024) | [14][17] | Confirmed |
| [T1133](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | Citrix remote-desktop portal without MFA, 12 Feb 2024 | [14][17] | Confirmed |
| [T1136](/mitre/techniques/T1136.md) | Create Account | Persistence | Privileged administrator accounts created on the SelectRX server, 12 to 21 Feb 2024 (Nebraska complaint, 16 Dec 2024) | [46] | Confirmed as an allegation |
| [T1486](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | Ransomware deployed and systems encrypted, 21 Feb 2024 | [14][17] | Confirmed |
| [T1657](/mitre/techniques/T1657.md) | Financial Theft | Impact | UHG paid the demanded $22 million ransom in Bitcoin (UHG answer for the record, Senate Finance, 1 May 2024) | [17] | Confirmed |

Steps without a supported technique:

- **Lateral movement (12 to 21 Feb) and exfiltration (17 to 20 Feb)** are stated without a method, so only the tactics are supported. [T1021 Remote Services](/mitre/techniques/T1021.md), T1041, T1048 or T1567 would be inferences and are not bound (Inferred from [14][17]).
- **Backups locked up.** This fits T1486 applied to backup systems; [T1490 Inhibit System Recovery](/mitre/techniques/T1490.md) would need evidence that recovery features were deleted or disabled, which the record does not give, so it is not bound for Change (Inferred from [17]).

### ATT&CK Enterprise techniques: ALPHV and RansomHub in general

These describe the actors' general tradecraft, not observed steps at Change, and are context for defenders.

AA23-353A, updated 27 Feb 2024, for ALPHV affiliates (Confirmed [23]):

| Id | Name | Tactic (v20.0) | Source |
|---|---|---|---|
| [T1598](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | [23] |
| [T1586](/mitre/techniques/T1586.md) | Compromise Accounts | Resource Development | [23] |
| [T1555](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | [23] |
| [T1558](/mitre/techniques/T1558.md) | Steal or Forge Kerberos Tickets | Credential Access | [23] |
| [T1557](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | Credential Access, Collection | [23] |

ATT&CK's record of [S1068 BlackCat](/mitre/software/S1068.md) lists 21 techniques (Confirmed [30][33]): T1018 Remote System Discovery, T1033 System Owner/User Discovery, T1047 Windows Management Instrumentation, T1059.003 Windows Command Shell, T1069.002 Domain Groups, T1082 System Information Discovery, T1083 File and Directory Discovery, T1087.002 Domain Account, T1112 Modify Registry, T1134 Access Token Manipulation, T1135 Network Share Discovery, T1222.001 Windows Permissions, T1486 Data Encrypted for Impact, T1489 Service Stop, T1490 Inhibit System Recovery, T1491.001 Internal Defacement, T1548.002 Bypass User Account Control, T1561.001 Disk Content Wipe, T1570 Lateral Tool Transfer, T1680 Local Storage Discovery and T1685.005 Clear Windows Event Logs. Only T1486 is documented at Change (Confirmed [14]).

AA24-242A maps T1588.005, T1566, T1190, T1059.001, T1047, T1136, T1098, T1021.001, T1036, T1070, T1562.001, T1003, T1068, T1110.003, T1018, T1046, T1210, T1219, T1048.002, T1537, T1048.003, T1486 and T1490 for RansomHub affiliates in general (Confirmed [24]). In ATT&CK v20 T1562.001 Disable or Modify Tools redirects to [T1685](/mitre/techniques/T1685.md), and the library's `data/attack/superseded_by.jsonl` maps it there (Confirmed [32][33]). RansomHub's role at Change was extortion with stolen data, not intrusion, so none of these is bound to the Change record (Inferred from [6][61][67]).

### ATT&CK groups, software and mitigations

| Object | Id | Role in the record | Source |
|---|---|---|---|
| [BlackCat](/mitre/software/S1068.md) | S1068 | The ransomware the actor named; aliases ALPHV and Noberus | [30][14] |
| [RansomHub](/mitre/software/S1212.md) | S1212 | The second extortion, April 2024 | [31][61] |
| [Scattered Spider](/mitre/groups/G1015.md) | G1015 | S1068's only listed group user; not attributed to the Change attack | [30][25][26] |
| [Storm-0501](/mitre/groups/G1053.md) | G1053 | Described in the library as previously affiliated with BlackCat among other RaaS variants; not listed as an ATT&CK user of S1068; context only, not tied to Change | [33] |
| [ngrok](/mitre/software/S0508.md) | S0508 | Named in AA23-353A for ALPHV affiliates | [23] |
| [Brute Ratel C4](/mitre/software/S1063.md) | S1063 | Named in AA23-353A | [23] |
| [Cobalt Strike](/mitre/software/S0154.md) | S0154 | Named in AA23-353A, which prints the id S1054; ATT&CK's Cobalt Strike is S0154 and the library has no S1054 | [23][33] |
| [Tor](/mitre/software/S0183.md) | S0183 | Named in AA23-353A | [23] |
| [Multi-factor Authentication](/mitre/mitigations/M1032.md) | M1032 | The missing control; the library maps it to T1078, T1133, T1136 and T1021 | [33] |
| [Network Segmentation](/mitre/mitigations/M1030.md) | M1030 | Alleged missing segmentation; the library maps it to T1133 and T1136 | [33][46] |
| [Privileged Account Management](/mitre/mitigations/M1026.md) | M1026 | Alleged creation of privileged accounts; the library maps it to T1136 and T1078 | [33][46] |
| [Data Backup](/mitre/mitigations/M1053.md) | M1053 | Backups locked up; the library maps it to T1486 and T1490 | [33][17] |

There is no ATT&CK group object for ALPHV or BlackCat and no ATT&CK campaign object for the Change attack (Confirmed [33]).

### CAPEC and CWE

| Id | Name | Fit to this record | Source | Grade |
|---|---|---|---|---|
| [CAPEC-560](/mitre/capec/CAPEC-560.md) | Use of Known Domain Credentials | The library's CAPEC mapping for T1078; fits a login with stolen credentials | [33][14] | Confirmed for the mapping; Inferred for the fit |
| [CAPEC-555](/mitre/capec/CAPEC-555.md) | Remote Services with Stolen Credentials | The library's CAPEC mapping for T1133 and T1021; fits the Citrix login | [33][14] | Confirmed for the mapping; Inferred for the fit |
| CWE-308 | Use of Single-factor Authentication | Present in the library's CWE data; describes the portal's weakness. No CVE or CWE was assigned in the record | [33][14] | Inferred |

See the [CAPEC Reference](/CAPEC_REFERENCE.md) and the [CWE Reference](/CWE_REFERENCE.md).

### D3FEND countermeasures

The library's `data/attack/technique_to_d3fend.jsonl` carries these mappings for the bound techniques, among others; the table lists the most relevant ones, not the full set (Confirmed [33]):

| Countermeasure | D3FEND tactic | Library mapping | Guidance in the record it matches | Source |
|---|---|---|---|---|
| [User Account Permissions](/mitre/d3fend/user-account-permissions.md) | Isolate | T1078, T1136 | Limiting what a support employee's account can reach | [33][46] |
| [Account Locking](/mitre/d3fend/account-locking.md) | Evict | T1078, T1136 | Disabling the compromised account | [33] |
| [Agent Authentication](/mitre/d3fend/agent-authentication.md) | Harden | T1078, T1136 | Strengthening authentication on the portal | [33][17] |
| [Access Modeling](/mitre/d3fend/access-modeling.md) | Model | T1078, T1136 | Knowing which accounts reach which servers | [33] |
| [Restore User Account Access](/mitre/d3fend/restore-user-account-access.md) | Restore | T1078, T1136 | Credential rotation in the rebuild | [33][14] |
| [Session Termination](/mitre/d3fend/session-termination.md) | Evict | T1133 | Ending remote sessions on the portal | [33] |
| [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) | Detect | T1486 | Detecting mass encryption | [33] |
| [Decoy File](/mitre/d3fend/decoy-file.md) | Deceive | T1486 | Early warning of encryption | [33] |
| [Restore File](/mitre/d3fend/restore-file.md) | Restore | T1486 | Restoration from pre-incident backups | [33][17] |
| [Remote File Access Mediation](/mitre/d3fend/remote-file-access-mediation.md) | Isolate | T1486 | Limiting network file access to slow encryption | [33] |

[D3FEND Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) has a library page, but the library's D3FEND data does not map it to T1078 or T1133 (Confirmed [33]). It is cited here as the advisory's recommendation [23], not as a D3FEND mapping of either technique. The control that mattered most in this case therefore has no D3FEND binding to the entry techniques in the library today (Inferred).

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer, [change-healthcare-2024.json on GitHub](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/change-healthcare-2024.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FTeamStarWolf%2FTeamStarWolf%2Fmain%2Fnavigator%2Flibrary-layers%2Fchange-healthcare-2024.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 (navigator 4.9, layer format 4.5) and holds 30 techniques as 37 technique-tactic entries, each technique shown under every tactic in its library technique profile. Scores separate the evidence: 100 for techniques in the Change record (T1078, T1133, T1486, T1657), 75 for the technique alleged in the Nebraska complaint (T1136), and 40 for ALPHV/BlackCat general tradecraft from AA23-353A and ATT&CK S1068 that is not documented at Change. Each entry's comment names the source numbers of this study's Sources table.

## Cross-cutting themes

- **The perimeter was a policy, not a fact.** MFA was required on paper and missing on the one server that mattered (Confirmed [17]). Controls need to be measured where they apply, not where they are written (Inferred). See [Identity Security](/IDENTITY_SECURITY_REFERENCE.md) and [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).
- **Mergers inherit attack surface.** The vulnerable server came with the acquisition and was still in transition 14 to 16 months later (Confirmed [17] for the late-2022 acquisition and the unfinished transition; Inferred from [17] for the month count and the general point).
- **Concentration turns one breach into a national outage.** A clearinghouse that touches a third of patient records, by the senator's count, plus exclusivity clauses, made switching difficult or very difficult for two-thirds of the hospitals the AHA surveyed (Confirmed [17][56]). See [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md) and the [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md).
- **Ransomware-as-a-service splits the actor in two.** The operator took the money and the affiliate kept the data, so paying one did not satisfy the other (Reported [64][67]; Inferred for the general point). See [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md).
- **Counts are moving targets.** The breach grew from 500 to 192.7 million over a year of filings (Confirmed [20]). Cite the date with the number.
- **Data theft now outnumbers outages.** The large 2025 and 2026 healthcare cases are mostly data theft from vendors and SaaS applications, often by social engineering, rather than system-wide clinical downtime (Inferred from [22]).

### What is overstated and what is understated

- **Overstated: a nation-state attack.** The first filing said "suspected nation-state", was corrected within two weeks, and no primary source supports a state actor (Confirmed [1][2]; Reported for the unverified China claim [73]).
- **Overstated: 6 TB stolen.** The figure is ALPHV's own leak-site claim; RansomHub and the affiliate claimed about 4 TB, and no primary source states a volume (Reported [63][64][67]).
- **Overstated: Scattered Spider did it.** The link is structural only (Inferred from [25][27][30]).
- **Understated: the providers' cash crisis.** Practices covered payroll and supplies from personal funds; CMS and UHG together put more than $12 billion into provider liquidity (Confirmed [58][53][11]; Inferred for the sum).
- **Understated: the long tail.** A $799 million reserve increase came almost two years after the attack, and the multidistrict litigation has no settlement as of October 2026 (Confirmed [12][50]).
- **Understated: the backups.** Witty named the locked-up backup systems, built inside Change before the acquisition, as the root cause of the slow restoration (Confirmed [17]).

### Notes for the library's reference pages

Two existing pages carry figures this record corrects (Confirmed [11][17][20][22][63]):

- [Notable Incidents](/NOTABLE_INCIDENTS.md) states "6TB of data exfiltrated" as fact; it is ALPHV's claim. It describes Change as "~1/3 of all US healthcare billing"; the hearing figure is a third of patient records, the senator's count, and UHG's own figure is about 6 percent of U.S. health care payments. Its "$872M to $2.7B" impact range is superseded by the FY2024 10-K's $2.2 billion plus $867 million.
- The [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md) gives about 190 million; the current OCR figure is about 192.7 million.

## Sources

All sources were opened on 3 November 2026. "Primary" means the organization that published the fact; grades apply to the source as used here. Addresses shown as code rather than as links refuse automated link checkers: the sec.gov filings, the HHS FAQ page, the BronxCare copy of the substitute notice and the SecurityWeek articles open in a browser, and the api.congress.gov records need a free api.data.gov key (the same bills are on congress.gov).

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | UnitedHealth Group, Form 8-K, Item 1.05, report date 21 Feb 2024, filed 22 Feb 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000045/unh-20240221.htm` | 2026-11-03 | Confirmed |
| 2 | UnitedHealth Group, Form 8-K/A Amendment No. 1, filed 8 Mar 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000085/unh-20240221.htm` | 2026-11-03 | Confirmed |
| 3 | UnitedHealth Group press release, 7 Mar 2024 (Exhibit 99.1 to the 8-K/A) | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000085/pressreleasedatedmarch7202.htm` | 2026-11-03 | Confirmed |
| 4 | UnitedHealth Group newsroom, update of 7 Mar 2024 | [unitedhealthgroup.com/newsroom/2024/2024-03-07-uhg-update-change-healthcare-cyberattack.html](https://www.unitedhealthgroup.com/newsroom/2024/2024-03-07-uhg-update-change-healthcare-cyberattack.html) | 2026-11-03 | Confirmed |
| 5 | UnitedHealth Group newsroom, status update of 18 Mar 2024 | [unitedhealthgroup.com/newsroom/2024/2024-03-18-uhg-cyberattack-status-update.html](https://www.unitedhealthgroup.com/newsroom/2024/2024-03-18-uhg-cyberattack-status-update.html) | 2026-11-03 | Confirmed |
| 6 | UnitedHealth Group press release, 22 Apr 2024 (SEC exhibit) | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000150/pressreleasedatedapril2220.htm` | 2026-11-03 | Confirmed |
| 7 | UnitedHealth Group newsroom, 22 Apr 2024 (filed as 8-K/A Amendment No. 2 on 24 Apr 2024) | [unitedhealthgroup.com/newsroom/2024/2024-04-22-uhg-updates-on-change-healthcare-cyberattack.html](https://www.unitedhealthgroup.com/newsroom/2024/2024-04-22-uhg-updates-on-change-healthcare-cyberattack.html) | 2026-11-03 | Confirmed |
| 8 | UnitedHealth Group, Form 10-Q, Q1 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000155/unh-20240331.htm` | 2026-11-03 | Confirmed |
| 9 | UnitedHealth Group, Form 10-Q, Q2 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000262/unh-20240630.htm` | 2026-11-03 | Confirmed |
| 10 | UnitedHealth Group, Form 10-Q, Q3 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000323/unh-20240930.htm` | 2026-11-03 | Confirmed |
| 11 | UnitedHealth Group, Form 10-K, FY2024, filed 27 Feb 2025 | `https://www.sec.gov/Archives/edgar/data/731766/000073176625000063/unh-20241231.htm` | 2026-11-03 | Confirmed |
| 12 | UnitedHealth Group, Form 10-K, FY2025 | `https://www.sec.gov/Archives/edgar/data/731766/000073176626000062/unh-20251231.htm` | 2026-11-03 | Confirmed |
| 13 | UnitedHealth Group, Form 10-Q, Q3 2026 | `https://www.sec.gov/Archives/edgar/data/731766/000073176626000266/unh-20260930.htm` | 2026-11-03 | Confirmed |
| 14 | Andrew Witty, written testimony, House Energy and Commerce Oversight and Investigations Subcommittee, 1 May 2024 | [docs.house.gov/meetings/IF/IF02/20240501/117242/HHRG-118-IF02-Wstate-WittyS-20240501-U5.pdf](https://docs.house.gov/meetings/IF/IF02/20240501/117242/HHRG-118-IF02-Wstate-WittyS-20240501-U5.pdf) | 2026-11-03 | Confirmed |
| 15 | The same testimony, copy hosted by the House Energy and Commerce Committee | [d1dth6e84htgma.cloudfront.net/Witty_Testimony_OI_Hearing_05_01_24_5ff52a2d11.pdf](https://d1dth6e84htgma.cloudfront.net/Witty_Testimony_OI_Hearing_05_01_24_5ff52a2d11.pdf) | 2026-11-03 | Confirmed |
| 16 | The same testimony, copy hosted by the committee's minority | [democrats-energycommerce.house.gov/.../Testimony_Witty_OI_2024.05.01.pdf](https://democrats-energycommerce.house.gov/sites/evo-subsites/democrats-energycommerce.house.gov/files/evo-media-document/Testimony_Witty_OI_2024.05.01.pdf) | 2026-11-03 | Confirmed |
| 17 | Senate Finance Committee hearing record, "Hacking America's Health Care", 1 May 2024, with prepared statements and answers for the record | [govinfo.gov/content/pkg/CHRG-118shrg63595/html/CHRG-118shrg63595.htm](https://www.govinfo.gov/content/pkg/CHRG-118shrg63595/html/CHRG-118shrg63595.htm) | 2026-11-03 | Confirmed |
| 18 | House Energy and Commerce majority staff hearing memo, 29 Apr 2024 | [d1dth6e84htgma.cloudfront.net/Public_Memo_OI_Hearing_05_01_24_Change_Healthcare_Cyberattack_6a53b333f6.pdf](https://d1dth6e84htgma.cloudfront.net/Public_Memo_OI_Hearing_05_01_24_Change_Healthcare_Cyberattack_6a53b333f6.pdf) | 2026-11-03 | Confirmed |
| 19 | Change Healthcare HIPAA substitute notice, read in the copy BronxCare reproduces (the changehealthcare.com address now redirects to Optum) | `https://www.bronxcare.org/about-us/change-healthcare-hipaa-substitute-notice` | 2026-11-03 | Confirmed |
| 20 | HHS OCR, Change Healthcare Cybersecurity Incident FAQ (content last reviewed 13 Aug 2025) | `https://www.hhs.gov/hipaa/for-professionals/special-topics/change-healthcare-cybersecurity-incident-frequently-asked-questions/index.html` | 2026-11-03 | Confirmed |
| 21 | The same FAQ, Wayback Machine capture of 24 Oct 2026 | [web.archive.org/web/20261024232808 (capture of the HHS FAQ)](https://web.archive.org/web/20261024232808/https://www.hhs.gov/hipaa/for-professionals/special-topics/change-healthcare-cybersecurity-incident-frequently-asked-questions/index.html) | 2026-11-03 | Confirmed |
| 22 | HHS OCR breach portal, active and archive CSV exports | [ocrportal.hhs.gov/ocr/breach/breach_report.jsf](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf) | 2026-11-03 | Confirmed |
| 23 | FBI, CISA and HHS, AA23-353A "#StopRansomware: ALPHV Blackcat", 19 Dec 2023, updated 27 Feb 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa23-353a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a) | 2026-11-03 | Confirmed |
| 24 | CISA, FBI, MS-ISAC and HHS, AA24-242A "#StopRansomware: RansomHub Ransomware", 29 Aug 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-242a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a) | 2026-11-03 | Confirmed |
| 25 | FBI and CISA, AA23-320A "Scattered Spider", original PDF, 16 Nov 2023 | [cisa.gov/sites/default/files/2023-11/aa23-320a_scattered_spider_0.pdf](https://www.cisa.gov/sites/default/files/2023-11/aa23-320a_scattered_spider_0.pdf) | 2026-11-03 | Confirmed |
| 26 | AA23-320A, revision of 29 Jul 2025 | [cisa.gov/sites/default/files/2025-08/aa23-320a-scattered-spider-508c.pdf](https://www.cisa.gov/sites/default/files/2025-08/aa23-320a-scattered-spider-508c.pdf) | 2026-11-03 | Confirmed |
| 27 | HHS HC3 analyst note, social engineering attacks targeting IT help desks in the health sector, 3 Apr 2024 (AHA-hosted copy) | [aha.org/system/files/media/file/2024/04/hc3-tlp-clear-analyst-note-...pdf](https://www.aha.org/system/files/media/file/2024/04/hc3-tlp-clear-analyst-note-social-engineering-attacks-targeting-it-help-desks-in-the-health-sector-4-3-2024.pdf) | 2026-11-03 | Confirmed |
| 28 | Change Healthcare incident status page (now served by Optum) | [status.changehealthcare.com/incidents/hqpjz25fn3n7](https://status.changehealthcare.com/incidents/hqpjz25fn3n7) | 2026-11-03 | Confirmed |
| 29 | U.S. Department of State, Rewards for Justice, ALPHV BlackCat (undated page) | [rewardsforjustice.net/rewards/alphv-blackcat](https://rewardsforjustice.net/rewards/alphv-blackcat/) | 2026-11-03 | Confirmed |
| 30 | MITRE ATT&CK, software S1068 BlackCat | [attack.mitre.org/software/S1068](https://attack.mitre.org/software/S1068/) | 2026-11-03 | Confirmed |
| 31 | MITRE ATT&CK, software S1212 RansomHub | [attack.mitre.org/software/S1212](https://attack.mitre.org/software/S1212/) | 2026-11-03 | Confirmed |
| 32 | MITRE ATT&CK, T1562.001 (redirects to T1685 in v20) | [attack.mitre.org/techniques/T1562/001](https://attack.mitre.org/techniques/T1562/001/) | 2026-11-03 | Confirmed |
| 33 | TeamStarWolf library data: `data/attack/` (technique profiles, software, groups, campaigns, superseded_by, mitigation_to_technique, technique_to_d3fend), `data/weaknesses/cwe.jsonl` and the generated `mitre/` pages | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-03 | Confirmed |
| 34 | HHS 405(d), "Have you heard about multi-factor authentication" | [hhscyber.hhs.gov/Documents/Posters_and_awareness/HHS-have-you-heard-mfa_R.pdf](https://hhscyber.hhs.gov/Documents/Posters_and_awareness/HHS-have-you-heard-mfa_R.pdf) | 2026-11-03 | Confirmed |
| 35 | HHS, Healthcare and Public Health Cybersecurity Performance Goals | [hhscyber.hhs.gov/cybersecurity-performance-goals.html](https://hhscyber.hhs.gov/cybersecurity-performance-goals.html) | 2026-11-03 | Confirmed |
| 36 | CISA, Healthcare and Public Health cybersecurity toolkit | [cisa.gov/topics/cybersecurity-best-practices/healthcare](https://www.cisa.gov/topics/cybersecurity-best-practices/healthcare) | 2026-11-03 | Confirmed |
| 37 | HHS OCR, HIPAA Security Rule proposed rule, 90 FR 898, FR Doc 2024-30983, 6 Jan 2025 | [federalregister.gov/documents/2025/01/06/2024-30983/...](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information) | 2026-11-03 | Confirmed |
| 38 | Unified Agenda, RIN 0945-AA22, Spring 2025 | [reginfo.gov/public/do/eAgendaViewRule?pubId=202504&RIN=0945-AA22](https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202504&RIN=0945-AA22) | 2026-11-03 | Confirmed |
| 39 | Unified Agenda, RIN 0945-AA22, later entry | [reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22](https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22) | 2026-11-03 | Confirmed |
| 40 | American Hospital Association response to the HHS request for information on AI in clinical care (RIN 0955-AA13), 23 Feb 2026, section urging withdrawal of the HIPAA Security Rule proposal | [aha.org/system/files/media/file/2026/02/aha-response-to-hhs-rfi-on-ai-in-health-care-letter-2-23-2026.pdf](https://www.aha.org/system/files/media/file/2026/02/aha-response-to-hhs-rfi-on-ai-in-health-care-letter-2-23-2026.pdf) | 2026-11-03 | Confirmed |
| 41 | HHS 405(d) and Health-ISAC announcement of the voluntary performance goals, January 2024 (AHA-hosted) | [aha.org/system/files/media/file/2024/01/hhs-releases-new-voluntary-performance-goals-...pdf](https://www.aha.org/system/files/media/file/2024/01/hhs-releases-new-voluntary-performance-goals-to-enhance-cybersecurity-across-the-health-sector-1-30-24.pdf) | 2026-11-03 | Confirmed |
| 42 | Congress.gov API, S.5218 (118th Congress) | `https://api.congress.gov/v3/bill/118/s/5218` | 2026-11-03 | Confirmed |
| 43 | Congress.gov API, S.5390 (118th Congress) | `https://api.congress.gov/v3/bill/118/s/5390` | 2026-11-03 | Confirmed |
| 44 | Congress.gov API, S.3315 (119th Congress), actions | `https://api.congress.gov/v3/bill/119/s/3315/actions` | 2026-11-03 | Confirmed |
| 45 | Nebraska Attorney General, release of 16 Dec 2024 | [ago.nebraska.gov/sites/default/files/doc/release%20today.pdf](https://ago.nebraska.gov/sites/default/files/doc/release%20today.pdf) | 2026-11-03 | Confirmed |
| 46 | State of Nebraska v. Change Healthcare, UHG and Optum, complaint, Lancaster County District Court, 16 Dec 2024 | [ago.nebraska.gov/sites/default/files/doc/Court%20Filing_10.pdf](https://ago.nebraska.gov/sites/default/files/doc/Court%20Filing_10.pdf) | 2026-11-03 | Confirmed as an allegation |
| 47 | Nebraska, order overruling the motion to dismiss, 10 Nov 2025 | [ago.nebraska.gov/sites/default/files/doc/2025.11.10%20-%20Order%20Overruling%20MTD.pdf](https://ago.nebraska.gov/sites/default/files/doc/2025.11.10%20-%20Order%20Overruling%20MTD.pdf) | 2026-11-03 | Confirmed |
| 48 | Judicial Panel on Multidistrict Litigation, transfer order, MDL No. 3108, 7 Jun 2024 | [govinfo.gov/content/pkg/USCOURTS-jpml-1_24-F-03108/pdf/USCOURTS-jpml-1_24-F-03108-0.pdf](https://www.govinfo.gov/content/pkg/USCOURTS-jpml-1_24-F-03108/pdf/USCOURTS-jpml-1_24-F-03108-0.pdf) | 2026-11-03 | Confirmed |
| 49 | U.S. District Court for the District of Minnesota, MDL 3108 order on motions to dismiss, 19 Dec 2025 | [mnd.uscourts.gov/sites/mnd/files/20251219_24md3108-Ord-Provider-MTD.pdf](https://www.mnd.uscourts.gov/sites/mnd/files/20251219_24md3108-Ord-Provider-MTD.pdf) | 2026-11-03 | Confirmed |
| 50 | U.S. District Court for the District of Minnesota, MDL 3108 case page | [mnd.uscourts.gov/content/change-healthcare-inc-data-breach](https://www.mnd.uscourts.gov/content/change-healthcare-inc-data-breach) | 2026-11-03 | Confirmed |
| 51 | CMS fact sheet, CHOPD accelerated and advance payments, 9 Mar 2024 | [cms.gov/newsroom/fact-sheets/change-healthcare-optum-payment-disruption-chopd-...](https://www.cms.gov/newsroom/fact-sheets/change-healthcare-optum-payment-disruption-chopd-accelerated-payments-part-providers-advance) | 2026-11-03 | Confirmed |
| 52 | CMS statement on continued action, 9 Mar 2024 | [cms.gov/newsroom/press-releases/cms-statement-continued-action-respond-cyberattack-change-healthcare](https://www.cms.gov/newsroom/press-releases/cms-statement-continued-action-respond-cyberattack-change-healthcare) | 2026-11-03 | Confirmed |
| 53 | CMS press release on closing CHOPD, 17 Jun 2024 | [cms.gov/newsroom/press-releases/cms-preparing-close-program-...](https://www.cms.gov/newsroom/press-releases/cms-preparing-close-program-addressed-medicare-funding-issues-resulting-change-healthcare-cyber) | 2026-11-03 | Confirmed |
| 54 | CMS HPMS memo to Medicare Advantage and Part D plans, 6 Mar 2024 | [cms.gov/files/document/hpmsmemoonchangehealthcarecyberattack03062024.pdf](https://www.cms.gov/files/document/hpmsmemoonchangehealthcarecyberattack03062024.pdf) | 2026-11-03 | Confirmed |
| 55 | American Hospital Association, survey news release, 15 Mar 2024 | [aha.org/news/news/2024-03-15-aha-survey-change-healthcare-cyberattack-...](https://www.aha.org/news/news/2024-03-15-aha-survey-change-healthcare-cyberattack-having-significant-disruptions-patient-care-hospitals-finances) | 2026-11-03 | Confirmed |
| 56 | American Hospital Association, survey results PDF, March 2024 | [aha.org/system/files/media/file/2024/03/aha-survey-change-healthcare-cyberattack-...pdf](https://www.aha.org/system/files/media/file/2024/03/aha-survey-change-healthcare-cyberattack-significantly-disrupts-patient-care-hospitals-finances.pdf) | 2026-11-03 | Confirmed |
| 57 | AHA and FAH letter to OCR, 21 Mar 2024 | [aha.org/system/files/media/file/2024/03/ocr-urged-to-clarify-breach-notification-requirements-...pdf](https://www.aha.org/system/files/media/file/2024/03/ocr-urged-to-clarify-breach-notification-requirements-in-relation-to-change-healthcare-cyberattack-letter-3-21-2024.pdf) | 2026-11-03 | Confirmed for the letter; Reported for the OCR wording it quotes |
| 58 | American Medical Association, Change Healthcare survey results, April 2024 | [ama-assn.org/system/files/change-healthcare-survey-results.pdf](https://www.ama-assn.org/system/files/change-healthcare-survey-results.pdf) | 2026-11-03 | Confirmed |
| 59 | American Medical Association, follow-up survey results, 29 Apr 2024 | [ama-assn.org/system/files/change-healthcare-follow-up-survey-results.pdf](https://www.ama-assn.org/system/files/change-healthcare-follow-up-survey-results.pdf) | 2026-11-03 | Confirmed |
| 60 | Defense Health Agency via DVIDS, full military pharmacy operations restored, 25 Apr 2024 | [dvidshub.net/news/469562/full-military-pharmacy-operations-restored-after-change-healthcare-cyberattack](https://www.dvidshub.net/news/469562/full-military-pharmacy-operations-restored-after-change-healthcare-cyberattack) | 2026-11-03 | Confirmed |
| 61 | The Register, 8 Apr 2024 | [theregister.com/2024/04/08/change_healthcare_ransomware](https://www.theregister.com/2024/04/08/change_healthcare_ransomware/) | 2026-11-03 | Reported |
| 62 | SecurityWeek, second ransomware group extorting Change Healthcare, April 2024 | `https://www.securityweek.com/second-ransomware-group-extorting-change-healthcare/` | 2026-11-03 | Reported |
| 63 | BleepingComputer, gang claims 6 TB of Change Healthcare data, 28 Feb 2024 | [bleepingcomputer.com/news/security/ransomware-gang-claims-they-stole-6tb-of-change-healthcare-data](https://www.bleepingcomputer.com/news/security/ransomware-gang-claims-they-stole-6tb-of-change-healthcare-data/) | 2026-11-03 | Reported |
| 64 | Krebs on Security, BlackCat implodes after apparent $22M payment, 5 Mar 2024 | [krebsonsecurity.com/2024/03/blackcat-ransomware-group-implodes-...](https://krebsonsecurity.com/2024/03/blackcat-ransomware-group-implodes-after-apparent-22m-ransom-payment-by-change-healthcare/) | 2026-11-03 | Reported |
| 65 | WIRED, Andy Greenberg, $22 million payment, 4 Mar 2024 | [wired.com/story/alphv-change-healthcare-ransomware-payment](https://www.wired.com/story/alphv-change-healthcare-ransomware-payment/) | 2026-11-03 | Reported |
| 66 | WIRED, Andy Greenberg, Change Healthcare admits it paid, 22 Apr 2024 (updated 1 May 2024) | [wired.com/story/change-healthcare-admits-it-paid-ransomware-hackers](https://www.wired.com/story/change-healthcare-admits-it-paid-ransomware-hackers/) | 2026-11-03 | Reported |
| 67 | CyberScoop, AJ Vicens, extortion group threatens to sell Change Healthcare data, 9 Apr 2024 | [cyberscoop.com/extortion-group-threatens-to-sell-change-healthcare-data](https://cyberscoop.com/extortion-group-threatens-to-sell-change-healthcare-data/) | 2026-11-03 | Reported |
| 68 | CyberScoop, stolen Change Healthcare data could cover a substantial portion of Americans, April 2024 | [cyberscoop.com/stolen-change-healthcare-data-could-contain-...](https://cyberscoop.com/stolen-change-healthcare-data-could-contain-information-on-a-substantial-portion-of-americans/) | 2026-11-03 | Reported |
| 69 | Malwarebytes, 100 million officially impacted, October 2024 | [malwarebytes.com/blog/news/2024/10/100-million-us-citizens-officially-impacted-by-change-healthcare-data-breach](https://www.malwarebytes.com/blog/news/2024/10/100-million-us-citizens-officially-impacted-by-change-healthcare-data-breach) | 2026-11-03 | Reported |
| 70 | CyberInsider, Change Healthcare revises impact to 192.7 million | [cyberinsider.com/change-healthcare-revises-breach-impact-to-192-7-million-individuals](https://cyberinsider.com/change-healthcare-revises-breach-impact-to-192-7-million-individuals/) | 2026-11-03 | Reported |
| 71 | BleepingComputer, Lawrence Abrams, FBI disrupts Blackcat, 19 Dec 2023 | [bleepingcomputer.com/news/security/fbi-disrupts-blackcat-ransomware-operation-creates-decryption-tool](https://www.bleepingcomputer.com/news/security/fbi-disrupts-blackcat-ransomware-operation-creates-decryption-tool/) | 2026-11-03 | Reported |
| 72 | BleepingComputer, Sergiu Gatlan, U.S. ransomware negotiators sentenced, May 2026 | [bleepingcomputer.com/news/security/us-ransomware-negotiators-get-4-years-in-prison-over-blackcat-attacks](https://bleepingcomputer.com/news/security/us-ransomware-negotiators-get-4-years-in-prison-over-blackcat-attacks) | 2026-11-03 | Reported |
| 73 | Cyber Daily, Menlo Security claim on the affiliate, 7 Mar 2024 | [cyberdaily.au/security/10281-alphv-affiliate-behind-change-healthcare-attack-...](https://www.cyberdaily.au/security/10281-alphv-affiliate-behind-change-healthcare-attack-could-be-a-chinese-state-sponsored-actor) | 2026-11-03 | Reported |
| 74 | Conduent, Form 8-K, April 2025 | `https://www.sec.gov/Archives/edgar/data/1677703/000167770325000067/cndt-20250409.htm` | 2026-11-03 | Confirmed |
| 75 | Aflac, Form 8-K, June 2025 | `https://www.sec.gov/Archives/edgar/data/4977/000000497725000128/afl-20250620.htm` | 2026-11-03 | Confirmed |
| 76 | SecurityWeek, Episource data breach | `https://www.securityweek.com/data-breach-at-healthcare-services-firm-episource-impacts-5-4-million-people/` | 2026-11-03 | Reported |
| 77 | TechCrunch, Yale New Haven Health data breach, 25 Apr 2025 | [techcrunch.com/2025/04/25/data-breach-at-connecticut-yale-new-haven-health-affects-over-5-million](https://techcrunch.com/2025/04/25/data-breach-at-connecticut-yale-new-haven-health-affects-over-5-million/) | 2026-11-03 | Reported |
| 78 | DaVita, Form 8-K, April 2025 | `https://www.sec.gov/Archives/edgar/data/927066/000119312525079593/d948299d8k.htm` | 2026-11-03 | Confirmed |
| 79 | DentaQuest letter to the Rhode Island Attorney General, 2026 | [riag.ri.gov/media/8956/download](https://riag.ri.gov/media/8956/download) | 2026-11-03 | Confirmed |
| 80 | Aesto consumer notice letter, filed with the California Attorney General, 2026 | [oag.ca.gov/system/files/Allied%20Health%20-%20Aesto%20Consumer%20Notice%20Letter%20Template_Redacted.pdf](https://oag.ca.gov/system/files/Allied%20Health%20-%20Aesto%20Consumer%20Notice%20Letter%20Template_Redacted.pdf) | 2026-11-03 | Confirmed |
| 81 | iRhythm Technologies, Form 8-K, Item 1.05, June 2026 | `https://www.sec.gov/Archives/edgar/data/1388658/000138865826000055/irtc-20260610.htm` | 2026-11-03 | Confirmed |
| 82 | Lumexa Imaging, vendor privacy notice, 27 Aug 2026 | [lumexaimaging.com/wp-content/uploads/2026/08/Vendor-Privacy-Notice_8.27.26-3.pdf](https://www.lumexaimaging.com/wp-content/uploads/2026/08/Vendor-Privacy-Notice_8.27.26-3.pdf) | 2026-11-03 | Confirmed |
| 83 | AdaptHealth, Form 8-K, Item 1.05, June 2026 | `https://www.sec.gov/Archives/edgar/data/1725255/000110465926080297/ahco-20260627x8k.htm` | 2026-11-03 | Confirmed |
| 84 | CareCloud, Form 8-K, March 2026 | `https://www.sec.gov/Archives/edgar/data/1582982/000149315226013239/form8-k.htm` | 2026-11-03 | Confirmed |
| 85 | SecurityWeek, 5.6 million impacted by the Ascension attack | `https://www.securityweek.com/5-6-million-impacted-by-ransomware-attack-on-healthcare-giant-ascension/` | 2026-11-03 | Reported |

Not opened: the Justice Department's 19 Dec 2023 ALPHV release (bot verification on every copy), the Senate Finance Committee's own PDF of the Witty testimony (403; the printed hearing record [17] was used), HHS HC3 PDFs on hhs.gov (403), the HHS release announcing the OCR letter (403), the Wall Street Journal reporting relayed by [18], and the HICP volumes.

## Related references

- [Threat Actors](/THREAT_ACTORS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md)
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)
- [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [CTEM Reference](/CTEM_REFERENCE.md)
- [Threat Report Almanac](/THREAT_REPORT_ALMANAC.md)
- [ATT&CK Software Reference](/ATTACK_SOFTWARE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md)
- [CAPEC Reference](/CAPEC_REFERENCE.md)
- [D3FEND Reference](/D3FEND_REFERENCE.md)
- Case studies: [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Log4Shell](/case-studies/LOG4SHELL.md)
- Software: [S1068 BlackCat](/mitre/software/S1068.md), [S1212 RansomHub](/mitre/software/S1212.md), [S0154 Cobalt Strike](/mitre/software/S0154.md), [S1063 Brute Ratel C4](/mitre/software/S1063.md), [S0508 ngrok](/mitre/software/S0508.md), [S0183 Tor](/mitre/software/S0183.md)
- Groups: [G1015 Scattered Spider](/mitre/groups/G1015.md), [G1053 Storm-0501](/mitre/groups/G1053.md)
- Techniques: [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1136 Create Account](/mitre/techniques/T1136.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md), [T1490 Inhibit System Recovery](/mitre/techniques/T1490.md), [T1657 Financial Theft](/mitre/techniques/T1657.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md)
- Mitigations: [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1026 Privileged Account Management](/mitre/mitigations/M1026.md), [M1053 Data Backup](/mitre/mitigations/M1053.md)
- CAPEC: [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-555](/mitre/capec/CAPEC-555.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [change-healthcare-2024.json on GitHub](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/change-healthcare-2024.json)
