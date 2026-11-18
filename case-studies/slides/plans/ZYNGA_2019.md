# Slide plan: Zynga 2019: A Breach and Its Court Record

- Study: case-studies/ZYNGA_2019.md
- Cover title: Zynga 2019 / Credentials and the / Court Record
- Subtitle: A company notice, a breach index, a complaint and a court ruling describe related events while establishing different things.
- Published: 18 November 2026
- Notes: The cover sets the frame: an account-data incident read apart from the claims that gathered around it.

## EXECUTIVE SUMMARY | Separate the incident from its many claims

- Zynga 2019 is a case in separating an account-data incident from the claims that accumulate around it.
- A company notice, a breach-index entry, a complaint and a court ruling each establish different things.
- Treating them as interchangeable produces inflated counts, invented causes and misleading conclusions.
- The record supports no reconstructed entry technique, no complete cost and no uniform-harm claim.
Caption: Evidence grade: Executive framing, bounded to the documentary record.
Notes: Executive-assessment framing; draws on sources [1] through [11], with no stolen corpus inspected.

## KEY FACTS | The corpus, the dates and what each measures

Stat: 173M | Unique emails in the HIBP corpus
Stat: Aug 31 | 2019 approximate access window
Stat: Sep 12 | 2019 public announcement
Stat: Dec 19 | 2019 added to HIBP
- The notice warned that a username and password might have been obtained; no SSNs were collected.
- HIBP records salted SHA-1 password hashes, usernames and phone numbers in the supplied data.
- Unique email addresses are not a count of people, active players or notified recipients.
Caption: Evidence grade: Confirmed notice; Reported index figures.
Notes: Notice facts from [1]; announcement date from [2]; corpus, categories and dates from [3].

## PART 1 | What the original notification actually said

- The California AG archive holds a Zynga sample notice in a file dated September 30, 2019.
- It described possible unauthorized access around August 31 and a username and password possibly obtained.
- Zynga reported forensic specialists, precautions against invalid logins and law-enforcement contact.
- It said no SSNs were collected and that it believed financial information had not been accessed.
Caption: Evidence grade: Confirmed, company-authored notice hosted by a regulator.
Notes: Full notice inspected per [1]; archive hosting does not verify each sentence.

## PART 1 | September disclosure versus later finding

- Zynga's 2021 annual filing dates the public announcement to September 12, 2019.
- It reports unauthorized access to certain player-account and other company information in the third quarter.
- An early tentative account and a later reported finding differ; identify who said what, and when.
- A company conclusion is not an independent forensic replication; no vulnerability is assigned here.
Caption: Evidence grade: Reported company finding, not a forensic report.
Notes: Filing account and the no-financial-access statement from [2]; both remain attributed to the company.

## PART 1 | What the breach index adds, and its unit

- HIBP describes roughly 173 million unique email addresses supplied to it by dehashed.com.
- The entry lists usernames, salted SHA-1 hashes and phone numbers, added December 19, 2019.
- That count is not a count of people, active players, paid customers or notified recipients.
- Index-inclusion date is not the date the intrusion began; no corpus was acquired or searched.
Caption: Evidence grade: Reported operator corpus description.
Notes: Corpus, categories and inclusion date from [3]; the population unit is kept explicit.

## PART 2 | Hashing is not encryption, storage is not access

- A hash is a verifier derived from an input, not an encrypted password meant to be decrypted.
- An exposed SHA-1 hash is not an exposed password; salting and cost concern guessing resistance.
- Storage format does not explain how an intruder first reached the database.
- Stronger storage reduces some consequences; it does not prevent every access incident.
Caption: Evidence grade: Confirmed definitions; storage format from [3].
Notes: The hash-versus-encryption distinction is analysis bounded to the HIBP format and the notice.

## PART 2 | Keep the OMGPOP history separate

- HIBP's separate OMGPOP entry describes an approximately 2013 incident, later leaked in 2019.
- It involved more than seven million email and password pairs stored as plaintext passwords.
- It was added to HIBP in November 2023; related businesses do not mean one intrusion.
- Merging the entries risks double-counting, misdated incidents and mismatched storage practices.
Caption: Evidence grade: Reported, separate earlier incident.
Notes: OMGPOP figures and dates from [4]; kept out of the Zynga population.

## PART 3 | The first wave of litigation

The 2021 filing records five federal consumer class complaints beginning in March 2020.

| Date | Action |
|---|---|
| Mar 3, 2020 | Initial complaint |
| Mar 23, 2020 | Second complaint |
| Apr 15, 2020 | Third complaint |
| Jun 9, 2020 | Maryland Oeste action |
| Aug 2020 | Fifth complaint |
Caption: Evidence grade: Confirmed filing chronology; allegations remain allegations.
Notes: Dates and the allegation framing from [2]; the study avoids amplifying litigant details, including a plaintiff identified by initials as a minor.

## PART 3 | January 2021: evidence of assent was missing

- The January 6, 2021 order denied Zynga's arbitration motions without prejudice.
- It allowed limited discovery and ordered account-identification information within fourteen days.
- The court lacked verified account information to determine which terms plaintiffs accepted.
- Without prejudice meant the denial was not a permanent ruling that arbitration could never apply.
Caption: Evidence grade: Confirmed order; full document inspected.
Notes: Order terms and the without-prejudice point from [5]; an evidentiary gap, not a merits ruling.

## PART 3 | May and July 2021: venue, then standing

Left: May 5, 2021 (Oeste)
- The Maryland court transferred the case to the Northern District of California.
- It treated background allegations as true and did not decide the breach population.
Right: July 2021
- July 23 allowed TransUnion briefing; the hearing would focus on standing.
- July 30 compelled arbitration for three plaintiffs and dismissed the rest with leave to amend.
Caption: Evidence grade: Confirmed orders; venue and standing, not merits.
Notes: Transfer from [6]; briefing order from [7]; arbitration and standing dismissal from [8].

## PART 3 | The final order recovered: April 29, 2022

- Zynga's first-quarter 2022 filing describes an effective dismissal and dates the event March 29, 2022.
- The recovered ECF 105 order is filed and signed April 29, 2022; this study uses April 29.
- The court dismissed with prejudice for lack of subject-matter jurisdiction, without leave to amend.
- The basis was Article III standing, not a trial finding that Zynga's security was adequate.
Caption: Evidence grade: Confirmed order; the March date is retained as a source discrepancy.
Notes: Dismissal from [9]; cited date from [10]; recovered 23-page order inspected per [11].

## PART 3 | What the final standing analysis addressed

- The second consolidated complaint asserted 29 state-law causes of action.
- The court grouped harms: identity-theft risk, mitigation time, distress, lost value and privacy.
- It found no plausible allegation of successful identity theft or fraud under TransUnion.
- A jurisdictional disposition is not an adjudication that no information was exposed.
Caption: Evidence grade: Confirmed order analysis; treated as a facial challenge.
Notes: Causes, harm grouping and the TransUnion distinction from [11]; standing, not the security merits.

## AUDIT | What an incident audit should preserve

Four workstreams, four records to keep, each labeled by its own unit and source.

| Workstream | Preserve |
|---|---|
| Notification | Population per notice, fields, delivery evidence |
| Technical | Access, extraction, storage format, abuse risk |
| Research | Each number labeled by unit and source |
| Legal | Date and procedural scope of each order |
Caption: Evidence grade: Inferred audit guidance tied to the record.
Notes: Four workstreams drawn from section 11, resting on [1] through [11]; original analysis, not court findings.

## CROSS-CUTTING THEMES | Overstated versus understated

Left: Easy to overstate
- Reading 173 million addresses as 173 million affected people.
- Treating an exposed SHA-1 hash as an exposed or cracked password.
- Folding OMGPOP, or the 12 million dollar casino settlement, into this breach.
Right: Easy to understate
- Account credentials have value independent of payment-card data.
- Credential reuse is the real cross-service risk after exposure.
- A standing dismissal does not erase the acknowledged incident.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts from [2][3][4][9][11]; the casino settlement in [9] is a Washington matter, not this breach.

## CLOSE | Precision beats the largest number

- The strongest account is not the one with the largest number or the most elaborate attack diagram.
- It preserves the company warning, the described corpus, separate incidents and a changing posture.
- Keep the breach date, the dump date and the disclosure date distinct; label every count.
- No attacker identity, no original forensic report and no complete cost are established here.
Caption: Evidence grade: case-specific conclusions, bounded to the sources.
Notes: Conclusion synthesis across [1] through [11]; precision over an unsupported victim total.
