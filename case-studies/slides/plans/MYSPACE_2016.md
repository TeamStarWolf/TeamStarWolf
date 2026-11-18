# Slide plan: MySpace 2016: Old Credentials, Disputed Date

- Study: case-studies/MYSPACE_2016.md
- Cover title: MySpace 2016 / Old Credentials, New Exposure / Disputed Date
- Subtitle: The 2016 disclosure is firm; the extraction date is not, so this study keeps records, hashes and sale dates distinct from one breach year.
- Published: 18 November 2026
- Notes: Cover frames a disputed date, not a single 2016 hack; evidence labels stay attached throughout.

## EXECUTIVE SUMMARY | A firm 2016 disclosure, an unresolved extraction date

- The dataset became publicly known in 2016, when Time Inc. issued notices; that is the disclosure anchor.
- The account age, copied-data age, extraction date and sale date are not necessarily the same.
- The study separates account records from people, hashes from plaintext, and a seller's alias from a proven intruder.
- Substantial disclosure documentation exists, but no public forensic report reconstructs the original entry method.
Caption: Evidence grade: Confirmed disclosure; extraction date disputed.
Notes: Executive-assessment framing; primary filings and dataset analysis do not support one unqualified breach date. [1][4][7]

## KEY FACTS | Close-magnitude counts with different definitions

Stat: 360M | Accounts offered for sale (10-Q)
Stat: 359.4M | Unique email addresses (HIBP)
Stat: ~2008 | Hunt data-age estimate
Stat: 2013 | Relaunch cutoff, June 11
- The 10-Q reports accounts offered for sale; HIBP counts distinct email addresses; those units differ.
- Hunt favored mid-2008 to early 2009 while allowing that an older set could be stolen later.
- May 31, 2016 is the announcement and notice date, not a proven day of intrusion.
- Legacy data predates the June 11, 2013 relaunch; post-relaunch storage was described as double-salted hashes.
Caption: Evidence grade: Confirmed filings and dated records.
Notes: Account figure from [4]; address count and format from [8]; data-age estimate from [7]; relaunch and attribution from [1][3].

## PART 1 | The company could reset its own service only

- Time Inc.'s May 31, 2016 notice described legacy usernames, passwords and emails from before the 2013 relaunch.
- It said financial information did not appear involved, affected passwords were invalidated, and law enforcement was engaged.
- The company blog attributed the breach, as a company belief, to an alias called Peace.
- A reset invalidates credentials on Myspace; it cannot invalidate a reused secret at another service.
Caption: Evidence grade: Confirmed notice; attribution is a company belief.
Notes: [1][2][3]; credential reuse is the cross-service risk, and the record does not quantify how many users reused passwords.

## PART 1 | Filings add an interval the notices never stated

The quarterly and annual filings report a likely interval, each with what it does not prove.

| Filing | What it reports | Does not establish |
|---|---|---|
| 10-Q, Jun 30 2016 | ~360M accounts for sale; June 2013 to mid-2015 likely | A proven exact intrusion date |
| 10-K, 2016 | Repeats the interval; no material business impact | Each user's privacy or downstream loss |
| Viant 10-K, 2021 | Pre-June 2013 framing; ~360M accounts | A reconciliation of the earlier range |
Caption: Evidence grade: Confirmed filings; issuer-reported forensics.
Notes: [4][5][6]; the underlying forensic report was not retrieved, and the 10-Q also records a March 2, 2016 acquisition of Viant assets.

## PART 1 | What dataset analysis can date, and what it cannot

- Hunt compared email-provider proportions and welcome-email evidence, favoring mid-2008 to early 2009.
- He described 359,420,698 unique addresses and cautioned that Peace might be a seller, not the intruder.
- HIBP lists an approximately 2008 breach and a May 2016 sale, while saying the exact date is unknown.
- A small volunteer sample bounds individual records, not every record in a far larger collection.
Caption: Evidence grade: Reported analysis with explicit uncertainty.
Notes: [7][8]; these are analytical observations and hypotheses, not findings from the company's servers.

## PART 1 | Data age and extraction time are not the same

- A population cutoff can reflect extraction then, a later archival copy, an incomplete export, or a filtered set.
- These are alternative interpretations, not claims that any one of them occurred at Myspace.
- Email-provider distribution is conditional; a platform's audience need not mirror all email users.
- Without a trustworthy acquisition history, a population cutoff alone does not fix a timestamp.
Caption: Evidence grade: Inferred reasoning, not a forensic timeline.
Notes: [7][8]; the difference between data age and extraction time is substantive, not merely semantic.

## PART 2 | An exposed hash is not an exposed password

- HIBP characterizes the legacy store as unsalted SHA-1 hashes of lowercased, ten-character-truncated passwords.
- A fast unsalted hash, lowercasing and truncation are three distinct weaknesses, not broken encryption.
- A one-way hash is not encrypted text meant to be decrypted with a secret key.
- The study did not acquire the dump or attempt recovery, and does not claim every hash was cracked.
Caption: Evidence grade: Reported format; no cracking performed or claimed.
Notes: [8]; keep accounts present in the dump distinct from passwords actually recovered.

## PART 2 | Upgrading a live verifier does not reach old copies

- A newer authentication system may protect future logins while an older copy stays exposed.
- Double-salted hashing is a company assertion with no disclosed work factor to evaluate.
- Upgrading a production verifier does not retroactively transform copies already outside the organization's control.
- The reviewed sources reveal no full storage inventory, so the study invents none.
Caption: Evidence grade: Inferred lifecycle point; design details undisclosed.
Notes: [3][8]; a statement that production improved does not date when every legacy store or backup was retired.

## PART 2 | Accounts, addresses and people are different units

- The ~360M account figure and the 359.4M address count are close in magnitude but defined differently.
- One person may hold several addresses or accounts; one address may recur across records.
- A count of distinct addresses is not a count of reachable living individuals.
- Hundreds of millions of affected records is not a proven census of people with documented loss.
Caption: Evidence grade: Confirmed counts; no synthetic victim total.
Notes: [4][8]; "affected records" and "unique people" must not be merged into one figure.

## PART 2 | The seller is not necessarily the intruder

- Advertising stolen data proves access to a copy, not the original intrusion method or identity.
- The study does not adopt the notice's nationality label as an independently established identity.
- No retrieved finding attaches a state sponsor, malware family, insider culprit or conviction.
- Repeating an unverified actor across title, slide and tracker can look like three confirmations.
Caption: Evidence grade: Reported attribution; claimed, not confirmed.
Notes: [3][7]; possession and sale are evidence of access to a copy, not proof of the original compromise.

## PART 2 | The 2012 FTC order is background, not a breach penalty

- In September 2012 the FTC finalized a settlement over Myspace's personal-information representations.
- It required a privacy program and periodic independent assessments for twenty years, barring future misrepresentation.
- That dispute concerned sharing user identifiers with advertisers, a separate privacy-practices matter.
- No retrieved finding says the 2016 credential incident violated that order.
Caption: Evidence grade: Confirmed order; separate from the 2016 dataset.
Notes: [9]; distinguish a prior obligation, a possible enforcement risk and a completed enforcement finding.

## DEFENDER VIEW | Keep every date and unit tied to its source

The matrix prevents category errors; each question needs its own evidence.

| Question | Useful evidence | Invalid shortcut |
|---|---|---|
| When copied? | Custody or forensic record | A repeated 2008 label |
| How many people? | Identity-resolved harm evidence | A distinct-address count |
| Who intruded? | An investigative finding | A seller's advertised alias |
| Password exposed? | Recovery or reuse evidence | An exposed hash alone |
| Breach date? | Reconciled filing and analysis | A single sortable year |
Caption: Evidence grade: an original review tool.
Notes: [1][4][7][8]; preserve conflicts and name the evidence that would resolve them.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- A single, exact "2008 hack" date for the intrusion.
- An exposed hash read as a usable plaintext password.
- A distinct-address count read as unique harmed people.
Right: Easy to understate
- Legacy credentials stay consequential after a platform changes.
- A reset's reach is narrower than the credential-reuse problem.
- Disclosure histories need separate discovery, sale and filing dates.
Caption: Evidence grade: editorial corrections the case requires.
Notes: [2][4][7][8]; keep units and dates labeled rather than merged.

## CLOSE | Preserve the conflict; name what would resolve it

- A 2016 disclosure anchor sits beside an unresolved extraction date, and the study keeps both.
- A reset protects one service; credential reuse is the cross-service risk.
- The highest-value evidence is the referenced forensic report or an authoritative account of the dataset's custody.
- When authoritative records conflict, preserve the conflict and state what evidence would resolve it.
Caption: Evidence grade: case-specific conclusions, bounded to sources.
Notes: [1][4][5][7]; the disclosure history is supported more strongly than a complete legal aftermath.
