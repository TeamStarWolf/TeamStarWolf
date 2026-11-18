# Slide plan: Cathay Pacific 2018: Evidence That Survives Recovery

- Study: case-studies/CATHAY_PACIFIC_2018.md
- Cover title: Cathay Pacific 2018 / Passenger Data and Migration / Evidence That Survives Recovery
- Subtitle: A 2018 passenger-data breach where field counts, person counts, breach dates and a regulator's penalty must each be kept distinct.
- Published: 18 November 2026
- Notes: The cover sets the frame: a data-exposure case read on the public record, no attacker country or flight-safety claim.

## EXECUTIVE SUMMARY | Personal-data security failed across many boundaries

- Cathay Pacific shows personal-data security failing across several organizational boundaries at once.
- The boundaries span internet-facing services, remote access, administrative privilege and migration copies.
- Removing a compromised server reduces exposure but can make a later independent review harder.
- Passenger data is not homogeneous; a password assurance does not answer travel-history or passport questions.
Caption: Evidence grade: Executive framing; sources are [1] through [5].
Notes: Executive-assessment framing; no attacker country, named group or flight-safety inference is drawn [1][3].

## KEY FACTS | One disclosure, several counts that are not one total

Stat: 9.4M | Affected people, October 24 filing
Stat: 860K | Passport numbers reported exposed
Stat: 245K | HK identity-card numbers reported
Stat: 500K | ICO penalty, GBP under DPA 1998
- Counts are as reported, approximate, and must not be summed into a single victim total.
- The filing also reported 403 expired card numbers and 27 card numbers without CVV.
- It stated no complete travel or loyalty profile and no passenger password was compromised.
Caption: Evidence grade: Reported company counts; Confirmed penalty.
Notes: Field counts and company statements from the October 24 filing [1]; the GBP 500,000 penalty from the ICO notice [3].

## PART 1 | A field count is not a person count

- A number of passport identifiers is not the same as a number of unique current passport holders.
- A number of exposed fields does not establish a number of complete passenger profiles.
- One passenger can appear in several categories, so the counts must not be added together.
- The record does not support treating every affected passenger as having the same fields exposed.
Caption: Evidence grade: Reported company counts; interpretation is analysis.
Notes: Field-versus-person discipline; counts and the category list come from the October 24 filing [1].

## PART 1 | Keep the subject of every security assurance

- A statement about passenger passwords does not imply that no staff credential was stolen elsewhere.
- Separation from flight-operation systems does not imply that passenger privacy was unaffected.
- State the relevant system or identity class whenever the word "compromised" is used.
- "Affected" and "compromised" are different claims and should not be merged.
Caption: Evidence grade: Reported statements; the precision rule is analysis.
Notes: The company said affected systems were separate from flight operations and reported no flight-safety impact [1].

## PART 2 | Chronology needs several tracks, not one breach date

A single breach date cannot serve every purpose, so each point names its track.

| Track | Date or finding | Source |
|---|---|---|
| Earliest known compromise | October 2014 | ICO notice [3] |
| Suspicious activity detected | March 2018 | Company filing [1] |
| Personal-data access confirmed | Early May 2018 | Company filing [1] |
| Last unauthorized data access | May 11, 2018 | ICO notice [3] |
| Public disclosure | October 24, 2018 | Company filing [1] |
Caption: Evidence grade: Confirmed dates; tracks kept distinct.
Notes: Earliest compromise and the May 11, 2018 last access from the ICO notice; detection and disclosure from the filing [1][3].

## PART 2 | Technique can separate clusters, not assign identity

- The ICO notice described two attacker groups distinguished by their techniques.
- It left one group's initial access unresolved and qualified the other's suspected entry.
- Different techniques can support separating activity clusters, not nationality or sponsorship.
- An unknown entry path should stay visible rather than be filled from a vulnerability found elsewhere.
Caption: Evidence grade: Confirmed account; attribution kept descriptive.
Notes: Two groups, an unresolved entry path and the October 2014 to May 2018 window from the ICO notice [3].

## PART 3 | The Hong Kong findings connect controls, not one flaw

- The PCPD criticized annual-only scanning, an exposed management interface and incomplete remote-access MFA.
- It also found unencrypted migration backups, an inadequate data inventory and unnecessary retention.
- It found security and retention contraventions and issued an enforcement notice.
- It did not find sufficient evidence to attribute the incident to IT-department restructuring.
Caption: Evidence grade: Confirmed regulatory findings.
Notes: Report R19-15281, June 6, 2019; the restructuring question stays unproven, not a finding [2].

## PART 3 | The UK penalty is not a measure of total loss

- The ICO imposed a 500,000-pound penalty under the Data Protection Act 1998, not under GDPR.
- Its notice identified 111,578 UK data subjects within the global affected population.
- A penalty does not quantify each passenger's harm, every response cost or the value of stolen data.
- A ceiling under one historical framework is not comparable with a later penalty under another.
Caption: Evidence grade: Confirmed imposed amount; not an amount paid.
Notes: February 10, 2020 notice; it acknowledged uncertainty about an unsupported system's contribution [3].

## PART 4 | Notification law and a useful warning differ

- The PCPD found no notification contravention under the then-applicable ordinance, which had no mandatory rule.
- It still considered that passengers could have received an earlier warning.
- "No violation of this rule" and "the communication best served affected people" are different conclusions.
- A notice should separate confirmed fields from fields still under review.
Caption: Evidence grade: Confirmed historical positions.
Notes: PCPD finding and the government's June 2019 response, both historical and jurisdiction-specific [2][5].

## DEFENDER VIEW | Treat a migration copy as a data-bearing asset

- A migration creates new data paths; an export can move more easily than the production database.
- Encryption depends on where the key resides and which identity can use it, not just a label.
- An exception record should name the data, the business reason, the duration and the alternative protection.
- Completion needs a cleanup step confirming no temporary copies remain in staging, downloads or shares.
Caption: Evidence grade: Original defensive analysis.
Notes: Derived from the PCPD migration-backup finding; cleanup uses synthetic markers, never real identifiers [2].

## DEFENDER VIEW | Preserve evidence before recovery removes it

- Recovery and preservation need a shared decision point before a system is rebuilt or retired.
- Preserved material needs provenance: source system, collection time, collector, method and integrity checks.
- Define which artifacts stay available, for how long and under whose authority for independent review.
- State evidence gaps plainly rather than borrowing certainty from another system.
Caption: Evidence grade: Original defensive analysis.
Notes: The ICO notice criticized missing preservation evidence and policy exceptions during recovery [3].

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Overstated in the usual retelling
- Summing separate field counts into a single victim total.
- Reading the 2020 penalty as a GDPR fine or total incident loss.
- Treating removal of a server as a complete response.
Right: Understated and worth keeping
- Different fields were exposed for different passengers.
- Breach date, discovery date and notification date are distinct.
- A regulator's finding carries a different status from a company's statement.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Distinctions drawn across the filing and both regulators; no victim count is invented beyond the record [1][2][3].

## CLOSE | A specific, testable claim beats a simple story

- Sensitive data moves through production systems, temporary projects and historical repositories.
- Each movement creates another responsibility for access, retention and evidence.
- State which path changed, which data is now protected, which exception ended and which evidence remains.
- Acknowledge what the test did not cover rather than promising no future intrusion.
Caption: Evidence grade: a conclusion synthesis.
Notes: Final-assessment synthesis across the study's record [1][2][3].
