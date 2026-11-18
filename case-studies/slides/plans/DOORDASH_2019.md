# Slide plan: DoorDash 2019: Vendor Access and Breach Scope Discipline

- Study: case-studies/DOORDASH_2019.md
- Cover title: DoorDash 2019 / Vendor Access and / Breach Scope Discipline
- Subtitle: A third-party access incident where the record fixes dates and a notification subgroup, not the attacker, exploit chain or overall total.
- Published: 18 November 2026
- Notes: The cover sets the frame: a vendor-access breach scoped by evidence, not a reconstructed attack narrative.

## EXECUTIVE SUMMARY | One number cannot explain a multi-community breach

- Consumers, Dashers and merchants held different data fields and different payment relationships.
- A single affected-population number cannot explain those differences; scope needs a population, a category and evidence per statement.
- The strongest contemporaneous record is the company notice preserved by the California Attorney General.
- Hosting by a regulator aids preservation; it does not make a company notice an independent regulatory finding.
Caption: Evidence grade: Confirmed company notice; no independent regulator finding.
Notes: Executive-assessment framing from [1] and [2]; the notice identifies categories and a California population but no named attacker or exploit chain.

## KEY FACTS | Three dated milestones and one corrected population

Stat: 41,740 | California name & license notice subgroup
Stat: 124 | Days from access date to awareness
Stat: 21 | Days from awareness to notices
Stat: $1M | 2019 legal-matter costs in the filing
- Identified access date May 4, 2019; awareness September 5; notifications began September 26, 2019.
- The record names no attacker, no CVE and no complete exploit chain.
- The appendix corrected an earlier total-population figure while leaving the California count unchanged.
- 41,740 is a specific notification subgroup, not an overall affected-account count.
Caption: Evidence grade: Confirmed dates and counts, as stated by the notice.
Notes: Dates, the 41,740 subgroup and the correction from [2]; the $1 million legal-matter cost from [3].

## PART 1 | Three dates are not one dwell-time number

The appendix supplies three milestones; subtraction between them does not prove continuous attacker presence.

| Date | Milestone | Does not establish |
|---|---|---|
| May 4, 2019 | Identified access date | Continuous attacker dwell time |
| Sep 5, 2019 | Awareness of unusual activity | Knowledge during the prior interval |
| Sep 26, 2019 | Notification began | That every system was already contained |
Caption: Evidence grade: Confirmed milestones; the intervals are calculated, not proven dwell time.
Notes: Awareness, access and notification dates from [2]; 124 and 21 days are intervals between stated milestones, not evidence of continuous access.

## PART 1 | Keep affected, accessed and compromised distinct

- A field listed as potentially involved for some recipients is not confirmed for every recipient.
- Separate a dataset that contains a field from a field populated for a particular person.
- Keep records exposed or at risk distinct from records confirmed accessed or misused.
- Keep an unauthorized third party distinct from a contracted third-party service provider.
Caption: Evidence grade: Confirmed notice language; the distinctions are evidence discipline.
Notes: Field and population distinctions from [1] and [2]; the actor-versus-relationship point is drawn from the vendor-involvement discussion in [3].

## PART 1 | The notice bounds fields to a named population

- The sample notice says the recipient's name and driver's-license number were involved.
- It lists possible profile fields, hashed and salted passwords and the last four bank-account digits.
- It states full bank-account information was not accessed and offered protective services to the license group.
- These are company statements tailored to one notice population, not a uniform claim about all users.
Caption: Evidence grade: Confirmed company statements for a specific notice group.
Notes: Field list, the no-full-bank-account statement and the protection offer from [1]; the join-on-or-before April 5, 2018 boundary from [2].

## PART 1 | A corrected figure is part of the evidence

- The appendix says an earlier total-population figure was incorrect while the California count stayed unchanged.
- It does not print the original mistaken number or a corrected overall total.
- The source supports that a correction occurred, not a numerical reconciliation beyond what it states.
- Counts must name their unit: person, account, merchant location, notice recipient and database row differ.
Caption: Evidence grade: Confirmed correction; no reconciled worldwide total in the record.
Notes: The population correction and the unchanged California count from [2]; this study does not manufacture an overall figure from a headline.

## PART 2 | Vendor involvement is not a named exploit chain

Left: What the filing states
- A vendor incident produced unauthorized acquisition of certain Dasher license and consumer data.
- It reports resulting regulatory inquiries and litigation.
Right: What it does not supply
- The provider is not identified in the retrieved record.
- No technical sequence attributes it to phishing, exposed storage, an app flaw or an insider.
Caption: Evidence grade: Confirmed filing description; exploit chain unresolved in the record.
Notes: Vendor-incident description, inquiries and litigation from [3]; a later vendor-phishing support notice is kept as a separate event only, not imported into 2019 [5].

## PART 2 | A salted verifier is not a recovered password

- The notice describes passwords as hashed and salted and encourages a unique replacement.
- Reassuring language is not a guarantee that every password behind a stolen verifier is unrecoverable.
- The documents do not disclose the algorithm, work factor or password distribution needed to assess resistance.
- Separate three questions: readable passwords obtained, verifiers obtained and account access observed.
Caption: Evidence grade: Confirmed notice language; resistance not assessable from the record.
Notes: Hashed-and-salted description and the replacement advice from [1]; the study provides no password-cracking procedure and treats historical enrollment links as not current advice.

## PART 2 | Partial identifiers and license numbers differ

- The last four digits of a card or bank account do not carry a full credential's transactional capability.
- Fragments are not meaningless: they can lend familiarity to a deceptive conversation or weak verification.
- A driver's-license number is an identity attribute harder to change than a password.
- Response should separate support for a license-exposed person from someone with contact data only.
Caption: Evidence grade: Inferred risk analysis, not proof of downstream fraud here.
Notes: Partial-identifier and license-persistence reasoning from [1]; the study asks readers not to transmit identity documents through historical forms.

## PART 2 | Historical data keeps its cost while it stays reachable

- Support, disputes, accounting and legal duties may justify some retention; indefinite accumulation is different.
- A record's security cost continues as long as it stays accessible, including through providers.
- A retention review should start from purpose and ownership and cover exports and provider-held copies.
- Testing should trace a synthetic over-retention record to its expected deletion or restriction.
Caption: Evidence grade: Inferred; proposed practice, not a claim about DoorDash's systems.
Notes: Retention and historical-boundary discussion from the study; the join-date cutoff in [2] raises retention questions without proving a legacy-system root cause.

## PART 2 | Materiality and a reported cost answer different questions

- The November 2020 filing reported no material revenue loss or expenses to that point.
- An adjustment note identified $1 million of 2019 legal-matter costs tied to the incident.
- The $1 million is not a lifetime breach cost, a per-person award or a regulatory fine.
- The March 2020 SEC staff letter asked for magnitude, consequences and remediation, not an enforcement finding.
Caption: Evidence grade: Confirmed filing figures; the letter is a disclosure-review request.
Notes: Materiality statement and the $1 million legal-matter cost from [3]; comment 7 of the SEC staff letter from [4], which is not a finding that a rule was violated.

## DEFENDER VIEW | Design provider access and logging to answer later

- Separate provider identity from employee identity and link every service account to a business owner.
- Express permissions by task and data field; a bulk export should not look like an ordinary lookup.
- Keep a tested revocation path that disables a provider identity and invalidates active tokens and sessions.
- Design logs backward from the questions: which identity, which fields, whether an export, start and end.
Caption: Evidence grade: Original defensive analysis for comparable platforms.
Notes: Provider-access architecture and monitoring recommendations from the study; the 2015 NIST SP 800-161 is historical context only and was withdrawn in May 2022 [6].

## CROSS-CUTTING THEMES | What the retelling overstates and understates

Left: Easy to overstate
- One worldwide victim total summing non-comparable populations.
- A hosted company notice read as an independent regulator finding.
- A named exploit chain inferred from vendor involvement.
Right: Easy to understate
- Awareness, access and notification are three separate dated milestones.
- A corrected population figure is evidence, and its earlier version should survive.
- License exposure persists in ways a password reset cannot address.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn across the study; counts and denominators from [2], vendor scope from [3].

## CLOSE | A scope ledger beats an invented victim total

- Keep a scope table with dataset, data category, population, access evidence and confidence per row.
- Link geographic subsets to their parent population so later writers do not add them twice.
- Retain each estimate version and state the reason a figure changed, separating error from new exposure.
- State what the record proves, name what is unknown and design tests that would resolve the open questions.
Caption: Evidence grade: case-specific conclusions bounded to the sources.
Notes: Scope-ledger and correction-record discipline from [1] through [4]; the study avoids borrowing details from later DoorDash incidents or unrelated vendor compromises.
