# Slide plan: Twitch 2021 leak

- Study: case-studies/TWITCH_2021.md
- Cover title: Twitch 2021 / Code and Payouts / Limits of the Record
- Subtitle: How a 2021 server-configuration exposure leaked Twitch source code and creator payout data, and why that is not the same as a password breach.
- Published: 18 November 2026
- Notes: The cover frames the incident as a confidentiality and response problem held to a short, bounded public record.

## FRAMING | Confidentiality and response, not a breach
- Best studied as a confidentiality and response problem, not automatically a password breach.
- A platform can need urgent protective action without proof that every password was taken.
- Preserving login security does not make exposed business information unimportant.
- The record is short, so findings stay bounded rather than reconstructed.
Caption: Evidence grade: Inferred from the company record
Notes: This slide sets the analytical stance before any dated facts are introduced.

## OCTOBER RECORD | Three updates, one short record
Twitch's incident page carried three timestamped updates across ten days.

| Date (Pacific) | What Twitch reported |
| --- | --- |
| Oct 6, 10:30 p.m. | Erroneous server-configuration change and malicious access; no indication of exposed login credentials |
| Oct 7, 1 a.m. | Precautionary replacement of all stream keys, with instructions varying by software |
| Oct 15, 8 a.m. | Configuration remediated; source documents and some payout data the principal exposed material; passwords not exposed |
Caption: Evidence grade: Confirmed (company statement, inspected)
Notes: These are disclosure milestones, not a complete intrusion timeline.

## SCALE | What the public record actually sizes
Stat: 125GB | reported size of the leaked data set
Stat: 3 | timestamped Twitch updates, Oct 6 to 15
Stat: Oct 6 | first disclosure, 2021 Pacific time
- The figures size the disclosure, not an independently measured intrusion.
- A publication date is not an intrusion date or a first-access timestamp.
Caption: Evidence grade: Reported (leak size); Confirmed (update count)
Notes: The numbers describe the public record rather than a forensic reconstruction.

## ROOT CAUSE | A broad diagnosis, not an exploit map
Left: What the statement establishes
- Root-cause category was an erroneous server-configuration change.
- Malicious third-party access occurred.
- Source documents and some payout data were the principal exposed material.
Right: What it does not establish
- The affected service, before-and-after settings or effective permissions.
- A named vulnerability, open storage bucket or specific cloud-policy failure.
- Attacker identity, sophistication or dwell time.
Caption: Evidence grade: Confirmed (category); Inferred (specifics unresolved)
Notes: A broad documented diagnosis names a question for internal review rather than a guessed culprit.

## SECRETS | Passwords and stream keys differ
- An account password and a broadcasting authorization key are different objects with different lifecycles.
- Resetting one does not reveal the exposure status of the other.
- Precautionary rotation reduces prospective risk but cannot retract data already copied.
- Recovery messaging should map each action to the exact credential and workflow.
Caption: Evidence grade: Confirmed (stream-key reset); analysis otherwise
Notes: Separating access revocation from confidentiality restoration keeps the response honest about what rotation can and cannot do.

## RECOVERY | A working next broadcast is the test
- October instructions separated connected streaming accounts from manual stream-key setups.
- Several named applications and consoles were said to need no user action.
- Different integration methods produce different recovery experiences.
- Success is a working next broadcast, not merely receipt of an announcement.
Caption: Evidence grade: Confirmed (instructions); Inferred (recovery analysis)
Notes: A response team should identify integration differences before issuing one universal instruction.

## CONFIRMED VS STATED-OUT | What was in, what was not
Left: Reported in the exposed data
- Source-repository documents.
- Some creator-payout data.
Right: Twitch stated not exposed in the leak
- Login passwords.
- Credential systems, expressed as not accessed.
- Full card numbers and bank-account information.
Caption: Evidence grade: Reported (company statement)
Notes: Keeping these columns distinct separates a code-and-data leak from a credential compromise.

## SOURCE CODE | Reading code is not running production
- Repository access shows how a program is written, not authority to run it in production.
- The record does not establish altered production software or a later supply-chain attack.
- Circulating files should be treated as unverified, not authentic, current or complete.
- A bounded review checks for sensitive operational data and any credentials needing rotation.
Caption: Evidence grade: Inferred (confidentiality boundary)
Notes: Describing every source-code exposure as a supply-chain compromise blurs information access and software integrity.

## PAYOUTS | A payout is one stream, not income
- A platform payout is one revenue stream, gross, over a bounded period.
- It is a partial view, not any creator's complete earnings.
- The study does not reproduce or rank individual payout amounts.
- A genuine figure can still mislead when described as total income.
Caption: Evidence grade: Confirmed (payout data exposed); aggregate handling only
Notes: Factual accuracy about a disclosed value does not supply interpretive accuracy about wealth or fairness.

## EARLIER EVENTS | 2013 and 2015 are separate
Earlier Twitch notices are included to prevent historical conflation.

| Event | What the notice said |
| --- | --- |
| June 2013 | A caching change could expose limited data including stream keys and password hashes; resets required; denied a hack |
| March 2015 | Warned of possible unauthorized access to some account information; expired passwords and stream keys |
Caption: Evidence grade: Confirmed (notices inspected)
Notes: A shared brand and a recurring protective action do not connect separate incidents into one intrusion.

## ENFORCEMENT | A reported penalty, read with care
Stat: TRY 2M | reported KVKK administrative penalty total
Stat: 35,274 | Turkey-resident affected people, reported
Stat: Nov 2024 | news report publication date
- The penalty split was TRY 1.75M for security measures and TRY 250,000 for non-notification.
- The original decision text and payment proof were not obtained, so the report is the limit.
- A regional population is not a global victim total, and a sanction is not compensation.
Caption: Evidence grade: Reported (news item); decision not independently inspected
Notes: A later regulator's assessment and the 2021 company characterization answer different questions.

## UNKNOWNS | What the record does not settle
- Attacker identity and the original deployment change remain unresolved.
- A first-access timestamp and the full dwell period are not in the record.
- The exact exposed repository inventory and individual losses are not established.
- Total response cost and any final judicial outcome are not settled.
Caption: Evidence grade: Confirmed (stated gaps in the record)
Notes: A clearly marked unknown is more informative than a confidently drawn fictional connection.

## LESSONS | Reason separately about records and secrets
- Reason separately about confidential records, software knowledge and authorization secrets.
- Replace claims of complete compromise with the specific exposed categories.
- Use disclosure dates rather than an invented first-access date.
- Keep company assurances attributed and time-stamped.
Caption: Evidence grade: Inferred (editorial discipline)
Notes: A study that preserves these differences is more useful than a narrative claiming everything happened to everyone at once.
