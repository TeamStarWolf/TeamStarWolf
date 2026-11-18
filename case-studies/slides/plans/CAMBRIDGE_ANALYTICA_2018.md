# Slide plan: Cambridge Analytica and Facebook 2018

- Study: case-studies/CAMBRIDGE_ANALYTICA_2018.md
- Cover title: Consent / Data lineage / Platform accountability
- Subtitle: How personal data moved from a quiz app and permissive friends-permissions to Cambridge Analytica, treated as a consent failure, not a hack.
- Published: 18 November 2026
- Notes: The cover frames the case as a privacy, consent and data-provenance matter rather than a network intrusion.

## CASE FRAME | Not a breach, a consent failure
- The collection used Facebook's developer channels, not stolen passwords or infiltrated systems, per Facebook's own account.
- The security questions are about authority to collect, what people were told, and movement of data between organizations.
- Access through a functioning permission flow is not proof of meaningful consent or of an authorized downstream use.
- The FTC later found deceptive collection representations, so a platform can operate as designed while its data practices cause harm.
Caption: Evidence grade: Confirmed (FTC finding); technical route Reported (Facebook)
Notes: This slide fixes the central distinction between a consent gap and a conventional hack.

## TIMELINE | More than one starting point
The controversy peaked in 2018, but collection and transfer began earlier, and each date carries its own source.

| Date | Event | Source |
| --- | --- | --- |
| 2014 to 2015 | Graph API access to app users and friends | FTC complaint (alleged) |
| 2015 | Facebook says it learned data was passed on | Facebook statement |
| Mar 2018 | App suspended; deletion certifications requested | Facebook statement |
| Apr 2018 | Up to 87M people possibly affected | Facebook estimate |
| Jul 2019 | $5B FTC and $100M SEC settlements announced | FTC and SEC |
| Nov 2019 | FTC opinion and final order against the firm | FTC order |
Caption: Evidence grade: Confirmed and Reported; each date labeled by source
Notes: The chronology separates collection, awareness, disclosure and regulatory action instead of forcing a single date.

## CONSENT | A working flow is not meaningful consent
- Facebook stressed the technical route through developer channels; the FTC addressed the accuracy of what users were told.
- The Commission record cited an assurance the app would not collect identifying information, despite collection of persistent user identifiers.
- A persistent identifier that links to a profile can carry identifying significance even when a display-name field is absent.
- Consent can go stale when a product gains a new owner, purpose or recipient, which should trigger renewed review.
Caption: Evidence grade: Confirmed (FTC finding on representations)
Notes: The slide shows why a click is not an unlimited license and why wording must be tested against the data path.

## POPULATION | The 87M figure is an estimate
Stat: 87M | Facebook estimate of people possibly affected
Stat: 250K | Lower bound of direct app users, FTC record
Stat: 65M | Upper bound of friends in the FTC record
Stat: 30M | Identifiable US consumers, at least, FTC
- The 87M figure used the words "up to" and "may"; it is possible sharing, not proven receipt or changed votes.
- FTC categories describe a different evidentiary record and should not be added to the Facebook estimate.
Caption: Evidence grade: Reported (company estimate); Confirmed (FTC ranges)
Notes: The slide keeps the counting unit explicit and resists presenting the memorable number as a definitive count.

## SCOPE | One user's click exposed their friends
Left: Direct app users
- Roughly 250,000 to 270,000 installed the "thisisyourdigitallife" app, per the FTC complaint.
- These users saw and accepted the permission flow.
- Their consent question centers on what they understood.
Right: Friends reached through that consent
- The FTC record describes 50M to 65M friends.
- It includes at least 30M identifiable US consumers.
- The core failure: one user's consent exposed non-users' data.
Caption: Evidence grade: Confirmed (FTC complaint ranges)
Notes: The friends-permission scope is isolated as the central platform design failure.

## LINEAGE | Following data across boundaries
- The useful model is a sequence of transformations: platform, app, recipient storage, linkage, derived product.
- Every transition can change who controls the data and the purpose it serves, so recording only the first export is insufficient.
- A lineage record should hold the originating system, authority, permitted uses, recipients and expected retention.
- Contracts align with behavior when the provider can identify recipients and holds proportionate verification rights.
Caption: Evidence grade: Inferred (defensive governance model)
Notes: The slide converts the case into a provenance discipline for any data-sharing program.

## APP REVIEW | Legacy permissions outlive context
Left: New-app controls
- Each requested field ties to a visible user benefit and a defined purpose.
- Reviewers can reject broad access without breaking the core function.
- Approval is not the end; growth or new recipients prompt renewed scrutiny.
Right: Legacy exceptions
- A migration can tighten new apps while preserving old behavior for existing ones.
- Each exception needs an owner, an expiry condition and a usage measure.
- Ownership transfer can carry authority forward after the original context is gone.
Caption: Evidence grade: Demonstrated (control design)
Notes: The slide separates forward-looking review from the risk register that legacy exceptions require.

## DELETION | A certificate is not proof of removal
- The FTC final order required identifying recipients and destroying covered app information and related work product, including derived algorithms.
- An order establishes an obligation; it does not by itself prove that every copy or derivative was removed.
- Removal spans backups, extracts, feature stores, model artifacts and archived outputs, not one database table.
- A verification package should name systems searched, owners, methods and exceptions, and keep legal holds distinct from deletion.
Caption: Evidence grade: Confirmed (FTC order); full removal Inferred
Notes: The slide treats a deletion certificate as a scoped claim to verify, not a guarantee.

## ENFORCEMENT | Distinct figures, distinct proceedings
Stat: $5B | FTC 2019 Facebook settlement, broader
Stat: $100M | SEC 2019 Facebook disclosure settlement
Stat: 500K | ICO 2018 penalty, GBP, under DPA 1998
- These are separate proceedings with different payers, legal bases and dates, and should not be summed.
- The SEC case concerned investor disclosure; the FTC case concerned privacy governance; neither was paid by the firm.
Caption: Evidence grade: Confirmed (FTC, SEC and ICO releases)
Notes: The slide presents a ledger by proceeding so the amounts are not read as one damages award.

## UK OUTCOME | The penalty and its limits
- The preserved ICO statement reports a 500,000 GBP penalty under the Data Protection Act 1998 in October 2018.
- In October 2019 the parties withdrew their appeals and Facebook agreed to pay without admitting liability.
- The money went to the Treasury's consolidated fund; it was not a GDPR turnover penalty or a user compensation fund.
- The original ICO page and full report were outside the attempted retrieval paths, so the account relies on the preserved release.
Caption: Evidence grade: Reported (preserved ICO release)
Notes: The slide keeps the UK outcome attributed to its source and marks where the record is incomplete.

## CAUSATION | Capability is not proven effect
Left: What the record supports
- Deceptive collection representations, per the FTC finding.
- Loss of control over personal information.
- Persistent identifiers collected despite a non-identifying assurance.
Right: What it does not establish
- That a dataset determined an election.
- That a profile match proves a message was received.
- That exposure to a message proves persuasion.
Caption: Evidence grade: Confirmed (misuse); effectiveness claims unproven
Notes: The slide keeps data misuse as the confirmed harm while marking electoral efficacy as contested.

## RESPONSE | An incident category for misuse
- A response process keyed only to malware, stolen credentials or abnormal traffic can miss misuse through ordinary business channels.
- Reports from researchers, users or employees need a route to investigators who can examine purpose, permissions and recipients.
- Containment can restrict future access and preserve logs while facts are established, without destroying evidence of prior processing.
- Escalation should reach the owners of external statements so conditional public language can be updated when a risk materializes.
Caption: Evidence grade: Demonstrated (process design)
Notes: The slide defines a misuse-through-consent incident path distinct from a breach runbook.

## TESTING | Probe words, permissions and use
Five tests trace the gap between what a product says, what it permits and what recipients actually do.

| Test | What it checks |
| --- | --- |
| Permission-to-purpose | Trace each requested field to a documented function |
| Representation trace | Compare the permission screen with a collection record |
| Lifecycle change | Simulate ownership transfer and permission expansion |
| Downstream removal | Find exports and artifacts, confirm deletion, note gaps |
| Disclosure escalation | Route a finding that contradicts a public statement |
Caption: Evidence grade: Demonstrated (control-testing plan)
Notes: The slide turns the analysis into repeatable acceptance tests with expected results set before testing.

## TAKEAWAYS | Govern data after a granted request
- Authentication and API permission are necessary but do not establish truthful representations, legitimate purpose or acceptable onward use.
- The FTC finding, the individual settlements, the SEC case and the UK agreement are separate outcomes.
- Keep populations, dates and monetary figures attached to the proceedings that produced them.
- Where evidence cannot close the gap between words, permissions and use, retain the uncertainty and act proportionately.
Caption: Evidence grade: Confirmed and Inferred
Notes: The closing slide restates the governance lesson and the procedural discipline the record demands.
