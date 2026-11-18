# Slide plan: NetSarang ShadowPad 2017: A Trusted Release

- Study: case-studies/NETSARANG_SHADOWPAD_2017.md
- Cover title: NetSarang ShadowPad / July 2017 / Signed release, intrusion path
- Subtitle: A trusted software release shipped a signed backdoor; distribution breadth, execution, activation and verified impact are different findings.
- Published: 18 November 2026
- Notes: The cover sets the frame: a supplier compromise that reversed an ordinary update into an intrusion path.

## EXECUTIVE SUMMARY | A trusted update reversed into an intrusion path

- Software updates normally protect; a supplier compromise can reverse that relationship into an intrusion path.
- The question is not the download location, but whether the delivered artifact matches an authorized, reviewed release.
- A compromised package, execution of its code, activation of further capability and verified theft are four different findings.
- The record is bounded: Kaspersky documented discovery and design, and NetSarang acknowledged the affected release.
Caption: Evidence grade: Confirmed bounded record; no full initial-intrusion route established.
Notes: Executive framing follows the study's summary; the six primary records are [1] through [6].

## KEY FACTS | A signed release, five builds, one confirmed activation

Stat: 5 | Affected 2017 product builds
Stat: 1 | Confirmed activation, Hong Kong company
Stat: 6 | Primary records reviewed
- The backdoor was embedded in nssock2.dll and signed with a legitimate NetSarang certificate.
- The affected July 18, 2017 release was distributed July 18 to August 4; MyCERT lists August 5 as the clean update.
- Kaspersky reported one confirmed activated payload, at a Hong Kong company, not a worldwide count of intrusions.
Caption: Evidence grade: Confirmed, dated advisories and vendor statement.
Notes: Backdoor and certificate from [1][3]; builds from [4][5]; one confirmed activation from [1].

## PART 1 | Six bounded records, not six independent investigations

- Kaspersky's research article and technical annex describe the discovery and a staged modular platform.
- The press release preserves NetSarang's statement acknowledging the July 18 release shipped a backdoor.
- The Canadian alert, MyCERT advisory and Tenable plugin add build scope and one narrow detection check.
- Six records are not six investigations; several repeat one discovery and vendor notification process.
Caption: Evidence grade: Confirmed bounded record; corroboration is partly shared.
Notes: Records enumerated in [1][2][3][4][5][6]; shared-source caveat is the study's research discipline.

## PART 1 | A valid signature authenticated origin, not safety

- A code signature authenticates origin; it does not independently certify that the signed code is benign.
- The backdoor rode a legitimate NetSarang certificate, so signed and trusted did not mean safe.
- Treat release assurance as a chain: review, controlled build, binding, signing, same bytes published.
- Two approvals produced from one compromised job are not independent; ask what stays outside its control.
Caption: Evidence grade: Confirmed signed artifact; the chain model is original analysis.
Notes: Signed nssock2.dll and certificate from [1][3]; the release-chain framing is the study's analysis.

## PART 1 | The affected release: exact product scope

The table preserves the historical build identifiers; it is a scoping aid, not a current support matrix.

| Product | Affected 2017 build | Replacement build (MyCERT) |
|---|---|---|
| Xmanager Enterprise 5 | 1232 | 1236 |
| Xmanager 5 | 1045 | 1049 |
| Xshell 5 | 1322 | 1326 |
| Xftp 5 | 1218 | 1222 |
| Xlpd 5 | 1220 | 1224 |
Caption: Evidence grade: Confirmed historical build identifiers.
Notes: Build table reproduced from [4][5]; a product name alone is not a reliable exposure decision.

## PART 1 | Distribution is not the same as execution

Each date answers a different question, so each row carries its interpretation limit.

| Event | Supported date | Interpretation limit |
|---|---|---|
| Affected release | July 18, 2017 | Release date is not every customer's install date |
| Distribution interval | July 18-Aug 4 | Cached packages could remain available later |
| Clean update | August 5 (MyCERT) | A remedy's release is not universal deployment |
| Research publication | August 15 | Disclosure is not the first investigation activity |
| Canadian alert | August 17 | The alert is guidance, not a new victim count |
| Detection plugin | August 23 | One published check is not the start of all detection |
Caption: Evidence grade: Confirmed dates; interpretation limits kept explicit.
Notes: Dates and limits from [1][3][4][5][6]; keep acquisition, install and execution dates separate.

## PART 2 | Exposure, execution, activation and impact are four stages

- Exposure means the suspect artifact was present or available on a host.
- Execution means relevant code ran; activation means evidence supports added malicious capability.
- Impact means a specific consequence, such as verified information transfer, is evidence-supported.
- Record the strongest supported stage per host; absence of a known lookup does not prove nothing ran.
Caption: Evidence grade: Analytical categories for this study, not a universal taxonomy.
Notes: Four-stage model and visibility limits are the study's analysis, anchored by [1][2].

## PART 2 | Administrative software and the authority available to it

- An administration workstation can hold connection profiles, access tokens and reusable session material.
- Map actual authority: which accounts, which systems, which actions require fresh authentication.
- Potential authority, attempted access and successful use are separate evidence states.
- A connectivity product's presence is not proof that all reachable systems were actually reached.
Caption: Evidence grade: Inferred risk model; no specific secret theft is established here.
Notes: Authority-mapping and the potential-versus-used distinction are the study's defensive analysis.

## PART 2 | Cached packages outlive a supplier's cleanup

- A supplier's website cleanup does not remove installers already copied into internal repositories.
- Desktop images, virtual-machine templates, offline installer folders and automation can preserve the old build.
- A standard rebuild can reinstall the affected artifact onto an otherwise cleaned workstation.
- Closing internal distribution paths is part of remediation, not separate housekeeping.
Caption: Evidence grade: Inferred defensive inference; the distribution interval is Confirmed.
Notes: Distribution interval July 18 to August 4 from [4]; the cached-copy inference is the study's analysis.

## DEFENDER VIEW | DNS evidence is useful, incomplete and contextual

- Discovery began with suspicious DNS activity, investigated with a partner and traced to NetSarang software.
- An enterprise resolver aggregates many machines, so a single query may not attribute to one endpoint.
- Preserve endpoint, resolver and network records with consistent, documented timestamps.
- Do not replay historical command-and-control traffic against live infrastructure to test a theory.
Caption: Evidence grade: Confirmed discovery lead; the detection guidance is original analysis.
Notes: DNS discovery narrative from [1]; resolver and replay cautions are the study's defensive analysis.

## DEFENDER VIEW | A proposed evidence and acceptance matrix

The matrix makes the basis for closure visible; adapt the rows, but keep the evidence specific.

| Question | Evidence to retain | Completion meaning |
|---|---|---|
| What was acquired? | Package identity, source, interval | Exposure population is bounded |
| What ran? | Endpoint records, gaps noted | Execution finding is supported |
| What more occurred? | Correlated host and network findings | Activation and impact stay specific |
| What authority existed? | Account, session, destination review | Follow-on investigation is prioritized |
| Can the bad release return? | Repository, image, automation checks | Redeployment paths are corrected |
Caption: Evidence grade: Original review tool, condensed from the study.
Notes: Condensed from the study's evidence and acceptance matrix; an exception needs a named owner.

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Easy to overstate
- One confirmed activation read as a global victim count.
- A valid signature read as proof the code was safe.
- A replaced package read as a restored environment.
Right: Easy to understate
- Distribution breadth is not the same as targeting breadth.
- Cached internal copies survive a supplier's website cleanup.
- Administrative hosts hold authority that outlives the application.
Caption: Evidence grade: Editorial corrections the case requires.
Notes: Overstated and understated contrasts; the activation-versus-total point ties to [1].

## CLOSE | Replacing software is not restoring confidence

- A customer can use the expected supplier channel and still receive a compromised artifact.
- Replacing software is not the same as restoring confidence in the environment where it ran.
- Keep attribution, reach and impact qualified: one confirmed activation is not a global total.
- Stop distribution, find what deployed, investigate what ran, resume through a justified path.
Caption: Evidence grade: Case-specific conclusions, reach and impact bounded.
Notes: Conclusion synthesis across the study; attribution and victim-count cautions from [1][3].
