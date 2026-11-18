# Slide plan: Operation Aurora 2010

- Study: case-studies/OPERATION_AURORA_2010.md
- Cover title: Operation Aurora 2010 / A Browser Zero-Day / An Enterprise Breach
- Subtitle: How one Internet Explorer zero-day became an enterprise breach, and why disciplined separation of evidence outlasts the headline.
- Published: 18 November 2026
- Notes: The cover frames Aurora as three linked problems, not a single browser bug, and sets the bounding discipline used throughout.

## EXECUTIVE SUMMARY | Three problems, not one browser bug
- Aurora is best read as three linked problems: technical compromise, uncertainty about what was stolen, and a response where intrusion meets user safety.
- Reducing it to a browser flaw misses the enterprise consequences; reducing it to a slogan loses origin, operator and sponsor as distinct claims.
- The account is a deliberately bounded public record drawn from Google, McAfee and Microsoft, not Google's internal investigation.
- Central lesson: a patch can close a known entry condition without answering what an intruder already obtained.
Caption: Evidence grade: Confirmed public record; internal forensics not claimed
Notes: Set the thesis that each layer needs its own evidence standard before any detail lands.

## KEY FACTS | The disclosed record at a glance
Stat: 20+ | other large firms Google said were targeted
Stat: 8 | vulnerabilities addressed in cumulative MS10-002
Stat: IE 6 | version in successful attacks known to Microsoft
Stat: 9 days | Google disclosure to out-of-band patch
- CVE-2010-0249 was the Internet Explorer memory-corruption flaw at the confirmed technical root.
- The named-company count is Google's disclosed estimate, not a verified census.
Caption: Evidence grade: Reported counts; Confirmed CVE and patch dates
Notes: Anchor the few hard numbers and flag that the company count is an estimate, not proof of equal compromise.

## PART 1 | The contemporaneous victim statement
- Google's 12 January 2010 statement reported a targeted corporate intrusion detected in mid-December and intellectual-property theft.
- It said at least twenty other large companies were similarly targeted and described the attack as originating from China.
- Two targeted Gmail accounts appeared accessed only for account data and subject lines, not message bodies.
- Separate third-party access to dozens of activist accounts was explicitly distinguished from a Google security breach.
Caption: Evidence grade: Reported (first-party victim statement)
Notes: Stress that targeting is not compromise and a separate account problem should not merge into the corporate incident.

## PART 2 | The technical account and the patch
An intro to the confirmed mechanism and the vendor response, kept separate from campaign scope.

| Source and date | What it documented | Bounding limit |
|---|---|---|
| McAfee, Jan 14 | IE exploit of CVE-2010-0249, then a remote-access Trojan | Protection claims tied to observed attacks only |
| MSRC, Jan 20 | Successful attacks known to it involved IE 6 | A dated subset, not proof other versions were immune |
| MS10-002, Jan 21 | Fixed eight flaws; accelerated from February | Eight fixed, not eight proven used in Aurora |
Caption: Evidence grade: Confirmed advisories; no victim-by-victim reconstruction
Notes: Separate the confirmed IE zero-day from the broader campaign and from universal exploitation claims.

## CHRONOLOGY | Separate clocks for one campaign
Publication dates are not intrusion, discovery or cleanup dates.

| Date or period | Documented development | Interpretation limit |
|---|---|---|
| Mid-Dec 2009 | Detection period in Google's later statement | Not a proven start for all activity |
| Jan 12, 2010 | Google disclosed its findings | Disclosure differs from intrusion date |
| Jan 14 | McAfee account; Microsoft advisory first issued | Early assessments were later updated |
| Jan 21 | MS10-002 published | Release is not proof of universal install |
| Mar 22-23 | Google announced a changed search arrangement | Blog conventions are not a second decision |
Caption: Evidence grade: Confirmed dated record
Notes: Make the case that event, collection and assessment times are separate fields against hindsight overstatement.

## ATTACK MODEL | Four boundaries in the intrusion
Left: Content to local information
- External content to browser process: user interaction does not make memory corruption authorized.
- Browser context to local data: reduced privilege limits consequence, it does not make compromise harmless.
Right: Authority to transfer
- User authority to enterprise resources: sessions and shared access can widen an incident.
- Access to transfer or misuse: proving transfer needs different evidence than proving access.
Caption: Evidence grade: Inferred (original conceptual model)
Notes: Present this as a teaching model, not a diagram of Google's network, and keep access distinct from exfiltration.

## ATTRIBUTION | Keep the questions separate
- A responsible worksheet separates infrastructure, malware relationships, operator behavior, sponsorship and motive.
- Traffic origin is not the controller's location; a language or working-hour artifact does not identify a government department.
- Google's reported origin and suspected objective stay as company statements, not independently proven state attribution.
- Containment needs less confidence than public allegation; name which decision a judgment is meant to support.
Caption: Evidence grade: Reported origin; Inferred attribution bounds
Notes: Hold "attributed by a vendor" apart from "government-confirmed" and tie confidence to the decision at stake.

## DEFENDER VIEW | Patch is a workstream, not a verdict
Left: Vulnerability queue
- Identify affected software and authoritative provenance.
- Test, deploy and verify actual installed state.
- Record the population left outside the rollout.
Right: Incident queue
- Scope affected identities and data.
- Remove unauthorized access and assess prior loss.
- Closing the patch item must not close this one.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: Argue the two queues overlap but have different acceptance criteria, so a successful install does not end investigation.

## IP RECOVERY | Reading access is not exfiltration
- Classify the question: was a repository reachable, queried, retrieved from, transferred out, or modified. A single log rarely answers all five.
- Weigh three asset classes: source material, the systems that build a product, and the credentials that authorize release.
- Theft of one class does not prove tampering in another; integrity and confidentiality need separate evidence.
- No specific Google repository, stolen-file inventory or signing-key compromise is asserted here.
Caption: Evidence grade: Inferred investigation plan; no private mechanics claimed
Notes: Turn the reported category of harm into an investigation plan without inventing the original incident's internals.

## GMAIL DISTINCTIONS | Why the account categories matter
- Corporate intrusion, limited metadata access and an individual's compromised device have different investigative paths and remediation.
- Metadata is not trivial: a subject line or account detail can reveal relationships, though that does not establish added theft here.
- A clean provider-side check does not clear a user's device, and local malware does not prove a provider breach.
- The study uses no activist identities and no private messages; the lesson needs no renewed exposure.
Caption: Evidence grade: Reported categories; Inferred guidance
Notes: Show why a combined headline conceals differences exactly when affected people need precise guidance.

## BUSINESS RESPONSE | The danger of a one-line ending
- The March update redirected Google.cn users to uncensored search via Google.com.hk, with stated transition and access constraints.
- Google also said it intended to keep research, development and a sales presence in China.
- So a summary that every Google activity in China simply ended misreads the announcement.
- An intrusion does not mechanically dictate a market decision; governance and incident command must communicate without merging.
Caption: Evidence grade: Reported (first-party business statement)
Notes: Guard against the tidy ending and against a strategic announcement standing in for proof of remediation.

## EVIDENCE MATRIX | What each workstream cannot prove alone
An original teaching aid pairing evidence to seek with its limit.

| Workstream | Evidence to seek | Cannot establish alone |
|---|---|---|
| Browser exposure | Inventory, versions, configuration | That every vulnerable install was exploited |
| Identity | Session history and unusual actions | Operator identity from a login location |
| Information access | Repository audit records with context | Transfer merely because reading was possible |
| Integrity | Trusted baselines and reviewed changes | Confidentiality of an unchanged artifact |
| Remediation | Verified state, access removed | Permanent absence of future intrusion |
Caption: Evidence grade: Inferred (original teaching aid)
Notes: Press that a visually complete matrix is useless if green labels hide unknowns; mark supported versus uncertain cells.

## CROSS-CUTTING THEMES | Disciplined separation
- Separate vulnerability from exploitation, and targeting from compromise.
- Separate infrastructure origin from operator identity from sponsorship.
- Separate provider breach from endpoint compromise, and patch install from recovery.
- Separate strategic response from forensic closure; each boundary carries its own evidence standard.
Caption: Evidence grade: Inferred synthesis of the bounded record
Notes: Consolidate the discipline that makes the study more useful than a story that fills every gap with certainty.

## TABLETOP | A ninety-minute coordination exercise
- A fictional drill for security, engineering, identity, communications and an executive, using synthetic logs and invented organizations only.
- Early phases separate local observation from a news headline, and capability from observed action from inferred consequence.
- A mid phase forces separate patch and incident queues; a perfect deploy rate that excludes the hard machine earns no credit.
- Scoring rewards decision ownership, evidence preservation and user protection, not how many tools were named.
Caption: Evidence grade: Demonstrated (synthetic exercise design)
Notes: Offer a safe rehearsal that drills the same separations without malware, live accounts or attacker infrastructure.

## CLOSE | The most durable lesson
- Software exploitation affects enterprise information, which affects user trust, which affects business decisions.
- Each layer matters, and each needs its own evidence standard rather than one borrowed certainty.
- A patch closes a known entry condition; it does not report what an intruder already took.
- Preserving distinctions beats a tidy narrative that answers every open question it cannot support.
Caption: Evidence grade: Confirmed framing; Inferred lessons
Notes: Land the thesis that disciplined separation, not a single verdict, is the lasting takeaway from Aurora.
