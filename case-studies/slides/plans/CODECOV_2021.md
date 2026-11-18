# Slide plan: Codecov 2021: Inherited Authority

- Study: case-studies/CODECOV_2021.md
- Cover title: Codecov 2021 / The Build Helper / As Credential Boundary
- Subtitle: A narrow coverage-upload step sat amid authority far beyond its purpose; execution, exposure, credential use and access stay distinct.
- Published: 18 November 2026
- Notes: The cover sets the frame: inherited authority, not a universal-compromise claim.

## EXECUTIVE SUMMARY | A reporting step inside a boundary it did not define

- Codecov is a case of inherited authority: a coverage-upload step sat in an environment holding authority far beyond uploading a report.
- The question is not only whether a downloaded script was authentic; it is what that script could reach once the build system ran it.
- The record is a bounded reconstruction plus original defensive analysis, not a claim that every customer, pipeline or build was compromised.
- No exploit testing, customer-system access or malware execution is part of the account.
Caption: Evidence grade: Confirmed provider record; no universal-compromise claim.
Notes: Inherited-authority framing and scope limits from [1][2]; sections 3 through 8 are original analysis.

## KEY FACTS | A bounded period, a checksum mismatch, five accounts

Stat: 108 | Affected windows, not one continuous interval
Stat: 5 | Public provider accounts in the record
Stat: Apr 1 | 2021 customer checksum report
Stat: Apr 15 | 2021 Codecov disclosure
- Codecov identified January 31 through April 1, 2021 as the period containing unauthorized uploader changes.
- An HMAC key recoverable from an intermediate layer of the public self-hosted Docker image enabled altering the uploader stored in Google Cloud Storage.
- Codecov did not conclusively identify the responsible actor in its notice.
Caption: Evidence grade: Confirmed, dated provider statements.
Notes: Period, windows and root-cause key from [1][2]; the checksum discovery is from [2].

## PART 1 | Five different states, not one checkbox labeled compromised

- Potential exposure, observed transfer, credential use, repository access and malicious modification are distinct states.
- "No evidence" describes the investigation's findings; its strength depends on logging, retention, coverage and the exact question asked.
- Keep the Bash uploader altered distinct from any one customer's secrets provably exfiltrated.
- Keep "could have exposed" distinct from "confirmed exposed"; a responsible investigator records these separately.
Caption: Evidence grade: Confirmed evidence rules; no victim total asserted.
Notes: Scope-word discipline and the absence-of-evidence caveat from the study's sections 1.1 and 1.2.

## PART 1 | A timeline that distinguishes discovery from disclosure

Each date answers a different question: when could exposure begin, when did containment occur, when could a downstream team act.

| Date | Publicly documented development | Source |
|---|---|---|
| Jan 31, 2021 | Start of the reported unauthorized-change period | [1] |
| Apr 1, 2021 | Customer checksum discrepancy; discovery, remediation | [2] |
| Apr 15, 2021 | Codecov disclosure and affected-user notices | [1] |
| Apr 29, 2021 | Additional environment-variable and impact information | [1] |
| May 4, 2021 | Twilio public response account | [4] |
| May 13, 2021 | Rapid7 public response account | [5] |
Caption: Evidence grade: Confirmed dates; no invented extraction timestamps.
Notes: Supplier discovery, public disclosure and downstream notification kept separate, per the study's section 2.1.

## PART 1 | HashiCorp: an exposed key is not a malicious release

- HCSEC-2021-12 reported exposure of the GPG private key used to sign release hash files; the key was revoked, replaced, and releases re-signed.
- The investigation had not found unauthorized use of that key, and an April 27 FAQ reported no evidence of malicious code or binary changes.
- The exposure was separated from macOS notarization, Windows Authenticode and Linux package signing, which that key did not cover.
- Key replacement is also a consumer-coordination problem: a signature failure can tempt a hurried operator to disable verification.
Caption: Evidence grade: Reported by HashiCorp; exposure distinguished from malicious use.
Notes: Key exposure, revocation and the mechanism separation from [3]; the coordination point is analysis.

## PART 1 | Twilio and Rapid7: access reached information, not just secrets

Left: Twilio (May 4)
- Limited uploader use; an April 22 GitHub notice involved an exposed user token.
- Repositories were cloned before notification; review identified a small number of customer email addresses.
- Reported no repository modification; rotated potentially exposed credentials and secrets.
Right: Rapid7 (May 13)
- Use on one CI server building and testing internal MDR tooling, not product-code CI servers.
- Access reached a small subset of internal-tooling repositories with internal credentials and alert-related data for a subset of MDR customers.
- Reported no unauthorized repository changes and no access to its Insight platform or products.
Caption: Evidence grade: Reported by each provider; accounts not combinable.
Notes: Twilio contents from [4]; Rapid7 scope from [5]. The label internal is not a data classification.

## PART 2 | Business purpose is narrower than process authority

- A coverage tool's intended output is a measurement artifact; the operating system does not infer that purpose and restrict the process to it.
- Actual authority comes from files, environment, credentials, network access, service permissions and execution context.
- If a process can read a credential, calling it reporting-only does not make the credential inaccessible.
- The review question is the minimum authority the task needs versus authority present only because a broad build job is convenient to reuse.
Caption: Evidence grade: Inferred defensive model built on the confirmed record.
Notes: Authority-versus-purpose argument from the study's section 3.1; a role name is not an enforcement boundary.

## PART 2 | Three inventories, and none substitutes for another

A joined record answers what a single list cannot, and it stores identifiers, never secret values.

| Inventory | Question it answers | Gap it leaves |
|---|---|---|
| Dependency | Which tools a project uses | A wrapper may fetch another script at runtime |
| Execution | Which bytes actually ran in a job | The fetched content may not be preserved |
| Authority | What those bytes could access | A default role can miss temporary elevation |
Caption: Evidence grade: Inferred model; an original review aid.
Notes: The three inventories and the joined record (job identity, revision, runner, credential identifiers) from section 3.2.

## PART 2 | Distribution, verification and isolation solve different problems

- A supplier-side control prevents unauthorized content changes; a consumer-side control rejects unexpected content before execution.
- A checksum only establishes agreement with the expected digest supplied to the verifier; one compromised path can replace both artifact and digest.
- A signature shifts trust to a signing identity and its protection, not to safety inside the artifact.
- Each control needs an owner, a trust source, a failure mode and a renewal process; they are not duplicates.
Caption: Evidence grade: Inferred analysis; general control properties.
Notes: Independent-control argument and the checksum limit from section 3.3; isolation bounds consequence when prevention fails.

## DEFENDER VIEW | Build an exposure ledger that preserves uncertainty

- Record one row per potentially affected execution: repository, job, time range, integration path, artifact evidence, credential identifiers, confidence.
- Distinguish confirmed affected execution, plausible exposure, ruled-out execution and insufficient records; missing bytes must not silently become ruled out.
- Follow each credential into its issuer, authorized resources, actions, expiration and revocation, then search authorized audit records for the exposure period.
- Do not record live credentials in the incident spreadsheet; link to protected evidence and name who can retrieve it.
Caption: Evidence grade: Inferred investigation model (a hypothetical organization).
Notes: Exposure ledger and authority-tracing from sections 4.1 and 4.2; revoking a credential does not prove derived access ended.

## DEFENDER VIEW | Evaluate information separately from access

- If a repository was accessed, classify its contents and reachable history, not only the currently checked-out branch.
- Have a data owner review ambiguous business information; security personnel should not guess whether a sample contains real customer data.
- State conclusions at the level evidence supports: a clone is confirmed, contact information is identified, the exact files the actor selected may not be visible.
- A negative finding should name the systems searched, the interval, the record type and the relevant blind spots.
Caption: Evidence grade: Inferred guidance; bounded-claim discipline.
Notes: Access-versus-information separation and coverage-statement framing from sections 4.3 and 4.4.

## CONTROL MATRIX | Each control names the failure it does not eliminate

An assessment aid, not a maturity score; tests use authorized environments and synthetic secrets.

| Control objective | Acceptance evidence | Failure it does not eliminate |
|---|---|---|
| Know executed content | Resolved artifact digest per job | A trusted artifact may be malicious |
| Validate before execution | Mismatch test stops the job | Compromised signing authority |
| Isolate reporting tasks | Test identity cannot reach release | Abuse of legitimate permission |
| Revoke completely | Old identity denied, derived access reviewed | Data already copied |
Caption: Evidence grade: Inferred assessment aid, not a score for any organization.
Notes: Condensed from the study's section 6 matrix; each row pairs acceptance evidence with a residual failure.

## CROSS-CUTTING THEMES | What the retelling overstates versus understates

Left: Easy to overstate
- Reading "the uploader was altered" as every customer's secrets provably stolen.
- Treating an exposed signing key as a malicious release.
- Combining HashiCorp, Twilio and Rapid7 into one universal impact statement.
Right: Easy to understate
- Inherited authority reached well beyond uploading a coverage report.
- Internal tooling still carried credentials and customer-related data.
- Revoking a credential does not prove all derived access has ended.
Caption: Evidence grade: Mixed; each claim bounded to its source's scope.
Notes: Overstated and understated contrasts from sections 2.2 through 3 and 9; accounts stay non-combinable.

## CLOSE | A patched helper is not a recovered build system

- The durable finding is a boundary problem: the authority granted to an automated helper may exceed its stated purpose.
- Prevention matters, but a mature response also needs evidence of what actually ran and a method to repair every trust relationship reached.
- Keep execution, exposure, credential use, access and modification in separate fields through investigation and communication.
- Deliver a traceable account: which code ran, what authority it inherited, how that authority was used, and what the reachable data was.
Caption: Evidence grade: Confirmed boundary finding plus original synthesis.
Notes: Closing synthesis from the study's section 9; rests on [1] through [5] with distinctions preserved.
