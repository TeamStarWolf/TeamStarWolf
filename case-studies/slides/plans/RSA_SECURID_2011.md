# Slide plan: RSA SecurID 2011

- Study: case-studies/RSA_SECURID_2011.md
- Cover title: Supplier compromise / Customer uncertainty / Controlled recovery
- Subtitle: A 2011 incident at an authentication supplier, read with its qualifiers intact: what was disclosed, taken, and remediated.
- Published: 18 November 2026
- Notes: The cover frames a supplier breach whose lesson is trust dependency, not universal customer compromise.

## EXECUTIVE | A supplier incident is a trust-anchor problem
- A trusted supplier's extracted information can weaken customer security without any malicious update.
- RSA stated the stolen data did not by itself enable a direct customer attack, but could aid a broader one.
- A control can keep operating while the assurance behind it needs reassessment.
- Recovery becomes coordinated inventory, verification, replacement, revocation, monitoring and communication.
Caption: Evidence grade: Inferred
Notes: This sets the core distinction between a working control and confidence in the assumptions behind it.

## DISCLOSURE | What RSA stated on March 17
- The March 17 open letter said RSA detected an attack and found information extracted, including SecurID-related data.
- RSA framed it as an advanced persistent threat and limited its claims to its then-current assessment.
- It said the data could weaken a two-factor implementation inside a broader attack, not break it outright.
- EMC's same-day Form 8-K recorded the customer letter and did not expect a material financial effect then.
Caption: Evidence grade: Confirmed
Notes: These are the dated, qualified statements RSA and EMC actually made, kept separate from later retellings.

## TIMELINE | Dated records across reporting periods
Each primary record carries its own date and its own state of knowledge.

| Date | Record | What it establishes |
|---|---|---|
| March 17, 2011 | RSA letter, notice, EMC 8-K | Disclosure and acknowledged extraction |
| May 21 | Lockheed detection date | Customer's reported event date |
| May 28 | Lockheed statement | Its account of response and restoration |
| June 7 | EMC reply to SEC staff | Explains the Q1 financial assessment |
| June 30 | EMC Form 10-Q | Charge and reserve at that date |
| October 4 | Coviello testimony | Outreach and one downstream use |
| December 31 | EMC annual-report note | Later reserve and revised completion |
Caption: Evidence grade: Confirmed
Notes: March 17 is the disclosure date, not a proven first day of intrusion, and later numbers were unknown earlier.

## VECTOR | What the record does not establish
- Popular accounts describe a recruiting-themed Excel file, a Flash exploit (CVE-2011-0609), a remote-access Trojan and lateral movement.
- Those details come from a teaching deck and news coverage, not from independently verified primary technical evidence.
- The primary record does not fix the exact stolen cryptographic material or its mapping to customer deployments.
- Keep the reported initial vector separate from the limited facts RSA actually confirmed as taken.
Caption: Evidence grade: Reported
Notes: The phishing-and-Flash story is widely repeated but is held here as reported, not primary, evidence.

## STATES | Supplier exposure is not customer breach
Left: Supplier exposure
- Information at the authentication supplier was extracted.
- Relevance to a specific customer deployment still has to be shown.
Right: Customer compromise
- It requires evidence of an actual unauthorized customer action.
- Keep exposure records and incident findings in separate status fields.
Caption: Evidence grade: Inferred
Notes: This model blocks both errors: dismissing the supplier event and announcing a local breach from it alone.

## LOCKHEED | A reported downstream attempt
- Lockheed's May 28 statement reported a significant attack detected May 21 and said customer, program and employee data stayed secure.
- Coviello's October testimony cited one instance where stolen information was indicated as a factor, in an attack the target reported unsuccessful.
- The testimony described outreach to thousands of customers and coordination with government and information-sharing groups.
- Treat this as a reported connected event, not proof that every customer was compromised.
Caption: Evidence grade: Reported
Notes: These are the parties' own statements at the time, which do not by themselves build a detailed causal chain.

## FINANCE | Read the charges with their periods
Stat: $66.3M | Q2 cost-of-sales remediation charge
Stat: $81.3M | Reserve recorded at June 30, 2011
Stat: $46.6M | Remaining reserve at Dec 31, 2011
- The charge and the reserve are different accounting measures and must not be added together.
- Expected completion moved from the end of 2011 to mid-2012, showing remediation can outlast early planning.
- The study preserves disclosed amounts, periods and categories rather than inventing a single incident total.
Caption: Evidence grade: Confirmed
Notes: The figures are exact SEC disclosures, each tied to a period, not a universal price tag for the breach.

## LIFECYCLE | Assurance spans more than login
- Assurance spans enrollment, normal use, recovery, administrative change and retirement, not login alone.
- A replacement that swaps the device but leaves old authority active has not met its security objective.
- During a supplier incident, state which lifecycle assumptions are uncertain rather than declaring total failure.
- A successful login shows a system accepted a combination, not who acted or whether the action was authorized.
Caption: Evidence grade: Inferred
Notes: This is original defensive framing, not a claim about RSA's internal design or any one customer.

## REPLACEMENT | Migration needs revocation evidence
- Name an accountable owner and a defined population: assigned, spare, dormant, contractor, emergency and integration.
- Verify identity over trusted channels before asking users to act, so urgency does not aid impersonators.
- Bound any coexistence of old and new authority with a recorded approver, reason and expiry.
- Do not infer revocation from shipment or receipt; test that retired authority no longer works where it should not.
Caption: Evidence grade: Inferred
Notes: Completion means acceptance criteria are met, not that a package left a warehouse.

## HELP DESK | Support is part of the control
- A help desk shapes recovery and account binding, so it is part of the authentication system.
- Keep emergency access limited, monitored, independently approved, purpose-bound and set to expire.
- Give support scripts that state what staff will never request and where users can verify announcements.
- A broad bypass created under migration pressure can outlast the incident as a lasting weakness.
Caption: Evidence grade: Inferred
Notes: This responds to the breadth of the customer notice without blaming a specific help-desk failure.

## DETECTION | Separate the login from the session
- Correlate identity activity with device, network and application evidence where it is lawfully available.
- Record enough context to separate the authentication decision from the session that followed.
- Absence of an event in data never collected cannot establish that the event did not happen.
- Apply proportionate containment early, but do not read precautionary action as confirmed compromise.
Caption: Evidence grade: Inferred
Notes: The case file should mark each action as a verified event, an unresolved exposure or a conservative risk call.

## ACCEPTANCE | Match the evidence to the claim
Each workstream needs acceptance evidence that matches the claim being made.

| Workstream | Acceptance evidence | Common false shortcut |
|---|---|---|
| Scope | Reconciled users, devices, integrations | Counting shipped devices as affected users |
| Revocation | Old authority no longer accepted in scope | Assuming a new token disables every old path |
| Monitoring | Known coverage, escalation, retention | Treating absent logs as proof of no misuse |
| Finance | Amount, period, category, source reconciled | Adding a reserve to its related charge |
| Closure | Named owner, exceptions, reopening triggers | Declaring all customers safe from recovery alone |
Caption: Evidence grade: Inferred
Notes: A physical inventory cannot prove successful authentication, and authentication cannot prove retired recovery routes.

## TAKEAWAYS | Keep the qualifiers intact
- An incident at a security supplier can become a distributed, customer-side recovery problem.
- An initial assessment is dated, and a reported unsuccessful attack is not confirmed data theft.
- A financial reserve is not an added incident charge, and a replacement offer is not a completed revocation.
- The lessons hold without assuming universal compromise or a broken authentication algorithm.
Caption: Evidence grade: Inferred
Notes: Preserving the qualifiers is what makes the study rigorous and the defensive work actionable.
