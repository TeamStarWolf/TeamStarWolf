# Slide plan: Ashley Madison 2015

- Study: case-studies/ASHLEY_MADISON_2015.md
- Cover title: Ashley Madison 2015 / Sensitive Context / The Meaning of Deletion
- Subtitle: An evidence-bounded reading of the 2015 breach, where false associations and a deletion promise mattered as much as the intrusion itself.
- Published: 18 November 2026
- Notes: The cover frames a breach whose severity came from context and inference, not from card numbers alone.

## ASSESSMENT | Why context set the severity
- Breach severity cannot be measured only by counts of payment cards or identity documents.
- An email tied to a sensitive service can cause reputational harm even when the association is false.
- Product promises carry security weight: a deletion option creates an expectation about what remains.
- Access, retention, accuracy and communication form one combined control problem.
Caption: Evidence grade: Inferred
Notes: The study reads company practice and regulatory outcomes without identifying users or inspecting leaked records.

## SCOPE | What the record does and does not support
Left: What the sources support
- Analysis of company information-handling practices under Canadian and Australian law.
- Regulatory findings, allegations and settlement obligations, kept distinct.
- Procedural limits: no admission, and no conclusion on the breach cause.
Right: What the study refuses
- Exposing individuals or judging their personal relationships.
- Accessing leaked material or any search tool built from it.
- Treating a database entry as proof of a person's conduct.
Caption: Evidence grade: Confirmed
Notes: The joint investigation itself declined to conclude on the cause of the breach.

## TIMELINE | Discovery and publication were separate
The joint report and FTC complaint place these events on distinct dates.

| Date (2015) | Event | Source |
| --- | --- | --- |
| Late 2014 to early 2015 | Alleged unauthorized network access | FTC complaint [2] |
| May and June | Alleged logins at a payment processor | FTC complaint [2] |
| 12 July | Organization became aware; large transfer detected | Joint report [1] |
| 15 July | Impact Team public threat | Joint report [1] |
| 18 and 20 August | Major publications of data | Joint report [1] |
Caption: Evidence grade: Reported
Notes: Publication can follow access that has already ended, and an attacker may keep copies after credentials are revoked.

## SCALE | A record count is not an identity count
Stat: 36M | User accounts described in the joint report
Stat: 12 Jul | Date the organization became aware (2015)
Stat: 18 Aug | First major publication date (2015)
- The account count does not establish an equal number of verified identities or relationships.
- The Impact Team name is not a verified attribution to specific individuals.
- Choosing the correct verb, compromise, announcement or publication, resolves more confusion than another date.
Caption: Evidence grade: Confirmed
Notes: Numbers from the joint report describe data volume, not confirmed people or conduct.

## FALSE LINK | An address in the dump is not an account
- Inadequate email checks let non-users' addresses appear in exposed databases.
- A database entry cannot establish that the associated person registered or did anything.
- An incorrect association can be as damaging as a correct disclosure, with no account to request correction.
- A breach database is not a reliable public directory, and researchers should not search for acquaintances.
Caption: Evidence grade: Confirmed
Notes: The Canadian regulator reported that the site did not verify addresses at signup, so an address is not proof of use.

## ACCESS | Credential handling and attributable entry
Left: Alleged weaknesses
- Weak remote-access controls and inadequate monitoring.
- Unrevoked credentials for former service-provider staff.
- A shared remote-access secret and plaintext credentials in files.
Right: Design response
- Individually attributable access tied to a current role.
- An access register covering contractors, not only employees.
- Reduced shared secrets, with documented rotation dependencies.
Caption: Evidence grade: Reported
Notes: These remote-access failures are allegations in the FTC proceeding, not proof that one credential explains the whole intrusion.

## ENCRYPTION | A mechanism is only as good as its access
- Encryption was in use alongside plaintext key storage and weak password management.
- The real question is who can obtain readable data, under which conditions.
- Key management needs its own inventory, ownership and tested recovery.
- Password hashing and data encryption serve different purposes and should not be conflated in a report.
Caption: Evidence grade: Confirmed
Notes: The Canadian release recorded both the encryption in use and the operational practices that undercut it.

## DELETION | Defining account states in operational terms
- Deactivated can mean hidden from other users but retained internally.
- Inactive can mean unused for a specified period.
- Deleted should name which records go, which narrow exceptions remain and when they expire.
- Deletion testing must cover databases, search indexes, analytics copies, exports and backups.
Caption: Evidence grade: Confirmed
Notes: The compliance agreement ended indefinite retention for inactive and deactivated accounts and required a justified schedule.

## FULL DELETE | When a paid promise did not match the system
- The FTC described allegations that information remained for people who paid for Full Delete.
- Whether a limited retention period is justified differs from whether a customer was told accurately.
- A button label, confirmation message and backend action should agree.
- A fabricated trustmark shaped assurance that a privacy disclaimer elsewhere did not correct.
Caption: Evidence grade: Reported
Notes: The paid-deletion allegation and the trustmark finding both tie product representations to security commitments.

## HARM | Nonfinancial consequences drive the model
- Breach harm can reach reputation, relationships, employment and personal safety.
- A record can enable harassment or coercion even if it cannot open a bank account.
- A false record can demand an explanation the affected person cannot easily give.
- Support should avoid re-exposure, and internal access should exclude curiosity-driven browsing.
Caption: Evidence grade: Confirmed
Notes: The study does not attribute particular deaths or outcomes to the incident, treating serious nonfinancial harm as foreseeable.

## RESOLUTION | Reading the enforcement figures precisely
Stat: $1.657M | Combined payment, coordinated settlement
Stat: $8.75M | Federal judgment, partly suspended
Stat: $17.5M | Larger amount, conditionally suspended
- The FTC split is $828,500 to the Commission and $828,500 to states and the District.
- Each amount needs a payer, recipient, instrument and status; a judgment is not cash paid.
- The selected figures show the structure of the resolution, not an individual claim value.
Caption: Evidence grade: Confirmed
Notes: The combined payment and suspended judgments come from the FTC, federal order and District of Columbia announcements.

## CLOSURE | Remediation is not evidence of completion
- The Canadian agreement required policies, training, an independent report and written confirmation to close.
- A remediation program needs separate states for planned, implemented and verified work.
- Each action should carry an evidence requirement defined in advance.
- Repaired controls reduce future risk without undoing exposure already published.
Caption: Evidence grade: Confirmed
Notes: A list of required changes is not proof that every change was complete on the announcement date.

## RESPONSE | A plan for sensitive-data exposure
Left: Combine the workstreams
- Technical containment joined to a privacy assessment of the data categories.
- An approved support route for urgent concerns from affected people.
- Selective, controlled evidence preservation using aggregate descriptions.
Right: Communicate with care
- Separate confirmed facts from open investigation questions.
- Avoid directing people to leaked-data search sites.
- Make no promise that paying an extortionist removes information.
Caption: Evidence grade: Demonstrated
Notes: The response plan is original defensive analysis for organizations handling sensitive personal information.

## LESSON | Make every consequential promise testable
- Access should have a demonstrable boundary and retention a defensible end.
- Deletion should be an observable process and assurance a verifiable basis.
- A database account is not proof of conduct, and careful language prevents repeating the harm.
- Where evidence is incomplete, state the limitation and assign an owner to resolve it.
Caption: Evidence grade: Inferred
Notes: The durable recommendation turns product design and data lifecycle into parts of security rather than later follow-up.
