# Slide plan: Capital One 2019: When a Request Became Data Authority

- Study: case-studies/CAPITAL_ONE_2019.md
- Cover title: Capital One 2019 / When a Request / Became Data Authority
- Subtitle: Valid credentials used in an invalid context: how an exposed request handler reached a machine identity with authority over years of personal data.
- Published: 15 November 2026
- Notes: House-style TeamStarWolf case study; evidence-bounded, not a present-day assessment of Capital One or AWS.

## EXECUTIVE SUMMARY | Valid credentials can be used in an invalid context

- An identity system may recognize a workload correctly while the app under it is induced to act against its owner's intent.
- Three separate questions: what requests may a service make, what authority can it obtain, what data can that authority retrieve.
- Identity design is a partner to input validation, not a substitute for it.
- Recovery is a data-management problem: which records were read, which protections applied, who needs notification.
Caption: Evidence grade: Inferred, analysis anchored to the disclosures.
Notes: Executive assessment; the central distinction is drawn from the company account [1].

## KEY FACTS | The disclosed facts, separated by source type

Stat: ~100M | US individuals affected, est. July 2019
Stat: 6M | Canada individuals affected, est. 2019
Stat: 4,700 | Additional US SSNs identified, Feb 2021
Stat: $80M | OCC civil money penalty, August 2020
- Principal access 22 to 23 March 2019; outside report 17 July; determination 19 July. [1]
- Application data from 2005 through early 2019 was the largest category. [1]
- Credit-card numbers and login credentials were reported not compromised. [1]
- DOJ reported the conviction of Paige A. Thompson in June 2022, with two acquittals. [3]
Caption: Evidence grade: Confirmed, company, DOJ and OCC disclosures.
Notes: The company core and later milestones [1][2][3][4].

## KEY FACTS | An incident has four clocks, not one date

At least four clocks matter: activity, discovery, response, and institutional accountability, and they move at different speeds.

| Date | Milestone |
|---|---|
| Mar 2019 | Principal access window in disclosure [1] |
| Jul 2019 | Outside report, determination, announcement [1] |
| Nov 2019 | AWS EC2 metadata enhancements [7] |
| Aug 2020 | OCC penalty and consent order [4][5] |
| Feb 2021 | Additional SSN exposure identified [2] |
| Jun 2022 | DOJ conviction outcome [3] |
Caption: Later controls are not evidence they existed earlier.
Notes: Keep event, discovery, response and accountability clocks distinct [1][2][3][4][5][7].

## PART 1 | Untrusted requests can reach an oversized authority envelope

- Request boundary: decide which input is content and which may steer destinations or resources.
- Workload boundary: a machine identity can hold consequential authority with no login screen.
- Authorization boundary: enumerate, read, and protected-service permissions each need separate review.
- Data boundary: sensitivity depends on retention, field protection, and who can obtain plaintext.
Caption: Private storage can still expose data via an overpowered path.
Notes: An original four-boundary model anchored to the complaint's high-level account [6].

## PART 1 | SSRF is a class of failure, not a precise exploit script

- SSRF: untrusted influence makes a server send an unintended request, so internal destinations become relevant.
- The label does not establish the exact request sequence in every case described with it.
- AWS docs distinguish request-oriented IMDSv1 from session-oriented IMDSv2. [8]
- The Nov 2019 metadata enhancements were defense in depth, announced after the access window. [7]
- Treat metadata protection as one boundary; test rollout across redeploy and recovery.
Caption: A later feature is not proof it existed before release.
Notes: General SSRF definition plus current AWS references, no causal claim [7][8].

## PART 1 | Encryption was not broken; an authorized path returned plaintext

- The failure can be authorization around decryption, not the mathematical primitive. [1]
- Record who may request plaintext, under what conditions, and what storage access it is coupled to.
- Tokenization helps only if the mapping service, permissions, and reversal workflows stay separate.
- Names, addresses, and behavioral history still carry privacy risk without any login access.
Caption: Evidence grade: a Confirmed distinction; the design is Inferred.
Notes: The company protection distinction; the review worksheet is original analysis [1].

## PART 2 | One number cannot describe unequal harm

- Applicants and customers differ, and some records hold more sensitive fields than others.
- Build a versioned exposure ledger: separate confirmed, reachable, and under-investigation records.
- Do not inflate a headline through overlap, or shrink it because one field was protected.
- Feb 2021 added about 4,700 US SSNs: a revised understanding, not necessarily later access. [2]
Caption: "No credentials exposed" is not "no one is at risk".
Notes: Population accounting and the Feb 2021 scope revision [2].

## PART 2 | Retained data is accessible consequence that accumulates

- Application material spanning 2005 to early 2019 widens the reach of one path. [1]
- Build a retention inventory: active, operational, legal hold, archival, deletion-eligible.
- Archive after a period is incomplete if the same front-end identity still reads it.
- Verify deletion across replicas, exports, and derivatives within legal obligations.
Caption: The study does not claim any retention period was unlawful.
Notes: Retention as a security boundary; the historical span from the disclosure [1].

## PART 2 | Detection should follow relationships, not only volume

- A low-volume read from an unexpected collection can signal more than a scheduled batch.
- Document each workload identity's purpose, normal data families, and execution environment.
- Flag new collections, unfamiliar contexts, and unusual discovery-then-retrieval sequences.
- Test the whole chain: an alert with no off-hours owner is not a response capability.
Caption: Proposed analytics, not alerts known to exist in 2019.
Notes: The detection design is proposed, with no source citation in the study.

## DEFENDER VIEW | Contain authority without destroying its evidence

- Capture configuration and access history before or alongside containment when feasible.
- Fix the input path and the reachable identity; changing one name may leave authority open.
- Treat sensitive-data review as controlled analysis, not a second uncontrolled copy.
- Preserve alternatives: a legitimate batch, a misconfigured process, or unauthorized use.
Caption: Validate that the causal path is closed, not just renamed.
Notes: The response guidance is original; no source citation in the study.

## DEFENDER VIEW | Technical controls need organizational mechanisms

Left: Governance findings
- OCC cited risk assessment before cloud migration and delayed correction. [4]
- Review migrations as changed trust boundaries, not product swaps. [5]
- Board reports name unconstrained data paths, owners, and tests.
Right: Ninety-day program
- Days 1-30: inventory reachable services, capture effective permissions.
- Days 31-60: cut permissions, time-bound exceptions, exercise alerts.
- Days 61-90: survive redeploy, reconcile ledgers, run the tabletop.
Caption: The $80M OCC penalty went to the US Treasury, not customers.
Notes: OCC findings and consent order with an original program proposal [4][5].

## CROSS-CUTTING THEMES | What gets overstated, and what gets missed

Left: Overstated, remove it
- "All cloud storage was public": private storage still exposed through an authorized path.
- "Encryption was mathematically broken": it was not; a trusted path returned plaintext.
- The earliest estimate treated as an immutable final total.
Right: Understated, keep it
- Personal data supports impersonation and fraud without any account login.
- A workload authenticating is not authorization of the human directing it.
- One compromised context becoming authority over years of records.
Caption: From the study's common-errors list.
Notes: The overstated-versus-understated pairing; see population and encryption points [1][2].

## CLOSE | Make the request-to-data connection deliberate and recoverable

- A narrow web-layer boundary can connect to a large data estate through a machine identity.
- Engineering task: make that connection limited, observable, and recoverable.
- Organizational task: accurate inventory, tested access, and honest revision of conclusions.
- The strongest lesson is a disciplined method, not a single configuration setting.
Caption: An evidence-bounded study; not legal advice or a forensic report.
Notes: Conclusion; research cut-off 15 November 2026 [1][2][3][4][5][6][7][8].
