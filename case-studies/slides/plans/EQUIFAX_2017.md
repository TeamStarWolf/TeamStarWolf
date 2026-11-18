# Slide plan: Equifax 2017: When a Patch Ticket Is Not Proof

- Study: case-studies/EQUIFAX_2017.md
- Cover title: Equifax 2017 / When a Patch Ticket / Is Not Proof
- Subtitle: Patch faster is the right lesson but an incomplete one; the scale came from ownership, identity, data reach and blind monitoring.
- Published: 15 November 2026
- Notes: House-style briefing condensed from the full study, which stays the source of truth. Keep fact, allegation, inference and recommendation distinct. No exploit content.

## EXECUTIVE SUMMARY | Patch faster is right, but it is an incomplete lesson

Equifax is compressed into one line: patch vulnerable software. Correct, but it skips the questions that explain the scale.

- A critical vulnerability notice went out, yet an exposed application stayed vulnerable.
- An application compromise reached data unrelated to that application.
- An installed monitoring control stayed silent and nobody treated the silence as a problem.
- Patch, ownership, identity, data access, detection health and communication are separate testable controls.
Caption: Evidence grade: a Confirmed framing from the study thesis.
Notes: The thesis of the study: a patch is one interruption point, not a substitute for limiting post-compromise reach. [2]

## KEY FACTS | One intrusion, four record-keepers, four purposes

Stat: 147M | People affected, approx, per FTC
Stat: 48 | Unrelated DBs reached past 3 portal
Stat: ~9,000 | Database queries alleged by DOJ
Stat: $575M+ | Settlement floor, up to $700M
- A 13 May 2017 start, 29 July discovery, 30 July portal offline, per GAO. [2]
- CVE-2017-5638 in the Apache Struts Jakarta multipart parser, advisory S2-045. [1]
- Four alleged PLA members charged; charges are allegations, not convictions. [4]
Caption: Evidence grade: Confirmed dates [2]; Reported figures [3][4].
Notes: The settlement value is a floor, not the total loss; the 48 extra databases describe access expansion, not 51 firms or 51 exfiltration events. [2][3]

## KEY FACTS | Each source proves something different, and no more

| Source | What it can establish |
|---|---|
| Apache S2-045 | Vulnerability traits, not who patched [1] |
| GAO-18-559 | Reconstruction; no control re-verification [2] |
| FTC 2019 | Allegations and settlement scope [3] |
| DOJ 2020 | Attribution allegations, not a verdict [4] |
Caption: Evidence grade: mixed; read each source by its purpose.
Notes: GAO explicitly did not independently verify Equifax controls or remediation; DOJ states defendants are presumed innocent. Do not merge these into one certified account. [2][4]

## PART 1 | Internet input became server authority at the boundary

- The defensive object was the running application, not the inbox holding the advisory.
- A vulnerable library hides in build files, vendor packages, dead deployments and containers.
- Proposed control: map component to service, external route, who can replace it, what test proves it.
- A software bill of materials helps, but a build artifact is not a census of the running estate.
Caption: Evidence grade: an Inferred recommendation generalized from the case.
Notes: Trust decision 1 of 6. Product names alone do not prove exploitability; a defender needs deployed-component and execution-path inventory. [1][2]

## PART 1 | A compromised service inherited a broad identity

- Compromise worsens when the execution environment holds credentials beyond the app function.
- The real risk is reuse, breadth of trust, and whether a defender can revoke without an outage.
- A managed secret store cannot fix an overprivileged identity by itself.
- Rotate after exposure, but rotation without reducing reachable privilege restores the weakness.
Caption: Evidence grade: Inferred; the FTC alleged exposed admin credentials. [3]
Notes: Trust decision 2 of 6. If a compromised service can legitimately fetch a high-privilege secret, the attacker inherits the privilege. [3]

## PART 1 | Local access turned into cross-system reach

- Network rules, database authorization and app-layer policy should each challenge movement.
- A firewall rule allowing a connection is not permission to query every schema.
- Review a concrete service identity: what can it enumerate, read and export.
- Test allowed and denied paths with synthetic data; seek blast-radius evidence, not a demonstration.
Caption: Evidence grade: Reported expansion to 48 DBs [2]; Inferred controls.
Notes: Trust decision 3 of 6. GAO reports access expanded beyond 3 portal databases to 48 unrelated ones; prefer scoped permission inspection over unrestricted simulation. [2]

## PART 2 | A read-only identity still ran a collection operation

- When the protected asset is information, read-only access can still cause serious harm.
- A low-privilege label misleads when the identity can read millions of sensitive records.
- Query count alone is a poor threshold; one query can return many rows.
- Detection needs context: rows returned, unusual joins, new schemas, new callers, staging.
Caption: Evidence grade: Reported ~9,000 queries [4]; Inferred detection.
Notes: Trust decision 4 of 6. Authorization should reflect the data reachable and the purpose, not only whether rows can be modified. [4]

## PART 2 | Encrypted egress is not proof the payload should leave

- Encryption protects transport; it does not prove an authorized party or an allowed payload.
- Blanket decryption of every connection is not a universal remedy either.
- Give each application a documented reason to talk to each external dependency.
- Low-and-slow movement evades simple volume thresholds; correlate identity, destination, behavior.
Caption: Evidence grade: an Inferred detection-engineering recommendation.
Notes: Trust decision 5 of 6. Connect source identity, destination history, process behavior and preceding sensitive-data access rather than treating network size as the whole incident. [2]

## PART 2 | A running sensor is not a seeing sensor

- Monitoring depends on collection, credentials, parsers, time sync, transport, storage, rules, escalation.
- An expired certificate kept a network-inspection device from seeing encrypted traffic. [2]
- A silent control can mean a quiet environment or a blind one.
- A harmless synthetic test event, source to analyst, makes the blind spot visible.
Caption: Evidence grade: a Confirmed certificate finding [2]; an Inferred test method.
Notes: Trust decision 6 of 6. The certificate concerns a monitoring function, not a consumer browser warning; maintenance must not silently redefine a service as protected. [2]

## DEFENDER VIEW | Closure needs evidence, not a ticket marked done

Left: Weak closure
- Forwarding the advisory to another team.
- A screenshot of a ticket marked done.
- A scanner result with unknown coverage.
Right: Strong closure
- Before and after component evidence plus a deploy ID.
- A service-health test and a safe re-verification.
- A named owner; unknown stays unknown until proven.
Caption: Evidence grade: an Inferred exposure-management program.
Notes: Every relevant service needs an applicability state (affected, unaffected with evidence, not yet assessed, retired); exceptions need expiry, compensating control, approver and retest date. [1][2]

## MITRE MAPPINGS | This study asserts no ATT&CK technique IDs

The study maps no formal MITRE ATT&CK techniques; a defender needs real deployed components and execution paths before claiming technique-level mappings.

- The six trust decisions read as attack-path stages, not as verified technique IDs.
- Formal mapping would require assumptions the bounded evidence does not support.
- Keep the boundary visible: stages are interpretation, not confirmed telemetry.
Caption: Evidence grade: Inferred; no technique IDs claimed.
Notes: The boundary is preserved deliberately. The detection hypotheses are for a defender's own environment, not validated signatures from Equifax logs. [2][4]

## CROSS-CUTTING THEMES | The breach is both overstated and understated

Left: Overstated
- One $700M fine or the total economic cost.
- 51 independent companies, or 51 exfiltration events.
- A ransomware attack, or a zero-day against a known fix.
Right: Understated
- 48 unrelated databases reached past 3 portal databases.
- Monitoring silence read as health, not as blindness.
- Read-only access to millions of records called harmless.
Caption: Evidence grade: Confirmed distinctions from the study's corrections.
Notes: Do not flatten settlement components into one fine, convert charges into convictions, or call the known-fix intrusion a zero-day. [2][3][4]

## CLOSE | Prove the right systems changed and what they reach

A defensible program answers five questions with evidence: what is exposed, who owns it, what changed, what access remains, and how the organization learns its assumptions failed.

- A patch is one interruption point, not a limit on post-compromise reach.
- Keep fact, allegation, inference and recommendation separate in every derivative.
- Decks may compress the narrative; speaker notes must carry sources and caveats.
Caption: Evidence grade: an Inferred synthesis; no exploit content.
Notes: The valuable output is a shorter path from an uncertain signal to an accountable decision, with less data reachable and fewer silent failures. [1][2][3][4]
