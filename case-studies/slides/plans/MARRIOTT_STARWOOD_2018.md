# Slide plan: Marriott and Starwood, 2014-2018: Acquiring a Business Does Not Reset Its Intrusion Clock

- Study: case-studies/MARRIOTT_STARWOOD_2018.md
- Cover title: Marriott and Starwood / 2014-2018 / Inherited Intrusion
- Subtitle: An acquisition transfers ownership, not a clean environment; inherited access, shifting victim counts and a SHA-1 correction all demand discipline.
- Published: 15 November 2026
- Notes: Condensed companion to the full article; every proposed control needs local legal and operational validation.

## EXECUTIVE SUMMARY | Acquiring a business does not reset its intrusion clock

- An acquisition changes ownership; it does not remove an intruder or validate every privileged account.
- The Starwood intrusion is alleged from around July 2014 and detected in September 2018, spanning the 2016 purchase. [2]
- A migration plan can reduce future complexity while the legacy environment stays a live source of exposure.
- Regulatory allegations are not a reconstructed exploit chain or a definitive actor attribution.
Caption: Evidence grade: FTC allegations, not adjudicated findings.
Notes: Executive summary and scope; the pathway and dates are alleged in the FTC complaint [2]; allegation status retained [2][3].

## KEY FACTS | One intrusion ran four years before anyone detected it

Stat: 2014 | Starwood server compromise alleged, FTC
Stat: 2018 | Intrusion detected, four years later
Stat: 339M | Consumer records in FTC second-breach count
Stat: 383M | Guest records upper bound, not unique people
- Compromise around July 2014; detected September 2018; publicly disclosed November 2018. [1][2]
- The 383 million figure is a records upper bound, expressly not a count of unique guests. [1]
- Marriott acquired Starwood in September 2016, inheriting the live environment and its history. [2]
Caption: Evidence grade: dated company and FTC disclosures.
Notes: The timeline and record-count bounds [1][2]; three-breach scope [3]; detection is not containment [2].

## PART 1 | The FTC addressed three breaches, not one continuous event

- The FTC October 2024 action separates an earlier card breach, the reservation breach and a later Marriott-network incident. [3]
- Combined scale exceeds 344 million customers across all three; the reservation breach involves 339 million guest account records. [3]
- Do not insert the later Marriott-network incident into the 2014-2018 timeline as an established continuation. [3]
- One proceeding can resolve related allegations while describing technically distinct intrusions. [3]
Caption: Boundary: three incidents, three scopes, one proceeding.
Notes: The FTC three-breach announcement and combined figure [3]; the reservation-breach detail from the complaint [2].

## PART 1 | The victim numbers are dated claims, not one count

Treat each figure as a dated claim with its own wording, scope and supporting work; do not add, average or swap them.

| Figure | Source and date | What it counts |
|---|---|---|
| ~500M | Initial 2018 announcement | Early estimate, up to approx guests |
| 383M | Marriott, Jan 2019 [1] | Records upper bound, not unique people |
| 339M | FTC, 2024 [2][3] | Consumer and guest account records |
Caption: Evidence grade: dated claims, not three victim populations.
Notes: The records-versus-people distinction [1]; FTC counts [2][3]; NY nationwide customer scope differs from worldwide records [7].

## PART 2 | The 2024 SHA-1 correction retires the AES-128 claim

- April 2024: Marriott says card and some passport numbers used SHA-1, not the described AES-128. [1]
- Hashing and encryption are not synonyms; NIST classifies SHA-1 as a hash function. [8]
- The short correction does not describe salts, keyed constructions or every affected field. [1]
- Verify field-level construction through configuration and code review, using synthetic data only. [8]
- Propagate the correction into articles, slides, FAQs and risk registers, not just the source page.
Caption: Evidence grade: a Confirmed company correction; implementation unstated.
Notes: The April 2024 SHA-1 correction [1]; SHA-1 as a hash per NIST [8]; cryptography-verification and editorial-propagation guidance.

## PART 2 | Acquisition security runs in four evidence-bound phases

Left: Before and at close
- Before close: record diligence limits as uncertainty, not a clean bill of health.
- At close: assign security ownership before extending network or identity trust. [2]
Right: During and at retirement
- During integration: keep legacy monitoring and patching; test cross-environment trust paths.
- At retirement: remove accounts, jobs and exports; account for retained copies.
Caption: Boundary: a retirement date is not a compensating control.
Notes: The four-phase acquisition-security model; a shared login expands an isolated compromise's reach [2].

## PART 2 | Retirement and retention set the breach blast radius

- A system is not retired because new reservations stop; accounts, jobs, backups and support access can remain.
- Retained data needs an owner, an access boundary and a disposal schedule, not indefinite retention by accident.
- Restoration from backup can reintroduce records scheduled for deletion; reconcile copies after restore.
- The FTC final order addresses an information-security program, data retention and customer deletion requests. [4][5]
Caption: Evidence grade: order obligations [4][5]; the controls are proposals.
Notes: Retirement, data-minimization and claim-ledger guidance; the final-order scope governs its application [4][5].

## DEFENDER VIEW | A valid account is still an attack path

- The FTC account emphasizes harvested administrative and user credentials. [2]
- Account validity and user legitimacy are different questions; a real account can pass ordinary checks. [2]
- Service identities need the same scrutiny as humans; they hold durable permissions across systems.
- After compromise, contain the exposure path before rotating secrets, or rotation gains little durable benefit.
Caption: Boundary: a capability class is shown, the operator not identified [2].
Notes: The credential-compromise section; FTC credential-harvesting allegations [2]; no actor attribution claimed [2].

## DEFENDER VIEW | Detection must fuse database behavior with identity

- Combine identity, source, query purpose, data sensitivity and export destination; no single feature proves misuse.
- Hypothesis A: a privileged identity acts from an unexpected device or context.
- Hypothesis B: sensitive-data access precedes unfamiliar staging or export.
- Hypothesis C: an integration change expands the reachable data set across environments.
- Hypothesis D: a legacy system loses telemetry before retirement.
Caption: Evidence grade: Demonstrated proposals; test with synthetic data.
Notes: The detection hypotheses; FTC monitoring and logging allegations motivate but do not prescribe these rules [2].

## MITRE MAPPINGS | The record supports capability classes, not technique IDs

The sources describe a capability pathway but do not assign ATT&CK technique IDs, a CVE or an actor.

| Element | Record supports | Mapping stance |
|---|---|---|
| Initial access | External server compromise [2] | No specific CVE established |
| Credential access | Credential harvesting alleged [2] | Class, not technique ID |
| Lateral movement | Internal network movement [2] | Not mapped to a technique |
| Attribution | Travel data has value | No actor named |
Caption: Boundary: no CVE, no technique ID, no actor claimed.
Notes: The attribution and vulnerability-discipline section; FTC pathway allegations [2]; NIST context [8] contextualizes, does not map.

## CROSS-CUTTING THEMES | Avoid overstating and understating in the same report

Left: Overstated if careless
- Adding 500M, 383M and 339M into one victim population.
- Repeating the AES-128 label after the SHA-1 correction. [1]
- Calling the $52M state settlement an FTC fine or total breach cost. [3][7]
Right: Understated if careless
- Treating the acquisition close as the start of the security clock. [2]
- Letting a retirement date excuse paused patching and monitoring.
- Converting limited logging into proof that no exposure occurred.
Caption: Discipline: state the unit, scope, date and evidence grade.
Notes: Reconciliation, editorial-checks and metrics sections; figures [1][3][7]; the two-timeline boundary [2].

## CLOSE | Inherited systems keep their history until you change them

- Inherited systems retain their history until an organization investigates and changes them.
- Acquisition, migration and retirement are business events with security consequences, not automatic controls.
- A strong program can say who owns the data, who can reach it and what protection is actually implemented.
- Keep the three breaches, the population figures and the SHA-1 correction labeled and separate. [1][3]
Caption: Evidence grade: author analysis grounded in the cited record.
Notes: Editorial checks and conclusion; three-breach and correction discipline [1][3]; an inaccessible ICO notice was not reviewed in full.
