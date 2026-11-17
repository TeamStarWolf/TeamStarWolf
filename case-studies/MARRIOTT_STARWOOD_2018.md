# Marriott and Starwood, 2014-2018: Acquiring a Business Does Not Reset Its Intrusion Clock

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Acquisition and integration security teams, data and identity owners, detection engineers, incident responders and privacy and risk leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 23 min (5,216 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2014 to 2018 Starwood breach, you need to tell records from people or the SHA-1 correction from the earlier AES-128 claim, or you are securing an acquired environment

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [The historical record in six bounded accounts](#the-historical-record-in-six-bounded-accounts), [Acquisition security: four phases with different evidence](#acquisition-security-four-phases-with-different-evidence)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The Starwood reservation-system breach is a case about inherited risk, long-lived access and the difficulty of describing a large data exposure accurately. An acquisition changes ownership. It does not remove an intruder, validate every privileged account or make an older database's security properties known. A migration plan can reduce future complexity while the legacy environment remains a live source of exposure in the meantime.

The incident also demonstrates why data-breach numbers need definitions. The initial announcement discussed up to approximately 500 million guests. A later disclosure described approximately 383 million guest records as an upper bound, expressly not a count of unique people. A subsequent FTC complaint used 339 million consumer records for the relevant breach. These numbers belong to different dated assessments and should not be added, averaged or presented as interchangeable counts of individuals.

A further correction materially affects the technical story. In April 2024, Marriott amended its older disclosure to say that payment-card numbers and some passport numbers in the involved tables had been protected using SHA-1 rather than the previously described AES-128. A historical study that simply repeats the earlier encryption claim misses an important change in the public record. Hashing and encryption are not synonyms, and a source correction must travel into derivative articles and slides.

The breach is often discussed alongside other Marriott and Starwood incidents. This study keeps the 2014-2018 reservation-database intrusion separate from the earlier payment-card breach and the later Marriott-network incident addressed in the 2024 FTC action. Combined enforcement totals are not the victim count of one event. Regulatory allegations are also not a substitute for an independently reconstructed exploit chain or definitive actor attribution.

The practical outcome is an acquisition-security framework: establish accountable ownership immediately after control transfers, preserve identity and data boundaries, investigate inherited environments rather than assuming they are clean, and verify security claims at the level of actual fields and access paths. Retirement is a project milestone. Trustworthy containment, data minimization and evidence-backed restoration are separate responsibilities.

## Scope, evidence and research limits

The main case is the Starwood guest-reservation breach beginning in 2014 and detected in 2018, spanning Marriott's 2016 acquisition of Starwood. Later records through the 2024 regulatory resolutions and company correction are included because they change the historical interpretation. The document is not a current compliance audit of Marriott, an estimate of every financial consequence, or a consumer claims guide.

Primary sources include Marriott's dated disclosures, the FTC's complaint and final order, the FTC's announcement distinguishing three breaches, the New York Attorney General's settlement announcement and NIST's explanation of SHA-1's status as a hash function. Sources were reviewed on 15 November 2026. No guest records, passport numbers, payment-card information, malware samples or victim systems were accessed.

The ICO penalty notice and a Senate-hosted testimony PDF were located but could not be fetched through the research tool. This study does not claim to have read those inaccessible documents. The final UK penalty amount is supported here by Marriott's own acknowledgement. Detailed regulatory findings are grounded in the accessible FTC complaint, with their allegation status retained. This limitation is preferable to silently presenting search snippets as a full-document review.

The article separates four kinds of statement: a company's account of its investigation; a regulator's allegations; an operative final order; and the author's proposed defensive analysis. A final settlement order establishes obligations within its terms. It does not mean every narrative inference in a commentary has become a judicial finding. Where the sources do not establish a specific vulnerability identifier or actor, this study does not invent one.

The implementation and exercise sections are original proposals for authorized organizations. They require adaptation to current law, contractual responsibilities, technology and operational needs. They do not authorize changes to production systems, deletion of records, external notifications or decisions about an individual's travel or identity documents.

## The historical record in six bounded accounts

### 1. A disclosure that explicitly distinguished records from people

Marriott's 4 January 2019 update revised the earlier population estimate to an upper limit of approximately 383 million guest records. It said the number of unique guests was lower and could not be quantified confidently because of duplicated information. The same page now carries the April 2024 cryptographic correction discussed below. [1]

This is a warning against converting a database count into a population census. One traveler can have many reservations, loyalty entries or historical versions. Conversely, similar names can represent different people. A defensible analysis should preserve the unit being counted and the method used to deduplicate it. Uncertainty about the exact number of individuals does not make the underlying exposure unimportant.

### 2. The FTC later described an extensive inherited intrusion

The FTC complaint alleges that an external-facing Starwood webserver was compromised around July 2014, followed by malware, credential harvesting and movement through the internal network. It says the intrusion was detected in September 2018 and identifies 339 million consumer records globally for that breach. It alleges weaknesses in monitoring, access controls, segmentation and other safeguards. [2]

The complaint supplies a useful high-level pathway without establishing a single named CVE in this account. A case study should not substitute a famous vulnerability merely because it fits the era. Likewise, the presence of credential-harvesting tools explains a class of capability; it does not identify the operator by itself.

### 3. Three breaches were addressed, not one continuous event

The FTC's October 2024 announcement separates an earlier Starwood payment-card breach, the long-running reservation-system breach and a later incident involving Marriott's own network. It gives a combined scale exceeding 344 million customers across the three incidents, while identifying the second event as involving 339 million guest account records. [3]

The important distinction is scope. The later Marriott incident should not be inserted into the 2014-2018 attack timeline as if it were a continuation established by the same evidence. A regulator can resolve several related security-practice allegations in one proceeding while describing technically distinct intrusions.

### 4. Security obligations became a final order

The FTC finalized its order in December 2024. The order addresses an information-security programme, data retention, customer deletion requests, loyalty-account reviews and restrictions on misrepresenting privacy and security practices. Its definitions and scope govern its application. [4][5]

This study uses the order to identify the nature of the regulatory response, not to provide legal advice about every entity or jurisdiction covered. A consumer-facing summary is not a replacement for the order's detailed definitions, time limits and exceptions. Nor does the existence of an order establish present noncompliance.

### 5. Monetary outcomes belong to different proceedings

Marriott acknowledged a GBP18.4 million ICO fine in October 2020 and stated that it did not intend to appeal, while making no admission of liability. The New York Attorney General announced a separate USD52 million multistate settlement in October 2024 and described acquisition-security and vendor-oversight requirements among its measures. [6][7]

These values must not be merged into a single penalty without currency, date and proceeding labels. They are not the total cost of the breach. The USD52 million was not an FTC civil penalty in this case; the FTC announcement expressly identifies the separate state settlement. [3]

### 6. A later correction changed the cryptographic description

The April 2024 update on Marriott's January 2019 page says payment-card numbers and some passport numbers in the relevant tables were protected with SHA-1 rather than the previously described AES-128. NIST identifies SHA-1 as a hash function. [1][8]

The correct response is not to replace one overconfident claim with another. The short correction does not fully describe the implementation, surrounding controls or every affected field. It does establish that the earlier blanket AES-128 description should not be repeated as current fact. An analysis should distinguish the cryptographic primitive, its use, the data's structure and the adversary's access.

## Timeline: ownership, discovery and accountability

| Period or date | Evidence-supported milestone | Boundary to preserve |
|---|---|---|
| Around July 2014 | FTC alleges compromise of the Starwood environment. [2] | No specific initial CVE established here. |
| September 2016 | Acquisition closes; FTC describes Marriott's subsequent responsibility. [2] | Ownership transfer does not establish a clean environment. |
| September 2018 | Reservation intrusion detected according to FTC account. [2] | Detection is not necessarily complete containment. |
| November 2018 | Public incident disclosure described by Marriott. [1] | Public disclosure date is not initial access date. |
| January 2019 | Company revises scale to a records-based upper bound. [1] | Records are not unique guests. |
| October 2020 | Company acknowledges final UK fine. [6] | Do not substitute an earlier proposed amount. |
| April 2024 | Company appends cryptographic correction. [1] | Earlier encryption wording is superseded for stated fields. |
| October-December 2024 | State settlement and FTC final-order process. [3][4][7] | Multiple breaches and proceedings have different scope. |

An acquisition creates two timelines that must be examined together. One describes legal and organizational control. The other describes technical compromise and remediation. An incident may begin before ownership changes and continue afterward. A security assessment that starts its clock at the transaction close can therefore miss relevant history.

The same principle applies to migration. A system scheduled for retirement remains a live security responsibility until access, dependencies and retained data are actually controlled. A deadline in an integration plan is not a compensating control. Risk decisions must cover the interval during which the old environment still processes or stores valuable information.

## Reconcile the estimates before drawing conclusions

The initial 500 million figure, the 383 million upper bound and the later 339 million records figure should be treated as dated claims with different wording and supporting work. The sources do not justify presenting them as three independent victim populations. Nor should the writer select the largest number solely for dramatic effect or the smallest solely to minimize the incident.

A population ledger should include the source date, counted object, geographic scope, deduplication method, uncertainty and relationship to previous estimates. The New York settlement's nationwide customer figure belongs to a different geographic scope than the worldwide records figure. A reader should be able to identify that difference without studying every footnote.

For an active incident, use separate categories for potentially reachable records, confirmed accessed data, confirmed exported data and records whose status cannot be resolved. The distinction matters for both investigation and communication. Limited logging can prevent a precise conclusion; it should not be converted into proof that no exposure occurred.

Data-quality problems make deduplication difficult. Names change, addresses change, loyalty accounts merge and reservations can contain multiple guests. A matching algorithm can merge two people incorrectly or count one person repeatedly. Investigators should retain the assumptions and confidence of the matching method. A precise-looking total produced by an uncertain method remains uncertain.

The goal is not perfect certainty before any useful action. It is a truthful account of what the evidence supports, updated as analysis improves. Customer assistance can proceed while estimates remain bounded, provided the organization explains the limits and avoids giving an individual a false definitive answer.

## Cryptography: verify the implemented protection, not the label

Encryption and hashing serve different purposes. Encryption is designed to permit authorized recovery of plaintext using appropriate key material. A hash function produces a digest and is not simply encryption with a different name. The practical protection of a stored field depends on how the primitive is used, the input space and the surrounding access controls. NIST's SHA-1 material establishes its classification and transition concerns; it does not independently assess Marriott's implementation. [8]

A security inventory should therefore describe the actual field-level construction. Which fields are protected? Where is the transformation performed? Are values copied into free-text fields, exports, logs or backups? What identities can obtain the original value? Who can alter the protection logic? A database described as encrypted may still contain unprotected copies elsewhere.

The April 2024 correction is important because it changes the answer to one of those questions, but it does not answer all of them. The study does not infer whether salts, keyed constructions or other controls were present where the correction does not say. It also does not claim that every protected value was recovered by the intruder. Those would require additional evidence.

A mature assurance process should verify claims through configuration, code review and controlled tests using synthetic data. A diagram or policy statement can describe intended design while the deployed system behaves differently. The test should identify where a value remains readable and which roles can retrieve it. Do not use real passport or payment-card numbers merely to demonstrate the control.

Cryptographic corrections also require editorial propagation. A statement may appear in an article, PDF, slide deck, FAQ and internal risk register. Updating only the source webpage leaves a network of stale claims. Maintain a claim identifier and a list of derivatives so that a material correction can be applied consistently.

## Acquisition security: four phases with different evidence

### Before close: understand without pretending to control

Pre-acquisition assessment often operates under legal, commercial and access constraints. The buyer may not be able to run intrusive tests or inspect every system. Those limits should be recorded as uncertainty, not converted into a clean bill of health. Ask for evidence about incidents, privileged access, data holdings, unsupported systems and monitoring coverage, with explicit limitations on what was independently validated.

The assessment should produce a post-close verification backlog. A questionnaire answer is a starting point, not proof. Each unresolved claim should have an owner, a validation method and a target date after appropriate access becomes available. This creates continuity between due diligence and operational integration.

### At close: assign responsibility before expanding trust

When control transfers, identify who owns security decisions for the acquired environment. Establish incident escalation, administrative access and evidence preservation. Avoid treating network connectivity or identity federation as a routine integration convenience before understanding the trust it grants. A shared login can expand the reach of a previously isolated compromise.

A minimum baseline should cover privileged accounts, remote access, exposed services, logging and critical data stores. Where evidence is missing, preserve separation and use bounded exceptions rather than granting broad access by default. The aim is not to halt the business indefinitely. It is to prevent integration from making an unknown environment more dangerous without a reasoned decision.

### During integration: test controls while systems remain live

Migration work competes for engineering attention. Legacy systems may receive fewer improvements because they are due to retire. That makes temporary controls especially important. Define which data remains, which users retain access, what monitoring must continue and who approves exceptions. A retirement date should not become a reason to stop patching or investigating.

Test cross-environment paths introduced by integration. Can an acquired identity administer the parent environment? Can a reporting service read both databases? Can a shared support account bypass segmentation? These questions matter even when the primary reservation databases remain separate. Actual trust paths are more informative than brand labels on a network diagram.

### At retirement: remove authority and account for retained copies

A system is not fully retired merely because new reservations stop using it. Accounts, service credentials, scheduled jobs, exports, backups and support access can remain. Retirement acceptance should enumerate those remnants and decide what must be preserved, restricted or deleted under applicable requirements.

Verify that data retained for legal or operational reasons has an owner, an access boundary and a disposal schedule. Retention should not be indefinite by accident. A legacy database moved into an archive can still be a valuable target if its access model remains broad and its monitoring disappears.

## Credential compromise turns identity into an attack path

The FTC's account emphasizes harvested administrative and user credentials. The general defensive lesson is that account validity and user legitimacy are different questions. An attacker using a real account may pass ordinary access checks. Detection needs context about the source system, requested data, timing, privilege and business purpose.

Privileged accounts should be individually attributable where feasible, restricted to appropriate administrative environments and reviewed for actual need. Emergency access needs monitoring and expiration. Service identities deserve the same scrutiny as human users because they often hold durable permissions across databases and systems.

Credential rotation after compromise is necessary where relevant, but sequence matters. If the compromised host or session can immediately obtain the replacement secret, rotation may produce little durable benefit. Contain the exposure path, invalidate sessions as appropriate and validate the consuming systems before restoring trust.

A useful exercise begins with a synthetic compromised account and asks which data stores it can reach. The answer should include indirect access through services, backups and management interfaces. Document denied paths as well as allowed ones. A role described as read-only can still expose large amounts of sensitive information.

## Detection should connect database behavior with identity context

Database activity is not inherently suspicious because it is large or administrative. Backups, reporting and migrations can legitimately move substantial data. The challenge is to distinguish authorized work from misuse using context that remains trustworthy when one account or host is compromised.

A detection design should combine identity, source, query purpose, data sensitivity and export destination. A new source host using an old privileged account may deserve attention even when the query is syntactically ordinary. A familiar reporting job producing an unexpected export can be another useful signal. No single feature should be treated as a universal proof of compromise.

The pipeline also needs coverage testing. Does the audit configuration record the relevant operations? Are timestamps consistent? Can logs be altered by the same account being monitored? Does an analyst know the business owner of the database? An alert without a reliable escalation path can become another unexamined record.

The FTC complaint's allegations about monitoring and logging support the importance of this area, but the following hypotheses are original proposals, not recovered Starwood rules. They should be tested locally with synthetic data and approved workflows before production use. Avoid exporting raw guest information into broadly accessible security systems when metadata is sufficient.

### Hypothesis A: a privileged identity acts from an unexpected context

Correlate administrative access with source-device identity, recent role changes and approved maintenance. Validate that legitimate work can be explained without giving administrators blanket exemptions. Test with a controlled account in a nonproduction environment and confirm that the event reaches an analyst with the correct service owner attached.

### Hypothesis B: sensitive-data access precedes unfamiliar staging

Observe unusual exports, archive creation or movement into locations outside the normal workflow. The detector should distinguish routine backup and migration jobs from unexplained activity. A harmless synthetic dataset can test the sequence without creating another sensitive-data repository.

### Hypothesis C: an integration change expands the reachable data set

Alert or require review when a new trust relationship gives an identity access across previously separate environments. The change may be legitimate, but its consequences should be explicit. Test that the approval record identifies the data and permissions being added, not merely the network connection being opened.

### Hypothesis D: a legacy system loses visibility before retirement

Track log freshness, sensor coverage and ownership through the migration. A system marked decommissioning should not disappear from monitoring while it still stores accessible guest data. The test should intentionally interrupt a benign telemetry feed in a replica and confirm that the resulting blind spot is assigned and resolved.

## Incident response needs a data map and a claim ledger

The incident commander needs more than a list of affected machines. A data map identifies which tables, exports, backups and downstream systems may contain the same information. Without that map, containment can focus on one database while copied records remain accessible through another service.

Scope should be documented as evidence accumulates. Record what is confirmed, what is inferred and what remains unresolved. A discovered export file may establish that data was collected locally; evidence of transfer is a separate question. Missing files or incomplete logs complicate the assessment and should appear in the confidence statement.

Preserve relevant evidence with provenance, integrity checks and restricted access. Do not create a second uncontrolled breach by copying guest datasets into analyst notebooks, chat attachments or shared folders. Use approved secure handling and minimize the personal data required for each investigative task.

Containment should address the compromised authority as well as the host. Restrict affected accounts, sessions and paths according to an authorized plan, while evaluating business dependencies. A reservation outage can harm guests and operations, but that does not justify continuing unrestricted access through a known compromised path. Decision-makers need options and their consequences, not a false choice between everything online and everything off.

The public claim ledger should link every material statement to evidence and a revision trigger. Examples include population counts, data categories, protection methods and service-restoration status. The April 2024 correction shows why that ledger must remain maintainable after the first incident-response sprint ends.

## Data minimization is a blast-radius control

A data store's value to the business changes over time, while its exposure cost can remain. Retaining historical guest information because deletion is inconvenient creates a risk that may not correspond to a continuing operational need. The review should identify purpose, required retention and access for each category, rather than treating every legacy field as permanently necessary.

Minimization is not indiscriminate deletion. Legal holds, accounting duties, fraud prevention and legitimate customer service can require retention. Those reasons should be explicit, with bounded access and review dates. The organization should not delete evidence during an investigation or ignore applicable preservation duties in the name of reducing risk.

The FTC final order's retention provisions are an example of a regulatory response, not a complete retention schedule for every organization. A practical programme needs coordination among legal, privacy, operations and engineering. The technical work includes locating copies and verifying that retention rules actually execute.

A deletion workflow should also account for recovery. If a system is restored from backup, does it reintroduce records previously scheduled for removal? The answer may require a controlled reconciliation process after restoration. A policy that applies only to the live table is incomplete if old exports and restored copies remain outside it.

## Vendor and franchise boundaries need operational clarity

Hospitality environments involve multiple operators, service providers and ownership arrangements. A single brand name can conceal different administrative responsibilities. The security model should identify who operates each system, who receives alerts, who can contain an incident and which contractual route supports urgent action.

A contract assigning responsibility is useful but does not prove that the corresponding control works. Exercise escalation with the actual service provider. Confirm that an alert can reach the right internal team outside ordinary working hours and that both sides understand what evidence is available. An unanswered ticket queue is not an effective incident channel.

Data flows also deserve review. A provider may need limited access for support without needing a complete copy of the guest database. Administrative convenience should not silently expand data sharing. Document scope and retention for support exports, test environments and troubleshooting artifacts.

The New York settlement announcement highlights vendor oversight and acquisition assessment among its measures. This study generalizes those themes into a control framework; it does not assert that every franchisee is covered identically by every term of the FTC order or state settlement. Legal scope must be read from the relevant instrument.

## Metrics that expose uncertainty rather than hide it

| Measure | Evidence | Misleading substitute |
|---|---|---|
| Inherited-system coverage | Named owner and verified inventory after close | Completed acquisition questionnaire |
| Privilege containment | Tested effective access across environments | Role names without permission review |
| Legacy visibility | Fresh, complete telemetry until access ends | Retirement project status |
| Field-protection assurance | Deployed implementation tested with synthetic data | A generic encrypted database label |
| Population confidence | Defined unit, scope and deduplication method | One unsupported precise-looking count |
| Retirement completion | Accounts, jobs, copies and access reconciled | New traffic moved to a replacement |

A metric should reward finding gaps, not encourage teams to conceal them. If newly discovered systems make the dashboard look worse, leadership should distinguish improved visibility from deteriorating security. If a count changes because deduplication improves, preserve the explanation rather than implying earlier numbers were exact.

Report material exceptions in business terms. Which guest data remains reachable? Which identity can cross the boundary? Which claim about protection is unverified? Which legacy system is still live despite a retirement milestone? These questions make it easier for leaders to authorize meaningful work instead of approving an abstract maturity score.

## Ninety-day acquisition-security plan

### Days 1-20: establish responsibility and evidence

Identify owners for acquired systems, data and incident decisions. Preserve logs and administrative history. Reconcile exposed services, privileged accounts and critical data stores using more than one inventory source. Record what was not accessible during diligence and assign a post-close validation task for each unresolved claim.

### Days 21-40: test high-value boundaries

Review remote access and effective privileges, then validate separation between environments. Test field-protection claims using synthetic data and controlled inspection. Prioritize paths that combine sensitive records with broad administrative authority. Avoid expanding trust merely to simplify integration deadlines.

### Days 41-65: connect monitoring and response

Exercise database alerts, service-provider escalation and containment authority. Confirm that logs survive a simulated compromise of the monitored account or host. Build a data map that includes exports and backups. Establish a claim ledger for incident communication before a crisis requires it.

### Days 66-90: prove retirement and retention decisions

For systems being replaced, verify account removal, job shutdown, copy ownership and retained-data access. Test restoration procedures for reintroduced data and privileges. Report unresolved risk with an owner and deadline. A migrated application is not automatically a retired exposure.

## Tabletop: the acquisition that inherited an intruder

This is a fictional exercise, not a reconstruction of private Starwood events. Use invented hotels, synthetic guest data and test systems. Participants should include acquisition integration, IT operations, security, privacy, legal, database administration, service-provider management and communications.

### Inject 1: the acquired system is due to retire

A sensitive legacy database will be replaced in six months. Its owner requests an exception from monitoring improvements because the work seems temporary. Ask what remains exposed during the interval, what compensating measures exist and who accepts the risk. Success is a bounded decision, not a promise that retirement will eventually solve it.

### Inject 2: a valid administrator denies making a query

An alert shows a privileged operation that the account owner says they did not perform. Ask how the team distinguishes account misuse, automation and incomplete attribution. Success includes preserving evidence and evaluating the credential's reach. Failure is closing the alert simply because the account is legitimate.

### Inject 3: the data count changes

Initial analysis finds many records, then deduplication reduces the estimate. Ask whether the team is counting records, reservations, accounts or people. Success is a transparent explanation of the method and scope. The public message should not imply certainty that the evidence cannot support.

### Inject 4: the protection label is wrong

A test reveals that a field described in documentation as encrypted uses a different construction. Ask who validates the implementation, which prior statements need correction and whether additional copies exist. Success is an evidence-led revision. Do not replace the old label with a new claim that exceeds what was actually tested.

### Inject 5: a provider has the missing logs

The critical evidence is held by a service provider with a short retention period. Ask how the team preserves it, verifies completeness and restricts access to personal information. Success is a tested contractual and operational route, not an improvised request that arrives after deletion.

### Inject 6: migration finishes but old credentials remain

The new reservation service is live, while an old support account still reaches archived data. Ask what retirement means and who signs acceptance. Success includes reviewing residual identities, jobs and copies. A successful customer transaction on the new system does not prove the old risk is gone.

After the exercise, assign each gap an owner, deadline and retest. Distinguish a missing tool from a missing decision right. The goal is to make inherited uncertainty visible and actionable before an intruder benefits from the gap between corporate integration and technical trust.

## Attribution and vulnerability discipline

This study does not make a definitive attribution to a government or named intrusion group. Travel data can have intelligence value, but potential value does not identify who took it. Public speculation, tool overlap and geopolitical context should not be converted into a finding unsupported by the primary records used here.

The same restraint applies to vulnerability claims. The FTC complaint describes an external-facing server compromise and several control deficiencies. It does not establish a specific initial CVE in the passages used for this study. A control weakness, a malware capability and an exploited software vulnerability are related but distinct concepts.

Defenders can still act without a complete attribution or exploit reconstruction. They can reduce privileged reach, verify telemetry, minimize retained data and investigate inherited environments. The absence of a named zero-day should not make a case seem less important, and the presence of a familiar tool should not make its operator seem certain.

## Editorial checks and conclusion

Keep the three breaches separate. Label 500 million as an initial estimate, 383 million as a dated records upper bound and 339 million as the later complaint's records figure. Do not call all of them unique guests. Preserve the April 2024 SHA-1 correction and do not repeat the older AES-128 claim without qualification.

Distinguish the UK fine, the state settlement and the FTC order. Do not call the USD52 million an FTC fine or a total breach cost. Keep allegations attributed and do not invent a specific CVE or actor. Note that the inaccessible ICO notice was not reviewed in full for this package.

The lasting lesson is that inherited systems retain their history until an organization investigates and changes them. Acquisition, migration and retirement are business events with security consequences, not automatic security controls. The strongest programme can explain who owns the data, who can reach it, what protection is actually implemented and what evidence supports each claim.

## Sources and reading notes

[1] Marriott. Marriott Provides Update on Starwood Database Security Incident. 4 January 2019; correction appended 17 April 2024. Read the correction before reusing the older field-protection language. https://marriott.gcs-web.com/news-releases/news-release-details/marriott-provides-update-starwood-database-security-incident

[2] Federal Trade Commission. Marriott/Starwood Complaint, matter 1923022. 2024. Allegations; second-breach account in paragraphs 11-16, broader control allegations in paragraph 27. https://www.ftc.gov/system/files/ftc_gov/pdf/1923022marriottcomplaint.pdf

[3] Federal Trade Commission. FTC Takes Action Against Marriott and Starwood Over Multiple Data Breaches. October 2024. Distinguishes three incidents and the separate state monetary settlement. https://www.ftc.gov/news-events/news/press-releases/2024/10/ftc-takes-action-against-marriott-starwood-over-multiple-data-breaches

[4] Federal Trade Commission. Finalization announcement. December 2024. https://www.ftc.gov/news-events/news/press-releases/2024/12/ftc-finalizes-order-marriott-starwood-requiring-them-implement-robust-data-security-program-address

[5] Federal Trade Commission. Final Decision and Order, Docket C-4807. December 2024. Definitions and operative requirements must be read within the order's scope. https://www.ftc.gov/system/files/ftc_gov/pdf/1923022marriottfinalorder.pdf

[6] Marriott. Update on Conclusion of UK ICO Investigation. 30 October 2020. Company acknowledgement of final fine; not a substitute for the inaccessible full ICO notice. https://marriott.gcs-web.com/news-releases/news-release-details/marriott-international-update-conclusion-uk-ico-investigation

[7] New York Attorney General. USD52 million multistate settlement announcement. 9 October 2024. https://ag.ny.gov/press-release/2024/attorney-general-james-announces-52-million-multistate-settlement-marriott-over

[8] NIST. NIST Transitioning Away from SHA-1 for All Applications. 15 December 2022. Used to establish SHA-1 as a hash function and contextualize the distinction, not to assess Marriott's implementation. https://www.nist.gov/news-events/news/2022/12/nist-transitioning-away-sha-1-all-applications

## Publication status

Unpublished research draft for review. No GitHub publication, live deployment or public sharing occurred. The full article is the source of truth; the deck is a condensed companion. Proposed controls require local validation and current operational and legal guidance.
