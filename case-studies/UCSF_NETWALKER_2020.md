# UCSF Ransomware 2020: Research Recovery, Privacy and the Limits of a Payment

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Healthcare, research and higher-education security teams, data-protection owners and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,348 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2020 UCSF NetWalker incident, you need to separate four meanings of affected or a payment from an outcome, or you are planning research-data recovery and privacy review

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [Four meanings of affected](#four-meanings-of-affected), [Payment and outcome should not be collapsed](#payment-and-outcome-should-not-be-collapsed)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

A ransomware incident at a research institution creates several different recovery questions. Can people reach the systems they need? Can researchers trust the restored data and reproduce their work? What information might have been exposed? Who is accountable for the services that protect a distributed academic environment? A ransom payment answers none of these questions by itself, even when it is made in pursuit of a decryption tool.

The University of California, San Francisco's 2020 incident is particularly useful because the institution published multiple dated updates. Its early operational statements, later payment disclosure, subsequent personal-information notification, and later IT operating-model review should be read together. Stopping at the most widely circulated payment headline would omit important distinctions about scope and the evolution of the investigation.

This study separates institution-confirmed facts from ransomware-family context and original defensive analysis. The consulted UCSF incident statements do not name the malware family. An Emsisoft profile associates the incident with NetWalker, while FBI and Justice Department materials explain the broader threat and enforcement history. Neither general family behavior nor a prosecution of a participant is used to invent an exact UCSF intrusion chain or identify its specific attacker.

No malware was executed, no leaked personal records were accessed, and no attacker was contacted. The research does not reproduce negotiation transcripts or advise a future victim to pay. Original sections on research continuity, data validation, privacy review, governance and exercises are clearly analytical proposals rather than claims about UCSF's private investigation.

## What UCSF disclosed, in sequence

UCSF's June 17 update said staff detected and stopped unauthorized access on June 1 in a limited School of Medicine environment. It described precautionary isolation wider than the intrusion's target, assistance from a cybersecurity firm, unaffected patient-care operations and an anticipated start to bringing isolated systems back within about two weeks. That was a forecast, not a verified completion date. [1]

On June 26, UCSF disclosed payment of approximately $1.14 million for a tool to unlock encrypted data and the return of obtained data. It said a limited number of servers had been encrypted, academic work was affected, and patient-care delivery, the overall campus network and COVID-19 work were not affected. Its then-current belief that patient medical records were not exposed was explicitly provisional. The statement did not establish that criminals had verifiably deleted every copy. [2]

On November 6, UCSF announced notifications about potentially affected personal information belonging to current and former employees, students, collaborators and research participants. The listed categories included identifiers, medical, insurance and financial information. It reported no evidence of misuse. Potential exposure, actual misuse and patient-care availability are different propositions; the later notice should not be erased by the earlier operational reassurance. [3]

These concise institutional findings are the backbone of the case. They establish neither the full number of impacted people nor a precise technical entry mechanism. The study does not turn omissions in a public update into proof that an event did not occur. Public communications often answer a narrower set of questions than a complete forensic report would.

## The NetWalker context and its attribution boundary

The FBI's alert dated July 28, 2020 describes multiple NetWalker access patterns, including phishing, vulnerable remote-access or web infrastructure, and weak remote-access credentials. It also discusses credential theft and data theft. Those are family-level observations, not findings about UCSF's entry point. The alert discourages ransom payment and notes that payment does not guarantee file recovery. Its date is read from the document, not inferred from the September-looking file path. [4]

The Justice Department's January 27, 2021 announcement described an international disruption, a defendant charged, seizure of cryptocurrency, and disabling a hidden resource. It described a developer-and-affiliate model. An indictment was an allegation at that stage; a resource seizure was not proof that every infection or criminal capability had disappeared. [5]

A later DOJ announcement records an October 4, 2022 sentence of twenty years for Sebastian Vachon-Desjardins in connection with NetWalker attacks. This is a later legal outcome, not merely the original allegation. The consulted release does not establish that he personally conducted the UCSF intrusion, and this case makes no such accusation. [6]

Emsisoft's NetWalker profile places UCSF among the family's incidents. It is cited as a vendor attribution layer, not a substitute for an institution's own forensic disclosure. General capabilities discussed in that profile are not assigned wholesale to UCSF. The institution's confirmed payment and scope remain sourced to UCSF itself. [8]

## The institutional review extended beyond malware

The executive summary of UCSF's June 7, 2021 IT Operating Model Task Force report described the ransomware incident as a catalyst for broader review. It identified problems involving collaboration, capabilities and funding, organizational accountability, and clarity of security direction. It proposed twenty-one countermeasures across a multiyear program. Recommendations are not evidence that all controls were implemented or that each issue was the exact technical cause of this attack. [7]

Only the indexed executive-summary text was accessible during this review. Attempts to reopen later passages and render the PDF redirected to the institution's current IT homepage. The document is therefore used within that limited scope, with the retrieval limitation preserved in the source register. It is not represented as a complete, page-by-page audit of the institution's improvement program.

Original analysis: this broader perspective changes the lesson. A malware family label describes a threat, but an operating model determines who can fund, operate, verify and improve the controls that matter. An incident can be technically contained while the conditions that make recovery difficult remain unresolved. The improvement plan needs to address those conditions without pretending that one generic control explains every event.

## Four meanings of affected

Original analysis: a useful incident record should distinguish malicious activity, precautionary isolation, business disruption, and personal-information risk. These categories can overlap, but they are not interchangeable. A server may be isolated because it shares a trust relationship with an affected system even when no malicious activity is confirmed on that server. A research workflow may be unavailable because a dependency was disconnected, not because its own data was encrypted.

Conversely, a system that remains available can still contain information relevant to a confidentiality investigation. Availability is not a privacy clearance. A working clinical application does not settle whether a separate research or administrative collection contained medical information. Precision is especially important when an institution has many missions, overlapping communities and different kinds of records.

A dashboard should preserve the reason for each classification. Instead of counting every disconnected host as infected, record confirmed encryption, confirmed unauthorized access, precautionary isolation, and unresolved status separately. Record the date and evidence supporting each change. This helps executives understand why service disruption may exceed the set of confirmed malicious changes.

The same discipline belongs in public language. A statement that patient-care delivery is unaffected should remain a statement about operations. It should not be rewritten as no health-related information was at risk unless that separate finding has been established. A defensible narrative retains the scope of the original claim rather than converting a limited reassurance into a universal one.

## Discovery, disclosure and recovery are different clocks

Original analysis: an incident timeline needs several clocks. Discovery is when the institution identified a problem. Containment is when specific access or propagation was stopped. Disclosure is when an audience was informed. Restoration is when a service or dataset met its acceptance criteria. These dates may be close together or months apart, and a long interval does not explain itself.

A public statement can also contain an estimate. When a team expects systems to return within two weeks, that is a planning signal with uncertainty, not an actual recovery measurement. Later researchers should seek a completion record before reporting a definitive outage duration. If none is available, the honest description is that a forecast was published and the exact completion date was not established by the consulted sources.

For internal management, record the dependency behind each estimate. A server rebuild may be straightforward while data validation requires a scientist who understands the study. A service may be technically ready but waiting for an account review or an approved network path. Without those dependencies, a date becomes a promise disconnected from the work that determines it.

Retrospective writing should also resist the temptation to make the earliest statement sound like the final conclusion. Investigation changes the available knowledge. Keeping the dates visible allows a reader to see that development without assuming either that the institution knew everything immediately or that any later refinement proves earlier bad faith.

## Research data is more than a collection of files

Original analysis: restoring research requires understanding how data becomes a result. A folder may contain source measurements, processed outputs, analysis scripts, configuration files, participant linkage records and working notes. Their value depends partly on relationships among them. Restoring a subset that opens successfully may still leave the study unable to reproduce a reported finding.

A research recovery inventory should identify the authoritative source for each important component. It should distinguish irreplaceable observations from outputs that can be regenerated, while also documenting the time and environment needed for regeneration. A derived file is not necessarily cheap to replace if it requires substantial computing capacity, specialized software, or expert review.

Version relationships matter. An analysis script restored from one date and a dataset restored from another may produce a plausible but incorrect combination. Record which versions belong together and how that relationship is validated. Where a project uses external references or licensed tools, include those dependencies in the recovery plan rather than discovering them during a crisis.

This is not an assertion that UCSF lost or mismatched any particular dataset. It is a defensive implication for research organizations evaluating their own resilience. The objective is to define recovery in terms of trustworthy scientific work, not simply the presence of readable bytes on a newly rebuilt server.

## An original research recovery worksheet

The following worksheet is a proposed operational aid, not a record of UCSF's response.

| Recovery question | Evidence or owner needed | Acceptance boundary |
|---|---|---|
| Which data is authoritative? | Research owner and provenance record | A convenient copy is not automatically the source of record |
| Which versions belong together? | Dataset, code and configuration mapping | Individually readable files can be an invalid combination |
| Can outputs be reproduced? | Controlled representative rerun | Successful execution alone does not validate scientific meaning |
| Are access permissions correct? | Data steward and identity review | Restoring data should not restore unnecessary access |
| Are external dependencies available? | Tool, license and compute owners | A restored directory is not a complete working service |
| Has the workflow been approved? | Technical and research acceptance | One team cannot silently sign off another team's obligations |

Each row needs an owner, a completion record and an unresolved-question field. The worksheet should not contain participant identifiers or secret credentials. Link to protected evidence rather than copying sensitive material into a general incident document. Access should follow the minimum necessary audience for the recovery task.

The record should also distinguish a test from a universal guarantee. A representative rerun provides evidence about a selected workflow. Document why it was representative, which dependencies it covered, and what remained outside the test. This prevents a successful small sample from becoming an unsupported claim that every research product is intact.

## Backup coverage must be demonstrated

Original analysis: the existence of a backup service is not proof that a particular workload was covered, retained long enough, and recoverable within the necessary time. Coverage needs evidence at the dataset and dependency level. A service catalog entry can describe a capability without proving that a laboratory or application actually used it correctly.

A useful review asks which assets are included, which are excluded, who approved the exclusions, and when a restore was last validated. It also asks whether recovery authority is sufficiently separate from production authority. The point is not to prescribe one technology but to test whether a compromise of ordinary operational access can defeat the recovery option as well.

Recovery tests should include access controls, ownership, application compatibility and data relationships. A file restored to a temporary location may demonstrate media readability while leaving the real operational recovery problem untouched. Test the ability to put the workflow back into a trusted environment with the people and tools that normally use it.

For this historical case, the consulted institutional disclosures do not provide a complete backup architecture or a definitive account of every failed recovery alternative. It would be improper to infer that no backups existed solely because a payment was made. It would be equally improper to infer that backups were fully adequate merely because a backup service was available somewhere in the institution.

## Payment and outcome should not be collapsed

Original analysis: a payment is a transaction made under pressure, not a technical recovery result. A promised tool, a delivered tool, successful decryption, validated data, restored operations, and verified removal of unauthorized access are distinct milestones. The incident record should identify which of these is actually supported instead of treating one as shorthand for all the others.

Confidentiality presents a separate problem. Receiving a copy of obtained information does not establish that every other copy ceased to exist. The relevant historical statement can be reported without endorsing an impossible-to-verify assurance. A case study should describe the stated purpose of a payment and avoid turning that purpose into proof of the final outcome.

This distinction also matters when calculating cost. A disclosed payment is not the complete incident cost. Investigation, restoration, operational interruption, communications, support and longer-term improvements may require resources, but their amounts cannot be invented or estimated from an unrelated organization. If the institution has not published a total in the consulted record, leave the total unknown.

This document does not offer legal clearance, negotiation tactics, or a recommendation to pay. Decisions in an active incident require qualified organizational, legal and operational advice based on the current circumstances. The analytical lesson is narrower: keep the evidence for each outcome separate so that a difficult financial decision does not erase the remaining recovery and privacy work.

## Privacy review continues after availability returns

Original analysis: an availability incident can trigger a much longer information review. A team may need to understand which collections were reachable, which were actually accessed, what records were included, and which people are represented. These questions require data stewardship and context that infrastructure logs alone may not provide.

The first step should be a scoped inventory, not indiscriminate copying of personal records into investigation notes. Record collection identity, custodian, purpose, retention period and relevant access evidence. Where inspection of content is necessary, use an authorized process with appropriate restrictions. The evidence trail itself should not become an additional uncontrolled repository of sensitive data.

No evidence of misuse is a useful finding only within a defined scope. It does not prove that exposure was impossible, and it should not be rewritten as a guarantee about future activity. Similarly, potential involvement in an incident does not prove that every person in a broad category experienced identity theft or financial loss. A clear notification distinguishes those propositions.

Operational and privacy teams should coordinate without forcing one workstream to wait for the other unnecessarily. Services may resume under validated conditions while the data review continues. The open privacy work needs named owners and deadlines so it does not disappear when the visible outage ends. Completion criteria should reflect the relevant obligations rather than a general desire to close the incident ticket.

## Governance in a distributed institution

Original analysis: research organizations often need specialized systems that do not fit a single standard service. The governance challenge is to make that diversity visible and supportable, not to pretend it can be eliminated by decree. A laboratory may have unusual software, instruments or collaboration needs; central IT may have responsibilities for common infrastructure and security evidence. Both perspectives matter.

An effective operating model specifies who is accountable for patching, monitoring, backup, access management and recovery testing for each workload. Shared responsibility should mean documented division of work, not a gap in which each team assumes the other is handling the task. The model must include escalation when a control cannot be applied in the usual way.

Funding is part of the control. If the approved service is unaffordable or cannot meet the mission's requirements, a policy alone will not create dependable adoption. An organization should identify the reason for exceptions and offer a feasible route to reduce risk. That might involve a supported specialized environment, a funded migration, or a time-bounded compensating arrangement.

Accountability also requires evidence. A statement that a system owner is responsible is insufficient if the owner has neither the authority nor the tools to perform the work. A governance review should test that the assigned role can actually see the system's status, request changes, obtain help, and verify completion. Otherwise the title creates blame without creating control.

## Containment without losing the recovery path

Original analysis: broad isolation can be justified when the scope is uncertain, but the response should preserve a controlled way to investigate and restore. Document why a boundary was chosen, which dependencies it interrupts, and which conditions would justify narrowing it. This helps a later team distinguish a deliberate precaution from evidence of confirmed compromise.

The business owner should identify the effects of isolation without demanding immediate reconnection by default. Some workflows can pause; others may need a documented alternative. The alternative should not create an unmanaged copy of protected data or bypass the same controls being investigated. Convenience during a crisis can create a second incident if it becomes an uncontrolled new environment.

Reconnection should be a decision with evidence. The team needs confidence in the system build, relevant access, monitoring and dependencies, as well as the data it will serve. A successful network test is not enough. Conversely, an unresolved question in one isolated component should not automatically prevent every unrelated service from resuming if a defensible boundary exists.

A staged approach makes the reasoning visible. Start with a limited validated function, observe its behavior, confirm the responsible owner's acceptance, and expand deliberately. The process should include a rollback condition and a clear contact for unexpected behavior. It should not rely on an undocumented assumption that the absence of an immediate alert proves complete safety.

## Attribution, enforcement and restitution

Original analysis: the history of a ransomware family and the history of one victim are connected but not identical. A prosecution can demonstrate accountability for a participant without resolving the role of that participant in every incident associated with the family. A study should preserve this distinction, especially when naming individuals.

Legal stages also have different meanings. A charge is not a conviction; a sentence is a later adjudicated outcome. Seized assets, forfeiture orders and restitution are not interchangeable financial events. Reporting a large seizure beside a victim's payment can imply reimbursement even when no evidence links them. Do not make that connection without a specific supported record.

The same restraint applies to technical disruption. Removing a communication resource can interfere with an operation without uninstalling malware from victim systems, recovering all data, or preventing every affiliate from using other tools. The impact of a disruption should be described in terms of the action actually reported, not an unqualified statement that the threat was eliminated.

For defenders, enforcement evidence can inform the broader picture, but it does not replace local recovery. An organization still needs to validate its systems and review data exposure. The positive significance of a criminal sentence is not diminished by acknowledging that victims may have separate unresolved operational or privacy obligations.

## A ninety-minute research-institution tabletop

This original exercise uses a fictional university department. It is not a reconstruction of UCSF's private deliberations. Participants include a research owner, infrastructure responder, data steward, identity administrator, communications lead and institutional decision-maker. Use synthetic records and invented data. No real participant information, active malware or criminal contact is required.

For the first twenty minutes, disclose an encryption event in a departmental environment and uncertain access to a neighboring service. Ask the team to choose a containment boundary, identify mission impacts, and draft a short internal update. The exercise tests whether the group distinguishes confirmed encryption from precautionary isolation and whether the update preserves that distinction.

For minutes twenty through forty, provide a usable backup of one dataset but a missing version relationship between the data and its analysis code. Ask what additional evidence is needed before research resumes. The correct response is not simply that a file opens. Participants should identify the research acceptance owner and a representative validation method.

For minutes forty through sixty, introduce information that a collection may contain personal data even though clinical operations remain available. Ask the team to establish a privacy workstream and revise its communication without contradicting the supported operational facts. Watch for the false inference that unaffected patient care means no medical information could be involved.

For the final thirty minutes, provide a proposed recovery plan with one unresolved ownership gap. Ask leadership to decide what can resume, what must remain restricted, and who will fund and verify the corrective work. Score the quality of the decision record, the clarity of residual uncertainty, and whether an exception has an owner and expiry. Do not score the exercise merely on how quickly participants declare victory.

## A worked recovery decision

Consider a fictional laboratory whose primary storage was encrypted while its instrument controller remained functional. The team has a protected copy of recent measurements, but the analyst who understands the processing configuration is unavailable. The instrument's availability does not solve the data-validation problem, and the backup's readability does not establish that a published result can be reproduced.

A defensible interim decision might allow collection of new measurements into an approved isolated location while pausing the affected analysis workflow. The technical team can validate storage and permissions, while the research owner identifies an authorized substitute reviewer. The decision should document how new observations will later be reconciled with the restored environment.

Now suppose the data steward finds a separate linkage file that associates coded observations with people. That discovery changes the privacy review, not necessarily the instrument's operational safety. The team should preserve the distinction instead of either shutting down everything reflexively or dismissing the linkage file because the scientific data looks anonymous.

The final acceptance record would explain the validated data versions, authorized access, representative scientific check, reconciliation of interim work, and any continuing privacy review. This example illustrates why research recovery needs more than a server owner. It also demonstrates how limited resumption can be compatible with an honest statement that the broader incident is not yet fully resolved.

## Measures for a durable improvement program

Original analysis: improvement should be demonstrated through coverage and tested outcomes. Useful measures include the proportion of important research workflows with a named recovery owner, the proportion with validated dependency maps, and the number of exceptions that have both funding decisions and review dates. Every percentage needs a defined inventory; an unknown population cannot support a reliable coverage claim.

Measure restore quality as well as restore speed. A short time to recover files is less meaningful if the team cannot verify their version relationships or permissions. Record which representative workflows were tested and what failed. Failures discovered during an exercise are valuable if they result in assigned work and a retest rather than a cosmetic completion status.

For governance, test whether local teams can obtain a supported solution for a legitimate specialized requirement. Track unresolved requests and the risk created while they wait. A centralized model that improves visibility but cannot meet essential needs may encourage work to move outside the managed environment. A distributed model without evidence of control can produce a different but equally serious blind spot.

Finally, distinguish recommendations, approved projects, implemented controls and verified outcomes. A published plan is an important commitment but not proof of completion. This distinction protects both the institution and the reader from overclaiming progress. It makes the next review concrete: which outcome has been tested, what remains uncertain, and who is responsible for the next decision?

## Conclusion

The case is more instructive when the payment is treated as one event rather than the ending. The institution's dated disclosures support a bounded operational account and a later personal-information notification. Family reporting and enforcement records provide context, but they do not supply missing UCSF-specific forensic details.

For a research organization, reliable recovery means that systems, data relationships, access and scientific workflows can be trusted for their intended use. Privacy review may continue after operations return. Governance improvements need funding, ownership and verification. Those are the decisions that turn a difficult incident into a durable improvement program without inventing certainty where the public record does not provide it.

## Sources and reading scope

[1] UCSF, June 17, 2020 update. Full incident text read; recovery forecast retained as forecast. https://www.ucsf.edu/news/2020/06/417861/ucsf-update-it-security-incident

[2] UCSF, June 26, 2020 update. Full incident text read; payment purpose, limited scope and provisional assessment distinguished. https://www.ucsf.edu/news/2020/06/417911/update-it-security-incident-ucsf

[3] UCSF, November 6, 2020 notification. Full notice read; potential impact and lack of evidence of misuse preserved. https://www.ucsf.edu/news/2020/11/418981/ucsf-notifies-individuals-regarding-cybersecurity-incident

[4] FBI, July 28, 2020, NetWalker FLASH. Extracted text of threat context and mitigation/payment caution read. Family context only, not UCSF-specific entry evidence. https://www.ic3.gov/CSA/2020/200929-2.pdf

[5] DOJ, January 27, 2021, NetWalker disruption announcement. Substantive announcement read; allegations and disruption scope preserved. https://www.justice.gov/archives/opa/pr/department-justice-launches-global-action-against-netwalker-ransomware

[6] DOJ, October 4, 2022, sentencing announcement. Substantive release read; no UCSF-specific attribution inferred. https://www.justice.gov/archives/opa/pr/canadian-national-sentenced-connection-ransomware-attacks-resulting-payment-tens-millions

[7] UCSF, June 7, 2021, IT Operating Model Task Force Recommendations. Indexed executive-summary text read; subsequent opening and screenshot attempt redirected to current IT homepage. No claim of full report or implementation audit. https://itgov.ucsf.edu/sites/g/files/tkssra3556/f/wysiwyg/ITOM%20Final%20Report%202021%20-%20ITGwebsite.pdf

[8] Emsisoft Malware Lab, NetWalker profile. Vendor family attribution and selected context read. No claim of direct access to UCSF forensic evidence; product recommendations and timeless decryption claims not adopted. https://www.emsisoft.com/en/blog/37677/ransomware-profile-netwalker/

Accessed November 15, 2026. Seven institutional/law-enforcement records plus one vendor contextual profile. Original analysis is not legal, clinical or payment advice.
