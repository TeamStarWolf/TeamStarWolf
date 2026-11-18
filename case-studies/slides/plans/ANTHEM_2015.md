# Slide plan: Anthem, 2015: Health Identity, Privileged Access and the Enterprise Data Warehouse

- Study: case-studies/ANTHEM_2015.md
- Cover title: Anthem 2015 / Identity, authority / and the warehouse
- Subtitle: A stolen credential becomes an enterprise breach when authority into a consolidated identity warehouse is not bounded, logged and tested.
- Published: 15 November 2026
- Notes: House-style case study; separates allegations, regulator accounts and settlements from verified fact.

## EXECUTIVE SUMMARY | A foothold mattered only because it reached the warehouse

The question is not the phishing email but how an initial foothold gained enough authority to reach a consolidated identity repository.

- Interrupt the progression at endpoint, credential misuse, privileged access, bulk retrieval and exfiltration.
- Health-plan identifiers can be protected health information without any theft of clinical histories.
- Calling all exposed data medical records overstates it; calling it contact information understates it.
- Remedy: map data paths, restrict authority, log sensitive operations, govern bulk extraction, verify.
Caption: Original analysis, not a reconstruction of every Anthem system.
Notes: Executive assessment; distinguishes legal class, technical content, individual impact. [1][2][7]

## KEY FACTS | The numbers describe people and remedies, not one attack

Stat: 78.8M | Affected people, not current subscribers
Stat: $16M | Federal HIPAA settlement, 2018
Stat: $39.5M | Multistate resolution, 2020
Stat: $115M | Prior class-action fund (closed)
- The 78.8M population includes former members, partner-plan enrollees and minors.
- HHS classed the data as electronic protected health information; no clinical theft was established.
- These remedies are distinct; summing public figures is not a defensible total cost.
- Anthem's 10-K could not quantify eventual expense and flagged litigation uncertainty.
Caption: Evidence grade: confirmed figures from named sources; totals not reconciled.
Notes: Populations reported, not audited. [1][2][5][7][8]

## PART 1 | Compressing the timeline into one attack date misleads

The earliest alleged email, access, discovery, notice, reporting, settlement and charging are different events across several years.

| Event | Date, approx |
|---|---|
| Alleged phishing to subsidiary | 18 Feb 2014 |
| Alleged unauthorized access | 13 May 2014 |
| Discovery | 29 Jan 2015 |
| Public announcement | 4 Feb 2015 |
| Federal settlement | Oct 2018 |
| Multistate resolution effective | 30 Oct 2020 |
Caption: Evidence grade: 2014 dates alleged in the indictment; 2015 onward from filings.
Notes: The window is not proof of continuous presence. [1][2][3][5][6]

## PART 1 | The data needs a category matrix, not one broad label

- Anthem described identity and employment information for current and former members and employees.
- No evidence at filing that credit-card or clinical data (claims, test results, diagnostic codes) was taken.
- HHS classed it as electronic protected health information serving affiliated and covered-entity plans.
- Not every affected person had every field taken; the population spans former enrollees and minors.
Caption: Evidence grade: a dated company statement plus regulator classification.
Notes: Keeps legal class, technical content and individual impact separate. [2][7][8]

## PART 1 | Read the chain as authority transitions, not a recipe

The indictment moves from targeted email and malware to remote access, credential acquisition, lateral movement, reconnaissance, collection and exfiltration.

- Each step hands up authority: workstation to credential, credential to service, service to sensitive data.
- Each transition has different evidence: endpoint, identity, authorization and warehouse audit logs.
- A familiar commercial transfer service in an allegation is not proof the provider took part.
- The study publishes no operational steps for reproducing the intrusion.
Caption: Evidence grade: an alleged chain; the defensive interpretation is original.
Notes: Preserves user, device, session, service and data-operation links. [3]

## PART 1 | Attribution stays an allegation and should not drive controls

- DOJ named Fujie Wang and a John Doe, alleging a China-based hacking group; all presented as allegations.
- The study does not infer state sponsorship from nationality, geography, infrastructure or victim count.
- No current conviction, arrest or final disposition is claimed.
- Warehouse controls are needed whether the motive is fraud, resale or intelligence.
Caption: Evidence grade: the indictment and DOJ announcement only.
Notes: Bounds criminal status to the charged allegations. [3][4]

## PART 2 | A data warehouse is a concentration of authority

Combining distributed data makes the warehouse useful and makes it a high-consequence boundary; the model here is proposed, not Anthem's diagram.

- The real questions: which users and services reach it, which datasets, which operations, where results go.
- Design access from business tasks, not job titles; a broad analyst role hides real differences.
- Bulk retrieval needs its own boundary: purpose, approved destination, limited dataset, accountable recipient.
- Scope the supporting systems too: jobs, service identities, consoles, staging areas and retained exports.
Caption: Original control model for comparable environments.
Notes: Protect the full data path, not just the server. Original analysis, no new source claims.

## PART 2 | Privileged identity needs independent, testable control

- A DBA noticed his credentials used without consent; Anthem shut down database access and forced resets.
- Password resets alone are not eradication: active sessions and service tokens can persist.
- Separate administrative authority from ordinary browsing and email; avoid shared admin accounts.
- Test revocation as a workflow with synthetic accounts and documented expected behavior.
Caption: Evidence grade: the detection narrative reported via the CA page; revocation design is original.
Notes: A historical consumer account, not a full forensic explanation. [8]

## PART 2 | Encrypted is context, not a complete description of safety

- The assurance describes data accessed unencrypted; the indictment alleges encrypted archives for transport.
- These are different stages; attacker packaging does not mean records were protected at retrieval.
- Storage encryption fails against an authorized application path a compromised identity can use.
- An encrypted connection is not proof of an approved destination or business purpose.
Caption: Evidence grade: assurance and indictment statements; no claim encryption would have prevented it.
Notes: Connect cryptographic protection with authorization and operational evidence. [3][6]

## DEFENDER VIEW | Start detection with a few high-value questions

Left: Questions to answer first
- Which identities can query the warehouse?
- Which operations retrieve broad or sensitive results?
- Which endpoints and services can create exports?
Right: Evidence to connect
- Identity: account, device, session, authorization decision.
- Warehouse: context to tell expected from anomalous.
- Transfer: destination ownership and business approval.
Caption: Confirm the evidence exists before promising full-chain detection.
Notes: Containment is a coordinated decision. An original workbench, no new source claims.

## MITRE MAPPINGS | Map tactics, but keep technique detail unmapped

The study models a chain but publishes no technique IDs; this maps only the alleged tactics and marks the boundary.

| Phase (study) | ATT&CK tactic | Mapped |
|---|---|---|
| Targeted email | Initial Access | Tactic only |
| Malware | Execution | Tactic only |
| Remote access | Command and Control | Tactic only |
| Credential acquisition | Credential Access | Tactic only |
| Lateral movement, recon | Lateral Movement, Discovery | Tactic only |
| Collection, transfer | Collection, Exfiltration | Tactic only |
Caption: Technique IDs and sub-techniques not mapped: the study declines an exploit recipe.
Notes: Tactic-level only; the study does not use ATT&CK IDs. [3]

## CROSS-CUTTING THEMES | The record is easy to overstate and to understate

Left: Overstated if you say
- "Medical records stolen": clinical theft was not established.
- "78.8M current subscribers": the population is broader and historical.
- "A proven China state operation": attribution stays an allegation.
Right: Understated if you say
- "Just contact information": identity data can be ePHI.
- "A stolen password": that authority reached a whole warehouse.
- "Encrypted, so safe": crypto did not bound the authorized path.
Caption: Evidence grade: both errors flagged by the study's source discipline.
Notes: Keeps classification, technical content and consequence separate. [2][3][7][8]

## CLOSE | Test one data path end to end, then expand

- Pick one important path: business purpose, approved identity, permitted query, destination, signal, revocation.
- Record what succeeds and what stays unverified; expand coverage deliberately.
- Preserve allegations as allegations; distinguish settlements from adjudicated liability.
- The federal corrective-action agreement was not retrieved; the limitation stays visible.
Caption: Original analysis; keeps the people behind the records central.
Notes: Final judgment and limitations. [1]
