# Slide plan: When You Cannot Patch the Cloud

- Study: case-studies/CLOUD_MANAGED_SERVICE_FLAWS.md
- Cover title: When You Cannot Patch the Cloud / Cross-Tenant and Token Flaws in Four / Managed Cloud Services
- Subtitle: Four provider-side flaws in Azure Cosmos DB, Azure PostgreSQL, AWS AppSync and Google Cloud Platform, none with a CVE, each fixed by the provider
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/CLOUD_MANAGED_SERVICE_FLAWS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The service you run but do not operate

- A managed cloud service is one the customer runs but the provider operates: the provider holds the code, the fabric and the isolation between tenants.
- When the flaw is in the part the provider holds, the customer cannot patch it; the provider fixes it on its own side, often silently.
- Four such flaws across four services, found by three firms, each fixed by the provider with no customer patch.
Caption: Evidence grade: Confirmed for the providers' own statements; Reported for the finder write-ups and the GhostToken news reports.
Notes: ChaosDB [1][2]. ExtraReplica [3][4]. AppSync [5][6]. GhostToken [7][8]. The "cannot patch" framing is the study's (Inferred).

## THE PATTERN | Flaws in the part you cannot patch

- **Cross-tenant and cross-account.** Three of the four crossed a boundary the provider's design was meant to hold: Cosmos DB, PostgreSQL and AppSync.
- **Token persistence.** The fourth, GhostToken, let an authorized app keep access to a Google account while hiding from the account's own apps list.
- **The fix is the provider's.** In every case the flaw and the fix lived in the provider's service; the customer never applied a version.
Caption: The customer's half is inventory, credential rotation and configuration, not patching. A provider fix closes one path; hygiene decides the rest.
Notes: Mechanisms from the finder and vendor records [1][3][5][7][8]. The shared-responsibility reading is the study's (Inferred).

## KEY FACTS | Four services, no CVE, provider fixes

Stat: 4 | managed services, three providers
Stat: 0 | cases that carry a CVE
Stat: 4 | fixed by the provider, no customer patch
Stat: 3 of 4 | crossed a tenant or account boundary
- Named: Azure Cosmos DB, Azure Database for PostgreSQL Flexible Server, AWS AppSync, Google Cloud Platform.
- No CVE means no CVSS from an assigning authority; severity is the finder's and the provider's words, not a score.
Notes: Wiz states the PostgreSQL flaw got no CVE identifier [3]. Providers assign CVEs to shipped software, not server-side service fixes (Inferred).

## PART 1 | ChaosDB, Azure Cosmos DB

- Wiz (26 August 2021): flaws in the Cosmos DB Jupyter Notebook feature let one tenant reach other tenants' notebooks and retrieve their primary keys.
- A primary key is a long-lived credential; once copied, disabling the feature does not stop it, so the response was a key-rotation notice.
- Reported 12 August 2021; Microsoft turned the feature off; published 26 to 27 August 2021.
Caption: Microsoft's update states no customer data was accessed by third parties, and that affected customers were notified to rotate their primary key.
Notes: Mechanism and key-rotation from Wiz [1]; the dates, the fix and the no-access statement from Microsoft's own update [2].

## PART 2 | ExtraReplica, Azure PostgreSQL Flexible Server

- Wiz (28 April 2022): a two-flaw chain let one customer read another customer's PostgreSQL database, crossing the tenant boundary.
- A privilege escalation in Azure's PostgreSQL engine, then an over-permissive certificate check that let an attacker-domain certificate authenticate across.
- Instances using private network access were not exposed; single-server was not affected.
Caption: Microsoft says it mitigated within 48 hours and no customer data was accessed. Wiz notes the issue received no CVE identifier.
Notes: Mechanism, scope and the no-CVE statement from Wiz [3]; the dates, the fix and the no-access statement from Microsoft's advisory [4].

## PART 3 | The confused deputy in AWS AppSync

- Datadog (21 November 2022): AppSync could be steered into assuming IAM roles in other AWS accounts, bypassing the cross-account validation.
- Datadog frames it as a confused deputy; AWS calls it a case-sensitivity parsing issue that bypassed cross-account role usage validations.
- The cross-account role use appeared in logs as activity of the service itself, which makes it hard to spot.
Caption: AWS's bulletin states no customers were affected and the only activity was between the researcher's own accounts; AWS fixed it in about five days.
Notes: Mechanism, dates and detection from Datadog [5]; AWS's own wording and the no-impact statement from the AWS security bulletin [6].

## PART 4 | GhostToken, Google Cloud Platform

- Astrix Security (published 21 April 2023): deleting the GCP project behind an authorized OAuth app put the app into a pending-deletion state.
- In that state the app dropped off the account's apps-with-access page while its token kept working; restoring the project revived it, repeatably.
- Reported to Google 19 June 2022; Google deployed a global patch 7 April 2023, making hidden apps visible again.
Caption: No Google statement of Google's own was found, and the finder's write-up now redirects to its acquirer, so this case rests on two news reports.
Notes: Mechanism, dates and Google's fix from the two news reports [7][8]; the sourcing gap is the study's note (Inferred).

## NO CVE, STILL SERIOUS | Why these carry no identifier

- None of the four has a CVE. Providers assign CVE identifiers to software they ship, not to server-side fixes of their own multi-tenant services.
- Wiz says so directly for ExtraReplica: the issue received no CVE identifier, unlike a software vulnerability.
- The effect is that there is no neutral third-party record or score; the facts come from the finder and the provider, graded to each.
Caption: No CVE does not mean no severity: three of the four carried cross-tenant data-access impact and one gave persistent, hidden account access.
Notes: The no-CVE statement is Wiz's [3]; the reason and the reading are the study's (Inferred from [1][3][5][7][8]).

## HOW EACH PROVIDER ANSWERED | Statements in their own words

| Provider | What they said and did | On impact |
|---|---|---|
| Microsoft (Cosmos DB) | Turned the feature off; notified customers to rotate keys | No customer data accessed by third parties |
| Microsoft (PostgreSQL) | Mitigated within 48 hours; private access not exposed | No customer data accessed |
| Amazon Web Services | Fixed in about five days; reviewed logs to launch | No customers affected; only the researcher's accounts |
| Google (GhostToken) | Global patch made hidden apps visible again | No Google statement of its own was found |
Caption: Three providers published their own account; for GhostToken the public record is two news reports, since the finder's write-up now redirects away.
Notes: Microsoft [2][4]; AWS [6]; Google's fix as the news reports describe it [7][8].

## DEFENDER VIEW | Find and fix, read-only first

Left: What to read
- Which managed services you use, what each holds, and what each can do on your behalf (data, keys, cross-account roles, OAuth grants).
- Which database instances use public versus private networking.
- Which third-party applications hold OAuth grants, and their scopes.
Right: What to do
- Rotate long-lived credentials on a schedule and after any provider notice; a key copied before a fix still works.
- Prefer private networking and least-privilege, scoped cross-account trust.
- Review OAuth grants; treat an app vanishing from the list as something to verify.
Caption: The database flaws happened inside the provider's fabric, where the customer had little to see; there the control is rotation and private networking.
Notes: Per-service steps from [1][3][4][5]; the read-first framing is the study's (Inferred).

## MITRE MAPPINGS | Cloud and identity techniques

| Id | Technique | Tie to the record |
|---|---|---|
| T1199 | Trusted Relationship | ExtraReplica and AppSync, across a tenant or account boundary |
| T1078.004 | Cloud Accounts | Operating as or into another tenant or account |
| T1552 | Unsecured Credentials | ChaosDB, the Cosmos DB primary keys reached across tenants |
| T1528 | Steal Application Access Token | GhostToken, the OAuth token the app holds |
| T1564 | Hide Artifacts | GhostToken, the app made invisible on the apps page |
Caption: These sit on ATT&CK's cloud and identity platforms. None carries a CWE, because none carries a CVE; the mappings are analytical.
Notes: Names and tactics from library data [9]; ties from [1][3][5][7][8]. Also T1530 Data from Cloud Storage and T1550.001 Application Access Token.

## CROSS-CUTTING THEMES | The customer's half of a shared model

- **One place, not one bug.** Four services, three firms, about two years; what ties them is the part of the service the customer cannot patch.
- **The provider carried the fix.** Each provider found and fixed its own flaw; two stated no data was accessed, one that no customers were affected.
- **The customer's half is hygiene.** Inventory, credential rotation, private networking and grant review decide how much is lost before the provider's fix lands.
Notes: Shared-place reading and the hygiene conclusion are the study's (Inferred). Provider statements [2][4][6]; GhostToken gap [7][8].
