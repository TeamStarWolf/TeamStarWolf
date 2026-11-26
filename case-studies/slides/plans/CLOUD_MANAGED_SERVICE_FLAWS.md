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
Caption: Evidence grade: Confirmed for the providers' own statements; Reported for the finder write-ups, the archived GhostToken account and the news reports.
Notes: ChaosDB [1][2]. ExtraReplica [3][4]. AppSync [5][6]. GhostToken, from the finder's archived write-up [10] plus [7][8][11]. The "cannot patch" framing is the study's (Inferred).

## THE PATTERN | Flaws in the part you cannot patch

- **Cross-tenant and cross-account.** Three of the four crossed a boundary the provider's design was meant to hold: Cosmos DB, PostgreSQL and AppSync.
- **Token persistence.** The fourth, GhostToken, let an authorized app be hidden from a Google account's apps list and its access revived at will.
- **The fix is the provider's.** In every case the flaw and the fix lived in the provider's service; the customer never applied a version.
Caption: The customer's half is inventory, credential rotation and configuration, not patching. A provider fix closes one path; hygiene decides the rest.
Notes: Mechanisms from the finder and vendor records [1][3][5][10]. The shared-responsibility reading is the study's (Inferred).

## KEY FACTS | Four services, no CVE, provider fixes

Stat: 4 | managed services, three providers
Stat: 0 | cases that carry a CVE
Stat: 4 | fixed by the provider, no customer patch
Stat: 3 of 4 | crossed a tenant or account boundary
- Named: Azure Cosmos DB, Azure Database for PostgreSQL Flexible Server, AWS AppSync, Google Cloud Platform.
- No CVE means no CVSS from an assigning authority; severity is the finder's and the provider's words, not a score.
Notes: Wiz states the PostgreSQL flaw got no CVE identifier [3]. The providers' CVE policy changed in 2024 [13][14]; none of the four has a CVE as of 25 November 2026 [17][18].

## PART 1 | ChaosDB, Azure Cosmos DB

- Wiz (26 August 2021): flaws in the Cosmos DB Jupyter Notebook feature let one tenant reach other tenants' notebooks and retrieve their primary keys.
- A primary key is a long-lived credential; once copied, disabling the feature does not stop it, so the response was a key-rotation notice.
- Reported 12 August 2021; Microsoft disabled the feature (Wiz observed, 14 August); customers notified 26 August; Microsoft's post 27 August.
Caption: Microsoft's post states no customer data was accessed by third parties or researchers; it later retired the notebooks feature on 30 March 2024.
Notes: Mechanism and the over-30-percent notice from Wiz [1]; the no-access statement from Microsoft's post [2]; the disable date from Wiz's walkthrough [16]; retirement [15].

## PART 2 | ExtraReplica, Azure PostgreSQL Flexible Server

- Wiz (28 April 2022): a two-flaw chain let one customer read another customer's PostgreSQL database, crossing the tenant boundary.
- A privilege escalation in Azure's PostgreSQL engine, then an over-permissive certificate name check that let an attacker-domain certificate authenticate across.
- The first flaw also hit Single Server; the cross-tenant bypass did not. Private-access instances were not exposed.
Caption: Microsoft says it mitigated within 48 hours and no customer data was accessed. Wiz notes the issue received no CVE identifier.
Notes: Mechanism, scope and the no-CVE statement from Wiz [3]; the dates, the fix and the no-access statement from Microsoft's post [4].

## PART 3 | The confused deputy in AWS AppSync

- Datadog (21 November 2022): AppSync could be steered into assuming IAM roles in other AWS accounts, bypassing the cross-account validation.
- Datadog frames it as a confused deputy; AWS calls it a case-sensitivity parsing issue that bypassed cross-account role usage validations.
- Datadog notes the cross-account role use appears in CloudTrail as activity of the service itself, which makes it hard to spot.
Caption: AWS's bulletin states no customers were affected and the only activity was between the researcher's own accounts; AWS fixed it in about five days.
Notes: Mechanism, dates and the detection point from Datadog [5]; AWS's own wording and the no-impact statement from the AWS bulletin [6]. The log signal is Datadog's, not AWS's.

## PART 4 | GhostToken, Google Cloud Platform

- Astrix Security (published 20 April 2023): deleting the GCP project behind an authorized OAuth app put it into a pending-deletion state for 30 days.
- In that state the app dropped off the account's apps-with-access page and could not be removed; the tokens were unusable until the project was restored.
- Restoring the project re-enabled the old refresh token, which gave an access token; the attacker could repeat the hide-and-reveal loop.
Caption: Reported 19 June 2022; accepted 18 August; patched 7 April 2023. The finder's page redirects to Cisco, its acquirer; this study reads the archive.
Notes: Mechanism, dates and Google's handling from the finder's archived write-up [10]; scope and zero-day from [7][8]; the acquisition from Cisco [12].

## NO CVE, STILL SERIOUS | What that means, then and now

- None of the four has a CVE. When they were handled, 2021 to 2023, the providers did not assign CVEs to server-side fixes of their multi-tenant services.
- Wiz says so for ExtraReplica: the issue received no CVE identifier, unlike a software vulnerability.
- That practice changed: Microsoft issues cloud-service CVEs since June 2024, Google Cloud since November 2024, not applied back to these four.
Caption: No CVE does not mean no severity: three carried cross-tenant data-access impact and one gave hidden, revivable account access.
Notes: The no-CVE statement is Wiz's [3]; the policy change is Microsoft's and Google's own [13][14]. Searched the CVE Program, GitHub Advisory Database and Wiz open-cvdb [17].

## HOW EACH PROVIDER ANSWERED | Statements in their own words

| Provider | What they said and did | On impact |
|---|---|---|
| Microsoft (Cosmos DB) | Turned the feature off; notified customers to rotate keys | No customer data accessed by third parties or researchers |
| Microsoft (PostgreSQL) | Mitigated within 48 hours; private access not exposed | No customer data accessed |
| Amazon Web Services | Fixed in about five days; reviewed logs to launch | No customers affected; only the researcher's accounts |
| Google (GhostToken) | Global patch made hidden apps visible again | No statement on Google's own channel; on record via the finder |
Caption: Three providers published their own account; for GhostToken the record is the finder's archived write-up, since no Google statement was found.
Notes: Microsoft [2][4]; AWS [6]; Google's fix and handling from the finder's archived write-up [10].

## DEFENDER VIEW | Find and fix, read-only first

Left: What to read
- Which managed services you use, what each holds, and what each can do on your behalf (data, keys, cross-account roles, OAuth grants).
- Which database instances use public versus private networking.
- Which third-party applications hold OAuth grants, and their scopes.
Right: What to do
- Rotate long-lived credentials on a schedule and after any provider notice; a key copied before a fix still works.
- Prefer private networking and least-privilege, scoped cross-account trust.
- Review OAuth grants; after a hiding flaw, check for apps that may have abused it beforehand.
Caption: Separate the provider-side exposure a customer cannot see from the later use of a stolen key, which logging and Azure Defender can surface.
Notes: Per-service steps from [1][3][4][5][10]; the admin check after GhostToken from Dark Reading [11]; the ChaosDB logging advice from Microsoft [2].

## MITRE MAPPINGS | Cloud and identity techniques

| Id | Technique | Tie to the record |
|---|---|---|
| T1552.005 | Cloud Instance Metadata API | ChaosDB reached the host metadata service on the way to other tenants' keys |
| T1588.004 | Digital Certificates | ExtraReplica used a certificate for an attacker-owned domain |
| T1199 / T1078.004 / T1059.009 | Trusted Relationship, Cloud Accounts, Cloud API | AppSync: trusted service assumes a cross-account role and acts via the API |
| T1528 / T1550.001 / T1671 | Steal / use Application Access Token, Cloud Application Integration | GhostToken: an OAuth app holds and revives a token, and persists as an integration |
Caption: These map to cloud and identity platforms within ATT&CK's Enterprise matrix. T1530 and T1564 from an earlier draft were dropped as weak fits.
Notes: Names, tactics and platforms from the library's ATT&CK v20.0 reference [9]; ties from [3][5][10] and Wiz's walkthrough [16]. Each row states its analytical boundary in the study.

## CROSS-CUTTING THEMES | The customer's half of a shared model

- **One place, not one bug.** Four services, three firms, about two years; what ties them is the part of the service the customer cannot patch.
- **Outside firms found all four; each provider fixed its own.** Two providers stated no data was accessed, one that no customers were affected; no Google statement was found on its own channel.
- **The customer's half is hygiene.** Inventory, credential rotation, private networking and grant review decide how much is lost before the provider's fix lands.
Notes: Shared-place reading and the hygiene conclusion are the study's (Inferred). Provider statements [2][4][6]; GhostToken from the finder's archived write-up [10].
