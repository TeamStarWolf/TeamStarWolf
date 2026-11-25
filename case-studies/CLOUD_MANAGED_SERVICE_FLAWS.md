# When You Cannot Patch the Cloud: Cross-Tenant and Token Flaws in Azure Cosmos DB, Azure PostgreSQL, AWS AppSync and Google Cloud Platform

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Cloud platform and security engineers, identity and IAM owners, incident responders, and anyone running managed cloud databases, APIs or OAuth-connected apps

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,699 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run managed cloud services (a cloud database, a GraphQL or API service, OAuth-connected applications) on Azure, AWS or Google Cloud, or you need the facts behind four provider-side cross-tenant and token flaws

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 5: Find and fix](#part-5-find-and-fix), [Part 6: Weakness and technique mapping](#part-6-weakness-and-technique-mapping)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

A managed cloud service is a service the customer runs but does not operate. The provider holds the code, the fabric and the isolation between one tenant and the next, and the customer holds data, keys and configuration on top. When the flaw is in the part the provider holds, the customer cannot patch it. The provider fixes it on its own side, usually silently, and the customer learns of it from a notice, a blog post, or not at all.

This study reads the public record of four such flaws across four named services, each found by a security firm and each fixed by the provider with no customer patch: the ChaosDB flaw in Azure Cosmos DB, found by Wiz (2021); the ExtraReplica flaw in Azure Database for PostgreSQL Flexible Server, found by Wiz (2022); a cross-account confused-deputy flaw in AWS AppSync, found by Datadog (2022); and the GhostToken flaw in Google Cloud Platform, found by Astrix Security (reported 2022, fixed and published 2023). Three of the four crossed a boundary the provider's design was meant to hold: one tenant could reach another tenant's data in Cosmos DB and in PostgreSQL, and one account could get AppSync to act across into other accounts. The fourth let an authorized application keep access to a Google account while hiding itself from the account's own list of connected apps.

None of the four carries a CVE. The providers assign CVE identifiers to software they ship, not to server-side fixes of their multi-tenant services, and Wiz states plainly that the PostgreSQL flaw received no CVE identifier (Confirmed [3]). So none of these has a CVSS score from an assigning authority; the severity is the finder's characterization and the vendor's statement, not an assigned number (Inferred for the absence, from the pages below).

The vendors answered in their own words, and this study keeps each separate. Microsoft published its own update for both Azure flaws, stating in each that no customer data was accessed (Confirmed [2][4]). Amazon Web Services published a security bulletin stating that no customers were affected and that the only activity was between the researcher's own accounts (Confirmed [6]). For GhostToken, no Google statement of Google's own was found, and the finder's original write-up now redirects to the page of the firm's acquirer, so this case rests on two contemporaneous news reports and is graded accordingly (Reported [7][8]).

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| Services named | Azure Cosmos DB, Azure Database for PostgreSQL Flexible Server, AWS AppSync, Google Cloud Platform | Confirmed, named in the vendor and finder records [1][2][3][4][5][6][7][8] |
| Cases with a CVE | None | Inferred; no source cites a CVE, Wiz states the PostgreSQL flaw got no CVE identifier [3], and providers assign CVEs to shipped software, not server-side service fixes |
| CVSS, and whose | None assigned; severity is the finder's and vendor's characterization | Inferred from [1][3][5][7][8] |
| Shared mechanism | A flaw in the provider's own managed service crossed a tenant or account boundary, or let an authorized token persist while hidden | Reported across [1][3][5][7][8] |
| Who fixed it | The provider, on its own side, with no customer patch | Confirmed [2][4][6]; Reported [7][8] |
| Vendor statement on impact | Microsoft: no customer data accessed (both Azure cases); AWS: no customers affected; Google: no public statement found | Confirmed [2][4][6]; Inferred for Google's silence [7][8] |
| Public exploitation detail | None of the sources reports in-the-wild exploitation against a named victim | Inferred from [1][2][3][4][5][6][7][8] |

### Key findings

- **You cannot patch these.** The flaw and the fix both live in the provider's service. The customer's work is inventory, detection, credential rotation and configuration, not applying a version (Inferred from [2][4][6]).
- **Tenant isolation is a promise the provider keeps, until it does not.** Three of the four crossed a boundary the design was meant to hold: Cosmos DB notebooks between tenants, PostgreSQL instances between customers, and AppSync role assumption across accounts (Reported [1][3][5]).
- **Long-lived credentials outlive the fix.** ChaosDB exposed Cosmos DB primary keys, which keep working until rotated; disabling the feature does not invalidate a key already copied. GhostToken's OAuth token survived the user's attempt to remove the application (Reported [1][7][8]).
- **The record is only as public as the provider makes it.** Microsoft and AWS each published a statement of what they found and did; for GhostToken no Google statement was found, and the finder's own page now redirects to its acquirer, so the public account is thinner (Confirmed [2][4][6]; Inferred for the GhostToken gap [7][8]).
- **No CVE does not mean no severity.** All four lack a CVE, yet three carried cross-tenant data-access impact and one gave persistent, hidden access to an account (Inferred).

### Top recommendations

1. Inventory the managed cloud services you use and, for each, what it holds and what it can do on your behalf: which hold data, which assume roles or identities across accounts, and which applications hold OAuth grants. You cannot defend a service you have not listed.
2. Rotate long-lived credentials on a schedule and after any provider security notice. A database primary key or access key copied before a fix still works; the fix does not rotate it for you.
3. Prefer private networking and least privilege. The ExtraReplica flaw did not reach instances using private network access, and cross-account role trust should be scoped to the minimum and reviewed.
4. Review third-party application and OAuth grants on a schedule, and treat an application vanishing from the connected-apps list as something to verify, not as proof it is gone, which is the lesson of GhostToken.
5. Build detection for the provider-side signals you can still see. For AppSync, AWS noted the cross-account role assumption appears to come from the service itself, so watch for unusual cross-account role use and for spikes in access-denied events attributed to a service identity.

## Scope and evidence standard

This study rests on the nine sources listed below: the two finder write-ups from Wiz (Cosmos DB and PostgreSQL), Microsoft's two own update posts for those flaws, Datadog's write-up and Amazon Web Services' security bulletin for AppSync, two news reports for GhostToken, and the library's ATT&CK data. It names only the four services, their three providers (Microsoft, Amazon Web Services and Google) and the three finders (Wiz, Datadog and Astrix Security). No individual researcher is named. No exploit was run, and no step-by-step is reproduced here even where a finder published one; each mechanism is described in words, at the level the vendor's own statement uses.

**Confirmed** means an official record, here a provider's own statement, supports the claim. **Reported** means a finder's or a third party's write-up stated it without a provider record. **Inferred** marks the author's interpretation, including a statement about what a source does not say. A statement that a source gives no detail is a statement about that source, not about the world.

Two limits on the evidence are worth stating at the top. First, none of these flaws has a CVE record to anchor to, so there is no neutral third-party identifier or score; the facts come from the finder and the provider, and the study grades each to its source. Second, the GhostToken case is thinner than the other three. The finder, Astrix Security, was acquired, and its original write-up now redirects to the acquirer's product page rather than the research, so this study could not open the finder's own account and rests on two contemporaneous news reports from 21 April 2023 (Reported [7][8]). Where those two reports agree, the study says so; where only one carries a fact, the study attributes it.

For each provider, this study used the provider's own channel where one exists. Microsoft published an update for Cosmos DB and an advisory for PostgreSQL, and Amazon Web Services published a bulletin for AppSync; all three are cited as the provider's own words (Confirmed [2][4][6]). For Google and GhostToken, no Google statement of Google's own was found on the pages opened, so the vendor's response is reported only as the two news sources describe it, and the study does not conclude Google said nothing (Inferred for the absence [7][8]).

## Part 1: ChaosDB, Azure Cosmos DB (Wiz)

### The service and the flaw

Azure Cosmos DB is Microsoft's managed, multi-tenant database service. In 2019 Microsoft added a Jupyter Notebook feature to it, and by February 2021 that feature was enabled for Cosmos DB accounts. On 26 August 2021 Wiz reported that a series of flaws in that feature let one customer break out of their own notebook environment and reach other customers' notebooks, and from there retrieve other customers' Cosmos DB primary keys, which Wiz describes as giving full read, write and delete access to those customers' data (Reported [1]). This study describes the effect and reproduces none of the technique.

The primary key is the point that matters for a defender. It is a long-lived credential for a Cosmos DB account. Once it is copied, disabling the feature that exposed it does not make it stop working; only rotating the key does. That is why the response to this flaw was not only a provider fix but a key-rotation notice to customers (Reported [1]; Confirmed [2]).

### The three dates

Microsoft's own update sets the timeline. The feature was in scope for the vulnerability over a window Microsoft gives as 7 to 13 August 2021; the researcher reported the issue to Microsoft on 12 August 2021; and Microsoft says it mitigated the vulnerability immediately by turning off the preview feature for all customers (Confirmed [2]). Wiz published its write-up on 26 August 2021, and Microsoft published its update the next day, 27 August 2021 (Reported [1]; Confirmed [2]). So the private report, the fix and the public write-up are three separate dates in the same month: 12 August, the days around 13 August, and 26 to 27 August 2021.

### What Microsoft said

Microsoft's update, dated 27 August 2021, states that it mitigated the vulnerability immediately by turning off the feature in scope for all customers, and that the feature stayed off pending a redesign (Confirmed [2]). On access, Microsoft's post is specific: it states that no customer data was accessed because of this vulnerability by third parties, and that its investigation shows no unauthorized access other than the researcher's activity (Confirmed [2]). Microsoft also says it notified the customers whose keys may have been affected so they could regenerate the primary read-write key, and it credits Wiz for the report (Confirmed [2]). Wiz's own account adds that Microsoft notified a large share of Cosmos DB customers to rotate keys, and that Microsoft emailed the customers affected during the research window (Reported [1]). The two accounts agree on the shape: a provider fix, plus a key-rotation notice, with Microsoft stating no third-party access.

## Part 2: ExtraReplica, Azure Database for PostgreSQL Flexible Server (Wiz)

### The service and the flaw

Azure Database for PostgreSQL Flexible Server is Microsoft's managed PostgreSQL offering. On 28 April 2022 Wiz reported a flaw it named ExtraReplica: a chain of two weaknesses that together let one customer reach another customer's PostgreSQL database, bypassing the isolation between tenants (Reported [3]). Wiz describes the chain as a privilege escalation in Azure's modified PostgreSQL engine, followed by an over-permissive certificate name check that let a certificate issued for an attacker-owned domain authenticate to other customers' instances, giving unauthorized read access across the tenant boundary (Reported [3]). Microsoft's own advisory titles the issue a privilege escalation and remote code execution, which is the provider's framing of the same chain (Confirmed [4]). This study reproduces none of the technique.

The flaw did not reach every instance. Wiz states, and Microsoft confirms, that instances using private network access were not exposed, and that the single-server offering was not affected; the exposure was to Flexible Server instances using public access networking (Reported [3]; Confirmed [4]). That boundary is the defender's lever: private networking is both a hardening step and, here, the thing that kept an instance out of scope.

### The three dates

Wiz reported the vulnerabilities to the Microsoft Security Response Center on 11 January 2022, under case 69557 (Reported [3]). Microsoft's advisory states it mitigated the certificate issue within 48 hours, on 13 January 2022, and that it finished updating the entire fleet of existing servers by 25 February 2022 (Confirmed [4]). Wiz published on 28 April 2022, the date of Microsoft's own advisory (Reported [3]; Confirmed [4]). So the report, the first fix, the fleet-wide completion and the public write-up are four points: 11 January, 13 January, 25 February and 28 April 2022.

### What Microsoft said

Microsoft's advisory, dated 28 April 2022, states that the issue was mitigated within 48 hours and that no action is required by customers, and it recommends that customers enable private network access to further reduce exposure (Confirmed [4]). On access, the advisory states that its analysis revealed no customer data was accessed using this vulnerability (Confirmed [4]). It credits Wiz with finding the issue and working with Microsoft to validate the fixes (Confirmed [4]). Wiz's account aligns: it quotes Microsoft confirming the issue was fully mitigated with no customer action required, and adds that Microsoft said it was not aware of any attempts to exploit the vulnerability (Reported [3]). Wiz also notes directly that the issue did not receive a CVE identifier, unlike a software vulnerability, which is the clearest statement in these four cases of why a serious cloud flaw can carry no CVE (Confirmed [3] for the no-CVE statement).

## Part 3: The confused deputy in AWS AppSync (Datadog)

### The service and the flaw

AWS AppSync is Amazon Web Services' managed service for GraphQL APIs. To do its work it can assume AWS Identity and Access Management roles that a customer has set up to trust the AppSync service. On 21 November 2022 Datadog reported a cross-account flaw in that mechanism: AppSync could be steered into assuming roles in other AWS accounts, bypassing the validation that was supposed to keep the service's role use inside the caller's own account (Reported [5]). Datadog frames this as a confused deputy, the classic pattern where a trusted intermediary is tricked into using its privilege on an attacker's behalf. Amazon Web Services, in its own words, calls it a case-sensitivity parsing issue that could be used to bypass the service's cross-account role usage validations (Confirmed [6]). Both descriptions point at the same thing: a check on the role identifier could be evaded, so a role in another account was accepted. This study reproduces none of the technique.

Datadog's write-up adds a detection point worth carrying forward: the cross-account role assumptions appeared in CloudTrail as actions taken by the AppSync service itself rather than by a user, which makes them hard to spot, and it suggests watching for spikes in access-denied events attributed to the service and for roles making calls they normally do not (Reported [5]).

### The three dates

Datadog's timeline is explicit. It identified the flaw and reported it to Amazon Web Services on 1 September 2022; AWS reproduced it on 2 September; AWS pushed a fix to the AppSync service on 6 September 2022, about five days after the report; and the two coordinated public disclosure on 21 November 2022 (Reported [5]). AWS's bulletin carries the same 21 November 2022 publication date (Confirmed [6]). So the report, the provider fix and the public disclosure are three separate dates: 1 September, 6 September and 21 November 2022.

### What Amazon Web Services said

AWS published a security bulletin, AWS-2022-009, titled for the reported AppSync issue and dated 21 November 2022 (Confirmed [6]). It states that it moved immediately to correct the issue when it was reported (Confirmed [6]). On impact, the bulletin is specific: it states that no customers were affected by the issue and no customer action is required, that the only activity associated with the issue was between accounts owned by the researcher, and that no other customer accounts were impacted; AWS says it reviewed logs going back to the launch of the service (Confirmed [6]). It thanks Datadog Security Labs for the report (Confirmed [6]). Datadog's own account agrees that AWS remediated the issue and reports AWS confirming it had not been used against other customers, and Datadog adds that it queried its own log sources and confirmed none of its customers were affected (Reported [5]).

## Part 4: GhostToken, Google Cloud Platform (Astrix Security)

### The service and the flaw

A third-party application that a user authorizes against a Google account is backed, on the provider side, by an OAuth client that lives in a Google Cloud Platform project. On 21 April 2023 the flaw named GhostToken, found by Astrix Security, was reported in that link between the application and its underlying project. By deleting the GCP project behind an authorized application, an attacker could put the application into a pending-deletion state in which it dropped off the user's list of applications with access to the account, while the application's token kept working; restoring the project revived the application and its access, and the step could be repeated, so the malicious application could be made to appear and disappear from the account's own management page (Reported [7][8]). One report states the pending-deletion state lasts 30 days (Reported [7]). The result the two reports describe is a connected application that keeps access to the account while hiding from the one page a user would check to remove it. This study reproduces none of the technique.

The scope, as reported, is broad: the flaw is described as affecting all Google accounts, including enterprise Workspace accounts, because it sits in the GCP application and OAuth mechanism that Google accounts share, not in one product's data path (Reported [8]).

### The three dates

The two reports give the timeline in running text rather than a formal table. Astrix found the flaw and reported it to Google on 19 June 2022; Google deployed a global patch more than nine months later, on 7 April 2023; and the public write-up and the two news reports followed on 21 April 2023 (Reported [7][8]). So the report, the fix and the publication are 19 June 2022, 7 April 2023 and 21 April 2023: a long gap between report and fix, longer than in the other three cases.

### What Google did, and the gap in the record

Both reports describe Google's fix the same way: the April 2023 patch makes applications in the pending-deletion state visible again on the account's third-party-access page, so a user can see and remove them (Reported [7][8]). Neither report quotes a statement from Google, and neither points to a Google security bulletin; this study found no Google statement of Google's own on the pages it opened, so it reports the fix only as the two news sources describe it and does not state what Google itself said (Inferred for the absence [7][8]). There is a further gap: the finder's own write-up, which would be the primary account, now redirects to the page of the firm's acquirer rather than the research, so this case alone among the four rests on secondary reporting (Reported [7][8]). No CVE is cited; one report calls the flaw a zero-day, which is a characterization, not an identifier (Reported [8]).

## Part 5: Find and fix

### Decide what you run and what it can reach

For each managed cloud service in use, write down two things: what it holds, and what it can do on your behalf. For Azure Cosmos DB, that is data and the primary keys that reach it; record which accounts exist and when their keys were last rotated. For Azure Database for PostgreSQL, record which instances use public access and which use private networking, since the ExtraReplica exposure was to public-access instances. For AWS AppSync, record which IAM roles trust the service and what those roles can reach, since the flaw turned that trust across account boundaries. For Google Cloud Platform and Google accounts, record which third-party applications hold OAuth grants and what scopes they hold (Inferred from [1][3][5][7][8]).

### Rotate credentials and narrow trust

Where a flaw exposed a long-lived credential, the provider fix is not the end of the work. For Cosmos DB, rotate the primary key, because a key copied during the exposure window keeps working after the feature is disabled; Microsoft's notice to affected customers was a rotation notice for that reason (Confirmed [2]). For PostgreSQL, prefer private network access, which kept instances out of scope for ExtraReplica (Confirmed [4]). For AppSync and cross-account roles, scope the trust to the minimum and review which roles a service may assume. For OAuth applications, review grants on a schedule and revoke ones you do not recognize (Inferred from [1][3][4][5]).

### Watch for the signals the provider leaves you

These fixes are the provider's, but some of the attacker's activity is visible to the customer. For AppSync, AWS's and Datadog's accounts both note that the cross-account role assumption appears as activity of the service itself, so the useful detections are unusual cross-account role use and spikes in access-denied events attributed to a service identity (Reported [5]; Confirmed [6]). For OAuth applications, GhostToken's lesson is that the connected-apps list can be made to lie, so a periodic export and comparison of granted applications is worth more than a single glance at the page (Reported [7][8]). For the database flaws, the honest statement is that the cross-tenant access happened inside the provider's fabric, where the customer had little to see; the control there is rotation and private networking, not detection (Inferred).

## Part 6: Weakness and technique mapping

The mapping below is this study's reading of the ATT&CK definitions, checked on 25 November 2026 against each case's public record, using the library's ATT&CK v20.0 data for the technique names and tactics [9]. None of these flaws carries a CWE, because none carries a CVE; the weakness labels that a CVE record would supply are absent here, which is itself part of the record. The techniques describe what an attacker does with a flaw, not the provider-side bug itself, so each row is an analytical mapping with its boundary stated.

| Technique | Case support | Boundary |
|---|---|---|
| [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/) | ExtraReplica and AppSync, where the provider's own trusted service or shared fabric is the path across a tenant or account boundary | The closest technique to a confused-deputy or cross-tenant flaw; analytical [3][5][9] |
| [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | Operating as or into another tenant or account: the Cosmos DB keys, the PostgreSQL cross-tenant authentication, the AppSync assumed role | Analytical; the techniques model the use of the access, not the isolation flaw [1][3][5][9] |
| [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) | ChaosDB, where other customers' Cosmos DB primary keys were retrievable across the tenant boundary | Analytical; the keys are credentials reached through the flaw [1][9] |
| [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) | ChaosDB and ExtraReplica, where the end effect is reading another customer's data | Analytical; the collection step the cross-tenant access enables [1][3][9] |
| [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) | GhostToken, where the attacker's application holds an OAuth token against the victim's account | Analytical; the token is obtained through consent and kept, not stolen from a store [7][8][9] |
| [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/) | GhostToken, where the OAuth token is used for continued access to the account | Analytical; the use of the token for access [7][8][9] |
| [T1564 Hide Artifacts](https://attack.mitre.org/techniques/T1564/) | GhostToken, where the malicious application is made invisible on the account's connected-apps page | Analytical; a broad technique, and GhostToken's pending-deletion trick is one instance of it [7][8][9] |

These cases sit on ATT&CK's cloud and identity platforms rather than the enterprise endpoint matrix; the mapping reflects that. The library's ATT&CK data supplies the names and tactics [9].

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read four flaws across three providers as one broken cloud. They are four separate services, found by three firms over about two years, fixed by each provider on its own side; what ties them is not a shared bug but a shared place, the part of the service the customer cannot patch (Inferred). The easy understatement is to treat a provider's statement that no customer data was accessed as the end of the matter. Microsoft and AWS each investigated and said so, and those statements are the best evidence available (Confirmed [2][4][6]); but for ChaosDB the control that still mattered to a customer was rotating a key the provider could not rotate for them, and for GhostToken no such statement was found at all (Reported [1][7][8]).

### The customer's half of a shared responsibility

The shared-responsibility model says the provider secures the cloud and the customer secures what they put in it. These four cases show where that line actually runs under stress. The flaw and the fix were the provider's in every case, and the provider carried them. The customer's half was never patching; it was knowing which services held data or trust, rotating the credentials a flaw could expose, preferring private networking and least privilege, and reviewing the grants and connections a provider's own list might not show honestly. A fixed flaw, like these four, closes one path; the standing work is the inventory and the credential hygiene that decide how much a customer loses in the window before a provider's fix arrives (Inferred).

## Sources

1. Wiz, ChaosDB: How we hacked thousands of Azure customers' databases, 26 August 2021, for the Cosmos DB Jupyter Notebook flaw, the cross-tenant access, the primary keys and the key-rotation notice. https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases
2. Microsoft Security Response Center, Update on the vulnerability in the Azure Cosmos DB Jupyter Notebook Feature, 27 August 2021, for Microsoft's own statement that it mitigated the issue immediately, that no customer data was accessed by third parties, and that affected customers were notified to regenerate the primary read-write key. https://www.microsoft.com/en-us/msrc/blog/2021/08/update-on-vulnerability-in-the-azure-cosmos-db-jupyter-notebook-feature
3. Wiz, Wiz Research discovers ExtraReplica, a cross-account database vulnerability in Azure PostgreSQL, 28 April 2022, for the two-flaw chain, the cross-tenant read access, the scope limits, and the statement that the issue received no CVE identifier. https://www.wiz.io/blog/wiz-research-discovers-extrareplica-cross-account-database-vulnerability-in-azure-postgresql
4. Microsoft Security Response Center, Azure Database for PostgreSQL Flexible Server Privilege Escalation and Remote Code Execution, 28 April 2022, for Microsoft's own statement that it mitigated the issue within 48 hours, that no action is required by customers, that private network access was not exposed, and that no customer data was accessed. https://www.microsoft.com/en-us/msrc/blog/2022/04/azure-database-for-postgresql-flexible-server-privilege-escalation-and-remote-code-execution
5. Datadog Security Labs, A confused deputy vulnerability in AWS AppSync, 21 November 2022, for the cross-account confused-deputy mechanism, the disclosure timeline, and the CloudTrail detection notes. https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/
6. Amazon Web Services, Security Bulletin AWS-2022-009, Reported AWS AppSync Issue, 21 November 2022, for AWS's own description of the case-sensitivity parsing issue, its statement that no customers were affected and that the only activity was between the researcher's accounts, and the credit to Datadog. https://aws.amazon.com/security/security-bulletins/AWS-2022-009/
7. SecurityWeek, Google Cloud Platform Vulnerability Led to Stealthy Account Backdoors, 21 April 2023, for the GhostToken mechanism, the 30-day pending-deletion state, and Google's fix making the applications visible again. https://www.securityweek.com/google-cloud-platform-vulnerability-led-to-stealthy-account-backdoors/
8. The Hacker News, GhostToken flaw could let attackers hide malicious apps in Google Cloud Platform, 21 April 2023, for the disclosure dates, the all-Google-accounts scope, and Google's 7 April 2023 global patch. https://thehackernews.com/2023/04/ghosttoken-flaw-could-let-attackers.html
9. TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings. https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack

## Related references

- [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md) and [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) for the wider record of attacks on cloud services and the controls that answer them.
- [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) for roles, trust and OAuth grants, which three of these four cases turn on.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating a managed service's public endpoint as attack surface.
