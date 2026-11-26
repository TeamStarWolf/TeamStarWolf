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

About 28 min (6,455 words at 230 words a minute)

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

This study reads the public record of four such flaws across four named services, each found by a security firm and each fixed by the provider with no customer patch: the ChaosDB flaw in Azure Cosmos DB, found by Wiz (2021); the ExtraReplica flaw in Azure Database for PostgreSQL Flexible Server, found by Wiz (2022); a cross-account confused-deputy flaw in AWS AppSync, found by Datadog (2022); and the GhostToken flaw in Google Cloud Platform, found by Astrix Security (reported 2022, fixed and published 2023). Three of the four crossed a boundary the provider's design was meant to hold: one tenant could reach another tenant's data in Cosmos DB and in PostgreSQL, and one account could get AppSync to act across into other accounts. The fourth let an authorized application be hidden from a Google account's own list of connected apps while its access could be revived at will.

None of the four carries a CVE. When these four were handled, between 2021 and 2023, the major cloud providers did not assign CVE identifiers to server-side fixes of their multi-tenant services, and Wiz states for the PostgreSQL flaw that it received no CVE identifier, unlike a software vulnerability (Reported [3]). That practice has since changed: Microsoft began issuing CVEs for critical cloud-service flaws in June 2024, and Google Cloud in November 2024, even where customers need no action (Confirmed [13][14]), and Microsoft has since assigned CVEs to Azure Database for PostgreSQL Flexible Server itself, for unrelated extension flaws (Confirmed [18]). Neither policy was applied back to these four: no CVE has been assigned to any of them as of 25 November 2026 (Inferred, from the CVE and open-cvdb search in the Scope section). So none of the four has a CVE, and none has a CVSS score from an assigning authority; the severity is the finder's and the provider's characterization and, in Wiz's open database, a non-CVSS rating, not a number from an assigning authority (Inferred for the absence; the pages searched are in the Scope section).

The vendors answered in their own words, and this study keeps each separate. Microsoft published a blog post of its own for both Azure flaws, stating in each that no customer data was accessed (Confirmed [2][4]). Amazon Web Services published a security bulletin stating that no customers were affected and that the only activity was between the researcher's own accounts (Confirmed [6]). For GhostToken, no statement from Google on Google's own channel was found; the finder's own write-up, which records Google's handling and the fix, is read here from the Internet Archive, since the live page now redirects to the product site of Cisco, which acquired Astrix Security (Reported [10]; Confirmed for the acquisition [12]).

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| Services named | Azure Cosmos DB, Azure Database for PostgreSQL Flexible Server, AWS AppSync, Google Cloud Platform | Confirmed, named in the vendor and finder records [1][2][3][4][5][6][7][8][10] |
| Cases with a CVE | None | Inferred; no source cites a CVE and Wiz states the PostgreSQL flaw received none [3]. Searched: cve.org and the NVD keyword API, the GitHub Advisory Database, and Wiz's open cloud-vulnerability database [17] |
| CVE policy, then and now | None of the four was assigned a CVE under the practice of 2021 to 2023; Microsoft (June 2024) and Google Cloud (November 2024) now issue CVEs for critical cloud-service flaws (Microsoft has assigned some to the PostgreSQL service for unrelated flaws), and none was applied back to these four | Confirmed for the policy [13][14] and the later CVEs [18]; Inferred that none was applied back |
| CVSS, and whose | None assigned (no CVE); beyond the finder's and vendor's characterizations, Wiz's open database rates them critical (ChaosDB, ExtraReplica), high (AppSync) and medium (GhostToken), which are the database's ratings, not a CNA's | Inferred; open-cvdb ratings [17] |
| Shared mechanism | A flaw in the provider's own managed service crossed a tenant or account boundary, or let an authorized OAuth app be hidden and revived | Reported across [1][3][5][7][8][10] |
| Who fixed it | The provider, on its own side, with no customer patch | Confirmed [2][4][6]; Reported [10] |
| Vendor statement on impact | Microsoft: no customer data accessed (both Azure cases); AWS: no customers affected; Google: no statement on Google's own channel found, its handling on record only through the finder | Confirmed [2][4][6]; Reported [10]; Inferred for Google's channel [7][8] |
| Public exploitation detail | None of the sources reports in-the-wild exploitation against a named victim | Inferred from [1][2][3][4][5][6][7][8][10][11] |

### Key findings

- **You cannot patch these.** The flaw and the fix both live in the provider's service. The customer's work is inventory, detection, credential rotation and configuration, not applying a version (Inferred from [2][4][6]).
- **Tenant isolation is a promise the provider keeps, until it does not.** Three of the four crossed a boundary the design was meant to hold: Cosmos DB notebooks between tenants, PostgreSQL instances between customers, and AppSync role assumption across accounts (Reported [1][3][5]).
- **Long-lived credentials and standing grants outlive the fix.** ChaosDB exposed Cosmos DB primary keys, which keep working until rotated; Wiz observed that some of the credentials it had obtained were revoked, and still urged every customer to rotate (Reported [16][19]). GhostToken's refresh token was unusable while the attacker's project sat in pending deletion and was re-enabled when the project was restored, so the standing grant survived the user's inability to see or remove it (Reported [10]).
- **The record is only as public as the provider makes it.** Microsoft and AWS each published a statement of what they found and did (Confirmed [2][4][6]). Google published nothing about GhostToken on its own channel that this study found, as of 25 November 2026; its handling is on record only through the finder's write-up, which this study reads from the archive (Reported [10]; Inferred for the absence on Google's channel).
- **No CVE does not mean no severity.** All four lack a CVE, yet three carried cross-tenant data-access impact and one gave hidden, revivable access to an account (Inferred).

### Top recommendations

1. Inventory the managed cloud services you use and, for each, what it holds and what it can do on your behalf: which hold data, which assume roles or identities across accounts, and which applications hold OAuth grants. You cannot defend a service you have not listed.
2. Rotate long-lived credentials on a schedule and after any provider security notice. A database primary key or access key copied before a fix still works; the fix does not rotate it for you. Where a provider says it notified only some customers, as Microsoft did for ChaosDB, the finder urged every customer to rotate, not only those notified, citing CISA's guidance to regenerate keys for all Cosmos DB accounts (Reported [19]).
3. Prefer private networking and least privilege. The ExtraReplica flaw did not reach instances using private network access, and cross-account role trust should be scoped to the minimum and reviewed.
4. Review third-party application and OAuth grants on a schedule, and treat an application vanishing from the connected-apps list as something to verify, not as proof it is gone, which is the lesson of GhostToken. After a provider fixes a hiding flaw, check for apps that may have abused it beforehand (Reported [11]).
5. Build detection for the provider-side signals you can still see. For AppSync, Datadog noted the cross-account role assumption appears in CloudTrail as activity of the service itself, so watch for unusual cross-account role use and for spikes in access-denied events attributed to a service identity (Reported [5]).

## Scope and evidence standard

This study rests on the nineteen sources listed below: the two finder write-ups from Wiz (Cosmos DB and PostgreSQL), Wiz's technical walkthrough, its ChaosDB mitigation post and its open cloud-vulnerability database; Microsoft's two own blog posts for those flaws, its cloud-CVE policy post, its Cosmos DB notebooks retirement notice and the two CVE records it later assigned to the PostgreSQL service; Datadog's write-up and Amazon Web Services' security bulletin for AppSync; the finder's own GhostToken write-up read from the Internet Archive, two news reports and Dark Reading for GhostToken, Google Cloud's CVE-policy post, Cisco's acquisition announcement; and the library's ATT&CK data. It names only the four services, their three providers (Microsoft, Amazon Web Services and Google), the three finders (Wiz, Datadog and Astrix Security), the two news publications and Dark Reading as sources, Cisco as the firm that acquired Astrix Security, and CISA as the issuer of the key-rotation guidance Wiz cites. No individual researcher is named. No exploit was run, and no step-by-step is reproduced here even where a finder published one; each mechanism is described in words, at the level the vendor's own statement uses.

**Confirmed** means an official record, here a provider's own statement, supports the claim. **Reported** means a finder's or a third party's write-up stated it without a provider record. **Inferred** marks the author's interpretation, including a statement about what a source does not say. A statement that a source gives no detail is a statement about that source, not about the world.

Two limits on the evidence are worth stating at the top. First, none of these flaws has a CVE record to anchor to, so there is no neutral third-party identifier or score. The absence was checked against cve.org and the NVD keyword API, the GitHub Advisory Database and Wiz's open cloud-vulnerability database (open-cvdb), which lists all four with no CVE [17]; the finders and providers cite none. As the Executive summary notes, the providers' practice of not assigning CVEs to cloud-service fixes, which held when these four were handled, changed in 2024 (Confirmed [13][14]); it was not applied back to these four, which carry no CVE as of 25 November 2026 (Inferred). Second, Google published nothing about GhostToken on its own channel that this study could find (the Google Cloud security bulletins for 2023, the two news reports, and Google's project documentation), so Google's handling is reported only as the finder's own write-up records it (Reported [10]; Inferred for Google's channel). That write-up is reachable: the live Astrix page now redirects to Cisco, which acquired Astrix Security (announced 4 May 2026, completed by 29 June 2026) [12], so this study reads the finder's account from an Internet Archive capture and cites it as archived [10].

For each provider, this study used the provider's own channel where one exists. Microsoft published a blog post for Cosmos DB and a blog post for PostgreSQL (both are MSRC blog posts, not Security Update Guide advisories), and Amazon Web Services published a bulletin for AppSync; all three are cited as the provider's own words (Confirmed [2][4][6]). For AppSync, no later statement, fix, guidance change or CVE was found on AWS's own channel as of 25 November 2026 (the bulletin and its RSS feed; the bulletins index renders by script and could not be read) (Inferred absence [6]). For Google and GhostToken, no Google statement of Google's own was found on the pages opened, so the vendor's response is reported only as the finder's write-up and the two news sources describe it, and the study does not conclude Google said nothing (Reported [10]; Inferred for the absence [7][8]).

## Part 1: ChaosDB, Azure Cosmos DB (Wiz)

### The service and the flaw

Azure Cosmos DB is Microsoft's managed, multi-tenant database service. In 2019 Microsoft added a Jupyter Notebook feature to it, and by February 2021 that feature was being enabled automatically for Cosmos DB accounts. On 26 August 2021 Wiz reported that a series of flaws in that feature let one customer break out of their own notebook environment and reach other customers' notebooks, and from there retrieve other customers' Cosmos DB primary keys, which Wiz describes as long-lived credentials that give full read, write and delete access to those customers' data (Reported [1]). This study describes the effect and reproduces none of the technique.

The primary key is the point that matters for a defender. It is a long-lived credential for a Cosmos DB account. Once it is copied, disabling the feature that exposed it does not make it stop working; only rotating the key does. That is why the response to this flaw was not only a provider fix but a key-rotation notice to customers, and why Wiz's own observation that some of the credentials it had obtained were revoked does not remove the need to rotate (Reported [16]).

### The three dates

Microsoft's own blog post sets the report and statement dates; the finder's record sets the fix date. The researcher reported the issue to Microsoft on 12 August 2021 (Confirmed [2]). Microsoft says it mitigated the issue by turning off the preview feature for all customers, but gives no date beyond "immediately"; Wiz's timeline records that it observed the feature disabled on 14 August 2021, two days after the report (Confirmed for the action [2]; Reported for the date [16]). Microsoft states that the customers who could have been affected were those active in, or who created an account during, a researcher-activity period of 7 to 13 August 2021, which it used to decide whom to notify; this is not a statement of how long the feature was exposed, and Wiz holds that the flaw had been reachable far longer (Confirmed for Microsoft's wording [2]; Reported [1]). Wiz published its write-up on 26 August 2021, and Microsoft published its blog post the next day, 27 August 2021 (Reported [1]; Confirmed [2]).

### What Microsoft said, and the end state

Microsoft's blog post, dated 27 August 2021, states that it mitigated the vulnerability by turning off the feature for all customers (Confirmed [2]). On access, the post is specific: it states that no customer data was accessed because of this vulnerability by third parties or security researchers, and that its investigation shows no unauthorized access other than the researcher's activity (Confirmed [2]). It says notifications were sent to all customers who could have been affected due to researcher activity, advising them to regenerate their primary read-write key, and it credits Wiz (Confirmed [2]). Wiz adds a figure Microsoft does not give: Microsoft notified over 30 percent of Cosmos DB customers to rotate keys (Reported [1]), and in a companion mitigation post Wiz urged every customer to rotate, not only those notified, citing CISA's guidance to regenerate keys for all Cosmos DB accounts (Reported [19]).

The description "stayed off pending a redesign" belongs to Wiz, not Microsoft; Wiz wrote that the feature was still turned off for all customers pending a security redesign (Reported [1]). Microsoft's own end state came later and on its own channel: it retired the built-in Jupyter notebooks in Cosmos DB, the feature behind ChaosDB, effective 30 March 2024, in a retirement notice created on 6 October 2023 (Confirmed [15]).

## Part 2: ExtraReplica, Azure Database for PostgreSQL Flexible Server (Wiz)

### The service and the flaw

Azure Database for PostgreSQL Flexible Server is Microsoft's managed PostgreSQL offering. On 28 April 2022 Wiz reported a flaw it named ExtraReplica: a chain of two weaknesses that together let one customer reach another customer's PostgreSQL database, bypassing the isolation between tenants (Reported [3]). Wiz describes the chain as a privilege escalation in Azure's modified PostgreSQL engine, followed by an over-permissive check on a certificate's Common Name that let a certificate issued for an attacker-owned domain authenticate to other customers' instances, giving unauthorized read access across the tenant boundary (Reported [3]). Microsoft's own blog post titles the issue a privilege escalation and remote code execution, which is the provider's framing of the same chain (Confirmed [4]). This study reproduces none of the technique.

The flaw did not reach every instance, and the two offerings differ. Wiz states that the first flaw, the privilege escalation, affected both the Flexible Server and the Single Server offerings, but that the cross-account bypass did not reach Single Server; Microsoft states that the Single Server offering was not impacted by the vulnerability and that customers using the private access networking option were not exposed (Reported [3]; Confirmed [4]). Private networking is the defender's lever here: it is both a hardening step and, in this case, the thing that kept an instance out of scope.

### The dates

Wiz reported the vulnerabilities to the Microsoft Security Response Center on 11 January 2022, under case 69557 (Reported [3]). Microsoft states it mitigated the certificate issue within 48 hours, on 13 January 2022, and that it finished updating the entire fleet of existing servers by 25 February 2022 (Confirmed [4]). Wiz published on 28 April 2022, the date of Microsoft's own blog post and of Wiz's open-cvdb entry [17], though the Wiz page's own byline and metadata read 29 April 2022 (Reported [3][17]; Confirmed [4]). So the report, the first fix, the fleet-wide completion and the public write-up are four points: 11 January, 13 January, 25 February and 28 April 2022.

### What Microsoft said

Microsoft's blog post, dated 28 April 2022, states that it mitigated the issue within 48 hours and that no action is required by customers, and it recommends that customers enable private network access to further reduce exposure (Confirmed [4]). On access, the post states that its analysis revealed no customer data was accessed using this vulnerability (Confirmed [4]). It credits Wiz with finding the issue and working with Microsoft to validate the fixes (Confirmed [4]). Wiz's account aligns: it quotes Microsoft confirming the issue was fully mitigated with no customer action required, and adds that Microsoft said it was not aware of any attempts to exploit the vulnerability (Reported [3]). Wiz also notes directly that the issue did not receive a CVE identifier, unlike a software vulnerability, which is the clearest statement in these four cases of why a serious cloud flaw of this period carried no CVE (Reported [3]).

## Part 3: The confused deputy in AWS AppSync (Datadog)

### The service and the flaw

AWS AppSync is Amazon Web Services' managed service for GraphQL APIs. To do its work it can assume AWS Identity and Access Management roles that a customer has set up to trust the AppSync service. On 21 November 2022 Datadog reported a cross-account flaw in that mechanism: AppSync could be steered into assuming roles in other AWS accounts, bypassing the validation that was supposed to keep the service's role use inside the caller's own account (Reported [5]). Datadog frames this as a confused deputy, the classic pattern where a trusted intermediary is tricked into using its privilege on an attacker's behalf. Amazon Web Services, in its own words, calls it a case-sensitivity parsing issue that could be used to bypass the service's cross-account role usage validations (Confirmed [6]). Both descriptions point at the same thing: a check on the role identifier could be evaded, so a role in another account was accepted. This study reproduces none of the technique.

Datadog's write-up adds a detection point worth carrying forward: it reports that the cross-account role assumptions appear in CloudTrail as actions taken by the AppSync service itself rather than by a user, which makes them hard to spot, and it suggests watching for a large number of access-denied events whose source is the AppSync service and for roles making calls they normally do not (Reported [5]). AWS's bulletin says nothing about logs or detection; this detection point is Datadog's, not AWS's.

### The dates

Datadog's timeline is explicit. It identified the flaw and reported it to Amazon Web Services on 1 September 2022; AWS reproduced it on 2 September; AWS pushed a fix to the AppSync service on 6 September 2022, about five days after the report; and the two coordinated public disclosure on 21 November 2022 (Reported [5]). AWS's bulletin carries the same 21 November 2022 publication date and shows no later update (Confirmed [6]). So the report, the provider fix and the public disclosure are three separate dates: 1 September, 6 September and 21 November 2022.

### What Amazon Web Services said

AWS published a security bulletin titled "Reported AWS AppSync Issue," dated 21 November 2022; the identifier AWS-2022-009 appears in the page's address, not its text (Confirmed [6]). It states that it moved immediately to correct the issue when it was reported (Confirmed [6]). On impact, the bulletin is specific: it states that no customers were affected by the issue and no customer action is required, that the only activity associated with the issue was between accounts owned by the researcher, and that no other customer accounts were impacted; AWS says it reviewed logs going back to the launch of the service (Confirmed [6]). It thanks Datadog Security Labs for the report (Confirmed [6]). Datadog's own account agrees that AWS remediated the issue and reports AWS confirming it had not been used against other customers, and Datadog adds that it queried its own log sources and confirmed none of its customers were affected (Reported [5]).

## Part 4: GhostToken, Google Cloud Platform (Astrix Security)

### The service and the flaw

A third-party application that a user authorizes against a Google account is backed, on the provider side, by an OAuth client that lives in a Google Cloud Platform project. On 20 April 2023 the finder, Astrix Security, published the flaw it named GhostToken, in that link between the application and its underlying project (Reported [10]). Deleting the GCP project behind an authorized application puts the application into a pending-deletion state, which lasts 30 days, during which the application drops off the user's "Apps with access to your account" page, the only place a user can see and revoke it; the application is thus hidden and, from the user's side, unremovable (Reported [10][7]). The finder reports that while the project sits in pending deletion the application's tokens are unusable, but that restoring the project re-enables the original refresh token, which can then be exchanged for an access token to reach the user's data; the attacker can repeat the delete-and-restore loop, revealing the application only for the moment it is used and hiding it again (Reported [10]). This study describes the effect and reproduces none of the technique.

The scope, as reported, is broad: the finder describes the flaw as affecting all Google accounts, and The Hacker News reports it as including enterprise Workspace accounts, because it sits in the GCP application and OAuth mechanism that Google accounts share, not in one product's data path (Reported [10][8]).

### The dates and Google's handling

The finder's write-up carries a disclosure timeline. Astrix reported the flaw to Google on 19 June 2022; Google's initial response on 23 June 2022 classed it as an abuse risk; Google accepted the report on 18 August 2022; and Google deployed a global patch on 7 April 2023, which, in the finder's words and as part of their coordination, added applications in a pending-deletion state to the user's app-management screen so they can be seen and removed (Reported [10]). The finder published on 20 April 2023; the two news reports and Dark Reading followed, dated 20 and 21 April 2023 (Reported [7][8][11]). So the report, Google's acceptance, the fix and the publication span 19 June 2022, 18 August 2022, 7 April 2023 and 20 April 2023: a long gap between report and fix, longer than in the other three cases.

Google's handling is on record only through the finder. Google published nothing about GhostToken on its own channel that this study could find, as of 25 November 2026: there is no entry in the Google Cloud security bulletins for 2023, and neither news report quotes Google (Inferred for the absence on Google's channel [7][8]). What is on record, from the finder's own account, is the abuse-risk classification, the acceptance and the fix scope (Reported [10]). No CVE is cited; the finder and The Hacker News both call the flaw a zero-day, which is a characterization, not an identifier (Reported [8][10]).

### Why the finder's page is read from the archive

The finder's live page now returns a redirect (this study's own observation, 25 November 2026) to the product site of Cisco, which acquired Astrix Security (announced 4 May 2026, completed by 29 June 2026; Confirmed for the acquisition [12]). The write-up itself is preserved in the Internet Archive, so this study reads the finder's account from an archived capture and cites it as archived [10]; the two news reports and Dark Reading are used for what they add, not as a substitute for the finder's own words (Reported [7][8][11]).

## Part 5: Find and fix

### Decide what you run and what it can reach

For each managed cloud service in use, write down two things: what it holds, and what it can do on your behalf. For Azure Cosmos DB, that is data and the primary keys that reach it; record which accounts exist and when their keys were last rotated. For Azure Database for PostgreSQL, record which instances use public access and which use private networking, since the ExtraReplica exposure was to public-access instances. For AWS AppSync, record which IAM roles trust the service and what those roles can reach, since the flaw turned that trust across account boundaries. For Google Cloud Platform and Google accounts, record which third-party applications hold OAuth grants and what scopes they hold (Inferred from [1][3][5][10]).

### Rotate credentials and narrow trust

Where a flaw exposed a long-lived credential, the provider fix is not the end of the work. For Cosmos DB, rotate the primary key, because a key copied during the exposure window keeps working after the feature is disabled; Microsoft's notice to affected customers was a rotation notice for that reason, and the finder, in its mitigation post, urged every customer to rotate, not only those notified (Confirmed [2]; Reported [19]). For PostgreSQL, prefer private network access, which kept instances out of scope for ExtraReplica (Confirmed [4]). For AppSync and cross-account roles, scope the trust to the minimum and review which roles a service may assume. For OAuth applications, review grants on a schedule and revoke ones you do not recognize; after a provider fixes a hiding flaw, check for applications that may have abused it before the fix, as the finder advised administrators to do after GhostToken (Reported [11]).

### Watch for the signals the provider leaves you

These fixes are the provider's, but some of the attacker's activity is visible to the customer. For AppSync, Datadog's account notes that the cross-account role assumption appears in CloudTrail as activity of the service itself, so the useful detections are unusual cross-account role use and spikes in access-denied events attributed to a service identity; AWS's bulletin, by contrast, says only that an attacker could act as the service, and nothing about logs (Reported [5]). For OAuth applications, GhostToken's lesson is that the connected-apps list can be made to lie, so reviewing the apps-with-access page regularly, which the finder recommends, beats a single glance; exporting and comparing the granted applications over time is this study's own addition (Reported [10] for the finder's advice; Inferred for the export-and-compare step). For the database flaws, the provider-side exposure happened inside the fabric, where a customer could see little; but the later use of a stolen key against a customer's own database is visible to that customer, and Microsoft's ChaosDB update recommends that customers with diagnostic logging enabled review it for unusual IP addresses and that they enable diagnostic logging and Azure Defender (Confirmed [2]). The split to hold is between the provider-side exposure, which the customer cannot see, and the later use of the credential, which the customer can.

## Part 6: Weakness and technique mapping

The mapping below is this study's reading of the ATT&CK definitions against each case's public record, using the library's MITRE reference, which tracks the ATT&CK v20.0 release [9], for the technique names, tactics and platforms. None of these flaws carries a CVE, so none carries the CWE weakness label a CVE record would supply; that absence is graded Inferred, and it is an absence of an assigned identifier, not a statement that no weakness class applies (a CWE can be assigned without a CVE). The techniques describe what an attacker does with a flaw, not the provider-side bug itself, so each row is an analytical mapping with its boundary stated. Most of these techniques sit on ATT&CK's cloud and identity platforms (IaaS, SaaS, Identity Provider, Office Suite), which are part of the Enterprise matrix, not a separate cloud matrix; the exception is T1588.004, a resource-development technique whose platform is PRE.

| Technique | Case support | Boundary |
|---|---|---|
| [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) | ChaosDB, where the notebook reached host metadata services on the way to other tenants' Cosmos DB primary keys | A partial fit: Wiz's walkthrough shows the instance metadata service returned only VM metadata, and the certificates and keys came from the WireServer host and Service Fabric, so the technique covers only the metadata-API step of the chain [16][9] |
| [T1588.004 Digital Certificates](https://attack.mitre.org/techniques/T1588/004/) | ExtraReplica, where the attacker used a certificate issued for an attacker-owned domain that passed the loose Common Name check | Analytical; a resource-development technique, matching the certificate step the finder describes [3][9] |
| [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/) | AppSync, where the provider's own trusted service is tricked into acting across an account boundary | The closest technique to a confused-deputy flaw; a weak fit, since the technique centres on trusted third parties, stated as such [5][9] |
| [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | AppSync, where an IAM role in another account is assumed and acted as | Analytical; fits AppSync's assumed role, not the database cases [5][9] |
| [T1059.009 Cloud API](https://attack.mitre.org/techniques/T1059/009/) | AppSync, where the assumed role is used to make AWS API calls in the victim account | Analytical; the execution step the role assumption enables [5][9] |
| [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) | GhostToken, where the attacker's OAuth application holds a token and a refresh token to the victim's account | The description covers consented OAuth applications and refresh tokens, so a good fit; the token is obtained by consent, not stolen from a store [10][9] |
| [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/) | GhostToken, where the re-enabled refresh token is exchanged for an access token to reach data | Analytical; the use of the token for access [10][9] |
| [T1671 Cloud Application Integration](https://attack.mitre.org/techniques/T1671/) | GhostToken, where persistence rests on an OAuth application integration that stays valid while hidden | A persistence technique for OAuth integrations in SaaS, a closer fit than a generic hide-artifacts mapping [10][9] |

Three techniques from an earlier draft were dropped on this reading: T1530 Data from Cloud Storage, whose definition centres on object storage rather than managed databases; T1564 Hide Artifacts, which lists no SaaS or identity platform and whose sub-techniques do not cover hiding an OAuth grant, better captured by T1671; and the use of T1199 and T1078.004 for the database cases, which fit only AppSync. Two further techniques were considered and left out: T1212 Exploitation for Credential Access, too generic for what the public sources establish, and the provider-internal privilege-escalation step that began the database chains (T1068 or T1611). The finders do document that step, in sections of their own ([3] and [16]); it is left out because this study maps what an attacker does with the flaw across the tenant boundary, not the provider-internal bug, for consistency with the other rows.

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read four flaws across three providers as one broken cloud. They are four separate services, found by three firms over about two years, fixed by each provider on its own side; what ties them is not a shared bug but a shared place, the part of the service the customer cannot patch (Inferred). The easy understatement is to treat a provider's statement that no customer data was accessed as the end of the matter. Microsoft and AWS each investigated and said so, and those statements are the best evidence available (Confirmed [2][4][6]); but for ChaosDB the control that still mattered to a customer was rotating the key, even though Wiz observed some of the credentials it had obtained were revoked (Reported [16]), and for GhostToken no Google statement was found on Google's own channel, on the pages listed in Scope, as of 25 November 2026 (Inferred).

### The customer's half of a shared responsibility

The shared-responsibility model says the provider secures the cloud and the customer secures what they put in it. These four cases show where that line actually runs under stress. The flaw and the fix were the provider's in every case, and the provider carried them. The customer's half was never patching; it was knowing which services held data or trust, rotating the credentials a flaw could expose, preferring private networking and least privilege, and reviewing the grants and connections a provider's own list might not show honestly. A fixed flaw, like these four, closes one path; the standing work is the inventory and the credential hygiene that decide how much a customer loses in the window before a provider's fix arrives (Inferred).

## Sources

1. Wiz, ChaosDB: How we hacked thousands of Azure customers' databases, 26 August 2021, for the Cosmos DB Jupyter Notebook flaw, the cross-tenant access, the long-lived primary keys, the over-30-percent notification figure, and the key-rotation advice. https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases
2. Microsoft Security Response Center blog, Update on the vulnerability in the Azure Cosmos DB Jupyter Notebook Feature, 27 August 2021, for Microsoft's own statement that it turned the feature off, that no customer data was accessed by third parties or security researchers, that affected customers were notified to regenerate the primary read-write key, and its diagnostic-logging and Azure Defender recommendations. https://www.microsoft.com/en-us/msrc/blog/2021/08/update-on-vulnerability-in-the-azure-cosmos-db-jupyter-notebook-feature
3. Wiz, Wiz Research discovers ExtraReplica, a cross-account database vulnerability in Azure PostgreSQL, 28 April 2022 (the page's own metadata reads 29 April 2022), for the two-flaw chain, the certificate Common Name check, the Single Server and private-access scope, the quoted Microsoft response, and the statement that the issue received no CVE identifier. https://www.wiz.io/blog/wiz-research-discovers-extrareplica-cross-account-database-vulnerability-in-azure-postgresql
4. Microsoft Security Response Center blog, Azure Database for PostgreSQL Flexible Server Privilege Escalation and Remote Code Execution, 28 April 2022, for Microsoft's own statement that it mitigated the issue within 48 hours, that no action is required by customers, that Single Server was not impacted and private network access was not exposed, and that no customer data was accessed. https://www.microsoft.com/en-us/msrc/blog/2022/04/azure-database-for-postgresql-flexible-server-privilege-escalation-and-remote-code-execution
5. Datadog Security Labs, A confused deputy vulnerability in AWS AppSync, 21 November 2022, for the cross-account confused-deputy mechanism, the disclosure timeline, and the CloudTrail detection notes. https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/
6. Amazon Web Services, Security Bulletin, Reported AWS AppSync Issue (AWS-2022-009 in the address), 21 November 2022, for AWS's own description of the case-sensitivity parsing issue, its statement that no customers were affected and that the only activity was between the researcher's accounts, and the credit to Datadog. https://aws.amazon.com/security/security-bulletins/AWS-2022-009/
7. SecurityWeek, Google Cloud Platform Vulnerability Led to Stealthy Account Backdoors, 21 April 2023, for the GhostToken mechanism, the 30-day pending-deletion state, and Google's fix making the applications visible again. https://www.securityweek.com/google-cloud-platform-vulnerability-led-to-stealthy-account-backdoors/
8. The Hacker News, GhostToken flaw could let attackers hide malicious apps in Google Cloud Platform, 21 April 2023, for the all-Google-accounts scope including Workspace, the 19 June 2022 and 7 April 2023 dates, and the zero-day characterization. https://thehackernews.com/2023/04/ghosttoken-flaw-could-let-attackers.html
9. TeamStarWolf library MITRE reference, which states the ATT&CK v20.0 release (`mitre/README.md`), with `data/attack/technique_profiles.jsonl` for the technique names, tactics and platforms in the mappings. https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/README.md
10. Astrix Security, GhostToken: Exploiting GCP application infrastructure to create an invisible, unremovable trojan app on Google accounts, published 20 April 2023, read from the Internet Archive capture of 15 June 2024, for the finder's own mechanism, the refresh-token re-enablement on restore, the disclosure timeline including Google's abuse-risk classification and acceptance, and the user guidance. https://web.archive.org/web/20240615223611/https://astrix.security/ghosttoken-exploiting-gcp-application-infrastructure-to-create-invisible-unremovable-trojan-app-on-google-accounts/
11. Dark Reading, 'GhostToken' Opens Google Accounts to Permanent Infection, 20 April 2023, for the finder's advice to administrators to look for applications that may have abused the flaw before the 7 April 2023 patch, and that the finder was not aware of active exploitation. https://www.darkreading.com/remote-workforce/-ghosttoken-opens-google-accounts-to-permanent-infection
12. Cisco, Securing the Agentic Workforce: Cisco Announces Intent to Acquire Astrix Security, 4 May 2026 (completed 29 June 2026), for the acquisition behind the finder's page redirect. https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security
13. Microsoft Security Response Center blog, Toward greater transparency: Unveiling Cloud Service CVEs, 27 June 2024, for Microsoft's statement that it issues CVEs for critical cloud-service vulnerabilities even where customers need no patch. https://www.microsoft.com/en-us/msrc/blog/2024/06/toward-greater-transparency-unveiling-cloud-service-cves
14. Google Cloud, Google Cloud expands CVE program, 12 November 2024, for Google Cloud's statement that it issues CVEs for critical Google Cloud vulnerabilities even where it requires no customer action or patching. https://cloud.google.com/blog/products/identity-security/google-cloud-expands-cve-program/
15. Microsoft, Azure Cosmos DB built-in Jupyter notebooks retirement, notice created 6 October 2023, retirement effective 30 March 2024, for Microsoft's own end state for the feature behind ChaosDB. https://azure.microsoft.com/en-us/updates/azurecosmosdb-notebooks-retirement/
16. Wiz, ChaosDB Explained: Azure's Cosmos DB vulnerability walkthrough, 11 November 2021, for the dated timeline (the feature disabled on 14 August 2021, some obtained credentials observed revoked on 16 August 2021) and the credential path through the host metadata and WireServer services to the primary keys. https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough
17. Wiz open cloud-vulnerability database (open-cvdb), for the absence check and the non-CVSS severities: it lists ChaosDB, ExtraReplica, the AWS AppSync confused deputy and GhostToken, each with no CVE, and rates them critical, critical, high and medium. https://github.com/wiz-sec/open-cvdb
18. CVE Program records CVE-2024-43613 and CVE-2024-49042 (assigner Microsoft, published 12 November 2024), for Microsoft having since assigned CVEs to Azure Database for PostgreSQL Flexible Server itself, for unrelated extension privilege-escalation flaws. https://www.cve.org/CVERecord?id=CVE-2024-43613 and https://www.cve.org/CVERecord?id=CVE-2024-49042
19. Wiz, ChaosDB: How to discover your vulnerable Azure Cosmos DBs and protect them, 29 August 2021, for the advice that every Cosmos DB customer rotate keys, citing CISA's guidance to regenerate keys for all Cosmos DB accounts. https://www.wiz.io/blog/protecting-your-environment-from-chaosdb

## Related references

- [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md) and [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) for the wider record of attacks on cloud services and the controls that answer them.
- [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) for roles, trust and OAuth grants, which three of these four cases turn on.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating a managed service's public endpoint as attack surface.
