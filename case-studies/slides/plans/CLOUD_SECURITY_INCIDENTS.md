# Slide plan: Major Cloud Security Incidents: The Public Record, 2011 to 2026

- Study: case-studies/CLOUD_SECURITY_INCIDENTS.md
- Cover title: Major Cloud Security Incidents / The Public Record / 2011 to 2026
- Subtitle: Most of it in the customer's band, the worst of it in the provider's
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CLOUD_SECURITY_INCIDENTS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Headlines said "cloud breach"; the record says identity

- Mandiant found no breach of Snowflake's enterprise environment in 2024: stolen customer credentials, no MFA.
- GTIG says the 2025 Salesloft Drift theft did not stem from a core Salesforce vulnerability.
- The regulator that fined Capital One cited the bank's own risk assessment before migration.
- The other half is short and serious: Storm-0558 forged tokens with a Microsoft consumer key.
- From 2021 the dominant pattern is a stolen non-human identity that many tenants trust.
Caption: Evidence grade: Confirmed for incident facts from primaries; Reported for finder write-ups and press-only 2026 events.
Notes: Snowflake [53]. Salesloft Drift [68]. Capital One [9]. Storm-0558 [47]. Non-human identity pattern, Inferred from [68][37][27][80][77].

## KEY FACTS | Fifteen years, from reused passwords to multi-tenant apps

Stat: $80M | OCC penalty against Capital One, August 2020
Stat: 22 | Organizations reached by Storm-0558 (CSRB)
Stat: 165 | Organizations notified in the Snowflake campaign
Stat: 2,250+ | Tenants Storm-0940 tried as ConnectWise apps
- Earliest primary opened: Dropbox, 31 July 2012, passwords reused from other sites.
- Largest non-attack event: CrowdStrike Channel File 291, about 8.5 million Windows devices.
- Storm-0558, UNC5537, UNC6395, Storm-0940 and Storm-3168 have no ATT&CK object.
Notes: OCC [9]. Storm-0558 [47]. UNC5537 [53]. Storm-0940 [77]. Dropbox [1]. CrowdStrike [58][59]. ATT&CK objects [97].

## PART 1 | Every provider leaves identity, access and data with the customer

| Provider | How it draws the line |
|---|---|
| AWS | Security "of" the cloud is AWS's; security "in" it is the customer's |
| Microsoft | Data, configuration, identities and users stay with the customer in every model |
| Google Cloud | Shared fate; customers "always remain responsible" for access and data |
Caption: Snowflake 2024 and Salesloft Drift 2025 sit in the customer band; Storm-0558 sat in the provider's.
Notes: AWS [89]. Microsoft [90]. Google [91]. The banding of incidents is Inferred from [53][68][47][18][70].

## PART 2 | The timeline in five eras

| Era | What defined it |
|---|---|
| 2011 to 2018 | Reused passwords, a posted access key, public buckets, MSPs targeted |
| 2019 to 2021 | Capital One, SolarWinds in Microsoft tenants, Codecov, Cosmos DB |
| 2022 to 2023 | Lapsus$, Okta support, CircleCI, Storm-0558's forged tokens |
| 2024 | Midnight Blizzard, the Snowflake customer tenants, the CSRB review |
| 2025 to 2026 | OAuth apps, Actor tokens, Qubole roles, ConnectWise app identities |
Caption: Each year's wider record is in the library's chronicle series, 2016 to 2025.
Notes: 2011 to 2018 [1][2][3][4][5][6][7]. 2019 to 2021 [8][9][14][16][18]. 2022 to 2023 [21][19][37][27][29]. 2024 [42][53][47]. 2025 to 2026 [68][70][80][77].

## PART 3 | Stolen and single-factor credentials opened most doors

- **Dropbox, 2012.** Passwords reused from other sites; about 68 million credentials confirmed in 2016.
- **Snowflake customers, 2024.** At least 79.7 percent of accounts used had prior infostealer exposure.
- **Midnight Blizzard, 2023 to 2024.** A password spray found a legacy test account with no MFA.
- **Uber, 2022.** A contractor approved a push after repeated two-factor prompts.
- **Lapsus$.** The CSRB found SMS and voice MFA defeated by SIM swapping.
Caption: Some Snowflake credentials had gone unrotated for as long as four years.
Notes: Dropbox [1][2]. Snowflake [53]. Midnight Blizzard [43][46]. Uber [22]. CSRB [33].

## PART 3 | Exposure is not the same as a breach

Left: Storage and endpoints
- 2017 public buckets reported by UpGuard (Reported).
- Microsoft's 2019 support database: no malicious use found.
- Microsoft's 2023 SAS token: no customer data exposed.
Right: Metadata and SSRF
- Capital One calls its flaw a "configuration vulnerability".
- The SSRF-to-metadata account rests on press reporting (Reported).
- AWS shipped IMDSv2 in November 2019; default for new launches in March 2024.
Caption: S3 Block Public Access became the default for new buckets only in April 2023.
Notes: UpGuard [4][5][6]. Microsoft [13][35]. Capital One [8]. SSRF basis, Reported [10]. IMDSv2 [11][12]. S3 defaults [88].

## PART 3 | The provider's band failed too, and customers could not stop it

- **Storm-0558, 2023.** A 2016 consumer signing key forged tokens that enterprise Exchange Online accepted.
- **Cosmos DB notebooks, 2021.** A preview feature could expose another customer's primary key.
- **Entra ID Actor tokens, 2025.** CVE-2025-55241: no originating-tenant check, no API-level log.
- **Cloudflare Containers, 2026.** Residual disk data could cross tenants until the fix.
- Researchers and bug bounties, not attackers, found the three cross-tenant flaws.
Caption: The CSRB found Microsoft still did not know how the key was obtained.
Notes: Storm-0558 [47][34]. Cosmos DB [18]. CVE-2025-55241 [69][70]. Cloudflare [75]. Who found them [18][70][75].

## PART 3 | One stolen secret in the trust layer reaches thousands of tenants

| Year | Trusted identity | What it reached |
|---|---|---|
| 2022 | CircleCI engineer's SSO session | Customer CI secrets and keys |
| 2023 | Okta support service account | Files of 134 customers; 5 sessions hijacked |
| 2025 | Salesloft Drift OAuth tokens | Many Salesforce instances |
| 2026 | Qubole cross-account roles | Customer AWS secrets and S3 data |
| 2026 | ConnectWise multi-tenant apps | Sign-in attempts at 2,250+ tenants |
Caption: Todyl's 2026 cases add stolen app secrets and GDAP into 27 organizations.
Notes: CircleCI [27]. Okta [36][37]. Drift [68]. Qubole [80]. ConnectWise [77][78]. Todyl [82].

## PART 4 | The CSRB called Storm-0558 preventable

- "A cascade of security failures at Microsoft"; security culture inadequate.
- State detected it on a log available only with G5 licensing.
- Commerce and the UK victims, without premium logging, could not look back.
- Microsoft's crash-dump account was corrected only in March 2024.
- 25 recommendations, including free default audit logs and CVEs for cloud flaws.
Caption: The Lapsus$ review of August 2023 recommended FIDO2 phishing-resistant MFA.
Notes: CSRB MEO review [47][49]. Crash-dump correction [34][47]. Logging [47][31]. Lapsus$ review [33].

## PART 4 | Regulators judged the customer's cloud governance

| Date | Body | Action |
|---|---|---|
| Aug 2020 | OCC | $80M penalty on Capital One over migration risk assessment |
| Oct 2022 | FTC | Proposed Drizly order binding the CEO personally |
| Jul 2023 | SEC | Material incidents disclosed on Form 8-K in four business days |
| Apr 2024 | CISA | ED 24-02 on Midnight Blizzard's theft of agency mail |
| Dec 2024 | CISA | BOD 25-01 secure cloud baselines |
Caption: Treasury warned in February 2023 that cloud concentration links many firms to one provider.
Notes: OCC [9]. FTC [26]. SEC [32]. ED 24-02 [50]. BOD 25-01 [64]. Treasury [28].

## PART 5 | Defaults changed, years after the incidents that argued for them

| When | Provider change |
|---|---|
| Apr 2023 | S3 Block Public Access on for every new bucket |
| Sep 2023 | Microsoft email-access logs in the standard tier |
| Mar 2024 | IMDSv2 as an account default for new EC2 launches |
| Oct 2024 | Azure mandatory MFA for portal sign-in |
| Sep 2025 to Oct 2026 | Snowflake retires single-factor passwords (estimated dates) |
Caption: Microsoft committed to CVEs for critical cloud flaws in June 2024.
Notes: S3 [88]. Logging [31]. IMDSv2 [12]. Azure MFA [63]. Snowflake [71]. Cloud CVEs [57].

## DEFENDER VIEW | Six moves the record supports

- Phishing-resistant MFA on every human path; no passwords on non-human ones.
- Inventory every app, token and integration role you trust or are trusted through.
- Short-lived credentials by default: IMDSv2, OIDC instead of long-lived CI secrets.
- Log mailbox and API access, keep it, and baseline it per application.
- Bind sessions to network location and alert on credential reuse elsewhere.
- Plan for the provider that fails, attack or not.
Caption: Overstated: "the provider was hacked". Understated: control-plane risk, paid logging, the delegated-trust layer.
Notes: MFA [33][71][63]. Apps and roles [43][78]. Short-lived [12][27]. Logging [30][87][47]. Sessions [37][93]. Concentration [28][58].

## MITRE MAPPINGS | Forty-eight Enterprise techniques, identity first

| Id | Technique | Tie to the record |
|---|---|---|
| T1078.004 | Cloud Accounts | Uber to Storm-0940 |
| T1199 | Trusted Relationship | Okta, Drift, Qubole, ConnectWise |
| T1528 | Steal Application Access Token | CircleCI, Drift, Storm-0940 |
| T1606 | Forge Web Credentials | Storm-0558 |
| T1110.003 | Password Spraying | Midnight Blizzard, Storm-0940 |
| T1530 | Data from Cloud Storage | Capital One, Qubole |
Caption: ATT&CK v20.0. Objects: G0016, G1004, G1015, G1057, G0092, C0024, C0027, C0059, S0013, S0153.
Notes: Techniques [40][77][76][68][37][53][29][42] and the library data [97]. CWE, CAPEC and D3FEND [97]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Identity is the perimeter the record keeps crossing

- **Non-human identities lead the modern record.** OAuth apps, service principals, CI tokens, roles.
- **Trust is transitive.** Support vendors, CI platforms, integrations and MSP tools multiply reach.
- **Logs decide what can be known.** Premium logging found Storm-0558.
- **Defaults move slowly, then all at once.** 2023 to 2026 changed four of them.
- **Accountability reached the boardroom.** Penalties, a CEO order, disclosure deadlines.
Notes: Non-human identity, Inferred from [68][37][27][35][76][80][82]. Trust [33][16][68][77]. Logs [47][37][70]. Defaults [88][12][63][71]. Accountability [9][26][32][38][51].
