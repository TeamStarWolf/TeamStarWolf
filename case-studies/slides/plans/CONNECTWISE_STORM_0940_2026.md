# Slide plan: The ConnectWise Cloud Backup Compromise of October 2026: A Case Study

- Study: case-studies/CONNECTWISE_STORM_0940_2026.md
- Cover title: The ConnectWise Cloud Backup / Compromise of October 2026 / A Case Study
- Subtitle: A backup vendor's app credential, customer tenants that trusted it, and no user sign-in at all
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/CONNECTWISE_STORM_0940_2026.md, published 12 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The trust was the attack surface

- An application credential held in ConnectWise's own tenant was compromised in mid-October 2026.
- It was used to sign in as the multi-tenant Cloud Backup app and take Microsoft Graph tokens.
- The sign-ins were app-only: no user signed in, so user MFA never came into play.
- Microsoft assesses that the China-state aligned Storm-0940 was responsible, using the ARTEX framework.
- No CVE applies: this was abuse of an application identity, not a software flaw.
Caption: Evidence grade: Confirmed from ConnectWise, Microsoft and Huntress; Microsoft gives no confidence level for the attribution.
Notes: Credential and tokens [3]. App-only [2][3]. Attribution and ARTEX [2]. No CVE [2][8].

## KEY FACTS | Targeted is not the same as compromised

Stat: 2,250+ | Tenants with attempted sign-ins (Microsoft)
Stat: 162 | Tenants with confirmed sign-ins (Huntress, 16 Oct)
Stat: 2 | Tenants with post-compromise activity
Stat: 0 | CVEs or KEV entries for Cloud Backup
- Main window: 15 October 2026, from 03:44 UTC to the last confirmed sign-in at 08:44 UTC.
- Huntress found the two in more than 10,000 tenants it reviewed; it sees only its own customers.
- Microsoft does not say how many tenants were compromised.
Notes: 2,250 [2]. 162 and two of 10,000 [3]. No CVE or KEV [8]. Window [3]. Microsoft's caveat [2].

## PART 1 | Five days from spray to shutoff

| Date (UTC) | Event |
|---|---|
| 10 to 14 Oct | Spray against 327 accounts at eight organizations; no success |
| 15 Oct 03:44 | A ConnectWise app self-assigns Global Administrator in one tenant |
| 15 Oct 06:13 | The Cloud Backup app signs in and obtains Graph tokens, to 08:44 |
| 16 Oct | Huntress publishes; ConnectWise publishes its advisory at 17:47 |
| 17 Oct 05:01 | ConnectWise confirms unauthorized access and shuts off app access |
| 19 Oct | Full reset of accounts and credentials completed |
| 21 Oct | Microsoft names Storm-0940 and ARTEX; restoration begins |
| 4 Nov | Last update: billing and some notifications still in progress |
Caption: The 14 October detection date rests on one news report and is graded Reported.
Notes: Spray [2]. 15 October events [3]. 16 and 17 October [1][3]. Reset [1]. Attribution [2]; restoration [1]. 14 October [12].

## PART 2 | One credential, many tenants, no user

- The secret was an application credential held in the vendor's own tenant.
- With it the attacker authenticated as ConnectWise's multi-tenant apps into consenting tenants.
- The Graph tokens carried the permissions those customers had granted the vendor.
- The sprays came from the same 144.172.64[.]0/24 range and failed against users.
- How the vendor-tenant credential was first obtained is not public.
Caption: The Record reports Microsoft named elevated permissions such as Directory.ReadWrite.All (Reported).
Notes: Credential [3]. Authentication and tokens [2][3]. Range [2][3]. Initial access unknown [1]. Permission [9].

## PART 2 | Persistence was planted on other apps

Left: In one tenant, 15 October
- A Cloud Management app gave itself Global Administrator at 03:44 and 03:48.
- A script then made nine credential changes to two other apps; six succeeded.
- The new client secrets were set to expire in 2028.
Right: Elsewhere in the record
- Directory roles taken in about 50 tenants from 01:58; vendor automation not ruled out.
- Microsoft saw Graph reconnaissance and bulk secret reads across Azure Key Vaults.
- Huntress found no mailbox or file changes in the two tenants it reviewed.
Caption: Graph directory reads leave no audit record without Graph activity logs.
Notes: Self-assignment and secrets [3]. About 50 tenants [3]. Key Vault and Graph [2]. Two tenants [3]. Logging [3][4].

## DISCREPANCIES | The numbers measure different things

| Figure | What it actually measures |
|---|---|
| 2,250+ tenants | Sign-in attempts (Microsoft), not compromises |
| 162 tenants | Confirmed sign-ins among Huntress customers on 16 Oct |
| 300+ of ~1,000 | Tenants with successful sign-ins from one address (Huntress, 17 Oct) |
| 2,900 a minute | Peak failed spray logons on 11 Oct, not tenant sign-ins |
| 327 | Accounts at eight organizations, not 327 organizations |
| Four or three app IDs | Microsoft's text against its hunting queries; Huntress lists seven |
Caption: None of these is a count of compromised tenants (Inferred).
Notes: Microsoft [2]. Huntress [3]. Spray figures [2] against press [12]. App IDs [2][3].

## PART 3 | Microsoft attributes; others relay

| Who | What they say |
|---|---|
| Microsoft | "Assesses" Storm-0940, China-state aligned; no confidence level |
| ConnectWise | It "appears" a China state-aligned group was responsible |
| Huntress | Consistent with Microsoft; not independently verified |
| Storm-0940 targets | Defense, government, legal, think tanks, technology and more |
| Second wave | Policy, national security, trade and critical-minerals tenants |
Caption: The target profile reads as intelligence collection rather than extortion (Inferred).
Notes: Microsoft [2][6]. ConnectWise [1]. Huntress [4][5]. Targets [2]. Second wave [3].

## PART 3 | ARTEX changed tempo, not technique

Stat: 200+ | Sign-ins in under four minutes on four app credentials
Stat: 3h | Under three hours, targeting to privileged access, in multiple cases
- ARTEX is an open-source, multi-agent LLM penetration-testing framework.
- Microsoft says Storm-0940 used it to speed scanning, spraying and OAuth app abuse.
- Many actors use ARTEX; by 6 November a financially motivated cluster, Storm-3358, did too.
- Huntress rates LLM involvement low-to-medium on its own telemetry alone.
Notes: Figures and ARTEX [2]. Not a fingerprint [2][5]; Storm-3358 [7]. Huntress confidence [4].

## PART 4 | Restoration took weeks

- 17 October: seven application identities disabled and certificates revoked.
- 18 October: SaaS Security and Cloud Management taken offline with Cloud Backup.
- 28 October: restoration through a new app; every partner re-authorizes each tenant.
- ConnectWise warned that issued tokens may stay valid until they expire.
- Disabling the apps does not reverse changes already made inside a tenant.
Caption: ConnectWise says backup archives stayed encrypted and isolated (Confirmed as stated; not independently verified).
Notes: Containment and restoration [1]. Token and in-tenant warnings [1]. Archives [1].

## DEFENDER VIEW | No scanner would have found this

Left: Inventory and limit
- List every multi-tenant app with standing Graph permissions, by application ID.
- Cut each grant to the least privilege it needs.
- Restrict who and what can add credentials to applications.
Right: Detect and respond
- Alert on role self-assignment and credentials added to apps.
- Turn on Graph activity logs before you need them.
- For an affected vendor app: disable it, do not delete it first.
Caption: Treat multi-tenant app consents as exposures with an owner, a privilege rating and a review date (Inferred).
Notes: Inventory and least privilege [2]. App management policies [3]. Alerts [3][4]. Graph logs [4]. Disable first [2].

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "2,250 compromised" and "thousands of companies."
- The 2,900 figure and "327 organizations."
- Any framing of this as an AI-led breach.
Right: Understated
- Secrets planted on other apps outlive the vendor's credential rotation.
- Tokens issued before the shutoff may stay valid until expiry.
- 162 is a floor: Huntress sees only its own customers.
Notes: Counts [2][11]. Spray figures [2][12]. AI framing [4]. Secrets [3]. Tokens [1]. Floor [3]. The assessments are Inferred.

## MITRE MAPPINGS | Eleven techniques, no group object

| Id | Technique | Tie to ConnectWise |
|---|---|---|
| T1110.003 | Password Spraying | The 10 to 14 October spray |
| T1199 | Trusted Relationship | Customers' grants to the vendor app |
| T1078.004 | Cloud Accounts | Sign-ins as the Cloud Backup app |
| T1528 | Steal Application Access Token | Graph tokens obtained |
| T1098.003 | Additional Cloud Roles | Global Administrator self-assigned |
| T1098.001 | Additional Cloud Credentials | Secrets added to two apps |
| T1555.006 | Cloud Secrets Management Stores | Bulk Key Vault secret reads |
Caption: ATT&CK v20.0; also T1595, T1195, T1087.004 and T1580. CAPEC-565, CAPEC-21, CAPEC-169. No Storm-0940 or ARTEX object exists.
Notes: Techniques [2][3] with [14]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Standing consent is standing exposure

- **Vendor apps are part of your perimeter.** The foothold was a vendor's own app.
- **MSPs remain a force multiplier.** One credential reached more than 2,250 tenants with attempts.
- **AI changes tempo, not technique.** Every step maps to an existing ATT&CK technique.
- **Logs decide what can be known.** Without Graph activity logs, no one can say what was read.
- **The lineage is long.** SolarWinds-era actors also added credentials to apps and service principals.
Notes: Vendor app [2][3]. MSPs [2][15]. Tempo [2]. Logs [3]. Lineage [16]. The themes are Inferred from the record.
