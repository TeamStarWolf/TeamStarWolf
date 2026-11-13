# Slide plan: The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner

- Study: case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md
- Cover title: The European Commission / Cloud Breach of 2026 / Through the Poisoned Trivy Scanner
- Subtitle: A security scanner, a pipeline secret and a cloud key that reached too far
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The scanner in the pipeline was the way in

- On 19 March 2026 stolen credentials turned Trivy releases and Actions tags into a stealer.
- The European Commission ran an affected Trivy received through normal update channels.
- An AWS secret taken that day carried management rights over other Commission accounts.
- The SOC alerted on 24 March; ShinyHunters published the data on 28 March.
- CERT-EU assesses the Trivy compromise as the access vector with high confidence.
Caption: Evidence grade: Confirmed for CERT-EU, the Commission, Aqua, NVD and KEV; Reported for news and actor claims.
Notes: Trivy compromise [3]. Access vector and key [1]. Detection [1][2]. Leak [1]. The campaign's home study is the TeamPCP supply-chain study.

## KEY FACTS | Five days, one key, up to 71 clients

Stat: 5 days | From key theft to SOC alert (Inferred)
Stat: 71 | Hosting clients whose data may be affected
Stat: 91.7 GB | Published, compressed (340 GB uncompressed)
Stat: 9.4 | CVSS 4.0 for CVE-2026-33634
- Upstream identifier: CVE-2026-33634, CWE-506 Embedded Malicious Code.
- In CISA KEV from 26 March 2026, due 9 April.
- No lateral movement found as of 2 April; no website altered.
Notes: Dwell time Inferred from [1]. Clients and volumes [1]. CVSS [4]. CVE and CWE [3][4]. KEV [5]. Lateral movement [1].

## PART 1 | From a poisoned release to a public leak

| Date (2026) | Event |
|---|---|
| Late Feb | Privileged token extracted from Trivy's Actions environment |
| 1 Mar | First incident disclosed; rotation not atomic |
| 19 Mar | Malicious v0.69.4 and moved tags; Commission AWS secret taken |
| 24 Mar | Commission SOC alerts; incident response begins |
| 25 Mar | CERT-EU notified; secret secured, new keys disabled |
| 26 Mar | CVE-2026-33634 added to KEV |
| 27 Mar | Press release IP/26/748 |
| 28 Mar | ShinyHunters publishes the dataset |
| 2 Apr | CERT-EU post-incident report |
Caption: All dates come from CERT-EU, the Commission, Aqua, NVD and CISA.
Notes: Late Feb [6]. 1 Mar [3][4]. 19 Mar [1][3]. 24 to 25 Mar [1][2]. KEV [5]. Press release [2]. Leak and report [1].

## PART 2 | What the stealer took from the pipeline

- Read the memory of the GitHub Actions runner process.
- Swept more than 50 disk locations for SSH keys and cloud, Kubernetes and Docker credentials.
- Encrypted the haul and sent it to a typosquatted domain.
- Fell back to a public tpcp-docs repository in the victim's own GitHub account.
- Images by digest, source builds and releases made immutable were not affected.
Caption: Tradecraft is kept at advisory level; no command, payload or hash is reproduced.
Notes: Stealer behavior, Confirmed from Aqua's advisory [3]. Self-label "TeamPCP Cloud stealer" [6]. Unaffected references [3].

## PART 2 | Inside the Commission's AWS estate

Left: What CERT-EU records
- AWS API key held on 19 March.
- TruffleHog run to find and validate more secrets.
- New access key attached to an existing user.
- Data taken from the europa.eu hosting backend.
Right: What it did not find
- No lateral movement as of 2 April.
- No website taken offline or altered.
- No impact on internal systems, per the Commission.
Caption: The key carried management rights over other Commission-affiliated AWS accounts.
Notes: Intrusion record, Confirmed [1]. Internal systems [2]. Management rights [1].

## PART 3 | Three claims that should not be merged

| Claim | What the record says |
|---|---|
| Trivy compromise | Aqua: TeamPCP, plausible, not confirmed |
| AWS intrusion | CERT-EU names the vector, not the operator |
| The leak | CERT-EU: ShinyHunters published the data |
| Law enforcement | FBI FLASH on TeamPCP; two men charged in Australia |
Caption: No primary source shows how the data passed from the intruder to the leak site (Inferred).
Notes: Aqua attribution [6]. CERT-EU [1]. ShinyHunters claim of responsibility, Reported [15]. FBI [8]. AFP charges are allegations [9].

## PART 3 | ATT&CK's view of the actors

- G1056 TeamPCP: financially motivated, cloud-native, active since at least September 2025.
- G1057 ShinyHunters: a criminal collective that sells or extorts with stolen data.
- G1057 links ShinyHunters to The Com, with Scattered Spider and LAPSUS$.
- No ATT&CK campaign object covers this incident in v20.0.
Caption: Neither ATT&CK group page names the European Commission.
Notes: G1056 [11]. G1057 [12]. The Com links [12]. Campaign objects [11][18]. Wiz's LAPSUS$ remark at RSA, Reported [13].

## PART 4 | Impact on the Union's websites

- Up to 71 hosting clients: 42 internal Commission clients, at least 29 other Union entities.
- Names, usernames and email addresses, mainly from Commission websites.
- At least 51,992 outbound email files (2.22 GB), mostly automated notifications.
- Notices went to CERT-EU and to the data protection authorities the law requires.
Caption: Larger claims of mail dumps, contracts and an SSO directory remain unverified.
Notes: Clients and data [1]. Websites and internal systems [2]. Regulation (EU, Euratom) 2023/2841 and Regulation (EU) 2018/1725 [1]. Larger claims, Reported [16].

## PART 4 | The campaign around the Commission

Stat: 1,000+ | Organisations potentially compromised (police estimate)
Stat: 500,000+ | Credentials stolen (police estimate)
Stat: 10,000+ | Workflow files referencing trivy-action (Reported)
- Aqua says it cannot notify all Trivy users.
- The Commission is the one downstream victim with a published government report.
Caption: Police estimates are allegations, not counts.
Notes: AFP estimates [9]. Socket count, Reported [13]. Aqua [6]. Rarity Inferred from [1][6][8][9].

## DEFENDER VIEW | A KEV entry with no patch to apply

Left: Remediate
- Move to Trivy v0.69.2 or v0.69.3, trivy-action v0.35.0, setup-trivy v0.2.6.
- Rotate every secret a pipeline in the window could read.
- Pin Actions to full commit SHAs.
Right: Hunt and harden
- CloudTrail: odd STS calls, TruffleHog, new keys on old users.
- Look for tpcp-docs or docs-tpcp repositories.
- Take long-lived cloud keys out of CI/CD.
Caption: A ticket closed on the upgrade alone leaves the stolen keys live (Inferred).
Notes: Versions [3][4]. Rotation [4]. SHA pinning [1][3][8]. Hunting [1]. Fallback repositories [4][8]. Keys out of CI [1][8].

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "ShinyHunters hacked the Commission": CERT-EU says it published the data.
- Mail servers, contracts and an SSO directory: leak-site and relayed claims.
Right: Understated
- The reach of one pipeline key over several AWS accounts.
- At least 30 Union bodies affected.
- Aqua's incomplete first containment on 1 March.
Notes: Responsibility claim, Reported [15]; CERT-EU [1]. Larger claims [1][16]. Key reach [1]. Union bodies Inferred from [1]. Containment [3][7].

## MITRE MAPPINGS | CERT-EU's four techniques and the rest

| Id | Technique | Tie to the Commission case |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | Compromised Trivy (CERT-EU) |
| T1586.003 | Cloud Accounts | AWS secret obtained (CERT-EU) |
| T1078.004 | Cloud Accounts | Stolen key used (CERT-EU) |
| T1005 | Data from Local System | Website data taken (CERT-EU) |
| T1098.001 | Additional Cloud Credentials | New access key (Inferred) |
| T1580 | Cloud Infrastructure Discovery | Reconnaissance (Inferred) |
Caption: ATT&CK v20.0. Upstream rows, CWE-506, CAPEC-442 and D3FEND pairings are in the study and its Navigator layer.
Notes: Mappings [1] with [18]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Security tools are supply chain too

- **Trusted tools carry secrets.** A scanner runs with the pipeline's keys by design.
- **Containment has to be atomic.** A partial rotation may have left the door open.
- **Mutable references are an attack surface.** Tags moved; digests did not.
- **Keep attribution layers apart.** Tool compromise, intrusion and leak differ in evidence.
Notes: Themes Inferred from [1][3][4][6]. Lineage: SolarWinds SUNBURST and the XZ Utils backdoor studies.
