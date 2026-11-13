# Slide plan: The TeamPCP Supply-Chain Campaign of 2026: Trivy, Checkmarx and the Bitwarden CLI (CVE-2026-33634)

- Study: case-studies/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md
- Cover title: The TeamPCP / Supply-Chain Campaign / of 2026
- Subtitle: Trivy, Checkmarx and the Bitwarden CLI: when the scanner in the pipeline stole its secrets
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/TEAMPCP_TRIVY_SUPPLY_CHAIN_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A trusted CI step became the credential thief

- On 19 March a malicious Trivy release shipped and almost every trivy-action tag moved to a credential stealer.
- Aqua's assessment: access kept through an incomplete clean-up of a late-February intrusion.
- Stolen pipeline secrets opened Checkmarx, LiteLLM, Telnyx and, by Bitwarden's account, its CLI.
- CERT-EU traces the European Commission's Europa hosting breach, about 91.7 GB, to Trivy.
- Who did the April work is not settled.
Caption: Evidence grade: Confirmed for the vendor, CVE, KEV and CERT-EU records; the April attribution is Reported.
Notes: Release and tags [1]. Root cause [1][3]. Downstream [9][12][13][26]. Commission [28]. April attribution [21][22].

## KEY FACTS | One KEV entry, no patch to chase

Stat: 76/77 | trivy-action tags force-pushed
Stat: 7/7 | setup-trivy tags replaced
Stat: 91.7 GB | taken from Europa.eu hosting
Stat: 2 | men arrested by the AFP in August
- CVE-2026-33634: CWE-506 embedded malicious code, CVSS v4 9.4; KEV 26 March, due 9 April.
- CVE-2026-42994: the Bitwarden CLI 2026.4.0 on npm; not in KEV.
- Actor: ATT&CK G1056 TeamPCP, financially motivated; Aqua's advisory names no actor.
Caption: The AFP's figures of 1,000+ organizations and 500,000+ credentials are allegations, not verified counts.
Notes: Tags [1]. Commission [27][28]. Arrests [16]. CVE and KEV [1][3][4][5]. Actor [18][2].

## PART 1 | From a February token to an August arrest

| Date (2026) | Event |
|---|---|
| About 28 Feb | A pull_request_target workflow yields a token (Reported) |
| 1 Mar | Aqua discloses; rotation is not atomic |
| 19 Mar | Trivy v0.69.4 and moved Action tags |
| 23 to 27 Mar | Checkmarx, litellm and telnyx publishes |
| 22 Apr | Checkmarx second wave; Bitwarden CLI 2026.4.0 |
| 26 Aug | AFP arrests two alleged members |
Caption: Exposure windows lasted hours; the stolen secrets stayed valid until rotated (Inferred).
Notes: February [7][25]. Disclosure [1][3]. 19 March [1]. Publishes [9][11][12][26]. April [5][9][13]. Arrests [16].

## PART 1 | The record disagrees with itself

- **Tag counts.** Aqua says 76 of 77 trivy-action tags; Wiz counts 75 of 76.
- **Timing.** Checkmarx and Wiz give different Open VSX times; LiteLLM and Wiz give different windows.
- **Telnyx and the CVE.** Telnyx's advisory has no CVE id; NVD lists telnyx under CVE-2026-33634.
- **Checkmarx entry.** One update says 19 March; its timeline says 23 March.
Caption: Where sources disagree, the study gives both values and leaves them unresolved.
Notes: Tags [2][20]. Open VSX [9][10]. LiteLLM [10][12]. Telnyx [3][26]. Checkmarx [9].

## PART 2 | How the release and the Actions were poisoned

Left: The Trivy release
- A pushed commit pointed the release checkout at an imposter commit.
- Pushing the v0.69.4 tag ran the normal release pipeline.
- It reached registries, Linux packages and Aqua's Homebrew tap.
- The malicious code never reached Trivy's main branch.
Right: The Actions
- Existing trivy-action tags were force-pushed to new commits.
- All seven setup-trivy tags were replaced.
- Any workflow pinned to a tag pulled the stealer on its next run.
- Immutable releases protected only later versions.
Caption: Described at advisory level; no commands or payloads are reproduced.
Notes: Release [1]. Actions [1]. Tag pinning consequence Inferred.

## PART 2 | What the stealer took

- Read runner process memory for secrets before the real scan ran.
- Swept SSH, cloud, Kubernetes, Docker, .env, database and wallet credentials.
- Encrypted the haul and sent it to a typosquat domain.
- Fallback: a public tpcp-docs repository in the victim's own GitHub account.
- ATT&CK records the payload as S9041 TeamPCP Cloud Stealer.
Caption: Evidence grade: Confirmed from Aqua's advisory and discussion and the ATT&CK object.
Notes: Behaviour [1]. Sinks [8]. Software object [18][31].

## PART 3 | Who: firm for March, blurred for April

| Party | Says |
|---|---|
| Aqua advisory | "a threat actor"; no name |
| Checkmarx | Access came from the Trivy attack; names Team PCP |
| Wiz | KICS is the same actor, from a shared RSA key |
| Bitwarden | No actor; a broader Checkmarx incident |
| Sophos, Socket | The April link is unresolved |
| ATT&CK | G1056 TeamPCP, financially motivated |
Caption: Checkmarx, Bitwarden, Aqua and ATT&CK are Confirmed statements; Wiz, Sophos and Socket are Reported.
Notes: Aqua [2][8]. Checkmarx [9]. Wiz [10][20]. Bitwarden [13]. Sophos [22], Socket [21]. ATT&CK [18].

## PART 4 | Impact and response

Left: Victims
- European Commission: up to 71 Europa hosting clients, about 91.7 GB.
- LiteLLM compromised through Trivy in its CI.
- Mercor: "one of thousands of companies" hit via LiteLLM.
- AFP: 1,000+ organizations alleged.
Right: Response
- Aqua restored latest to 0.69.3 and engaged Sygnia.
- Checkmarx declared containment on 6 July.
- LiteLLM rebuilt its release pipeline for v1.83.0.
- Bitwarden shipped 2026.4.1; no vault data affected.
Caption: Mercor's figure and the AFP's counts are claims, not verified counts.
Notes: Commission [27][28]. LiteLLM [12]. Mercor, Reported [29]. AFP [16]. Aqua [1][8][19]. Checkmarx [9]. LiteLLM [12]. Bitwarden [13].

## PART 5 | A KEV entry with nothing to patch

- The KEV entry is embedded malicious code: the fix is removal plus rotation.
- The due date, 9 April, fell about three weeks after the March windows closed.
- Scanners keyed on CVE and package version miss moved Action tags.
- The work is proving whether a pipeline ran in a window.
Caption: The vulnerability-management reading is the study's own (Inferred).
Notes: KEV [4]. Fix [1][4]. Due date Inferred from [1][4]. Tags and windows Inferred.

## DEFENDER VIEW | Pin, rotate, restrict, watch

Left: Prevent
- Pin every third-party Action to a full commit SHA.
- Ephemeral runners, least-privilege GITHUB_TOKEN, just-in-time secrets.
- Restrict runner egress to known endpoints (Inferred).
- Treat IDE extension marketplaces as supply chain.
Right: Respond
- Rotate every reachable secret at once, then verify revocation.
- Hunt for tpcp-docs and docs-tpcp repositories.
- Review workflow logs inside each window.
- Alert on cloud API misuse and abnormal traffic.
Notes: Pinning [1][3]. Microsoft guidance [15]. Egress, CERT-EU [28]. Extensions [9]. Rotation [1][3]. Hunting [1][10]. Logs [1][12]. Cloud alerting [28].

## OVERSTATED AND UNDERSTATED | Not a bug, and not over in March

Left: Overstated
- Calling it a Trivy "vulnerability" suggests a code flaw to patch.
- Folding the Bitwarden CLI into TeamPCP outruns the primaries.
- "Thousands of companies" and 154 organizations are claims.
- Hours-long windows sound small.
Right: Understated
- The compromise began in February, not March.
- CVE-2026-33634 also covers litellm and telnyx in NVD.
- Checkmarx exposure ran from 19 March to 9 May.
- Most victims will never disclose.
Notes: Overstated [1][4][13][21][22][23][29]. Understated [1][3][9]. Readings Inferred where labelled.

## MITRE MAPPINGS | Thirty techniques, four named by CERT-EU

| Id | Technique | Tie to the record |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | Trivy v0.69.4 release |
| T1195.001 | Compromise Software Dependencies and Development Tools | Action tags, packages |
| T1677 | Poisoned Pipeline Execution | Release workflow redirected |
| T1003.007 | Proc Filesystem | Runner memory read |
| T1567.001 | Exfiltration to Code Repository | tpcp-docs fallback |
| T1078.004 | Cloud Accounts | AWS key at the Commission |
Caption: ATT&CK v20.0; the other techniques are in the study's table and its Navigator layer. CWE-506, CWE-78, CWE-94.
Notes: Techniques [1][9][18][28] with library data [31]. CWE [1][3][4][5]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The security tool is part of the attack surface

- **The scanner runs with the build's secrets.** SolarWinds and xz utils showed the same trust.
- **Worms and token theft are one line.** ATT&CK ties Mini Shai-Hulud to G1056.
- **AI tooling sits in the blast radius.** LiteLLM and MCP configurations were targets.
- **One compromise, many extortion victims.** Vect and LAPSUS$ partnerships.
Notes: Themes Inferred except the ATT&CK tie [18], the AI targets [12][14] and the partnerships [9][23].
