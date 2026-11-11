# Slide plan: npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses

- Study: case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md
- Cover title: npm Supply-Chain Attacks / 2018 to 2026 / The Record and the Defenses
- Subtitle: Stolen publish rights, install-time payloads and the defaults that now push back
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Attackers wanted publishing rights, not code flaws

- npm lets a few maintainers, many of them volunteers, ship small packages that millions of projects pull in by name, often several levels deep.
- Almost every incident from 2018 to 2026 is a legitimate publish by someone who should not have been able to publish.
- The payloads mostly ran at install time through lifecycle scripts, which npm 12, pnpm and Yarn Berry now block by default for dependencies.
- Most bad versions were found and pulled within minutes to hours, which is why release-age gates work (Inferred).
- Provenance alone does not: TanStack shipped through its own trusted-publisher binding and keyv carried valid provenance.
Caption: Grades: Confirmed from primary sources, Reported from press or third parties, Demonstrated for research, Inferred for the study's reasoning.
Notes: Executive summary and key findings. Publish access [1][58][17][20][18][30][43][35]. Install scripts [7][28][38][48][79]. Release-age gate Inferred from [1][7][18][35][38][43]. Provenance [43][47][121].

## KEY FACTS | The biggest waves reached hundreds of packages in days

Stat: 2B+ | weekly downloads: chalk, debug and 16 others
Stat: 500+ | packages GitHub removed after Shai-Hulud
Stat: 700+ | Shai-Hulud 2.0 packages; 25,000+ repositories
Stat: 444 | packages, 1,381 versions, in the keyv wave
- Period: event-stream 3.3.6 on 9 September 2018 to the tensorlake malware advisory on 8 October 2026.
- axios: 100 million weekly downloads (Socket); version 1.14.1 was on the registry for under 3 hours.
- State-linked: GitHub tied a 2023 campaign to Jade Sleet/TraderTraitor; Socket attributes 338+ packages to Contagious Interview.
Caption: Download and package counts are the vendors' own figures (Aikido, Wiz, Socket), graded Confirmed as vendor counts.
Notes: Period [1][54]. chalk and debug, Aikido, September 2025 [21]. Shai-Hulud, September 2025 [70]. Shai-Hulud 2.0, about 700 to nearly 800 packages by Wiz's count, November 2025 [26]; CERT-FR more than 700 by 26 November [29]. keyv wave, August 2026 [47]. axios [36][35]. Jade Sleet [12]. Contagious Interview [24].

## PART 2 | Eight years moved from one maintainer to self-spreading worms

| Date | Event | What happened |
|---|---|---|
| Sep 2018 | event-stream | Handover by social engineering; flatmap-stream stole wallet keys |
| Oct to Nov 2021 | ua-parser-js, coa, rc | Account takeovers; coa live about 72 minutes |
| Jan to Mar 2022 | colors, faker, node-ipc | Maintainers sabotaged their own packages |
| Sep 2025 | chalk, debug and 16 others | 2FA-reset phishing from npmjs.help; a browser wallet clipper |
| Sep and Nov 2025 | Shai-Hulud and 2.0 | Stolen tokens republish the victim's other packages |
| Mar 2026 | axios | A RAT on the lead maintainer's PC; 1.14.1 live under 3 hours |
| Aug 2026 | keyv and CHAINDROP | A compromised GitHub account; releases with valid provenance |
Caption: Rows are Confirmed from maintainer post-mortems, GitHub, CISA and vendor research; the operational record has 28 rows.
Notes: event-stream [1][2]. ua-parser-js [4][5]; coa [6][7]; rc [8]. colors and faker [9]; node-ipc 2022 [10][11]. chalk and debug [20][21]. Shai-Hulud [22][70][23]; 2.0 [26][27][28]. axios [35][33][34][36]. keyv and CHAINDROP [47][48][49][50][51].

## PART 2 | The 2025 worms turned one stolen token into hundreds of packages

Left: Shai-Hulud, September 2025
- @ctrl/tinycolor 4.1.1 and 4.1.2 carried bundle.js, which ran TruffleHog and dumped environment secrets.
- It pushed a shai-hulud-workflow.yml workflow and exfiltrated to webhook.site and a public repository.
- It republished up to 20 of each victim's packages; GitHub removed 500+.
Right: Shai-Hulud 2.0, November 2025
- Ran as a preinstall script, even when installation failed (Check Point).
- Registered infected machines as self-hosted runners named SHA1HULUD.
- Tried to destroy the home directory when it could not steal or exfiltrate.
- At PostHog, the npm token was taken days earlier through a pull_request_target workflow.
Caption: Unit 42 assessed with moderate confidence that an LLM generated the first wave's bash script.
Notes: Shai-Hulud [22][70][23]; LLM assessment [27]. Shai-Hulud 2.0 [26][27][28][29]; PostHog bot PAT on 18 November, attack on 24 November [30].

## PART 2 | In 2026 the attackers went through the controls npm had added

- TanStack, 11 May: 84 malicious versions across 42 packages, published through the project's own trusted-publisher binding.
- keyv, 4 August: releases carried valid provenance signed by GitHub Actions; at least 444 packages were hit (Aikido).
- axios, 31 March: social engineering and a RAT on the lead maintainer's PC exposed the npm credentials.
- Red Hat, May to June: a malicious VS Code extension compromised the GitHub account behind 32 packages.
- node-ipc, 14 May: a credential stealer that runs on require(), not at install.
- CHAINDROP spread only through tokens set to bypass 2FA, which could still publish until a change targeted for January 2027.
Notes: TanStack [43]. keyv [47]. axios [35]. Red Hat Cloud Services [46]. node-ipc 2026 [44][45]. CHAINDROP [48]; bypass-2FA change of 31 July 2026 and January 2027 target [84]; the link between the two dates is Inferred.

## PART 3 | Almost every path ended in a legitimate publish

| Path to publish rights | Cases |
|---|---|
| Social engineering of a maintainer handover | event-stream (2018) |
| Account hijack | ua-parser-js, coa, rc (2021) |
| The maintainer, on purpose | colors, faker, node-ipc 10.1.x (2022) |
| Phishing that impersonated npm | eslint-config-prettier; chalk, debug and 16 others (2025) |
| CI workflow injection under pull_request_target | Nx, PostHog (2025); TanStack (2026) |
| Tokens stolen and reused by worms | Shai-Hulud, 2.0, Mini Shai-Hulud, CHAINDROP |
| Malware on the maintainer's own machine | axios (a RAT); Red Hat (a VS Code extension) |
| Packages the attacker created | Contagious Interview personas; tea.xyz token farming |
Caption: Ultralytics on PyPI (December 2024) used the cache-poisoning step that hit TanStack 17 months later.
Notes: Paths [1][5][58][9][10][17][20][21][18][30][43][22][26][161][48][35][46][24][25]. lottie-player's compromised token is Reported [14]. Rspack, Gluestack and node-ipc 2026 do not state a path [15][16][44]. Ultralytics [55].

## PART 4 | Install scripts ran most payloads, and npm 12 now blocks them

| Execution point | Cases |
|---|---|
| preinstall script | coa (2021); Shai-Hulud 2.0; Mini Shai-Hulud; CHAINDROP |
| During npm install, through a bundled script | Shai-Hulud bundle.js; the Nx postinstall |
| On require(), with no install script | node-ipc 2026; the Gluestack RAT (trigger Inferred) |
| In the browser | chalk/debug wallet clipper; lottie-player CDN popups |
| Through an editor or AI tool | Nx Console; Claude and Gemini CLIs; CHAINDROP hooks |
| Inside CI with the project's own credentials | Shai-Hulud workflow; SHA1HULUD runner; TanStack |
Caption: allowScripts governs only install-time scripts, so the require() stealer and the browser clipper sit outside it (Inferred).
Notes: preinstall [7][28][38][48]. Bundled script [22][19]. require() [44][16]. Browser [21][13]. Editors and AI tools [19][18][48]. CI [22][26][43]. allowScripts scope [78]; Nx advisory on transitive, agent and editor installs [19].

## PART 5 | The registry hardened one step at a time, 2022 to 2026

| Date | Change |
|---|---|
| Feb 2022 | 2FA for top-100 maintainers; top-500 from May; high-impact packages from November |
| Sep 2023 | Provenance GA for GitHub Actions and GitLab CI/CD |
| Jul 2025 | Trusted publishing with OIDC GA |
| Dec 2025 | Every classic token revoked; npm login issues two-hour session tokens |
| May 2026 | Staged publishing GA, behind a maintainer's 2FA approval |
| Jul 2026 | npm 12 blocks dependency scripts; publish-time malware scanning |
| Sep 2026 | Read and write (stage only) granular tokens |
Caption: Removing direct publishing for bypass-2FA tokens is targeted for January 2027.
Notes: 2FA [60][62][65]. Provenance [67][68]. Trusted publishing [69]. Classic tokens [71][72][73]. Staged publishing [77]. npm 12 [79][81]; malware scanning [82][83]. Stage-only tokens [86]. Bypass-2FA [84].

## PART 5 | npm, pnpm and Yarn now block dependency builds by default

Left: npm
- npm 12.0.0, 8 July 2026: dependency lifecycle scripts blocked unless the root allowScripts policy allows them.
- allow-git and allow-remote default to none; approvals pin to pkg@version.
- min-release-age, in days, since npm 11.10.0.
Right: pnpm and Yarn
- pnpm 10.0.0 (January 2025) stopped running dependency lifecycle scripts by default.
- pnpm 11.0.0: a one-day minimumReleaseAge, blockExoticSubdeps and strictDepBuilds on by default.
- Yarn Berry: enableScripts false for third-party postinstall; npmMinimalAgeGate since 4.10.0.
Caption: Current on 3 November 2026: npm 12.2.1, pnpm 12.16.1, Yarn Berry 4.18.1 and bun 1.4.4.
Notes: npm 12 [79][80]. allow-git and allow-remote [79]; approvals pinned to pkg@version [98][106]. min-release-age [74]. pnpm 10.0.0 [89]; pnpm 11.0.0 [93]. Yarn [130][95]. Current releases [97].

## PART 6 | Most bad versions were gone within hours, so a short wait works

Stat: 72 min | coa on the registry in 2021
Stat: <3 h | axios 1.14.1, 00:21 to 03:15 UTC
Stat: 6-8 min | Mini Shai-Hulud detection after each publish
Stat: 20-26 min | TanStack detection after publish
- pnpm's release note says such attacks are usually discovered and removed within an hour.
- A gate of a day or more would have skipped every version in the exposure table; event-stream, live 9 September to 26 November 2018, is the exception (Inferred).
- A malicious version has no CVE on day one; Dependabot raises malware advisories only when malware alerts are on.
Notes: coa, about 14:12 to 15:24 CET [7]. axios [35]. Mini Shai-Hulud [38]. TanStack [43]. Nx, about 4 hours [18]. pnpm 10.16.0 [90]. Gate reading Inferred from [1][7][18][35][38][43]. Malware advisories and alerts [149][63]. npm's publish-time scan holds new versions about five minutes [82].

## PART 6 | Provenance proves where a package was built, not that it is safe

Left: Where it caught the attack
- Nx detected its bad versions because they lacked provenance.
- eslint-config-prettier users noticed releases with no matching commits and no provenance.
- pnpm's trustPolicy: no-downgrade turns that tripwire into an install failure.
Right: Where it said nothing
- TanStack published through its own OIDC trusted-publisher binding.
- keyv's releases had valid provenance signed by GitHub Actions.
- npm says provenance does not guarantee a package has no malicious code.
Caption: A pipeline that runs attacker code under pull_request_target defeats SLSA Build L2 and L3 alike (Inferred).
Notes: Nx [18][19]. eslint-config-prettier [17]. trustPolicy [91]. TanStack [43]; trusted publishing generates provenance [69], so that they carried it is Inferred. keyv [47]. npm documentation [121]. SLSA [144]; the pipeline reading is Inferred from [43][18].

## MITRE MAPPINGS | ATT&CK models the npm worms directly, as S9008 and S9043

| Id | Technique | Tie to the npm record |
|---|---|---|
| T1195.001 | Compromise Software Dependencies and Development Tools | S9008, S9043, G1056; G0082 (Axios and Mastra) |
| T1546.016 | Installer Packages | coa and Shai-Hulud 2.0 preinstall hooks |
| T1677 | Poisoned Pipeline Execution | shai-hulud-workflow.yml; Nx workflow injection |
| T1528 | Steal Application Access Token | Nx NPM_TOKEN; TanStack OIDC token |
| T1567.001 | Exfiltration to Code Repository | Shai-Hulud, Sha1-Hulud and keyv repositories |
| T1204.005 | Malicious Library | Contagious Interview packages (G1052) |
Caption: S9008 maps 33 techniques and S9043 55; no ATT&CK campaign covers npm; the layer has 30 entries. MITRE notice in the notes.
Notes: ATT&CK v20.0. T1195.001 [162][22][35][38]. T1546.016 [164][7][26]. T1677 [160][22][18]. T1528 [160][18][43]. T1567.001 [165][22][27][47]. T1204.005 [163][24]. S9008 and S9043 [160][161]; no campaign [166]. Navigator layer npm-supply-chain-attacks.json: score 100 for ATT&CK-published links, 50 for the study's labelled inferences. CWE-506 [6][45]; CAPEC-538 and CAPEC-695 [167][168]; D3FEND for T1195.001 and T1552 [166][170]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | When a wave lands, find every copy before you rotate

Left: Find and check
- Walk every lockfile and global install root, including each Node version nvm installed.
- npm ls <pkg>@<ver> --all, npm query with --expect-result-count=0, pnpm ls -r, yarn why.
- Compare against the Wiz CSVs (795 rows for 2.0, 446 for keyv) and Datadog's axios checker.
Right: Clean and rotate
- npm ci --ignore-scripts from a clean lockfile, then clear the cache.
- Revoke npm tokens, especially bypass_2fa automation tokens; gh auth logout does not revoke.
- Hunt Sha1-Hulud repositories, SHA1HULUD runners and CHAINDROP's .claude and .vscode hooks.
Caption: Lab, 4 November 2026: overrides on direct dependencies failed with EOVERRIDE; change the dependency itself.
Notes: Step 1 [137][138][136][109][125][128]. Step 2 [109][110][111][125][128][129]; Wiz CSVs [32][52]; Datadog [37]; CISA on nested dependencies and cached copies [23]. Step 4 [117][118][26]. Step 5 [119][48][151][155][26]. Lab capture [175]; overrides [116]; lodash up to 4.17.23 flagged, fix 4.18.1 [175].

## DEFENDER VIEW | Harden install, CI and publish so a stolen token is not enough

- Install: npm 12 or ignore-scripts, a short allowScripts list, a release-age gate, allow-git=none and npm ci in CI.
- CI: no untrusted code under pull_request_target, a read-only GITHUB_TOKEN, actions pinned to full SHAs or a workflow lockfile.
- Publish: trusted publishing over OIDC, "Require two-factor authentication and disallow tokens", staged publishing, stage-only tokens.
- Accounts: 2FA with WebAuthn security keys, set to auth-and-writes.
- Edge: a proxy that can quarantine (Verdaccio, JFrog Curation, Sonatype Firewall), with private scopes listed first.
- Alerts: Dependabot malware alerts, the dependency review action and an SBOM per build.
Notes: Install [79][107][74][126][130][117]. CI [139][145][55]; OWASP CICD-SEC-3 [173]. Publish [122][77][85][86]. 2FA [123]. Edge [140][141][142]; private scopes before the catch-all as the dependency-confusion defense is Inferred [140][3]. Alerts [76][150][120].

## CROSS-CUTTING THEMES | The developer machine became the soft target

- **The trust unit is a person with a login.** Every control that worked raised the cost of using a maintainer's rights.
- **Install time is closing.** What is left runs on require(), in the browser or through editors and agents.
- **Speed cuts both ways.** Worms published hundreds of versions in hours; most bad versions were found in minutes to hours.
- **Provenance is not a verdict.** It caught Nx and eslint-config-prettier; it said nothing about TanStack or keyv.
- **CI is part of the supply chain.** pull_request_target, shared caches, runner memory and self-hosted runners recur.
- **The developer machine is the soft target.** A RAT, a VS Code extension, AI CLIs, editor tasks and agent hooks.
Notes: Themes are the study's Inferred readings. Login [58][73][122][77]. Install time [79][89][130][44][21][19][48]. Speed [22][47][38][43][90]. Provenance [18][17][43][47]. CI [18][30][43][55][26]. Developer machine [35][46][18][48].
