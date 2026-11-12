# Slide plan: Chrome Isolated Web Apps: Vulnerabilities and Abuse in 2026

- Study: case-studies/CHROME_ISOLATED_WEB_APPS_2026.md
- Cover title: Chrome Isolated Web Apps / Vulnerabilities and Abuse / in 2026
- Subtitle: Thirteen CVEs found by Google, two research toolkits, and no exploitation on record
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHROME_ISOLATED_WEB_APPS_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | No IWA hack on record, but a real control plane to get right

- Isolated Web Apps are signed, bundled Chrome apps that may use APIs the open web cannot.
- 2026 brought ten CVEs in the IWA component and three in Controlled Frame, all found by Google.
- None is in KEV, and every CISA SSVC entry records exploitation none.
- Researchers at Praetorian and SpecterOps built IWA sidecars for command and control.
- The year's eight exploited Chrome zero-days were all outside IWA code.
Caption: Evidence grade: Confirmed for design, policies and CVEs; Demonstrated for the research tools; Reported for attributions.
Notes: Model [1][2][3]. CVEs [25][31][35][39][43]. KEV and SSVC [45][38][49]. Research [68][72]. Zero-days [45].

## KEY FACTS | A small, internally found slice of Chrome's security work

Stat: 13 | IWA and Controlled Frame CVEs in 2026
Stat: 0 | Of them in CISA KEV
Stat: 8 | Exploited Chrome zero-days, none IWA
Stat: 8.8 | Top CVSS, CVE-2026-11102
- Every IWA bug credits Google as reporter; Chromium rated each Medium or Low.
- Default on only on ChromeOS; desktop force-install is still marked future_on.
- Every 2026 IWA fix is in Chrome 157.0.8103.38 and later.
Notes: Counts [25][31][35][39][43][44][50]; the union of thirteen is Inferred. KEV [45]. Score [26][28]. Defaults [9][11][59]. Build [43][52].

## PART 1 | An app identified by its signing key, not its server

- An IWA ships as a Signed Web Bundle, installed like an app and updated as a new signed bundle.
- Its origin, isolated-app://<Web Bundle ID>/, derives from the developer's public key.
- Strict isolation headers, a mandatory CSP and Trusted Types are required.
- Each IWA origin gets its own storage partition.
- A compromised key is "a troublesome situation" in Google's words; rebinding is a last resort.
Caption: The model removes the live web server from the trust chain and puts the key, the update host and Google's allowlist in its place (Inferred).
Notes: Packaging [1][2][3]. Identity [4][1]. Isolation [5][2][19]. Key compromise [62].

## PART 1 | Two APIs that cannot be made safe for the open web

| API | What it gives an IWA |
|---|---|
| Direct Sockets | Raw TCP, UDP and server sockets |
| Controlled Frame | Embed, script and intercept any site |
| Sub apps (Chrome 152) | Several apps under one install |
| Unframed mode (Chrome 152) | The app fills the whole window |
Caption: The Controlled Frame explainer warns that an embedding IWA could observe keystrokes and cookies inside the frame.
Notes: Direct Sockets [8]. Controlled Frame [7]. Chrome 152 features [22][16]. Warning [7].

## PART 2 | The defaults are permissive where IWAs run

| Policy | Default |
|---|---|
| IsolatedWebAppUserInstallationEnabled | True (ChromeOS 146+) |
| DefaultDirectSocketsSetting | Allow for IWA origins |
| DefaultControlledFrameSetting | Allow for IWA origins |
| DefaultSubAppsWithoutPromptsSetting | Ask |
| IsolatedWebAppInstallForceList | ChromeOS 128+; desktop future_on |
Caption: Google's allowlist governs admin installs from Chrome 143; developer mode is exempt.
Notes: Policies [11][12][13][14][16]. Allowlist [20][21]. The reading of the defaults is Inferred from [12][13][14].

## PART 3 | Ten IWA-component CVEs, each found by Google

- Key rotation: CVE-2026-11102, a potential bypass that accepts a compromised previous key.
- Mandatory CSP bypass through a service worker: CVE-2026-13886.
- Cross-IWA checks bypassed: CVE-2026-17780 and CVE-2026-87468.
- Sandbox origin bypass through a data: URL iframe: CVE-2026-87577.
- UI spoofing and a cross-origin leak: CVE-2026-14042, -17909, -87540, -121172, -121206.
- Controlled Frame: CVE-2026-17743, -87513 and -87435.
Caption: The public issue titles cluster on the trust machinery: key rotation, CSP, navigation and sandbox rules.
Notes: Issue titles [28][33][37][40][41][42]. Fix posts [25][31][35][39][43]. Controlled Frame [35][39][49].

## PART 3 | Labels, scores and build strings mislead

Left: What the records say
- From September, Chrome Releases labels the component "Isolated".
- An NVD search for "Isolated Web Apps" finds five of the ten.
- CVE-2026-11102: Chromium Medium, NVD and CISA-ADP 8.8 High.
Right: What a scanner does with it
- Rules keyed on the old label miss half the record.
- CVSS bands put Chromium's Low bugs in Medium.
- NVD's fixed strings for 150 and 151 run one build above the Linux fix.
Caption: Rank IWA bugs on exploitation and exposure, not on the band a scanner shows (Inferred).
Notes: Labels [44][39][43]. Scores [26][27][34][38]. Fixed builds [32][35][31].

## PART 4 | The published abuse is an IWA used as a C2 sidecar

- Praetorian's ChromeAlone (DEF CON 33, August 2025) ships BLOWTORCH, an IWA SOCKS proxy.
- SpecterOps's SilentChrome-BOF and Ditto (13 August 2026) sideload an extension and an IWA.
- The IWA opens outbound TCP with Direct Sockets for the agent's SOCKS bridge.
- Both need prior code execution as the user on Windows.
- No vendor disclosure, CVE or fix is named for the technique.
Caption: Demonstrated by the researchers and not reproduced here; no adversary use is on record.
Notes: ChromeAlone [71][72]. SpecterOps [68][69][70]. Precondition [68]; for ChromeAlone Inferred from [72]. No disclosure, Inferred [68].

## PART 4 | Off by default is a default, not a barrier

- The tools switch IWA support on in the profile themselves.
- A locally registered key distribution component granted Direct Sockets in Chromium 148.
- That grant needed no developer-mode flag and raised no warning.
- Local Network Access exceptions had to be written for private and loopback reach.
- Disallowing extension Developer Mode stopped the unpacked extension from starting.
Caption: Google's developer policy forbids these patterns for publishers; it does not bind a profile tamperer (Inferred).
Notes: Research steps [68]. Key distribution role [19]. Policy [63]. Developer Mode result [68].

## PART 6 | The real 2026 zero-days were elsewhere

| CVE | Component | Fixed |
|---|---|---|
| CVE-2026-2441 | CSS | 13 Feb |
| CVE-2026-3910, -3909 | V8, Skia | 12 to 13 Mar |
| CVE-2026-5281 | Dawn | 31 Mar |
| CVE-2026-11645 | V8 | 8 Jun |
| CVE-2026-85046, -87491 | V8 | 3 and 8 Sep |
| CVE-2026-125350 | XML | 9 Nov |
Caption: Volexity ties the September chain to UTA0560, UTA0565 and JungleBamboo (APT31): Reported, and not IWA.
Notes: KEV [45][46]. Release posts [53][54][55][56][57][58][39][52]. Volexity [73][74]. Microsoft [75].

## PART 7 | Routine patching, with one IWA bug worth a look

- KEV: no entry. SSVC: exploitation none on every record.
- Chromium severity Medium or Low; CVSS 4.3 to 6.5, and 8.8 for CVE-2026-11102.
- CVE-2026-11102 deserves a closer look where allowlisted IWAs run.
- pinned_version and allowlist removal both freeze an app below its fixes.
- RelaunchNotification and RelaunchFastIfOutdated close the restart gap.
Caption: Exploitation evidence, not a feature's headline, should set browser patch urgency (Inferred).
Notes: Signals [45][38][26][30]. Priority Inferred from [28][19][62]. Pinning [11][20]. Relaunch [66][67].

## DEFENDER VIEW | Govern the control plane, then watch the profile

Left: Harden
- User IWA installs off where not needed.
- Direct Sockets and Controlled Frame blocked by default, allowed per app.
- DevTools disallowed where users do not need them.
- Extension Developer Mode disallowed.
Right: Detect on Windows
- Writes to the profile's preference files.
- Writes to the native-messaging registry keys.
- Chrome started with IWA launch arguments.
- Chrome reaching internal or loopback addresses.
Caption: Legitimate IWA use on desktop is rare, which makes these signals cheap (Demonstrated by SpecterOps; Inferred for the baseline).
Notes: Policies [12][13][14][15][17][64]. Detection [68].

## MITRE MAPPINGS | Researcher-demonstrated techniques, no adversary use

| Id | Technique | Tie to IWAs |
|---|---|---|
| T1176 | Software Extensions | IWA reconstructed in the profile |
| T1176.001 | Browser Extensions | Extension sideloaded by profile edits |
| T1090 | Proxy | Direct Sockets SOCKS bridge |
| T1071.001 | Web Protocols | WebSocket control and relay |
| T1564.003 | Hidden Window | Minimized or hidden-desktop IWA |
| T1203 | Exploitation for Client Execution | Capability in CVE records |
Caption: ATT&CK v20.0; also T1036, T1112, T1027, T1189 and context rows. S0699 Mythic, S0154 Cobalt Strike; G0128 context only.
Notes: Techniques [68][72][80][81][83]. Objects [86]. CWE and CAPEC [85]. D3FEND [82][84]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Signed code moves trust; it does not remove it

- **Trust moves.** The key, the update host and Google's allowlist replace the web server.
- **Power is the surface.** High-trust APIs make the app itself the attack surface.
- **Defaults are not walls.** A local attacker turns the feature on.
- **Browsers persist.** Extensions, IWAs and native hosts give an implant a home.
- **Labels shape sight.** A renamed component halves a keyword search.
Notes: Trust [2][19][20]. APIs [1][63][68][72]. Defaults [68]. Persistence [68][72]. Labels [44][26]. The lessons are Inferred.
