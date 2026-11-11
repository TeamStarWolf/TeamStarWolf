# Slide plan: Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab

- Study: case-studies/EXPOSURE_CHECKS_2026_11.md
- Cover title: Thirty Days of Exposure Checks / Version and Configuration / Evidence from the Lab
- Subtitle: A month of KEV listings checked on matched pairs, and why a version string only starts the check
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/EXPOSURE_CHECKS_2026_11.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A version string starts an exposure check; it does not end it

- CISA added 34 vulnerabilities to KEV between 4 October and 3 November 2026.
- The lab built a check for the 24 with a container image or a local check, plus Ghostcat.
- Most ran on matched pairs on loopback: one build below the vendor's fix, one at or above it.
- Fixed and vulnerable builds often print the same banner, and several flaws need one configuration line.
- A workaround changes the configuration and leaves the version a scanner reads untouched.
Caption: Evidence grade: Confirmed for the records, Reported for the AhsayCBS exploitation write-ups, Demonstrated for the lab.
Notes: KEV window [4]. Lab coverage and pairs [43]. Banners and preconditions [23][28][43]. Workarounds [43].

## KEY FACTS | Thirty-four listings in a month, five of them years old

Stat: 34 | KEV additions, 4 October to 3 November 2026
Stat: 24 | Entries with a container image or a local check
Stat: 5 | CVEs from 2015 to 2023 listed on one day
Stat: 3 | Days to the due date for every entry in the study
- Appliance entries (Ivanti, Cisco, Fortinet, PAN-OS, BeyondTrust, VeloCloud, ESX) had no lab target.
- No exploit that changes a system was run; two checks sent benign behavior probes.
- Cleanup removed every container and image; 14 dangling volumes were left on the host.
Notes: KEV counts, dates and appliance entries [4]. Lab coverage and probes [43]. Cleanup [44].

## PART 1 | What the lab could reach, and what it could not

| Outcome | Plans |
|---|---|
| Version verdict on a pair or a real host | WordPress, AhsayCBS, ONLYOFFICE, Windows Shell |
| Host inventory, no version verdict | Fragnesia, SiteGuard |
| Blocked: no runnable vulnerable target | BIND, Strapi, NetScaler |
| Inconclusive: precondition not settled | Struts, Confluence |
| Skipped: needs a host the lab lacked | Siemens Software Center |
Caption: The edge appliances in the window are the part of the list a container lab cannot reach.
Notes: Outcomes from the capture files per CVE [43]. Appliance entries [4].

## PART 2 | ONLYOFFICE: the build is old, and the JWT setting decides

Left: The record
- Traversal with code execution in /upload before 5.6.3, only when JWT is in use.
- Listed on 8 October 2026, more than five years after NVD published it.
Right: The lab
- The package database read 5.6.2-2 and 5.6.3-2.
- JWT was on in both; the first regex missed the minified api.js.
Caption: Upgrade to 5.6.3 or later, and read the token block in local.json.
Notes: NVD record and changelog [23][24]. KEV listing [4]. Lab readings [43].

## PART 2 | Windows Shell and AhsayCBS: read the build, not the change record

Left: Windows Shell, CVE-2026-96951
- A Mark-of-the-Web bypass, exploited; Edge added in revision 2.
- Build 26300.9818 against the fixed 26300.9711 compared True.
Right: AhsayCBS, CVE-2026-105133 and -105134
- version.txt read 10.3.4.0 and 10.3.4.45.
- 10.3.4.0 is a first patch Ahsay itself calls incomplete.
Caption: Compare as a version, not as text, and do not trust a first hotfix to be the fix.
Notes: Microsoft and NVD [20][21]. Workstation readings [43]. AhsayCBS records [14][16]. Ahsay notice [15]. Container readings [43].

## PART 2 | SiteGuard, Fragnesia and WordPress: three host-level readings

| Flaw | What the lab read | What it means |
|---|---|---|
| SiteGuard | No package, config or process; pgrep matched itself | Filter on the executable name |
| Fragnesia | Running 7.1.5; fallback 6.19.14 installed | The fallback sits in an affected range |
| WordPress | 7.1.3 and 7.1.4; a deny rule turned 302 into 403 | The rule changed a status, not the version |
Caption: Collect evidence before patching: SiteGuard warns that the update may erase attack traces.
Notes: SiteGuard [10][11][43]. Fragnesia ranges and lab [6][8][43]. WordPress [1][2][3][43].

## PART 3 | The plans that did not finish, and why

- BIND: the vulnerable image uses schema 1 manifests, which Docker 28 cannot pull.
- Strapi: the image installs itself on first boot, and the quarantined lab gave it no network.
- NetScaler: the CPX image needs a licence acceptance that is the owner's to give.
- Struts: the version was in range, but the DMI setting was not found.
- Confluence: both instances stayed in the setup wizard, which needs a licence key.
Caption: A "blocked" with a reason is more useful than a silent gap.
Notes: BIND [25][26][27][43]. Strapi [30][31][32][43]. NetScaler [33][34][43]. Struts [28][29][43]. Confluence [35][36][43].

## PART 4 | When the version string lies

| Product | Same on both builds | What told them apart |
|---|---|---|
| ProFTPD | The 1.3.6rc1 (git) banner | Behavior: the patched build refused |
| Node.js | Bundled Brotli 1.2.0 | The Node version |
| GitLab | The bundled Ruby string | version-manifest.txt |
| Plex | A parser read the XML prolog | Only the version attribute |
| PHP | X-Powered-By after the workaround | The configuration check |
Caption: Banners find hosts; they never clear them.
Notes: Capture files for CVE-2015-3306, CVE-2026-111497, CVE-2026-97229, CVE-2026-96652 and CVE-2026-109618 [43].

## PART 5 | From the KEV feed to a per-host verdict

- Build the list: filter the KEV feed's dateAdded to the last 30 days.
- Join the records: CWE and ranges from NVD, fixed builds from the vendor.
- Read the installed version from the package manager or the product's manifest.
- Compare with a version-aware tool: sort -V, dpkg --compare-versions, PowerShell [version].
- Read the precondition line, then record any workaround separately.
Caption: The sequence is this study's summary of what the captures show.
Notes: KEV feed [4]. Record disagreements [16][17][30][31]. Commands as captured [43]. The sequence is Inferred.

## PART 5 | The traps the lab hit

| Trap | Where |
|---|---|
| Same banner on both builds | ProFTPD, Node.js, GitLab |
| A parser matching the wrong field | Plex |
| A regex that never matched | ONLYOFFICE api.js |
| A process check matching itself | SiteGuard |
| A threshold from the wrong distribution | Fragnesia on Kali |
| A default that is not the setting | Struts DMI |
Caption: Test a check on a known-fixed and a known-vulnerable target before trusting it across a fleet.
Notes: Each trap is a capture [43]. The lesson is Inferred.

## PART 6 | Overstated and understated

Left: Overstated
- A version match as proof of exposure.
- A base score as the measure of urgency.
- A check's own "FIXED" line.
Right: Understated
- Old flaws on three-day clocks.
- First hotfixes the vendor calls incomplete.
- Fallback kernels and mitigated hosts.
Caption: For a KEV entry, the due date and SSVC "active" decide the priority; the base score decides little.
Notes: Preconditions [23][28][43]. Scores [1][3][4]. Kernel threshold [43]. Old listings [4]. Ahsay [15]. Fallback kernel [6][43]. The readings are Inferred.

## MITRE MAPPINGS | Twelve techniques bound from the records

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | ONLYOFFICE, AhsayCBS, Confluence, WordPress, Struts |
| T1068 | Exploitation for Privilege Escalation | Fragnesia; SiteGuard, Inferred |
| T1505.003 | Web Shell | KEV's Fragnesia chain; AhsayCBS, Reported |
| T1553.005 | Mark-of-the-Web Bypass | Windows Shell |
| T1499.004 | Application or System Exploitation | The BIND crash |
Caption: Also bound: T1566.001, T1204.002, T1059.004, T1105, T1496.001, T1005, T1595.002. ATT&CK v20.0; no group, software or campaign. Notice in notes.
Notes: Techniques [1][4][7][8][10][12][14][16][17][18][20][23][25][26][29][35][36][37][38][40][43]. CWE and CAPEC [41]. D3FEND [39][42]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What a month of checks teaches

- **Version plus precondition is the unit of exposure.** The clearest verdicts read both.
- **The record is several records.** Vendor, NVD, GitHub and CISA disagreed three times.
- **Safe labs produce honest gaps.** Each blocked plan has its reason written down.
- **The checker is code, and code has bugs.** Matched pairs caught them.
- **The edge is still the blind spot.** Appliances need the vendor's own command on the device.
Notes: Preconditions [43]. Disagreements [1][3][4][16][17][30][31]. Gaps [43]. Checker bugs [43]. Edge [4]. Lessons are Inferred.
