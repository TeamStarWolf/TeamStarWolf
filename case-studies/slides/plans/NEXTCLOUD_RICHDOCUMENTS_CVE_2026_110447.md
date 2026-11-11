# Slide plan: Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix

- Study: case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md
- Cover title: Collabora Built-in CODE Server / CVE-2026-110447 / Lab-Verified Exposure and Fix
- Subtitle: A convenience app on Nextcloud, a silent fix, and attacks that came before the warning
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An anonymous request could run a command on the Nextcloud host

- The flaw is in richdocumentscode, the Built-in CODE Server app, not in the Nextcloud Office connector.
- Its proxy.php built the server's launch command with request-derived values inside a double-quoted bash -c string.
- Whenever the bundled server was down, a request could run a command as the web server user.
- The fix shipped silently on 11 September 2026; the advisory came 33 days later.
- Victims reported web shells from 10 September; CISA added the CVE to KEV on 23 October.
Caption: Evidence grade: Confirmed for the flaw, fix and exploitation; Reported for the ransomware claim; Demonstrated for the lab.
Notes: The app and the flaw [1][2][9]. Silent fix and advisory delay [1][11][13]. First logged attack [18]. KEV [4]. Lab [43][44][45][46].

## KEY FACTS | Every record agrees it is critical and exploited

Stat: 9.8 | CVSS 3.1, NVD
Stat: 9.2 | CVSS 4.0, CNA and Collabora
Stat: 33 | Days from the fixed release to the advisory
Stat: 3 | Days KEV allowed to fix it
- Weakness: CWE-78, OS command injection, in the advisory, the CVE record, NVD and KEV.
- Affected: richdocumentscode below 26.4.303; standalone Collabora Online is not affected.
- KEV: added 23 October 2026, due 26 October, ransomware use Unknown, forensic triage Yes.
Notes: Scores [1][2][3]. 33 days is date arithmetic from 11 September to 14 October [1][13]. KEV [4]. CWE-78 [1][2][3][4]. Affected and not affected [1].

## PART 1 | Quoting each value was not enough

- startCoolwsd() built two options from the request: the font-config URL and the lok_allow host.
- Each value went through escapeshellarg(), which wraps it in single quotes.
- Both were then placed inside an outer double-quoted bash -c string.
- Inside double quotes single quotes are literal, so the outer shell still expanded command substitution.
- The attack needs the bundled server, coolwsd, to be down: after a restart, an upgrade or a crash.
Caption: The same proxy produced CVE-2025-66208 in 2025; the advisory says that fix does not prevent this one.
Notes: Root cause in 26.4.302 [9]. Outer-shell expansion is Inferred from [9][12]. Precondition [1]. CVE-2025-66208 [8][1].

## PART 1 | The fix, and the hardening that followed

| Release | Date | Change |
|---|---|---|
| 26.4.302 | 31 Aug 2026 | Vulnerable |
| 26.4.303 | 11 Sep 2026 | Whole inner command escaped before bash -c |
| 26.4.402 | 24 Sep 2026 | Options passed as separate arguments |
| 26.4.502 | 23 Oct 2026 | Stops coolwsd when the app is disabled |
Caption: The fix commit is titled as a tidy-up; neither it nor the changelog says security. 26.4.303 and later need Nextcloud 30.
Notes: Fix commit 6cc8dae [11]. Compare [12]. Releases and dates [13]. Hardening [16][17]. Changelog [14]. Nextcloud 30 floor [15].

## PART 2 | Attackers were ahead of the fix and the warning

| Date | Event |
|---|---|
| 10 Sep 2026 | First logged attack on a server running 26.4.302 |
| 11 Sep 2026 | 26.4.303 released with no security note |
| 14 Sep 2026 | A second source hits a host already on 26.4.303 |
| 14 Oct 2026 | CVE, NVD and Collabora advisory published |
| 23 Oct 2026 | CISA KEV listing; 26.4.502 released |
| 30 Oct 2026 | Attack reported on a disabled, not-updated app |
Notes: Issue #354 reports [18]. Releases [13]. CVE and NVD [2][3]. Advisory [1]. KEV [4]. Disabled app report and vendor reply [18].

## PART 3 | What the attackers did, from the victims' own reports

- Unauthenticated GET requests to proxy.php carrying an encoded shell command in the path.
- One-line PHP web shells dropped in the app folder.
- Callbacks to webhook.site carrying the host's system details.
- On one host, searches for password databases and coin wallets.
- No vendor, CERT or research firm has attributed the activity, and no primary source counts the victims.
Caption: The ransomware link rests on one unverified issue comment; KEV lists ransomware use as Unknown.
Notes: Victim reports on issue #354 [18]. Forum backdoor name, single user, Reported [19]. No attribution or count [1][3][4][18]. Ransomware claim Reported [18][27]; KEV [4].

## PART 4 | The lab told vulnerable from fixed without touching proxy.php

Left: What the lab saw
- A version floor flagged 26.4.302 VULNERABLE and 26.4.303 FIXED.
- The fixed proxy.php escapes the whole inner command before bash -c.
- Neither container ran coolwsd, the state the advisory calls exploitable.
Right: How the lab ran
- Two Docker containers, port 80 published only on loopback.
- The vulnerable public image and the official image with the official 26.4.303 release.
- Every step read state; no request was sent to proxy.php.
Caption: Lab of 4 November 2026. Exploitation was not exercised.
Notes: Setup [43]. Version check [44]. No coolwsd process [45]. Fix in the running file [46].

## PART 4 | Two traps in the obvious checks

| Check | Lab result | Lesson |
|---|---|---|
| occ app:list | Fails on an uninstalled instance | Read info.xml directly |
| HEAD /apps/.../info.xml | 200 on 26.4.302, 404 on 26.4.303 | Try /custom_apps/ too |
| occ integrity:check-app | Silent, exit 0 | That is a pass |
| proxy.php in access logs | 0 requests on both | Version scans stay quiet |
Caption: The 404 came from the folder layout, not the fix: the official image keeps App Store apps in custom_apps/.
Notes: occ failure [43][44]. Remote probe [45]; custom_apps layout [24]. Integrity check [45][22]. Detection silence [46].

## DEFENDER VIEW | Find every copy, then upgrade or remove

Left: Find
- Check richdocumentscode and richdocumentscode_arm64.
- Look in both apps/ and custom_apps/.
- Read the version from appinfo/info.xml; occ answers only on an installed instance.
Right: Fix
- Upgrade to 26.4.303 at minimum, 26.4.502 preferred.
- On Nextcloud 29 or older, upgrade Nextcloud first or remove the app.
- Disabling the app is not a fix.
Caption: After removal, point the Nextcloud Office connector at a standalone Collabora Online server.
Notes: App ids and folders [20][24]. Version read [44][45]. occ commands [21]. Upgrade or remove [1][17]. Nextcloud 30 floor [15]. Standalone servers unaffected [1].

## DEFENDER VIEW | Treat an exposed host as possibly compromised

| BOD 26-04 step | For CVE-2026-110447 |
|---|---|
| Scoping | Every host with either app id, enabled or disabled |
| Preserve evidence | Access logs from 10 September 2026, nextcloud.log, coolwsd logs |
| Patch | 26.4.303 or later, or remove the app |
| Contain | Block known sources and outbound webhook.site |
| Triage | Integrity check, web-shell file search, log search |
Caption: Upgrading does not remove a web shell already planted; keep a copy, delete it, and rotate secrets the web server user could read.
Notes: KEV forensic triage flag [4]. BOD 26-04 steps [5]; the right-hand column is Inferred from [1][18][20][22]. Lingering shells [18].

## PART 7 | Signals arrived in the wrong order

- The fix came a month before the warning, while victims posted web shells on a public issue.
- The CVE arrived with KEV nine days behind; by then the question was whether you were hit.
- 9.2 and 9.8 are both critical; the precondition covers routine restarts and upgrades.
- Inventories that record only enabled apps undercount exposure.
- End-of-life Nextcloud turns the patch into a removal.
Notes: Fix and advisory dates [1][13][18]. CVE and KEV [2][4]. Scores [2][3]. Precondition [1]. Disabled apps [1][18]. Nextcloud 30 floor [15]. The conclusions are Inferred.

## MITRE MAPPINGS | One exploitation technique, five steps from the victims' reports

| Id | Technique | Tie to CVE-2026-110447 |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated proxy.php requests |
| T1059.004 | Unix Shell | Decoded command piped to sh |
| T1505.003 | Web Shell | PHP shells in the app folder |
| T1027 | Obfuscated Files or Information | Base64 command in the path |
| T1140 | Deobfuscate/Decode Files or Information | Command decoded on the host |
| T1082 | System Information Discovery | System details in the callback |
Caption: ATT&CK v20.0. CWE-78; CAPEC-88 and CAPEC-650; no group, software or campaign is bound. MITRE notice in the notes.
Notes: Techniques [18][19][29][30][31][32][33][34]. CWE and CAPEC [36][37][38]. D3FEND [39][40]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Convenience components carry production risk

- **A test server ran in production.** The app calls itself for local testing, yet it was internet-facing at several victims.
- **Escape the whole command, not each value.** The durable fix passes each option as its own argument.
- **Silent fixes shift the burden to the defender.** Update cadence is a security control.
- **Victims were the early warning.** Watch the issue trackers of the components you expose.
- **Web shells outlive patches.** Upgrade, then hunt.
Notes: App summary [43]; victims [18]. 26.4.402 hardening [16]. Silent fix [11][13][14]. Issue #354 [18]. Lingering shells [18]. Lessons are Inferred.
