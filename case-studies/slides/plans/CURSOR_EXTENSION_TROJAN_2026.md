# Slide plan: The Trojanized Claude Code Extension on Cursor's Marketplace (October 2026)

- Study: case-studies/CURSOR_EXTENSION_TROJAN_2026.md
- Cover title: The Trojanized / Claude Code Extension / on Cursor's Marketplace
- Subtitle: About 11 hours on 29 October 2026: a tampered editor extension, an SSH backdoor that mostly failed, and no CVE to track
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CURSOR_EXTENSION_TROJAN_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Developers trusted the editor to fetch their tools

- Cursor's marketplace served a tampered Claude Code extension.
- Versions 2.1.312 and 2.1.313, Windows and macOS, for about 11 hours.
- Cursor says Anthropic did not develop these builds.
- A loader profiled the host, planted an SSH key and set up persistence.
- The reverse SSH login mostly failed for want of admin rights.
Caption: Evidence grades: Confirmed from Cursor's notice and Microsoft's analysis.
Notes: Window and builds [1]. Not developed by Anthropic [1]. Loader behavior [1][2]. Admin rights [1]. Auto-update delivery, Reported [13].

## KEY FACTS | One marketplace, two builds, no CVE

Stat: 11 | Hours the builds were served
Stat: 2 | Tampered versions, 2.1.312 and 2.1.313
Stat: 0 | CVE or KEV entries
Stat: 0 | Actors named by any primary
- Cursor's marketplace only; never the Visual Studio Marketplace or npm.
- No 2.1.313 on Open VSX, npm or GitHub.
- Cursor's current notice gives no victim count.
- How the attacker got publishing access is unpublished.
Notes: Window 09:27 to 20:35 UTC [1]. Channel [2][4][6][7][8]. KEV 2026.11.10 [9]. No actor [1][2][3][4][5]. Count [1][5][13].

## PART 1 | Eleven hours, then a week of corrections

| Date (2026) | Event |
|---|---|
| 27 Oct | Legitimate 2.1.312 on npm, GitHub, Open VSX |
| 29 Oct, 09:27 UTC | Malicious builds live on Cursor |
| 29 Oct, 20:35 UTC | Cursor pulls them, shuts marketplace |
| 30 Oct | Anthropic ships 2.1.314 |
| 30 Oct | Phorion's advisory, then its marketplace correction to Cursor |
| 30 Oct | Cursor updates IOCs and versions |
| 31 Oct | Microsoft publishes its analysis |
| 10 Nov | KEV has no entry |
Caption: Rows Confirmed from the notices and registry records.
Notes: Releases [6][7][8]. Window [1]. Phorion revisions [3]. Microsoft [2]. KEV [9].

## PART 1 | Where the record disagrees

- Duration: Cursor says about 11 hours; Ars and Anthropic say nearly 12.
- Account: Ars says Anthropic's account; Anthropic places it at Cursor.
- Discovery: Phorion, OSM and an alert from Dean Hardcastle all credited.
- Early reports blamed Open VSX, npm and the VS Code Marketplace.
Caption: The study follows Cursor's notice and Microsoft's statement.
Notes: Duration [1][2][11][13]. Account [2][11][12]. Discovery, Reported [5][12][13]. Registries cleared [2][4][6][7].

## PART 2 | The loader, at advisory level

- A function prepended to the extension's main script.
- It runs when the editor loads the file, before activation.
- Profiles host, user, Git email, public IP and env var names.
- Beacons over HTTP to port 8099.
- Adds an SSH key and tries a reverse tunnel to TCP 22.
Caption: No commands, scripts or key material are reproduced.
Notes: Injection, Demonstrated [3]. No install scripts, Reported [5]. Profile and beacon [1]. Env var names, not values [3]. Key and tunnel [1].

## PART 2 | Persistence and why the login failed

Left: What it installed
- macOS LaunchAgent named like a system monitor.
- Windows scheduled task, with a Startup-folder fallback.
- Retries about every 60 seconds.
- Linux cron entry in the indicator list.
Right: Why most hosts were spared
- Enabling SSH needs admin rights the extension lacks.
- The macOS Remote Login check fails and skips the enable step.
- No defense where Remote Login is already on.
Caption: Uninstalling the extension does not remove the persistence.
Notes: Persistence [1][2]. Admin rights [1]. Remote Login and crontab flaw, Demonstrated [3]. Uninstall [1][2].

## PART 3 | Nobody is named

| Who | What they say |
|---|---|
| Cursor | No actor named |
| Microsoft | Maps behavior, no attribution |
| Phorion | No actor stated |
| OSM | Identity unverified |
| Socket | No earlier campaign tied |
Caption: Confirmed: no primary attributes the activity.
Notes: Attribution [1][2][3][4][5]. OVHcloud CLI tampering is not linked by any opened source [4][13][17].

## PART 4 | Victims and response

- Cursor users who installed or updated in the window, Windows or macOS.
- An early "at most 5,000 users" was later removed.
- Cursor rotated keys, rebuilt its marketplace, took the server offline.
- Anthropic moved its extension straight to 2.1.314.
- No CVE, no KEV entry, no regulator filing located.
Caption: The figure and the 2.1.314 move are Reported; the rest Confirmed.
Notes: Victims [1]. Figure, Reported [5][13][15]. Response [1]. 2.1.314, Reported [15]. KEV [9].

## PART 5 | A CVE-keyed programme will not see this

- No CVE, no KEV due date, no fixed version to chase.
- 2.1.312 is both a clean release and a malicious build.
- Inventory extensions by marketplace and VSIX hash.
- Then hunt the host artifacts Cursor lists.
Caption: Triage readings Inferred from Confirmed facts.
Notes: Version overlap [1][6][8]. Hashes and indicators [1]. Hunt guidance [1][3].

## DEFENDER VIEW | Restrict, inventory, hunt

Left: Prevent
- Allow approved publishers only.
- Set an extension installation cooldown.
- Block outbound SSH from workstations.
Right: Detect and respond
- Editor helpers writing authorized_keys.
- Non-Apple com.apple.* LaunchAgents.
- SSH with remote port forwarding.
- Rotate credentials from a clean system.
Notes: Allowlist and cooldown, Microsoft [2]. Egress, Inferred from [1]. Detection guidance, Phorion [3]. Remediation [1].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- "Nearly 12 hours" against Cursor's roughly 11.
- npm, Open VSX and the VS Code Marketplace blamed.
- The SSH backdoor, which mostly failed.
Right: Understated
- Affected versions: the first notice named only 2.1.313.
- The victim count, which no primary now gives.
- The beacon still flagged credential-rich hosts.
Notes: Overstated [1][2][4][11]. Understated [1][3][5][13].

## MITRE MAPPINGS | Seventeen techniques, four mapped by Microsoft

| Id | Technique | Tie to the record |
|---|---|---|
| T1195.001 | Compromise Software Dependencies and Development Tools | Tampered extension |
| T1098.004 | SSH Authorized Keys | Planted key |
| T1572 | Protocol Tunneling | Reverse SSH tunnel |
| T1543.001 | Launch Agent | macOS persistence |
| T1053.005 | Scheduled Task | Windows persistence |
Caption: ATT&CK v20.0; CAPEC-442 and CAPEC-670; twelve more techniques and the layer in the study.
Notes: Techniques [1][2][3] with library data [18]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The developer machine is the soft target

- **Extensions are a supply chain.** Here the extension was the payload itself.
- **Trust follows the name.** As with SolarWinds and XZ Utils, a legitimate identity.
- **Registries cannot vet at publish pace.** Allowlists and pinning fit this case.
- **Early reporting misnames the channel.** Three registries blamed, then cleared.
Notes: npm and AI Threats studies [19]. SolarWinds and XZ comparison Inferred. Registry blame [4][14].
