# Slide plan: PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab

- Study: case-studies/PHP_8_4_27_CVES.md
- Cover title: PHP 8.4.27 / CVE-2026-109618 and CVE-2026-109619 / Two Fixes Verified in the Lab
- Subtitle: Two flaws in how PHP fails, one fix, and the inventory checks that miss a vulnerable build
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/PHP_8_4_27_CVES.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Two interpreter flaws let an unauthenticated request run code

- CVE-2026-109618 corrupts request state after an out-of-memory abort; on mod_php it fires before any application code.
- CVE-2026-109619 leaves worker-global state pointing at freed memory for a later request on the same worker.
- PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 fixed both on 21 October 2026.
- CISA added both to KEV on 26 October 2026, due 29 October.
- In the lab, the upgrade was the only change a version scanner could see.
Caption: Evidence grade: Confirmed for the flaws, the fix and KEV; Reported for third-party telemetry; Demonstrated for the lab.
Notes: Flaws [1][2]. Releases [8][9]. KEV [18]. Lab readings [46][47].

## KEY FACTS | Every risk signal points the same way

Stat: 9.2 | CNA CVSS 4.0 score for both CVEs
Stat: 9.8 | NVD CVSS 3.1 score for CVE-2026-109618
Stat: 5 | Days from the releases to the KEV listing
Stat: 3 | Days KEV gave agencies to fix
- Weaknesses: CWE-416, CWE-755, CWE-824 and CWE-1325 in NVD; the advisories and KEV add CWE-1419.
- Access: network, unauthenticated, no user interaction.
- Highest-risk setup: Apache mod_php; FPM, php-cgi, FrankenPHP and LiteSpeed are also at risk.
Notes: Scores [5][6]. KEV dates [18]. Weaknesses [1][2][5][18]. Access [1][2][5]. Setups [9].

## PART 1 | One flaw fires before the application runs

Left: CVE-2026-109618
- PHP aborts on out-of-memory with longjmp().
- Some request memory is reachable before it is initialized.
- Request shutdown then reads invalid state.
- Validated as RCE on mod_php with default limits.
Right: CVE-2026-109619
- A fatal error or late diagnostic leaves a stale pointer.
- A later request on the same worker uses it.
- Session upload progress is one confirmed consumer.
- Validated as RCE on mod_php and FPM.
Caption: Suppressing errors with error_reporting, display_errors or @ does not protect against CVE-2026-109619.
Notes: CVE-2026-109618 mechanism and reachability [1]. CVE-2026-109619 producer and consumer [2]. FPM for 109618 by source analysis only [1].

## PART 1 | The fix changed how PHP fails

- Commit 3584a98bda0f, "Avoid state corruption via bailout", closes both flaws.
- It replaces the bailout on out-of-memory with UnwindExit and resets globals start-up can read.
- The design: a delayed soft limit at the next VM safe point, and a hard _exit() at a higher one.
- It adds 10,759 lines and removes 988.
- Source backports reached end-of-life 7.4, 8.0 and 8.1; distributions had the patches in advance.
Caption: Two community-filed issues report regressions at the new hard limit and in the upload-progress decoder (Reported).
Notes: Commit [14]. Design [1]. Backports [9]. Regressions GH-24492 and GH-24493, Reported [27][28].

## PART 2 | Attempts came before the patch

| Date | Event |
|---|---|
| 30 July 2026 | Calif begins an audit |
| 24 August 2026 | Wiz reports to PHP |
| 12 October 2026 | The PHP CNA reserves both ids |
| 17 October 2026 | Amazon sees an attempt against MadPot (Reported) |
| 20 October 2026 | The ids leak with a wrong 10.0 score |
| 21 October 2026 | Releases, advisories, CVE records, CISA alert |
| 26 October 2026 | Both CVEs added to KEV, due 29 October |
| 4 November 2026 | TeamStarWolf lab run |
Notes: Calif and the leak, PHP Foundation [21]. Wiz [21][25]. Reservation [3][4]. Amazon, Reported [22]. Release day [1][2][3][4][8][17]. KEV [18]. Lab [46][47].

## PART 2 | The records disagree on score, weakness and range

| Field | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| CNA CVSS 4.0 | 9.2 Critical | 9.2 Critical |
| NVD CVSS 3.1 | 9.8 Critical | 8.1 High |
| NVD CPE lower bound | 7.3.0 | 5.4.0 |
| CWE-1419 | Advisory and KEV only | Advisory and KEV only |
| SSVC | Exploitation active | Exploitation active |
Caption: The CNA range lists only supported branches; treat every older PHP as affected unless a distribution says otherwise.
Notes: Scores and ranges [3][5][6]. CWE lists [1][2][5][18]. SSVC [6]. The inventory rule is Inferred.

## PART 3 | Two official images, side by side on loopback

Left: Setup
- php:8.4.26-apache (vulnerable) and php:8.4.27-apache (fixed), pinned by digest.
- Each published only on a loopback port.
- Both are Apache mod_php targets.
Right: The test step, described
- Version-check class: versions, settings and headers only.
- No proof-of-concept was run.
- The logs show HEAD and GET requests returning 200, and no crash.
Caption: Lab of 4 November 2026 UTC: two plans, every container, image and network removed afterwards.
Notes: Setup 01-setup.txt [46][47]. Digests match Docker Hub [29][30]. Test class and logs 02-test.txt [47]. Cleanup 05-cleanup.txt [46][47].

## PART 3 | What told the builds apart

| Observable | 8.4.26 (vulnerable) | 8.4.27 (fixed) |
|---|---|---|
| php -v | PHP 8.4.26 | PHP 8.4.27 |
| X-Powered-By | PHP/8.4.26 | PHP/8.4.27 |
| Marker page | php=8.4.26 | php=8.4.27 |
| Upload progress at defaults | On | On |
Caption: The upgrade does not change the upload-progress default; php.net advises keeping it off until the next bugfix release.
Notes: All Demonstrated, 02-test.txt and 04-mitigation.txt [46][47]. php.net advice [11].

## PART 3 | Where common inventory missed the vulnerable build

- Inside the official image, dpkg -l returned no PHP rows and rpm was absent.
- A header read against / returned no X-Powered-By, because PHP served no script there.
- The CLI reported its own SAPI, cli, not the web server's.
- Only php -v, the loaded module and a PHP-served URL showed the build.
- Combining host packages, loaded modules and container sweeps found every build in the lab.
Caption: Demonstrated in the CVE-2026-109619 exposure capture; image scans would add images that are not running (Inferred).
Notes: 03-exposure.txt [47]. SAPI check 02-test.txt [46]. Container sweep [46].

## PART 3 | A workaround is a setting, not a version

Left: CVE-2026-109618 run
- Apache admin values: memory_limit -1, post_max_size 1M, upload progress off.
- Read through the web server: -1 1M '0'.
- The header still said PHP/8.4.26.
Right: CVE-2026-109619 run
- session.upload_progress.enabled=0 in a conf.d file.
- The web page printed upload_progress=OFF.
- The fixed container still had it On by default.
Caption: A version scanner is right to keep flagging a mitigated host; only the upgrade clears the finding.
Notes: 04-mitigation.txt [46][47]. Vendor interim guidance, not a complete fix [1][2][9].

## DEFENDER VIEW | Compare against your platform's fixed build

| Platform | Fixed build |
|---|---|
| Upstream | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Docker | php:8.4.27-apache, pinned by digest |
| Debian 13 | php8.4 8.4.27-1~deb13u1 |
| Ubuntu 24.04 | php8.3 8.3.6-0ubuntu0.24.04.13 |
| RHEL 10 | php 8.3.36-1.el10_2; php8.4 8.4.27-1.el10_2 |
| RHEL 9 | php 8.0.30-8.el9_8.1 |
Caption: Backported packages keep old version strings, so a banner check flags patched hosts.
Notes: Upstream [3][8]. Docker [30][46]. Debian [31]. Ubuntu [32]. Red Hat [33]. The banner rule is Inferred.

## DEFENDER VIEW | Update, restart, keep upload progress off, look back

- Update every PHP that serves requests and restart every worker.
- Keep session.upload_progress.enabled=0 in php.ini, the FPM pool or the server configuration.
- If you cannot update today, apply the vendor's interim settings for both flaws; neither is complete.
- Watch PHP workers launching shells or downloading tools, as CISA advises.
- Investigate internet-facing PHP hosts from 17 October; KEV marks both for forensic triage.
Caption: CISA's SIGMA rule and Corelight's Zeek and Suricata package exist; CISA rates the rule's false-positive rate medium-high.
Notes: Update [8]. Upload progress [9][11][20]. Interim settings [1][2]. CISA [17][35]. KEV and Amazon look-back [18][22]. Corelight [36].

## MITRE MAPPINGS | One technique from the record, four inferred

| Id | Technique | Basis |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Vendor-validated RCE; KEV listing |
| T1059.004 | Unix Shell | Inferred from CISA's shell warning |
| T1105 | Ingress Tool Transfer | Inferred from CISA's download warning |
| T1505.003 | Web Shell | Inferred; no source records one |
| T1499.004 | Application or System Exploitation | Inferred side effect |
Caption: The study's own bindings to ATT&CK v20.0; no group, software or campaign object covers php2shell. MITRE notice in the notes.
Notes: Bindings [1][2][16][17][18][23][39][40][41][48][49]. CWE-416, 755, 824, 1325 and 1419 [1][2][5][18]; CAPEC-130 via CWE-1325 [37][38][45]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Failure paths are attack surface

- **Failure paths are attack surface.** Both flaws live in what PHP does when something goes wrong.
- **The runtime is under the application.** CMS-version inventories miss it.
- **A workaround is a setting, not a version.** Track mitigated and remediated as different states.
- **Inventory is a set of methods.** Packages, headers and the CLI each missed something.
- **Disclosure can leak.** Plan as if the public clock starts before the advisory.
Notes: Fix design [1][2][14]. Wiz, Reported [25]. Lab [46][47]. Leak and early images [21]. Amazon, Reported [22]. Readings are Inferred.
