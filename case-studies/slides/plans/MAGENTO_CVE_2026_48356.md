# Slide plan: Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix

- Study: case-studies/MAGENTO_CVE_2026_48356.md
- Cover title: Magento and Adobe Commerce / CVE-2026-48356 / Lab-Verified Exposure and Fix
- Subtitle: An anonymous file write, a web tier that decides the outcome, and a bulletin months behind the attacks
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/MAGENTO_CVE_2026_48356.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An anonymous cart call can write a PHP file to the store's disk

- Sansec's PolyShell finding: the guest-cart REST routes store a file attached to a custom option under pub/media/custom_options/quote/ with no extension check.
- A file named .php that starts with an image header passes the only content check and lands on disk.
- Whether it then runs as code depends on the web server configuration in front of Magento.
- Sansec reported attacks from 19 March 2026; Adobe's bulletin APSB26-73 came on 14 July; CISA added the CVE to KEV on 27 October.
- In the lab, 2.4.8-p5 stored the file and the stock nginx deny refused to serve it.
Caption: Evidence grade: Confirmed for the flaw, versions, KEV and patch; Demonstrated for the lab; Reported (Sansec) for attack dates and counts.
Notes: The flaw and the upload path [1][10]. Web-tier dependence [10]. Sansec advisory and attacks [10][11]. Bulletin [1]. KEV [5]. Lab write and blocked execution [26][27][28].

## KEY FACTS | Every signal but the vendor's own rating says urgent

Stat: 9.6 | CVSS 3.1, Adobe bulletin and GitHub advisory
Stat: 9.3 | CVSS 3.1 in the CVE record and NVD
Stat: 471 | Stores hit in one hour on 30 March, per Sansec
Stat: 117 | Days from first reported attacks to the bulletin
- Weakness: CWE-434, Unrestricted Upload of File with Dangerous Type, in every record.
- Adobe rating: Critical, Priority 2, "not aware of exploits in the wild" on a bulletin last updated 11 August 2026.
- CISA KEV: added 27 October 2026, due 10 November 2026; SSVC records exploitation as active.
Notes: Scores [1][3][4][6]. 471 stores is Reported (Sansec) [11]. 117 days is the study's arithmetic from 19 March to 14 July [1][10]. CWE-434 [1][3][4][5][6]. Rating and statement [1][2]. KEV and SSVC [3][5].

## PART 1 | Three missing checks turned a shopper feature into a file write

- Magento lets a merchant attach custom options to a product, and one option type is a file the shopper uploads.
- POST and PUT on /V1/guest-carts/:cartId/items accept a file_info object inside a custom option, with no login.
- The option id is not checked against the product's own options.
- The upload runs even when the product has no file option at all.
- Nothing restricts the extension; getimagesizefromstring is the only content check, and a polyglot passes it.
Caption: Sansec says GraphQL is not vulnerable. The preconditions are a reachable storefront, the REST API and one sellable product.
Notes: Custom options and the upload folder [10]. The routes and the three missing checks [10]. GraphQL [10]. Preconditions are Inferred from [1][10].

## PART 1 | The web tier, not the flaw, decides whether the file runs

Left: Where the file becomes code (Sansec)
- Stock nginx with Magento 2.0.0 to 2.2.x.
- Any version behind an nginx configuration that passes every .php file to FastCGI.
- Apache before 2.3.5 without php_flag engine 0.
Right: What upstream ships today
- nginx.conf.sample on 2.4-develop denies /media/custom_options/.
- A regex deny covers custom_options under /pub/media/.
- The folder's .htaccess carries Require all denied.
Caption: Blocking the directory stops execution, not the upload.
Notes: Execution conditions [10]. Upstream nginx and Apache rules on 2.4-develop [14]. The write still lands [10].

## PART 1 | The scores disagree, and the split is bulletin against record

| Source | Score | Impact wording |
|---|---|---|
| Adobe bulletin APSB26-73 | 9.6, A:L | Privilege escalation, no authentication |
| GitHub advisory GHSA-p3ch-8535-fp8j | 9.6, A:L | Unreviewed, no package ranges |
| CVE record, Adobe as CNA | 9.3, A:N | Arbitrary code execution |
| NVD | 9.3, A:N | Status Analyzed |
Caption: UI:R does not describe the upload, which needs no user; it most likely scores the shopper or admin served the file (Inferred).
Notes: Bulletin [1]. GHSA [6]. CVE record and CISA ADP [3]. NVD [4]. UI:R reading is Inferred [3][10]. SSVC Automatable no sits in tension with Sansec's automated wave [3][10][11].

## PART 1 | Attackers were four months ahead of the bulletin

| Date | Event |
|---|---|
| 17 March 2026 | Sansec publishes the PolyShell advisory |
| 19 March 2026 | First attacks in the wild, per Sansec |
| 30 March 2026 | 471 stores compromised in one hour, per Sansec |
| 14 July 2026 | APSB26-73, KB KA-37421 patches and the CVE record |
| 11 August 2026 | Bulletin updated, still unaware of exploits |
| 24 October 2026 | Sansec ties the deepveindrilling loader to PolyShell uploads |
| 27 October 2026 | CISA adds CVE-2026-48356 to KEV |
Notes: Advisory [10]. Attacks and the mass wave are Reported (Sansec) [10][11]. Bulletin, KB and record [1][3][7]. Bulletin update [1]. Loader campaign, Reported (Sansec) [12]. KEV [5].

## PART 1 | The fix ships as patch files; Adobe and Sansec split on 2.4.9

- Adobe ships one isolated patch ZIP per release line in KB KA-37421, with no Composer packages.
- A store must be on the latest security patch level for its line before it applies the patch.
- No public commit in magento/magento2 names the fix.
- Sansec says 2.4.9 GA, released 12 May 2026, already contains the fix.
- Adobe, the CVE record and NVD list 2.4.9 as affected, and Adobe ships a 2.4.9-2026-jul patch.
Caption: For patching decisions, follow Adobe's list and treat 2.4.9 as affected.
Notes: KB KA-37421 [7]. Repository commits and tags [13]. Sansec's account is Reported [10]. Adobe, CVE record and NVD [1][3][4].

## PART 2 | On 2.4.8-p5 the file landed, and nginx refused to serve it

Left: What the lab saw
- An anonymous guest cart's add-item call returned HTTP 200.
- A 69-byte .php file beginning with GIF89a appeared under custom_options/quote/, owned by www-data.
- A loopback request for it returned a 404 page; nginx logged access forbidden by rule.
Right: How the lab ran
- Magento Open Source 2.4.8-p5, MySQL 8.0 and OpenSearch 2.11.1 in Docker.
- Only the web port published, on loopback.
- The proof-of-concept step is described, not reproduced.
Caption: Lab of 4 November 2026. No fixed-state comparison: Adobe's isolated patch was not on the lab host.
Notes: Setup and version checks [25][26][27]. The write, the file and the refusal [26][28]. Compose translated to docker run, and the ownership repair [25][26]. No patched build [26][28].

## PART 2 | The exposure checks read the host without changing it

| Check | Lab result |
|---|---|
| Version | Magento CLI 2.4.8-p5; composer.lock 2.4.8-p5 |
| B2B and Events modules | NO-B2B-OR-EVENTS-MODULES |
| Quality Patches Tool | QPT-NOT-INSTALLED |
| Custom options sweep | One 69-byte file, the lab's own marker |
| accesson.php and CMS loader query | Nothing found |
| nginx -T and .htaccess | Upstream denies in place |
Caption: The exposure sweep still listed the marker that the test capture had deleted; a note on run order, not a product finding.
Notes: Exposure capture [27]. Mitigation capture [28]. Upstream rules [14]. Ordering note is Inferred [26][27].

## DEFENDER VIEW | Check the release, the web tier and the media folders

| Check | What to read | Why |
|---|---|---|
| Release | bin/magento --version and composer.lock | Compare with Adobe's affected list |
| Patch state | Commerce Version Tool, or cloud patch status | The version string hides the isolated patch |
| Web tier | nginx -T and the folder's .htaccess | Sizes the blast radius, not the flaw |
| Media folders | Files other than .htaccess under custom_options | Strong indicator of compromise |
| CMS content | fpCode, se_referrer, localStorage.getItem | Loader markers Sansec reported |
Caption: Run the checks read-only from the Magento root, on stores you are authorized to assess.
Notes: Version checks [26][27]. Patch confirmation [7]. Web-tier rules [10][14]. IOC sweeps and CMS markers [10][12].

## DEFENDER VIEW | Patch first, bridge at the edge, and hunt before closing

Left: Apply the fix
- Move to the latest security patch release for the line.
- Apply the matching APSB26-73 patch from KA-37421.
- Confirm with the Commerce Version Tool; on cloud, do not apply it twice.
Right: If you cannot patch this week
- A WAF rule on the guest-cart item calls is the only control Sansec says stops the upload.
- Keep the media-folder deny ahead of any PHP location block.
- Neither replaces the patch.
Caption: If you find a compromise: remove dropped files, review admin_user and rotate database, admin and API credentials.
Notes: Patch procedure [7][8][9]. KEV due date 10 November 2026 [5]. WAF and directory deny [10]. Compromise response [12]. Removal and ordering are Inferred.

## PART 4 | Vendor priority alone would have given this flaw a 30-day window

- Adobe's Priority 2 means no known attacks and a patch within about 30 days; Priority 1 is for flaws already exploited.
- By 14 July, Sansec had reported months of attacks; KEV caught up 105 days after the patch.
- 9.3 and 9.6 are both Critical; exploitation, not the base score, changed the risk.
- The fix is a patch file on an unchanged release number, so version-based inventory cannot see it.
- The GitHub advisory lists no package ranges, so dependency scanners may not flag the store.
Notes: Priority definitions [2]. Attacks before the bulletin [10][11]. 105 days is date arithmetic from [1][5]. Scores [1][3][4]. Isolated patches [7]. GHSA [6]. The consequences are Inferred.

## MITRE MAPPINGS | Two techniques shown in the lab, two more from Sansec

| Id | Technique | Tie to CVE-2026-48356 |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated guest-cart upload; Demonstrated |
| T1036.008 | Masquerading: Masquerade File Type | .php behind a GIF89a header; Demonstrated |
| T1505.003 | Server Software Component: Web Shell | Webshells and accesson.php, per Sansec |
| T1189 | Drive-by Compromise | Storefront JavaScript loaders, per Sansec |
Caption: ATT&CK v20.0. CWE-434; CAPEC-1 and CAPEC-650; no group, software or campaign object is bound. MITRE notice in the notes.
Notes: Techniques [10][11][12][15][16][17][18][26]. CWE and CAPEC [19][20][21][23]. D3FEND pairings [22][23]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The write is the flaw; the record decides the urgency

- **The web tier decides the outcome.** The lab store kept the file and refused to run it; a later configuration change could turn it live.
- **Research led, the vendor followed, the government caught up.** Sansec in March, Adobe in July, CISA in late October.
- **"Not aware of exploits" is a dated statement.** APSB26-73 still carried it eight days after KEV listed the CVE.
- **Isolated patches are invisible to version inventory.** Record patch state, not only version.
- **Cleanup outlasts the patch.** The loader campaign was still active in October.
Notes: Lab result [26][28]. Dates [1][5][10]. Bulletin statement against KEV [1][5]. Isolated patches [7]. Loader campaign, Reported (Sansec) [12]. Lessons are Inferred.
