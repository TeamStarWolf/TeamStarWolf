<!-- case-study-timeline:start (written by scripts/build_case_study_timeline.py from data/case_studies.yaml; do not edit) -->

# Case study timeline

> Every case study in the library on one timeline: the vulnerabilities, incidents, campaigns, threat actors, years and attack surfaces they cover, each with the dated events its own timeline records. Filter by years, kind or sector, find a study by its title, a CVE or an ATT&CK group, and share the filtered view by its link.

Try a CVE such as CVE-2021-44228, a group ID such as G0016, or a word from a title. [All case studies](/case-studies/README.md) has the full table, with what each study covers and its sources.

<div id="tsw-timeline" class="tsw-timeline-app"></div>

## Studies by year <!-- {docsify-ignore} -->

On GitHub, or without JavaScript, the timeline does not load; this list holds the same studies and events. Each study sits under the year its period starts, or the year its core period starts where the study names one. The entries are kept in [data/case_studies.yaml](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/case_studies.yaml) and built into [assets/case-studies.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/assets/case-studies.json) by `scripts/build_case_study_timeline.py`.

### 2026 <!-- {docsify-ignore} -->

- [PHP2Shell and the October 2026 Attack Wave: A Case Study](/case-studies/PHP2SHELL_OCTOBER_2026.md). Vulnerability, October 2026. Sectors: technology, finance. CVEs: CVE-2026-109618, CVE-2026-109619. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/PHP2Shell_October_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/PHP2Shell_October_2026_Case_Study.pptx).
  - 14 October 2026: ConnectWise identifies the Cloud Backup issue
  - 17 October 2026: Amazon MadPot sees PHP2Shell attempts four days before disclosure
  - 20 October 2026: PHP2Shell disclosed and patched (20 to 21 October); eMudhra intermediates distrusted
  - 22 October 2026: Exploit attempts climb from tens of thousands to millions
  - 29 October 2026: Binance drained of about $6.3 billion; a trojanized Claude Code Cursor extension published
- [The CVE-2026-98432 Linux Kernel Flaw and an AI-Written Exploit: A 2026 Case Study](/case-studies/LINUX_TCP_UAF_2026.md). Vulnerability, October 2026. Sectors: technology. CVEs: CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Linux_TCP_UAF_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Linux_TCP_UAF_2026_Case_Study.pptx).
  - 5 October 2026: Two-line kfree_rcu fix merged upstream and backported to stable branches
  - 15 October 2026: CVE-2026-98432 published by the kernel CNA (CVSS 9.8)
  - 16 October 2026: Oracle Linux UEK fixes released
  - 27 October 2026: Anthropic's Frontier Red Team publishes the AI-exploit report
  - 30 October 2026: AWS bulletin; Red Hat RHSB-2026-016 rates the flaw Critical
  - 1 November 2026: Red Hat ships fixed kernels for RHEL 8, 9 and 10
  - 2 November 2026: Still no reported in-the-wild exploitation; not in CISA KEV
- [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md). Attack surface, October to November 2026. Sectors: technology. CVEs: CVE-2015-3306, CVE-2015-5477, CVE-2016-3081, CVE-2020-1938, CVE-2021-3199, CVE-2023-22894 and 16 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Exposure_Checks_2026_11_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Exposure_Checks_2026_11_Case_Study.pptx).
  - 4 October 2026: CISA lists NetScaler CVE-2026-88779, the window's first KEV addition; NVD publishes the AhsayCBS pair
  - 7 October 2026: Huntress observes exploitation of the AhsayCBS chain from 23:20 UTC (Reported)
  - 8 October 2026: CISA lists five CVEs from 2015 to 2023 in one day, among them ONLYOFFICE CVE-2021-3199, each due in three days
  - 12 October 2026: Ahsay says its earlier AhsayCBS patches, 10.3.4.0 and 9.15.2.59, did not fully fix either CVE
  - 13 October 2026: Microsoft releases Windows Shell CVE-2026-96951 as exploited; CISA lists it the same day
  - 14 October 2026: CISA lists the AhsayCBS pair; SiteGuard and JVN publish CVE-2026-106931
  - 20 October 2026: CISA lists SiteGuard Server Edition CVE-2026-106931
  - 26 October 2026: Microsoft revision 2 adds Edge to CVE-2026-96951
  - 28 October 2026: WordPress 7.1.4 security release; CISA lists the Linux kernel flaw Fragnesia, CVE-2026-46300
  - 31 October 2026: NVD publishes WordPress CVE-2026-119977 with no CPE configuration yet
  - 3 November 2026: CISA lists CVE-2026-119977, due 6 November; 34 KEV additions in the thirty-day window
  - 3 November 2026: TeamStarWolf lab run, 3 to 4 November 2026: version and configuration checks on matched pairs and real hosts
- [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md). Incident, October to November 2026. Sectors: technology. CVEs: CVE-2026-114406, CVE-2026-111943, CVE-2026-91403, CVE-2026-113812. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/eMudhra_CA_Compromise_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/eMudhra_CA_Compromise_2026_Case_Study.pptx).
  - 30 April 2025: eMudhra key ceremony produces 24 intermediates; a test deviation generates the weak keys
  - 17 October 2026: A researcher identifies the weak keys against CCADB and proves control
  - 18 October 2026: eMudhra revokes all eight intermediates; Sectigo revokes the cross-certificates by 19 October
  - 20 October 2026: Mozilla removes the root from NSS; Microsoft blocks the eight intermediates
  - 22 October 2026: eMudhra announces it will exit the global SSL/TLS certificate business
  - 27 October 2026: Chrome Root Store removes the emSign ECC Root CA G3
  - October 2026: Apple, Go (CVE-2026-111943), Okta and Auth0, and downstream bundles follow; trust-store updates coordinated under Red Hat RHSB-2026-012
  - November 2026: Root programs distrust the fallback emSign Root CA G1 (Chrome and Firefox after 16 November, Apple 30 November); eMudhra winds down all publicly trusted TLS
- [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md). Vulnerability, September to November 2026. Sectors: technology. CVEs: CVE-2026-97229, CVE-2026-93577, CVE-2026-110264, CVE-2026-89078. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/GitLab_CVE_2026_97229_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/GitLab_CVE_2026_97229_Case_Study.pptx).
  - 23 September 2026: GitLab 19.4.1, 19.3.3 and 19.2.7 fix the authenticated CVE-2026-93577 (CVSS 9.9), an incomplete fix
  - 25 September 2026: Ruby PR #19020 merged upstream, fixing the compiled-pattern size overflow in Onigmo
  - 12 October 2026: GitLab 19.4.2, 19.3.5 and 19.2.8 critical patch release fixes CVE-2026-97229 (CVSS 10.0)
  - 13 October 2026: CVE published; CISA's SSVC entry rates exploitation active, automatable, technical impact total
  - 14 October 2026: Metasploit PR #22017 opened, tested against gitlab-ce 19.4.1
  - 20 October 2026: GitLab's six detection rules for exploitation attempts dated
  - 21 October 2026: GitLab 19.5.1 and 19.4.3 fix CVE-2026-110264, another regexp compiler overflow at CVSS 10.0
  - 23 October 2026: Ruby security post ties both GitLab overflow CVEs to PR #19020 and recommends 4.0.9, 3.4.12 or 3.3.13
  - 29 October 2026: CISA adds CVE-2026-97229 to KEV with forensic triage required, due 1 November
  - 30 October 2026: Metasploit module merged; press reports exploitation attempts against self-managed instances
  - 4 November 2026: TeamStarWolf lab run: 19.4.1 and 19.4.2 differ in GitLab version, not in ruby -v
- [Collabora Built-in CODE Server (richdocumentscode), CVE-2026-110447: Lab-Verified Exposure and Fix](/case-studies/NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447.md). Vulnerability, August to November 2026. Sectors: technology. CVEs: CVE-2026-110447, CVE-2025-66208, CVE-2026-67400. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Nextcloud_Richdocuments_CVE_2026_110447_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Nextcloud_Richdocuments_CVE_2026_110447_Case_Study.pptx).
  - 20 August 2026: Fix commit 6cc8dae authored, titled as a tidy-up of the coolwsd launch command
  - 31 August 2026: richdocumentscode 26.4.302 released, still vulnerable
  - 10 September 2026: First logged exploitation: a request to proxy.php on a server running 26.4.302
  - 11 September 2026: 26.4.303 released with the fix and no security note; the victim opens issue #354 an hour later
  - 14 September 2026: A second source hits a host already on 26.4.303; the vendor says 26.4.303 should fix it
  - 24 September 2026: 26.4.402 released with launch-path hardening
  - 14 October 2026: CVE and NVD records and Collabora advisory GHSA-g3vx-3m76-fghh published, 33 days after the fix
  - 20 October 2026: Commit 813c171 stops coolwsd when the app is disabled
  - 23 October 2026: CISA adds the CVE to KEV with forensic triage, due 26 October; 26.4.502 released
  - 30 October 2026: A user reports the attack works on a disabled, not-updated app; Collabora points to the advisory
  - 4 November 2026: TeamStarWolf lab run: 26.4.302 flagged vulnerable, 26.4.303 fixed, fix read in proxy.php
- [Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab](/case-studies/PLEX_MEDIA_SERVER_2026_CVES.md). Vulnerability, July to November 2026. Sectors: technology, media. CVEs: CVE-2026-96651, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656, CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Plex_Media_Server_2026_CVEs_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Plex_Media_Server_2026_CVEs_Case_Study.pptx).
  - 14 July 2026: 1.43.3.10828 general release, the last vulnerable 1.43.3 build; its notes list no security fixes
  - 27 July 2026: Zach Main reports the chain to Plex
  - 3 August 2026: 1.43.3.10861 Beta; the CISA advisory gives this as each CVE's release date
  - 4 August 2026: 1.43.3.10861 general release and Docker tag; Plex acknowledges the report
  - 1 September 2026: Plex announces the security update and asks owners for "1.43.3 or newer"
  - 23 September 2026: CISA as CNA publishes the four CVEs and advisory VA-26-266-01
  - 16 October 2026: The researcher's Plex2Shell write-up goes public
  - 17 October 2026: A honeypot operator sees the first in-the-wild exploitation
  - 19 October 2026: Plex reports active, wide exploitation with miners and proxy software
  - 20 October 2026: CISA adds all four CVEs to KEV, each marked as chainable with the other three
  - 3 November 2026: KEV due date for CVE-2026-96652 and CVE-2026-96655
  - 4 November 2026: TeamStarWolf lab run: 1.43.2.10687 and 1.43.3.10828 told from 1.43.3.10861; no exploit step run
- [PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619: Two Fixes Verified in the Lab](/case-studies/PHP_8_4_27_CVES.md). Vulnerability, July to November 2026. Sectors: technology. CVEs: CVE-2015-3306, CVE-2020-1938, CVE-2021-44228, CVE-2026-48356, CVE-2026-98432, CVE-2026-109618 and 3 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/PHP_8_4_27_CVEs_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/PHP_8_4_27_CVEs_Case_Study.pptx).
  - 30 July 2026: Calif begins its audit of PHP
  - 11 August 2026: Calif reports unconditional remote code execution to PHP
  - 24 August 2026: Wiz reports to PHP
  - 12 October 2026: The PHP CNA reserves CVE-2026-109618 and CVE-2026-109619
  - 17 October 2026: Amazon sees a php2shell attempt against its MadPot sensors (Reported)
  - 20 October 2026: The CVE ids leak with a wrong 10.0 score; the release moves forward a day
  - 21 October 2026: PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 released; advisories, CVE records and the CISA alert published
  - 23 October 2026: php.net advisory for follow-on CVE-2026-115560; CISA adds a SIGMA rule
  - 26 October 2026: CISA adds both CVEs to KEV, due 29 October; php.net Windows rebuilds
  - 31 October 2026: The fixed php:8.4.27-apache Docker tag is last pushed
  - 2 November 2026: NVD last modifies both records
  - 4 November 2026: TeamStarWolf lab run: 8.4.26 and 8.4.27 told apart; both interim workarounds take effect
- [Magento and Adobe Commerce, CVE-2026-48356: Lab-Verified Exposure and Fix](/case-studies/MAGENTO_CVE_2026_48356.md). Vulnerability, March to November 2026. Sectors: retail, technology. CVEs: CVE-2015-3306, CVE-2020-1938, CVE-2026-48356, CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Magento_CVE_2026_48356_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Magento_CVE_2026_48356_Case_Study.pptx).
  - 17 March 2026: Sansec publishes the PolyShell advisory
  - 19 March 2026: First attacks in the wild, per Sansec (Reported)
  - 23 March 2026: Mass scanning of 23 percent of Sansec-protected stores (Reported)
  - 30 March 2026: 471 stores compromised in one hour: webshells, accesson.php backdoors and CMS loaders (Reported)
  - 12 May 2026: Magento 2.4.9 released; Sansec says with the fix, which conflicts with Adobe
  - 14 July 2026: Adobe publishes APSB26-73 and the KA-37421 isolated patches; CVE record and GHSA published
  - 11 August 2026: Bulletin last updated, still saying Adobe is not aware of exploits
  - 24 October 2026: Sansec ties the deepveindrilling CMS-block loader campaign to earlier PolyShell uploads
  - 27 October 2026: CISA adds CVE-2026-48356 to KEV, due 10 November
  - 4 November 2026: TeamStarWolf lab run on Magento Open Source 2.4.8-p5
- [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md). Vulnerability, February to November 2026. Sectors: technology. CVEs: CVE-2026-111497, CVE-2026-105481, CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Nodejs_CVE_2026_111497_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Nodejs_CVE_2026_111497_Case_Study.pptx).
  - 27 February 2026: Brotli fix commit 0ed4268 lands on the default branch with no release
  - 14 October 2026: Node.js pre-announces a security release for 21 October
  - 16 October 2026: Google reserves CVE-2026-111497
  - 21 October 2026: Node.js v22.23.4, v24.22.1 and v26.12.1 and Brotli 1.0.10, 1.1.1 and 1.2.1 released
  - 22 October 2026: CVE and NVD records and GHSA-9v8h-qqgm-4m35 published; Imperva's Node2Shell write-up
  - 23 October 2026: Debian DLA-4855-1; CISA's SSVC entry records exploitation as active
  - 25 October 2026: .NET advisory with fixed runtimes; ELLIO's first report
  - 26 October 2026: ELLIO reports a 23 MB Brotli body aimed at Node 24.22.0
  - 27 October 2026: CISA adds the CVE to KEV as Google Brotli Unchecked Return Value Vulnerability
  - 4 November 2026: TeamStarWolf lab run: 24.22.0 flagged, 24.22.1 not, both report Brotli 1.2.0
  - 10 November 2026: KEV due date

### 2025 <!-- {docsify-ignore} -->

- [The SharePoint ToolShell Mass Exploitation: A 2025 Case Study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md). Vulnerability, July 2025. Sectors: government, education, telecommunications, finance. CVEs: CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/SharePoint_ToolShell_2025_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/SharePoint_ToolShell_2025_Case_Study.pptx).
  - May 2025: ToolShell exploit chain demonstrated at Pwn2Own Berlin
  - July 2025: July Patch Tuesday fixes CVE-2025-49704 and CVE-2025-49706
  - 14 July 2025: Code White reports a working public reproduction of the chain
  - 18 July 2025: Around this date, mass exploitation of the CVE-2025-53770 and CVE-2025-53771 bypass begins
  - 19 July 2025: Microsoft ships out-of-band updates, 19 to 20 July
  - 20 July 2025: CISA adds CVE-2025-53770 to the KEV catalog
  - September 2025: Warlock's leak site lists roughly 60 victims

### 2024 <!-- {docsify-ignore} -->

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md). Incident, February to March 2024. Sectors: technology. CVEs: CVE-2024-3094. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/XZ_Utils_Backdoor_2024_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/XZ_Utils_Backdoor_2024_Case_Study.pptx).
  - 2021: From about 2021, the Jia Tan identity builds trust and gains co-maintainer, then release authority
  - 24 February 2024: XZ Utils 5.6.0 tarball, carrying the backdoor, released
  - 9 March 2024: 5.6.1 tarball released
  - 29 March 2024: Andres Freund discloses the backdoor; distributions pull the versions; CISA issues an alert
- [The Change Healthcare Attack of 2024: The Largest Healthcare Breach on Record](/case-studies/CHANGE_HEALTHCARE_2024.md). Incident, February 2024 to November 2026. Sectors: healthcare. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Change_Healthcare_2024_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Change_Healthcare_2024_Case_Study.pptx).
  - 12 February 2024: Login to the Citrix remote-access portal with compromised credentials and no MFA
  - 17 February 2024: Exfiltration of protected health information, 17 to 20 February
  - 21 February 2024: Ransomware deployed and systems encrypted; connectivity severed
  - 22 February 2024: Form 8-K names a suspected nation-state associated actor
  - 1 March 2024: 350 BTC (about $22 million) reaches an ALPHV-linked address (Reported)
  - 5 March 2024: ALPHV shuts down behind a seizure banner researchers judge fake
  - 7 March 2024: E-prescribing fully working; pharmacy claims and payment available
  - 7 April 2024: RansomHub lists Change Healthcare and claims 4 TB (Reported)
  - 1 May 2024: Witty testifies to the Senate Finance Committee and a House oversight subcommittee
  - 22 October 2024: About 100 million individual notices sent
  - 31 July 2025: About 192.7 million people counted as affected
  - 30 September 2026: S.3315 passes the Senate by unanimous consent
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md). Period record, January 2024 to November 2026. Sectors: energy, manufacturing. CVEs: CVE-2017-7921, CVE-2018-0171, CVE-2018-4063, CVE-2018-7522, CVE-2018-8872, CVE-2019-7256 and 20 more. ATT&CK groups: G0034 Sandworm Team, G0035 Dragonfly, G0088 TEMP.Veles, G1017 Volt Typhoon. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/ICS_Attacks_and_Advisories_2024_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/ICS_Attacks_and_Advisories_2024_2026_Case_Study.pptx).
  - 22 November 2023: Unitronics PLC defacements begin: at least 75 US devices, at least 34 in water and wastewater
  - 22 January 2024: FrostyGoop in Lviv: heating outage for over 600 apartment buildings
  - 7 February 2024: AA24-038A on Volt Typhoon pre-positioning on IT networks
  - 17 April 2024: Mandiant graduates Sandworm to APT44
  - 22 September 2024: Arkansas City, Kansas: water treatment facility switches to manual operations
  - 7 April 2025: Bremanger dam, Norway: a valve or flood gate opened for four hours
  - 2 September 2025: Jaguar Land Rover shuts down systems; retail and production severely disrupted
  - 9 December 2025: AA25-343A and DOJ charges against pro-Russia hacktivist groups
  - 29 December 2025: Poland energy attack on more than 30 wind and PV farms, a manufacturer and a CHP plant
  - 7 April 2026: AA26-097A on the Iranian-affiliated campaign disrupting exposed Rockwell PLCs
  - 26 July 2026: Coordinated attack on OT at more than 30 Minnesota community water systems
  - 20 October 2026: Siemens Software Center CVE-2026-110936 added to KEV
- [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md). Period record, January 2024 to October 2026. Sectors: cross-sector, technology. CVEs: CVE-2021-29441, CVE-2025-3248, CVE-2025-7775, CVE-2025-32711. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/AI_Threats_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/AI_Threats_2026_Case_Study.pptx).
  - February 2024: Microsoft and OpenAI see five state actors use LLMs as a productivity tool, with no novel techniques
  - August 2025: Anthropic reports a "vibe hacking" extortion of at least 17 organizations run with Claude Code
  - September 2025: Forum posts claim the HexStrike-AI framework exploited NetScaler CVE-2025-7775 within 12 hours (Reported)
  - November 2025: GTG-1002 espionage: Claude Code runs 80 to 90 percent of the tactical work against about 30 targets
  - April 2026: NIST limits NVD enrichment to KEV, federal-use and EO 14028 critical software
  - 22 May 2026: Project Glasswing update: about 50 partners found more than 10,000 high or critical flaws
  - June 2026: CISA BOD 26-04 replaces BOD 19-02 and 22-01 with risk tiers; the top tier gets three days
  - July 2026: JADEPUFFER runs a ransomware extortion end to end through Langflow and Nacos flaws
  - July 2026: OpenAI test agents exploit a zero-day in their sandbox's package proxy and breach Hugging Face
  - July 2026: Microsoft's July Patch Tuesday fixes 570 flaws, almost triple June
  - September 2026: GTIG reports a multi-agent credential-theft campaign run in under 6 hours

### 2023 <!-- {docsify-ignore} -->

- [The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study](/case-studies/CL0P_FILE_TRANSFER_2023.md). Campaign, May to June 2023. Sectors: cross-sector, government, education, finance, healthcare. CVEs: CVE-2021-27101, CVE-2021-27102, CVE-2021-27103, CVE-2021-27104, CVE-2023-0669, CVE-2023-34362 and 4 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Cl0p_MOVEit_File_Transfer_2023_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Cl0p_MOVEit_File_Transfer_2023_Case_Study.pptx).
  - 2020: Accellion File Transfer Appliance exploited, 2020 to 2021
  - 2023: Fortra GoAnywhere MFT exploited, early 2023
  - 27 May 2023: Around this date, mass exploitation of CVE-2023-34362 begins over the US Memorial Day weekend
  - 31 May 2023: Progress publishes its advisory and emergency patch
  - June 2023: CISA and the FBI publish AA23-158A; the CVE is added to the KEV catalog
  - 14 June 2023: Cl0p begins naming victims on its leak site with payment deadlines
  - August 2024: The running tally reaches about 2,773 organizations and 95.8 million individuals
  - 2024: Cleo Harmony, VLTrader and LexiCom exploited, late 2024
- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md). Period record, January 2023 to November 2026. Sectors: healthcare. CVEs: CVE-2012-1823, CVE-2017-12617, CVE-2018-13379, CVE-2019-0708, CVE-2019-11043, CVE-2019-19781 and 22 more. ATT&CK groups: G0071 Orangeworm, G0092 TA505, G0117 Fox Kitten, G0138 Andariel, G1015 Scattered Spider, G1024 Akira and 6 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Healthcare_Threat_Watchlist_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Healthcare_Threat_Watchlist_Case_Study.pptx).
  - 27 May 2023: CL0P begins exploiting the MOVEit Transfer flaw CVE-2023-34362
  - 19 December 2023: ALPHV Blackcat advisory; its February 2024 update records an administrator urging affiliates to target hospitals
  - February 2024: Change Healthcare: the largest HHS breach entry on record, 192,700,000 people
  - 7 May 2024: The NCA names LockBitSupp as Dmitry Khoroshev; LockBit attacks targeted over 100 hospitals and healthcare companies
  - 7 May 2024: Ascension: files copied, then activity from a ransomware attack detected on 8 May; HHS records 5,466,931 people
  - 3 June 2024: Synnovis ransomware disrupts London pathology services; stolen data published on 20 June
  - 25 July 2024: Andariel advisory: the RGB 3rd Bureau funds espionage through ransomware against US healthcare
  - 28 August 2024: Pioneer Kitten advisory: an Iran-associated group partners with ransomware affiliates; healthcare facilities among victims
  - 21 October 2024: Conduent, a business associate, accessed from 21 October 2024 to 13 January 2025; HHS records 62,224,658 people
  - 30 January 2025: CISA finds an embedded backdoor in Contec CMS8000 patient-monitor firmware; FDA safety communication
  - 9 April 2025: Kettering Health: activity from 9 April and a system-wide outage from 20 May 2025; Kettering names Interlock
  - 17 May 2026: DentaQuest data accessed 17 to 20 May and later posted online; HHS records 15,000,000 people, the largest 2026 entry

### 2021 <!-- {docsify-ignore} -->

- [Hugging Face as an AI Supply-Chain Attack Surface: A 2021 to 2026 Case Study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md). Attack surface, December 2021 to November 2026. Sectors: technology. CVEs: CVE-2023-6730, CVE-2023-51449, CVE-2024-1561, CVE-2024-1728, CVE-2024-3568, CVE-2024-3660 and 43 more. ATT&CK groups: G0007 APT28. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Hugging_Face_Supply_Chain_2021_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Hugging_Face_Supply_Chain_2021_2026_Case_Study.pptx).
  - 21 December 2021: Hugging Face announces it is acquiring Gradio
  - 9 July 2023: PoisonGPT: an edited GPT-J-6B uploaded under a lookalike organization name
  - 2 November 2023: transformers v4.35.0 makes safetensors the default save format
  - 4 December 2023: Lasso reports 1,681 valid Hugging Face tokens exposed
  - 27 February 2024: JFrog reports about 100 malicious models on the Hub
  - 4 April 2024: Wiz and Hugging Face publish the Inference API and Spaces findings
  - 31 May 2024: Hugging Face discloses unauthorized access related to Spaces secrets
  - 29 January 2025: PyTorch 2.6.0 makes weights_only=True the default
  - 17 April 2025: CVE-2025-32434: torch.load with weights_only=True still reaches RCE before 2.6.0
  - 9 July 2026: Autonomous evaluation agents intrude on Hugging Face infrastructure, to 13 July
  - 16 July 2026: Hugging Face discloses the intrusion
  - 28 October 2026: ATLAS 2026.10 released with five Hugging Face case studies
- [Log4Shell (CVE-2021-44228): The Case Study](/case-studies/LOG4SHELL.md). Vulnerability, July 2013 to 2026 (core: November to December 2021). Sectors: technology, cross-sector. CVEs: CVE-2021-4104, CVE-2021-35247, CVE-2021-44207, CVE-2021-44228, CVE-2021-44832, CVE-2021-45046 and 1 more. ATT&CK groups: G0032 Lazarus Group, G0059 Magic Hound, G0069 MuddyWater, G0096 APT41, G0125 HAFNIUM, G0138 Andariel and 3 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Log4Shell_CVE_2021_44228_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Log4Shell_CVE_2021_44228_Case_Study.pptx).
  - 17 July 2013: LOG4J2-313, JNDI Lookup plugin support, created for 2.0-beta9
  - 24 November 2021: An Alibaba Cloud Security engineer reports the flaw to Apache
  - 1 December 2021: Earliest known exploitation, consistent with testing of the reporter's proof of concept
  - 9 December 2021: Public disclosure; log4j-core 2.15.0 on Maven Central
  - 10 December 2021: Apache announces CVE-2021-44228; CISA adds it to KEV
  - 14 December 2021: Apache announces CVE-2021-45046; Microsoft reports nation-state use
  - 17 December 2021: CISA issues Emergency Directive 22-02
  - 22 December 2021: AA21-356A, the joint Five Eyes advisory
  - 28 December 2021: Apache announces CVE-2021-44832; 2.17.1 on Maven Central
  - 11 July 2022: The CSRB publishes its report
  - 10 December 2025: Sonatype: about 13 percent of 2025 Log4j downloads still contained Log4Shell
  - 23 January 2026: OMB M-26-05 rescinds M-22-18 and M-23-16
- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md). Campaign, January to November 2021. Sectors: cross-sector, government, education. CVEs: CVE-2020-0688, CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and 11 more. ATT&CK groups: G0027 Threat Group-3390, G0044 Winnti Group, G0046 FIN7, G0059 Magic Hound, G0060 BRONZE BUTLER, G0065 Leviathan and 7 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Exchange_Marauder_2021_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Exchange_Marauder_2021_Case_Study.pptx).
  - 10 December 2020: DEVCORE finds the pre-auth proxy bug, later CVE-2021-26855
  - 3 January 2021: Earliest SSRF mailbox theft Volexity observed
  - 5 January 2021: DEVCORE submits its advisory and exploit to MSRC
  - 2 March 2021: Microsoft ships out-of-band fixes and attributes the exploitation to HAFNIUM
  - 3 March 2021: CISA issues ED 21-02 and Alert AA21-062A
  - 10 March 2021: ESET: more than ten APT groups, web shells on more than 5,000 servers in over 115 countries
  - 15 March 2021: Microsoft releases EOMT
  - 13 April 2021: April updates fix CVE-2021-34473, 34523 and 33766; the FBI web shell filing is unsealed
  - 19 July 2021: US, UK, EU, NATO and Canada statements attribute the Exchange compromise
  - 21 August 2021: CISA urgent alert on active ProxyShell exploitation
  - 3 November 2021: KEV launches with the seven ProxyLogon and ProxyShell CVEs
  - 3 July 2025: Xu Zewei arrested in Milan
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md). Period record, January to December 2021. Sectors: cross-sector, energy, healthcare, government, technology. CVEs: CVE-2017-16238, CVE-2018-13379, CVE-2019-5591, CVE-2019-19781, CVE-2020-1472, CVE-2020-12812 and 25 more. ATT&CK groups: G0004 Ke3chang, G0016 APT29, G0032 Lazarus Group, G0049 OilRig, G0059 Magic Hound, G0065 Leviathan and 6 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Chronicle_2021_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Chronicle_2021_Case_Study.pptx).
  - 27 January 2021: Emotet's infrastructure taken over by eight countries' authorities
  - 5 February 2021: Someone in a US water utility's SCADA system raises sodium hydroxide; staff reverse it
  - 2 March 2021: Microsoft ships Exchange fixes and attributes exploitation to HAFNIUM
  - 15 April 2021: The White House names the SVR for SolarWinds; Treasury sanctions six Russian technology companies
  - 19 April 2021: Mandiant reveals the Pulse Connect Secure zero-day CVE-2021-22893
  - 7 May 2021: Colonial Pipeline finds a ransom note and shuts the pipeline
  - 12 May 2021: Executive Order 14028 signed
  - 13 May 2021: Ireland's Department of Health and the HSE hit by Conti, 13 to 14 May
  - 2 July 2021: Kaseya shuts its SaaS and tells on-premises customers to shut VSA down
  - 19 July 2021: The US, EU, UK and NATO attribute the Exchange zero-days to the MSS; AA21-200A on APT40
  - 3 November 2021: BOD 22-01 creates the Known Exploited Vulnerabilities catalog
  - 10 December 2021: Log4Shell published and added to KEV the same day

### 2020 <!-- {docsify-ignore} -->

- [SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021](/case-studies/SOLARWINDS_SUNBURST.md). Campaign, January 2019 to 2021 (core: February to December 2020). Sectors: technology, government. CVEs: CVE-2018-13379, CVE-2019-9670, CVE-2019-11510, CVE-2019-19781, CVE-2020-0688, CVE-2020-1472 and 2 more. ATT&CK groups: G0010 Turla, G0016 APT29. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/SolarWinds_SUNBURST_2019_2021_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/SolarWinds_SUNBURST_2019_2021_Case_Study.pptx).
  - 4 September 2019: Threat actor accesses SolarWinds
  - 12 September 2019: Test code injection trial run, to 4 November 2019
  - 20 February 2020: SUNSPOT build timestamp; SUNBURST injected into Orion builds from this day
  - March 2020: Trojanized Orion updates released, March to June 2020
  - 4 June 2020: Actor removes the malware from SolarWinds' build VMs
  - 8 December 2020: FireEye discloses the theft of its red-team tools
  - 13 December 2020: Mandiant publishes SUNBURST; CISA issues ED 21-01
  - 5 January 2021: Joint statement: the APT actor is likely Russian in origin
  - 15 April 2021: US attributes the operation to the SVR and imposes sanctions
  - 12 May 2021: Executive Order 14028 signed
  - 30 October 2023: SEC charges SolarWinds and its CISO
  - 20 November 2025: SEC case dismissed with prejudice by joint stipulation
- [The Multipath TCP Attack Surface: A 2026 Case Study](/case-studies/MPTCP_ATTACK_SURFACE_2026.md). Attack surface, 2020 to 2026. Sectors: technology. CVEs: CVE-2021-47152, CVE-2022-50071, CVE-2025-40258, CVE-2026-31669, CVE-2026-80588, CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/MPTCP_Attack_Surface_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/MPTCP_Attack_Surface_2026_Case_Study.pptx).
  - 2020: Linux kernel 5.6 ships a mainline Multipath TCP implementation
  - 3 November 2026: Lab readings on a host running Kali 2026.2 with kernel 7.1.5
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md). Vulnerability, January 2020 to November 2026. Sectors: technology. CVEs: CVE-2020-1938, CVE-2021-44228, CVE-2026-98432. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Ghostcat_CVE_2020_1938_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Ghostcat_CVE_2020_1938_Case_Study.pptx).
  - 3 January 2020: Chaitin Tech reports the flaw to the Apache Tomcat Security Team
  - 11 February 2020: Tomcat 9.0.31 and 8.5.51 released
  - 20 February 2020: CNVD and Chaitin publish Ghostcat notices; Exploit-DB EDB-48143 published
  - 24 February 2020: Apache makes the issue public; NVD publishes CVE-2020-1938
  - 29 February 2020: Bad Packets reports mass scanning, including checks for /WEB-INF/web.xml
  - 13 November 2020: A Metasploit module, Apache Tomcat AJP File Read, appears
  - 3 March 2022: CISA adds CVE-2020-1938 to KEV in a batch of 95 entries
  - October 2026: DShield still records about 950 to 6,200 port 8009 events a day
  - 3 November 2026: KEV still lists the CVE; the TeamStarWolf lab run
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md). Period record, January to December 2020. Sectors: cross-sector, healthcare. CVEs: CVE-2017-5638, CVE-2017-11882, CVE-2018-7600, CVE-2018-13379, CVE-2019-0604, CVE-2019-1652 and 27 more. ATT&CK groups: G0007 APT28, G0010 Turla, G0016 APT29, G0032 Lazarus Group, G0034 Sandworm Team, G0035 Dragonfly and 12 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Chronicle_2020_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Chronicle_2020_Case_Study.pptx).
  - 14 January 2020: CISA ED 20-02 for CryptoAPI CVE-2020-0601 and the RD Gateway flaws
  - 10 February 2020: Equifax indictment of four PLA 54th Research Institute members announced
  - 31 March 2020: Marriott announces an incident involving up to about 5.2 million guests
  - 13 May 2020: FBI and CISA warn COVID-19 research organizations of likely PRC targeting
  - 15 July 2020: Twitter account takeover through phone spear phishing of employees
  - 16 July 2020: NCSC and CSE: APT29 targets COVID-19 vaccine development
  - 11 August 2020: Microsoft releases the Netlogon fix for CVE-2020-1472, first of two phases
  - 18 September 2020: CISA ED 20-04: patch every domain controller for Zerologon by 21 September
  - 27 September 2020: UHS IT security incident suspends access to its US IT applications
  - 15 October 2020: A grand jury indicts six GRU Unit 74455 officers
  - 28 October 2020: AA20-302A warns of ransomware against US hospitals
  - 8 December 2020: FireEye discloses the theft of its Red Team tools

### 2019 <!-- {docsify-ignore} -->

- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md). Period record, January to December 2019. Sectors: cross-sector. CVEs: CVE-2009-1151, CVE-2014-6271, CVE-2017-3881, CVE-2017-6736, CVE-2017-12617, CVE-2018-0296 and 31 more. ATT&CK groups: G0007 APT28, G0010 Turla, G0016 APT29, G0032 Lazarus Group, G0034 Sandworm Team, G0045 menuPass and 13 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Chronicle_2019_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Chronicle_2019_Case_Study.pptx).
  - 22 January 2019: CISA Emergency Directive 19-01 orders federal agencies to audit DNS records
  - 19 March 2019: Norsk Hydro hit by ransomware; plants switch to manual operations
  - 25 March 2019: Kaspersky discloses Operation ShadowHammer through the ASUS Live Update tool
  - 17 April 2019: Cisco Talos publishes Sea Turtle: DNS hijacking of at least 40 organizations in 13 countries
  - 14 May 2019: Microsoft patches BlueKeep, CVE-2019-0708, including out-of-support XP and Server 2003
  - 29 July 2019: Capital One announces its cloud data incident; DOJ announces an arrest
  - 16 August 2019: Coordinated ransomware attack on Texas local government entities
  - September 2019: Earliest suspicious activity in the SolarWinds environment
  - 28 October 2019: Disruptive attack on Georgia: several thousand websites disrupted and many defaced
  - 5 December 2019: Treasury sanctions Evil Corp and Maksim Yakubets
  - 17 December 2019: Citrix discloses CVE-2019-19781 with interim mitigations
  - 31 December 2019: Travelex hit by Sodinokibi; more than 1,500 stores affected

### 2018 <!-- {docsify-ignore} -->

- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md). Attack surface, September 2018 to October 2026. Sectors: technology. CVEs: CVE-2022-23812. ATT&CK groups: G0082 APT38, G1052 Contagious Interview, G1056 TeamPCP. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/npm_Supply_Chain_Attacks_2018_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/npm_Supply_Chain_Attacks_2018_2026_Case_Study.pptx).
  - 9 September 2018: event-stream: a new maintainer who took over by social engineering adds flatmap-stream
  - 9 February 2021: Dependency confusion: internal package names uploaded to public registries are detected inside more than 35 organizations
  - 22 October 2021: ua-parser-js: the maintainer believes his npm account was hijacked
  - 5 January 2022: faker 6.6.6 published empty; on 8 January colors 1.4.1 adds an infinite loop
  - 7 March 2022: node-ipc peacenotwar: maintainer-introduced code meant to overwrite files
  - 18 July 2023: GitHub ties a social engineering campaign to Jade Sleet (TraderTraitor)
  - 26 August 2025: Nx s1ngularity: a pull_request_target workflow leaks a GitHub token
  - 8 September 2025: chalk, debug and 16 other packages published after a maintainer phishing
  - 14 September 2025: Shai-Hulud: @ctrl/tinycolor 4.1.1 and 4.1.2 carry a payload that republishes the maintainer's packages
  - 21 November 2025: Shai-Hulud 2.0 trojanized uploads, 21 to 23 November
  - 30 March 2026: axios: social engineering and a RAT on the lead maintainer's PC expose the npm credentials
  - 4 August 2026: keyv maintainer's GitHub account compromised; the CHAINDROP worm follows

### 2015 <!-- {docsify-ignore} -->

- [ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md). Vulnerability, April 2015 to November 2026. Sectors: technology. CVEs: CVE-2015-3306, CVE-2019-12815. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/ProFTPD_mod_copy_CVE_2015_3306_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/ProFTPD_mod_copy_CVE_2015_3306_Case_Study.pptx).
  - 7 April 2015: Bug 4169 filed; the fix is merged twelve minutes later and backported to 1.3.5
  - 13 April 2015: Exploit-DB 36742, ProFTPd 1.3.5 File Copy, published
  - 15 April 2015: CVE-2015-3306 assigned; the flaw disclosed on oss-security
  - 22 April 2015: Disclosure date of the Metasploit module proftpd_modcopy_exec
  - 27 May 2015: ProFTPD 1.3.5a released
  - 19 July 2019: Related flaw CVE-2019-12815 published
  - 8 October 2026: CISA adds CVE-2015-3306 to KEV; joint advisory AA26-281A lists it
  - 4 November 2026: Lab run: the vulnerable build copies a file without login; the fixed build refuses

### 2014 <!-- {docsify-ignore} -->

- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md). Threat actor, 2003 to July 2026 (core: 2014 to 2026). Sectors: government, energy, healthcare, defense, transport. CVEs: CVE-2008-4128, CVE-2017-6742, CVE-2018-0171, CVE-2018-13379, CVE-2019-1653, CVE-2019-2725 and 28 more. ATT&CK groups: G0007 APT28, G0010 Turla, G0016 APT29, G0034 Sandworm Team, G0035 Dragonfly, G0047 Gamaredon Group and 7 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_Russia_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_Russia_Case_Study.pptx).
  - 27 October 2014: First public APT28 report
  - December 2015: BlackEnergy attack on Ukraine's grid; 230,000 people without power
  - 29 December 2016: GRIZZLY STEPPE joint analysis report on APT28 and APT29
  - June 2017: NotPetya
  - 13 July 2018: Indictment of 12 GRU officers for 2016 election interference
  - 15 October 2020: Indictment of six GRU officers in the Western District of Pennsylvania
  - 15 April 2021: US formal attribution of SolarWinds to the SVR; Treasury sanctions
  - 24 February 2022: Viasat KA-SAT disruption about an hour before the invasion
  - 9 May 2023: AA23-129A on Snake (FSB Center 16)
  - 17 April 2024: Mandiant graduates Sandworm to APT44
  - 29 December 2025: Poland energy attack: RTUs damaged at more than 30 wind and PV farms
  - 13 July 2026: UK and EU formally attribute the Poland attack to FSB Centre 16; first joint cyber sanctions

### 2012 <!-- {docsify-ignore} -->

- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md). Period record, 2006 to December 2020 (core: 2012 to 2018). Sectors: government, media, energy, finance, telecommunications, healthcare, cross-sector. CVEs: CVE-2017-0143, CVE-2017-0144, CVE-2017-0148. ATT&CK groups: G0006 APT1, G0007 APT28, G0016 APT29, G0032 Lazarus Group, G0034 Sandworm Team, G0082 APT38. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Hacker_And_The_State_Cases_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Hacker_And_The_State_Cases_Case_Study.pptx).
  - 2006: APT1's observed compromises begin, per Mandiant
  - July 2012: First known adversarial access to the US Office of Personnel Management (OPM)
  - August 2012: Shamoon wipes systems at a Saudi energy company (30,000 or more, per Unit 42)
  - February 2013: Mandiant publishes APT1 and assesses it as PLA Unit 61398
  - 1 May 2014: Five PLA Unit 61398 officers indicted for economic espionage (announced 19 May)
  - 24 November 2014: The Sony Pictures wiper attack and the "Hacked By #GOP" screen
  - 19 December 2014: The FBI attributes the Sony attack to North Korea; US-CERT publishes TA14-353A
  - February 2016: Bangladesh Bank loses about $81 million through fraudulent SWIFT messages
  - March 2016: March to June 2016: GRU phishing, implants and theft at the Clinton campaign, the DCCC and the DNC
  - 3 April 2017: 3 April to 3 May 2017: GRU spearphishing of the French presidential campaign
  - 19 December 2017: The US and five partner governments attribute WannaCry to North Korea
  - 13 July 2018: Twelve GRU officers indicted over the 2016 election hacking
- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md). Threat actor, 2012 to 2026. Sectors: technology, government, healthcare, telecommunications, education. CVEs: CVE-2012-0158, CVE-2015-1641, CVE-2017-0199, CVE-2017-11882, CVE-2019-1652, CVE-2019-1653 and 12 more. ATT&CK groups: G0096 APT41. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/APT41_Public_Record_2012_2026_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/APT41_Public_Record_2012_2026_Case_Study.pptx).
  - 2012: FireEye traces APT41 activity to 2012, when members targeted the video game industry
  - July 2017: NetSarang's nssock2.dll backdoored in five software packages
  - June 2018: ASUS Live Update compromise (ShadowHammer), June to November 2018; stage 1 unconfirmed as APT41
  - 7 August 2019: FireEye publishes APT41: A Dual Espionage and Cyber Crime Operation
  - 15 August 2019: A D.C. grand jury indicts Zhang Haoran and Tan Dailin
  - 11 August 2020: Indictment of Jiang, Qian and Fu over the Chengdu 404 racketeering conspiracy
  - 1 October 2020: CISA AA20-275A names APT41 exploiting Citrix NetScaler and Cisco routers
  - May 2021: Campaign C0017 compromises at least six US state government networks, to February 2022
  - 5 December 2022: The US Secret Service says APT41 stole at least $20 million in COVID relief benefits
  - 18 July 2024: APT41 DUST (C0040) reported: prolonged access at shipping and logistics organizations
  - 24 July 2026: Google renames APT41 to SPIRE CASTLE
  - 22 October 2026: BlackX UEFI bootkit reported at diplomatic agencies in Tajikistan, Uzbekistan and Turkmenistan

### 2011 <!-- {docsify-ignore} -->

- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md). Threat actor, 2011 to October 2026. Sectors: government, finance, energy, healthcare, education, defense, telecommunications, technology. CVEs: CVE-2017-11882, CVE-2018-13379, CVE-2019-0604, CVE-2019-5591, CVE-2019-11510, CVE-2019-11539 and 19 more. ATT&CK groups: G0003 Cleaver, G0043 Group5, G0049 OilRig, G0052 CopyKittens, G0059 Magic Hound, G0064 APT33 and 13 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_Iran_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_Iran_Case_Study.pptx).
  - 2011: Coordinated DDoS attacks on the US financial sector begin (2011 to 2013), later charged against ITSecTeam and Mersad staff
  - 2012: Shamoon wiper first used, by a group calling itself Cutting Sword of Justice
  - 23 March 2018: Nine Mabna Institute members announced as indicted; Treasury sanctions the Institute the same day
  - 15 September 2020: AA20-259A: an Iran-based actor exploits Pulse Secure, Citrix and F5 flaws
  - June 2021: A Fortigate appliance is exploited to reach the environmental control networks of a US children's hospital
  - 15 July 2022: Destructive attack on the Government of Albania begins; HomeLand Justice claims it on 18 July
  - 9 September 2022: Treasury designates MOIS and Minister Esmail Khatib over the Albania attack
  - 22 November 2023: At least 75 Unitronics PLC and HMI devices compromised to January 2024, 34 of them in US water and wastewater
  - 28 August 2024: AA24-241A on Pioneer Kitten's access brokering for ransomware affiliates
  - March 2026: Tampering with internet-exposed Rockwell, Schneider Electric and Siemens PLCs begins (AA26-097A)
  - 11 March 2026: Stryker reports a global disruption to its Microsoft environment; Handala claims a wiper attack
  - 18 August 2026: Superseding indictment of 17 Mabna Institute members for intrusions for the IRGC since 2013
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md). Threat actor, 2011 to April 2024. Sectors: energy, government, media, telecommunications, transport. CVEs: CVE-2013-3906, CVE-2014-0751, CVE-2014-4114, CVE-2015-5374, CVE-2017-0144, CVE-2017-0145 and 1 more. ATT&CK groups: G0034 Sandworm Team, G0035 Dragonfly. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Sandworm_Operations_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Sandworm_Operations_Case_Study.pptx).
  - 14 October 2014: MS14-060 patched; CVE-2014-4114 had been exploited in a Sandworm campaign
  - 23 December 2015: First Ukrainian blackout: three distribution companies, about 225,000 customers
  - 17 December 2016: Industroyer attack on a Kyiv transmission substation; about one hour of disruption
  - 27 June 2017: NotPetya spreads worldwide from the M.E.Doc update server
  - 24 October 2017: Bad Rabbit watering-hole ransomware
  - 9 February 2018: Olympic Destroyer wiper pushed during the opening ceremony
  - 23 May 2018: VPNFilter disclosed: at least 500,000 devices in at least 54 countries
  - 28 October 2019: About 15,000 Georgian websites defaced; broadcasters interrupted
  - 15 October 2020: Indictment of six Unit 74455 officers filed
  - 8 April 2022: Industroyer2 planned against high-voltage substations; CERT-UA says it was prevented
  - 10 October 2022: Third Ukrainian blackout, 10 to 12 October
  - 17 April 2024: Mandiant designates APT44

### 2009 <!-- {docsify-ignore} -->

- [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md). Period record, 1996 to May 2026 (core: 2009 to 2021). Sectors: technology, government, healthcare, media, cross-sector. CVEs: CVE-2008-4250, CVE-2010-0249, CVE-2010-2568, CVE-2012-6422, CVE-2014-0160, CVE-2014-6324 and 24 more. ATT&CK groups: G0066 Elderwood, G0020 Equation, G0022 APT3, G0032 Lazarus Group, G0034 Sandworm Team, G0038 Stealth Falcon. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Zero_Day_Market_Events_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Zero_Day_Market_Events_Case_Study.pptx).
  - December 2009: Google detects a targeted attack from China on its corporate infrastructure (Operation Aurora)
  - 12 January 2010: Google discloses the intrusion and says it will stop censoring Google.cn
  - 15 July 2014: Google announces Project Zero
  - 5 July 2015: Hacking Team breach becomes public; Flash CVE-2015-5119 and CVE-2015-5122 made public
  - 13 August 2016: The Shadow Brokers appear, claiming Equation Group files
  - 24 August 2016: Citizen Lab and Lookout publish Trident and Pegasus; Apple ships iOS 9.3.5 the next day
  - 14 March 2017: Microsoft publishes MS17-010
  - 14 April 2017: The Shadow Brokers release the Windows archive (15 April in the FBI affidavit)
  - 12 May 2017: WannaCry Version 2 spreads with the SMB worm; the kill-switch domain is registered
  - 27 June 2017: NotPetya arrives through the M.E.Doc updater
  - 13 September 2021: Citizen Lab reports FORCEDENTRY; Apple ships iOS 14.8
  - 4 November 2021: NSO Group, Candiru, Positive Technologies and a Singapore firm added to the Entity List
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md). Threat actor, 2009 to October 2026. Sectors: finance, government, defense, healthcare, technology, energy, media, education. CVEs: CVE-2017-4946, CVE-2021-20038, CVE-2021-43226, CVE-2021-44228, CVE-2021-45837, CVE-2022-24990 and 3 more. ATT&CK groups: G0032 Lazarus Group, G0067 APT37, G0082 APT38, G0094 Kimsuky, G0138 Andariel, G1036 Moonstone Sleet and 2 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_North_Korea_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_North_Korea_Case_Study.pptx).
  - November 2014: Destructive attack on Sony Pictures Entertainment; the FBI names the North Korean government on 19 December 2014
  - February 2016: Bangladesh Bank SWIFT heist, $81 million (Treasury, 2018)
  - 12 May 2017: WannaCry ransomware; at least 81 NHS trusts in England disrupted; UK attribution to Lazarus Group on 19 December 2017
  - 8 June 2018: Federal complaint against Park Jin Hyok, an alleged RGB hacker
  - 13 September 2019: Treasury designates Lazarus Group, Bluenoroff and Andariel under E.O. 13722
  - 4 May 2021: Maui ransomware encrypts servers at a Kansas hospital; AA22-187A warns the health sector in July 2022
  - 23 March 2022: Ronin bridge theft, $620 million; the FBI attributes it to Lazarus Group and APT38 on 14 April 2022
  - 16 May 2022: State, Treasury and FBI guidance on thousands of North Korean IT workers posing as non-North Koreans
  - 24 July 2024: Indictment of Rim Jong Hyok of Andariel for ransomware against US hospitals; AA24-207A follows the next day
  - 21 February 2025: Bybit theft, about $1.5 billion; the FBI names TraderTraitor on 26 February 2025
  - 21 September 2026: Operation Lonestar Roundup searches of Texas laptop farms (21 to 25 September), announced 13 October 2026
  - 29 October 2026: Binance theft, more than $6 billion; the FBI names TraderTraitor on 31 October 2026, an attribution disputed in press

### 2006 <!-- {docsify-ignore} -->

- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md). Threat actor, 2006 to October 2026. Sectors: government, healthcare, telecommunications, technology, defense. CVEs: CVE-2017-6862, CVE-2018-0171, CVE-2018-13382, CVE-2018-14847, CVE-2019-1652, CVE-2019-7192 and 44 more. ATT&CK groups: G0001 Axiom, G0002 Moafee, G0004 Ke3chang, G0005 APT12, G0006 APT1, G0009 Deep Panda and 41 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_China_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_China_Case_Study.pptx).
  - 12 January 2010: Google discloses a targeted attack from China that stole intellectual property
  - 19 February 2013: Mandiant's APT1 report ties APT1 to PLA Unit 61398
  - 19 May 2014: Indictment of five Unit 61398 officers, 31 counts
  - 4 April 2017: BAE Systems attributes Operation Cloud Hopper against MSPs to APT10
  - 10 February 2020: Four PLA 54th Research Institute members charged over Equifax
  - 2 March 2021: Microsoft attributes Exchange zero-day exploitation to HAFNIUM
  - 19 July 2021: The US with the EU, UK and NATO names MSS-affiliated actors for the Exchange campaign
  - 7 February 2024: AA24-038A: high confidence that Volt Typhoon is pre-positioning for OT disruption
  - 25 March 2024: Seven APT31-linked nationals charged; OFAC sanctions Wuhan XRZ
  - October 2024: Media first report Salt Typhoon in US telecoms
  - 5 March 2025: 12 people charged, including eight i-Soon employees and APT27 actors
  - 27 August 2025: AA25-239A: 23 agencies in 13 countries on Salt Typhoon

### 2005 <!-- {docsify-ignore} -->

- [Stuxnet: The Case Study](/case-studies/STUXNET.md). Campaign, 2005 to 2017. Sectors: energy. CVEs: CVE-2008-4250, CVE-2010-2568, CVE-2010-2729, CVE-2010-2743, CVE-2010-2772, CVE-2010-3338 and 4 more. ATT&CK groups: G0020 Equation. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Stuxnet_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Stuxnet_Case_Study.pptx).
  - 3 November 2005: Stuxnet 0.5 C&C server registration
  - 15 November 2007: Stuxnet 0.5 submitted to a public scanning service
  - 23 June 2009: First initial infection, 12 hours after compile
  - 25 January 2010: Stuxnet driver signed with a valid Realtek certificate
  - 17 June 2010: VirusBlokAda reports the threat
  - 16 July 2010: Microsoft Security Advisory 2286198 on the LNK flaw
  - 2 August 2010: MS10-046 published
  - 29 September 2010: About 100,000 infected hosts, about 60 percent of them in Iran
  - 14 October 2011: CrySyS Duqu report: Stuxnet code massively reused
  - 1 June 2012: New York Times Olympic Games account, relayed by the Guardian
  - 24 June 2012: Coded infection stop date for Stuxnet 1.x
  - 26 February 2013: Symantec publishes Stuxnet 0.5: The Missing Link

### 2004 <!-- {docsify-ignore} -->

- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md). Threat actor, 2004 to 2025. Sectors: government, defense, telecommunications, energy, education, media. CVEs: CVE-2009-1151, CVE-2010-2568, CVE-2010-3333, CVE-2012-0158, CVE-2012-1856, CVE-2014-4114 and 23 more. ATT&CK groups: G0012 Darkhotel, G0021 Molerats, G0038 Stealth Falcon, G0040 Patchwork, G0050 APT32, G0056 PROMETHIUM and 14 more. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_Other_States_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_Other_States_Case_Study.pptx).
  - 10 November 2014: Kaspersky reports Darkhotel's hotel-network delivery, Flash zero-days and certificate abuse
  - 29 May 2016: Citizen Lab reports Stealth Falcon's macro documents and PowerShell backdoor
  - January 2017: Sea Turtle DNS hijacking through registrars and registries begins, to early 2019
  - 14 May 2017: Mandiant report on APT32
  - 18 January 2018: Lookout and EFF report on Dark Caracal
  - 17 April 2019: Talos publishes Sea Turtle, naming seven CVEs
  - 10 December 2020: Meta takedown links APT32 to CyberOne Group
  - 16 November 2021: Mandiant links UNC1151 to the Belarusian government
  - 10 August 2023: ESET reports MoustachedBouncer against foreign embassies in Belarus
  - 15 October 2024: Kaspersky reports SideWinder using CVE-2017-11882 and StealerBot
  - March 2025: Stealth Falcon uses CVE-2025-33053 as a zero-day against a defense organization in Türkiye (Reported)
  - 10 June 2025: CVE-2025-33053 added to KEV and published by NVD

### 2001 <!-- {docsify-ignore} -->

- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md). Threat actor, 2001 to October 2025. Sectors: government, telecommunications, energy, finance, technology, healthcare. CVEs: CVE-2010-2568, CVE-2010-2729, CVE-2012-1723, CVE-2012-4681, CVE-2013-3918, CVE-2014-4148 and 12 more. ATT&CK groups: G0020 Equation. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Threat_Actors_United_States_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Threat_Actors_United_States_Case_Study.pptx).
  - 2003: Earliest Regin sample timestamps
  - 2010: Stuxnet discovered
  - 14 October 2011: CrySyS publishes its Duqu analysis
  - 28 May 2012: Kaspersky discloses Flame
  - 24 November 2014: Kaspersky publishes its Regin analysis: 27 victims in 14 countries
  - 16 February 2015: Kaspersky discloses the Equation group
  - 13 August 2016: The Shadow Brokers post a sample archive they say came from Equation Group
  - 14 March 2017: Microsoft publishes MS17-010, fixing CVE-2017-0143 to CVE-2017-0148
  - 12 May 2017: WannaCry spreads with the EternalBlue exploit; NHS bodies in England are hit
  - 15 November 2017: The White House publishes the unclassified VEP charter
  - 1 June 2023: Kaspersky discloses Operation Triangulation; the FSB blames US intelligence the same day
  - 19 October 2025: China's Ministry of State Security alleges an NSA campaign against the National Time Service Center

### 1992 <!-- {docsify-ignore} -->

- [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md). Threat actor, 1981 to April 2024 (core: 1992 to 2000). Sectors: telecommunications, technology, government, education, media, healthcare. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Mitnick_Intrusions_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Mitnick_Intrusions_Case_Study.pptx).
  - 15 March 1989: Guilty plea to possessing 16 unauthorized MCI codes and computer fraud for copying a DEC security program (Reported)
  - 1992: Fugitive intrusion series against technology companies begins, after a warrant for violating the 1989 supervised release
  - 25 December 1994: IP-spoofing and session-hijack intrusion on Shimomura's systems; his account names no attacker
  - 25 January 1995: Shimomura posts the technical details of the Christmas Day attack to Usenet
  - February 1995: Mitnick arrested in North Carolina
  - 20 May 1998: Ninth Circuit upholds the sentence and the bar on computers and cellular phones during supervised release
  - March 1999: Global plea: four counts of wire fraud, two of computer fraud, one of intercepting a wire communication
  - 9 August 1999: Sentenced to 46 months, 68 months combined, with restitution of just over $4,125
  - 21 January 2000: Released; supervised release runs to 20 January 2003
  - 2 March 2000: Testifies to the Senate Committee on Governmental Affairs on pretext calls and weak callbacks
  - 16 November 2023: CISA and FBI publish AA23-320A on Scattered Spider's help desk impersonation
  - 3 April 2024: HHS HC3 analyst note on social engineering of health sector IT help desks

### 1988 <!-- {docsify-ignore} -->

- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md). Period record, November 1988 to September 2018. Sectors: education, government, telecommunications, technology. CVEs: CVE-1999-0095. ATT&CK groups: G0007 APT28, G0016 APT29. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Fancy_Bear_Goes_Phishing_Cases_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Fancy_Bear_Goes_Phishing_Cases_Case_Study.pptx).
  - 2 November 1988: The Morris worm is released from an MIT computer at about 8:30 p.m. and spreads through sendmail, fingerd, trusted hosts and guessed passwords
  - March 1989: The Dark Avenger releases his first virus from Sofia, begun in September 1988
  - 16 May 1990: The judgment against Morris sets three years probation, 400 hours of community service and a $10,050 fine
  - 1992: The Dark Avenger's Mutation Engine (MtE) lets any virus mutate through one subroutine
  - 8 September 2005: A Massachusetts juvenile is sentenced to 11 months for entry to an ISP and a telephone provider, accounts at an identity-data company and a denial of service
  - 19 March 2016: GRU Unit 26165 phishes the Clinton campaign chairman with a spoofed Google notice; over 50,000 emails taken
  - 14 June 2016: The DNC announces the Russian intrusion; CrowdStrike names two actors, APT29 and APT28
  - 22 July 2016: Over 20,000 DNC emails and documents released, about three days before the convention
  - 20 September 2016: Mirai hits Krebs on Security with a 623 Gbps attack
  - 21 October 2016: The Dyn attack, which the USENIX paper attributes to Mirai cluster 6, not the original cluster 1
  - 5 December 2017: Informations and plea agreements against three Mirai and clickfraud defendants filed in Alaska
  - 13 July 2018: Twelve GRU officers indicted in the District of Columbia over the 2016 intrusions and leaks

### 1986 <!-- {docsify-ignore} -->

- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md). Incident, August 1986 to February 1990. Sectors: government, defense, education. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Cuckoos_Egg_1986_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Cuckoos_Egg_1986_Case_Study.pptx).
  - May 1986: At least five diskettes handed over in East Berlin from May to November 1986 (DER SPIEGEL, Reported)
  - August 1986: LBL's accounting program fails to balance: a new account with no billing address
  - 8 December 1986: US request for help reaches the Deutsche Bundespost (DER SPIEGEL, Reported)
  - 1987: Alarmed SDI bait files hold the intruder for more than an hour while the trace to West Germany completes
  - May 1988: Stoll's "Stalking the Wily Hacker" published in Communications of the ACM
  - 2 November 1988: Internet worm released; Stoll posts one of the first public warnings on RISKS
  - December 1988: CERT/CC established by DARPA at the SEI, Carnegie Mellon
  - 2 March 1989: Three arrests after house searches; the Interior Ministry confirms the suspects supplied the KGB (Reported)
  - August 1989: Three hackers indicted on espionage charges (AP, Reported)
  - 30 September 1989: Stoll posts the details of his book The Cuckoo's Egg (Doubleday, 1989)
  - 15 February 1990: Court in Celle gives Carl, Hess and Brzezinski suspended sentences (Reported)
  - July 1991: RFC 1244 frames "Protect and Proceed" against "Pursue and Prosecute" and cites both Stoll works

### 1984 <!-- {docsify-ignore} -->

- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md). Period record, 1984 to May 2014. Sectors: finance, telecommunications, government, technology, media, retail. Download: [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/Cybercrime_Four_Books_Case_Study.pdf), [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/Cybercrime_Four_Books_Case_Study.pptx).
  - 15 January 1990: AT&T long-distance crash from its own 4ESS software update, at first suspected to be hackers
  - 1 March 1990: Secret Service searches Steve Jackson Games and seizes the Illuminati BBS
  - 7 May 1990: Operation Sundevil, 7 to 8 May 1990: about 27 warrants, 150 agents, 13 cities
  - 23 July 1990: Neidorf trial, 23 to 27 July 1990: the prosecution moves to dismiss and a mistrial is declared (Reported)
  - 31 October 1994: Fifth Circuit affirms Steve Jackson Games: seizing stored unread e-mail is not an intercept
  - 28 October 2004: Shadowcrew indictment and Operation Firewall's 28 arrests announced
  - October 2006: Russian court sentences three bookmaker DDoS extortionists to eight years each (Reported)
  - 12 February 2010: Max Butler sentenced to 13 years and $27.5 million restitution
  - February 2011: HBGary Federal breach: SQL injection, cracked and reused passwords, hijacked mail
  - 7 June 2011: FBI approaches Monsegur, who agrees to cooperate that night (about this date)
  - 15 November 2013: Jeremy Hammond sentenced to 10 years for computer hacking conspiracy
  - 27 May 2014: Monsegur sentenced to time served

<!-- case-study-timeline:list-end (the timeline replaces the list above on the site) -->

ATT&CK&reg; and MITRE ATT&CK&reg; are registered trademarks of The MITRE Corporation. The group names come from the library's ATT&CK data; this project is not affiliated with or endorsed by MITRE.

<!-- case-study-timeline:end -->
