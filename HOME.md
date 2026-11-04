<!--
  HOME.md: the site homepage (docsify renders it at "/", under the cover in _coverpage.md;
  README.md stays the GitHub face). The cover carries the title, the one-sentence pitch and
  the three buttons, and this page never repeats them. It opens with the README's front
  door: the two link rows (.tsw-links: the project links, then "Explore the library", same
  labels and order as the top of README.md, with "Library" for this site where the README
  says "Website") and the "What's inside" table, then the doors.
  No counts on this page. The script-written blocks, never typed here:
    - "What's inside" (between the stats markers): scripts/build_stats.py, a table of
      what each part holds and where to start, the same rows as the README's table
    - "Start-here guides" (between the guides markers): scripts/build_home_guides.py, from
      each guide's own Time and Difficulty table
    - "Browse by domain" (between the domains markers): scripts/build_site_nav.py, from the
      hubs in docs/site_nav.json
  CI fails when any of these blocks is stale. Edit the scripts, not the blocks.
  Link rules: raw-HTML hrefs use hash form (#/FOO, no .md); external links carry
  target="_blank" rel="noopener"; JSONL/dataset links are always github.com URLs,
  never hash routes. Keep each HTML block free of blank lines.
  Legacy anchors: the empty .tsw-anchor divs (quick-router, learning-paths, how-to-guides,
  core-references, study-and-career) and the footer's id (data-amp-navigator-layers) keep
  #/?id= links to the sections of the previous homepage working. Keep them outside
  headings (docsify copies heading HTML into the sidebar, which would duplicate the id),
  and do not remove them.
  The first paragraph (.tsw-gh-only) is hidden on the site and shows only on github.com,
  which strips the classes; spaces between the card parts keep the stripped text readable.
-->

<p class="tsw-gh-only">This file is the homepage of the TeamStarWolf site, laid out for the site; its links work there, not on GitHub. Read it at <a href="https://teamstarwolf.github.io/TeamStarWolf/" target="_blank" rel="noopener">teamstarwolf.github.io/TeamStarWolf</a>, or start from the <a href="https://github.com/TeamStarWolf/TeamStarWolf#readme" target="_blank" rel="noopener">README</a> on GitHub.</p>

<div class="tsw-anchor" id="quick-router"></div><div class="tsw-anchor" id="learning-paths"></div>

<div class="tsw-links">
  <p><strong><a href="#/">Library</a></strong> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="https://teamstarwolf.github.io/intelligence-hub/" target="_blank" rel="noopener">Intelligence Hub</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">ATT&amp;CK-Navi</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/INDEX">Browse all references</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/CONTRIBUTING">Contribute</a></p>
  <p><span class="tsw-links-label">Explore the library:</span> <a href="#/languages/README">Languages</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/paradigms/README">Paradigms</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/frameworks/README">Frameworks</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/commands/README">Commands</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/formats/README">Formats</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/hubs/README">Domains</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/guides/README">Guides</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/disciplines/README">Learning paths</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/mitre/README">ATT&amp;CK</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/detections/TECHNIQUE_DETECTION_LIBRARY">Detections</a> <span class="tsw-links-sep" aria-hidden="true">·</span> <a href="#/data/README">Data</a></p>
</div>

## What's inside

<!-- stats:start (written by scripts/build_stats.py; do not edit) -->
<table>
  <thead><tr><th>What</th><th>Contents</th><th>Start at</th></tr></thead>
  <tbody>
    <tr><td>Reference documents</td><td>One topic each: its terms, tooling, and the frameworks and guidance that apply</td><td><a href="#/INDEX">Reference index</a></td></tr>
    <tr><td>How-to guides</td><td>One task, step by step, with the time it takes, what you need, and what you produce</td><td><a href="#/guides/README">Guides</a></td></tr>
    <tr><td>Learning paths</td><td>An order of study for one discipline, with training, tools, books, and certifications</td><td><a href="#/disciplines/README">Learning paths</a></td></tr>
    <tr><td>Framework pages</td><td>One page per Enterprise ATT&amp;CK technique, tactic, group, software entry, campaign, and mitigation, CAPEC attack pattern, D3FEND countermeasure, ATLAS technique and mitigation, and F3 technique</td><td><a href="#/mitre/README">Framework pages</a></td></tr>
    <tr><td>Developer reference pages</td><td>One page per programming language, paradigm, software framework, command-line tool, data format, and database engine</td><td><a href="#/languages/README">Languages</a></td></tr>
    <tr><td>Security platform pages</td><td>One page per vendor platform a security program runs on, from endpoint and exposure management to identity, cloud, OT, and backup</td><td><a href="#/platforms/README">Security platforms</a></td></tr>
    <tr><td>AI tooling pages</td><td>AI tools and models in groups, a one-page manual for each tool, a learning path, and hands-on labs</td><td><a href="#/ai-tooling/README">AI tooling</a></td></tr>
    <tr><td>Case studies</td><td>Evidence-graded studies of how the threat landscape is changing, written from primary sources, with figures and PDF downloads</td><td><a href="#/case-studies/README">Case studies</a></td></tr>
  </tbody>
</table>
<!-- stats:end -->

## Where do you want to start?

<p class="tsw-lead">Three ways in, by what you came to do.</p>

<div class="tsw-doors">
  <a class="tsw-door tsw-door--learn" href="#/disciplines/README">
    <span class="tsw-door-who">I'm learning</span>
    <span class="tsw-door-t">Learning paths</span>
    <span class="tsw-door-d">One path per discipline, from detection engineering and incident response to cloud, OT, and AI security: an order of study with training, tools, books, and certifications.</span>
    <span class="tsw-door-go">Pick a path</span>
  </a>
  <a class="tsw-door tsw-door--task" href="#/guides/README">
    <span class="tsw-door-who">I have a job to do</span>
    <span class="tsw-door-t">How-to guides</span>
    <span class="tsw-door-d">Numbered steps with the time, the difficulty, what you need, and what you will produce. Triage a CVE, build a detection, respond to ransomware.</span>
    <span class="tsw-door-go">Open the guides</span>
  </a>
  <a class="tsw-door tsw-door--data" href="#/mitre/README">
    <span class="tsw-door-who">I work with framework data</span>
    <span class="tsw-door-t">Framework pages and data</span>
    <span class="tsw-door-d">One page per technique, group, attack pattern, countermeasure, and mitigation, with the JSONL data and Navigator layers behind them, from Enterprise ATT&amp;CK, CAPEC, D3FEND, ATLAS, and F3.</span>
    <span class="tsw-door-go">Browse the frameworks</span>
  </a>
</div>

<p class="tsw-lead">Current headlines, advisories, and CVE briefs are on the <a href="https://teamstarwolf.github.io/intelligence-hub/" target="_blank" rel="noopener">Intelligence Hub</a>. The rules for reading them are in <a href="#/THREAT_INTELLIGENCE_REFERENCE?id=the-public-intelligence-hub">the threat intelligence reference</a>.</p>

<div class="tsw-anchor" id="how-to-guides"></div>

## Start-here guides

<p class="tsw-lead">Each guide's time and level come from its own header table.</p>

<!-- guides:start (written by scripts/build_home_guides.py; do not edit) -->
<div class="tsw-guides">
  <a class="tsw-guide" href="#/guides/HOW_TO_USE_THIS_LIBRARY"><span class="tsw-guide-t">How to Use This Library</span> <span class="tsw-pills"><span class="tsw-pill" title="30-45 min"><span class="tsw-sr-only">Time: </span>30-45 min</span> <span class="tsw-pill" title="Beginner"><span class="tsw-sr-only">Level: </span>Beginner</span></span></a>
  <a class="tsw-guide" href="#/guides/TRIAGE_A_CVE"><span class="tsw-guide-t">Triage a New CVE in 30 Minutes</span> <span class="tsw-pills"><span class="tsw-pill" title="~30 minutes"><span class="tsw-sr-only">Time: </span>About 30 minutes</span> <span class="tsw-pill" title="Intermediate"><span class="tsw-sr-only">Level: </span>Intermediate</span></span></a>
  <a class="tsw-guide" href="#/guides/BUILD_YOUR_FIRST_DETECTION"><span class="tsw-guide-t">Build and Deploy Your First Detection</span> <span class="tsw-pills"><span class="tsw-pill" title="Half a day hands-on, plus a 1-2 week audit soak"><span class="tsw-sr-only">Time: </span>Half a day hands-on, plus a 1-2 week audit soak</span> <span class="tsw-pill" title="Beginner to intermediate"><span class="tsw-sr-only">Level: </span>Beginner to intermediate</span></span></a>
  <a class="tsw-guide" href="#/guides/RESPOND_TO_RANSOMWARE"><span class="tsw-guide-t">Respond to a Ransomware Incident</span> <span class="tsw-pills"><span class="tsw-pill" title="First 24-72 hours of the incident (steps run in parallel after Step 3)"><span class="tsw-sr-only">Time: </span>First 24-72 hours of the incident</span> <span class="tsw-pill" title="Advanced: decisions under pressure, some irreversible"><span class="tsw-sr-only">Level: </span>Advanced</span></span></a>
  <a class="tsw-guide" href="#/guides/HARDEN_A_WINDOWS_BASELINE"><span class="tsw-guide-t">Harden a Windows Baseline</span> <span class="tsw-pills"><span class="tsw-pill" title="Half a day for a pilot; 2-4 weeks to full production"><span class="tsw-sr-only">Time: </span>Half a day for a pilot</span> <span class="tsw-pill" title="Intermediate"><span class="tsw-sr-only">Level: </span>Intermediate</span></span></a>
  <a class="tsw-guide" href="#/guides/START_A_VULN_MGMT_PROGRAM"><span class="tsw-guide-t">Start a Vulnerability Management Program (First 90 Days)</span> <span class="tsw-pills"><span class="tsw-pill" title="~90 days elapsed; 2-4 hours to first scan"><span class="tsw-sr-only">Time: </span>About 90 days elapsed</span> <span class="tsw-pill" title="Intermediate"><span class="tsw-sr-only">Level: </span>Intermediate</span></span></a>
</div>
<!-- guides:end -->

<p class="tsw-more"><a href="#/guides/README">All how-to guides</a></p>

## How it connects

<p class="tsw-lead">Pages link to their neighbors. One route through the library, for PowerShell abuse:</p>

<div class="tsw-connect">
  <div class="tsw-node"><span class="tsw-node-k">Reference</span> <a href="#/LOTL_DETECTION_REFERENCE">Living Off the Land Detection</a> <span class="tsw-node-d">Telemetry, baselines, and hardening for abuse of built-in tools.</span></div>
  <div class="tsw-node"><span class="tsw-node-k">Learning path</span> <a href="#/disciplines/detection-engineering">Detection Engineering</a> <span class="tsw-node-d">An order of study, from log sources to tested rules.</span></div>
  <div class="tsw-node"><span class="tsw-node-k">Framework page</span> <a href="#/mitre/techniques/T1059-001">T1059.001 PowerShell</a> <span class="tsw-node-d">Mitigations, detection, data sources, adversary usage, and NIST SP 800-53 controls.</span></div>
  <div class="tsw-node"><span class="tsw-node-k">Detection</span> <a href="#/detections/TECHNIQUE_DETECTION_LIBRARY?id=t1059001">Technique Detection Library</a> <span class="tsw-node-d">Example queries for the technique, with data source and confidence.</span></div>
  <div class="tsw-node"><span class="tsw-node-k">Layer</span> <a href="#/navigator/index">Navigator layers</a> <span class="tsw-node-d">Heatmaps to load in ATT&amp;CK Navigator.</span></div>
  <div class="tsw-node"><span class="tsw-node-k">Workbench</span> <a href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">ATT&amp;CK-Navi</a> <span class="tsw-node-d">The ATT&amp;CK matrices with coverage, threat, and exposure views.</span></div>
</div>

<p class="tsw-lead">The references also follow the chain from a vulnerability to its countermeasures:</p>

<div class="tsw-chain">
  <a class="tsw-chip" href="#/CVE_REFERENCE">CVE</a>
  <a class="tsw-chip" href="#/CWE_REFERENCE">CWE</a>
  <a class="tsw-chip" href="#/CAPEC_REFERENCE">CAPEC</a>
  <a class="tsw-chip" href="#/ATTACK_TECHNIQUE_ATLAS">ATT&amp;CK</a>
  <a class="tsw-chip" href="#/D3FEND_REFERENCE">D3FEND</a>
</div>

<div class="tsw-anchor" id="core-references"></div>

## Explore the frameworks

<div class="tsw-explore">
  <p class="tsw-explore-lead">Each Enterprise ATT&amp;CK technique, tactic, group, software entry, campaign, and mitigation has its own page, generated from the MITRE data in this repository, and so does each CAPEC attack pattern, D3FEND countermeasure, ATLAS technique and mitigation, and F3 technique. ICS and Mobile ATT&amp;CK are in the JSONL data only, without pages. Go straight to one:</p>
  <div class="tsw-ids">
    <a class="tsw-id" href="#/mitre/techniques/T1059"><code>T1059</code> Command and Scripting Interpreter</a>
    <a class="tsw-id" href="#/mitre/groups/G0016"><code>G0016</code> APT29</a>
    <a class="tsw-id" href="#/mitre/software/S0154"><code>S0154</code> Cobalt Strike</a>
    <a class="tsw-id" href="#/mitre/campaigns/C0024"><code>C0024</code> SolarWinds Compromise</a>
    <a class="tsw-id" href="#/mitre/mitigations/M1038"><code>M1038</code> Execution Prevention</a>
    <a class="tsw-id" href="#/mitre/capec/CAPEC-66"><code>CAPEC-66</code> SQL Injection</a>
    <a class="tsw-id" href="#/mitre/d3fend/process-lineage-analysis">D3FEND Process Lineage Analysis</a>
    <a class="tsw-id" href="#/mitre/atlas/AML-T0051"><code>AML.T0051</code> LLM Prompt Injection</a>
  </div>
  <div class="tsw-families">
    <span class="tsw-families-label">Browse by family</span>
    <a href="#/mitre/techniques/README">Techniques</a>
    <a href="#/mitre/tactics/README">Tactics</a>
    <a href="#/mitre/groups/README">Groups</a>
    <a href="#/mitre/software/README">Software</a>
    <a href="#/mitre/campaigns/README">Campaigns</a>
    <a href="#/mitre/mitigations/README">Mitigations</a>
    <a href="#/mitre/capec/README">CAPEC</a>
    <a href="#/mitre/d3fend/README">D3FEND</a>
    <a href="#/mitre/atlas/README">ATLAS</a>
    <a href="#/mitre/f3/README">F3</a>
    <a href="#/mitre/crosswalk">Crosswalk</a>
  </div>
  <a class="tsw-btn" href="#/explore">Filter these families in Explore</a>
</div>

<div class="tsw-anchor" id="study-and-career"></div>

## Browse by domain

<!-- domains:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->
<div class="tsw-domains">
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/threat-informed-defense">Threat-informed defense and ATT&amp;CK</a> <a href="#/ATTACK_MATRIX_ANALYSIS_REFERENCE">ATT&amp;CK Matrix Analysis</a> <a href="#/ATTACK_TECHNIQUE_ATLAS">ATT&amp;CK Technique Atlas</a> <a href="#/scores/attack_priority_gaps">Priority Gap Analysis</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/detection-and-response">Detection and response</a> <a href="#/THREAT_HUNTING_REFERENCE">Threat Hunting</a> <a href="#/INCIDENT_RESPONSE_REFERENCE">Incident Response</a> <a href="#/DIGITAL_FORENSICS_REFERENCE">Digital Forensics</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/threat-intelligence">Threat intelligence and adversaries</a> <a href="#/THREAT_GROUP_PROFILES">Threat Group Profiles</a> <a href="#/MALWARE_FAMILIES">Malware Families</a> <a href="#/OSINT_REFERENCE">OSINT</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/offensive-security">Offensive security</a> <a href="#/RED_TEAM_REFERENCE">Red Team</a> <a href="#/PURPLE_TEAM_REFERENCE">Purple Team</a> <a href="#/ACTIVE_DIRECTORY_ATTACKS">Active Directory Attacks</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/network-security">Network security</a> <a href="#/NETWORK_DEFENSE_REFERENCE">Network Defense</a> <a href="#/PACKET_ANALYSIS_REFERENCE">Packet Analysis</a> <a href="#/WIRELESS_SECURITY_REFERENCE">Wireless Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/cloud-and-infrastructure">Cloud and infrastructure</a> <a href="#/KUBERNETES_SECURITY_REFERENCE">Kubernetes Security</a> <a href="#/CONTAINER_SECURITY_REFERENCE">Container Security</a> <a href="#/SAAS_SECURITY_REFERENCE">SaaS Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/platform-hardening">Platform hardening</a> <a href="#/LINUX_HARDENING_REFERENCE">Linux Hardening</a> <a href="#/MACOS_SECURITY_REFERENCE">macOS Security</a> <a href="#/MOBILE_SECURITY_REFERENCE">Mobile Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/application-and-supply-chain">Application and supply chain security</a> <a href="#/SECURE_CODING_REFERENCE">Secure Coding</a> <a href="#/API_SECURITY_REFERENCE">API Security</a> <a href="#/SUPPLY_CHAIN_SECURITY_REFERENCE">Supply Chain Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/identity-and-data-protection">Identity and data protection</a> <a href="#/ACTIVE_DIRECTORY_SECURITY_REFERENCE">Active Directory Security</a> <a href="#/ZERO_TRUST_REFERENCE">Zero Trust</a> <a href="#/DATA_SECURITY_REFERENCE">Data Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/ai-and-emerging-tech">AI and emerging tech</a> <a href="#/ATLAS_REFERENCE">MITRE ATLAS</a> <a href="#/AI_MCP_SECURITY_REFERENCE">AI and MCP Security</a> <a href="#/ai-tooling/">AI Tooling</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/ics-ot-and-hardware">ICS, OT, and hardware</a> <a href="#/ICS_ATTACK_ATLAS">ICS ATT&amp;CK Atlas</a> <a href="#/HARDWARE_SECURITY_REFERENCE">Hardware Security</a> <a href="#/FIRMWARE_IOT_SECURITY_REFERENCE">Firmware and IoT Security</a></div>
  <div class="tsw-domain"><a class="tsw-domain-t" href="#/hubs/grc-and-security-program">GRC and security program</a> <a href="#/VULNERABILITY_MANAGEMENT_REFERENCE">Vulnerability Management</a> <a href="#/SECURITY_METRICS_REFERENCE">Security Metrics</a> <a href="#/CAREER_PATHS">Career Paths</a></div>
</div>
<!-- domains:end -->

<p class="tsw-more">Each domain has a hub page listing its references, with a summary and reading time for each: <a href="#/hubs/README">all domains</a>. Every reference, A to Z: <a href="#/INDEX">the reference index</a>.</p>

## What changed

<p class="tsw-lead">Changes are recorded in the <a href="#/CHANGELOG">changelog</a> as they merge to the main branch. There is no tagged release yet; when the first one is published, this section will link it.</p>

<div class="tsw-footer" id="data-amp-navigator-layers">
  <div class="tsw-footer-col">
    <div class="tsw-footer-h">TeamStarWolf library</div>
    <p>Open reference material for defenders, learners, and anyone with a security job to do. The framework pages and mapping data follow ATT&amp;CK v20.0. Original content is released under the <a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/LICENSE" target="_blank" rel="noopener">MIT License</a>; data and text drawn from MITRE and other sources stay under their owners' terms, listed in the <a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/THIRD_PARTY_NOTICES.md" target="_blank" rel="noopener">third-party notices</a>.</p>
    <a class="tsw-btn tsw-btn--navi" href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">Open ATT&amp;CK-Navi, the ATT&amp;CK workbench</a>
  </div>
  <div class="tsw-footer-col">
    <div class="tsw-footer-h">Data</div>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data" target="_blank" rel="noopener">JSONL relationship data</a>
    <a href="#/navigator/index">Navigator layers</a>
    <a href="#/ABOUT_THE_DATA">About the data</a>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/CITATION.cff" target="_blank" rel="noopener">Cite this library</a>
  </div>
  <div class="tsw-footer-col">
    <div class="tsw-footer-h">Project</div>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf" target="_blank" rel="noopener">Source on GitHub</a>
    <a href="#/CONTRIBUTING">Contributing</a>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/SECURITY.md" target="_blank" rel="noopener">Security policy</a>
    <a href="https://github.com/TeamStarWolf/TeamStarWolf/issues" target="_blank" rel="noopener">Open an issue</a>
    <a href="https://teamstarwolf.github.io/intelligence-hub/" target="_blank" rel="noopener">Intelligence Hub</a>
    <a href="https://github.com/TeamStarWolf/cybersecurity-resources" target="_blank" rel="noopener">Bookmarks</a>
  </div>
  <p class="tsw-footer-small">TeamStarWolf: <a href="#/">Library</a> · <a href="https://teamstarwolf.github.io/intelligence-hub/" target="_blank" rel="noopener">Intelligence Hub</a> · <a href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">ATT&amp;CK-Navi</a> · <a href="https://github.com/TeamStarWolf/cybersecurity-resources" target="_blank" rel="noopener">Bookmarks</a><br>ATT&amp;CK&reg; and MITRE ATT&amp;CK&reg; are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE. The TeamStarWolf name and STARWOLF 64 art are naming and art only, never a claim about people, affiliations, or capability. Star Fox is a Nintendo trademark; this project is not affiliated with or endorsed by Nintendo. Offensive material is provided for authorized security testing, education, and defensive research.</p>
</div>
