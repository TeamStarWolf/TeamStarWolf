<!--
  HOME.md — the site homepage (docsify renders this at "/"; README.md stays the GitHub face).
  Numbers on this page mirror README.md "At a glance" (the single source of truth) —
  update both, plus _coverpage.md bullets, in the same PR.
  Section "Browse by domain" mirrors _sidebar.md groups; section "Discipline paths"
  mirrors disciplines/*.md and disciplines/README.md.
  Link rules: raw-HTML hrefs use hash form (#/FOO, no .md); external links carry
  target="_blank" rel="noopener"; JSONL/dataset links are always github.com URLs,
  never hash routes.
-->

<div class="tsw-hero">
  <div class="tsw-hero-id">
    <span class="tsw-hero-glyph">🐺</span>
    <div>
      <div class="tsw-hero-title">TeamStarWolf</div>
      <p class="tsw-hero-tag">An open, threat-informed cybersecurity reference library — ATT&amp;CK at the center, mapped to controls, detections, and tooling.</p>
    </div>
  </div>
  <div class="tsw-hero-actions">
    <a class="tsw-btn tsw-btn--primary" href="#/INDEX">Reference Index</a>
    <a class="tsw-btn tsw-btn--ghost" href="#/THREAT_INFORMED_DEFENSE_REFERENCE">Threat-Informed Defense</a>
    <a class="tsw-btn tsw-btn--ghost" href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">ATTACK-Navi ↗</a>
  </div>
</div>

<div class="tsw-stats">
  <a class="tsw-stat" href="#/INDEX"><span class="tsw-stat-n">139</span><span class="tsw-stat-l">Reference docs</span></a>
  <a class="tsw-stat" href="#/disciplines/"><span class="tsw-stat-n">47</span><span class="tsw-stat-l">Discipline paths</span></a>
  <a class="tsw-stat" href="#/ATTACK_TECHNIQUE_ATLAS"><span class="tsw-stat-n">898</span><span class="tsw-stat-l">ATT&amp;CK techniques</span><span class="tsw-stat-s">691 Ent · 83 ICS · 124 Mobile</span></a>
  <a class="tsw-stat" href="#/detections/strategies/README"><span class="tsw-stat-n">691 + 1,739</span><span class="tsw-stat-l">Detection strategies + analytics</span></a>
  <a class="tsw-stat" href="#/CONTROLS_MAPPING"><span class="tsw-stat-n">5,314</span><span class="tsw-stat-l">Control→technique mappings</span></a>
  <a class="tsw-stat" href="#/THREAT_GROUP_PROFILES"><span class="tsw-stat-n">168 / 784</span><span class="tsw-stat-l">Threat groups / software</span></a>
  <a class="tsw-stat" href="#/navigator/"><span class="tsw-stat-n">28</span><span class="tsw-stat-l">Navigator layers</span></a>
  <a class="tsw-stat" href="#/detections/TECHNIQUE_DETECTION_LIBRARY"><span class="tsw-stat-n">65</span><span class="tsw-stat-l">Multi-platform detection queries</span></a>
</div>

## Quick router

<div class="tsw-router">
  <div class="tsw-card">
    <div class="tsw-card-h">Map coverage &amp; gaps</div>
    <a class="tsw-card-l" href="#/THREAT_INFORMED_DEFENSE_REFERENCE">Threat-Informed Defense</a>
    <a class="tsw-card-l" href="#/ATTACK_MATRIX_ANALYSIS_REFERENCE">ATT&amp;CK Matrix Analysis</a>
    <a class="tsw-card-l" href="#/scores/attack_priority_gaps">Priority Gap Analysis</a>
    <a class="tsw-card-l" href="#/navigator/">Navigator Layers</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Build detections</div>
    <a class="tsw-card-l" href="#/detections/TECHNIQUE_DETECTION_LIBRARY">Technique Detection Library</a>
    <a class="tsw-card-l" href="#/detections/strategies/README">Detection Strategies</a>
    <a class="tsw-card-l" href="#/DETECTION_RULES_REFERENCE">Detection Rules</a>
    <a class="tsw-card-l" href="#/SIEM_REFERENCE">SIEM Reference</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Hunt</div>
    <a class="tsw-card-l" href="#/THREAT_HUNTING_REFERENCE">Threat Hunting</a>
    <a class="tsw-card-l" href="#/THREAT_HUNTING_PLAYBOOKS">Hunting Playbooks</a>
    <a class="tsw-card-l" href="#/ATTACK_DATA_COMPONENTS">Data Components &amp; Log Sources</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Respond now</div>
    <a class="tsw-card-l" href="#/INCIDENT_RESPONSE_REFERENCE">Incident Response</a>
    <a class="tsw-card-l" href="#/IR_PLAYBOOKS">IR Playbooks</a>
    <a class="tsw-card-l" href="#/RANSOMWARE_DEFENSE_REFERENCE">Ransomware Defense</a>
    <a class="tsw-card-l" href="#/DIGITAL_FORENSICS_REFERENCE">Digital Forensics</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Emulate &amp; test</div>
    <a class="tsw-card-l" href="#/PENETRATION_TESTING_METHODOLOGY">Pentest Methodology</a>
    <a class="tsw-card-l" href="#/PENTEST_CHECKLISTS">Pentest Checklists</a>
    <a class="tsw-card-l" href="#/RED_TEAM_REFERENCE">Red Team</a>
    <a class="tsw-card-l" href="#/PURPLE_TEAM_REFERENCE">Purple Team</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Harden</div>
    <a class="tsw-card-l" href="#/WINDOWS_HARDENING_REFERENCE">Windows Hardening</a>
    <a class="tsw-card-l" href="#/LINUX_HARDENING_REFERENCE">Linux Hardening</a>
    <a class="tsw-card-l" href="#/CLOUD_SECURITY_REFERENCE">Cloud Security</a>
    <a class="tsw-card-l" href="#/ZERO_TRUST_REFERENCE">Zero Trust</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Know the adversary</div>
    <a class="tsw-card-l" href="#/THREAT_GROUP_PROFILES">Threat Group Profiles</a>
    <a class="tsw-card-l" href="#/THREAT_ACTORS">Threat Actors</a>
    <a class="tsw-card-l" href="#/MALWARE_FAMILIES">Malware Families</a>
    <a class="tsw-card-l" href="#/ATTACK_CAMPAIGNS_REFERENCE">Campaigns</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Prioritize &amp; govern</div>
    <a class="tsw-card-l" href="#/VULNERABILITY_MANAGEMENT_REFERENCE">Vulnerability Management</a>
    <a class="tsw-card-l" href="#/VULNERABILITY_PRIORITIZATION_REFERENCE">Vulnerability Prioritization</a>
    <a class="tsw-card-l" href="#/CTEM_REFERENCE">CTEM</a>
    <a class="tsw-card-l" href="#/SECURITY_METRICS_REFERENCE">Security Metrics</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Secure AI</div>
    <a class="tsw-card-l" href="#/ATLAS_REFERENCE">ATLAS</a>
    <a class="tsw-card-l" href="#/AI_SECURITY_REFERENCE">AI Security</a>
    <a class="tsw-card-l" href="#/AI_MCP_SECURITY_REFERENCE">AI &amp; MCP Security</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Deceive</div>
    <a class="tsw-card-l" href="#/ENGAGE_REFERENCE">Engage</a>
    <a class="tsw-card-l" href="#/HONEYPOT_DECEPTION_REFERENCE">Honeypot &amp; Deception</a>
    <a class="tsw-card-l" href="#/DECEPTION_TECHNOLOGY_REFERENCE">Deception Technology</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Fight fraud</div>
    <a class="tsw-card-l" href="#/FRAUD_FRAMEWORK_REFERENCE">F3 Fraud Framework</a>
    <a class="tsw-card-l" href="#/SOCIAL_ENGINEERING_REFERENCE">Social Engineering</a>
    <a class="tsw-card-l" href="#/IDENTITY_SECURITY_REFERENCE">Identity Security</a>
  </div>
  <div class="tsw-card">
    <div class="tsw-card-h">Level up</div>
    <a class="tsw-card-l" href="#/CAREER_PATHS">Career Paths</a>
    <a class="tsw-card-l" href="#/CERTIFICATIONS">Certifications</a>
    <a class="tsw-card-l" href="#/LABS">Hands-On Labs</a>
    <a class="tsw-card-l" href="#/HOMELAB_SETUP">Home Lab Setup</a>
  </div>
</div>

Or press <kbd>/</kbd> and type a technique ID — T1059 works.

## How it connects

One knowledge graph runs through the whole library — from a vulnerability to the weakness it exploits, the attack pattern that uses it, the ATT&CK technique it becomes, and the countermeasure that stops it.

<div class="tsw-chain">
  <a class="tsw-chip" href="#/CVE_REFERENCE">CVE</a>
  <a class="tsw-chip" href="#/CWE_REFERENCE">CWE <span class="tsw-chip-n">969</span></a>
  <a class="tsw-chip" href="#/CAPEC_REFERENCE">CAPEC <span class="tsw-chip-n">615</span></a>
  <a class="tsw-chip" href="#/ATTACK_TECHNIQUE_ATLAS">ATT&amp;CK <span class="tsw-chip-n">898</span></a>
  <a class="tsw-chip" href="#/D3FEND_REFERENCE">D3FEND <span class="tsw-chip-n">156</span></a>
</div>

<div class="tsw-chips">
  <span class="tsw-chips-label">Beyond the enterprise intrusion</span>
  <a class="tsw-chip" href="#/ATLAS_REFERENCE">ATLAS · AI <span class="tsw-chip-n">170</span></a>
  <a class="tsw-chip" href="#/ENGAGE_REFERENCE">Engage · deception <span class="tsw-chip-n">31</span></a>
  <a class="tsw-chip" href="#/FRAUD_FRAMEWORK_REFERENCE">F3 · fraud <span class="tsw-chip-n">123</span></a>
  <a class="tsw-chip" href="#/EMB3D_REFERENCE">EMB3D · embedded</a>
  <a class="tsw-chip" href="#/TELECOM_5G_SECURITY_REFERENCE">FiGHT · 5G</a>
  <a class="tsw-chip" href="#/SPACE_SECURITY_REFERENCE">SPARTA · space</a>
  <a class="tsw-chip" href="#/CTEM_REFERENCE">CTEM · exposure loop</a>
</div>

## Flagships

<div class="tsw-flagship">
  <div class="tsw-card tsw-flag">
    <a class="tsw-flag-t" href="#/THREAT_INFORMED_DEFENSE_REFERENCE">Threat-Informed Defense Reference</a>
    <p class="tsw-flag-sub">ATT&amp;CK enriched into decisions: per-technique coverage stacks, 24 analytic lenses, and the NIST 800-53 mappings to act on them.</p>
    <div class="tsw-flag-links">
      <a class="tsw-flag-cta" href="#/THREAT_INFORMED_DEFENSE_REFERENCE">Open the reference →</a>
      <a class="tsw-flag-2nd" href="#/techniques/README">per-technique pages →</a>
    </div>
  </div>
  <div class="tsw-card tsw-flag">
    <a class="tsw-flag-t" href="#/detections/strategies/README">Detection Engineering</a>
    <p class="tsw-flag-sub">MITRE's own detection guidance made operational: 691 strategies, 1,739 analytics, and ready-to-adapt queries for Splunk, Elastic, Microsoft, Chronicle, and CrowdStrike.</p>
    <div class="tsw-flag-links">
      <a class="tsw-flag-cta" href="#/detections/strategies/README">Open the strategies →</a>
      <a class="tsw-flag-2nd" href="#/detections/TECHNIQUE_DETECTION_LIBRARY">Technique Detection Library →</a>
    </div>
  </div>
  <div class="tsw-card tsw-flag">
    <a class="tsw-flag-t" href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">ATTACK-Navi ↗</a>
    <p class="tsw-flag-sub">The interactive workbench: coverage, detection, exposure &amp; risk heatmaps over the same data.</p>
    <div class="tsw-flag-links">
      <a class="tsw-flag-cta" href="https://teamstarwolf.github.io/ATTACK-Navi/" target="_blank" rel="noopener">Open ATTACK-Navi ↗</a>
      <a class="tsw-flag-2nd" href="https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json" target="_blank" rel="noopener">load the master layer in Navigator ↗</a>
    </div>
  </div>
</div>

## Browse by domain

<!-- Mirrors _sidebar.md — when the sidebar gains/loses a doc, update this section in the same PR. -->
<div class="tsw-switchboard">
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🗺️ Coverage &amp; Data</div>
    <a class="tsw-swb-l" href="#/THREAT_INFORMED_DEFENSE_REFERENCE">Threat-Informed Defense</a>
    <a class="tsw-swb-l" href="#/ATTACK_MATRIX_ANALYSIS_REFERENCE">ATT&amp;CK Matrix Analysis</a>
    <a class="tsw-swb-l" href="#/ATTACK_TECHNIQUE_ATLAS">ATT&amp;CK Technique Atlas</a>
    <a class="tsw-swb-l" href="#/detections/strategies/README">Detection Strategies</a>
    <a class="tsw-swb-l" href="#/ATTACK_DATA_COMPONENTS">Data Components</a>
    <a class="tsw-swb-l" href="#/scores/attack_priority_gaps">Priority Gaps</a>
    <a class="tsw-swb-l" href="#/ICS_ATTACK_ATLAS">ICS ATT&amp;CK Atlas</a>
    <a class="tsw-swb-l" href="#/MOBILE_ATTACK_ATLAS">Mobile ATT&amp;CK Atlas</a>
    <a class="tsw-swb-more" href="#/INDEX">all 29 →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🛡️ Defense &amp; Detection</div>
    <a class="tsw-swb-l" href="#/DETECTION_RULES_REFERENCE">Detection Rules</a>
    <a class="tsw-swb-l" href="#/SIEM_REFERENCE">SIEM Reference</a>
    <a class="tsw-swb-l" href="#/SIEM_DETECTION_CONTENT">SIEM Detection Content</a>
    <a class="tsw-swb-l" href="#/THREAT_HUNTING_REFERENCE">Threat Hunting</a>
    <a class="tsw-swb-l" href="#/THREAT_HUNTING_PLAYBOOKS">Hunting Playbooks</a>
    <a class="tsw-swb-l" href="#/ENDPOINT_SECURITY_REFERENCE">Endpoint Security</a>
    <a class="tsw-swb-l" href="#/LOTL_DETECTION_REFERENCE">LOTL Detection</a>
    <a class="tsw-swb-l" href="#/NETWORK_DEFENSE_REFERENCE">Network Defense</a>
    <a class="tsw-swb-more" href="#/INDEX">more →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🎯 Threat Intelligence &amp; Adversaries</div>
    <a class="tsw-swb-l" href="#/THREAT_INTELLIGENCE_REFERENCE">Threat Intelligence</a>
    <a class="tsw-swb-l" href="#/THREAT_ACTORS">Threat Actors</a>
    <a class="tsw-swb-l" href="#/MALWARE_FAMILIES">Malware Families</a>
    <a class="tsw-swb-l" href="#/NOTABLE_INCIDENTS">Notable Incidents</a>
    <a class="tsw-swb-l" href="#/OSINT_REFERENCE">OSINT</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🚨 Incident Response &amp; Forensics</div>
    <a class="tsw-swb-l" href="#/INCIDENT_RESPONSE_REFERENCE">Incident Response</a>
    <a class="tsw-swb-l" href="#/IR_PLAYBOOKS">IR Playbooks</a>
    <a class="tsw-swb-l" href="#/RANSOMWARE_DEFENSE_REFERENCE">Ransomware Defense &amp; Resilience</a>
    <a class="tsw-swb-l" href="#/CYBER_RESILIENCE_BCDR_REFERENCE">Cyber Resilience &amp; BCDR</a>
    <a class="tsw-swb-l" href="#/DIGITAL_FORENSICS_REFERENCE">Digital Forensics</a>
    <a class="tsw-swb-l" href="#/NETWORK_FORENSICS_REFERENCE">Network Forensics</a>
    <a class="tsw-swb-l" href="#/MALWARE_ANALYSIS_REFERENCE">Malware Analysis</a>
    <a class="tsw-swb-l" href="#/REVERSE_ENGINEERING_REFERENCE">Reverse Engineering</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">⚔️ Offensive Security</div>
    <a class="tsw-swb-l" href="#/RED_TEAM_REFERENCE">Red Team</a>
    <a class="tsw-swb-l" href="#/PURPLE_TEAM_REFERENCE">Purple Team</a>
    <a class="tsw-swb-l" href="#/PENETRATION_TESTING_METHODOLOGY">Pentest Methodology</a>
    <a class="tsw-swb-l" href="#/PENTEST_CHECKLISTS">Pentest Checklists</a>
    <a class="tsw-swb-l" href="#/WEB_APPLICATION_PENTESTING">Web App Pentesting</a>
    <a class="tsw-swb-l" href="#/ACTIVE_DIRECTORY_ATTACKS">AD Attacks</a>
    <a class="tsw-swb-l" href="#/CLOUD_ATTACK_REFERENCE">Cloud Attack</a>
    <a class="tsw-swb-l" href="#/PRIVESC_REFERENCE">Privilege Escalation</a>
    <a class="tsw-swb-more" href="#/INDEX">more →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🌐 Network Security</div>
    <a class="tsw-swb-l" href="#/NETWORKING_FUNDAMENTALS">Networking Fundamentals</a>
    <a class="tsw-swb-l" href="#/NETWORK_PROTOCOLS_REFERENCE">Network Protocols</a>
    <a class="tsw-swb-l" href="#/NETWORK_PROTOCOLS_SECURITY">Network Protocols Security</a>
    <a class="tsw-swb-l" href="#/NETWORK_SECURITY_ARCHITECTURE">Network Security Architecture</a>
    <a class="tsw-swb-l" href="#/EDGE_DEVICE_SECURITY_REFERENCE">Edge &amp; Network Device Security</a>
    <a class="tsw-swb-l" href="#/PACKET_ANALYSIS_REFERENCE">Packet Analysis</a>
    <a class="tsw-swb-l" href="#/WIRELESS_SECURITY_REFERENCE">Wireless Security</a>
    <a class="tsw-swb-l" href="#/SDR_RF_SECURITY_REFERENCE">SDR &amp; RF Security</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">☁️ Cloud &amp; Infrastructure</div>
    <a class="tsw-swb-l" href="#/CLOUD_SECURITY_REFERENCE">Cloud Security</a>
    <a class="tsw-swb-l" href="#/CLOUD_SECURITY_BENCHMARK">Cloud Security Benchmark</a>
    <a class="tsw-swb-l" href="#/CLOUD_NETWORK_SECURITY">Cloud Network Security</a>
    <a class="tsw-swb-l" href="#/SAAS_SECURITY_REFERENCE">SaaS Security</a>
    <a class="tsw-swb-l" href="#/CONTAINER_SECURITY_REFERENCE">Container Security</a>
    <a class="tsw-swb-l" href="#/KUBERNETES_SECURITY_REFERENCE">Kubernetes Security</a>
    <a class="tsw-swb-l" href="#/DEVSECOPS_REFERENCE">DevSecOps</a>
    <a class="tsw-swb-l" href="#/SECRETS_MANAGEMENT_REFERENCE">Secrets Management</a>
    <a class="tsw-swb-more" href="#/INDEX">more →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">💻 Application Security</div>
    <a class="tsw-swb-l" href="#/SECURE_CODING_REFERENCE">Secure Coding</a>
    <a class="tsw-swb-l" href="#/WEB_APPLICATION_SECURITY_REFERENCE">Web Application Security</a>
    <a class="tsw-swb-l" href="#/API_SECURITY_REFERENCE">API Security</a>
    <a class="tsw-swb-l" href="#/BROWSER_SECURITY_REFERENCE">Browser Security</a>
    <a class="tsw-swb-l" href="#/THREAT_MODELING_REFERENCE">Threat Modeling</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🖥️ Platform Hardening</div>
    <a class="tsw-swb-l" href="#/WINDOWS_HARDENING">Windows Hardening</a>
    <a class="tsw-swb-l" href="#/WINDOWS_HARDENING_REFERENCE">Windows Hardening Reference</a>
    <a class="tsw-swb-l" href="#/WINDOWS_HARDENING_GPO">Windows Hardening GPO</a>
    <a class="tsw-swb-l" href="#/LINUX_HARDENING">Linux Hardening</a>
    <a class="tsw-swb-l" href="#/LINUX_HARDENING_REFERENCE">Linux Hardening Reference</a>
    <a class="tsw-swb-l" href="#/MACOS_SECURITY_REFERENCE">macOS Security</a>
    <a class="tsw-swb-l" href="#/MOBILE_SECURITY_REFERENCE">Mobile Security</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🔐 Identity &amp; Data Protection</div>
    <a class="tsw-swb-l" href="#/IDENTITY_SECURITY_REFERENCE">Identity Security</a>
    <a class="tsw-swb-l" href="#/IDENTITY_ACCESS_MANAGEMENT_REFERENCE">Identity &amp; Access Management</a>
    <a class="tsw-swb-l" href="#/ACTIVE_DIRECTORY_SECURITY_REFERENCE">Active Directory Security</a>
    <a class="tsw-swb-l" href="#/PASSWORD_SECURITY_REFERENCE">Password Security</a>
    <a class="tsw-swb-l" href="#/ZERO_TRUST_REFERENCE">Zero Trust</a>
    <a class="tsw-swb-l" href="#/CRYPTOGRAPHY_REFERENCE">Cryptography</a>
    <a class="tsw-swb-l" href="#/POST_QUANTUM_MIGRATION_REFERENCE">Post-Quantum Migration</a>
    <a class="tsw-swb-l" href="#/DATA_SECURITY_REFERENCE">Data Security</a>
    <a class="tsw-swb-more" href="#/INDEX">more →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🤖 AI &amp; Emerging Tech</div>
    <a class="tsw-swb-l" href="#/AI_SECURITY_REFERENCE">AI Security</a>
    <a class="tsw-swb-l" href="#/AI_MCP_SECURITY_REFERENCE">AI &amp; MCP Security</a>
    <a class="tsw-swb-l" href="#/AI_OFFENSIVE_SECURITY_REFERENCE">AI Offensive Security</a>
    <a class="tsw-swb-l" href="#/BLOCKCHAIN_SECURITY_REFERENCE">Blockchain Security</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🏭 ICS, OT &amp; Hardware</div>
    <a class="tsw-swb-l" href="#/ICS_OT_SECURITY_REFERENCE">ICS/OT Security</a>
    <a class="tsw-swb-l" href="#/HARDWARE_SECURITY_REFERENCE">Hardware Security</a>
    <a class="tsw-swb-l" href="#/FIRMWARE_IOT_SECURITY_REFERENCE">Firmware &amp; IoT Security</a>
    <a class="tsw-swb-l" href="#/AUTOMOTIVE_SECURITY_REFERENCE">Automotive Security</a>
    <a class="tsw-swb-l" href="#/PHYSICAL_SECURITY_REFERENCE">Physical Security</a>
    <a class="tsw-swb-l" href="#/SECURITY_GADGETS_REFERENCE">Security Gadgets</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">📋 GRC &amp; Security Program</div>
    <a class="tsw-swb-l" href="#/GRC_REFERENCE">GRC Reference</a>
    <a class="tsw-swb-l" href="#/GRC_COMPLIANCE_REFERENCE">GRC Compliance</a>
    <a class="tsw-swb-l" href="#/FRAMEWORKS">Frameworks</a>
    <a class="tsw-swb-l" href="#/ENTERPRISE_SECURITY_CONTROLS">Enterprise Security Controls</a>
    <a class="tsw-swb-l" href="#/SECURITY_ARCHITECTURE_REFERENCE">Security Architecture</a>
    <a class="tsw-swb-l" href="#/SECURITY_METRICS_REFERENCE">Security Metrics</a>
    <a class="tsw-swb-l" href="#/VULNERABILITY_MANAGEMENT_REFERENCE">Vulnerability Management</a>
    <a class="tsw-swb-l" href="#/VULNERABILITY_PRIORITIZATION_REFERENCE">Vulnerability Prioritization</a>
    <a class="tsw-swb-more" href="#/INDEX">more →</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">🎓 Careers &amp; Learning</div>
    <a class="tsw-swb-l" href="#/CAREER_PATHS">Career Paths</a>
    <a class="tsw-swb-l" href="#/CERTIFICATIONS">Certifications</a>
    <a class="tsw-swb-l" href="#/INTERVIEW_PREP">Interview Prep</a>
    <a class="tsw-swb-l" href="#/LABS">Hands-On Labs</a>
    <a class="tsw-swb-l" href="#/HOMELAB_SETUP">Home Lab Setup</a>
    <a class="tsw-swb-l" href="#/CTF_METHODOLOGY">CTF Methodology</a>
    <a class="tsw-swb-l" href="#/GLOSSARY">Glossary</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">📖 Resources</div>
    <a class="tsw-swb-l" href="#/STARRED_REPOS">Starred Repositories</a>
    <a class="tsw-swb-l" href="#/CYBERSECURITY_BOOK_LIST">Book List</a>
    <a class="tsw-swb-l" href="#/YOUTUBE_CHANNELS">YouTube Channels</a>
    <a class="tsw-swb-l" href="#/TWITTER_FOLLOW_LIST">X / Twitter List</a>
    <a class="tsw-swb-l" href="#/RESOURCES">Resources</a>
    <a class="tsw-swb-l" href="#/OPEN_SOURCE_TOOLKIT">Open Source Toolkit</a>
    <a class="tsw-swb-l" href="#/TOOLS">Tools Reference</a>
  </div>
</div>

## Discipline paths

47 guided paths take you from zero to working practitioner — the right references in the right order.

<div class="tsw-chips">
  <span class="tsw-chips-label">Defend &amp; respond</span>
  <a class="tsw-chip" href="#/disciplines/detection-engineering">Detection Engineering</a>
  <a class="tsw-chip" href="#/disciplines/threat-hunting">Threat Hunting</a>
  <a class="tsw-chip" href="#/disciplines/incident-response">Incident Response</a>
  <a class="tsw-chip" href="#/disciplines/digital-forensics">Digital Forensics</a>
  <a class="tsw-chip" href="#/disciplines/malware-analysis">Malware Analysis</a>
  <a class="tsw-chip" href="#/disciplines/siem-soar">SIEM &amp; SOAR</a>
  <a class="tsw-chip" href="#/disciplines/security-operations">Security Operations</a>
  <a class="tsw-chip" href="#/disciplines/threat-intelligence">Threat Intelligence</a>
  <a class="tsw-chip" href="#/disciplines/active-defense-deception">Active Defense &amp; Deception</a>
  <a class="tsw-chip" href="#/disciplines/osint">OSINT</a>
  <span class="tsw-chips-label">Attack &amp; assess</span>
  <a class="tsw-chip" href="#/disciplines/offensive-security">Offensive Security</a>
  <a class="tsw-chip" href="#/disciplines/red-teaming">Red Teaming</a>
  <a class="tsw-chip" href="#/disciplines/penetration-testing">Penetration Testing</a>
  <a class="tsw-chip" href="#/disciplines/purple-teaming">Purple Teaming</a>
  <a class="tsw-chip" href="#/disciplines/exploit-development">Exploit Development</a>
  <a class="tsw-chip" href="#/disciplines/bug-bounty">Bug Bounty</a>
  <a class="tsw-chip" href="#/disciplines/social-engineering">Social Engineering</a>
  <a class="tsw-chip" href="#/disciplines/physical-security">Physical Security</a>
  <a class="tsw-chip" href="#/disciplines/reverse-engineering">Reverse Engineering</a>
  <span class="tsw-chips-label">Build &amp; harden</span>
  <a class="tsw-chip" href="#/disciplines/cloud-security">Cloud Security</a>
  <a class="tsw-chip" href="#/disciplines/container-kubernetes-security">Container &amp; Kubernetes Security</a>
  <a class="tsw-chip" href="#/disciplines/devsecops">DevSecOps</a>
  <a class="tsw-chip" href="#/disciplines/application-security">Application Security</a>
  <a class="tsw-chip" href="#/disciplines/supply-chain-security">Supply Chain Security</a>
  <a class="tsw-chip" href="#/disciplines/network-security">Network Security</a>
  <a class="tsw-chip" href="#/disciplines/identity-access-management">Identity &amp; Access Management</a>
  <a class="tsw-chip" href="#/disciplines/active-directory">Active Directory</a>
  <a class="tsw-chip" href="#/disciplines/zero-trust-architecture">Zero Trust Architecture</a>
  <a class="tsw-chip" href="#/disciplines/data-security">Data Security</a>
  <a class="tsw-chip" href="#/disciplines/cryptography-pki">Cryptography &amp; PKI</a>
  <span class="tsw-chips-label">Govern</span>
  <a class="tsw-chip" href="#/disciplines/governance-risk-compliance">Governance, Risk &amp; Compliance</a>
  <a class="tsw-chip" href="#/disciplines/vulnerability-management">Vulnerability Management</a>
  <a class="tsw-chip" href="#/disciplines/cyber-risk-quantification">Cyber Risk Quantification</a>
  <a class="tsw-chip" href="#/disciplines/threat-modeling">Threat Modeling</a>
  <a class="tsw-chip" href="#/disciplines/privacy-engineering">Privacy Engineering</a>
  <a class="tsw-chip" href="#/disciplines/security-awareness">Security Awareness</a>
  <a class="tsw-chip" href="#/disciplines/security-architecture">Security Architecture</a>
  <span class="tsw-chips-label">Specialized &amp; emerging</span>
  <a class="tsw-chip" href="#/disciplines/ai-llm-security">AI &amp; LLM Security</a>
  <a class="tsw-chip" href="#/disciplines/ai-ml-security">AI/ML Security</a>
  <a class="tsw-chip" href="#/disciplines/adversarial-ai-attacks">Adversarial AI Attacks</a>
  <a class="tsw-chip" href="#/disciplines/blockchain-web3-security">Blockchain &amp; Web3 Security</a>
  <a class="tsw-chip" href="#/disciplines/hardware-security">Hardware Security</a>
  <a class="tsw-chip" href="#/disciplines/iot-security">IoT Security</a>
  <a class="tsw-chip" href="#/disciplines/ics-ot-security">ICS/OT Security</a>
  <a class="tsw-chip" href="#/disciplines/mobile-security">Mobile Security</a>
  <a class="tsw-chip" href="#/disciplines/radio-frequency-security">RF Security</a>
  <a class="tsw-chip" href="#/disciplines/hacker-hobbies">Hacker Hobbies</a>
  <a class="tsw-chip tsw-chip--all" href="#/disciplines/">All 47 paths →</a>
</div>

## Data & Navigator layers

<!-- JSONL/dataset links must stay github.com URLs — docsify's hash router cannot serve raw files. -->
<div class="tsw-databand">
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">Datasets</div>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack" target="_blank" rel="noopener">ATT&amp;CK core — technique_profiles, group/software/mitigation→technique, campaigns ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack" target="_blank" rel="noopener">Detections — detection_strategies, analytics, data_components ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses" target="_blank" rel="noopener">Weaknesses — cwe, capec ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl" target="_blank" rel="noopener">Technique → D3FEND edges ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/control_to_technique.jsonl" target="_blank" rel="noopener">Coverage edges — control_to_technique (5,314 edges) ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/vendor_to_control.jsonl" target="_blank" rel="noopener">vendor_to_control ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/vendor_to_technique.jsonl" target="_blank" rel="noopener">vendor_to_technique ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/ai" target="_blank" rel="noopener">ATLAS datasets (data/ai) ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/engage" target="_blank" rel="noopener">Engage datasets (data/engage) ↗</a>
    <a class="tsw-swb-l" href="https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/fraud" target="_blank" rel="noopener">F3 fraud datasets (data/fraud) ↗</a>
  </div>
  <div class="tsw-swb-group">
    <div class="tsw-swb-h">Layers</div>
    <a class="tsw-swb-l" href="#/navigator/">Navigator layers index (28 layers)</a>
    <a class="tsw-swb-l" href="https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json" target="_blank" rel="noopener">Load master coverage layer ↗</a>
    <a class="tsw-swb-l" href="https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/analytics/no_nist_coverage.json" target="_blank" rel="noopener">Framework blind spots (223 unmapped techniques) ↗</a>
    <a class="tsw-swb-l" href="https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/analytics/group_frequency.json" target="_blank" rel="noopener">Group frequency ↗</a>
    <a class="tsw-swb-l" href="#/CONTROLS_MAPPING">Controls Mapping</a>
    <a class="tsw-swb-l" href="#/COVERAGE_SCHEMA">Coverage Schema</a>
  </div>
</div>

Control mappings sourced from CTID (NIST 800-53 R5 → ATT&CK).

## Learn & grow

<div class="tsw-swb-group tsw-learn">
  <a class="tsw-swb-l" href="#/CAREER_PATHS">Career Paths</a>
  <a class="tsw-swb-l" href="#/CERTIFICATIONS">Certifications</a>
  <a class="tsw-swb-l" href="#/INTERVIEW_PREP">Interview Prep</a>
  <a class="tsw-swb-l" href="#/LABS">Hands-On Labs</a>
  <a class="tsw-swb-l" href="#/HOMELAB_SETUP">Home Lab Setup</a>
  <a class="tsw-swb-l" href="#/CYBERSECURITY_BOOK_LIST">Book List</a>
  <a class="tsw-swb-l" href="#/STARRED_REPOS">Starred Repos</a>
</div>

Free training platforms (Antisyphon, PortSwigger, HTB Academy, TryHackMe, LetsDefend and more) live in [Hands-On Labs](/LABS.md) and [Resources](/RESOURCES.md).

<div class="tsw-footer">
  <div class="tsw-footer-links">
    <a href="#/.github/CONTRIBUTING">Contribute</a><span class="tsw-footer-sep">·</span><a href="https://github.com/TeamStarWolf/TeamStarWolf/issues" target="_blank" rel="noopener">Open an issue ↗</a><span class="tsw-footer-sep">·</span><a href="https://github.com/TeamStarWolf/TeamStarWolf/blob/main/LICENSE" target="_blank" rel="noopener">MIT License ↗</a><span class="tsw-footer-sep">·</span><a href="https://github.com/TeamStarWolf/ATTACK-Navi" target="_blank" rel="noopener">ATTACK-Navi repo ↗</a><span class="tsw-footer-sep">·</span><a href="https://github.com/TeamStarWolf/LimeWire" target="_blank" rel="noopener">LimeWire ↗</a><span class="tsw-footer-sep">·</span><a href="https://github.com/TeamStarWolf/PokeNav" target="_blank" rel="noopener">PokeNav ↗</a>
  </div>
  <div class="tsw-footer-small">
    All offensive material is for authorized security testing, education, and defensive research only.<br>
    🐺 TeamStarWolf — built for the cybersecurity community.
  </div>
</div>
