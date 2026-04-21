# Notable Cybersecurity Incidents

> A curated reference of significant cyber incidents, nation-state campaigns, ransomware events, and critical vulnerabilities. Maintained as part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity reference library.

---

## Table of Contents

1. [Early Hacking History (1986–2009)](#1-early-hacking-history-19862009)
2. [Nation-State Campaigns (2010–2020)](#2-nation-state-campaigns-20102020)
3. [Recent Events (2020–2025)](#3-recent-events-20202025)
4. [Ransomware Incident Reference](#4-ransomware-incident-reference)
5. [Ransomware Incident Response — Negotiation Guide](#5-ransomware-incident-response--negotiation-guide)
6. [Contacting Authorities](#6-contacting-authorities)
7. [Critical Vulnerability Classes to Watch](#7-critical-vulnerability-classes-to-watch)
8. [Related Resources](#related-resources)

---

## 1. Early Hacking History (1986–2009)

The incidents below established the legal, technical, and geopolitical frameworks that define modern cybersecurity. Many introduced concepts — worms, espionage, social engineering, mass exploitation — that remain central today.

| Year | Incident | Actor | Impact | Significance |
|------|----------|-------|--------|--------------|
| 1986 | **Hannover Hackers / Clifford Stoll** | Hess/KGB-linked West German hackers | Penetrated US military/research networks (LBL, MILNET) | First documented cyber espionage case; Stoll's honeypot technique pioneered active defense; documented in *The Cuckoo's Egg* |
| 1988 | **Morris Worm** | Robert Tappan Morris (Cornell grad student) | ~6,000 Unix machines crashed (~10% of the internet at the time); estimated $100K–$10M damage | First major internet worm; first person convicted under the CFAA; exposed the dangers of buffer overflows and sendmail/fingerd vulnerabilities |
| 1994 | **Citibank Wire Transfer Heist** | Vladimir Levin (Russia) | $10.7M fraudulently transferred; ~$400K unrecovered | First major online bank fraud; exploited Citibank's cash management system via dial-up; demonstrated financial system cyber risk |
| 1995 | **Kevin Mitnick Arrested** | Kevin Mitnick | Penetrated Nokia, Motorola, Sun, and dozens of other companies; stole source code | Most-wanted hacker of his era; social engineering legend; his arrest shaped the Computer Fraud and Abuse Act's interpretation; no-internet probation conditions made headlines |
| 1999 | **Melissa Virus** | David L. Smith | 1M+ machines infected; $80M+ in damages; overloaded mail servers at Microsoft, Intel, and the US Marine Corps | First macro/email hybrid worm to go mainstream; spread via infected Word documents through Outlook; established email as a primary attack vector |
| 2000 | **MafiaBoy DDoS** | Michael Calce ("MafiaBoy"), age 15 | Took down Yahoo, Amazon, eBay, CNN, Dell — estimated $1.2B in damages | One of the first major distributed denial-of-service attacks against commercial internet infrastructure; catalyzed FBI/RCMP cybercrime cooperation |
| 2003 | **SQL Slammer Worm** | Unknown | Infected 75,000+ hosts in 10 minutes; doubled every 8.5 seconds; disrupted ATMs, 911 systems, airline ticketing, South Korean internet | Fastest-spreading worm in history; exploited an unpatched MS SQL Server 2000 buffer overflow (MS02-039); proved patch management was existential |
| 2007 | **Estonia DDoS Campaign** | Russian nationalist hackers (Nashi, attributed) | Took down parliament, banks, newspapers, and government portals for weeks | First nation-state-level coordinated cyberattack against an entire country's digital infrastructure; catalyzed NATO cyber doctrine and the Tallinn Manual |
| 2008 | **Operation Buckshot Yankee / AGENT.BTZ** | Russian GRU/SVR (attributed) | Infected classified and unclassified US military networks including US CENTCOM; required 14 months to remediate | Malicious USB drive dropped in a parking lot; penetrated air-gapped classified networks; directly caused the creation of US Cyber Command and the ban on USB drives in military contexts |
| 2009 | **Operation Aurora** | APT10 / Comment Crew (Chinese PLA Unit 61398, attributed) | Breached Google, Adobe, Juniper Networks, and 30+ other technology companies; stole source code and human-rights activists' Gmail data | First publicly acknowledged large-scale Chinese APT campaign; prompted Google to nearly leave China; established "advanced persistent threat" as a household term |

---

## 2. Nation-State Campaigns (2010–2020)

This era saw state-sponsored hacking mature into a strategic geopolitical instrument — targeting critical infrastructure, political processes, financial systems, and the intelligence community itself.

### 2010 — Stuxnet

- **Target:** Natanz uranium enrichment facility, Iran
- **Attribution:** Joint US/Israel operation (attributed, not officially confirmed until 2011 leaks)
- **Method:** Four zero-days chained together; spread via USB; targeted Siemens S7-315/S7-417 PLCs controlling IR-1 centrifuges; caused centrifuges to spin out of spec while reporting normal status to operators
- **Impact:** Destroyed roughly 1,000 centrifuges; set back Iranian nuclear program ~2 years
- **Significance:** First known cyberweapon specifically designed to cause physical destruction of industrial equipment; established ICS/SCADA as a legitimate warfare domain; inspired every subsequent ICS-targeting malware family (Industroyer, TRITON, etc.)

### 2011 — RSA SecurID Breach

- **Target:** RSA Security (EMC)
- **Attribution:** APT1 / Comment Crew (Chinese PLA Unit 61398)
- **Method:** Spear-phishing email with malicious Excel attachment exploiting Flash zero-day; pivoted to steal the seed values for 40 million SecurID tokens
- **Impact:** Enabled subsequent attacks on Lockheed Martin, Northrop Grumman, L-3 Communications using cloned RSA tokens; RSA replaced all tokens at a cost of ~$66M
- **Significance:** Demonstrated supply-chain attacks on security vendors; compromised the root-of-trust underpinning US defense contractor remote access

### 2011 — Operation Shady RAT

- **Target:** 72+ organizations including US government agencies, defense contractors, the UN, the IOC, and various national Olympic committees
- **Attribution:** Chinese government (attributed by McAfee)
- **Method:** Spear-phishing leading to remote access trojans; longest-running APT campaign disclosed at the time — active for 5+ years
- **Impact:** Terabytes of sensitive data exfiltrated; full scope never publicly disclosed
- **Significance:** McAfee's disclosure report coined "RAT" as a standard term and brought APT campaigns to board-level attention worldwide

### 2012 — Shamoon (Disttrack)

- **Target:** Saudi Aramco and RasGas (Qatar)
- **Attribution:** Iranian IRGC / APT33 (Elfin)
- **Method:** Spear-phishing for initial access; custom wiper malware overwrote MBR and files with an image of a burning US flag
- **Impact:** 30,000+ Saudi Aramco workstations rendered inoperable in hours; forced Aramco to revert to manual operations for weeks; global hard drive shortage as Aramco replaced destroyed equipment
- **Significance:** First major destructive cyberattack against energy sector critical infrastructure; established the "wiper" attack category; foreshadowed NotPetya

### 2013 — Target Data Breach

- **Target:** Target Corporation (US retail)
- **Attribution:** Eastern European cybercriminals (Rescator marketplace)
- **Method:** Phishing email to Fazio Mechanical (HVAC vendor); used vendor VPN credentials to pivot to Target POS systems; installed RAM-scraping malware on 1,800+ POS terminals
- **Impact:** 40M credit/debit card numbers and 70M personal records stolen; $291M total costs; CEO and CIO resigned
- **Significance:** First major high-profile supply-chain breach; established that vendor trust relationships are a primary attack vector; reshaped PCI-DSS enforcement

### 2014 — Sony Pictures Hack

- **Target:** Sony Pictures Entertainment
- **Attribution:** Lazarus Group / Bureau 121 (DPRK, attributed by FBI)
- **Method:** Spear-phishing + credential theft; deployed "Destover" wiper malware; exfiltrated ~100TB of data before wiping
- **Impact:** Unreleased films leaked; executive salary data, embarrassing emails, and employee SSNs exposed; ~$35M in IT recovery costs; film release decisions affected by threats
- **Significance:** First major DPRK offensive cyber operation publicly attributed; demonstrated that nation-states would use cyberattacks as retaliation for cultural/political content (in response to *The Interview*); established destructive wipers as a DPRK hallmark

### 2015 — OPM Breach

- **Target:** US Office of Personnel Management
- **Attribution:** Chinese APT (Axiom group / APT17, attributed)
- **Method:** Stolen contractor credentials (KeyPoint Government Solutions); persistent access over ~14 months; exfiltrated SF-86 security clearance investigation files
- **Impact:** 21.5M current/former/prospective federal employee background investigation records stolen, including 5.6M fingerprints; data included details of foreign contacts, mental health history, financial history
- **Significance:** Worst known US government intelligence breach in history; SF-86 data allows identification and potential blackmail of intelligence officers worldwide; catalyzed DHS CDM program

### 2016 — SWIFT Banking Heists

- **Target:** Bangladesh Bank, Banco del Austro (Ecuador), RCBC (Philippines), and others
- **Attribution:** Lazarus Group / DPRK (attributed by BAE Systems, Symantec)
- **Method:** Compromised SWIFT messaging terminals; injected fraudulent wire transfer instructions to Federal Reserve Bank of New York; malware suppressed confirmation messages
- **Impact:** $81M stolen from Bangladesh Bank alone (of $951M attempted); funds routed through Philippine casinos and laundered; ~$1B total attempted across all SWIFT heists
- **Significance:** First major attack on the international financial messaging backbone; exposed that SWIFT member banks had no mandatory security standards; SWIFT established the Customer Security Programme (CSP) in response

### 2016 — DNC Hack & Election Interference

- **Target:** Democratic National Committee, Hillary Clinton campaign (John Podesta), DCCC
- **Attribution:** APT28 / Fancy Bear (Russian GRU Unit 26165 and Unit 74455)
- **Method:** Spear-phishing (Podesta's "legitimate email" click); X-Agent keylogger/implant; data exfiltrated and released via Guccifer 2.0 persona and WikiLeaks
- **Impact:** Thousands of internal emails released; measurable effect on 2016 US presidential election; DNC chair resigned
- **Significance:** Established cyber operations as a primary tool of election interference; introduced "hack and leak" as an influence operation technique; triggered Mueller investigation and IC Community Assessment

### 2016 — Mirai Botnet

- **Target:** Dyn DNS provider (and internet at large)
- **Attribution:** Paras Jha, Josiah White, Dalton Norman (US college students)
- **Method:** Scanned internet for IoT devices with default credentials (Telnet); infected cameras, DVRs, routers; launched 1.2+ Tbps DDoS against Dyn
- **Impact:** Took down Twitter, Netflix, Reddit, Spotify, GitHub, PayPal, CNN for hours on October 21, 2016
- **Significance:** First botnet built entirely from consumer IoT devices; source code release enabled dozens of derivative botnets; exposed catastrophic IoT security failures and the fragility of DNS infrastructure

### 2016–2017 — Shadow Brokers Leaks

- **Target:** NSA's Equation Group (TAO division)
- **Attribution:** Unclear; possibly Russian GRU or insider (never formally charged)
- **Method:** Unknown initial theft vector; NSA offensive toolset posted publicly in stages
- **Impact:** Release included EternalBlue (MS17-010 SMB exploit), EternalRomance, DoublePulsar backdoor, and dozens of other zero-days; tools weaponized within weeks into WannaCry and NotPetya
- **Significance:** Largest public leak of offensive cyber capabilities in history; demonstrated that nation-state zero-days cannot be safely stockpiled; reignited Vulnerabilities Equities Process debate

### 2017 — WannaCry

- **Target:** Global (indiscriminate); notably NHS UK, FedEx/TNT, Telefónica, Renault, Russian Interior Ministry
- **Attribution:** Lazarus Group / DPRK (attributed by US, UK, Australia)
- **Method:** EternalBlue + DoublePulsar (leaked NSA tools) for lateral movement; encrypted files and demanded $300–$600 Bitcoin ransom; no targeted victim selection
- **Impact:** 200,000+ systems across 150 countries; NHS UK cancelled ~19,000 appointments and surgeries; ~$4–8B in total damages; 327 Bitcoin collected (relatively little)
- **Significance:** First global ransomware worm; demonstrated that leaked nation-state exploits could be weaponized for mass destruction; kill-switch discovery by Marcus Hutchins ("MalwareTech") stopped spread; exposed NHS's chronic under-patching

### 2017 — NotPetya

- **Target:** Initially Ukrainian businesses; spread globally to Maersk, Merck, FedEx/TNT, Mondelez, Reckitt Benckiser, Saint-Gobain
- **Attribution:** Sandworm / GRU Unit 74455 (attributed by US, UK, EU)
- **Method:** Distributed via trojanized update to M.E.Doc Ukrainian accounting software; EternalBlue for lateral spread; MBR wiper disguised as ransomware; no functional decryption capability
- **Impact:** $10B+ in global damages (largest in history); Maersk replaced 45,000 PCs and 4,000 servers; Merck $870M; FedEx $400M; Ukraine's financial and government systems largely paralyzed
- **Significance:** Definitively classified as a cyberweapon, not ransomware; established supply-chain software updates as a top-tier attack vector; demonstrated that destructive cyberattacks cause kinetic-level economic damage; directly inspired NIST supply chain security guidance

### 2020 — SolarWinds / SUNBURST

- **Target:** SolarWinds Orion platform customers; confirmed victims include US Treasury, State, DHS, DOJ, NSA, and 100+ private companies
- **Attribution:** APT29 / Cozy Bear (SVR, Russian Foreign Intelligence Service)
- **Method:** Trojanized SolarWinds Orion software update (DLL backdoor "SUNBURST"); 18,000 organizations installed the update; attackers manually selected ~100 high-value targets for second-stage TEARDROP/RAINDROP implants
- **Impact:** Months-long undetected access to US government networks; extent of data stolen classified; FireEye's own red team tools stolen; discovered only by accident (FireEye anomaly detection)
- **Significance:** Most sophisticated supply-chain attack ever documented; forced complete CISA emergency directive; reshaped zero-trust architecture adoption; SUNBURST's anti-forensic techniques set a new bar for APT operational security

---

## 3. Recent Events (2020–2025)

### 2021 — Colonial Pipeline (DarkSide Ransomware)

- **Date:** May 7, 2021
- **Actor:** DarkSide (RaaS affiliate, Eastern European)
- **Method:** Compromised VPN account (no MFA) using a leaked password found in a dark web dump; deployed DarkSide ransomware to IT network; operators proactively shut down OT pipeline operations out of caution
- **Impact:** 5,500 miles of US East Coast fuel pipeline shut for 6 days; fuel shortages across 17 states; Biden declared national emergency; $4.4M ransom paid; DOJ recovered ~$2.3M via Bitcoin wallet seizure
- **Significance:** First ransomware attack to trigger US national emergency declaration; demonstrated that IT/OT convergence makes critical infrastructure vulnerable even when OT systems are not directly attacked; DarkSide disbanded within days under US pressure

### 2021 — Kaseya VSA (REvil)

- **Date:** July 2, 2021 (timed to US Independence Day weekend)
- **Actor:** REvil / Sodinokibi (RaaS)
- **Method:** Zero-day in Kaseya VSA on-premises RMM software (auth bypass + arbitrary file upload); compromised ~60 MSPs, pushing ransomware to all managed endpoints; 1,500+ downstream businesses affected
- **Impact:** $70M ransom demand (largest ever at time); Coop Swedish grocery chain closed 800 stores; Dutch IT companies, New Zealand schools affected; universal decryptor key later obtained by FBI and shared
- **Significance:** Largest MSP supply-chain ransomware attack; demonstrated that MSPs are a force-multiplier for ransomware; REvil subsequently shut down, re-emerged, and was finally disrupted in January 2022

### 2021 — Log4Shell (CVE-2021-44228)

- **Date:** Disclosed December 9, 2021
- **Affected Software:** Apache Log4j 2 (versions 2.0-beta9 through 2.14.1) — ubiquitous Java logging library
- **Method:** JNDI injection via any logged string; attacker-controlled LDAP/RMI server returns malicious Java class; unauthenticated RCE; exploitable in a single HTTP header
- **CVSS:** 10.0 (Critical)
- **Impact:** Hundreds of millions of devices vulnerable; mass exploitation within hours of disclosure by nation-states (HAFNIUM, Lazarus, Iranian APTs), RaaS groups, and cryptominers; CISA called it "the most serious vulnerability I have seen in my decades-long career"
- **Significance:** Most widely exploited vulnerability of the 2020s; demonstrated the fragility of open-source dependency chains; catalyzed SBOM (Software Bill of Materials) requirements in US Executive Order 14028

### 2021 — Microsoft Exchange ProxyLogon / ProxyShell

- **ProxyLogon (CVE-2021-26855):** Pre-auth SSRF + CVE-2021-27065 post-auth file write = pre-auth RCE; disclosed March 2021; HAFNIUM exploited as zero-day
- **ProxyShell (CVE-2021-34473 / 34523 / 31207):** URL normalization bypass + privilege escalation + arbitrary file write; exploited in mass exploitation waves August 2021 by LockBit, Conti, BlackByte, Babuk affiliates
- **Impact:** Tens of thousands of Exchange servers compromised globally; web shells planted en masse; CISA emergency directive issued; hundreds of US government agencies affected
- **Significance:** Illustrated how a single product's widespread deployment makes it a strategic target; ProxyShell exploitation continued 18+ months after patches were available

### 2022 — Lapsus$ Group

- **Targets:** Microsoft (Bing/Cortana source code), Okta (customer support systems), Nvidia (DLSS source code, employee credentials), Samsung (Galaxy source code), T-Mobile, Ubisoft, Vodafone, Globant
- **Actor:** Loosely organized teenagers, primarily UK and Brazilian, ages 16–21
- **Method:** SIM swapping; social engineering help desks; purchasing insider access; MFA fatigue attacks (repeated push notification bombing); recruiting insiders on Telegram
- **Impact:** Massive source code leaks; Okta breach affected ~2.5% of customers; Nvidia GPU driver signing certificates leaked and used to sign malware
- **Significance:** Demonstrated that sophisticated technical attacks are unnecessary when humans are the weakest link; forced industry-wide re-evaluation of MFA (TOTP/hardware keys over push notifications); Okta's handling criticized as inadequate

### 2022 — Uber Breach

- **Date:** September 15, 2022
- **Actor:** 18-year-old (claimed affiliation with Lapsus$)
- **Method:** Purchased credentials of an Uber contractor on dark web; bypassed MFA via WhatsApp social engineering (posed as Uber IT, convinced target to approve MFA push); pivoted to internal tools, Slack, HackerOne bug reports, AWS, GCP, GSuite admin
- **Impact:** Full access to Uber's internal infrastructure; HackerOne vulnerability reports exposed; employee data accessed; no customer payment data confirmed stolen
- **Significance:** Textbook MFA fatigue attack executed by a teenager; HackerOne exposure meant open vulnerability reports were visible; demonstrated that privileged internal tooling (Slack, admin consoles) requires the same zero-trust treatment as production systems

### 2022–2023 — LastPass Breach

- **Date:** Initial breach August 2022; vault theft November/December 2022; disclosed fully January 2023
- **Actor:** Unattributed (financially motivated)
- **Method:** Compromised a DevOps engineer's home computer (via vulnerable media software); used stolen credentials to access LastPass cloud backup storage containing encrypted password vaults
- **Impact:** Encrypted password vaults for all ~33M users stolen; unencrypted metadata (URLs, usernames) also taken; multiple downstream cryptocurrency thefts totaling $35M+ attributed to vault decryption of high-value targets
- **Significance:** Demonstrated that password managers themselves are high-value targets; weak master passwords (under 12 characters, reused) are crackable offline; incident response transparency failures eroded trust; catalyzed industry discussion of zero-knowledge architecture limits

### 2023 — MOVEit Transfer (Cl0p)

- **Date:** May 27–28, 2023 (mass exploitation); June 2023 (disclosure cascade)
- **Actor:** Cl0p ransomware gang (TA505, Russian-speaking)
- **CVE:** CVE-2023-34362 (SQL injection leading to RCE in Progress Software MOVEit Transfer)
- **Method:** Unauthenticated SQL injection to extract admin credentials; deploy web shell ("LEMURLOOT"); exfiltrate all data; no encryption deployed — pure extortion via data theft
- **Impact:** 2,500+ organizations affected; 90M+ individuals' records stolen; victims include US government agencies (DOE, OPM), Shell, British Airways, BBC, Boots, Johns Hopkins, Ernst & Young, Aon, Cognizant; total damages estimated $9.9B+
- **Significance:** Largest single-vulnerability mass exploitation event in history; Cl0p's "no encryption" model proved that ransomware groups don't need ransomware — data theft alone is sufficient leverage; highlighted managed file transfer software as a systemic risk

### 2023 — MGM Resorts (Scattered Spider)

- **Date:** September 2023
- **Actor:** Scattered Spider (UNC3944) — English-speaking teenagers/young adults, some US/UK nationals
- **Method:** LinkedIn OSINT to identify IT help desk employees; vishing (voice phishing) to impersonate employee and reset MFA; pivoted to Okta, then Azure, then ESXi hypervisors; deployed ALPHV/BlackCat ransomware to encrypt ESXi hosts
- **Impact:** 10-day outage of MGM's casino operations, hotel check-in systems, slot machines, and digital room keys across Las Vegas; $100M+ in losses; customer data including SSNs and passport numbers of 6M+ guests stolen
- **Significance:** Demonstrated that Scattered Spider's combination of social engineering + legitimate tool abuse (living-off-the-land) could defeat enterprise security stacks; contrast with Caesars Entertainment (paid ~$15M ransom quietly same month); vishing remains devastatingly effective

### 2024 — Change Healthcare (BlackCat/ALPHV)

- **Date:** February 21, 2024
- **Actor:** BlackCat/ALPHV ransomware (affiliate-driven)
- **Method:** Stolen credentials to Citrix remote access portal (no MFA); lateral movement to Change Healthcare's network; 6TB of data exfiltrated; ransomware deployed
- **Impact:** Change Healthcare processes ~15B healthcare transactions/year (~1/3 of all US healthcare billing); outage paralyzed pharmacies, hospitals, and insurance claims processing for weeks; UnitedHealth Group paid $22M ransom; total impact estimated $872M–$2.7B; ALPHV exit-scammed the affiliate after receiving ransom
- **Significance:** Single point of failure in US healthcare billing infrastructure; most disruptive cyberattack on US healthcare ever; exposed catastrophic concentration risk; ALPHV subsequently disbanded; UHG CEO congressional testimony reshaped healthcare cybersecurity regulation

### 2024 — CDK Global (BlackSuit)

- **Date:** June 2024
- **Actor:** BlackSuit ransomware (successor to Royal ransomware)
- **Method:** Social engineering for initial access; ransomware deployed to CDK's SaaS platform
- **Impact:** CDK Global provides dealer management systems to ~15,000 US automotive dealerships; outage lasted ~2 weeks forcing dealers to use paper; CDK reportedly paid ~$25M ransom; estimated $1B+ in lost revenue across the industry
- **Significance:** Demonstrated SaaS platform single points of failure; automotive industry has no manual fallback for modern dealership operations; reinforced concentration risk concerns raised by Change Healthcare

### 2023–2025 — Volt Typhoon (Chinese Pre-Positioning)

- **Actor:** Volt Typhoon (Bronze Silhouette) — Chinese MSS/PLA (attributed by US IC, Five Eyes)
- **Targets:** US critical infrastructure — power utilities, water systems, telecommunications, transportation, military logistics nodes; Guam infrastructure specifically targeted
- **Method:** Living-off-the-land (LOTL) — exclusively uses native OS tools (wmic, ntdsutil, netsh, PowerShell); no custom malware deployed; compromises SOHO routers (Cisco, Netgear, ASUS) as proxy infrastructure; long-dwell persistent access
- **Impact:** Confirmed presence in multiple US critical infrastructure sectors; CISA/FBI issued emergency advisories; some victims had Volt Typhoon present for 5+ years undetected; no destructive action taken — assessed as pre-positioning for wartime disruption
- **Significance:** Shift from intelligence collection to sabotage pre-positioning; LOTL techniques defeat signature-based detection; assessed as preparation for potential conflict over Taiwan; forced rethinking of OT/IT network segmentation and SOHO router security

---

## 4. Ransomware Incident Reference

### Evolution Timeline

| Period | Milestone | Key Characteristics |
|--------|-----------|---------------------|
| 1989 | **AIDS Trojan** (Joseph Popp) | First ransomware; distributed via floppy disk; symmetric encryption; demanded $189 payment to PO Box |
| 2013 | **CryptoLocker** | First modern ransomware; RSA-2048 + AES-256; Bitcoin payment demanded; ~$27M collected before Gameover ZeuS takedown |
| 2014–2016 | **Bitcoin ransom standardization** | Bitcoin enables anonymous payment collection; ransomware-as-a-service emerges; targets shift from consumers to SMBs |
| 2016–2018 | **RaaS model matures** | Affiliates handle deployment; developers take 20–30% cut; Cerber, Satan, GandCrab pioneer subscription models |
| 2019–2020 | **Big game hunting + double extortion** | Maze introduces data exfiltration before encryption; threat to publish data removes backup as defense; average ransom jumps from $5K to $100K+ |
| 2021–2022 | **Triple extortion** | DDoS attacks on victim added as third pressure lever; threats to contact customers/partners/regulators directly; REvil, Conti, LockBit dominate |
| 2022–2023 | **Encryption-free extortion** | Cl0p MOVEit attacks use pure data theft; no ransomware needed when data exfiltration alone provides leverage |
| 2024–2025 | **Fragmentation + branding churn** | Law enforcement disruptions cause group rebranding (DarkSide→BlackMatter→ALPHV→BlackCat); ecosystem remains resilient |

### RaaS Business Model

```
┌─────────────────────────────────────────────────────┐
│              Ransomware Ecosystem                    │
│                                                      │
│  Initial Access Brokers (IABs)                       │
│  └─ Buy/sell network access on dark web forums       │
│     Prices: $500 (SMB) – $100,000 (Fortune 500)      │
│                                                      │
│  RaaS Developers (Core Group)                        │
│  └─ Write malware, maintain infrastructure           │
│     Take: 20–30% of ransom payments                  │
│                                                      │
│  Affiliates                                          │
│  └─ Deploy ransomware, negotiate with victims        │
│     Take: 70–80% of ransom payments                  │
│                                                      │
│  Money Launderers / Cashout Services                 │
│  └─ Convert crypto, provide cash                    │
└─────────────────────────────────────────────────────┘
```

### Notable Ransomware Groups — Status

| Group | Active Period | Notable Incidents | Status |
|-------|--------------|-------------------|--------|
| **REvil / Sodinokibi** | 2019–2022 | Kaseya VSA ($70M demand), JBS Foods ($11M), Travelex | Disrupted Jan 2022; Russian FSB arrested 14 members; some members re-emerged |
| **Conti** | 2020–2022 | HSE Ireland (healthcare system), Costa Rica government ($10M demand), Broward County Schools | Disbanded May 2022 after internal chat leaks and backlash over Russia support; splinter groups formed (BlackBasta, Royal, etc.) |
| **DarkSide** | 2020–2021 | Colonial Pipeline ($4.4M paid) | Disbanded May 2021 under US government pressure following Colonial Pipeline; infrastructure seized |
| **LockBit** | 2019–present | Royal Mail UK, Boeing, ICBC, Fulton County GA | Operation Cronos (Feb 2024) disrupted infrastructure, seized servers, arrested affiliates, decryptor released; LockBit 3.0 rebranded and resumed operations within days |
| **ALPHV / BlackCat** | 2021–2024 | MGM Resorts, Change Healthcare ($22M) | FBI seized infrastructure Dec 2023 (released decryptor for 500 victims); exit-scammed affiliates after Change Healthcare ransom; effectively disbanded mid-2024 |
| **Cl0p (TA505)** | 2019–present | MOVEit (90M+ records), Accellion FTA, GoAnywhere | Active; specializes in managed file transfer zero-days; rarely encrypts, prefers pure extortion |
| **Scattered Spider** | 2022–present | MGM Resorts ($100M+), Caesars Entertainment (~$15M) | Active; US/UK nationals; several arrests 2023–2024 including alleged ringleader |

---

## 5. Ransomware Incident Response — Negotiation Guide

> **Disclaimer:** This section is for cybersecurity professionals advising organizations under attack. Payment decisions require qualified legal counsel. Paying ransoms to sanctioned entities is a federal crime.

### Step 1 — Immediate OFAC Sanctions Check (Before Any Payment)

The US Treasury's Office of Foreign Assets Control (OFAC) maintains a Specially Designated Nationals (SDN) list. Paying a ransom to a sanctioned entity — even if unaware — can result in civil penalties up to $1M+ and criminal charges.

- Check: [ofac.treasury.gov](https://ofac.treasury.gov) — SDN list search
- Known sanctioned ransomware groups: Evil Corp (OFAC sanctioned Dec 2019 — **do not pay**), Sandworm/TrickBot operators (sanctioned Sept 2019)
- Retain legal counsel with OFAC expertise **before** any payment decision
- OFAC issued guidance that paying ransoms to sanctioned groups is a strict liability offense — "I didn't know" is not a defense

### Step 2 — Engage Professional Incident Response

| Firm | Services | Contact |
|------|----------|---------|
| **Coveware** | Ransom negotiation, decryptor QA, threat actor attribution | coveware.com |
| **Kivu Consulting** | Negotiation, forensics, OFAC compliance guidance | kivuconsulting.com |
| **Mandiant / Google Cloud** | IR, negotiation, attribution, nation-state expertise | mandiant.com |
| **Palo Alto Unit 42** | IR, ransomware negotiation, threat intel | unit42.paloaltonetworks.com |
| **CrowdStrike Services** | IR, negotiation, ransomware-specific expertise | crowdstrike.com/services |

### Step 3 — Payment Decision Framework

Work through these questions **in order** before any payment decision:

```
1. Can we restore from clean, verified, offline backups?
   YES → Do not pay. Focus on restoration and forensics.
   NO  → Continue to step 2.

2. Is data actually exfiltrated (double extortion confirmed)?
   YES → Data is already stolen; payment does NOT guarantee deletion.
         Factor in breach notification obligations regardless.
   NO  → Encryption-only attack; backup restoration is the primary path.

3. Is the threat actor on the OFAC SDN list?
   YES → Do not pay without OFAC license. Consult legal counsel immediately.
   NO  → Continue to step 4.

4. What are the regulatory notification requirements?
      - HIPAA: 60 days from discovery
      - SEC (public companies): 4 business days after materiality determination
      - GDPR: 72 hours to supervisory authority
      - State breach laws: typically 30–72 hours

5. What is the operational impact of continued downtime vs. payment risk?
      - Patient safety / life-safety systems: escalate urgency
      - Revenue loss vs. ransom cost
      - Reputational damage of data publication
```

### Step 4 — Negotiation Principles

- **Delay is your ally:** Every hour of delay buys time for IR teams to restore systems and reduce dependency on the decryptor. Tell negotiators you need "time to gather funds" or "approval from the board."
- **Request proof of decryption:** Before any payment discussion, demand a test decryption of 2–3 non-sensitive files. This confirms the decryptor works and that the actor possesses the key.
- **Never pay the first demand:** Ransomware groups expect negotiation. Typical negotiated reduction is **40–60% off the initial demand.** Counter with 10–20% of the ask and work up.
- **Establish communication channel hygiene:** Use dedicated email/communications isolated from compromised systems. Assume the attacker is still watching internal comms.
- **Document everything:** All communications preserved for law enforcement, cyber insurance claims, and regulatory inquiries.
- **Do not negotiate from a position of urgency:** Never reveal the full scope of damage or your insurance coverage limits.

### Step 5 — After Payment (If Made)

- **Decryptor quality varies:** Some decryptors are slow, buggy, or corrupt files. Do not delete encrypted files until restoration is confirmed. Maintain encrypted backups.
- **78–80% of payers are hit again within one year** (Cybereason, 2021 survey). Re-infection risk is high if root cause is not fully remediated.
- **Attacker still has the data:** Payment does not guarantee stolen data is deleted. Treat all exfiltrated data as permanently compromised.
- **Mandatory cyber insurance notification:** Most policies require notification within 24–72 hours of discovery.
- **Full forensic investigation required:** Identify the initial access vector, lateral movement path, persistence mechanisms, and full dwell time before declaring remediation complete.

### Free Decryptors — No More Ransom Project

**nomoreransom.org** — Joint initiative by Europol, Interpol, and security vendors.

- Free decryptors available for **150+ ransomware families** including: Avaddon, Babuk, DarkSide, GandCrab, HermeticRansom, Maze, MegaCortex, REvil/Sodinokibi (partial), Shade/Troldesh, WannaCry
- Always check before paying — a free decryptor may already exist
- Submit ransomware samples to help researchers develop new decryptors

---

## 6. Contacting Authorities

> Reporting to authorities is strongly recommended. Law enforcement agencies have intelligence on active threat actors, may have decryption keys, and reporting helps protect other victims. Reports are confidential.

### United States

| Agency | Role | Contact |
|--------|------|---------|
| **FBI — Internet Crime Complaint Center (IC3)** | Primary cyber crime reporting; ransomware, fraud, nation-state intrusions | [ic3.gov](https://ic3.gov) |
| **FBI Local Field Office** | Direct engagement for active incidents; 24/7 availability for critical infrastructure | [fbi.gov/contact-us/field-offices](https://www.fbi.gov/contact-us/field-offices) |
| **CISA (Cybersecurity & Infrastructure Security Agency)** | Critical infrastructure incidents; operational assistance; free IR support available | [cisa.gov/report](https://cisa.gov/report) · 888-282-0870 · report@cisa.dhs.gov |
| **US Secret Service — Electronic Crimes Task Force (ECTF)** | Financial cybercrime, ransomware with financial nexus | [secretservice.gov/investigation/cyber](https://www.secretservice.gov/investigation/cyber) |
| **National Cyber-Forensics and Training Alliance (NCFTA)** | Industry-law enforcement partnership; particularly useful for financial sector | [ncfta.net](https://www.ncfta.net) |
| **US-CERT / CISA ICS-CERT** | ICS/SCADA and OT-specific incidents | [us-cert.cisa.gov](https://us-cert.cisa.gov) |

### International

| Country | Agency | Contact |
|---------|--------|---------|
| **United Kingdom** | National Cyber Security Centre (NCSC) | [ncsc.gov.uk/cyberalert](https://www.ncsc.gov.uk/cyberalert) |
| **United Kingdom** | Action Fraud (financial cybercrime) | [actionfraud.police.uk](https://www.actionfraud.police.uk) |
| **European Union** | Europol European Cybercrime Centre (EC3) | [europol.europa.eu/report-a-crime/report-cybercrime-online](https://www.europol.europa.eu/report-a-crime/report-cybercrime-online) |
| **Australia** | Australian Cyber Security Centre (ACSC) | [cyber.gov.au/acsc/report](https://www.cyber.gov.au/acsc/report) · 1300 CYBER1 |
| **Canada** | Canadian Centre for Cyber Security (CCCS) | [cyber.gc.ca](https://www.cyber.gc.ca) · 1-833-CYBER-88 |
| **Germany** | BSI (Bundesamt für Sicherheit in der Informationstechnik) | [bsi.bund.de](https://www.bsi.bund.de) |
| **Interpol** | Cybercrime Directorate (via national police) | Contact national law enforcement to initiate |

> **Tip:** For active ransomware incidents, contact the **FBI and CISA simultaneously**. CISA can provide immediate free technical assistance and the FBI may already have intelligence on the threat actor and potentially decryption keys.

---

## 7. Critical Vulnerability Classes to Watch

The following vulnerability classes have proven to be high-impact, widely exploited, or structurally significant. Security teams should treat each as a standing detection and patching priority.

| CVE Class | Representative CVEs | CVSS Range | Why It Matters |
|-----------|--------------------|-----------:|----------------|
| **Microsoft Exchange ProxyLogon** | CVE-2021-26855, CVE-2021-27065 | 9.1–9.8 | Pre-auth SSRF chained to arbitrary file write = unauthenticated RCE; exploited as zero-day by HAFNIUM (Chinese APT); >250,000 servers exposed on disclosure day; web shells left behind persist for years |
| **Microsoft Exchange ProxyShell** | CVE-2021-34473, CVE-2021-34523, CVE-2021-31207 | 7.2–9.8 | URL path confusion bypass + privilege escalation + file write; mass-exploited by LockBit, Conti, and other RaaS affiliates; still actively exploited 3+ years after patch |
| **Log4Shell** | CVE-2021-44228, CVE-2021-45046 | 10.0 | JNDI injection in Apache Log4j 2; unauthenticated RCE via any logged string; affects hundreds of millions of Java applications; exploited by nation-states within hours of PoC publication; SBOM-class vulnerability |
| **PrintNightmare** | CVE-2021-34527, CVE-2021-1675 | 8.2–8.8 | Windows Print Spooler LPE and remote code execution; affects all Windows versions; patch bypass found within days; impacts domain controllers; exploited by Vice Society, Magniber ransomware |
| **Follina / MSDT** | CVE-2022-30190 | 7.8 | Microsoft Support Diagnostic Tool RCE triggered by specially crafted Office documents; exploited without macros via ms-msdt: URI handler; exploited by TA413 (Chinese APT) targeting Tibet; patched June 2022 |
| **MOVEit Transfer SQLi** | CVE-2023-34362, CVE-2023-35036, CVE-2023-35708 | 9.1–9.8 | SQL injection in Progress MOVEit Transfer; unauthenticated; mass-exploited by Cl0p in coordinated global campaign; 90M+ records stolen; largest single-vulnerability breach event in history |
| **Citrix Bleed** | CVE-2023-4966 | 9.4 | Session token leak from Citrix NetScaler ADC/Gateway; allows session hijacking bypassing MFA; exploited by LockBit affiliate against Boeing, DP World, ICBC, Allen & Overy; CISA emergency directive issued |
| **ConnectWise ScreenConnect** | CVE-2024-1708, CVE-2024-1709 | 9.8–10.0 | Authentication bypass + path traversal; RCE on ScreenConnect RMM; exploited by LockBit, ransomware affiliates, nation-states within 48 hours of PoC; affects hundreds of MSPs |
| **Ivanti Connect Secure** | CVE-2025-0282, CVE-2023-46805, CVE-2024-21887 | 9.0–10.0 | Pre-auth stack overflow / auth bypass / command injection in Ivanti VPN appliances; exploited by Chinese APT (UNC5221/5337) as zero-days; CISA ordered federal agencies to disconnect; ICT (Integrity Checker Tool) repeatedly bypassed |
| **Citrix/Netscaler (general)** | CVE-2023-3519 | 9.8 | Unauthenticated RCE in Citrix ADC/NetScaler; exploited as zero-day against critical infrastructure; CISA alert AA23-201A; implants installed before patch release |

### Vulnerability Prioritization Guidance

When triaging, prioritize patching based on:

1. **CISA KEV (Known Exploited Vulnerabilities) Catalog** — [cisa.gov/kev](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — mandatory patching deadlines for federal agencies; use as a baseline for all orgs
2. **EPSS Score** (Exploit Prediction Scoring System) — probability a CVE will be exploited in the wild within 30 days
3. **Asset exposure** — internet-facing systems (VPNs, file transfer, email) require faster patching than internal-only
4. **Compensating controls** — can you segment, disable, or add WAF rules while patching?

---

## Related Resources

This file is part of the TeamStarWolf cybersecurity reference library. See also:

| File | Description |
|------|-------------|
| [IR_PLAYBOOKS.md](./IR_PLAYBOOKS.md) | Incident response playbooks by incident type (ransomware, data breach, insider threat, nation-state APT) |
| [THREAT_ACTORS.md](./THREAT_ACTORS.md) | Threat actor profiles — APT groups, RaaS gangs, hacktivist groups; TTPs, targets, and attribution |
| [MALWARE_FAMILIES.md](./MALWARE_FAMILIES.md) | Malware family reference — ransomware, RATs, wipers, banking trojans, rootkits |
| [DETECTION_RULES_REFERENCE.md](./DETECTION_RULES_REFERENCE.md) | YARA rules, Sigma rules, SIEM queries, and detection strategies by threat category |

---

*Last updated: 2025 · Maintained by [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) · Contributions welcome via pull request*
