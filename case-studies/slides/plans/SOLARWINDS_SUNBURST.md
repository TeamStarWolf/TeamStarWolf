# Slide plan: SolarWinds and SUNBURST: The Supply-Chain Intrusion, 2019 to 2021

- Study: case-studies/SOLARWINDS_SUNBURST.md
- Cover title: SolarWinds and SUNBURST / The Supply-Chain Intrusion, / 2019 to 2021
- Subtitle: A signed update, a quiet backdoor and a cloud follow-on that ran through identity
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/SOLARWINDS_SUNBURST.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A signed Orion update shipped a backdoor nobody wrote

- For most of 2020, IT teams installed a routine, digitally signed SolarWinds Orion update that carried the SUNBURST backdoor.
- A build-server implant, SUNSPOT, swapped one source file for a trojanized copy during each build and then put the original back.
- Fewer than 18,000 customers may have installed it; the White House put follow-on compromise at nine federal agencies and about 100 companies.
- The most damaging phase for many victims came after the foothold: stolen AD FS signing keys, forged SAML tokens and added cloud credentials.
- The US and the UK attributed the operation to Russia's SVR in April 2021, and the actor kept working through new trusted channels.
Caption: Grades: Confirmed for the build swap, the counts and the attribution; the SEC allegations are Confirmed as allegations only.
Notes: Signed update and the SUNSPOT swap [6][7][9]. Fewer than 18,000 installs [14]. Nine agencies and about 100 companies [53]. Identity follow-on [12][22][23]. SVR attribution [54][56]. The 2021 campaigns [61][64][65].

## KEY FACTS | Most installs were never used; about 100 companies were breached

Stat: <18,000 | customers may have installed the update
Stat: ~33,000 | active-maintenance Orion customers notified
Stat: 9 | federal agencies hit by follow-on compromise
Stat: ~100 | private-sector companies compromised
- Affected releases: Orion Platform 2019.4 HF 5, 2020.2 with no hotfix and 2020.2 HF 1, released March to June 2020.
- The backdoored SolarWinds.Orion.Core.BusinessLayer.dll was signed by SolarWinds on 24 March 2020.
- No CVE covers SUNBURST; CVE-2020-10148 belongs to the separate SUPERNOVA web shell story.
Notes: Installs and notification counts [14]. Agencies and companies [53]. Affected releases [17][14]. Signing date [6]. No CVE for SUNBURST is Inferred; CVE-2020-10148 [32][33][79].

## PART 1 | The build, not the source, was the target

- SUNSPOT called itself taskhostw.exe; its binary carries a build timestamp of 20 February 2020 11:40:02.
- It polled the process list every second for MsBuild.exe and, while Orion compiled, replaced InventoryManager.cs with the SUNBURST version.
- It checked MD5 hashes before the swap so a mismatched file would not break the build, then restored the original.
- It used mutexes, AES-encrypted payload blobs, a boot-time scheduled task and an RC4-encrypted log named to pass as a VMware file.
- Kevin Mandia told the Senate that the build process, not the source code, was modified.
Caption: Code signing worked as designed and so signed the backdoor; signing happened after the source swap.
Notes: SUNSPOT behaviour and timestamp [7]. Injection into builds from 20 February 2020 [9]. Mandia testimony [45]. Signing [6]; the lesson is Inferred [7].

## PART 1 | SUNBURST was built to stay quiet for weeks

Left: Before it called home
- Waited roughly 12 to 14 days before its first beacon.
- Ran only on domain-joined hosts, after checks.
- Checked blocklists of security processes, services and drivers, and could disable services.
Right: When it called home
- Resolved victim-specific DGA subdomains of avsvmcloud[.]com over DNS.
- CNAME answers handed chosen victims to HTTP command and control.
- HTTP traffic imitated the Orion Improvement Program protocol.
- Attacker hostnames matched the victim's own; VPS addresses sat in the victim's country.
Caption: FireEye decompiled an update of about 18,000 files and 3,500 executables to find the implant.
Notes: Dormancy, guardrails and DNS command and control [6][21]. Anti-analysis and service disabling [21]. Camouflage and infrastructure [6]. Decompilation figures from Mandia's testimony [45].

## PART 1 | The worst harm ran through identity, not the Orion foothold

Left: Second stage on chosen victims
- TEARDROP and Raindrop loaders ran Cobalt Strike Beacon.
- An IFEO debugger value on dllhost.exe launched wscript.exe, then rundll32.
- auditpol changes, temporary netsh rules, a renamed AdFind and 7-Zip archiving.
- Almost every Beacon had its own command-and-control address.
Right: Cloud follow-on
- Theft of the AD FS token-signing certificate, then forged SAML tokens (Golden SAML).
- Federation trusts added or modified.
- Credentials added to service principals and OAuth apps, then Graph API calls to read mail.
- Forged SAML tokens mattered in only about 15 percent of Microsoft's cases.
Notes: Loaders and the handoff [11][6][8]. Unique Beacon infrastructure [11]. Golden SAML, federation trusts and added credentials [12][22][23]. Brad Smith's 15 percent figure [45]. Golden SAML public since 2017 [92][45].

## PART 1 | Not every victim came through Orion, and SUPERNOVA is separate

Left: Other ways in
- CISA listed password guessing and spraying, poorly secured admin credentials and external remote services.
- Volexity's think-tank case: Exchange CVE-2020-0688, a stolen Duo integration key and a forged duo-sid cookie.
- The third Volexity incident came through a backdoored Orion server in June and July 2020.
Right: SUPERNOVA is a different story
- A web shell on Orion servers, which SolarWinds treats as a separate issue.
- CISA assesses its actor as separate from the supply-chain actor.
- It used CVE-2020-10148, an Orion API authentication bypass (CWE-288).
Caption: Neither ATT&CK C0024 nor CISA AA20-352A mentions SUPERNOVA, so the study keeps it out of the mappings.
Notes: Non-Orion vectors [12]. Volexity's three incidents; the weakness was in how the integration was secured, not a Duo flaw [10]. SUPERNOVA [17][79][80]. CVE-2020-10148 [33][32]. Exclusion from the mappings is Inferred from [1][12].

## PART 2 | Alleged access in January 2019, discovery only in December 2020

| Date | Event |
|---|---|
| Jan 2019 | Alleged earliest access to SolarWinds' VPN (SEC complaint; GAO) |
| 12 Sep to 4 Nov 2019 | Trial run of the code injection |
| 20 Feb 2020 | SUNSPOT build timestamp; SUNBURST injected into builds |
| Mar to Jun 2020 | Trojanized Orion updates released |
| 4 Jun 2020 | Actor removes the malware from SolarWinds' build VMs |
| 8 Dec 2020 | FireEye discloses the theft of its red-team tools |
| 13 Dec 2020 | Mandiant publishes SUNBURST; CISA issues ED 21-01 |
| 15 Apr 2021 | US attributes to the SVR and imposes sanctions |
Caption: The dates differ by source because they measure VPN access, infrastructure and activity SolarWinds itself found.
Notes: SEC allegation and GAO [40][44]. Trial run [13]. Build timestamp and injection [7][9]. Release window [14][16]. Removal [13][9]. FireEye disclosure [47][48]. SUNBURST and ED 21-01 [6][25]. Attribution [54][55]. Discrepancies, Inferred reading [1][69][9][13].

## PART 3 | Attribution went from "nation-state" to "SVR" in four months

| Date | Who | What they said |
|---|---|---|
| 13 Dec 2020 | FireEye | UNC2452, no country |
| 17 Dec 2020 | Microsoft | A nation-state attack; Russia not named |
| 5 Jan 2021 | FBI, CISA, ODNI, NSA | An APT actor likely Russian in origin |
| 15 Apr 2021 | White House | The SVR, high confidence |
| 15 Apr 2021 | UK NCSC | Highly likely the SVR |
| 27 Apr 2022 | Mandiant | Sufficient evidence that UNC2452 is APT29 |
Caption: Kaspersky's three code overlaps with Kazuar were offered as a lead, not an attribution.
Notes: FireEye [6]. Microsoft [31]. Joint statement [52]. White House [54]. NCSC [56]. Mandiant [77]. Kazuar overlaps [70]. The names UNC2452, Dark Halo, SolarStorm, StellarParticle, NOBELIUM and Midnight Blizzard [6][10][69][7][26][75][76].

## PART 3 | The same actor turned to new trusted channels in 2021

Stat: ~3,000 | accounts phished from USAID's Constant Contact account
Stat: 140+ | cloud providers notified; as many as 14 compromised
Stat: 22,868 | attacks on 609 customers, 1 July to 19 October 2021
- NOBELIUM used an early-stage toolset of EnvyScout, BoomBox, NativeZone and VaporRage.
- Password spraying across 36 countries compromised three entities.
- FoggyWeb, in use from April 2021 at the earliest, backdoored AD FS servers.
- The October 2021 reseller campaign abused the delegated admin rights of cloud resellers.
Notes: Constant Contact phishing, more than 150 organizations [61]. Early-stage toolset [62]. Password spraying [63]. FoggyWeb [64]. Reseller and provider campaign figures [65][66].

## PART 4 | Policy moved faster than any review of the incident

- **Emergency Directive 21-01**, 13 December 2020: disconnect or power down affected Orion; sunset 8 January 2026.
- **Executive Order 14028**, 12 May 2021: SBOM elements, secure-development attestation, a Cyber Safety Review Board.
- **NTIA SBOM minimum elements** (July 2021), **NIST SSDF v1.1** (February 2022) and **OMB M-22-18** (September 2022).
- The Board's first review went to Log4j; it never reviewed SolarWinds (Reported).
- SEC v. SolarWinds and its CISO, filed 30 October 2023, was dismissed with prejudice on 20 November 2025.
Caption: The lineage from this incident to the policy is the study's inference; Log4j later shaped the SBOM argument.
Notes: ED 21-01 [25]. EO 14028 [59][60]. NTIA [97]. SSDF [87]. OMB [98]. CSRB first report [93]; ProPublica, Reported [94]. SEC complaint and dismissal [41][42][43]. Lineage Inferred.

## PART 5 | The dangerous thing had no CVE, so inventory mattered most

- SUNBURST was malicious code in a legitimate, signed product, not a flaw; the record gives it neither a CVE nor a CWE.
- The scanners that mattered in December 2020 were software inventory: which hosts ran the three affected builds.
- The remediated release, Orion 2020.2.1 HF 2, shipped on 15 December 2020; the signing certificate was revoked on 8 March 2021.
- The five CVEs the SVR exploited, per the April 2021 joint advisory, include CVE-2019-11510, CVE-2019-19781 and CVE-2018-13379.
- Removing the build was not enough: the remediation ticket for an exploited host is an incident, not a patch.
Notes: No CVE or CWE, Inferred from [17][33][35]. Affected builds [17]. HF 2 [19]. Certificate revocation [17]. Joint advisory CVEs [57]. Rebuild guidance [12]; the ticket point is Inferred.

## MITRE MAPPINGS | 112 techniques, with build, C2 and identity at the core

| Id | Technique | Tie to the SolarWinds record |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | SUNSPOT inserted SUNBURST into Orion builds |
| T1553.002 | Code Signing | DLL signed with the SolarWinds certificate |
| T1497.003 | Time Based Checks | 12 to 14 days of dormancy |
| T1071.004 | DNS | Beacons to avsvmcloud[.]com subdomains |
| T1552.004 | Private Keys | AD FS token-signing certificate theft |
| T1606.002 | SAML Tokens | Forged tokens, Golden SAML |
| T1098.001 | Additional Cloud Credentials | Credentials added to service principals |
Caption: ATT&CK v20.0: campaign C0024, group G0016 APT29, software S0559, S0562, S0560, S0565. MITRE notice in the notes.
Notes: Five ATT&CK objects cover 103 techniques; reports add nine for 112 [39]. Rows [1][2][4][6][7][12][22][23][17]. Navigator layer of 139 technique-tactic entries. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Guard the build, the egress and the identity provider

Left: Build and network
- Isolate build hosts, make build resources ephemeral and compare independent reproducible builds.
- Restrict and log management-server egress; keep passive DNS for retro-hunting.
- Hunt the second stage by behaviour: IFEO debugger values, auditpol, netsh, renamed AdFind.
Right: Identity and recovery
- Detect impossible tokens: odd lifetimes, no matching login, missing MFA claims.
- Watch AD FS configuration changes and added service-principal credentials.
- Roll the token-signing certificate twice and reset krbtgt twice.
- CISA judged a full rebuild the safest action.
Caption: Self-attestation and SBOMs are procurement levers, but a self-attestation is not an audit.
Notes: Build integrity [85][87]; reproducible builds exposing SUNSPOT is Inferred [7]. Egress and passive DNS, Inferred from [6][12]. Host hunts [11]. Identity signals [12][24][91]. Recovery [91][12]. Procurement caution [86][97][98], Inferred.

## CROSS-CUTTING THEMES | Trust was the attack surface at every hop

- **Trust is the attack surface.** A signed update, a monitoring server, an identity provider's key and a reseller's delegated rights.
- **Patience is a technique.** A test run months ahead, two weeks of dormancy and the implant removed once its job was done.
- **Disclosure came from a victim, not a control.** FireEye found it while investigating its own breach.
- **Attribution has a vocabulary.** "Likely Russian", "highly likely" and "high confidence" are different claims made months apart.
- **18,000 is an exposure count, not a victim count.** Follow-on compromise reached nine agencies and about 100 companies.
Notes: Trust pattern [6][22][66], Inferred. Patience [9][6][7][13]. Disclosure [45][47]; the agency notification is an SEC allegation [40]. Attribution vocabulary [31][52][56][54][77]. Counts [14][53].
