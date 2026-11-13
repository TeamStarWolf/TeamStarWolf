# Slide plan: CVE-2026-123039 and Root on the Check Point Gateway: The PHP2Shell Chain, the TSGA Implant and the ESXi Wiper of October and November 2026

- Study: case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md
- Cover title: CVE-2026-123039 and Root / on the Check Point Gateway
- Subtitle: The PHP2Shell chain, the TSGA implant and the ESXi wiper of October and November 2026
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHECK_POINT_GAIA_CVE_2026_123039.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A local flaw became a remote root chain

- PHP2Shell on unpatched Mobile Access portals gave the attacker a foothold.
- CVE-2026-123039 in the Gaia DynamicCLI daemon turned that foothold into root.
- Implants built for the appliance followed, then an SSH hop to VMware ESXi.
- In the first wave, on 30 October, a wiper ran on the hypervisor.
- The CVE was published on 12 November, two weeks after the first wave.
Caption: Evidence grade: Confirmed from the CVE record, sk1000362 and the Check Point Research report.
Notes: Chain [5]. Flaw [1][3]. Publication [1]. Exploited before any fix or record existed (Inferred from [1][3][5]).

## KEY FACTS | A 7.8 score on a flaw that delivered root

Stat: 7.8 | CVSS 3.1 base score (CNA), local vector
Stat: 2 | Attack waves before the CVE existed
Stat: 4 | Release lines with a fixed Take
Stat: 2 | End-of-support lines with no fix
- Weaknesses: CWE-862 Missing Authorization and CWE-732 Incorrect Permission Assignment.
- Exploited against "a couple of dozen customers" (vendor).
- Not in KEV catalog version 2026.11.10, still current on 13 November.
Notes: Score and CWEs [1][2]. Waves [5]. Fixed Takes and end of support [3][20]. Count [3]. KEV [7].

## PART 1 | A root daemon that never asks who is calling

- The DynamicCLI daemon runs as root and listens on a local socket.
- On affected releases the socket is world-writable.
- The daemon does not authenticate whoever connects to it.
- Any command it receives runs as root.
- The precondition: local code execution on the appliance first.
Caption: No socket path, message format or exploit detail is reproduced.
Notes: Flaw [1][3]. Precondition [3]. The CVE record says an authenticated local user [1].

## PART 1 | Fix by the support article, not the CVE record

| Release | First fixed Take | Note |
|---|---|---|
| R82.20 | Take 14 | Takes 11 to 13 unclassified |
| R82.10 | Take 52 | Take 51 unclassified |
| R82 | Take 132 | Take 131 unclassified |
| R81.20 | Take 174 | Support ends May 2027 |
| R81.10 | No fix | End of support March 2026 |
| R81 | No fix | End of support October 2024 |
Caption: The CVE record omits R81.10 and R81; sk1000362 lists both as affected.
Notes: CVE record ranges [1]. Fixed Takes [3]. Support periods [20]. Unclassified Takes are the study's reading (Inferred).

## PART 2 | Exploited a week before the CVE was reserved

| Date | Event |
|---|---|
| 26 Oct 2026 | KEV adds the PHP2Shell pair, due 29 Oct |
| 30 Oct 2026 | First wave: Israeli organizations, destructive |
| 2 Nov 2026 | Second wave: many countries, no destruction |
| 5 Nov 2026 | CVE-2026-123039 reserved |
| 8 Nov 2026 | sk1000362 created |
| 12 Nov 2026 | CVE published; CPR report; AV26-1154 |
Caption: Rows Confirmed from KEV, the CVE record, sk1000362, the CPR report and the Canadian Centre.
Notes: KEV [7]. Waves [5]. Reserved and published [1]. Support article [3]. Advisory [6].

## PART 3 | From the portal to the hypervisor

- PHP2Shell on the Mobile Access portal: the portal's service account.
- CVE-2026-123039: root on the gateway.
- Web shells in the portal's login templates.
- TSGA and TSProxy: the gateway implant and its in-process proxy.
- gogo scanning, then SSH to VMware ESXi as vpxuser.
- destroy_v6 wiped files on ESXi and left a note in Hebrew.
Caption: Confirmed from the CPR report; the report does not date each step.
Notes: Chain [5]. vpxuser is the account vCenter manages on each host [33]. Note text not reproduced.

## PART 3 | An implant built for the appliance

Left: TSGA
- Runs under names resembling a Check Point process.
- Encrypted remote access and configuration theft.
- Persists through backups and snapshots.
- Tampers with binary firewall logs.
Right: TSProxy
- A shared library dropped under /lib.
- Injected into selected appliance processes.
- Hands marked attacker connections to the implant.
- Encrypted SOCKS-style proxying.
Caption: A post-compromise backup is not a safe restore point (Inferred).
Notes: Capabilities [5]. Name resemblance and the restore lesson Inferred from [5].

## PART 4 | Shared tools, unproven operators

- TSGA and TSProxy are modified variants of PhiliKit (CPR).
- They share code, keys and a TLS certificate and private key.
- ESET assesses PhiliKit as part of UNC5221's SPAWN toolset.
- Against that: destruction, an Israel focus and a Hebrew note.
- CPR makes no high-confidence assessment.
Caption: Shared keys prove shared tools, not shared operators (Inferred).
Notes: Lineage and scenarios [5]. ESET [12][13]. The Armory Castle name appears only in news reports (Reported) [44][45].

## PART 5 | Five Check Point flaws in KEV, and one more waiting

| CVE | Surface | KEV |
|---|---|---|
| CVE-2024-24919 | Remote access information disclosure | 30 May 2024 |
| CVE-2026-50751 | IKEv1 authentication bypass | 8 Jun 2026 |
| CVE-2026-16232 | SmartConsole login bypass | 22 Jul 2026 |
| CVE-2026-85102 | VPN certificate validation, RCE | 22 Sep 2026 |
| CVE-2026-93616 | Management path traversal | 22 Sep 2026 |
| CVE-2026-123039 | Gaia DynamicCLI root | Not yet |
Caption: KEV rows Confirmed from the catalog version 2026.11.10.
Notes: KEV [7]. Records [23][25][26][29]. CVE-2026-50751 has its own study [51].

## PART 6 | Score the chain, not the CVE

- The 7.8 local score understates a flaw that PHP2Shell made remote.
- A KEV-only queue would not have surfaced it on 13 November.
- NVD had no CPE configuration, so scanners read the ranges their own way.
- Management servers and Maestro are in scope, not only gateways.
- Patch the same-day sibling, CVE-2026-107484, as well.
Caption: Prioritization readings Inferred from Confirmed records.
Notes: Score [1][3][5]. KEV [7]. NVD [2]. Scope [3]. Sibling [6][8].

## DEFENDER VIEW | Patch, hunt, rebuild, segment

Left: Fix and hunt
- Install the sk1000362 Take on every Gaia system.
- On R81 and R81.10, stop the daemon and plan the upgrade.
- Review the DynamicCLI log on every cluster member.
- Sweep for CPR's file names, hashes and addresses.
Right: Recover and contain
- Rebuild from a clean image, not a later backup.
- Rotate credentials, certificates and VPN trust.
- ESXi SSH off and lockdown mode on.
- No SSH path from any appliance to a hypervisor.
Notes: Fix, mitigation and log review [3]. Indicators [5]. Recovery Inferred from [5][40]. ESXi controls [37].

## OVERSTATED AND UNDERSTATED | The headline and the hop

Left: Overstated
- "Zero-day gives root" read as remote reach.
- A firm China attribution.
Right: Understated
- The 7.8 score in a remote chain.
- The KEV gap for a vendor-confirmed flaw.
- End-of-support releases with no fix.
- One hop from the firewall to ESXi.
Notes: Overstated [1][3][5][12][44]. Understated [3][5][7][20]. Readings Inferred.

## MITRE MAPPINGS | Twenty techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | PHP2Shell on the portal |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-123039 to root |
| T1505.003 | Web Shell | Login template web shells |
| T1055 | Process Injection | TSProxy in appliance processes |
| T1021.004 | SSH | Gateway to ESXi as vpxuser |
| T1485 | Data Destruction | destroy_v6 on ESXi |
Caption: ATT&CK v20.0; CWE-862, CWE-732; CAPEC-1, CAPEC-180, CAPEC-650; full table and layer in the study.
Notes: Techniques [1][3][5] with library data [47]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The appliance is a Linux server you do not run like one

- **Chains, not CVEs.** Two flaws scored apart were exploited together.
- **Disclosure trails exploitation.** Hunt from first exploitation.
- **Backups are attack surface.** Snapshot persistence turns restore into reinfection.
- **End of support is a security state.** R81 and R81.10 have no fix.
Notes: Chain [1][5][7]. Disclosure [1][5]. Backups [5]. End of support [3][20].
