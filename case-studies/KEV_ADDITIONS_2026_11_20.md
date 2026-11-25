# CISA KEV Additions of 20 November 2026: VMware vCenter, Cisco Expressway, Apache Roller and SAP NetWeaver

*A TeamStarWolf case study. Published 24 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads, VMware, Cisco, Apache Roller and SAP administrators, incident responders, and security engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,180 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run VMware vCenter, a clustered Cisco Expressway, Apache Roller or SAP NetWeaver Enterprise Portal, or you need the facts behind CISA's 20 November 2026 KEV additions

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: VMware vCenter, CVE-2026-123890](#part-1-vmware-vcenter-cve-2026-123890), [Part 6: Find and fix it](#part-6-find-and-fix-it)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

On 20 November 2026, CISA added four vulnerabilities to its Known Exploited Vulnerabilities (KEV) catalog: CVE-2026-123890, an authentication bypass in the VMware Directory Service of Broadcom VMware vCenter; CVE-2026-76466, a hard-coded credential flaw in Cisco Expressway Series; CVE-2026-129448, an unauthenticated deserialization flaw in the Apache Roller XML-RPC endpoint; and CVE-2025-42884, a JNDI injection in SAP NetWeaver Enterprise Portal. CISA's SSVC record lists exploitation as active for all four (Confirmed [1][2][3][4][5]). CISA set a due date of 23 November 2026 for each, and marked forensic triage as required for every entry except the SAP one (Confirmed [5]).

The four are unrelated products with very different evidence behind them. Only the vCenter flaw has a public account of how it was used: Mandiant and Google Threat Intelligence Group report that a suspected PRC-nexus actor they track as ARMORY CASTLE exploited it as a zero-day in early September 2026, about ten weeks before Broadcom's fix (Reported [8]). For Apache Roller, the CVE record itself says the flaw is being actively exploited, with no further detail (Confirmed [3]). For Cisco, the vendor's advisory says it has no direct evidence of active exploitation, although CISA lists the flaw as exploited (Confirmed [2][5]). For SAP, the fix is a year old, SAP scores the flaw 6.5 (Medium) and discusses no exploitation, and the sources reviewed describe none (Confirmed [4][5]).

This study keeps the four distinct and keeps three questions apart for each: what the vulnerability is, whether a fix exists, and what is known about exploitation. A shared KEV date is a calendar fact. It is not one campaign, and it is not evidence that the same actor used all four.

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| KEV date added | 20 November 2026, all four; due 23 November 2026 | Confirmed [5] |
| CVEs covered | CVE-2026-123890, CVE-2026-76466, CVE-2026-129448, CVE-2025-42884 | Confirmed [1][2][3][4] |
| CVSS 3.1 base score | 9.8 (vCenter, Cisco, Roller); 6.5 (SAP) | Confirmed [1][2][3][4] |
| Weaknesses (KEV) | CWE-288 (vCenter); CWE-798 (Cisco); CWE-502 (Roller); CWE-943 (SAP) | Confirmed [5] |
| CISA SSVC | Exploitation active and automatable yes for all four; technical impact total for vCenter, Cisco and Roller, partial for SAP | Confirmed [1][2][3][4] |
| Known ransomware campaign use | Unknown for all four | Confirmed [5] |
| Public account of exploitation | vCenter: Mandiant and GTIG, suspected PRC-nexus actor, early September 2026. Roller: one sentence in the CVE record. Cisco and SAP: none found | Reported [8]; Confirmed for Roller and Cisco statements [2][3] |
| Fixed releases | vCenter 9.1.1.0200, 9.0.2.0200, 8.0 U3m; Cisco Expressway X15.5.20; Roller 6.1.6; SAP Security Note 3660969 | Confirmed [1][2][3][4][6] |

### Key findings

- **One KEV date, four unrelated causes.** A cryptographic flaw in a directory service RPC interface, a shared credential in a clustering database service, an object-deserialization step that runs before authentication, and a lookup-URL injection have nothing in common beyond the catalog entry (Confirmed [1][2][3][4]).
- **vCenter was exploited before it was disclosed.** Mandiant's forensic evidence puts the first use in early September 2026 and dates the exploitation tool's build to 13 July 2026. Broadcom disclosed and fixed the flaw on 19 November 2026 (Reported [8]; Confirmed for the disclosure date [6]).
- **The vCenter flaw is one of two distinct authentication bypasses in the same service this year.** CVE-2026-123890 is not CVE-2026-59309 from July 2026. Mandiant saw the new flaw used against a server already patched for the old one (Reported [8]).
- **Cisco and CISA disagree about evidence, and both are on the record.** Cisco's advisory, updated 23 November 2026, says it has no direct evidence of active exploitation, while CISA's catalog lists the flaw as exploited. Read it as a gap between a vendor's telemetry and a federal listing, not as a contradiction (Confirmed [2][5]).
- **A medium score does not mean an unexploited flaw.** The SAP flaw scores 6.5, was fixed on 11 November 2025, and was added to KEV a year later. Its score reflects limited stated impact, not the exploitation record (Confirmed [4][5]).

### Top recommendations

1. Patch vCenter to a fixed build (9.1.1.0200, 9.0.2.0200 or 8.0 U3m, or 5.2.5 for VMware Cloud Foundation 5.x), restrict network access to the vCenter management and directory ports to a short allowlist, and treat any vCenter that was reachable from a compromised network as a candidate for a compromise review, not only a patch.
2. For vCenter, review the directory and identity layer after patching: rogue single sign-on administrator accounts, unexpected SSH enablement through the appliance management API, and signs that the SAML signing material was read.
3. Upgrade clustered Cisco Expressway devices to X15.5.20 or later, or migrate from X14 and earlier, because Cisco lists no workaround.
4. Upgrade Apache Roller to 6.1.6 or later. Where that waits, set `enabledForExtensions` to `false` in `WEB-INF/web.xml` or remove the XML-RPC servlet mapping, and restart. Turning XML-RPC off in the administration screen is not enough on older releases.
5. Apply SAP Security Note 3660969 on every NetWeaver Enterprise Portal running EP-BASIS or EP-RUNTIME 7.50, and do not defer it because of the 6.5 score.

## Scope and evidence standard

This study uses the CVE records and CISA's Vulnrichment entries, the NVD records, CISA's KEV catalog, the Broadcom and Cisco advisories, the Apache announcement, and the Mandiant and Google Threat Intelligence Group report on the vCenter exploitation. It covers the four 20 November 2026 additions. CISA's catalog also listed other entries on 23 and 24 November 2026, which are out of scope. No exploit was executed. No exploit code, indicator-driven tooling or credential material is reproduced.

**Confirmed** means an official source (the CVE record, the vendor advisory, CISA, NVD) supports the claim. **Reported** means a third-party write-up stated it without an independent official record, including the Mandiant account of the intrusion. **Demonstrated** marks a capability a finder says it proved under stated conditions; no such claim appears here. **Inferred** marks the author's interpretation.

A KEV entry establishes that CISA holds evidence of exploitation. It does not establish who exploited the flaw, how many systems were affected, or whether a given organization was. Those facts need the intrusion reports, and only one of the four has one.

## Part 1: VMware vCenter, CVE-2026-123890

### What the vulnerability is

Broadcom describes CVE-2026-123890 as an authentication bypass vulnerability in the VMware Directory Service of vCenter. A malicious actor with network access to vCenter may exploit it to bypass authentication and gain unauthorized access to the system. Broadcom scores it 9.8 (CRITICAL) under CVSS 3.1 with network access, low complexity, no privileges and no user interaction, and lists no workaround (Confirmed [1][6]). The weakness is CWE-288, authentication bypass using an alternate path or channel (Confirmed [5]). Broadcom credits Mandiant with reporting it (Confirmed [6]).

Mandiant gives the mechanism. In its account, the flaw lies in the directory service's remote procedure call interface for the Secure Remote Password (SRP-6a) authentication exchange: predictable timestamp generation in version-1 UUIDs lets an unauthenticated client recover the shared session key without knowing any password. With the key, the client establishes a session as `administrator@vsphere.local` (Reported [8]). The mechanism is Mandiant's reading; Broadcom's advisory states only the outcome.

### Affected and fixed versions

Broadcom's advisory VMSA-2026-0009, published 19 November 2026 and revised on 20 November 2026, lists the fixes: vCenter 9.1.x fixed in 9.1.1.0200, 9.0.x in 9.0.2.0200, 8.0 in 8.0 U3m, and VMware Cloud Foundation 5.x in 5.2.5. For vCenter 7.0 the advisory directs customers with an extended support contract to contact Broadcom support. VMware Telco Cloud Platform and Telco Cloud Infrastructure builds are fixed through knowledge base article KB463116 (Confirmed [6]). The same advisory carries four other CVEs: CVE-2026-123891, CVE-2026-123892 and CVE-2026-123893 in SDDC Manager and CVE-2026-123894 in VMware Tools for Windows. Each of those needs authentication or local privilege, and none is in KEV; this study does not analyze them (Confirmed [6]).

Mandiant states that its recovered exploitation tool achieves full compromise against vCenter Server 7.x and 8.x appliances (Reported [8]). Broadcom's advisory lists no fixed 7.0 build in the public matrix, so a 7.0 deployment without extended support has no public fix, and its exposure is the open question for those operators (Inferred from [6][8]).

### How it was used

Mandiant's account follows one intrusion. The actor first compromised a BeyondTrust Remote Support appliance, which Mandiant covered in a separate report [9], then moved to an internal Linux appliance without endpoint detection, scanned the internal network for the ports VMware services use (including 2012, the single sign-on RPC control interface), and ran an exploitation utility it names BONESAW against an internal vCenter server (Reported [8]).

Mandiant reports that the utility streams the directory database file, extracts the single sign-on token service's SAML signing key, creates a backdoor account, forges administrator SAML assertions, and assigns Global Administrator on the vCenter root folder. A second utility it names SAWSNAKE then forged the SAML assertion to obtain administrator session cookies, which Mandiant describes as a Golden SAML attack that can bypass multi-factor authentication. The actor created a local administrator account, enabled SSH on the appliance through the management API, copied the appliance's master encryption key and database password files, and disabled SSH again. From there it reached ESXi hosts, browsed the datastore volumes, and staged for exfiltration files that included an Active Directory database and registry hives from a guest virtual machine's disk (Reported [8]).

### Timing: exploited before it was public

Mandiant dates the exploitation to early September 2026, from forensic evidence, and reports that the recovered utility carries a build timestamp of 13 July 2026, which Mandiant cautions can be edited before compilation. It also reports that the utility ran against a vCenter server already patched for CVE-2026-59309, a different authentication bypass in the same directory service that Broadcom disclosed on 29 July 2026 (Reported [8]). The first public disclosure of CVE-2026-123890 is 19 November 2026, on the same day as Mandiant's report (Confirmed [6]; Reported [8]). On the record reviewed, the flaw was exploited for roughly ten weeks before a fix existed, which makes it a zero-day by the ordinary definition (Inferred from [6][8]).

The two vCenter flaws should stay distinct. Mandiant describes CVE-2026-59309 as a flaw reached over the directory service's LDAP ports, using malformed authorization tokens, and CVE-2026-123890 as a flaw in the RPC interface (Reported [8]). A patch for the first does not address the second.

### Attribution

Mandiant and GTIG attribute the activity to ARMORY CASTLE, which they describe as a suspected PRC-nexus espionage actor formerly tracked as UNC5221, based on tooling and techniques that match its earlier activity, including a backdoor that directly overlaps a previous intrusion (Reported [8]). The attribution is the analysts' assessment, labeled suspected. The sources reviewed give no victim count, and Mandiant's account describes one intrusion (Reported [8]).

## Part 2: Cisco Expressway Series, CVE-2026-76466

### What the vulnerability is

Cisco's advisory cisco-sa-vcs-static-cred-hr7EWZ8t, first published on 21 October 2026, describes a flaw in the database service feature of Cisco Expressway Series. An unauthenticated remote attacker with network access, and in possession of the persistent cookies, could run operating system commands as root. The cause, in Cisco's words, is the use of persistent cookies, together with insufficient validation of client certificates when TLS Verify Mode is enabled for clustering, so that the certificates are not validated. The attacker connects to the database service and invokes specific remote procedure calls. Cisco scores it 9.8 (CRITICAL) under CVSS 3.1 and assigns CWE-798, use of hard-coded credentials (Confirmed [2]).

The scope is narrower than the score suggests. Cisco states that the flaw affects Expressway-C and Expressway-E, virtual and appliance, when they run a vulnerable release and are configured in a cluster. A standalone Expressway is not described as vulnerable (Confirmed [2]). Cisco credits Stefan Aleksic of Jane Street with reporting it (Confirmed [2]).

### Fix and workaround

Cisco lists no workarounds. For releases X15.5.3 and earlier the first fixed release is X15.5.20, and for X14 and earlier the advisory says to migrate to a fixed release. The fix is also part of the broader Cisco Expressway Series security hardening release of October 2026 (Confirmed [2]).

### What is known about exploitation

The advisory's revision history is the useful record. Version 1.1, dated 23 November 2026, was updated to state that the flaw was added to CISA's KEV catalog and says that Cisco does not have direct evidence of active exploitation (Confirmed [2]). CISA's Vulnrichment record lists exploitation as active, automatable yes and technical impact total (Confirmed [1][5]). The vendor and the federal agency are describing different evidence: Cisco reports what its own telemetry and cases show, and CISA reports what it holds. No public account of the exploitation, an actor or an indicator was found in the sources reviewed (Inferred from [2][5]).

## Part 3: Apache Roller, CVE-2026-129448

### What the vulnerability is

Apache Roller's XML-RPC endpoint accepts vendor extension types and deserializes them while parsing the request, before it authenticates the requester. An unauthenticated remote attacker can use that to run code. The Apache Software Foundation scores it 9.8 (CRITICAL) and assigns CWE-502, deserialization of untrusted data (Confirmed [3][5]). The CVE record credits the finder as n0mi1k and the reporter as Matt Raible (Confirmed [3]).

### Two CVE numbers, one flaw

Apache first published CVE-2026-82384 on 28 September 2026, which listed only Apache Roller 6.1.5 as affected. The newer record, CVE-2026-129448, published on 17 November 2026, states that it covers the same underlying vulnerability across a broader range, Roller 4.0.0 through 6.1.4 (Confirmed [3][10]). Read together, every release from 4.0.0 through 6.1.5 is affected and 6.1.6 is the first fixed release. Only CVE-2026-129448 is in KEV, so a tool that matches on CVE-2026-82384 alone will miss the older versions (Confirmed [3][5]; Inferred for the tooling consequence).

The 6.1.5 record adds a precondition worth keeping: the servlet is mapped unconditionally, so parsing happens even when the global XML-RPC feature is set to disabled, and no non-default configuration is required (Confirmed [10]).

### Fix and the toggle that does not work

Apache recommends upgrading to Roller 6.1.6 or later, which disables the extension types and rejects XML-RPC requests when the feature is disabled. For those who cannot upgrade at once, the record gives two interim steps: set `enabledForExtensions` to `false` in `WEB-INF/web.xml`, or remove the `/roller-services/xmlrpc` servlet mapping, and restart Roller. It states that disabling XML-RPC in the administration interface is not enough, because older versions deserialize the request before checking that setting (Confirmed [3]).

### What is known about exploitation

The CVE record says "This issue is being actively exploited", and CISA's Vulnrichment entry, timestamped 18 November 2026, lists exploitation as active, automatable yes and technical impact total. The earlier record for 6.1.5 carried an SSVC value of exploitation none on 28 September 2026, so the status changed between the two records (Confirmed [3][10]). Apache's text gives no victims, actor or indicators, and no independent account of the exploitation was found in the sources reviewed (Inferred from [3][5]).

## Part 4: SAP NetWeaver Enterprise Portal, CVE-2025-42884

### What the vulnerability is

SAP's CVE record, titled JNDI Injection vulnerability in SAP NetWeaver Enterprise Portal, says an unauthenticated attacker can inject JNDI environment properties or pass a URL used during JNDI lookup operations, giving access to an unintended JNDI provider. SAP states the result could be disclosure or modification of information about the server, with no impact on availability. SAP scores it 6.5 (MEDIUM) under CVSS 3.1 with low confidentiality and integrity impact, and assigns CWE-943 (Confirmed [4][5]). The affected components are EP-BASIS 7.50 and EP-RUNTIME 7.50 (Confirmed [4]).

### A year between fix and listing

SAP published the record on 11 November 2025, its November 2025 Security Patch Day, and the fix is SAP Security Note 3660969. CISA added the flaw to KEV on 20 November 2026 and set a due date of 23 November 2026 (Confirmed [4][5]). The note itself requires an SAP support login and was not read for this study, so exact support package levels are not given here. CISA's Vulnrichment entry lists exploitation active, automatable yes and technical impact partial (Confirmed [1][4]).

A secondary report attributes to the researchers who reported the flaw the view that, under conditions that include an attacker-run lookup target and an exploitable class on the server, a JNDI lookup of this kind can lead to code execution. SAP and CISA do not state that, and the 6.5 score and CISA's partial technical impact reflect the stated disclosure-or-modification outcome (Reported [7]; Confirmed for the scores [4][1]). Whether the exploitation CISA cites reached code execution is not stated in any source reviewed. No actor, victim or indicator is public in those sources (Inferred from [4][5][7]).

## Part 5: What the four share, and what they do not

All four are listed on one date, all four are rated as automatable by CISA, and none has a published ransomware link (Confirmed [5]). Beyond that, the sources show four separate situations.

| CVE | Product | Reaches | Fix status | Public exploitation account |
|---|---|---|---|---|
| CVE-2026-123890 | VMware vCenter | Administrator session, then the identity layer | Fixed 19 November 2026 | Mandiant and GTIG, suspected PRC-nexus actor, from early September 2026 (Reported [8]) |
| CVE-2026-76466 | Cisco Expressway, clustered | Root on the device | Fixed in X15.5.20 | None; Cisco has no direct evidence (Confirmed [2]) |
| CVE-2026-129448 | Apache Roller | Code execution as the application | Fixed in 6.1.6 | One sentence in the CVE record (Confirmed [3]) |
| CVE-2025-42884 | SAP NetWeaver Enterprise Portal | Server information disclosure or modification | Fixed 11 November 2025 | None found (Inferred from [4][5]) |

Three of the four are in components that sit at a control point: the virtualization management plane, the video and collaboration edge, and an enterprise portal. The Mandiant report is the clearest case of why that matters. The actor's goal in that account was not vCenter itself, it was what vCenter holds: the signing key that mints trusted identities for the whole environment, the encryption key for stored secrets, and a route to the disks of every guest (Reported [8]). The same pattern appears in the Roller and Cisco records as an inference only, since neither has an intrusion account (Inferred).

## Part 6: Find and fix it

### vCenter

Inventory every vCenter, including those embedded in VMware Cloud Foundation, vSphere Foundation and Telco Cloud builds, and record the build against the fixed versions in Broadcom's matrix (Confirmed [6]). Restrict network access to vCenter's management and directory ports so that only administrative hosts reach them. Mandiant's report shows the actor scanning for ports 443, 5480, 9080, 389 and 2012 from a compromised appliance, which is why a flat internal network matters as much as the internet-facing exposure (Reported [8]).

After patching, hunt for the effects, not the bug. Mandiant's published guidance and indicators point to: new or unexpected single sign-on administrator or machine accounts, SSH enabled on the appliance through the management API and then disabled again, reads of the directory database file and the token service signing material, and outbound connections from the appliance. Mandiant also published file and network indicators and YARA rules for the malware families in its report (Reported [8]). If signing material may have been read, patching alone does not revoke forged tokens, and rotating the single sign-on signing certificates is the step that does. That rotation guidance is an inference from the mechanism, not a statement in the advisory (Inferred).

### Cisco Expressway

Determine which Expressway-C and Expressway-E devices run in a cluster, since Cisco's affected-product statement depends on it. Upgrade those to X15.5.20 or later, or migrate from X14 and earlier, and treat the absence of a workaround as a reason to schedule the work, not to wait (Confirmed [2]).

### Apache Roller

Find every Roller instance, including internal blogs, and the version each runs. Upgrade to 6.1.6 or later. If you apply the interim step, edit `WEB-INF/web.xml` and restart, then confirm the XML-RPC path no longer answers; do not rely on the administration toggle (Confirmed [3]). Watch for requests to `/roller-services/xmlrpc` from outside the networks that legitimately use blogging clients, and for the Roller process starting child processes (Inferred).

### SAP NetWeaver Enterprise Portal

Confirm that Security Note 3660969 is applied on every portal running EP-BASIS or EP-RUNTIME 7.50, and treat any portal that was reachable and unpatched through 20 November 2026 as one to review, since CISA lists exploitation as active and no indicator list is public (Confirmed [4][5]; Inferred for the review step).

### The vulnerability-management view

Rank these four by exposure and by what they reach, not by base score. The 6.5 SAP flaw and the 9.8 Cisco flaw both sit in KEV; the Cisco flaw needs a cluster and the SAP flaw needs the portal reachable. A single record cannot carry that. Write the precondition into the ticket so a later reader does not re-escalate a standalone Expressway or de-escalate an unpatched portal (Inferred).

## Part 7: Weakness and technique mapping

The mapping below is this study's interpretation of public definitions, checked on 24 November 2026. It is deliberately small, and the intrusion techniques apply only to the one reported intrusion.

| Label | Case support | Boundary |
|---|---|---|
| CWE-288 (vCenter) | Assigned for the directory service bypass | The authoritative weakness label [5] |
| CWE-798 (Cisco) | Assigned for the clustering credential flaw | The authoritative weakness label [2][5] |
| CWE-502 (Roller) | Assigned for the pre-authentication deserialization | The authoritative weakness label [3][5] |
| CWE-943 (SAP) | Assigned for the JNDI lookup injection | The authoritative weakness label [4][5] |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Unauthenticated network reach to each vulnerable service | High-confidence analytical mapping for all four; for vCenter the reported use was from an internal pivot, so the technique describes the service, not the path |
| [T1606.002 Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/) | Mandiant describes forged SAML assertions in the vCenter intrusion | Reported use in one intrusion [8] |
| [T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) | Mandiant describes two webshells on a Linux appliance in the same intrusion | Reported use in one intrusion; not tied to the vCenter flaw itself [8] |
| [T1098.004 Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) | Mandiant describes a public key added to an ESXi root account | Reported use in one intrusion [8] |
| Cisco, Roller and SAP post-exploitation techniques | No intrusion sequence is public | Not mapped; no real-world intrusion account is in evidence |

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read the shared date as a shared adversary. The Mandiant account names a suspected PRC-nexus actor for the vCenter flaw and for nothing else; the Cisco, Roller and SAP entries have no public actor, and putting one on them would be inventing a link. The second overstatement is to read KEV as a measure of scale. The catalog does not count victims, and no source reviewed does either.

The easy understatement runs the other way. A 6.5 score, a clustering precondition or a one-line exploitation note can read as low priority. The SAP flaw has been public for a year and is now listed as exploited. The Cisco flaw needs a cluster, but the advisory gives no workaround. The Roller flaw has two CVE numbers and a toggle that does not work. In each case the cautious reading comes from the vendor's own record, not from commentary (Confirmed [2][3][4]).

### Exploited before disclosed

The vCenter case is a reminder of what a patch date does and does not mean. The fix arrived on 19 November 2026, and by Mandiant's account the exploitation began in early September. A defender who treats the advisory date as the start of the exposure window is wrong by about ten weeks for an organization the actor had reason to want (Reported [8]; Inferred). Hardening that does not depend on the next advisory, such as limiting which hosts can reach the management plane and forwarding appliance logs off the device, is the response Mandiant's own report recommends.

## Sources

1. CVE Program, CVE Records CVE-2026-123890, CVE-2026-76466, CVE-2026-129448 and CVE-2025-42884, including CISA ADP Vulnrichment SSVC entries. https://www.cve.org/CVERecord?id=CVE-2026-123890
2. Cisco, Security Advisory cisco-sa-vcs-static-cred-hr7EWZ8t, version 1.1 of 23 November 2026. https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vcs-static-cred-hr7EWZ8t
3. Apache Software Foundation, announcement of CVE-2026-129448, Apache Roller: Unauthenticated deserialization in the XML-RPC endpoint. https://lists.apache.org/thread/cc0jck13nb9vvcmzxzwotr6n16mx28z9
4. SAP, CVE Record CVE-2025-42884 and Security Note 3660969 (support login required; the note was not read). https://me.sap.com/notes/3660969
5. CISA, Known Exploited Vulnerabilities Catalog, entries added 20 November 2026. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. Broadcom, VMSA-2026-0009: VMware vCenter, Tools, and SDDC Manager updates address multiple vulnerabilities, 19 November 2026, revised 20 November 2026. https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495
7. Rescana, SAP NetWeaver Enterprise Portal CVE-2025-42884 JNDI Injection Added to CISA KEV, a secondary report citing the researchers who reported the flaw to SAP. https://www.rescana.com/post/sap-netweaver-enterprise-portal-cve-2025-42884-jndi-injection-kev-patch-now
8. Google Threat Intelligence Group and Mandiant, ARMORY CASTLE Exploits vSphere, 19 November 2026. https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere
9. Google Threat Intelligence Group and Mandiant, ARMORY CASTLE Exploits BeyondTrust, 15 October 2026. https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust
10. CVE Program, CVE Record CVE-2026-82384, Apache Roller 6.1.5. https://www.cve.org/CVERecord?id=CVE-2026-82384

## Related references

- [CVE Reference](/CVE_REFERENCE.md) and [CWE Reference](/CWE_REFERENCE.md) for the identifiers used here.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating edge and management-plane services as attack surface.
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) for ranking exposure by precondition and context rather than base score.
