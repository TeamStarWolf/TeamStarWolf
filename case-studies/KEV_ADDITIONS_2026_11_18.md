# CISA KEV Additions of 18 November 2026: Synology DSM, LiteLLM, REDCap and Apache Axis

*A TeamStarWolf case study. Published 19 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads, Synology, LiteLLM, REDCap and Java application owners, incident responders, and security engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,317 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run Synology DSM, a LiteLLM proxy, REDCap or a Java application that bundles Apache Axis 1.x, or you need the facts behind CISA's 18 November 2026 KEV additions

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 5: Find and fix](#part-5-find-and-fix), [Part 6: Weakness and technique mapping](#part-6-weakness-and-technique-mapping)

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

On 18 November 2026, CISA added four vulnerabilities to its Known Exploited Vulnerabilities (KEV) catalog, each with a remote path to running code on the server: CVE-2024-10441 in Synology DiskStation Manager (DSM) and BeeStation OS, CVE-2026-40217 in the BerriAI LiteLLM proxy, CVE-2026-90817 in the Vanderbilt University REDCap research data platform, and CVE-2026-90436 in Apache Axis 1.x. For all four, CISA's SSVC record lists exploitation as active and technical impact as total (Confirmed [1][2][3][4][5]). CISA gave the Synology, REDCap and Axis entries a due date of 21 November 2026 and the LiteLLM entry 2 December 2026, and marked forensic triage as required for every entry except LiteLLM (Confirmed [5]).

The four are unrelated products, and the record says very little about the exploitation itself. CISA's catalog confirms that exploitation was observed but publishes no victim counts, no actor and no indicators, and lists known ransomware campaign use as Unknown for all four. The sources reviewed here do not describe who exploited what, or how many systems were affected (Confirmed for the listing [5]; no further detail appears in the sources).

The four differ in how much an attacker needs. The REDCap and Axis flaws need no credentials, though REDCap needs a valid public survey link and Axis needs a suitable class already on the application's classpath. The Synology flaw is rated network-reachable with no privileges, but its vendor advisory gives no mechanism. The LiteLLM flaw is a different kind of record: reaching it takes a proxy administrator credential in default configurations, so it is a sandbox escape for a privileged user, not a pre-authentication hole. This study keeps the four distinct and treats the shared KEV date as a calendar fact, not a shared cause.

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| KEV date added | 18 November 2026, all four | Confirmed [5] |
| CVEs covered | CVE-2024-10441, CVE-2026-40217, CVE-2026-90817, CVE-2026-90436 | Confirmed [1][2][3][4] |
| CVSS 3.1 base score | 9.8 (Synology), 8.8 (LiteLLM), 9.8 (REDCap), 9.8 (Axis, from the CISA ADP container) | Confirmed [1][2][3][4] |
| Weaknesses (KEV) | CWE-116 (Synology); CWE-420 (LiteLLM); CWE-73 and CWE-94 (REDCap); CWE-470 (Axis) | Confirmed [5] |
| CISA SSVC | Exploitation active for all four; automatable yes for Synology, REDCap and Axis, no for LiteLLM; technical impact total for all four | Confirmed [1][2][3][4] |
| KEV due dates | 21 November 2026 for Synology, REDCap and Axis; 2 December 2026 for LiteLLM | Confirmed [5] |
| Known ransomware campaign use | Unknown for all four | Confirmed [5] |
| Public detail on the exploitation | None found in the sources reviewed | Inferred from [1][2][3][4][5] |
| Fix available | Synology: since November 2024. LiteLLM: 1.83.11 or later. REDCap: 16.0.49, 17.3.10 or 17.4.4. Axis 1.x: none planned; a source patch exists | Confirmed [1][3][4][6][7][9] |

### Key findings

- **One KEV date, four unrelated causes.** An output-escaping flaw in a NAS plugin daemon, a regex-filtered Python sandbox, a URL-decoding mismatch plus a file-path parameter, and unsafe class loading from a SOAP fault have nothing in common beyond the catalog entry (Confirmed [1][2][3][4]).
- **The Synology flaw is two years old.** The vendor shipped fixes in November 2024; KEV added the CVE in November 2026. Appliance firmware that never updated is the likely reason it still matters, and that is an inference, not something CISA states (Confirmed for the dates [6]; Inferred).
- **The LiteLLM flaw needs a privileged credential.** The vendor advisory says reaching the endpoint requires a proxy-admin credential in default configurations. The vendor rates it Moderate, while KEV lists it because exploitation was observed (Confirmed [5][7]).
- **Apache Axis 1.x will not get a release.** The project says it does not expect to ship a fixed 1.x release; the choices are migrating or applying a source patch (Confirmed [4]).
- **Exploitation is confirmed; its scope is not.** Active exploitation is confirmed by CISA's records. Who is exploiting, against how many hosts and by what exact path is not in the public sources reviewed (Confirmed [5]; Inferred for the gap).

### Top recommendations

1. Inventory the four products first: Synology DSM and BeeStation OS devices, LiteLLM proxies, REDCap servers, and any Java application that bundles Axis 1.x.
2. Patch to the fixed releases named in Part 1 through Part 4, then check that exposed management interfaces are not reachable from the internet.
3. Treat forensic triage as part of the response for Synology, REDCap and Axis, as the KEV entries require, and consider it for LiteLLM; patching does not remove an intruder who got in earlier.
4. Rotate secrets held by a compromised service: the LiteLLM proxy stores provider API keys, and a REDCap server holds a database credential and research data.
5. Do not read the shared KEV date as one campaign. Track four separate tickets with four separate owners.

## Scope and evidence standard

This study uses the CVE records and the CISA SSVC (Vulnrichment) data, the CISA KEV entries, the Synology advisory Synology-SA-24:20, the BerriAI GitHub security advisory and the X41 D-Sec advisory for LiteLLM, the Securifera write-up for REDCap, and the Apache CVE record for Axis. NVD pages were not used for analysis. No exploit was run, and no exploit code, request or payload is reproduced here, although the finders for two of the four published theirs.

**Confirmed** means an official record (a CVE record, a vendor advisory, the KEV entry) supports the claim. **Reported** means a finder's or third party's write-up stated it without an independent official record. **Demonstrated** marks a capability a finder says it proved under stated conditions. **Inferred** marks the author's interpretation. A statement that a source gives no detail is a statement about that source, not about the world.

A KEV listing is evidence that exploitation of the vulnerability was observed. It is not evidence about how many systems were compromised, by whom, or whether a given organization was affected. A CVSS score measures severity under a stated vector; it does not measure exploitation. These distinctions carry through the sections below.

## Part 1: CVE-2024-10441, Synology DSM and BeeStation OS

### What the record says

Synology's advisory Synology-SA-24:20, titled "DSM (PWN2OWN 2024)", was published on 5 November 2024 and rates the flaw Critical. The CVE record describes an improper encoding or escaping of output flaw in the system plugin daemon that lets remote attackers execute arbitrary code "via unspecified vectors", with a CVSS 3.1 score of 9.8 (network, low complexity, no privileges, no user interaction). The CVE record itself was published on 19 March 2025 (Confirmed [1][6]).

The advisory lists these fixed releases: DSM 7.2.2-72806-1, 7.2.1-69057-6, 7.2-64570-4 and 7.1.1-42962-7, and BeeStation OS 1.1-65374. It lists mitigation as none. The CVE record also marks versions before DSM 7.0 as unknown, and the advisory rates DSM 6.2 Moderate for the bundle of CVEs it covers (Confirmed [1][6]).

### What is not public

Both the vendor and the CVE record say "unspecified vectors". The advisory's abstract ties arbitrary code execution to a Zero Day Initiative tracking number, ZDI-CAN-25403, and credits Pumpkin Chang and Orange Tsai of the DEVCORE Research Team and Ryan Emmons of Team Smoking Barrels; the CVE record credits Ryan Emmons as the finder. The advisory does not say which researcher found which of its three CVEs, so the pairing of finder to flaw is Inferred from the CVE record's credit. The advisory is silent on how the attack works, and this study does not fill that gap (Confirmed [1][6]; Inferred for the pairing).

### Exploitation status and exposure

CISA's SSVC record, dated 18 November 2026, lists exploitation active, automatable yes and technical impact total. KEV lists the due date as 21 November 2026, three days after addition, with forensic triage required (Confirmed [1][5]). The sources reviewed give no victim count, no actor and no observed command sequence. The most defensible reading is that unpatched DSM devices reachable from the network are exposed, and that the long gap between the 2024 fix and the 2026 KEV listing points to devices that were never updated, which is Inferred.

## Part 2: CVE-2026-40217, the LiteLLM guardrail sandbox escape

### What LiteLLM is

LiteLLM is an open-source proxy that gives applications one OpenAI-compatible API in front of more than a hundred model providers, with load balancing, cost tracking, rate limiting and guardrails. Its guardrails feature lets administrators supply Python code to filter or transform requests, and a testing endpoint, `/guardrails/test_custom_code`, runs that code on the proxy (Reported [8]).

### The flaw and its preconditions

The endpoint runs submitted Python inside a sandbox built by hand, and X41 D-Sec, which found the flaw, reports that the sandbox filtered dangerous names by matching the source text and could be escaped by rewriting Python bytecode, which yields arbitrary code execution in the proxy process. In the default Docker image that process runs as root (Demonstrated [8]; Confirmed that the sandbox is escapable [7]). The CVE record, assigned by MITRE, says LiteLLM "through 2026-04-08" is affected and rates it 8.8 under CVSS 3.1 with low privileges required (Confirmed [2]).

Reaching the endpoint takes authentication. X41 describes the vector as an authenticated HTTP API request using the master key, and the BerriAI advisory says it "requires a proxy-admin credential in default configurations". BerriAI rates it Moderate, 5.9 under CVSS 4.0, with high privileges required and high attack complexity, while X41 rated it 8.7 under CVSS 4.0, and the CVE record's CVSS 3.1 score is 8.8. The scores differ because they assume different privilege levels and use different CVSS versions (Confirmed [7]; Reported [8]).

### Timeline and fix

X41 reports identifying the issue on 13 February 2026, and says it published on 8 April 2026 when a distributions-list embargo expired, with no vendor patch available at that time. The CVE record is dated 10 April 2026, and BerriAI's advisory GHSA-wxxx-gvqv-xp7p was published on 7 May 2026 (Reported [8]; Confirmed [2][7]).

The advisory lists affected versions from 1.81.8 up to but not including 1.83.10, and says the fix replaces the hand-rolled sandbox with RestrictedPython. Its metadata names patched versions as 1.83.10 or later while its body says "Fixed in 1.83.11", so the safe instruction is to run 1.83.11 or later, and to block `POST /guardrails/test_custom_code` at the reverse proxy if upgrading is not immediate (Confirmed [7]). X41 adds that the default container should be run as a non-root user to limit what code execution yields (Reported [8]).

### Exploitation status

CISA's SSVC record, dated 15 June 2026, lists exploitation active, automatable no and technical impact total. KEV added the CVE on 18 November 2026 with a due date of 2 December 2026 and does not require forensic triage. The sources reviewed do not say who exploited it or how an attacker obtained the administrator credential. An exposed management interface with a weak or leaked master key is the plausible route, which is Inferred (Confirmed [2][5]).

## Part 3: CVE-2026-90817, REDCap

### The product and the finder

REDCap is a web application from Vanderbilt University for building surveys and research databases, and the finder describes it as freely available to consortium members but not openly distributed. The finder, Ryan Wincey of Securifera, reports working from a copy of the source that a member had published, and says an AI coding assistant helped implement the technique, though it did not propose it (Reported [10]).

### The flaw

The CVE record, assigned by Securifera and published on 20 September 2026, describes an unauthenticated remote code execution flaw in the survey passthrough routing and the Data Import processing logic. An attacker manipulates requests to reach an unintended controller route from a public survey context and supplies a crafted file-path or stream parameter during import handling. Exploitation requires knowing a valid public survey hash. The record rates it 9.8 under CVSS 3.1 and says versions from 13.3.0 are affected (Confirmed [3]).

Securifera's write-up explains the chain as three separate faults. A double URL-decoding mismatch lets a request reach an administrative route that was meant to be restricted. A permissions check runs before the survey respondent's identity is set, so the request is treated as a super user. And the import step passes an attacker-chosen name to PHP file functions without limiting it to uploaded files, which a stream-wrapper technique can turn into a write of attacker-chosen bytes to a server file. The write-up reports code execution against the finder's own test installation (Demonstrated [10]).

### Fixed versions and status

The CVE record lists REDCap 16.0.49, 17.3.10 and 17.4.4 as unaffected, which are the fixed releases on the three maintained lines (Confirmed [3]). CISA's SSVC record, dated 18 November 2026, lists exploitation active, automatable yes and technical impact total, and KEV requires forensic triage with a due date of 21 November 2026 (Confirmed [3][5]). REDCap servers typically hold research and survey data, and which data a given server holds is a question for its operator. The sources reviewed give no count of affected or compromised servers.

## Part 4: CVE-2026-90436, Apache Axis 1.x

### The flaw

The Apache record, published on 6 November 2026 and marked "unsupported when assigned", describes unsafe deserialization of an inbound SOAP fault. When a fault carries an `exceptionName` element in its detail, Axis loads the named class and, if a string data element is also present, instantiates it through its String constructor before checking that the result is a fault. Merely loading the class runs its static initializer, so with a suitable class on the application's classpath this leads to remote code execution (Confirmed [4]).

Two details matter for defenders. The fault is parsed while the engine resolves the target service, before any per-service handler chain runs, so authentication handlers configured on a service do not protect against it. And exploitation depends on what is on the classpath, so the same Axis version is more or less dangerous depending on the libraries around it (Confirmed [4]; Inferred for the second point). The record covers all Axis 1.x versions through 1.4, rates the flaw 9.8 under CVSS 3.1 in the CISA container, and credits Jose Apari-Pantigozo of OKIOK as the finder (Confirmed [4]).

### No fixed release

Axis 1.x is end of life. The Apache record recommends migrating to another SOAP engine such as Axis2, or applying the patch in the commit `41f3b4e8d04e310ca81f86b92630ab2c11d608bd` to a self-built copy, and says the project does not expect to create an Axis 1.x release (Confirmed [4]). KEV's entry adds that the vulnerability could affect an open-source component used inside other products, which is the practical problem: Axis 1.x is a library, often bundled in older Java applications whose owners may not know it is there (Confirmed [5]; Inferred for the bundling).

### Exploitation status

CISA's SSVC record, dated 17 November 2026, lists exploitation active, automatable yes and technical impact total. KEV added it on 18 November 2026, twelve days after the CVE record, with a due date of 21 November 2026 and forensic triage required (Confirmed [4][5]). The sources reviewed do not name an exploiting party or an affected product.

## Part 5: Find and fix

### Decide whether you are exposed

For each product, the question differs. For Synology, list DSM and BeeStation OS devices and their build numbers against the fixed releases above, and check whether any management port is reachable from outside the network. For LiteLLM, list proxies, record the version and whether the administrative API is exposed, and check who holds the master key. For REDCap, record the version against 16.0.49, 17.3.10 and 17.4.4, and consider that survey links are public by design. For Axis, search application archives and dependency manifests for `axis-1.4.jar` and related artifacts, since the library may be bundled without a visible product name (Inferred).

### Apply the fix and respond

Upgrade, then respond as if exploitation may already have happened for the products KEV marks for forensic triage. That means reviewing logs for the period before patching, checking for new accounts, scheduled tasks and unexpected outbound connections, and rotating credentials the server could read. For LiteLLM that includes the provider API keys the proxy holds and the master key. Where Axis cannot be replaced soon, applying the Apache patch to a self-built copy and removing unneeded classes from the classpath narrows the exposure, though the record does not promise that removing classes is sufficient (Inferred).

### The vulnerability-management view

The four have different priority drivers. Synology, REDCap and Axis are rated automatable by CISA, so internet-facing instances should be treated as urgent regardless of CVSS nuance. LiteLLM is rated not automatable and needs a privileged credential, so its urgency depends on whether the administrative API is exposed and how tightly the master key is held. A ticket should record those preconditions, so a later reader does not re-rank the work by the headline score (Inferred from [1][2][3][4][5]).

## Part 6: Weakness and technique mapping

The mapping below is this study's interpretation of public definitions, checked on 19 November 2026. It is deliberately small.

| Label | Case support | Boundary |
|---|---|---|
| CWE-116, CWE-420, CWE-73, CWE-94 and CWE-470 | Assigned in the KEV entries for the four CVEs | The authoritative weakness labels; X41 labels the LiteLLM flaw CWE-94 [5][8] |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Network-reachable Synology, REDCap and Axis flaws, and LiteLLM where its API is exposed | High-confidence analytical mapping |
| [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Code execution through a Python sandbox escape, PHP code written by the import chain, or a loaded class | Analytical mapping; the sources describe no post-exploitation commands |
| Specific persistence, lateral-movement or exfiltration techniques | No incident sequence is public | Not mapped; no real-world intrusion detail is in evidence |

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read four KEV entries on one day as a coordinated campaign. The entries share a catalog date and a response requirement, and nothing else in the reviewed record links them (Inferred from [5]). The easy understatement is to dismiss the LiteLLM entry because it needs administrator access: KEV lists it because exploitation was observed, and a proxy that holds many providers' API keys is a high-value target once a credential is obtained.

### Old fixes and unsupported software

Two of the four show a slow end of the patch lifecycle. The Synology fix is two years old, and Axis 1.x will not be fixed at all. A fixed version does not help a device that never updated, and an end-of-life library cannot be patched by upgrading. Both point to inventory as the control that matters: the work is knowing where the product runs, including inside other products (Inferred from [4][6]).

### Research found with AI assistance

The REDCap write-up describes an AI coding assistant implementing a published technique against the source. As in other recent disclosures, the evidence supports a narrow reading: tooling lowered the cost of building and testing the exploit, while the underlying flaws were ordinary ones, a decoding mismatch and an unchecked file name (Reported [10]; Inferred).

## Sources

1. CVE Program, CVE Record CVE-2024-10441 (Synology CNA; CISA ADP SSVC). https://cveawg.mitre.org/api/cve/CVE-2024-10441
2. CVE Program, CVE Record CVE-2026-40217 (MITRE CNA; CISA ADP SSVC). https://cveawg.mitre.org/api/cve/CVE-2026-40217
3. CVE Program, CVE Record CVE-2026-90817 (Securifera CNA; CISA ADP SSVC). https://cveawg.mitre.org/api/cve/CVE-2026-90817
4. CVE Program, CVE Record CVE-2026-90436 (Apache CNA; CISA ADP CVSS and SSVC). https://cveawg.mitre.org/api/cve/CVE-2026-90436
5. CISA, Known Exploited Vulnerabilities Catalog (entries added 18 November 2026; checked 19 November 2026). https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. Synology, Security Advisory Synology-SA-24:20 (DSM, Pwn2Own 2024). https://www.synology.com/en-global/security/advisory/Synology_SA_24_20
7. BerriAI, GitHub Security Advisory GHSA-wxxx-gvqv-xp7p, Sandbox escape in custom-code guardrail. https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p
8. X41 D-Sec, Advisory X41-2026-001: Guardrail Sandbox Escape in LiteLLM, 8 April 2026. https://www.x41-dsec.de/lab/advisories/x41-2026-001-litellm/
9. Apache Software Foundation, Axis 1.x patch commit. https://github.com/apache/axis-axis1-java/commit/41f3b4e8d04e310ca81f86b92630ab2c11d608bd
10. Securifera, Survey Says: Remote Code Execution, CVE-2026-90817, 27 September 2026. https://www.securifera.com/blog/2026/09/27/survey-says-remote-code-execution-cve-2026-90817/

## Related references

- [CVE Reference](/CVE_REFERENCE.md) and [CWE Reference](/CWE_REFERENCE.md) for the identifiers used here.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating exposed management interfaces and web applications as attack surface.
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) for ranking by exposure and preconditions rather than base score.
