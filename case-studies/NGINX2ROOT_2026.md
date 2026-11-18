# nginx2root 2026: The nginx HTTP/2 Remote Code Execution Flaws, CVE-2026-123007 and CVE-2026-123633

*A TeamStarWolf case study. Published 18 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services](/INTERNET_FACING_SERVICES_REFERENCE.md), [AI Offensive Security](/AI_OFFENSIVE_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads, nginx and platform operators, incident responders, and security engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,319 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run nginx anywhere, you may have it bundled in appliances or container images, or you need the facts of the nginx2root HTTP/2 flaws CVE-2026-123007 and CVE-2026-123633

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: Reach, scores and status](#part-2-reach-scores-and-status), [Part 4: Find and fix it](#part-4-find-and-fix-it)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

On 18 November 2026, F5 disclosed nginx2root, a set of five memory-corruption flaws in nginx, each an independent unauthenticated path to running code as the nginx worker, alongside a Linux kernel flaw that can raise that access to root on the host. This study covers the two that involve HTTP/2, which are also the two a single change blocks: CVE-2026-123007, an integer overflow in HTTP/2 flow control, and CVE-2026-123633, a use-after-free when an HTTP/2 connection is reused. F5 scores both at 9.2 under CVSS 4.0 and 8.1 under CVSS 3.1 (Confirmed [1][2][5]).

The record holds a real tension. The CVSS vector sets attack complexity high, nginx.org rates CVE-2026-123633 only medium, as of 18 November 2026 there is no reported exploitation in the wild and neither CVE is in the CISA Known Exploited Vulnerabilities catalog, and the finders withheld their exploits (Confirmed [5][10]; Reported [7][9]). At the same time, Wiz reports confirming code execution with an address-space-layout-randomization bypass on stock nginx builds serving ordinary static files, and Xint reports chaining the HTTP/2 flaw to reach root on a cloud host from inside a container (Reported [7][9]). Both can be true: a bug can be hard to weaponize in general and still have a working exploit for a common configuration.

nginx2root matters because of where the code sits. nginx is the reverse proxy and web server in front of a large share of the internet's sites and APIs, and this code runs before any authentication or application logic. The worker that an attacker would control is the process that terminates TLS and handles decrypted traffic, tokens and keys for everything behind it. This study separates what the official record establishes from what the finders demonstrated or claimed, keeps the HTTP/2 pair distinct from the wider cluster, and treats the hard part for defenders as finding exposed instances rather than understanding the bugs.

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| CVEs covered | CVE-2026-123007 and CVE-2026-123633, the HTTP/2 flaws of nginx2root | Confirmed [1][2] |
| Weaknesses | CWE-191 integer underflow and CWE-787 out-of-bounds write (123007); CWE-416 use-after-free (123633) | Confirmed [1][2] |
| Product | F5 NGINX Open Source and NGINX Plus; the HTTP/2 module, ngx_http_v2_module | Confirmed [1][2][5] |
| CVSS | 9.2 CRITICAL under CVSS 4.0 and 8.1 HIGH under CVSS 3.1, from F5, for both | Confirmed [1][2][6] |
| nginx.org severity | CVE-2026-123007 major; CVE-2026-123633 medium | Confirmed [5] |
| Affected | CVE-2026-123007: every official nginx release from 1.9.5 (2015) through 1.31.8. CVE-2026-123633: from 1.19.7. NGINX Plus from R33 | Confirmed [5]; Reported for the 1.9.5 origin [7] |
| Fixed | nginx 1.30.7 stable and 1.31.9 mainline, released 18 November 2026; NGINX Plus builds per F5 | Confirmed [5]; Reported [7] |
| Precondition | Network access to an HTTP/2 listener; CVE-2026-123633 also needs requests forwarded to an upstream. No authentication | Confirmed [1][2]; Reported [7] |
| Exploitation status | No known exploitation in the wild; neither CVE in CISA KEV as of 18 November 2026; exploits withheld | Confirmed [10]; Reported [7][9] |
| Quickest mitigation | Disable HTTP/2, which blocks both of these two flaws but not the other three nginx2root flaws | Reported [7] |

### Key findings

- **Two independent HTTP/2 flaws, reachable before anything else runs.** Both sit in nginx's front-door HTTP/2 code, so a well-built application behind nginx is exposed regardless of its own security (Confirmed [1][2]; Reported [7]).
- **The widest one is old and common.** CVE-2026-123007 affects every official nginx release since HTTP/2 was added in 2015, so the exposed population is bounded mainly by whether HTTP/2 is enabled, not by how new the server is (Reported [7]).
- **High complexity is not the same as safe.** The high attack-complexity rating reflects that an exploit must fit a build and configuration, not that no build is exploitable; the finders report working code execution against stock builds (Confirmed for the rating [1]; Reported [7][9]).
- **The scores disagree, so cite the system with the number.** F5 rates the pair 9.2 under CVSS 4.0; nginx.org rates one of them medium. Neither is wrong; they answer with different systems and judgments (Confirmed [1][5]).
- **Finding exposure is the hard part, and version strings lie.** nginx may be bundled in appliances and images, distributions backport fixes without changing the version nginx prints, and the attack traffic does not appear in access logs (Reported [7]).

### Top recommendations

1. Inventory every nginx you operate, including copies inside appliances, ingress controllers and container images, and record which listeners accept HTTP/2.
2. Upgrade to a fixed nginx (1.30.7 or 1.31.9), an NGINX Plus fixed build, or a patched distribution package, then restart nginx so the running worker is replaced; a configuration reload is not enough.
3. Where you cannot patch at once, disable HTTP/2 on exposed listeners to close these two flaws, and treat it as temporary, since it leaves the other three nginx2root flaws open.
4. Verify the actual package version against the distribution's advisory rather than trusting the version nginx prints, and rebuild container images from a fixed base.
5. Add detection for the signals this class produces, above all an nginx worker starting a shell or other program, because the triggering HTTP/2 frames are not logged as requests.

## Scope and evidence standard

This study uses the F5 CVE records and advisories, the nginx.org advisory list, the NVD and CISA records, and the public write-ups by Xint and Wiz. It covers the two HTTP/2 flaws the owner named; the other three nginx flaws and the Linux kernel flaw are summarized as context, not analyzed in depth. No exploit was executed, and no researcher exploit code is reproduced here; the finders withheld working exploits in any case.

**Confirmed** means an official source (the CVE records, F5, nginx.org, NVD, CISA) supports the claim. **Reported** means a finder's write-up stated it without an independent official record, including the exploitation demonstrations, the 1.9.5 origin and the exposure numbers. **Demonstrated** marks a capability a finder says it proved under stated conditions. **Inferred** marks the author's interpretation. **Not established** marks a claim the reviewed sources do not support, such as any count of compromised hosts.

A finder's demonstration of code execution against a stock build is strong evidence that the configuration is exploitable; it is not evidence that any particular production server was compromised. A memorable nickname and a large exposure estimate raise attention; they do not change the exploitation status. These distinctions carry the analysis below.

## Part 1: The two HTTP/2 flaws

### CVE-2026-123007: a flow-control counter that overflows

HTTP/2 flow control keeps a server from sending more response data than a client is ready to receive, using a per-connection credit that the protocol caps at a fixed maximum. The finders describe a bookkeeping error: when a stream is canceled while its data is still queued, nginx refunds the unsent amount to the connection credit without checking an upper bound. A client that has already restored the same credit, then cancels, can push the counter past the cap. Because the counter is an unsigned value, the later bounds check underflows and stops rejecting anything, so the client can set the credit to an arbitrary large value (Reported [7][9]).

From there the oversized credit is cast to a signed type when nginx sizes the next data frame, which turns it negative, and the send path converts that into an enormous copy length. The finders explain that on common 64-bit systems the large-copy routine works backward from an address that has wrapped, so only a small region around a buffer's edges is actually copied. That gives a controlled write and a read of memory that returns in the response, which is enough to defeat address randomization and redirect a cleanup step into running a command as the worker (Reported [7][9]). F5 labels the weakness an integer underflow and an out-of-bounds write (Confirmed [1]).

The reach is the notable part. F5 and the finders place the flaw in every official nginx release from the 2015 version that introduced HTTP/2 through 1.31.8, so the exposed set is governed by whether HTTP/2 is enabled rather than by version age (Confirmed for the affected list [1][5]; Reported for the 2015 origin [7]).

### CVE-2026-123633: a connection freed while still in use

The second flaw is a use-after-free. The finders describe an HTTP/2 connection that pauses in the middle of a headers frame being marked as reusable and staying marked after the request begins. When that request opens a connection to an upstream backend and nginx is short of connection slots, nginx can close the same HTTP/2 connection to free a slot, destroying the request while other code is still using it. Exploitation therefore needs HTTP/2 and requests that nginx forwards to an upstream (Confirmed for the weakness and module [2]; Reported for the mechanism [7][9]). F5 labels it a use-after-free (Confirmed [2]).

### What the finders demonstrated, and what they held back

Wiz reports confirming remote code execution with an address-randomization bypass on stock nginx 1.31.7 and 1.31.8 builds, over TLS, serving ordinary static files, with no backend or third-party module. Xint reports reaching command execution as the worker in tests against the official nginx container image, and separately chaining the HTTP/2 flaw with an unpatched Linux kernel flaw to reach root on a cloud host from inside a container. Both groups say they withheld working exploit code, and neither reports exploitation in the wild (Reported [7][9]). These are demonstrations against builds and configurations, not evidence that specific deployments were breached.

## Part 2: Reach, scores and status

### The HTTP/2 precondition, and why version is not enough

Both flaws require a reachable HTTP/2 listener, and CVE-2026-123633 also requires nginx to forward requests to an upstream. A build without the HTTP/2 module, or a server with HTTP/2 turned off on every listener, is not reachable through either. The finders stress that a version string does not settle exposure: HTTP/2 must be enabled, and a distribution may carry a backported fix under an unchanged version number. As a rough scale measure, Xint reports finding about 56.7 million nginx hosts on a public scan service and notes that most versioned ones fall in the affected range, while warning that this counts potential exposure, not confirmed vulnerability (Reported [7]).

### The scores disagree

F5, as the issuing authority, rates both flaws 9.2 under CVSS 4.0 and 8.1 under CVSS 3.1, with high attack complexity. nginx.org's own advisory list rates CVE-2026-123007 major and CVE-2026-123633 medium. The difference is not a contradiction; it reflects different scoring systems and different judgments about how hard exploitation is and how much the preconditions reduce it. A defender ranking the work should read the vector and name the system with the number rather than repeating a single severity word (Confirmed [1][2][5][6]; Inferred).

### Exploitation status

CISA's Vulnrichment records an SSVC decision of exploitation none, automatable no and technical impact total for both, as of 18 November 2026 (Confirmed [1][2]). Neither CVE is in the CISA Known Exploited Vulnerabilities catalog as of that date, and no public source reviewed here reports exploitation in the wild (Confirmed [10]). NVD had received the records but not yet completed analysis, so its enriched fields may change (Confirmed [6]).

### nginx2root in context

The two HTTP/2 flaws are part of a larger disclosure the finders call nginx2root: five nginx flaws in all, the other three in the HTTP/3 module, the DNS resolver used for request-time proxy destinations, and the mail proxy's authentication path, plus a separate Linux kernel flaw in the SCTP subsystem that can turn worker access into root on the host. Each nginx flaw is an independent path to code execution in its own configuration, and disabling HTTP/2 blocks only the two covered here. This study does not analyze the other four; a defender scoping the full cluster needs to check, per server, which protocols its listeners accept, how its proxy destinations are resolved, and whether it runs a mail proxy (Reported [7]).

## Part 3: why nginx is the wrong place to have a memory bug

### The worker holds every secret behind it

An attacker who exploits either flaw runs commands as the nginx worker user. That process terminates TLS and handles decrypted traffic for every site and API behind it, so request headers, cookies, bearer tokens and API keys pass through its memory. Because one nginx deployment often fronts several applications, a flaw in nginx exposes them even when their own code is sound. Chained with the unpatched kernel flaw, the finders report that worker access becomes root on the host, and because containers share the host kernel, that reaches other containers on the same host (Reported [7]). The impact ceiling is high; the preconditions and complexity are what hold it back.

### Version strings lie, and patching means restart

Two operational facts make this harder than applying a number. First, distributions backport fixes without changing the version nginx prints, so the output of a version command is not proof of patch state; the package version against the distribution's advisory is. Second, a configuration reload does not replace the running executable, and old workers keep serving existing connections until they exit, so a genuine fix needs a restart or a live binary upgrade, and container images need rebuilding from a fixed base (Reported [7]).

### Detection is hard by design

The frames that trigger CVE-2026-123007 are flow-control and stream-reset messages, not requests, so they do not appear in access logs, and TLS hides them on the wire. The finders' strongest suggested signal is therefore behavioral: an nginx worker starting a shell or any other program, which a host audit rule on process execution for the worker's user records. Weaker signs include long-lived HTTP/2 connections whose received data keeps growing while logged request sizes stay small, and repeated worker crashes, each of which has innocent explanations on its own (Reported [7][9]).

## Part 4: Find and fix it

### Decide whether you are exposed

Build an inventory of every nginx you run, including the copies inside ingress controllers, appliances and container images. For each, record the real package version, whether any listener accepts HTTP/2, and, for CVE-2026-123633, whether it forwards to an upstream. The finders give concrete checks: whether the binary includes the HTTP/2 module, whether the loaded configuration enables HTTP/2, and whether the server negotiates HTTP/2 from outside the network (Reported [7]).

### Apply the fix, or mitigate

Install a fixed nginx (1.30.7 or 1.31.9), an NGINX Plus fixed build, or a patched distribution package, then restart nginx. Prioritize internet-facing servers, then appliances, packaged products and shared container images, where many deployments run the same build and one working exploit reaches all of them. Where immediate patching is not possible, disable HTTP/2 on exposed listeners to close these two flaws, and record it as a temporary control with an owner and a removal date, since it does not address the other three nginx2root flaws (Confirmed for the fixed versions [5]; Reported [7]).

### Detect and monitor

Add a host audit rule for the nginx worker user running a program, which is the clearest signal and records from the moment it is installed. Watch also for the weaker patterns above, and treat their absence as the absence of a signal rather than proof of safety. No indicators of compromise have been published (Reported [7]; Inferred).

### The vulnerability-management view

Rank this by exposure, not the headline number. A public-facing nginx with HTTP/2 enabled is a different risk from an internal one without it. Use the HTTP/2 precondition, the upstream condition for CVE-2026-123633 and the real package version to build that ranking, and record the preconditions in the ticket so a later reader does not re-escalate a server that was never in scope (Inferred).

## Part 5: the pattern below the application

The finders place nginx2root as the third disclosure in a week about code beneath the application: an Apache HTTP Server HTTP/2 flaw, then Java4Shell (CVE-2026-114938) in the Java runtime's Base64 decoder, and now the reverse proxy that often sits in front of both. In each case the vulnerable code runs before authentication or application logic, so a well-built service behind it is exposed anyway (Reported [7]).

The discovery method is part of the story. The two HTTP/2 flaws were reported independently by five teams, and two of them describe AI-assisted code analysis finding the bugs, after at least one had sat in nginx for more than a decade. As with Java4Shell, the honest reading is not that one tool changed everything, but that the cost of auditing mature, low-level infrastructure code is falling, which raises the value of reducing the attack surface such code presents (Reported [7][9]; Inferred).

## Part 6: weakness and technique mapping

The mapping below is this study's interpretation of public definitions, checked on 18 November 2026. It is deliberately small.

| Label | Case support | Boundary |
|---|---|---|
| CWE-191 and CWE-787 (123007) | Assigned by F5 for the flow-control flaw | The authoritative weakness labels [1] |
| CWE-416 (123633) | Assigned by F5 for the connection-reuse flaw | The authoritative weakness label [2] |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Unauthenticated network reach to a vulnerable nginx | High-confidence analytical mapping |
| [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | The reported kernel chain from worker to root | Analytical mapping; applies to the chained kernel step, which is out of this study's main scope |
| Specific persistence, lateral-movement or exfiltration techniques | No incident sequence exists to map | Not mapped; no real-world intrusion is in evidence |

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is to read the exposure count as a victim count. About 56.7 million hosts is a measure of where nginx runs, filtered by nothing more than a version string; it is not a number of vulnerable, let alone compromised, servers, because HTTP/2 must be enabled and backports hide behind versions. The easy understatement is the opposite, reading medium and not in KEV as not my problem: the finders demonstrated code execution against stock builds, the worker holds every secret behind it, and the widest flaw has been present since 2015. The honest position is set by exposure, which here is concrete: does this nginx accept HTTP/2, and is it reachable (Inferred from [1][5][7][9][10]).

A second theme is the proxy as a single point of exposure. The most repeated defender instruction across the sources is not about either bug; it is to find the nginx instances you did not know you were running, inside appliances and images, and to confirm patch state by package rather than by the version the server prints. A flaw in shared front-door code is a supply-chain problem in slow motion: the same code runs everywhere, and the responsibility to patch it is scattered across everyone who deployed or bundled it.

## Sources

1. CVE Program, CVE Record CVE-2026-123007 (F5 CNA; CISA ADP Vulnrichment). https://www.cve.org/CVERecord?id=CVE-2026-123007
2. CVE Program, CVE Record CVE-2026-123633 (F5 CNA; CISA ADP Vulnrichment). https://www.cve.org/CVERecord?id=CVE-2026-123633
3. F5, Security Advisory K000163926 (CVE-2026-123007). https://my.f5.com/manage/s/article/K000163926
4. F5, Security Advisory K000163928 (CVE-2026-123633). https://my.f5.com/manage/s/article/K000163928
5. nginx, security advisories. https://nginx.org/en/security_advisories.html
6. NVD, CVE-2026-123633 (received, analysis pending as of 18 November 2026). https://nvd.nist.gov/vuln/detail/CVE-2026-123633
7. Equixly, nginx2root: Disabling HTTP/2 stops two of five nginx RCE flaws, 18 November 2026. https://equixly.com/blog/2026/11/18/nginx2root-disabling-http-2-stops-two-of-five-nginx-rce-flaws/
8. Xint, nginx2root. https://nginx2root.com/
9. Wiz Research, nginx HTTP/2 RCE vulnerabilities. https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities
10. CISA, Known Exploited Vulnerabilities Catalog (checked 18 November 2026). https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Related references

- [CVE Reference](/CVE_REFERENCE.md) and [CWE Reference](/CWE_REFERENCE.md) for the identifiers used here.
- [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md) for treating a reverse proxy as a front-door attack surface.
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) for ranking exposure by precondition and context rather than base score.
- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md) for the AI-assisted discovery the finders describe.
