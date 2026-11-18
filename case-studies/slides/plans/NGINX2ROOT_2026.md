# Slide plan: nginx2root HTTP/2

- Study: case-studies/NGINX2ROOT_2026.md
- Cover title: nginx2root / Two HTTP/2 RCE flaws / CVE-2026-123007 and 123633
- Subtitle: Two independent unauthenticated HTTP/2 memory-corruption flaws in nginx, both closed by disabling HTTP/2, as recorded on 18 November 2026.
- Published: 18 November 2026
- Notes: The cover frames a two-CVE pair inside a larger disclosure, dated to the record as it stood on publication day.

## OVERVIEW | What nginx2root is, and what this covers
- On 18 November 2026 F5 disclosed nginx2root, five nginx memory-corruption flaws plus a Linux kernel flaw that can raise access to root.
- This study covers the two HTTP/2 flaws a single change blocks: CVE-2026-123007 and CVE-2026-123633.
- Both sit in nginx front-door HTTP/2 code and run before any authentication or application logic.
- The hard defender problem is finding exposed instances, not understanding the bugs.
Caption: Evidence grade: Confirmed [1][2][5]; Reported [7]
Notes: This slide sets the two-CVE scope and why front-door code raises the stakes.

## TWO CVES | Two CVEs, kept distinct
House discipline keeps the pair distinct, each with its own identifier, mechanism and preconditions.

| Attribute | CVE-2026-123007 | CVE-2026-123633 |
|---|---|---|
| Weakness | CWE-191 underflow, CWE-787 OOB write | CWE-416 use-after-free |
| Module | ngx_http_v2_module | ngx_http_v2_module |
| Precondition | Reachable HTTP/2 listener | HTTP/2 listener plus upstream forwarding |
| Affected from | nginx 1.9.5 (2015) through 1.31.8 | nginx 1.19.7 |
| nginx.org severity | major | medium |
| Fixed in | 1.30.7 and 1.31.9 | 1.30.7 and 1.31.9 |
Caption: Evidence grade: Confirmed [1][2][5]; Reported for the 1.9.5 origin [7]
Notes: The pair shares a module but differs in weakness, precondition and affected range.

## CVE-123007 | A flow-control counter that wraps
- A canceled HTTP/2 stream refunds its unsent credit to the connection without an upper-bound check.
- A client that already restored the credit, then cancels, pushes the unsigned counter past its cap.
- The later bounds check underflows, letting the client set the credit to an arbitrary large value.
- F5 labels the weakness an integer underflow and an out-of-bounds write.
Caption: Evidence grade: Confirmed for the weakness labels [1]; Reported for the mechanism [7][9]
Notes: The first flaw is a bookkeeping error in HTTP/2 flow-control credit that leads to a controlled write.

## CVE-123633 | A connection freed while still in use
- An HTTP/2 connection paused mid headers frame is marked reusable and stays marked after the request begins.
- When nginx opens an upstream connection and is short of slots, it can close that same connection to free one.
- The request is destroyed while other code still uses it, a classic use-after-free.
- Exploitation needs HTTP/2 and requests that nginx forwards to an upstream.
Caption: Evidence grade: Confirmed for the weakness and module [2]; Reported for the mechanism [7][9]
Notes: The second flaw is a connection-reuse use-after-free that additionally requires upstream forwarding.

## PRECONDITIONS | What must be true to reach the worker
Left: Shared preconditions
- Network access to a reachable HTTP/2 listener.
- HTTP/2 enabled on the listener, not merely compiled in.
- No authentication before the vulnerable code runs.
Right: Extra for CVE-2026-123633
- nginx must forward the request to an upstream backend.
- Triggered when nginx is short of connection slots.
- Disabling HTTP/2 closes this flaw and CVE-2026-123007.
Caption: Evidence grade: Confirmed [1][2]; Reported [7]
Notes: The path to the worker is bounded by HTTP/2 reachability, with one extra condition for 123633.

## SCORES | The scores disagree
Stat: 9.2 | CVSS 4.0 base from F5, both CVEs
Stat: 8.1 | CVSS 3.1 base from F5, both CVEs
Stat: medium | nginx.org severity for CVE-2026-123633
- F5, the issuing authority, rates the pair the same under both CVSS systems.
- nginx.org rates CVE-2026-123007 major and CVE-2026-123633 medium.
- High attack complexity reflects build and configuration fit, not that no build is exploitable.
- Name the scoring system with the number rather than repeating one severity word.
Caption: Evidence grade: Confirmed [1][2][5][6]; Inferred for the reading
Notes: Two systems answer with different numbers, and both are valid judgments of the same pair.

## STATUS | Exploitation status versus compromise
- CISA Vulnrichment records SSVC exploitation none, automatable no, technical impact total for both.
- Neither CVE is in the CISA Known Exploited Vulnerabilities catalog as of 18 November 2026.
- No reviewed source reports exploitation in the wild, and the finders withheld their exploits.
- No count of compromised hosts is established; a working demonstration is not a victim count.
Caption: Evidence grade: Confirmed [1][2][10]; Reported [7][9]
Notes: Patch-available and demonstrated capability stay distinct from in-the-wild compromise here.

## DEMONSTRATED | What the finders showed and held back
- Wiz reports confirming code execution with an address-randomization bypass on stock 1.31.7 and 1.31.8 builds.
- That build served ordinary static files over TLS, with no backend or third-party module.
- Xint reports chaining the HTTP/2 flaw with an unpatched kernel flaw to reach root from inside a container.
- Both groups say they withheld working exploit code and report no exploitation in the wild.
Caption: Evidence grade: Reported [7][9]
Notes: The finders demonstrated capability against specific builds, not breaches of named deployments.

## WHY NGINX | The worker holds every secret behind it
- An attacker who exploits either flaw runs commands as the nginx worker user.
- That process terminates TLS and handles decrypted headers, cookies, tokens and keys for everything behind it.
- One nginx often fronts several applications, so a sound application is still exposed.
- Chained with the kernel flaw, the finders report worker access becoming root, reaching other containers on the host.
Caption: Evidence grade: Confirmed [1][2]; Reported [7]
Notes: The impact ceiling is high because of where the code sits; preconditions and complexity hold it back.

## INVENTORY | Version strings lie, patching needs restart
- Distributions backport fixes without changing the version nginx prints, so check the package against the advisory.
- nginx may be bundled in appliances, ingress controllers and container images you did not track.
- A configuration reload does not replace the running worker; a genuine fix needs a restart or live binary upgrade.
- Rebuild container images from a fixed base rather than trusting a printed version.
Caption: Evidence grade: Reported [7]
Notes: Finding exposure is the hard part, and a printed version number does not settle patch state.

## DETECTION | Detection is hard by design
- The triggering frames are flow-control and stream-reset messages, not requests, so access logs do not record them.
- TLS hides the frames on the wire.
- The strongest signal is behavioral: an nginx worker starting a shell or any other program.
- Weaker signs include growing HTTP/2 connections with small logged requests, and repeated worker crashes.
Caption: Evidence grade: Reported [7][9]; Inferred for weighting
Notes: Because the attack traffic is not logged as requests, detection leans on worker process behavior.

## FIX | Apply the fix, or mitigate
- Install a fixed nginx (1.30.7 or 1.31.9), an NGINX Plus fixed build, or a patched distribution package, then restart.
- Prioritize internet-facing servers, then appliances, packaged products and shared container images.
- Where patching must wait, disable HTTP/2 on exposed listeners to close these two flaws.
- Record that mitigation as temporary with an owner and removal date; it leaves the other three nginx flaws open.
Caption: Evidence grade: Confirmed for the fixed versions [5]; Reported [7]
Notes: Patching and restarting is the fix; disabling HTTP/2 is a bounded temporary control.

## CLUSTER | The wider nginx2root cluster
nginx2root is five nginx flaws plus a Linux kernel flaw; this study covers only the two HTTP/2 ones.

| Component | Status in this study |
|---|---|
| HTTP/2 flow control (123007) | Covered in depth |
| HTTP/2 connection reuse (123633) | Covered in depth |
| HTTP/3 module | Context only |
| DNS resolver for proxy destinations | Context only |
| Mail proxy authentication path | Context only |
| Linux kernel SCTP flaw | Context; enables worker-to-root |
Caption: Evidence grade: Reported [7]
Notes: Disabling HTTP/2 blocks only the two covered flaws, not the rest of the cluster.

## TAKEAWAYS | Set the risk by exposure, not headline
- Read the 56.7 million nginx hosts figure as where nginx runs, not as vulnerable or compromised servers.
- Do not read medium and not in KEV as safe; stock builds were shown exploitable and the widest flaw dates to 2015.
- Rank by exposure: does this nginx accept HTTP/2, is it reachable, does it forward upstream.
- A flaw in shared front-door code is a supply-chain problem scattered across everyone who deployed or bundled it.
Caption: Evidence grade: Inferred from [1][5][7][9][10]
Notes: The honest position is set by concrete exposure, which avoids both overstatement and dismissal.
