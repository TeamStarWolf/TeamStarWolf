# Java4Shell, CVE-2026-114938: The OpenJDK Base64 Intrinsic Heap Overflow

*A TeamStarWolf case study. Published 18 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Secure Coding](/SECURE_CODING_REFERENCE.md), [AI Offensive Security](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [Log4Shell](/case-studies/LOG4SHELL.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management leads, Java platform and application owners, incident responders, and security engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 13 min (3,099 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run Java anywhere, you may have runtimes bundled inside other products, you need the facts of CVE-2026-114938 (Java4Shell), or you are deciding how urgently to patch it

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: Reach and preconditions](#part-2-reach-and-preconditions), [Part 4: Find and fix it](#part-4-find-and-fix-it)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Java4Shell, CVE-2026-114938, is a memory-corruption flaw in the x86-64 Base64 decoder of OpenJDK, the Java runtime most server software is built on. A remote attacker with no credentials can send a short, malformed Base64 string to an application that decodes attacker-supplied Base64 and overwrite memory just past a heap buffer. Oracle scores it 8.1 under CVSS 3.1; the finders, Calif, score it 9.2 under CVSS 4.0 (Confirmed [1][5]).

The interesting part is the tension in the record. Oracle labels the flaw difficult to exploit, the CVSS vector sets attack complexity high, and as of 18 November 2026 there is no report of exploitation in the wild and no entry in the CISA Known Exploited Vulnerabilities catalog (Confirmed [1][2][8]). At the same time, the finders say they demonstrated unauthenticated remote code execution against several widely deployed Java applications in their default configurations, and CISA issued an alert the day of disclosure urging immediate patching (Reported [5]; Confirmed [4]). Both of those statements can be true: a bug can be hard to weaponize in general and still have working exploits for specific popular targets.

This study separates what the official record establishes (the flaw, the affected versions, the score, the status) from what the finders demonstrated or claimed, and from the engineering judgment a defender needs. It treats Java4Shell as three problems that need different owners: a memory-safety defect in a runtime most teams do not build themselves, an inventory problem because that runtime hides inside other products, and a prioritization problem because the severity depends on hardware and on how each application uses Base64.

### Key facts at a glance

| Fact | Value | Grade |
|---|---|---|
| CVE | CVE-2026-114938, nicknamed Java4Shell | Confirmed [1][2] |
| Weakness | CWE-122, heap-based buffer overflow | Confirmed [2][3] |
| Component | The x86-64 HotSpot Base64 decoder intrinsic, reached through the C2 JIT compiler; Oracle names the component Compiler | Confirmed [1]; Demonstrated [5] |
| CVSS 3.1 (Oracle) | 8.1 High, vector AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | Confirmed [1][3] |
| CVSS 4.0 (finders) | 9.2 | Reported [5] |
| Affected runtime | OpenJDK 17.0.6 and later, and distributions built from it; Oracle Java SE 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3, Oracle GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3, Oracle GraalVM Enterprise Edition 21.3.20.0.3 | Confirmed [1]; Reported for the OpenJDK range [5] |
| Hardware precondition | x86-64 processors with AVX-512 VBMI; ARM64 is not affected | Reported [5] |
| Disclosure | 17 November 2026, alongside the Oracle Critical Patch Update and an OpenJDK advisory | Confirmed [1][4]; Reported [5][6] |
| Exploitation status | No known exploitation in the wild; not in CISA KEV as of 18 November 2026; CISA SSVC exploitation none | Confirmed [2][4][8] |
| Mitigations without patching | Start the JVM with -XX:-UseBASE64Intrinsics, or with -XX:UseAVX=2 on x86-64 hosts; validate and size-limit Base64 at the boundary | Reported [5]; Confirmed [4] |

### Key findings

- **A memory-safe platform had a memory-corruption bug in its own plumbing.** Java checks memory accesses for the code written on top of it, but parts of the runtime are hand-written assembly where that protection does not apply. The defect is in such a routine (Confirmed [1]; Demonstrated [5]).
- **The severity depends on the CPU.** The vulnerable code is a hardware-specific optimization that only runs on x86-64 chips with AVX-512 VBMI. A runtime on ARM64, or on older x86-64 without those instructions, does not reach it (Reported [5]).
- **Difficult in general is not the same as safe in practice.** The high attack-complexity rating reflects that each target needs a bespoke exploit, not that no target is exploitable. The finders report working pre-authentication exploits for named products (Reported [5]; Confirmed for the rating [1]).
- **The hard part for defenders is finding the runtime, not understanding the bug.** Java hides inside appliances, container images and third-party applications, and may not show up as its own line in a software inventory (Confirmed [4]).
- **The public record is early.** NVD still lists the record as undergoing analysis, the finders are holding back weaponized exploits for individual products, and no victim or in-the-wild campaign is established (Confirmed [3][2]; Reported [5]).

### Top recommendations

1. Inventory every Java runtime you operate, including the copies bundled inside other products, container images and appliances, and record which host CPUs have AVX-512 VBMI.
2. Apply the vendor and distribution updates, prioritizing internet-facing systems that decode untrusted input, then systems that process attacker-influenced Base64 anywhere in a request.
3. Where you cannot patch at once, apply a documented compensating control: the runtime flags that disable the vulnerable routine, plus input validation and size limits on Base64 at the application boundary, as CISA advises.
4. Treat the severity as conditional. Rank exposure by whether an application decodes untrusted Base64 and whether the host CPU meets the hardware requirement, rather than by the base score alone.
5. Watch for unexpected JVM crashes and unfamiliar Java processes, which are the cheap signals this class of flaw tends to produce before a reliable exploit lands.

## Scope and evidence standard

This study uses Oracle's advisory, the CVE and NVD records, the CISA alert, the finders' technical write-up and the referenced OpenJDK advisory. It does not have independent access to the weaponized exploits, a victim's logs or a controlled lab run on affected hardware. No exploit was executed for this study.

**Confirmed** means an official source (Oracle, the CVE record, NVD, CISA) explicitly supports the claim. **Demonstrated** means the finders published a reproducible trigger or a described proof of concept. **Reported** means the finders or press stated it without an independent official record, such as the per-product exploits and the hardware list. **Inferred** marks the author's interpretation. **Not established** marks a claim the reviewed sources do not support, such as any count of compromised organizations.

A researcher's demonstration of remote code execution against a product in a lab is strong evidence that the product is exploitable; it is not evidence that any particular organization running that product was compromised. A nickname and a same-day alert raise attention; they do not by themselves change the exploitation status. These distinctions carry the analysis below.

## Part 1: The vulnerability

### A memory-corruption bug in a memory-safe platform

One of Java's long-standing selling points is memory safety: the runtime manages memory and checks accesses, so application code is largely spared the out-of-bounds reads and writes common in C and C++. That guarantee covers the code written on top of the runtime. It does not cover the runtime itself, parts of which are written in C, C++ and assembly for speed. Java4Shell lives in one of those parts (Confirmed [1]; Demonstrated [5]).

### The Base64 intrinsic, and why Oracle calls it the compiler

HotSpot, the standard JVM, speeds up hot methods by compiling them to native code with its C2 just-in-time compiler, and it replaces certain standard-library operations with hand-tuned machine code called intrinsics. The Base64 decoder has such an intrinsic on x86-64, using AVX-512 instructions to process many bytes at once. Because the vulnerable code is produced through the JIT compiler path, Oracle records the affected component as Compiler, even though the observable behavior is in Base64 decoding (Confirmed [1]; Demonstrated [5]).

### Root cause: an underflowed mask on the padded tail

The finders describe the defect as a miscalculated store mask for the final, padded chunk of a Base64 string. For certain malformed tails that still carry a padding character, the routine computes a negative output length, which turns into a mask that writes a full 64-byte vector where a smaller buffer was allocated. With an input of 64 letters followed by a single equals sign, the decoder allocates a 50-byte buffer and then writes 62 bytes past its end; on OpenJDK 17 the triggering length is higher. The runtime still rejects the input afterward, but by then adjacent heap memory has already been overwritten with a fixed pattern whose landing position, not its contents, is what the attacker controls (Demonstrated [5]).

### What the out-of-bounds write gives an attacker

A fixed-value overwrite with only positional control is a hard starting point, not an automatic takeover. The finders describe turning it into a controllable primitive by grooming the heap so the overwrite lands on the length field of an attacker-reachable array, which widens that array into a tool for reading and writing other heap memory. From there they describe a heap-disclosure capability, in the style of Heartbleed, that can leak secrets such as keys and tokens, and an escalation to code execution by reaching internal JVM structures. They performed the heap grooming remotely over real network paths rather than only in a local lab (Demonstrated and Reported [5]).

## Part 2: Reach and preconditions

### Affected runtimes and versions

The finders state that the flaw affects OpenJDK from version 17.0.6 onward, and therefore the many distributions built from OpenJDK, naming Amazon Corretto, Eclipse Temurin, the Microsoft Build of OpenJDK, Azul Zulu, BellSoft Liberica, SAP SapMachine, Red Hat OpenJDK, Oracle OpenJDK, Oracle Java SE and Oracle GraalVM for JDK (Reported [5]). Oracle's own advisory lists the specific affected Oracle Java SE, GraalVM for JDK and GraalVM Enterprise Edition builds in the key-facts table above (Confirmed [1]). The breadth matters: a team that never installed a JDK directly may still run several, inside products it bought.

### The hardware boundary

The vulnerable routine is a hardware-specific optimization that only runs on x86-64 processors with AVX-512 VBMI support, which the finders map to recent Intel Xeon families (Ice Lake and later) and AMD EPYC and Ryzen parts from Zen 4 onward. ARM64 processors are not affected, and x86-64 chips without those instruction-set extensions do not reach the code. A defender can check a Linux host for the relevant CPU flags before treating it as exposed (Reported [5]). This boundary is the single biggest reducer of the real population at risk, and it is not visible in the base CVSS score.

### Demonstrated impact

The finders report that in default configurations they achieved pre-authentication remote code execution against Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory, Jenkins and PingFederate, and post-authentication execution against Apache Kafka, Apache Solr, Elasticsearch, Gerrit and Spinnaker, with further results against sample applications on Apache Struts and Spring Boot. They also describe a client-side variant in which a Java program that connects to a malicious server over TLS can be compromised even if it exposes no service of its own (Reported [5]). These are lab demonstrations against products, not a claim that specific deployments of them were breached.

### What raises and lowers real-world exploitability

Four facts pull toward caution: the hardware precondition, the high attack complexity, the finders' own statement that there is no universal exploit and that each target needs a bespoke profile, and their note that exploitation is sensitive to network timing. Four facts pull the other way: unauthenticated reach, the breadth of software that decodes Base64 during ordinary work such as authentication and file upload, the demonstrated pre-authentication results against popular products, and the ease of the trigger itself. A useful reading holds both: the flaw is not a point-and-shoot internet worm today, and it is also not a theoretical curiosity (Inferred from [1][5]).

## Part 3: The scores, the label and the status

Oracle rates the flaw 8.1 under CVSS 3.1 with high attack complexity and full confidentiality, integrity and availability impact, the vector a defender should read before ranking it. The finders rate it 9.2 under CVSS 4.0. The two numbers are not in conflict; they come from different scoring systems and different judgments about complexity, and a reader should cite the system with the number (Confirmed [1][3]; Reported [5]).

CISA's Vulnrichment assigns CWE-122, a heap-based buffer overflow, and an SSVC decision of exploitation none, automatable no and technical impact total as of 17 November 2026 (Confirmed [2]). The flaw is not in the CISA Known Exploited Vulnerabilities catalog as of 18 November 2026, and no public source reviewed here reports exploitation in the wild (Confirmed [2][8]). NVD had published the record but still listed it as undergoing analysis on 18 November 2026, so its enriched fields may change (Confirmed [3]).

## Part 4: Find and fix it

### Decide whether you are exposed

Exposure needs two things at once: an affected runtime, and an x86-64 CPU with AVX-512 VBMI under it. Build an inventory of every Java runtime you operate, and follow CISA's reminder that runtimes bundled with third-party applications, container images and appliances may not appear as separate entries. Record the host CPU for each, and treat a runtime on ARM64 or on older x86-64 as out of scope for this specific flaw while still tracking it for the rest of the patch set (Confirmed [4]; Reported for the hardware test [5]).

### Apply the fix

The fix shipped on 17 November 2026 through the Oracle Critical Patch Update for Oracle's builds and through an OpenJDK advisory for the open-source line, with distributions following. Prioritize internet-facing systems, then any system that decodes attacker-influenced Base64 during normal processing (Confirmed [1][4]; Reported [5][6]).

### If you cannot patch yet

The finders describe two runtime flags that disable the vulnerable path: starting the JVM with the option that turns off the hardware Base64 routine, or the option that disables AVX-512 on x86-64 hosts, the latter only on x86-64 because other architectures reject it. CISA separately recommends restricting and validating Base64 input at the application boundary, enforcing input-size limits, and limiting unauthenticated access. Record any such control as temporary, with an owner and a removal date tied to patching (Reported [5]; Confirmed [4]).

### Detect and monitor

This class of flaw tends to crash the runtime before it executes code reliably, so CISA's suggested signals are practical: watch for unexpected JVM crashes, unfamiliar or rogue Java runtimes, and suspicious Java processes. None of these is specific proof of exploitation, and their absence is not proof of safety; they are cheap indicators worth collecting while patching proceeds (Confirmed [4]; Inferred).

### The vulnerability-management view

Rank this flaw by exposure, not by the headline number. A public-facing Keycloak or Jira on affected hardware is a different risk from an internal batch job on ARM64. Use the CVSS vector, the hardware test and the application's use of Base64 to build that ranking, and record the hardware precondition in the ticket so a later reader does not re-escalate a host that was never in scope (Inferred).

## Part 5: how the flaw was found

The finders, Calif, say they discovered and weaponized Java4Shell with heavy use of AI coding agents, describing a workflow they call the centaur hacker in which a human sets direction and tools and an agent does the search and much of the exploit construction. They report that one researcher found the bug in about an hour and built a first working exploit in two more, at a token cost under two hundred dollars, and that the same group earlier disclosed a PHP flaw by the same method. The work was covered by the New York Times (Reported [5][10]).

Two cautions apply. First, these are the finders' own figures, offered in a disclosure that also markets their method; they are worth reporting and not worth treating as audited. Second, the general lesson stands regardless of the exact numbers: audit effort against mature, hand-written runtime internals is getting cheaper, which raises the value of removing optimizations and code paths an application does not need. That argument, that unused complexity is a liability, is the finders' framing and a reasonable one, not a finding unique to this bug (Reported [5]; Inferred).

## Part 6: weakness and technique mapping

The mapping below is this study's interpretation of public definitions, checked on 18 November 2026. It is small on purpose; filling every stage with a plausible technique would read as precise without being so.

| Label | Case support | Boundary |
|---|---|---|
| CWE-122, heap-based buffer overflow | Assigned by CISA Vulnrichment and described by the finders | The authoritative weakness label [2][5] |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Unauthenticated network reach to a vulnerable service | Analytical mapping; applies to server-side chains, not the client-side variant |
| [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/) | The described client-side case, a Java client connecting to a malicious server | Analytical mapping; the finders describe this path but publish no product list for it |
| Specific persistence, lateral-movement or exfiltration techniques | No incident sequence exists to map | Not mapped; no real-world intrusion is in evidence |

## Cross-cutting themes

### What is overstated and what is understated

The easy overstatement is the nickname. Java4Shell echoes Log4shell, and the comparison flatters the flaw: Log4Shell was trivially and universally exploitable and was exploited at scale within days, while Java4Shell needs affected hardware, a bespoke per-target exploit and favorable network conditions, and has no reported exploitation yet. The easy understatement is the opposite error, reading difficult to exploit and not in KEV as not my problem: the finders demonstrated pre-authentication code execution against products many enterprises run on the open internet, and the patch is worth prioritizing on exposed hosts. The honest position is in between, and it is set by exposure rather than by the headline (Inferred from [1][4][5][8]).

A second theme is inventory. The most repeated defender instruction across the official and research sources is not about the bug at all; it is to find the Java runtimes you did not know you were running. A flaw in a runtime is a supply-chain problem in slow motion: the code is the same everywhere, but the responsibility for patching is scattered across every product that bundled it.

## Sources

1. Oracle, Critical Security Patch Update Advisory, November 2026. https://www.oracle.com/security-alerts/cspunov2026.html
2. CVE Program, CVE Record CVE-2026-114938 (Oracle CNA; CISA ADP Vulnrichment). https://www.cve.org/CVERecord?id=CVE-2026-114938
3. NVD, CVE-2026-114938 (undergoing analysis as of 18 November 2026). https://nvd.nist.gov/vuln/detail/CVE-2026-114938
4. CISA, Alert: Critical Java Vulnerability Requires Immediate Patching, 17 November 2026. https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching
5. Calif, Java4Shell (CVE-2026-114938), technical write-up by Quang Luong. https://calif.io/java4shell
6. OpenJDK Vulnerability Group, security advisory, 17 November 2026. https://openjdk.org/groups/vulnerability/advisories/2026-11-17
7. MITRE, CWE-122: Heap-based Buffer Overflow. https://cwe.mitre.org/data/definitions/122.html
8. CISA, Known Exploited Vulnerabilities Catalog (checked 18 November 2026). https://www.cisa.gov/known-exploited-vulnerabilities-catalog
9. oss-security mailing list, disclosure thread, 17 November 2026. https://www.openwall.com/lists/oss-security/2026/11/17/31
10. The New York Times, report on an AI-discovered Java security flaw, 17 November 2026. https://www.nytimes.com/2026/11/17/us/politics/ai-security-bug-java.html

## Related references

- [CVE Reference](/CVE_REFERENCE.md) and [CWE Reference](/CWE_REFERENCE.md) for the identifiers used here.
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) for ranking exposure by vector and context rather than base score.
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) for the memory-safety boundary between a managed runtime and its native internals.
- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md) for the AI-assisted discovery method the finders describe.
- [Log4Shell](/case-studies/LOG4SHELL.md) for the contrast with a genuinely universal Java-ecosystem flaw.
