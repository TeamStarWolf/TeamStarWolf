# Slide plan: Java4Shell (CVE-2026-114938)

- Study: case-studies/JAVA4SHELL_CVE_2026_114938.md
- Cover title: Java4Shell / CVE-2026-114938 / OpenJDK Base64 intrinsic overflow
- Subtitle: A heap overflow in OpenJDK's x86-64 Base64 decoder intrinsic that can give an unauthenticated attacker a path to remote code execution.
- Published: 18 November 2026
- Notes: The cover frames one bounded memory-corruption flaw, keeping the demonstrated code execution separate from the reported absence of in-the-wild use.

## OVERVIEW | What Java4Shell actually is
- A heap-based buffer overflow (CWE-122) in the OpenJDK x86-64 Base64 decoder intrinsic, a JIT-compiled native routine.
- An unauthenticated attacker can send a short malformed Base64 string to an app that decodes attacker-supplied Base64.
- The write lands just past a heap buffer; the attacker controls where it lands, not the fixed bytes it writes.
- Reach is bounded: it needs affected hardware and an app that feeds attacker data to Base64 decoding.
Caption: Evidence grade: Confirmed [1][2]; Demonstrated [5]
Notes: The flaw sits in the optimized decoder path, so "every Java app is vulnerable" overstates it.

## KEY FACTS | The record at a glance
These dated facts come from the official and finder sources.

| Fact | Value | Grade |
|---|---|---|
| CVE | CVE-2026-114938, nicknamed Java4Shell | Confirmed [1][2] |
| Weakness | CWE-122, heap-based buffer overflow | Confirmed [2][3] |
| Component | x86-64 HotSpot Base64 decoder intrinsic | Confirmed [1]; Demonstrated [5] |
| Disclosure | 17 November 2026, Oracle CPU and OpenJDK advisory | Confirmed [1][4] |
| Exploitation | No known in-the-wild use; not in CISA KEV | Confirmed [2][4][8] |
Caption: Evidence grade: Confirmed [1][2][3][4][8]; Demonstrated [5]
Notes: Each number is pinned to its source so a later reader can trace it.

## THE BUG | A memory-safe runtime's unsafe core
- Java manages memory and checks accesses for the code written on top of the runtime.
- That guarantee does not cover the runtime itself, parts of which are C, C++ and assembly for speed.
- HotSpot replaces some standard-library operations with hand-tuned machine code called intrinsics.
- The Base64 decoder has such an x86-64 intrinsic using AVX-512 to process many bytes at once.
Caption: Evidence grade: Confirmed [1]; Demonstrated [5]
Notes: Oracle records the component as Compiler because the code is produced through the JIT path.

## ROOT CAUSE | An underflowed mask on the padded tail
- The finders describe a miscalculated store mask for the final padded chunk of a Base64 string.
- A malformed tail that still carries a padding character makes the routine compute a negative output length.
- That turns into a mask writing a full 64-byte vector where a smaller buffer was allocated.
- With 64 letters then one equals sign, the decoder allocates 50 bytes and writes 62 bytes past the end.
Caption: Evidence grade: Demonstrated [5]
Notes: The input is rejected afterward, but adjacent heap memory is already overwritten by then.

## SCORES | Two scoring systems, two numbers
Stat: 8.1 | Oracle CVSS 3.1, High, AC:H
Stat: 9.2 | Calif CVSS 4.0, finders' score
- The two numbers come from different systems and different judgments about complexity.
- Oracle's 3.1 vector is AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H, worth reading before ranking.
- Cite the system with the number rather than treating 8.1 and 9.2 as in conflict.
Caption: Evidence grade: Confirmed [1][3]; Reported [5]
Notes: High attack complexity means each target needs a bespoke exploit, not that no target is exploitable.

## HARDWARE | The precondition that bounds reach
Stat: x86-64 | Only AVX-512 VBMI chips reach the code
Stat: ARM64 | Not affected by this flaw
- The finders map affected parts to Intel Xeon Ice Lake and later, and AMD Zen 4 onward.
- Older x86-64 without those instruction-set extensions does not reach the vulnerable routine.
- A defender can check a Linux host for the relevant CPU flags before treating it as exposed.
Caption: Evidence grade: Reported [5]
Notes: This hardware boundary is the single biggest reducer of the real population at risk and is not in the base score.

## REACH | Affected runtimes and the inventory problem
- The finders state OpenJDK 17.0.6 onward is affected, and the distributions built from it.
- Named distributions include Amazon Corretto, Eclipse Temurin, Microsoft Build of OpenJDK, Azul Zulu and others.
- Oracle's advisory lists specific affected Oracle Java SE, GraalVM for JDK and GraalVM Enterprise builds.
- Java hides inside appliances, container images and third-party apps, so it may not appear as its own inventory line.
Caption: Evidence grade: Confirmed [1]; Reported [5]
Notes: A team that never installed a JDK directly may still run several inside products it bought.

## DEMONSTRATED | Pre-auth RCE against named products
Left: Pre-authentication RCE
- Keycloak, Atlassian Jira, Atlassian Confluence.
- JFrog Artifactory, Jenkins, PingFederate.
Right: Post-authentication execution
- Apache Kafka, Apache Solr, Elasticsearch.
- Gerrit, Spinnaker, plus samples on Struts and Spring Boot.
Caption: Evidence grade: Reported [5]
Notes: These are lab demonstrations against products in default configurations, not a claim that specific deployments were breached.

## STATUS | Patch available is not patch deployed
- The fix shipped 17 November 2026 via the Oracle CPU and an OpenJDK advisory, with distributions following.
- CISA Vulnrichment assigns an SSVC decision of exploitation none, automatable no, technical impact total.
- The flaw is not in the CISA KEV catalog as of 18 November 2026, and no in-the-wild use is reported.
- NVD had published the record but still listed it as undergoing analysis, so enriched fields may change.
Caption: Evidence grade: Confirmed [1][2][3][4][8]; Reported [5]
Notes: Patch availability, patch deployment and exploitation status are kept as distinct records.

## BALANCE | What raises and lowers exploitability
Left: Pulls toward caution
- Hardware precondition and high attack complexity.
- No universal exploit; each target needs a bespoke profile.
- Exploitation is sensitive to network timing.
Right: Pulls toward urgency
- Unauthenticated reach and an easy trigger.
- Base64 is decoded during ordinary auth and file upload.
- Demonstrated pre-authentication results on popular products.
Caption: Evidence grade: Inferred from [1][5]
Notes: The honest reading holds both: not a point-and-shoot worm today, and not a theoretical curiosity.

## FIND IT | Decide exposure, then apply the fix
- Exposure needs two things at once: an affected runtime and an x86-64 CPU with AVX-512 VBMI under it.
- Inventory every Java runtime, including copies bundled in third-party apps, container images and appliances.
- Record the host CPU for each; treat ARM64 or older x86-64 as out of scope for this specific flaw.
- Apply the vendor and distribution updates, prioritizing internet-facing systems that decode untrusted input.
Caption: Evidence grade: Confirmed [1][4]; Reported [5]
Notes: The most repeated defender instruction is to find the Java runtimes you did not know you were running.

## MITIGATE | If you cannot patch yet
- Start the JVM with the flag that disables the hardware Base64 routine (-XX:-UseBASE64Intrinsics).
- Or disable AVX-512 on x86-64 hosts with -XX:UseAVX=2, which other architectures reject.
- Validate and size-limit Base64 at the application boundary and limit unauthenticated access, as CISA advises.
- Record any such control as temporary, with an owner and a removal date tied to patching.
Caption: Evidence grade: Reported [5]; Confirmed [4]
Notes: Watch for unexpected JVM crashes and unfamiliar Java processes as cheap signals while patching proceeds.

## DISCOVERY | How the flaw was found
Stat: ~1 hour | Time to find the bug, per the finders
Stat: 2 hours | More time to a first working exploit
Stat: <$200 | Token cost the finders claim
- The finders, Calif, describe an AI-assisted workflow with a human setting direction.
- These are the finders' own figures, offered in a disclosure that also markets their method.
- The durable lesson stands: auditing mature runtime internals is getting cheaper.
Caption: Evidence grade: Reported [5][10]; Inferred
Notes: The figures are worth reporting and are not treated as audited.

## TAKEAWAY | Overstated and understated
- The nickname flatters the flaw: Log4Shell was trivially and universally exploitable and used at scale in days.
- Java4Shell needs affected hardware, a bespoke per-target exploit and favorable network conditions.
- The opposite error reads "difficult" and "not in KEV" as not my problem, which the pre-auth demos undercut.
- Rank this flaw by exposure and the CVSS vector, not by the headline number.
Caption: Evidence grade: Inferred from [1][4][5][8]
Notes: A runtime flaw is a supply-chain problem in slow motion, with patching responsibility scattered across every product that bundled it.
