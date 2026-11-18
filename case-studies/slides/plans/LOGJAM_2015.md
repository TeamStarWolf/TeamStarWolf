# Slide plan: Logjam: Export Cryptography, Shared Primes and Imperfect Forward Secrecy

- Study: case-studies/LOGJAM_2015.md
- Cover title: Logjam / Export cryptography and shared primes / Imperfect forward secrecy
- Subtitle: A demonstrated 512-bit TLS downgrade and a 1024-bit feasibility estimate, kept distinct: a vulnerability study, not a breach narrative.
- Published: 15 November 2026
- Notes: Historical vulnerability and ecosystem-response study, not a claim of a specific criminal intrusion.

## EXECUTIVE SUMMARY | Two distinct Diffie-Hellman weaknesses, not one breach

- Researchers demonstrated an active downgrade against TLS links still allowing export-grade cryptography.
- Reuse of a few widely deployed primes concentrated the value of expensive precomputation.
- The 1024-bit and intelligence-agency argument was a feasibility assessment, not a demonstration.
- Ephemeral secrets help only when the underlying key exchange stays computationally hard.
Caption: Evidence grade: a demonstrated 512-bit attack versus a 1024-bit inference.
Notes: Executive assessment separates the concrete 512-bit attack from the 1024-bit estimate and the intelligence inference. [1][2]

## KEY FACTS | Exposure was measured, and bounded by its sampled populations

Stat: 512-bit | Group broken in the demonstration
Stat: ~1 week | Precomputation for the 512-bit group
Stat: ~1 min | Per-connection individual logarithm
Stat: 8.4% | Top-1M HTTPS domains vulnerable
- One prime served 82% of vulnerable servers; two covered more than 92%.
- CVE-2015-4000 identified the Logjam weakness.
- Public disclosure landed 20 May 2015; the paper followed 13 October 2015.
Caption: Evidence grade: measured populations, not compromise counts.
Notes: Figures are historical measurements over sampled populations, not a census of compromise. [1][2]

## PART 1 | Export suites left a path around strong defaults

- Export-grade cipher suites restricted strength and survived long after their policy rationale ended.
- A modern client could be pushed onto weaker server behavior under active interception.
- "Our normal cipher is strong" was insufficient while an export path with tiny parameters remained.
- OpenSSL compared the lesson with FREAK, but the two attacks must not be conflated.
Caption: Evidence grade: a demonstrated mechanism under active interception.
Notes: FREAK was export RSA, Logjam finite-field DH; the shared lesson is that weakened modes create paths. [1][3]

## PART 1 | Shared primes made precomputation reusable

- Finite-field DH can use fresh private exponents while sharing the same public prime.
- The number field sieve splits work into prime-tied preparation and a smaller per-target step.
- Preparation cost spreads across every session and server using the same prime.
- Sharing a prime is not reusing a session secret; it is an economic amplification mechanism.
Caption: Evidence grade: a described cryptanalytic method.
Notes: The 512-bit setup: about a week of precomputation, then per-connection logarithms near a minute. [2]

## PART 2 | A valid signature did not safely bind the transcript

- The attack needed an active intermediary and a server supporting export behavior.
- The attacker obtained server-authenticated export parameters while the client assumed a stronger suite.
- Signed parameters alone did not protect the negotiated suite context.
- The small group then made the session key recoverable under the demonstrated conditions.
Caption: Evidence grade: a demonstrated downgrade, mechanics not reproduced.
Notes: The study omits timing and packet mechanics; the decisive factors are the weak group, export path and active intermediary. [2][3]

## PART 2 | Exposure percentages describe samples, not compromise

Stat: 8.4% | Top-1M HTTPS domains, export-DHE
Stat: 3.4% | Browser-trusted sites
Stat: 14.8% | SMTP STARTTLS IPv4 population
Stat: 7% | Paper's demonstrated HTTPS coverage
- POP3S exposure was 8.9% and IMAPS 8.4%, so the issue reached beyond web browsing.
- The top-domain set and the browser-trusted set are different populations, not rival estimates.
- The paper's 7% reflects completed-computation coverage, not the broader vulnerable-server figure.
Caption: Evidence grade: measured exposure, not incident loss.
Notes: Denominators are measured subsets at a time and methodology, never messages read or accounts breached. [1][2]

## PART 2 | The 1024-bit case was inference, not attribution

- The paper estimated resources for 1024-bit precomputation but completed no public 1024-bit logarithm.
- OpenSSL characterized the intelligence-agency possibility explicitly as speculation.
- The 18%, 66% and 26% reach figures belong to hypothesized capability over historical populations.
- Consistency with known capabilities is weaker than proof; 768-bit was analysis, not a break.
Caption: Evidence grade: estimated and suggested, not demonstrated.
Notes: The HTTPS, VPN and SSH figures are not NSA-decrypted traffic, nor interchangeable with the 512-bit rates. [1][3]

## PART 2 | The response was a staggered sequence, not one patch

| Date | Vendor action |
|---|---|
| 20 May 2015 | OpenSSL plan: reject under 768-bit, 2048-bit advised |
| 11 Jun 2015 | OpenSSL client floor 768-bit (1.0.2b/1.0.1n) |
| 2 Jul 2015 | Mozilla NSS 3.19.1 minimum 1023-bit |
| May to Jun 2015 | Ubuntu sequence: OpenSSL, Apache, NSS |
Caption: Evidence grade: documented, dated vendor changes.
Notes: Default-disabled export is not removal, and the floors were transitional compatibility compromises. [3][4][5][6]

## PART 2 | Standards made strong group choice explicit

- RFC 7919 (Aug 2016) defined named finite-field groups at 2048 to 8192 bits with negotiation.
- Standardized large groups raise the computational barrier and improve interoperability.
- RFC 8270 (Dec 2017) raised the SSH DH group-exchange minimum to 2048 bits.
- SSH shared the finite-field concern but not the TLS export-downgrade mechanism.
Caption: Evidence grade: standardized later guidance.
Notes: A standard name does not excuse ignoring negotiation rules; adoption still needs deployment evidence. [7][8][9]

## DEFENDER VIEW | Fixing one symptom could leave another path intact

Left: Remove weak paths
- Eliminate export negotiation on servers.
- Make clients reject undersized groups.
- Supply strong key exchange, ECDHE where sound.
Right: Verify every layer
- Identify which component enforces each rule.
- Check load balancers terminating TLS alone.
- Treat old config examples as historical, not a baseline.
Caption: Evidence grade: architectural implications, no named victim.
Notes: Downgrade and direct weak-group use are distinct paths; removing one does not prove the other safe. [3][6][9]

## MITRE MAPPINGS | The study declines an ATT&CK mapping by design

| Aspect | Mapping status |
|---|---|
| In-path downgrade | Not mapped: no intrusion claimed |
| Victims or campaign | Not mapped: no breach in the record |
| Technique write-up | Not mapped: mechanics withheld |
Caption: Evidence grade: no ATT&CK mapping asserted by the source.
Notes: The record establishes demonstrated mechanics and response, not a campaign, so no technique IDs are mapped. [1][2][3]

## CROSS-CUTTING THEMES | Overstatement and understatement each distort it

Left: Overstated claims
- "The Internet was compromised" erases sample boundaries.
- "The NSA broke 1024-bit groups" turns inference into fact.
- "Forward secrecy was broken" ignores the weak-group caveat.
Right: Understated risks
- Treating export suites as harmless legacy options.
- Assuming a strong default cipher covered every path.
- Reading a transitional 768-bit floor as a strong target.
Caption: Evidence grade: interpretive discipline from the study.
Notes: A vulnerability is not a breach, and a feasibility estimate is not attribution. [1][2][3]

## CLOSE | Logjam ties math to negotiation and shared defaults

- The attack succeeded because weak legacy behavior stayed reachable and parameters were too small.
- Shared defaults made expensive preparation broadly reusable across servers.
- The lesson is not simply "use bigger keys" but remove the reachable weak paths.
- Keep demonstrated, measured, estimated and suggested claims distinct.
Caption: Evidence grade: a synthesis of the case.
Notes: Preserving the evidence distinctions keeps the account more useful than a dramatic, inaccurate claim. [1][2][3]
