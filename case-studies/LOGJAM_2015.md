# Logjam: Export Cryptography, Shared Primes and Imperfect Forward Secrecy

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [FREAK 2015](/case-studies/FREAK_2015.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

TLS and cryptography engineers, security architects, incident responders and standards followers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,304 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of Logjam, you need to separate a demonstrated 512-bit attack from the 1024-bit feasibility estimate or a vulnerability from a breach, or you are reviewing Diffie-Hellman group strength and forward secrecy

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. The demonstrated TLS downgrade](#_4-the-demonstrated-tls-downgrade), [6. The 1024-bit question: inference, not attribution](#_6-the-1024-bit-question-inference-not-attribution)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [FREAK 2015](/case-studies/FREAK_2015.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Logjam exposed two weaknesses in how finite-field Diffie-Hellman key exchange was deployed. ([Executive assessment](#executive-assessment))
- Researchers demonstrated an active downgrade against TLS connections that still allowed export-grade cryptography. ([Executive assessment](#executive-assessment))
- The argument about 1024-bit groups and national intelligence was a feasibility assessment, not a public demonstration. ([Executive assessment](#executive-assessment))
- It challenged an oversimplified forward secrecy: ephemeral secrets help only when the underlying key exchange stays computationally hard. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Historical vulnerability and ecosystem-response study, not a claim that a particular criminal intrusion occurred. The central disclosure was in 2015; the standards response examined here extends into 2016-2017.

## Executive assessment

Logjam exposed two related but different weaknesses in the way finite-field Diffie-Hellman key exchange was deployed. First, researchers demonstrated an active downgrade against vulnerable TLS connections that still allowed export-grade cryptography. Second, they showed why reuse of a small number of widely deployed primes could concentrate the value of expensive cryptanalytic preparation. The first was a concrete attack against 512-bit groups. The wider argument about 1024-bit groups and national intelligence capabilities was a feasibility assessment, not a public demonstration of breaking those groups or proof of a particular intelligence operation. Keeping those claims separate is fundamental to an accurate account. [1-2]

The public disclosure on May 20, 2015 prompted a response at several layers: server operators were told to remove export suites and strengthen groups; client libraries raised their minimum accepted Diffie-Hellman size; browsers and operating systems shipped dependent changes; later standards made strong finite-field group negotiation more explicit. Those changes were not interchangeable. A client rejecting tiny groups could stop the export downgrade even where an administrator had not yet removed export support. A server disabling export support could still use an inadequately sized normal group. An application upgraded at one layer could still depend on another component with older behavior. [3-8]

This was also a challenge to an oversimplified promise of forward secrecy. Ephemeral secrets protect against the later loss of a server's long-term authentication key only when the underlying key exchange remains computationally hard. They do not make a weak mathematical group strong. Logjam's most durable contribution was to connect that cryptographic distinction with measurements of actual Internet deployments, common software defaults, and a difficult compatibility-driven remediation process. [2-3]

## 1. What the sources can establish

The principal technical evidence is the original research team's website and peer-reviewed paper, *Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice*. The website separates the May public announcement from the October 13, 2015 paper publication. Its measurements represent historical observations from the research period, not a current scan and not a census of successful compromises. The paper documents the demonstrated computation and explains the larger estimates. Vendor advisories establish what particular software projects said they changed, while RFCs establish later protocol guidance. [1-8]

These sources do not supply a global list of victims whose traffic was decrypted, a verified financial-loss total, or an attribution finding against a named criminal group. Public disclosure of a technique cannot establish that all vulnerable hosts were exploited. Likewise, a vendor acknowledging a vulnerability does not certify the researchers' hypotheses about intelligence operations. This study therefore distinguishes demonstrated mechanics, measured exposure, vendor response, and conditional strategic inference rather than treating them as one incident narrative.

No exposed personal data, attack scripts, packet-manipulation procedure, or live target testing is included. The discussion describes the security failure and the defensive response at a level suitable for architectural review and historical education.

## 2. Why export-grade cryptography survived

The immediate TLS weakness depended on a legacy compatibility feature: export-grade cipher suites that restricted cryptographic strength. Such suites remained available in real server configurations long after the policy environment that motivated them had ceased to justify their use. Their presence was not merely a harmless option for ancient clients. The researchers showed that a connection involving a modern client could be pushed onto the weaker server behavior under the required active-interception conditions. [1-3]

This is why a statement such as "our normal cipher is strong" was insufficient. A server could have respectable parameters for its regular DHE configuration while also retaining an export path with much smaller parameters. A vulnerable client could accept the resulting weak group in circumstances where it believed it was using a normal suite. The security boundary was the behavior of the whole negotiation, not the administrator's preferred cipher at the top of a configuration list. [2-3]

OpenSSL explicitly compared the lesson with FREAK, another export-cryptography failure disclosed earlier in 2015, but the two should not be conflated. FREAK concerned export RSA; Logjam concerned finite-field Diffie-Hellman and a different negotiation failure. A system's status for one was not sufficient evidence of its status for the other. The common institutional lesson was narrower: retaining deliberately weakened modes could create unexpected paths around otherwise stronger defaults. [1,3]

## 3. The mathematics that made reuse matter

Finite-field Diffie-Hellman uses public group parameters and private contributions to establish a shared secret. Different sessions may use fresh private exponents while sharing the same public prime. Sharing a prime is not equivalent to reusing a session secret. Nevertheless, the best-known cryptanalytic method relevant to this research divided work into a costly preparation tied to that prime and a smaller computation tied to an individual target value. [2]

The researchers described the number field sieve process in terms of stages. Several expensive stages depend on the group prime; the final individual-logarithm work concerns a particular exchange. Consequently, the cost of preparation can be spread across many sessions and many servers when they use the same prime. That is an economic amplification mechanism. The attacker does not need to repeat the entire expensive preparation for every intercepted connection. [2]

For a common 512-bit group, the paper reports roughly a week of precomputation followed by individual logarithms on the order of a minute. Those figures describe the researchers' measured setup, not a timeless promise about every machine, group, or session. The important result was that export-size Diffie-Hellman could be brought into a range compatible with practical connection attacks after preparation. It was not simply an abstract warning that 512 bits looked small. [2]

The paper's observation that one group was used by 82% of vulnerable servers illustrates why a common default changed the return on that preparation. Its discussion of two groups covering more than 92% of vulnerable servers is another population-specific statement. Neither percentage means that 82% or 92% of all Internet services were compromised. The denominator is the vulnerable deployment subset measured by the researchers. [2]

## 4. The demonstrated TLS downgrade

The active Logjam attack required an adversary positioned to interfere with the connection and a server that supported the relevant export behavior. At a high level, the mismatch let the attacker obtain server-authenticated export-strength Diffie-Hellman parameters while a susceptible client treated the exchange as a stronger negotiation. The distinction between the suite context understood by the endpoints was not adequately protected by the signed parameters alone. [2-3]

This does not mean server certificates stopped working in every respect. The research showed how valid server-authenticated material could still be used in an unsafe negotiation context. Authenticating a parameter set is not enough if the receiver accepts an interpretation that permits parameters far below the intended security level. The failure demonstrates the difference between a valid signature and a securely bound protocol transcript. [2]

The small group then made the session key computationally recoverable under the demonstrated conditions. The research paper discusses the timing challenge of completing that work during a connection and the practical feasibility of the attack. This study does not reproduce the mechanics for manipulating connection timing or protocol messages. For defensive purposes, the decisive properties are the weak accepted group, the surviving export path, and the active intermediary. [2]

A separate possibility discussed by OpenSSL was passive recovery when a connection directly used an already weak group. That does not require the same downgrade setup. It is therefore misleading to summarize all of the research as "export enabled equals passive decryption." Export downgrade and direct use of weak groups are related risk paths with different prerequisites. Removing the former does not automatically establish the strength of the latter. [3]

## 5. Exposure figures and their denominators

The researchers' public site reported initial vulnerability affecting 8.4% of the top one million domains in its HTTPS measurement and 3.4% of browser-trusted sites. These are not competing estimates of the same population. A top-domain set and a browser-trusted set differ, as do the conditions under which a host enters each measurement. Neither is a present-day prevalence estimate. [1]

The site also reported export-DHE exposure in other TLS-using services, including 14.8% for its SMTP STARTTLS IPv4 population, 8.9% for POP3S and 8.4% for IMAPS. Those figures show that the deployment issue extended beyond web browsing. They do not establish the fraction of messages read, accounts accessed, or organizations breached. Exposure measurement is a description of reachable configurations at a time and under a methodology, not an incident-loss count. [1]

The paper's statement that the demonstrated work could compromise connections to 7% of Alexa's top million HTTPS sites must also retain its context. It reflects the groups and attack coverage described in the paper. It should not be substituted mechanically for the website's broader 8.4% vulnerable-server figure. Related studies can report a susceptible population and a narrower population covered by a particular completed computation without contradiction. [1-2]

This distinction matters for case-study graphics. A single pie chart labeled "Internet compromised" would erase both the sample boundary and the difference between capability and observed exploitation. A more accurate presentation uses separate labels for measured export support, demonstrated computational coverage, and hypothetical larger-group capability.

## 6. The 1024-bit question: inference, not attribution

The broader research asked whether a well-resourced adversary could perform the much more expensive preparation for widely reused 1024-bit groups. The paper presents resource estimates and discusses how group concentration could make such an investment strategically valuable. It does not claim to have publicly completed a 1024-bit discrete-logarithm computation. OpenSSL's contemporaneous explanation explicitly characterized the intelligence-agency possibility as speculation. [2-3]

The research site's conditional estimates included the potential reach of common groups across popular HTTPS sites, VPNs and SSH servers. The famous 18%, 66% and 26% figures belong to those respective historical populations and to the hypothesized capability described by the authors. They are not measured percentages of traffic decrypted by the NSA, not totals of known affected people, and not interchangeable with the 512-bit TLS downgrade rates. [1-2]

The authors considered the hypothesis consistent with aspects of publicly discussed intelligence capabilities. Consistency is weaker than proof. Multiple explanations can fit an observed capability when the underlying operational evidence is incomplete. A responsible historical case can explain why the hypothesis attracted attention without converting it into a finding that a specific agency broke a specific group's traffic. [2-3]

The same care applies to 768-bit discussion. The study's feasibility analysis and the subsequent vendor transition thresholds should not be rewritten as a report that every larger size had already been broken in the same demonstration. The demonstrated 512-bit result, the scaling estimates, and the thresholds chosen during remediation answer different questions.

## 7. May-July 2015: a staggered response

On May 20, OpenSSL announced its response strategy. It planned to reject groups below 768 bits immediately in the next release and move to a 1024-bit client floor afterward. That initial limit was a compatibility compromise, not a declaration that 768-bit groups were a strong long-term server choice. The same post recommended at least 2048-bit server parameters for a comfortable margin and acknowledged older clients that could reject larger groups. [3]

The post also distinguished changes already present from those still forthcoming. It stated that export suites were disabled by default in the then-current OpenSSL 1.0.2a and 1.0.1m releases, while the stronger client check was planned for 1.0.2b and 1.0.1n. Default disabling is not synonymous with removal from every explicit configuration or every downstream package. A reader should not collapse the announcement into a claim that all installations became protected on May 20. [3]

The June 11 advisory confirmed the client-side protection rejecting parameters shorter than 768 bits and identified upgrades to OpenSSL 1.0.2b or 1.0.1n for the respective branches. The advisory included several unrelated vulnerabilities as well. Their presence in the same bulletin does not make them alternative names or consequences of Logjam. The relevant Logjam identifier was CVE-2015-4000. [4]

Mozilla's July 2 advisory documented a different implementation boundary: NSS 3.19.1 imposed a minimum of 1023-bit primes. The unusual number should be recorded exactly rather than silently rounded in a patch-history table. The advisory listed Firefox 39, ESR 31.8 and 38.1, and corresponding fixes for other Mozilla-family products. This is evidence of a product-specific acceptance rule and release history, not a universal TLS protocol minimum. [5]

Ubuntu's historical account makes downstream timing especially visible. It says Ubuntu learned of the issue at the May 20 public disclosure. Its timeline records a June 1 OpenSSL update disabling export suites, a June 2 Apache change for Ubuntu 12.04 LTS adding elliptic-curve support, a June 11 OpenSSL minimum of 768 bits, and later NSS and OpenJDK updates. The operating-system response was therefore a sequence across libraries and applications rather than one magical "Logjam patch." [6]

## 8. Compatibility was an operational risk, not an excuse

Stronger acceptance rules could cause previously functioning connections to fail. Ubuntu warned that updated browsers might stop reaching sites with weak parameters. OpenSSL likewise discussed the large installed population using 768-bit groups and older clients with limitations on larger groups. Those statements explain why some vendors introduced transitional floors. They do not justify leaving the weak paths available indefinitely. [3,6]

An organization managing the transition had to determine which endpoint rejected which parameter and which component actually supplied that behavior. An updated browser and an older application linked against a different TLS library could behave differently against the same service. A load balancer might terminate TLS independently of the application server behind it. These are architectural implications of the layered remediation record, not documented descriptions of one named victim's infrastructure.

The historically appropriate control sequence was to eliminate export negotiation, ensure clients rejected undersized groups, and provide sufficiently strong server key exchange with an acceptable compatibility path. Choosing ECDHE could avoid the particular finite-field group problem, but a configuration still needed sound implementation and negotiation. The research team's administrator guidance is useful historical evidence; its old configuration examples should not be pasted into a current production system as if they were a contemporary baseline. [3,9]

## 9. August 2016: negotiating known strong groups

RFC 7919 addressed a related architectural limitation: traditional TLS finite-field Diffie-Hellman exchanges did not provide the same explicit named-group negotiation available in other parts of the ecosystem. It defined named finite-field groups at 2048, 3072, 4096, 6144 and 8192 bits and a way to negotiate supported groups. That response made group selection more explicit and gave implementations well-specified parameters rather than leaving every deployment to an opaque custom choice. [7]

This can appear contradictory beside warnings about shared primes, but it is not. The research objected to the attack economics of groups small enough for feasible or plausibly well-funded precomputation. It did not prove that any shared prime of any size was unsafe. Standardized large groups can improve parameter assurance and interoperability while raising the computational barrier. The relevant questions are group quality, size, negotiation and threat model, not merely whether another server uses the same number. [2,7]

Custom parameters are not automatically superior if they are generated or validated incorrectly. Conversely, a familiar standard name does not excuse ignoring a protocol's negotiation rules. The standards response is best understood as an effort to make strong choices explicit and implementable, not as an assertion that software could stop checking its inputs.

## 10. December 2017: the SSH consequence

RFC 8270 updated the recommended minimum size for SSH Diffie-Hellman group exchange to 2048 bits. It recommended selecting groups in a range from 2048 through 8192 bits and discussed preference for stronger choices where feasible. This is a later standards consequence of the broader concern about finite-field strength, not evidence that SSH used the exact TLS export-downgrade mechanism. [8]

SSH must remain separate in the narrative. The administrator guidance explicitly distinguished SSH from the active TLS export attack while recognizing the concern over common small finite-field groups. The question for SSH was the strength and selection of its own key-exchange groups. A vulnerability story that says "Logjam downgraded all SSH servers to export TLS" would mix protocols and invent a mechanism not established by the sources. [8-9]

The RFC's recommendations also have a defined scope: SSH group exchange. They should not be paraphrased as a complete inventory of every SSH algorithm's status or an instantaneous upgrade of every deployed server. Standards describe expected behavior; deployment evidence is needed to establish adoption.

## 11. Evidence matrix and unresolved questions

Demonstrated: the researchers completed preparation for a common 512-bit group and showed practical individual-logarithm computation and a TLS downgrade under the stated prerequisites. Measured: historical populations of services supported vulnerable configurations and heavily reused certain groups. Documented response: OpenSSL, Mozilla and Ubuntu published concrete changes with dated versions or release steps. Standardized later: stronger named finite-field groups for TLS and an increased SSH group-exchange recommendation. [1-8]

Estimated, not demonstrated here: the feasibility and strategic value of precomputation against widely deployed 1024-bit groups. Suggested, not established: a connection between that capability and particular intelligence operations. Unknown from this record: the number of real users whose sessions were decrypted, an aggregate loss figure, a global remediation-completion date, or a complete inventory of vulnerable services today. [1-3]

A future expansion could add archived vendor release notes across more browser and VPN implementations, with explicit product-version comparisons. It could also compare the original paper's measurement dates and scan populations in greater detail. That work would deepen deployment history, not justify inventing a victim narrative. The available primary record already supports a substantive account of the research and response; it does not support a claimed criminal incident chronology.

## 12. Why this case still belongs in the collection

Logjam is important because it ties a concrete mathematical result to negotiation design, common software defaults, and ecosystem incentives. Its lesson is not simply "use bigger keys." The attack succeeded because weak legacy behavior remained reachable, the protocol context did not prevent unsafe interpretation, accepted parameters were too small, and shared defaults made expensive preparation broadly reusable. Removing only one symptom could leave a different risk path intact.

For case-study authors, the evidence discipline is equally important. A vulnerability is not a breach; a feasibility estimate is not attribution; a measured host population is not a count of harmed people; and a vendor's transitional floor is not its strongest recommended server configuration. Preserving those distinctions makes the account more useful than a dramatic but inaccurate claim that forward secrecy was universally broken.

## Source register

[1] Original research team, Logjam public site, initial disclosure May 20, 2015 and publication notice October 13, 2015. Historical measurements and bounded larger-group hypothesis. https://weakdh.org/

[2] Adrian et al., Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice, CCS 2015. Primary research paper: computation, deployment measurements, protocol analysis and resource estimates. https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf

[3] OpenSSL, Logjam, FREAK and upcoming changes, May 20, 2015. Original response plan, compatibility constraints and explicit distinction between demonstrated results and speculation. https://openssl-library.org/post/2015-05-20-logjam-freak-upcoming-changes/

[4] OpenSSL Security Advisory, June 11, 2015. Historical client minimum and affected release branches; other vulnerabilities in the same bulletin are separate. https://openssl-library.org/news/secadv/20150611.txt

[5] Mozilla Foundation Security Advisory 2015-70, July 2, 2015. NSS 3.19.1 minimum of 1023-bit primes and product fixes. https://www.mozilla.org/en-US/security/advisories/mfsa2015-70/

[6] Ubuntu, LogJam vulnerability response page, published May 21, 2015 with subsequent timeline updates. Downstream patch sequence and compatibility warning. https://ubuntu.com/security/vulnerabilities/logjam

[7] RFC 7919, Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS, August 2016. Named strong finite-field groups and negotiation. https://www.rfc-editor.org/rfc/rfc7919.html

[8] RFC 8270, Increase the Secure Shell Minimum Recommended Diffie-Hellman Modulus Size to 2048 Bits, December 2017. Scope is SSH group exchange, not TLS export downgrade. https://www.rfc-editor.org/rfc/rfc8270.html

[9] Original research team, Guide to Deploying Diffie-Hellman for TLS. Historical remediation guidance, with later edits; not presented as current production configuration. https://weakdh.org/sysadmin.html
