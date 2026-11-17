# DNS over HTTPS: Encrypting the Lookup Without Eliminating Resolver Trust

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and platform engineers, browser and endpoint administrators, privacy engineers and enterprise resolver owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 10 min (2,246 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of RFC 8484 and the 2020 to 2021 browser rollouts, you need to separate transport confidentiality from resolver trust, or you are deciding an enterprise DNS policy

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [5. Privacy on the wire is not privacy from the resolver](#_5-privacy-on-the-wire-is-not-privacy-from-the-resolver), [9. Enterprise guidance framed the problem as resolver control](#_9-enterprise-guidance-framed-the-problem-as-resolver-control)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Browser Security Reference](/BROWSER_SECURITY_REFERENCE.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment
RFC 8484, published in October 2018, standardized DNS queries and responses carried in HTTPS exchanges. Its primary scope was the connection between a DNS client and a recursive resolver. It changed how that traffic travelled; it did not make the resolver unable to read the question. [1]

The advance addressed an important privacy weakness while making resolver selection and deployment policy more visible. Browser vendors did not all select the same default model. Enterprises also had reasons to distinguish encrypted access to an approved resolver from applications silently selecting an external one.

This focused historical draft follows the 2018 specification through selected 2020 browser announcements and 2021 operational guidance. It separates transport confidentiality, resolver trust, DNS data validation and the visibility retained by network observers. It is not a live test of any browser, resolver or network.

## 1. Evidence and chronology
The core sources are RFC 8484, RFC 9076, dated Mozilla and Google announcements, and NSA's January 2021 enterprise guidance. Current provider documentation supplies explicitly labeled implementation examples. It is not used to claim that every feature existed in 2018.

The direct Chromium technical article and monthly archive returned rate-limit errors. Google's separate May 19, 2020 product announcement was retrieved and supports the Chrome deployment comparison below. The earlier RFC 7626 endpoint also failed; RFC 9076, which replaced it in July 2021, was retrieved. Selected relevant sections were read, not every linked paper.

Three milestones must remain distinct: a protocol was published, a browser announced a rollout, and a particular client actually used an encrypted resolver. Only the first two are established here. No packet captures, population-level measurements or independent resolver audits were performed.

## 2. What the protocol standardized
RFC 8484 maps a DNS query-response pair to an HTTP exchange. It supports GET and POST and defines the binary application/dns-message representation. Resolver endpoint configuration is outside the protocol's discovery scope: the client uses a configured URI template rather than treating arbitrary unsolicited endpoints as trusted resolvers. [1]

The important architectural change is that DNS becomes an application carried over the HTTPS infrastructure. This can make deployment easier for clients that already have HTTP facilities. It also imports HTTP behavior into DNS handling.

This is not equivalent to changing the DNS namespace or abolishing recursion. A name still has to be resolved, caching still matters, and the server's answer can still be wrong or governed by policy. Encrypting the channel does not make the application semantics disappear.

A useful way to read the specification is therefore as a transport mapping with security consequences, rather than as a guarantee about everything done with a name after the request arrives.

## 3. Wire format and provider APIs are different layers
Google Public DNS documentation distinguishes its RFC 8484 API from a separate JSON API. The former supports GET and POST; the JSON interface uses GET. In the standards-based POST case, the body carries a binary DNS message. The documentation also warns that an HTTP success can contain a DNS failure, so callers must inspect the DNS response code. [2]

That distinction matters in monitoring. A dashboard counting HTTP 200 responses as successful name resolution can miss a resolver returning a valid DNS message that reports failure. Conversely, an HTTP error may indicate an API or transport problem rather than a negative DNS answer.

The same source recommends minimizing unnecessary HTTP headers because they can reveal client characteristics. [2] This exposes a design tension: reusing a rich application protocol gives implementers useful infrastructure, but also presents metadata that a simple DNS-message model might not lead them to inventory.

The study does not assume that every JSON DNS endpoint is an RFC 8484 service. Product documentation and negotiated media types belong in an interoperability assessment.

## 4. HTTP integration creates additional state
The specification relates HTTP cache freshness to DNS time-to-live values and requires a client to account for a response's HTTP Age when calculating remaining DNS lifetime. [1]

The analytical consequence is that freshness has to survive translation between two caching systems. A DNS response does not become permanently valid because it arrived through authenticated HTTPS. Reusing a stale answer can be an application correctness problem even when the encryption worked perfectly.

There is a related distinction between caching and privacy. Reuse can reduce traffic and latency; state retained to enable that reuse may also create linkage. A design review should identify which component caches the response, which party can inspect that cache, and which expiry rules are actually enforced.

This draft does not benchmark GET against POST or claim that one choice is always faster. It identifies the interoperability issue without replacing measurement with a slogan about HTTPS performance.

## 5. Privacy on the wire is not privacy from the resolver
RFC 9076 separates risks in network traffic from risks at servers. It notes that encrypted DNS can still expose information through traffic sizes, timing and connection characteristics. Recursive resolvers remain in a position to observe queries, and application-specific resolver selection can alter privacy differently depending on the network context. [3]

These are not reasons to dismiss encryption. They describe its boundary. Removing a nearby observer's access to plaintext DNS questions is a real improvement, even though the resolver still needs the plaintext question to answer it.

The trust decision becomes more explicit: which resolver receives the query, what it records, how long records remain, and who can obtain them? Those questions cannot be answered from the presence of a TLS session alone.

DoH is therefore not a VPN and not a guarantee of anonymous browsing. Destination connections and other metadata remain outside the narrow claim that the DNS payload is protected on its path to the selected resolver. A security description should name the protected path instead of promising that every observer loses every useful signal.

## 6. Firefox's US rollout selected a resolver policy
Mozilla's February 25, 2020 announcement said it was beginning a by-default rollout for US-based Firefox users, continuing over several weeks. It identified Cloudflare as the default provider in the described configuration and offered NextDNS as an alternative. It did not announce a simultaneous worldwide default rollout. [4]

Mozilla's accompanying policy explanation connected the deployment to its Trusted Recursive Resolver program. It described contractual requirements limiting retention and data use by participating resolvers. [5]

The protocol and that program perform different functions. HTTPS protects communication with a resolver. A provider agreement constrains what the organization may do after receiving the query. Neither should be presented as a substitute for the other.

This also explains why a browser choosing an external provider can be controversial even when the cryptography is sound. The change may reduce visibility for one party and increase reliance on another. Evaluating it requires the prior resolver arrangement, the new provider's practices and the user's expectations, not only a comparison between encrypted and unencrypted packets.

## 7. Chrome described an upgrade of the existing provider
Google's May 19, 2020 product announcement described Secure DNS as automatically upgrading to DoH when the user's current provider supported it. It also described options to select another provider or disable the feature. The announcement said desktop changes would arrive over subsequent weeks. [6]

That approach differs from the Firefox US announcement's stated default-provider model. Both use DoH, but they answer the resolver-selection question differently. It would be inaccurate to say that all browser DoH deployments inherently send every query to one new company.

The comparison is limited to what those dated announcements say. It is not a claim that current defaults, eligibility checks or enterprise policies are unchanged. Browser behavior can vary by platform, region and management state.

For a case study, this distinction is more revealing than a generic list of encrypted-DNS benefits. The protocol enabled several deployment choices rather than dictating one universal resolver governance model.

## 8. Canada's staged rollout showed regional variation
On July 8, 2021, Mozilla announced a planned Canadian rollout with CIRA, beginning at one percent and expanding gradually. The announcement identified CIRA's participation in the Trusted Recursive Resolver program and described alternative providers. [7]

This shows that the deployment was not simply one global switch. Region, provider partnership and rollout stage mattered. A planned progression to full coverage is not proof that every eligible client was already enrolled on the publication date.

The announcement also repeated the importance of operating rules for data handling. This reinforces the division between protocol standardization and service governance: the former supplies interoperable transport; the latter determines the obligations of the chosen operator.

The source establishes the plan and partner, not an independent audit of retention behavior. A historical report should not turn a vendor's stated policy requirements into a verified measurement of all provider practices.

## 9. Enterprise guidance framed the problem as resolver control
NSA's January 2021 guidance supported encrypted DNS through a designated enterprise resolver, whether operated internally or provided by an external service. It warned that uncontrolled external resolution could bypass protective DNS functions and expose internal names. Its preferred architecture retained the enterprise's selected resolver while adding encryption. [8]

This is more specific than “enterprises should block encryption.” The recommendation was about preserving a managed resolution path. The guidance also discussed a temporary tradeoff when an existing protective resolver could not yet support encrypted access. That historical tradeoff is not an instruction here to weaken a current system.

An organization may depend on DNS for internal service discovery and malicious-domain controls. A browser's independent resolver can create a different view of names from the operating system's view. The resulting failure might appear as an unavailable application even though both resolvers are functioning according to their own configuration.

The case suggests a concrete inventory: identify which applications choose resolvers themselves, which names require internal answers, and where policy enforcement occurs. These are analytical recommendations, not claims that a named enterprise experienced an outage.

## 10. DNSSEC and DoH answer different questions
Microsoft's later implementation documentation explicitly distinguishes DNS encryption from DNSSEC. It describes DoH as protection for traffic on the wire and DNSSEC as cryptographic validation of DNS data. The documentation also warns, in its specific Windows Server implementation context, that upstream communication is not automatically encrypted merely because the client-facing service supports DoH. [9]

This later example is included to clarify a persistent architectural limit, not to date the implementation to 2018. A protected first leg does not prove an encrypted path through every upstream resolver and authoritative server.

Similarly, an authenticated connection to a resolver proves which service the client reached under its certificate-validation assumptions. It is not the same assurance as validating the provenance of a signed DNS answer. The technologies can complement each other.

Neither assures that the website ultimately reached is benevolent. DNS transport integrity is one part of a larger navigation and application-security problem.

## 11. Port sharing is not invisibility
Cloudflare's current documentation describes DoH on HTTPS's usual port 443 and explains that it can be difficult to distinguish from other HTTPS traffic. It also lists support across HTTP versions. [10]

Difficult to distinguish does not mean undetectable. Endpoint identity, connection metadata and client configuration can remain observable. This study does not test a classifier or claim a measured evasion rate.

The same ambiguity can be useful for privacy and challenging for network administration. A casual observer loses an easy plaintext DNS channel; an organization relying only on that channel may need a different monitoring architecture. Those consequences should be evaluated together, without assuming that either privacy or governance automatically resolves every other concern.

No tunneling, exfiltration or control-bypass procedure is included here. The purpose is to explain the trust boundary and operational implications of a standard.

## 12. Conclusion and unfinished depth
DoH made encrypted DNS accessible through widely implemented HTTPS facilities. Its publication did not select a universal resolver, remove the resolver's visibility, authenticate every DNS answer or encrypt all later network traffic.

The strongest historical finding is the diversity of deployment choices: browser-selected trusted providers, upgrades of existing providers, regional partnerships and managed enterprise resolvers. Those choices determine much of the practical privacy outcome.

This focused draft does not provide a full caching interoperability test, browser source-code audit or measurement study. A deeper follow-up would need those artifacts before making claims about latency, fallback frequency or real-world leakage. The present package remains an unpublished, source-based historical study awaiting editorial review.

## Sources and reading scope

[1] Hoffman and McManus, RFC 8484, October 2018. Selected server-selection, request, caching and privacy sections. https://www.rfc-editor.org/rfc/rfc8484.html

[2] Google Public DNS, DNS-over-HTTPS documentation, updated September 2024; later implementation context. Selected API, error and header guidance. https://developers.google.com/speed/public-dns/docs/doh

[3] Wicinski, RFC 9076, July 2021. Selected encrypted-transport and resolver-privacy sections. https://www.rfc-editor.org/rfc/rfc9076.html

[4] Mozilla, US rollout announcement, 25 February 2020. Region, staging and provider choices. https://blog.mozilla.org/blogarchive/blog/2020/02/25/firefox-continues-push-to-bring-dns-over-https-by-default-for-us-users/

[5] Mozilla, The Facts: Mozilla's DNS over HTTPS, 25 February 2020. Resolver program and contractual policy rationale. https://blog.mozilla.org/netpolicy/2020/02/25/the-facts-mozillas-dns-over-https-doh/

[6] Google, More intuitive privacy and security controls in Chrome, 19 May 2020. Secure DNS section; existing-provider upgrade model. https://blog.google/products-and-platforms/products/chrome/more-intuitive-privacy-and-security-controls-chrome/

[7] Mozilla, Canadian rollout announcement, 8 July 2021. CIRA partnership and planned staged deployment. https://blog.mozilla.org/en/mozilla/firefox-by-default-dns-over-https-rollout-in-canada/

[8] NSA, Adopting Encrypted DNS in Enterprise Environments, January 2021. Selected executive summary and governance recommendations. https://media.defense.gov/2021/Jan/14/2002564889/-1/-1/0/CSI_ADOPTING_ENCRYPTED_DNS_U_OO_102904_21.PDF

[9] Microsoft Learn, DNS encryption using DNS over HTTPS, updated June 2026. Later implementation and DNSSEC distinction, not historical rollout evidence. https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-encryption-dns-over-https

[10] Cloudflare, DNS over HTTPS documentation, updated May 2026. Later transport-description context, not original deployment evidence. https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
