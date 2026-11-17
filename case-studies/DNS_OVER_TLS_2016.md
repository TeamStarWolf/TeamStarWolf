# DNS over TLS: Authentication, Fallback and the Cost of Keeping DNS Private

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [DNS over HTTPS: Encrypting the Lookup Without Eliminating Resolver Trust](/case-studies/DNS_OVER_HTTPS_2018.md), [Network Protocols Reference](/NETWORK_PROTOCOLS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and platform engineers, resolver and endpoint administrators, and privacy engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 10 min (2,341 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a focused, evidence-bounded account of RFC 7858 and DoT deployment, you need to separate attempted encryption from authenticated encryption, or you are deciding a resolver and fallback policy

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Authentication changed the meaning of success](#_3-authentication-changed-the-meaning-of-success), [10. The 2021 privacy assessment retained resolver trust](#_10-the-2021-privacy-assessment-retained-resolver-trust)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [DNS over HTTPS: Encrypting the Lookup Without Eliminating Resolver Trust](/case-studies/DNS_OVER_HTTPS_2018.md), [Network Protocols Reference](/NETWORK_PROTOCOLS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment
DNS over TLS (DoT) illustrates why adding encryption is not the same as defining a complete privacy service. The transport specification arrived in May 2016. Usage profiles were refined in March 2018. Operating-system support and public-resolver announcements then translated the protocol into choices about authentication, availability and provider trust. [1][2][4][5]

The central distinction is between attempting encryption and requiring an authenticated encrypted connection. A product can support DoT without guaranteeing that every lookup is protected. Conversely, a strict client can preserve its confidentiality requirement by refusing to resolve a name when the required secure service is unavailable. That refusal is not necessarily an implementation failure; it may be the intended security outcome.

This focused historical study examines selected standards and vendor evidence rather than presenting an exhaustive implementation audit. It covers the 2016 foundation, 2018 authentication and Android developments, Google's 2019 launch, subsequent operational guidance and a clearly separated 2022 transport evolution. It does not claim to measure today's global deployment or recommend changing a particular user's DNS configuration.

## 1. The 2016 protocol boundary
RFC 7858 focused on the path from a stub resolver to a recursive resolver. Its default service uses TCP port 853 and starts with a TLS handshake. Cleartext DNS is prohibited on that designated TLS connection, including after handshake failure. An earlier draft's upgrade approach, analogous to STARTTLS, was removed. The published design instead distinguished encrypted service by its dedicated port. [1]

Inside the protected connection, DNS messages retain a two-byte length prefix. Multiple requests can be pipelined; replies can arrive out of order and must be associated with the correct request. These details matter because a stream of encrypted bytes does not itself define DNS message boundaries or response matching. [1]

The practical reading is narrower than "DNS became encrypted in 2016." A standard described an interoperable service. Clients, servers, configuration and reachable network paths still had to make that service usable. A publication date is neither an installation count nor proof that a device's resolver used the new protocol.

## 2. TCP was not merely an emergency fallback
March 2016's RFC 7766 clarified DNS over TCP before the DoT specification appeared. It allowed clients to select TCP without first trying UDP and recommended reusing existing connections. Connection reuse spreads setup cost across multiple queries rather than paying for a fresh connection on every lookup. Pipelining permits another request while an earlier one is outstanding. An in-flight message identifier cannot be reused on the same connection. [3]

The document also treated persistent connections as an operational responsibility. Long idle timeouts and limited connection capacity could exhaust server resources. A design therefore needed to balance reuse against resource consumption, not simply keep every connection open indefinitely. [3]

For performance analysis, this creates several different experiments: a cold connection, a warm connection, multiple concurrent requests and a reconnect after interruption. Comparing an encrypted cold lookup with a warm unencrypted lookup would mix transport security with connection-state differences. That is an analytical caution derived from the architecture, not a benchmark produced for this study.

## 3. Authentication changed the meaning of success
RFC 8310, published in March 2018, updated RFC 7858 with Strict Privacy and Opportunistic Privacy profiles. Strict Privacy requires encryption and successful server authentication; it fails if that cannot be achieved. Opportunistic Privacy can produce an authenticated encrypted connection, an unauthenticated encrypted connection or cleartext, depending on available information and client behavior. A strict query must not silently fall back to the opportunistic profile. [2]

The document also identifies a bootstrap problem: the client may need an address for the server whose identity it intends to authenticate. Knowing where to connect and knowing whom to trust are separate inputs. An initial address lookup does not remove the need to validate the intended server. [2]

Consider a conceptual test, not an observed incident: the designated resolver is reachable, but its certificate is unacceptable. Counting only successful name resolutions would reward a client that silently abandoned authentication. A useful evaluation must record whether the requested security property survived, not merely whether an address was returned. The same reasoning explains why availability and privacy cannot always be collapsed into one pass/fail metric.

## 4. Android made the distinction user-visible
Google's April 17, 2018 security-blog cross-post described DoT in the Android P Developer Preview. The default behavior attempted an upgrade when the network's DNS server supported the protocol. A user could instead specify a private provider hostname; failure to reach that secure provider could cause the network to be marked as lacking internet access. [4]

The announcement explicitly distinguished applications using system resolution from applications issuing their own queries. System support was not a guarantee that independently implemented application DNS would follow the same path. Google exposed an API through which applications could inspect whether Private DNS was active. [4]

This is a developer-preview announcement, not evidence that every Android device shipped with the feature on that date. It is also a useful example of why an operating-system settings screenshot alone cannot prove complete traffic coverage. The settings describe one resolver path; applications can introduce additional paths. A rigorous device assessment would trace those paths separately. No such device assessment was performed here.

## 5. Google's January 2019 service announcement
On January 9, 2019, Google announced DoT support for Google Public DNS. The company identified TLS 1.3, TCP Fast Open, pipelining and out-of-order responses as implementation features intended to reduce overhead. The post also identified Android 9 users and the Stubby resolver as potential clients. [5]

This evidence connects a published protocol to a named deployed service. It does not establish that Google invented encrypted DNS or that its implementation was universally fastest. The post is a provider's account of its own service, not an independent comparative study.

The distinction between transport support and resolver selection remains important. Supporting a protocol does not mandate one provider. The study uses Google's dated announcement because it gives concrete implementation detail, not because a brand name substitutes for evaluating authentication, service behavior or data handling. A deployment history should identify the evidence it actually has: a launch statement, specified features and named client compatibility, rather than an inferred market-wide outcome.

## 6. A later service document records a privacy-relevant change
Google's DoT documentation explains that strict mode can fail rather than continue insecurely and that opportunistic behavior can fall back to ordinary DNS. It also warns that the service can close long-idle or heavily used connections, after which clients must establish a new connection. These are documented service behaviors, not measurements in this study. [6]

More unusually, the page records that EDNS Client Subnet (ECS), disabled at launch, was re-enabled for DoT on June 27, 2019. That dated note shows why a secure transport's privacy analysis cannot stop at the TLS handshake. The document is a later-maintained source reporting the historical change, not a preserved launch-day snapshot. [6]

A before-and-after comparison would therefore need to separate the unchanged encrypted client connection from a changed resolver feature. Treating both dates as a single timeless "private DNS" configuration would erase a consequential service distinction. The source supports the change itself; it does not supply this study with a quantified measurement of affected users or information exposure.

## 7. What Client Subnet adds to the picture
RFC 7871, an Informational document published in May 2016, describes ECS as carrying origin-network information so authoritative servers can tailor responses and indicate the scope in which a response can be cached. Its introduction explains the motivation: a centralized recursive resolver may be topologically distant from the client, making the resolver's own address a poor location signal. [7]

The RFC also acknowledges privacy shortcomings and recommends that nameserver software leave the feature disabled by default unless operators explicitly enable it for a clear benefit. This is not a requirement that every encrypted DNS service universally disable ECS. [7]

The important architectural separation is between the transport's protection of a connection and the application's deliberate disclosure of information. Encrypting a message in transit does not decide what information its recipient later forwards. That is why the 2019 service note belongs in a DoT case study even though ECS is not itself a TLS mechanism. The privacy boundary includes resolver behavior after decryption.

## 8. Padding addresses a different residual signal
October 2018's Experimental RFC 8467 discusses policies for the EDNS padding option. Padding increases message sizes to make size-based correlation harder. The document distinguishes the existence of a padding mechanism from the choice of how much padding to add. Its introduction makes clear that padding serves this purpose in combination with encrypted transport. [8]

This study retrieved the introduction and status information, but subsequent attempts to retrieve detailed policy sections returned access errors. It therefore does not prescribe specific block sizes or claim a complete evaluation of the recommended strategy.

The conceptual lesson is still useful. Hiding the literal question and reducing information in observable message lengths are different objectives. A padding option is not proof that an implementation enables it, uses the same policy as another implementation or defeats every traffic-analysis technique. Those would require implementation inspection or experiments. No packet captures or inference-accuracy tests were produced for this draft.

## 9. The 2020 operational guidance widened the responsibility
RFC 8932's October 2020 recommendations address DNS privacy service operators rather than just the wire protocol. Its certificate-management discussion recommends automated issuance and renewal, expiration monitoring and recognizable authentication names. It notes that certificate problems can make service unavailable and that managing pinned keys creates operational overhead. [9]

The document also distinguishes encrypted transport from DNSSEC validation. An authenticated connection to a resolver does not independently prove to a nonvalidating client that the resolver genuinely validated the DNS data. Its discussion of TLS proxies identifies another boundary: a protected client-facing connection can terminate before an unencrypted proxy-to-server path. [9]

These are specific reasons not to use "TLS enabled" as a completion criterion. The implementation may have a valid front-end certificate while an internal segment remains exposed, or it may carry an assertion of validation without the client independently checking it. Neither observation means encryption is useless. Each identifies where a claim must stop unless additional evidence supports it.

## 10. The 2021 privacy assessment retained resolver trust
RFC 9076, published in July 2021, examines residual risks beyond the immediate transport. It describes correlation through encrypted traffic size and timing, the information visible to recursive resolvers and privacy consequences of resolver selection. It also explains that application-specific DNS settings can diverge from system defaults. [10]

For DoT, the document notes that blocking port 853 can restrict access to encrypted resolution. It does not conclude that every such restriction has the same privacy effect; network context and available resolver policies matter. [10]

A useful assessment consequently separates three observations: what the local network can observe, what the chosen resolver receives and what later DNS participants receive. This study does not merge those observers into a single attacker or promise anonymity. Reducing one observer's access can be valuable even when another participant must still process the query. The relevant question is whether the resulting trust relationship matches the user's intended policy.

## 11. A clearly separate 2022 development
On July 19, 2022, Google described adding DNS over HTTP/3 to Android. The announcement said qualifying Android 11-and-later devices could upgrade transport for supported well-known providers while retaining the selected DNS service. This was later than the original 2016-2021 research focus and is included only as a follow-up. [11]

Google discussed reconnection costs, mobile network changes and head-of-line blocking in implementations as motivations. Its limited-rollout measurements concerned successful queries and reported improvements for its tested conditions. This draft does not reuse those percentages as a universal DoT-versus-DoH performance ranking. [11]

The historical significance is that deploying DoT did not end transport engineering. A later implementation could retain the privacy goal while changing how queries were carried. Nor should an implementation-specific processing limitation be rewritten as a rule that DoT forbids out-of-order responses: the earlier TCP and service evidence explicitly describes such responses. Protocol capability and implementation behavior require separate treatment.

## Conclusion and remaining research
DoT's advance was specific and substantial: it established a standardized encrypted DNS transport and helped make authenticated resolver access a practical system feature. Its history also made fallback behavior a central part of the privacy promise. A successful lookup, an encrypted connection and an authenticated provider are related but different observations.

This shorter draft remains depth-limited. It does not reconstruct all working-group deliberations, audit source code, inventory providers, test certificate failures or measure connection reuse. Selected primary passages support its chronology and distinctions. Future expansion should add reproducible, authorized client/server observations and independent deployment measurements rather than more generic security advice. The strongest next evidence would show what a named implementation actually does under a documented failure condition while keeping protocol requirements separate from product behavior.

## Source register
[1] IETF, RFC 7858, May 2016, specification and selected session-management passages. https://www.rfc-editor.org/rfc/rfc7858.html

[2] IETF, RFC 8310, March 2018, usage profiles, query fallback and bootstrap sections. https://www.rfc-editor.org/rfc/rfc8310.html

[3] IETF, RFC 7766, March 2016, TCP selection, connection reuse and pipelining. https://www.rfc-editor.org/rfc/rfc7766.html

[4] Google Security Blog, Android P Developer Preview cross-post, April 17, 2018. Original Android-blog retrieval failed; this official cross-post was retrieved. https://security.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html

[5] Google Security Blog, Google Public DNS DoT announcement, January 9, 2019. https://security.googleblog.com/2019/01/google-public-dns-now-supports-dns-over.html

[6] Google Public DNS, DoT documentation, accessed November 16, 2026; later-maintained document with June 27, 2019 ECS note. https://developers.google.com/speed/public-dns/docs/dns-over-tls/

[7] IETF, RFC 7871, May 2016, introduction and privacy note; Informational. https://www.rfc-editor.org/rfc/rfc7871.html

[8] IETF, RFC 8467, October 2018; Experimental. Introduction/status retrieved; detailed policy retrieval attempts failed. https://www.rfc-editor.org/rfc/rfc8467.html

[9] IETF, RFC 8932, October 2020, selected operator, certificate, DNSSEC and proxy guidance. https://www.rfc-editor.org/rfc/rfc8932.html

[10] IETF, RFC 9076, July 2021, selected network/resolver privacy sections. https://www.rfc-editor.org/rfc/rfc9076.html

[11] Google Security Blog, DNS-over-HTTP/3 in Android, July 19, 2022; later follow-up, not 2016 launch evidence. https://security.googleblog.com/2022/07/dns-over-http3-in-android.html
