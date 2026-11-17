# Retiring TLS 1.0 and 1.1: A Protocol Standard Was Not a Universal Shutdown Switch

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [TLS 1.3 in 2018: A Security Standard Meets Real Deployment](/case-studies/TLS_1_3_2018.md), [Network Protocols Reference](/NETWORK_PROTOCOLS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and platform engineers, TLS and browser administrators, and compliance owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 9 min (2,135 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of the TLS 1.0/1.1 deprecation, you need to separate a standards decision from universal removal or disablement from removal, or you are planning a protocol migration

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. The 2018 browser announcements used measured adoption](#_4-the-2018-browser-announcements-used-measured-adoption), [8. What the 2021 standard required](#_8-what-the-2021-standard-required)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [TLS 1.3 in 2018: A Security Standard Meets Real Deployment](/case-studies/TLS_1_3_2018.md), [Network Protocols Reference](/NETWORK_PROTOCOLS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment
RFC 8996, published in March 2021, formally deprecated TLS 1.0 and TLS 1.1, along with DTLS 1.0. It strengthened the earlier best-practice prohibition on negotiating the old versions and prohibited fallback to them. There is no DTLS 1.1. The document was a standards decision, not evidence that every deployed service stopped accepting old connections that month. [1]

This case follows the gap between protocol evolution, browser plans and actual product changes. The record is especially instructive because several vendors announced coordinated retirement plans in 2018, then revised schedules or distinguished disablement from removal. A timeline that compresses all of these into "TLS 1.0 ended in 2021" misstates both the technology and the operational history.

This is a focused historical draft, not a live configuration assessment. It does not claim that a particular present-day system is compliant or that every TLS 1.2 configuration is secure.

## 1. Evidence and scope
The central evidence is RFC 8996 and the dated vendor record. Technical history comes from NIST SP 800-52 Revision 2. The later RFC 9325 is used to show how best-practice guidance evolved after 2021, not to retroactively rewrite the earlier announcements.

The research reviewed selected sections and relevant release-note entries. It did not read every reference transitively, replay attack demonstrations or test a server. Google's 2018 announcement was located, but direct retrieval was blocked; this study does not rely on its detailed schedule. Apple's and Mozilla's original statements, Mozilla's updated rollout account, Firefox release notes and Microsoft's amended notice were available.

A primary source can contain several dates with different meanings. Microsoft's 2020 post now includes a 2022 update above its original plan. Both are evidence, but the newer text changes how the earlier promise should be interpreted. A historical narrative should not extract the first attractive date and ignore the amendment.

## 2. TLS 1.1 improved TLS 1.0 without solving every limitation
NIST's technical history identifies two important TLS 1.1 changes: explicit initialization vectors for CBC operation and revised padding-error treatment. The specification addressed timing sensitivity by requiring consistent record processing regardless of padding errors. TLS 1.2 then expanded hash-function choices and introduced authenticated-encryption cipher suites. TLS 1.3 redesigned the handshake and key derivation while removing several older cryptographic constructions. [2]

The distinction matters because "old TLS" is not one identical protocol. TLS 1.1 was a security improvement over TLS 1.0. Deprecating it later does not mean that improvement was imaginary. It means an intermediate design ceased to be the appropriate minimum after stronger successors became available.

Nor is protocol age itself an exploit. The technical question concerns what a version can express, which cryptographic choices it requires or permits, and whether supported implementations can maintain those choices safely. An administrator cannot make every old protocol feature modern merely by selecting a newer certificate.

A certificate signature, a handshake signature, the record-protection algorithm and the negotiated version are different parts of a connection. A migration review that inspects only one can miss the dependency elsewhere.

## 3. The precedent was not a single continuous SSL version
RFC 7568, published in June 2015, had already prohibited SSL 3.0 and fallback to it. Its abstract described the protocol as insufficiently secure and identified newer TLS versions as substantially more capable. [3]

That earlier action should remain distinct from the 2021 TLS decision. "SSL" often survives as a colloquial name in product interfaces, but a label is not reliable evidence of the negotiated protocol. Conversely, modern branding is not proof that an old compatibility path has disappeared.

For this case, the important continuity is institutional: standards bodies can retire a protocol while deployed software still needs an operational change. The important discontinuity is technical: each retirement has its own affected version, rationale and replacement conditions. Grouping SSL 3.0, TLS 1.0 and TLS 1.1 under one undated vulnerability obscures that evidence.

## 4. The 2018 browser announcements used measured adoption
On October 15, 2018, Apple's Secure Transports team published a WebKit notice planning Safari removal beginning in March 2020. It reported TLS 1.2 on 99.6 percent of Safari TLS connections and combined legacy TLS 1.0/1.1 usage below 0.36 percent. Those figures described Safari connection telemetry, not a census of all Internet services. [4]

Mozilla announced the same target month that day. It said its telemetry placed TLS 1.1 at only 0.1 percent of connections. It also explained that the announcement was being made far in advance because upgrading TLS could take time. Mozilla did not frame the decision as a newly discovered emergency requiring immediate action on that date. [5]

The measurements helped establish readiness within each vendor's observed population. They did not show that the remaining clients were unimportant. A tiny share of connections can still include a critical internal device, a low-volume administrative service or a user population with limited upgrade options.

The analytical lesson is to retain the denominator. Connection share, site support, installed software and affected people answer different questions. This study does not combine the vendors' percentages into a synthetic worldwide adoption figure.

## 5. Firefox's temporary reversal was documented
Mozilla's February 2020 post later acquired two decisive updates. A March 23 update said TLS 1.0 and 1.1 had been re-enabled in Firefox 74 and 75 Beta to improve access to important information. A June 24 update said disablement would proceed in Firefox 78, scheduled for June 30. [6]

Firefox 78's release notes separately confirm that TLS 1.0 and 1.1 were disabled and that sites without TLS 1.2 would display an error page. [7]

That sequence prevents two misleading claims. First, the original March target cannot be reported as an uninterrupted completed rollout. Second, the temporary reversal did not erase the retirement decision. The records show a change in timing followed by a release-specific action.

A useful chronology therefore distinguishes announcement, deployment, reversal and renewed deployment. Those states can coexist in one document, particularly when a vendor updates a blog post instead of publishing a fresh article for every change. Reading only the headline would miss the most important operational evidence.

## 6. Microsoft's amended notice separated browser families
Microsoft's March 31, 2020 notice postponed its planned change in light of global circumstances. A later update on the same page stated that Chromium-based Edge disabled the versions by default beginning with version 84, and that the policy allowing their enablement was removed beginning with version 91. [8]

The August 2022 amendment gave September 20, 2022 as the default-disablement date for Internet Explorer and EdgeHTML. It explicitly distinguished disabling by default from removing support. The original 2020 text retained earlier dates below the update. [8]

Those statements are not interchangeable. Chromium Edge, EdgeHTML and the operating system's wider TLS facilities are different scopes. A browser change does not establish that every program using Windows networking behaves identically.

This case does not recommend restoring old protocols. The significance of the vendor's override language is historical: it shows that default state, administrator policy and implementation capability can differ. A report should say which one it has verified.

## 7. Apple's platform notice had a different scope from Safari
Apple's September 21, 2021 developer notice marked TLS 1.0 and 1.1 deprecated on iOS 15, iPadOS 15, macOS 12, watchOS 8 and tvOS 15, with removal in future releases. It directed applications still using the versions to transition and said applications with App Transport Security enabled on all connections required no changes for that notice. [9]

This is a platform-development announcement, not proof of one common switch being thrown across all Apple clients in 2020. It should be read alongside, not substituted for, the earlier Safari plan.

The source also illustrates why the word "deprecated" needs a definition. In a standards document it can describe a protocol's status and normative prohibition. In an API notice it can identify discouraged interfaces scheduled for future removal. In a release note it may accompany an actual default change. The reader needs the concrete behavior, not just the label.

## 8. What the 2021 standard required
RFC 8996 moved the old protocol specifications to Historic status. Its negotiation rules prohibit TLS 1.0 and 1.1. It also preserves a subtle compatibility distinction: a legacy-looking record-layer version on an initial ClientHello is not itself permission to negotiate an old protocol. [1]

That distinction is useful when interpreting packet captures. A field value used for compatibility cannot be treated, by itself, as the final connection's negotiated security version. A scanner or analyst should identify the handshake outcome rather than classify a session from an isolated byte pattern.

The standard acknowledges interoperability failure with peers that cannot support newer versions. This is an explicit cost of retirement, not an accidental omission from the guidance. [1]

A failed connection after raising the minimum version can therefore be evidence that the change is working. It still needs investigation: the responsible dependency might be an old client, a server configuration, a terminating proxy or an embedded TLS library. The symptom alone does not identify which component must be replaced.

## 9. Later guidance did not declare TLS 1.2 universally obsolete
RFC 9325, published in November 2022, replaced RFC 7525. Its version guidance prohibits TLS 1.0 and 1.1, requires TLS 1.2 support, and recommends TLS 1.3 support with preference for it when implemented. It explicitly warns that prematurely abandoning TLS 1.2 can introduce interoperability costs. It separately sets stronger requirements for new transport protocols that integrate TLS. [10]

This later source prevents a common overcorrection: the retirement of 1.0 and 1.1 does not automatically mean every connection must use 1.3 or be considered insecure. Configuration and application context still matter.

The distinction also avoids collapsing support into selection. An implementation may support more than one acceptable version while preferring the newer one. A policy can forbid an old minimum without asserting that only one version may exist in all contexts.

This section records the 2022 document's guidance. It is not a substitute for checking later updates, product documentation and the requirements of a particular deployment before making a change.

## 10. A case-specific migration review
The documented rollout history suggests a concrete evidence standard for evaluating a migration. Record the client and server versions, the TLS library or platform involved, where TLS terminates, and the observed negotiated version. Separate browser behavior from background integrations and machine-to-machine clients.

Measure unsuccessful handshakes as well as successful modern traffic. Successful traffic alone omits clients that cannot connect at all. Where a service is business-critical, identify its owner and supported upgrade path before removing compatibility.

These are analytical recommendations derived from the scope differences in the vendor record, not claims that any named organization performed a particular inventory. The historical evidence does not justify silently weakening a configuration when a client fails. A temporary exception, if an organization chooses one, should have explicit ownership and an end condition rather than becoming the unrecorded permanent state.

The lasting work is dependency removal. Changing a browser default can expose a dependency; it cannot upgrade the remote system automatically.

## 11. Conclusion and remaining research
TLS 1.0 and 1.1 retirement was a sequence of technical advances, advance notices, revised rollouts and formal standards action. March 2021 is the RFC milestone, not a universal deployment completion date.

The primary sources support precise statements about particular products and versions. They do not establish a worldwide count of exposed systems, a single outage total or one common removal date. This study intentionally avoids those unsupported measures.

Further work could compare archived release artifacts and vendor policy histories, or examine a named environment's negotiated traffic under authorization. Neither has been performed here. The package is a source-based historical study, not a compliance certificate or a completed live audit.

## Sources and reading scope

[1] Moriarty and Farrell, RFC 8996, March 2021. Selected introduction, negotiation rules and operational considerations. https://www.rfc-editor.org/rfc/rfc8996.html

[2] NIST SP 800-52 Revision 2, August 2019. Section 1.1 technical history; selected passages, not full implementation assessment. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf

[3] Barnes et al., RFC 7568, June 2015. Abstract and prohibition context. https://www.rfc-editor.org/rfc/rfc7568.html

[4] Apple Secure Transports team, WebKit, 15 October 2018. Safari plan and connection telemetry. https://webkit.org/blog/8462/deprecation-of-legacy-tls-1-0-and-1-1-versions/

[5] Mozilla, Removing Old Versions of TLS, 15 October 2018. Original plan and telemetry limits. https://blog.mozilla.org/security/2018/10/15/removing-old-versions-of-tls/

[6] Mozilla Hacks, It's the Boot for TLS 1.0 and TLS 1.1, 6 February 2020, March23 and June24 updates. Reversal and resumed rollout. https://hacks.mozilla.org/2020/02/its-the-boot-for-tls-1-0-and-tls-1-1/

[7] Firefox 78 release notes. Selected TLS entry confirming disablement. https://www.mozilla.org/en-US/firefox/78.0/releasenotes/

[8] Microsoft Edge Blog, Plan for change, 31 March 2020, amended 10 August 2022. Product-specific defaults and revised dates. https://blogs.windows.com/msedgedev/2020/03/31/tls-1-0-tls-1-1-schedule-update-edge-ie11/

[9] Apple Developer, TLS 1.0 and 1.1 deprecation update, 21 September 2021. Platform/API scope. https://developer.apple.com/news/?id=bv8ur34d

[10] Sheffer et al., RFC 9325, November 2022. Selected version-negotiation guidance; later context. https://www.rfc-editor.org/rfc/rfc9325.html
