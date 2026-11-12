# Slide plan: The eMudhra Certificate Authority Key Compromise: A 2026 Case Study

- Study: case-studies/EMUDHRA_CA_COMPROMISE_2026.md
- Cover title: The eMudhra Certificate Authority / Key Compromise / A 2026 Case Study
- Subtitle: Eight CA keys anyone could compute, a browser fix in hours, and a client tail into 2027
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/EMUDHRA_CA_COMPROMISE_2026.md. First published 2 November 2026 and revised 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Eight trusted CA keys were small enough to guess

- In October 2026 a researcher found that eight eMudhra (emSign) intermediate CA keys could be computed from public certificates.
- Each P-384 private key was an integer below 256; Mozilla says local AI agents recovered them on a first try.
- Chrome blocked them 100 minutes after the report, Firefox within three hours, and eMudhra revoked them the next morning.
- Go, pip, macOS command-line tools, Java, appliances and embedded web views fixed on their own schedules.
- No vendor confirmed malicious use through 10 November 2026; eMudhra is leaving the public TLS business.
Caption: Evidence grade: Confirmed for the weakness, the response and the root cause; Demonstrated for public key recovery.
Notes: Weakness and AI agents [1]. Response times [3][2][1]. Client tail [31][30][21][35][28]. No confirmed misuse [30][31][24]. Exit [16].

## KEY FACTS | Sixteen certificates, one live CA, no leaves

Stat: 8 | CA keys anyone could compute
Stat: 256 | Upper bound on each private key's value
Stat: 100 min | From report to Chrome's CRLSet block
Stat: 18 mo | The weak keys sat in published certificates
- Six TLS CAs and two code-signing CAs, each in one eMudhra and one Sectigo cross-certificate.
- None of the eight issued an end-entity certificate, per eMudhra; one TLS CA had been live.
- Revoked 18 October 2026, reason cACompromise; Sectigo cross-certificates revoked 19 October.
Notes: Scope [1] comments 0, 2, 6, 10. Key values below 256 [1] comment 5. CRLSet [3]. Ceremony 30 April 2025 to report 17 October 2026 [1]. Revocation [1][18].

## PART 1 | A script, not the algorithm, made the keys weak

- One ceremony on 30 April 2025 made 16 subordinate keys correctly on Utimaco HSMs.
- A custom wrap and unwrap script moved them for Crypto4A HSMs and re-created weak ECDSA key objects in host memory.
- No key-strength check and no comparison of the certified key with the original.
- Near-identical object labels let the wrong object sign the certificate request.
- A June 2025 CRL signature anomaly was fixed only at the symptom level.
Caption: eMudhra states its HSMs worked correctly; CERT-In stresses the weakness was in key generation, not P-384.
Notes: eMudhra's Full Incident Report, comment 82 of [1]. Earlier accounts differ [1] comment 11, [15], [14]. CRL bug [9]. CERT-In [34].

## PART 2 | Three roots, one cross-signed back door

| Root | What happens |
|---|---|
| emSign ECC Root CA - G3 | Removed from NSS 20 Oct, Chrome 27 Oct; blocked by Apple |
| AAA Certificate Services | Sectigo cross-signs still verify through it on Microsoft and Apple |
| emSign Root CA - G1 (RSA) | Chrome and Mozilla cut off certificates first logged after 16 Nov 2026 |
| Remaining 10 eMudhra roots | Microsoft removes them from 16 Nov 2026 |
Caption: Removing G3 alone does not stop the six cross-signed TLS certificates; Apple blocks twelve intermediate certificates.
Notes: Roots [7][3][28][24]. Cross-certificates [1] comments 6 and 13, [28]. G1 cutoff [3][8]. Microsoft's counts [24]. Which root signed what differs by source; see the study's discrepancies list.

## PART 3 | The browsers moved in hours

| Time (UTC) | Event |
|---|---|
| 17 Oct 18:05 | Report with signed proof reaches the root programs |
| 17 Oct 19:45 | Chrome CRLSet blocks the intermediates' keys |
| 17 Oct 22:59 | Firefox OneCRL push complete |
| 18 Oct 09:24 | eMudhra revokes all eight |
| 20 Oct | NSS 3.131.1 and Firefox 158.0.1; Windows disallowed list |
| 21 Oct | Go CVE-2026-111943; Red Hat RHSB-2026-012 |
| 27 Oct | Chrome Root Store removal reaches devices |
| 10 Nov | eMudhra's Full Incident Report |
Notes: Report [1][4]. CRLSet [3]. OneCRL [2]. Revocation [1] comment 10. NSS and Firefox [2]. Windows [24]. Go [20][21]. Red Hat [70]. Chrome removal [3]. Report posted [1] comment 82.

## PART 4 | Forged certificates came after disclosure, not before

Left: What happened
- A public post forged a google.com subdomain certificate on 20 October, 12:15 UTC.
- Cloudflare saw a forged certificate dated 18:19 UTC, under an hour after the bug went public.
- About 22,000 handshakes in a week, mostly tests and self-issued origin certificates.
Right: What no one found
- No CT entries before Chrome's block, so no covert use against CT-enforcing browsers.
- No vendor confirmed malicious interception through 10 November.
- Use before disclosure against clients that skip CT and revocation cannot be ruled out.
Caption: Every handshake Cloudflare set to verify the certificate was refused.
Notes: Demonstration [37]. Cloudflare [30][29]. CT [3]. Vendor statements [34][32][31][33][24][36]. The pre-disclosure window is Inferred from [1][4].

## PART 5 | The checks that should have caught it never looked

- Standard linters (pkimetal, badkeys, zlint, pkilint) did not test for small EC private scalars.
- Google's weak-key scanner saw only CT-logged certificates; the dormant intermediates had none.
- The keys passed CCADB disclosure, a Sectigo cross-signature and audit cycles.
- Chrome added weak-key checks and proposed gating CCADB disclosure on them.
- HARICA agreed to draft CA/Browser Forum ballot text on minimum ECDSA scalar checks.
Caption: The full report came on 10 November, after the 14-day CCADB window from 18 October.
Notes: Chrome Root Program review, comment 50 of [1]. CA/B Forum minutes [40]. CCADB guidelines [47]. Audit and A series gap [10].

## PART 6 | The first distrust caused by keys that were weak from the start

| Year | CA | Trigger |
|---|---|---|
| 2011 | DigiNotar | Intrusion and rogue certificates |
| 2016 | WoSign and StartCom | Backdating and a concealed acquisition |
| 2017 | Symantec | Issuance without oversight |
| 2022 | TrustCor | Ownership and integrity concerns |
| 2024 | Entrust | Six years of compliance failures |
| 2026 | eMudhra | Weak key generation and handling |
Caption: The response reused every tool the lineage built: key blocklists, CT evidence, root removal and the Entrust-style SCT cutoff.
Notes: DigiNotar [53][54][55]. WoSign and StartCom [58][59]. Symantec [57][60]. TrustCor [61][62]. Entrust [63][64]. eMudhra [1][40]. The lineage reading is Inferred.

## PART 7 | The event has no CVE of its own

- CVE-2026-111943 is Go's crypto/x509 denylist record (CWE-299); it does not name eMudhra.
- Red Hat's RHSB-2026-012 groups it with CVE-2026-114406, CVE-2026-91403 and CVE-2026-113812.
- Red Hat says plainly it is not a software vulnerability: the ids carry trust-store updates.
- Mozilla's CVE-2026-113470 covers Firefox's bundled OneCRL list; CVE-2026-111944 does not exist.
- Windows, Apple, Python, Cisco and Splunk fixes ship under their own advisories.
Caption: A program that keys work on CVE ids sees only part of the fix (Inferred).
Notes: Go [20][21]. AWS usage [18]. Red Hat [70][72]. Oracle [71][75]. CPANSec [73]. Mozilla [74]. Qualys and the missing id [23][22].

## PART 7 | The client path is where the exposure lived

Stat: >50% | Probes from large networks still accepting the chain about two weeks in
Stat: 30-40% | Embedded browsers still accepting it
Stat: 2027 | Latest Cisco fix target dates
- pip trusts its vendored certifi bundle whatever the operating system says.
- macOS curl, git and python3 read /etc/ssl/cert.pem until 27.2.1, 26.7.3 and 15.8.3.
- Go binaries need a rebuild; containers keep the bundle they were built with.
Notes: Cloudflare probes [30]. Cisco [31]. pip [35]. macOS [28]. Go [21]. Containers [35][70]. Talos list of independent stores [32].

## DEFENDER VIEW | Find every trust store, then prove the chain is refused

Left: Fix
- Go 1.26.10 or 1.27.3; pip 26.2.2 and certifi 2026.10.19 in every environment.
- macOS 27.2.1, 26.7.3 or 15.8.3 for command-line tools.
- RHEL ca-certificates and Java updates; rebuild images with the cache off.
Right: Verify
- Block the intermediates by key, on every path, including the cross-signs.
- Keep Windows automatic trust updates on; feed disconnected devices.
- Test from each client path that the compromised chain fails.
Caption: A version number is not proof; a refused connection is.
Notes: Go [21]. Python [35]. Apple [28]. Red Hat [70]. Oracle [71]. Blocking [28][6]. Windows [26][24]. Verify by rejection [34].

## DEFENDER VIEW | Detection has a boundary

- Watch CT for certificates chaining to the eight or to G3, for example through crt.sh.
- Talos published Snort SIDs 67363 to 67374.
- Enforce strict CRL and OCSP checking on proxies and gateways.
- CT shows tests and careless use, not an unlogged certificate served to a client that never checks.
- CAA does not bind someone who holds a CA key; short-lived leaves do not shorten a stolen CA key.
Caption: CERT-In: CT supplements revocation and trust-store controls; it does not replace them.
Notes: CT monitoring [36][34]. Snort [32]. Proxies [36]. The CT and CAA limits are Inferred from [4][36].

## MITRE MAPPINGS | Seven techniques, none observed as adversary use

| Id | Technique | Tie to eMudhra |
|---|---|---|
| T1588.004 | Digital Certificates | Keys recovered by researchers |
| T1649 | Steal or Forge Authentication Certificates | Forged certificates after disclosure |
| T1557 | Adversary-in-the-Middle | Capability, not observed |
| T1588.003 | Code Signing Certificates | Two code-signing CAs |
| T1553.002 | Code Signing | Capability, not observed |
Caption: ATT&CK v20.0; also T1587.003 and T1608.003 in form only. CWE-299, CWE-295; CAPEC-485 and CAPEC-112 by reading. No group or software.
Notes: Techniques [65][67] with [1][37][30][3][2][34][24]. CWE [20][72][73][69]. D3FEND [68]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Trust is federated, and so is remediation

- **Key handling is attack surface.** Moving key material outside an HSM needs a strength check.
- **Scanners see what is logged.** Trusted but idle CAs fell outside the one pipeline that would have caught them.
- **Small anomalies are signals.** A CRL that did not verify in 2025 was the defect showing itself.
- **CT worked inside its boundary.** It protected browsers and said nothing about other clients.
- **Recovery is cheap now.** AI agents recovered the keys from a simple prompt.
Notes: Key handling [1][34]. Scanners [1] comment 50. CRL [9][1]. CT [3][4]. AI agents [1]. The lessons are Inferred.
