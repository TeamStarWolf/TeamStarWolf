# Slide plan: Certificate Transparency: Public Evidence, Private Trust

- Study: case-studies/CERTIFICATE_TRANSPARENCY_2013_2021.md
- Cover title: Certificate Transparency / 2013-2021 / Detectable, Not Impossible
- Subtitle: CT makes certificate misissuance detectable, not impossible; it adds public evidence after issuance, and detection depends on someone acting.
- Published: 18 November 2026
- Notes: Reference study of a system (RFC 6962 and RFC 9162), not an attack with victims; no certificate was issued, logged or revoked.

## EXECUTIVE SUMMARY | CT adds public evidence, not a guarantee of trust

- CT makes certificate issuance discoverable and log behavior auditable; it does not prevent a CA from misissuing.
- It reveals issuance after the fact; detection still depends on someone monitoring the logs and acting.
- The study keeps RFC status, browser policy and organizational monitoring as separate concepts.
- An unfamiliar certificate can be legitimate infrastructure; surprise is not confirmed misissuance.
Caption: Evidence grade: Reference study of a system, not an attributed incident.
Notes: Executive-assessment framing from [1][2]; roles and limits stated across [1] through [8].

## KEY FACTS | Three claims that must never be merged into one

Stat: 2013 | RFC 6962 published, Experimental
Stat: 2021 | RFC 9162 v2.0, Experimental
Stat: 6 | Chrome log lifecycle states
Stat: 5 | distinct clocks in one investigation
- RFC 9162 obsoletes RFC 6962 in metadata; both remain Experimental, not Internet Standards.
- Apple's policy still requires at least one SCT from a log compliant with RFC 6962.
- Browser policies are a snapshot checked 15 November 2026 and can change independently of the RFCs.
- Standard or policy, enforced by browsers, and universally logged are three different claims.
Caption: Evidence grade: Confirmed RFC status and dated policy snapshots.
Notes: RFC status from [1][2]; platform policies from [5][6]; snapshot date stated by the study.

## PART 1 | CT answers an information asymmetry in the Web PKI

- A domain owner can control its own servers yet lack visibility into certificates issued elsewhere for its names.
- The CT project connects the effort to the 2011 DigiNotar compromise and other certificate-authority failures.
- Public evidence lets researchers, owners and platforms inspect the same artifact and compare findings.
- Visibility alone does not determine intent, authorization or business context.
Caption: Evidence grade: Project history, plus original analysis of the gap.
Notes: Chronology and the DigiNotar link from [3]; the asymmetry framing is original analysis.

## PART 1 | A signed timestamp is a commitment, not a proof

- RFC 6962 describes append-only Merkle-tree logs and Signed Certificate Timestamps, or SCTs.
- An SCT commits the log to include an entry within its Maximum Merge Delay; it is a promise, not fulfillment.
- Inclusion and consistency proofs answer different questions: membership, and that a later tree extends an earlier one.
- Proving an item appears in a log does not establish authorization; an accurate record of a bad issuance is still accurate.
Caption: Evidence grade: Confirmed mechanism, with original evidence-chain analysis.
Notes: Merkle logs, SCTs and MMD from [1]; the commitment-versus-proof reading is original analysis.

## PART 1 | Logs, monitors and user agents do different work

- Logs accept and expose entries; monitors examine the logs they cover and can notify owners of matching certificates.
- User-agent policy helps enforce participation; precertificates obtain logging before the final certificate is delivered.
- Buying a certificate that carries SCTs does not mean someone watches every future issuance for your names.
- Separate the evidence supply chain from the response chain; a delay at any handoff reduces the practical benefit.
Caption: Evidence grade: Confirmed roles, plus original coverage analysis.
Notes: Roles and precertificates from [4]; the supply-chain-versus-response-chain point is original analysis.

## PART 2 | Obsoletes describes documents, not deployed logs

- RFC 9162 changes algorithm agility, log identifiers, artifact structures and APIs, using CMS precertificates and TransItem structures.
- Obsoletes is a document relationship; it does not prove every log switched formats or every browser accepts v2.0.
- It acknowledges that a log showing inconsistent views to different clients can circumvent the described auditing.
- A parser should identify the artifact version and apply version-aware validation, not treat every artifact as a generic timestamp.
Caption: Evidence grade: Confirmed specification; deployment is a separate question.
Notes: v2.0 changes and the split-view limitation from [2]; the deployment caveat is original analysis.

## PART 2 | A count of SCTs is not the same as compliance

- Chrome evaluates SCTs using log state, delivery method, operator diversity and certificate lifetime.
- Its embedded-SCT path uses two logs for lifetimes up to 180 days and three for longer lifetimes.
- Versions before 148 accepted SCTs in stapled OCSP responses under the TLS-delivery criteria.
- Three timestamps from inappropriate logs are not compliant because three exceeds two; these are policy details, not Merkle-tree properties.
Caption: Evidence grade: Dated policy snapshot checked 15 November 2026.
Notes: Policy criteria, the 180-day split and the pre-148 note from [5]; the count caveat is original analysis.

## PART 2 | Acceptance is platform-specific, not universal

- Apple's policy, published 21 April 2025, applies to publicly trusted TLS server-authentication certificates.
- It combines SCT counts, approved-log state, delivery mechanisms and operator limits.
- It requires at least one SCT from a log compliant with RFC 6962, so v2.0 status is not universal replacement.
- Interoperability means testing the clients that matter; a certificate that works in one browser can fail in another.
Caption: Evidence grade: Dated policy snapshot (Apple, 21 April 2025).
Notes: Apple requirements and the RFC 6962 condition from [6]; the client-population point is original analysis.

## PART 2 | A certificate can outlive the trust around it

- Chrome's lifecycle distinguishes Pending, Qualified, Usable, ReadOnly, Retired and Rejected states.
- A newly Qualified log may not yet be recognized across clients; ReadOnly stops new SCTs while the log keeps operating.
- Monitoring should consider more than expiration; an evidence dependency can change while the key and certificate file do not.
- A log-state change is not automatically malicious; record log identity, state, SCT timestamp and validation time.
Caption: Evidence grade: Confirmed lifecycle, plus original monitoring analysis.
Notes: The six states from [7]; the time-dependent-trust reading is original analysis.

## PART 2 | Public logs expose names: a deliberate tradeoff

- Disclosure to CT makes certificate contents, including domain names, publicly accessible.
- A hostname can reveal a project, a business relationship or an intended service before launch.
- Do not put secrets or confidential customer identifiers into certificate names.
- Private PKI has different trust-distribution duties; it is not a universal replacement for public trust.
Caption: Evidence grade: Confirmed guidance, plus original naming precaution.
Notes: Disclosure and enterprise-trust guidance from [8]; the naming precaution is original analysis.

## DEFENDER VIEW | Label every clock before you build a timeline

- One investigation can involve certificate validity, SCT signed time, tree-head time, monitor first-seen and analyst review.
- notBefore is not proof of issuance, deployment or first use; an SCT does not prove a site served the certificate.
- A monitor's first-seen time is a statement about that monitor's observation, not the earliest global appearance.
- Record timezone and clock assumptions; an apparent sequencing contradiction may be clock handling, not fraud.
Caption: Evidence grade: Original analysis grounded in the mechanism.
Notes: The five timestamps and their limits are original analysis building on [1].

## DEFENDER VIEW | Separate surprise from confirmed misissuance

- Preserve the artifact, fingerprint, issuer, names, log identity and the exact SCT or proof being evaluated.
- Begin with the name and business owner; ask whether a provider renewal, migration or test explains the entry.
- Escalate a specific artifact to the certificate authority or provider, not a broad accusation that the issuer is malicious.
- Finding an unauthorized certificate does not prove interception; finding none does not make misissuance acceptable.
Caption: Evidence grade: Original defensive recommendations.
Notes: Evidence packet, triage and escalation guidance are original recommendations in the study.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- An RFC number or a present SCT read as proof of acceptance.
- A browser's numerical threshold treated as an eternal property of CT.
- "Tamper-proof" when the real claim is detectable inconsistency.
Right: Easy to understate
- CT preserves evidence of behavior that should not have happened.
- Detection still needs an owner, an inventory and a response path.
- Public logs carry a real, deliberate privacy tradeoff.
Caption: Evidence grade: Editorial corrections the study requires.
Notes: Overstated and understated contrasts drawn across [1][2][5][8].

## CLOSE | Evidence-driven use beats overstating a timestamp

- CT improves the Web PKI by making important behavior visible and creating evidence that can be checked.
- Its value depends on logs, monitors, certificate authorities, browser programs and domain owners working together.
- Keep Experimental RFC status, log version, browser acceptance and organizational monitoring as separate concepts.
- Identify the artifact, label its timestamp, understand what a proof establishes, and investigate the business context.
Caption: Evidence grade: Case-specific conclusions, bounded to the sources.
Notes: Final-assessment synthesis across [1] through [8].
