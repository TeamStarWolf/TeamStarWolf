# Slide plan: Let's Encrypt and ACME: An Operable Default, Not a Promise

- Study: case-studies/LETS_ENCRYPT_ACME_2014_2021.md
- Cover title: Let's Encrypt and ACME / 2014-2021 / An operable HTTPS default
- Subtitle: Automated domain-validated issuance made HTTPS an operable default; a certificate proves control of a domain name, not the site's safety.
- Published: 18 November 2026
- Notes: Reference study of a CA and a protocol; what automated issuance provides and what it does not.

## EXECUTIVE SUMMARY | What the system provides, and what it does not

- Free, automated, renewable domain-validated certificates and the ACME protocol made HTTPS an operable default.
- A certificate proves control of a domain name, not the honesty or safety of the site behind it.
- The advancement was a combination: free issuance, automation, client work, hosting integration and trust distribution.
- Adoption needs several lenses: cumulative certificates, active certificates, names, hosted sites and connections.
Caption: Evidence grade: advancement case study, not an intrusion report.
Notes: Combination claim and multi-lens adoption from [1][8][21][22][29].

## KEY FACTS | A staged launch, not a single launch day

Stat: 2014 | Initiative announced by EFF and ISRG
Stat: Jun 2015 | Root and intermediate keys generated
Stat: Dec 2015 | Public beta opened, invitation removed
Stat: Mar 2018 | ACME v2 in production before the RFC
- IdenTrust cross-signatures were announced October 2015, a bridge into existing browser trust.
- RFC 8555 standardized ACME in March 2019, after the v2 endpoint was already live.
- Treating any one date as the whole launch obscures the work of turning a certificate into a usable connection.
Caption: Evidence grade: dated project records and the ACME RFC.
Notes: Dates from [1][2][6][7][14][15]; "live" is not "widely trusted" per [5].

## PART 1 | The unit of change was a repeatable deployment process

- A certificate purchase was one transaction in a larger process of control, issuance, installation and renewal.
- Removing a fee alone would not eliminate those transitions; a certificate left in a download directory protects no one.
- EFF's 2014 announcement named cost, complexity and administrative friction as the barriers to HTTPS.
- The announcement is evidence of design intent, not an independently measured result.
Caption: Evidence grade: the 2014 announcement read as design intent.
Notes: Barriers and intent from [1]; deployment as the unit of change is the study's reading.

## PART 1 | Four names that must stay separate

- ISRG is the nonprofit organization that operates the service.
- Let's Encrypt is the certificate-authority service itself.
- ACME is the protocol used to request and manage certificates; Certbot is one EFF client, not the CA.
- Each boundary changes who can repair a problem; a client packaging issue is not a CA outage.
Caption: Evidence grade: project records of the 2016 client transition.
Notes: Name separation and the Certbot transition from [10]; the boundaries are the study's framing.

## PART 2 | Building a CA differed from the first certificate

- The June 2015 ceremony generated root and intermediate keys, with the root kept offline, but not universal trust.
- A June schedule targeted the first certificate and general availability; an August update moved both dates.
- The September 14, 2015 first certificate worked only for clients already holding ISRG's root.
- Cross-signing in October 2015 bridged into deployed trust while ISRG pursued its own root distribution.
Caption: Evidence grade: operator-reported architecture and dated schedules.
Notes: Ceremony, schedules, first certificate and cross-sign from [2][3][4][5][6].

## PART 3 | What the automation actually automated

- RFC 8555 defines an exchange: an account requests an order, satisfies authorizations, submits a CSR and retrieves the certificate.
- The client need not run on the machine that ultimately consumes the certificate.
- Several kinds of authority coexist; an account request does not by itself prove control of every name.
- An inventory saying only "uses Let's Encrypt" leaves several distinct responsibilities unidentified.
Caption: Evidence grade: the ACME standard, RFC 8555.
Notes: Protocol structure and authority boundaries from [9]; the inventory point is analysis.

## PART 3 | Domain control is not a character reference

- Domain validation proves control of a name; it does not judge website content or an operator's real-world identity.
- An encrypted connection to a fraudulent website remains an encrypted connection to a fraudulent website.
- A valid certificate on a phishing site is expected behavior, not a failure of the CA.
- Planned Safe Browsing checks ended January 10, 2019; the domain-validated claim was always narrow.
Caption: Evidence grade: project position paper, with later update noted.
Notes: Validation-versus-content distinction and the 2019 change from [11].

## PART 3 | Short lifetimes made renewal part of the product

- Ninety-day certificates limited the damage window from compromise or misissuance and encouraged automation.
- The November 2015 rationale recommended renewal every sixty days, with room for manual action early on.
- The renewal workflow became central, not optional; a design that worked only once was inadequate.
- Waiting for expiry is not the same as responding to a known problem under a shorter deadline.
Caption: Evidence grade: historical policy and rationale, not current offerings.
Notes: Lifetime rationale and renewal cadence from [12]; the expiry-versus-emergency point is echoed at [23].

## PART 4 | Protocol evolution exposed assumptions

- ACME v2 reached production in March 2018 with wildcard support, before RFC 8555 was final; v1 clients would not work.
- TLS-SNI-01 could permit unauthorized issuance on hosting that accepted arbitrary uploaded certificates.
- Multi-perspective validation, launched February 2020, targeted network-path manipulation, not hosting ambiguity.
- Syntactically correct messages are insufficient when a deployment assigns an action a different meaning.
Caption: Evidence grade: dated project announcements and incident accounts.
Notes: ACME v2, TLS-SNI and multi-perspective from [14][16][18]; standardization at [15].

## MEASUREMENT | The denominator changes the claim

These measures answer different questions and cannot substitute for one another.

| Quantity | What it cannot establish alone |
|---|---|
| Cumulative issued certificates | Unique active sites or newly encrypted organizations |
| Currently valid certificates | Whether each certificate is installed and serving traffic |
| Domain names | A one-to-one count of businesses, servers or users |
| Hosted websites reported by an operator | An independently audited global population |
| Browser page loads or handshakes | All browsers, applications or Internet traffic |
Caption: Evidence grade: provider milestones and original CCS 2019 research.
Notes: Ledger condensed from section 5; counts from [21][22][29].

## INCIDENT 2020 | CAA recheck: renewal did not settle recovery

Stat: 3,048,289 | Currently valid affected certificates
Stat: 8 hrs | Window to recheck CAA before issuing
Stat: 1,711,396 | Revoked by the March 5 deadline
Stat: 1,336,893 | Still remaining at that deadline
- The defect was a recheck of CAA restrictions, not fabricated domain authorizations.
- The detailed report placed production activation on August 23, 2019 and counted the surviving population.
- Mozilla granted no exemption; the operator's disruption rationale was not permission to miss the deadline.
- "Affected certificate" is not "attacker certificate"; the record does not show adversary use of every one.
Caption: Evidence grade: public incident reports and a Mozilla bug record.
Notes: Figures and chronology from [23][24][25]; counts are the cited populations only.

## TRANSITION 2021 | A fresh certificate could meet an old trust problem

Left: What changed
- A December 2020 cross-sign of ISRG Root X1 extended Android compatibility past DST Root CA X3's expiry.
- The production chain change went live in May 2021, months before the September 30, 2021 expiry.
Right: What it did not fix
- Holding ISRG Root X1 did not make the longer default chain work under an OpenSSL 1.0.x path bug.
- A root-store inventory was useful evidence, not a complete model of connection success.
Caption: Evidence grade: project announcements and retrospective expiry guidance.
Notes: Android bridge, staged dates and the OpenSSL path issue from [26][27][28].

## CROSS-CUTTING THEMES | Three incidents, three different questions

Each episode failed or adapted a different stage, so another episode's repair did not transfer.

| Episode | Question that failed or adapted |
|---|---|
| TLS-SNI, shared hosting | Did the action really establish control of the name? |
| CAA rechecking | Was the policy check performed for the correct identifiers? |
| 2021 chain transition | Could this client build a path to its trust anchor? |
Caption: Evidence grade: original analysis grounded in the preceding records.
Notes: Comparison condensed from section 8.2; sources [16][23][27][28].

## CLOSE | Easier to deploy was never every site is safe

- Let's Encrypt and ACME turned certificate management into infrastructure that could be integrated and repeated at scale.
- The benefit and the dependency coexist: hosted automation spares manual renewal while concentrating reliance on a provider.
- Say which observation "the certificate worked" names: issued, loaded, path accepted or request completed.
- Open limits: no causal share of HTTPS growth, no universal compatibility, no proof that any site's content is safe.
Caption: Evidence grade: case conclusions, outcome claims bounded.
Notes: Synthesis across sections 8 and 9; rests on [1][29] and the incident records.
