# Deepfake & Synthetic-Media Defense

> In one minute: This is the defender's playbook for the synthetic-media threat that went mainstream in 2024-2026: AI voice clones and deepfaked video calls used to impersonate executives and finance officers and trigger fraudulent wire transfers, plus KYC-bypass, fake-interview, and reputation attacks. It leads with *why deepfake detection alone will never be enough* and builds a defense-in-depth model where process controls (dual approval, out-of-band verification, pre-shared passphrases) are the load-bearing layer, backed by content provenance (C2PA / Content Credentials), watermarking, liveness/PAD, and detection tooling with its real limits stated. Use it to answer "a 'CFO' just asked Finance to move money on a video call. How do we make sure that can't work?" For the attacker's tradecraft see [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md); for the fraud kill chain see [FRAUD_FRAMEWORK_REFERENCE.md](FRAUD_FRAMEWORK_REFERENCE.md).

| | |
|---|---|
| Read this when | building controls so an impersonated executive cannot authorize a payment; a suspected voice/video deepfake just hit Finance, the SOC, or a KYC flow; writing a wire-transfer approval policy, an awareness module, or an IR runbook for BEC/vishing; evaluating deepfake-detection or liveness vendors |
| Start at | [Anatomy of the finance-approval scam](#anatomy-of-the-finance-approval-video-call-scam), [Layer 1: Process & policy controls](#layer-1-process--policy-controls-the-strongest-layer), [Deepfake-defense checklist](#deepfake-defense-checklist) |
| Pairs with | [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md), [FRAUD_FRAMEWORK_REFERENCE.md](FRAUD_FRAMEWORK_REFERENCE.md), [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md), [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md), [IDENTITY_SECURITY_REFERENCE.md](IDENTITY_SECURITY_REFERENCE.md), [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md) |

---

## Why this matters: the threat in 2026

Generative voice, face-swap, and full-body avatar models are now cheap, fast, and good enough to fool people in real time. A convincing voice clone can be built from seconds of public audio (earnings calls, conference talks, podcasts), and live video "face-swap" tooling can impersonate a named executive on a Teams/Zoom call.

The defining case is the Arup deepfake CFO scam: in early 2024 a finance employee in the engineering firm's Hong Kong office was talked into 15 transfers totaling ~HK$200 million (~US$25.6 million) after a video call in which the "CFO" and several "colleagues" were all AI-generated. The employee was initially suspicious of a phishing email requesting a "secret transaction"; the live deepfake video call is what overcame that doubt. (Hong Kong Police disclosed the case Feb 2024; Arup confirmed it May 2024; [CNN](https://www.cnn.com/2024/05/16/tech/arup-deepfake-scam-loss-hong-kong-intl-hnk).)

Not every attempt succeeds, which tells you what works:

- Ferrari (2024): an AI voice clone of CEO Benedetto Vigna was defeated when an executive asked a challenge question only the real CEO could answer (a book he had recently recommended). The call ended.
- WPP (2024): an attempt used a voice clone plus public footage of CEO Mark Read in a fake Teams meeting to solicit money and credentials; staff recognized it and it failed.

Scale and forecast (defender-relevant anchors):

- Deloitte Center for Financial Services projects gen-AI-enabled fraud losses in the US could reach ~$40 billion by 2027, up from ~$12.3 billion in 2023 (≈32% CAGR; [Deloitte](https://www.deloitte.com/us/en/insights/industry/financial-services/deepfake-banking-fraud-risk-on-the-rise.html)).
- FinCEN Alert FIN-2024-Alert004 (13 Nov 2024) warned that fraudsters use GenAI deepfakes to defeat identity verification, authentication, and due-diligence controls at financial institutions ([FinCEN](https://www.fincen.gov/sites/default/files/shared/FinCEN-Alert-DeepFakes-Alert508FINAL.pdf)).
- NSA / FBI / CISA joint CSI, "Contextualizing Deepfake Threats to Organizations" (12 Sep 2023) named executive/financial-officer impersonation and brand abuse as the most substantial synthetic-media threats ([CISA](https://www.cisa.gov/news-events/alerts/2023/09/12/nsa-fbi-and-cisa-release-cybersecurity-information-sheet-deepfake-threats)).

Vendor threat reporting (Pindrop, Resemble AI, and others) describes steep year-over-year growth in AI-driven voice/contact-center fraud through 2025; treat specific percentages as vendor figures, not audited statistics. The strategic point stands regardless of the exact number: this is now a routine attack pattern, not a novelty.

---

## Attack taxonomy

| Attack | Channel | What the attacker impersonates | Objective |
|---|---|---|---|
| Executive voice-clone (vishing) | Phone / voicemail / WhatsApp | CEO/CFO/manager voice | Authorize a payment, reset a credential, pressure a subordinate |
| Video-call ("finance-approval") fraud | Zoom / Teams / Meet | CFO + colleagues on a live call | Approve wire transfers or vendor changes: the Arup pattern |
| KYC / onboarding bypass | Identity-proofing flow | A synthetic or stolen face on a "selfie + liveness" check | Open mule accounts, take over accounts, launder funds (FinCEN alert) |
| Fake-interview / insider access | Remote hiring video call | A job applicant (or the interviewer) | Get hired into a trusted role (e.g., DPRK IT-worker schemes) or harvest data |
| Business-email-compromise assist | Email + voice/video "proof" | Executive or supplier | Lend credibility to a BEC lure with a follow-up call |
| Reputation / NCII / extortion | Social, messaging | A real person's likeness | Defame, extort, or manipulate: non-consensual intimate imagery, fake statements |
| Disinformation / market manipulation | Broadcast, social | A public figure or spokesperson | Move markets, incite, damage brand |

This document is defender-framed and focuses on the fraud and access categories most organizations can actually control. For the psychology and delivery mechanics of these lures, see [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md#_4-vishing-and-phone-based-attacks); for the money-movement stages, [FRAUD_FRAMEWORK_REFERENCE.md](FRAUD_FRAMEWORK_REFERENCE.md).

---

## Anatomy of the finance-approval (video-call) scam

The high-loss pattern is consistent. Map your controls to each stage:

1. Recon. Harvest org chart, reporting lines, an in-flight deal or M&A pretext, and public audio/video of the target executive (LinkedIn, earnings calls, YouTube).
2. Pretext delivery. An email or chat from a spoofed/look-alike executive account requests a confidential, time-boxed transaction and discourages normal channels ("don't loop in the team yet").
3. Deepfake reinforcement. When the victim hesitates, escalate to a live video or voice call with a cloned executive, often padded with deepfaked "colleagues" for social proof and authority.
4. Pressure & isolation. Urgency, secrecy, and seniority collapse the victim's willingness to verify: "the deal closes today," "the board is waiting," "keep this between us."
5. Execution. Funds move, frequently split across many transfers and beneficiary accounts to beat per-transaction limits and slow recovery (Arup: 15 transfers, 5 accounts).
6. Cash-out. Money is layered through mule accounts and pulled offshore quickly; recovery windows are hours, not days.

Control mapping: stages 2-4 are defeated by process (a payment cannot be authorized on a call, period), stages 3 by verification (out-of-band callback), and stage 5-6 by banking controls (callback-on-payee-change, transaction monitoring, rapid recall procedures).

---

## Defense-in-depth model

No single control stops deepfakes. Detection is an arms race you do not reliably win; provenance is not yet universal. Process controls are the layer that does not degrade as the models improve: a wire that structurally cannot be approved by voice or video is safe no matter how good the fake is. Rank your investment accordingly:

| Priority | Layer | What it buys you | Fails when... |
|---|---|---|---|
| 1 | Process & policy | The fake cannot cause harm even if believed | Exceptions/urgency overrides erode it |
| 2 | Out-of-band verification | Human confirmation over a trusted second channel | People trust the inbound channel and skip it |
| 3 | Content provenance | Cryptographic origin/edit history for media | Producer/platform doesn't sign or strips it |
| 4 | Detection tooling | Flags likely synthetic media | Novel generator, low quality, live call, adversarial evasion |
| 5 | Liveness / PAD | Blocks presentation & injection attacks at onboarding | Injection attacks, deepfake-as-a-service outpace models |
| 6 | Awareness | People pause and verify | One-off training; no muscle memory under pressure |

---

## Layer 1: Process & policy controls (the strongest layer)

Design so that no synthetic media, however perfect, can move money or grant access on its own.

- Dual (two-person) authorization for wire transfers and any payment above a defined threshold (approvers segregated from initiators).
- No payment or credential action is *ever* authorized by voice or video call alone. Make this an absolute, written rule. A call may *request*; it can never *authorize*. This single policy neutralizes the Arup pattern.
- Out-of-band callback for new or changed payment details. Any change to a vendor/payee bank account is verified by calling a previously known number (from your records, not one supplied in the request) before the first payment.
- Cooling-off / hold on unusually urgent, secret, or out-of-pattern payments; urgency and secrecy are treated as risk signals, not reasons to move faster.
- Pre-shared verification passphrases / "safe words" for executives and finance/treasury staff, rotated and never spoken on the inbound channel being verified.
- Banking-side controls: Positive Pay, payee-name/account validation (e.g., Confirmation of Payee), per-transaction and velocity limits, and a rehearsed payment-recall procedure with the bank (the recovery window is measured in hours).
- Vendor-master hygiene: change-of-bank-details requests route through a controlled workflow with independent verification, not ad-hoc email/DM.
- Authority to say "no": explicitly empower junior staff to pause and verify a request from the most senior person in the company without career risk. Fraud engineers *rely* on rank silencing doubt.

> Tie these into your BEC controls; see [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md#_4-business-email-compromise-response) and [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md).

---

## Layer 2: Out-of-band verification & the live-call playbook

When a call *feels* like an executive making an unusual request, verify the person, not the pixels.

Always:

- Hang up and call back on a known-good number, or confirm via a separate trusted channel (in-person, an established Signal/Teams thread, the executive's assistant).
- Ask the pre-agreed challenge question or passphrase. Ferrari's attacker folded the moment a real, non-public question was asked.
- Escalate, don't decide. Route any secret/urgent money or access request to a second approver and to security.

Weak, degrading signals (use to raise suspicion, never to clear a call): unnatural blinking or gaze, lip-sync drift, lighting/skin artifacts, audio-video lag, flat prosody, odd hand-to-face motion, or refusal to turn to a sharp profile / wave a hand across the face. Real-time models increasingly handle these, so treat their *absence* as meaningless: a clean-looking call is not a verified call. Verification comes from the out-of-band channel and the shared secret, not from eyeballing artifacts.

---

## Layer 3: Content provenance & authentication

Provenance flips the model from "prove it's fake" to "prove it's real": cryptographically signed origin and edit history that travels with the media.

- C2PA / Content Credentials. The open standard from the Coalition for Content Provenance and Authenticity (steering members include Adobe, Microsoft, Google, Intel, OpenAI, BBC, Sony; it unified Adobe's Content Authenticity Initiative and the BBC/Microsoft Project Origin). A Manifest binds a signed Claim and its Assertions (capture device, edits, AI-generation flag) to the asset. The current technical spec is v2.4 ([spec.c2pa.org](https://spec.c2pa.org/)).
  - Hard binding = a cryptographic hash of the asset (tamper-evident, but breaks on re-encode/crop).
  - Soft binding = a fingerprint or embedded watermark that survives edits and lets a stripped asset be re-matched to its manifest.
  - Durable Content Credentials combine metadata + watermark + fingerprint so provenance survives platforms that strip metadata (screenshots, social re-uploads).
- Watermarking. Google SynthID (DeepMind) embeds imperceptible watermarks in AI images (Imagen), video (Veo), audio (Lyria), and text (Gemini), with a public SynthID Detector portal; adoption is spreading across vendors. Watermarking is a signal, not proof; see limits below.
- NIST guidance. NIST AI 100-4, "Reducing Risks Posed by Synthetic Content" (2024) maps the technical approaches (provenance metadata, watermarking, and detection) and is candid about watermark limitations: *scrubbing* (removal), *forgery* (spoofing a legitimate mark), false labels, and scalability/privacy trade-offs ([NIST](https://www.nist.gov/publications/reducing-risks-posed-synthetic-content-overview-technical-approaches-digital-content)).

Operational reality: provenance proves what carries a valid credential; it does not prove that unsigned media is fake (most media is still unsigned). Its near-term value is highest for your own outbound content (sign executive communications, press, official video) so audiences can verify authenticity: a brand-protection and anti-impersonation control.

---

## Layer 4: Detection tooling (and its limits)

Automated detectors are a useful triage/monitoring layer, not a verdict engine.

| Tool | Vendor | Modality | Notes |
|---|---|---|---|
| Reality Defender | Reality Defender | Image, video, audio, text | Multimodal API + real-time; enterprise focus |
| FakeCatcher | Intel | Video | rPPG "blood-flow" biological-signal analysis; real-time |
| Pindrop (Pulse) | Pindrop | Voice / call audio | Liveness + synthetic-voice detection for contact centers |
| Deepfake Detection | Hive AI | Image, video, audio | Large-scale classifier API |
| Sensity | Sensity AI | Multimodal | Monitoring/threat-intel orientation |
| Detect | Resemble AI | Audio | Synthetic-speech detection |

For KYC/onboarding, identity vendors bundle liveness + injection detection (e.g., iProov, Entrust/Onfido, Incode, Jumio, AU10TIX). Validate against ISO/IEC 30107-3 (below), not vendor marketing.

Known limits (plan around them):

- Generalization gap. Detectors trained on known generators degrade on new/unseen models; the fake generators evolve faster than public detectors.
- Quality/compression sensitivity. Call-quality video, phone-codec audio, and re-compression strip the artifacts detectors rely on.
- Adversarial evasion. Attackers can tune outputs to slip past a specific detector.
- No ground truth on live calls. Real-time detection during a Zoom/Teams call is immature and error-prone; do not gate a payment on a green "authentic" indicator.
- False positives create alert fatigue and can wrongly flag real people.

Bottom line: use detection to *raise suspicion and monitor at scale*, and resolve every real decision through Layer 1-2 controls.

---

## Layer 5: Identity-proofing & liveness (onboarding / KYC)

For account opening, high-risk authentication, and remote hiring, the deepfake goes at the biometric check. Two attack classes:

- Presentation attacks: a screen, printout, mask, or replayed video held up to the camera.
- Injection attacks: a synthetic feed injected via a virtual camera or a compromised app/API, bypassing the physical camera entirely (now the faster-growing vector).

Controls:

- Test PAD against ISO/IEC 30107-3 (Presentation Attack Detection), the reference standard: current edition :2023 (it replaced :2017, which certification labs still frequently cite); look for independent lab certification (e.g., iBeta) at Level 1/Level 2, and note that injection-attack resistance is largely out of 30107-3 scope (ask vendors specifically about it).
- Prefer passive + active liveness, device/environment integrity checks, and signals that a real camera (not a virtual one) is in use.
- Layer with document authentication, cross-checks against authoritative data, and step-up review for anomalies; FinCEN specifically recommends MFA (phishing-resistant) and live verification checks to counter deepfake identity documents.
- File a SAR on suspected deepfake fraud and include FinCEN's key term `FIN-2024-DEEPFAKEFRAUD` (SAR field 2 and narrative).

---

## Layer 6: Awareness & training

- Teach the finance-approval pattern by name and rehearse it: urgency + secrecy + seniority + unusual payment/access = stop and verify out-of-band, every time.
- Run deepfake-aware simulations (vishing/voice-clone drills, "unusual CFO request" tabletops) alongside phishing tests; see [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md#_7-security-awareness-training).
- Give executives and finance/treasury/IT-helpdesk targeted training: they are the impersonation targets and the approval choke points.
- Normalize verification culture: "I'm going to call you back to confirm" is professional, not insulting, even to the CEO.
- Publish and drill the safe-word / callback procedure so it is reflex under pressure, not something people look up.

---

## Incident response: suspected deepfake fraud

Fold these into your IR and BEC playbooks: [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md).

1. If funds moved: act in minutes. Contact the bank to recall/freeze, notify the beneficiary bank, and (US) file an FBI IC3 complaint / request a Financial Fraud Kill Chain recall for qualifying wires. Recovery odds fall by the hour.
2. Preserve evidence. Meeting recordings, call logs/CDRs, caller IDs, chat/email headers, the media files, and account/transaction details, for forensics and law enforcement (see [DIGITAL_FORENSICS_REFERENCE.md](DIGITAL_FORENSICS_REFERENCE.md)).
3. Verify who's real. Independently confirm with the impersonated executive; check whether their accounts were also compromised (BEC often precedes the call).
4. Regulatory clocks. A financial institution files a SAR (`FIN-2024-DEEPFAKEFRAUD`). Data-breach or sector duties may attach; see [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md).
5. Contain the pretext. Reset affected credentials, hunt for related lures across the org, and warn finance/AP of the active campaign.
6. Retrospective. Which control was supposed to stop this? Usually the missing one is *out-of-band callback* or *dual approval*; fix the process, not just the person.

---

## Regulatory & standards landscape

> Not legal advice. This is a defender's operational summary; obligations turn on facts and jurisdiction. Confirm specifics with counsel. Verified as of 2026-09-29.

| Instrument | Jurisdiction | What it does | Status / date | Source |
|---|---|---|---|---|
| FinCEN Alert FIN-2024-Alert004 | US | Alerts FIs to GenAI/deepfake fraud; SAR key term `FIN-2024-DEEPFAKEFRAUD`; recommends MFA + live verification | Issued 13 Nov 2024 | [FinCEN](https://www.fincen.gov/sites/default/files/shared/FinCEN-Alert-DeepFakes-Alert508FINAL.pdf) |
| NSA/FBI/CISA CSI: Contextualizing Deepfake Threats | US | Guidance: media authentication, awareness, detection | Released 12 Sep 2023 | [CISA](https://www.cisa.gov/news-events/alerts/2023/09/12/nsa-fbi-and-cisa-release-cybersecurity-information-sheet-deepfake-threats) |
| NIST AI 100-4: Reducing Risks Posed by Synthetic Content | US | Technical map of provenance, watermarking, detection + their limits | Published 2024 | [NIST](https://www.nist.gov/publications/reducing-risks-posed-synthetic-content-overview-technical-approaches-digital-content) |
| EU AI Act Art. 50 (transparency) | EU | Deepfakes (Art. 3(60)) must be labeled as AI-generated/manipulated | Transparency duties apply 2 Aug 2026; Code of Practice draft 17 Dec 2025 | [artificialintelligenceact.eu](https://artificialintelligenceact.eu/transparency-rules-article-50/) |
| TAKE IT DOWN Act | US (federal) | Criminalizes non-consensual intimate imagery incl. deepfakes; platform notice-and-removal | Signed 19 May 2025; platform removal process by 19 May 2026 | [Congress.gov](https://www.congress.gov/crs-product/LSB11314) |
| ISO/IEC 30107-3 | International | Presentation Attack Detection testing (APCER/BPCER); basis for liveness certification | Current edition :2023 (replaced :2017) | [ISO](https://www.iso.org/standard/79520.html) |
| C2PA Technical Specification | International (industry) | Content provenance / Content Credentials | v2.4 current | [spec.c2pa.org](https://spec.c2pa.org/) |

State laws add to this: many US states have deepfake statutes covering elections and non-consensual intimate imagery. At the federal level, the DEFIANCE Act (which would create a federal *civil* cause of action for intimate deepfakes) had passed the Senate but was not yet enacted as of 2026-09-29 (reintroduced as the DEFIANCE Act of 2025, S.1837 / H.R.3562); track its status before relying on it. Maintain a jurisdiction map for regulated content and elections exposure. General breach/incident clocks: [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md).

---

## Deepfake-defense checklist

Process (do these first):
- [ ] Written rule: no payment or credential/access action is authorized by voice or video call alone
- [ ] Dual authorization for wires above a threshold; initiator ≠ approver
- [ ] Out-of-band callback (known-good number) for every new/changed payee
- [ ] Pre-shared executive/finance passphrases, rotated, never spoken on the inbound channel
- [ ] Cooling-off + escalation on urgent/secret/out-of-pattern requests
- [ ] Bank controls: Positive Pay, payee validation, velocity limits, rehearsed recall

Verification & people:
- [ ] Callback + challenge-question drill baked into finance/treasury/helpdesk SOPs
- [ ] Deepfake-aware simulations run alongside phishing tests
- [ ] Junior staff explicitly empowered to pause and verify senior requests

Technology:
- [ ] Sign your own outbound media with C2PA / Content Credentials (anti-impersonation)
- [ ] Detection tooling deployed for triage/monitoring, not as a decision gate
- [ ] KYC/liveness validated against ISO/IEC 30107-3 (ask about injection-attack resistance)
- [ ] Phishing-resistant MFA everywhere identity is proven

Response:
- [ ] Deepfake-fraud steps in the IR/BEC playbook; bank-recall + IC3 path pre-mapped
- [ ] SAR process references `FIN-2024-DEEPFAKEFRAUD`
- [ ] Evidence-preservation checklist for calls/recordings/media

---

## Related Resources

- [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md): vishing, voice cloning, BEC delivery, awareness programs (attacker tradecraft)
- [FRAUD_FRAMEWORK_REFERENCE.md](FRAUD_FRAMEWORK_REFERENCE.md): MITRE Fight Fraud (F3): account takeover -> mule -> cash-out behavior chain
- [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md): BEC/wire-fraud response, triage, evidence handling
- [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md): the email pretext that usually precedes the call
- [IDENTITY_SECURITY_REFERENCE.md](IDENTITY_SECURITY_REFERENCE.md), [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md): MFA, identity proofing, liveness context
- [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md), [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md): GenAI risk and MITRE ATLAS technique mapping
- [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md): breach/incident notification clocks that a fraud event may also trip

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
