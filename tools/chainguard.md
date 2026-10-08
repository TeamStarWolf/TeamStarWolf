# Chainguard

*Chainguard, Inc. · Software supply-chain security: hardened minimal (zero-CVE) container images, secure language libraries, VM images, and the Chainguard OS/Factory build system*

Chainguard produces minimal, hardened, continuously-rebuilt-from-source container images (and now language libraries, VM images and OS packages) engineered to carry zero known CVEs, each shipping with build-time SBOMs and signed provenance attestations plus a CVE-remediation SLA. It attacks vulnerability risk at the source - the base image and dependencies - rather than detecting CVEs after deployment, dramatically shrinking attack surface and the volume of vulnerabilities teams must patch. It solves the problem of bloated, CVE-laden upstream base images and the patching treadmill they create.

## Capabilities & architecture

**Core capabilities**
- Chainguard Containers (Images): 2,000+ minimal, zero-CVE container images built on Wolfi (a container-optimized undistro/Linux distribution), stripped of shells, package managers and unnecessary utilities to minimize attack surface; :latest and :latest-dev variants
- Build-time SBOMs, signed attestations (Sigstore-based provenance), and a CVE-remediation SLA on paid/production images
- Chainguard Libraries: malware-resistant, built-from-source language libraries for Python, Java and JavaScript
- Chainguard VMs: minimal VM images optimized for cloud and security
- Chainguard OS: a minimal, continuously-updated Linux distribution underpinning the products; the Chainguard Factory build system (Factory 2.0 / DriftlessAF) rebuilds 10,000+ OSS projects daily from source whenever upstream changes
- OS Packages, Chainguard Actions, Agent Skills (AI agent skills, continuously reviewed/hardened), Image Directory (updated daily), and FIPS-validated image variants for regulated environments

**Architecture & deployment.** Delivered as a catalog of signed artifacts (OCI container images, library packages, VM images) pulled from Chainguard's registry into your own CI/CD, registries and clusters - not an agent or SaaS scanner. You adopt them as drop-in base images/dependencies; a management console provides entitlements, private repositories and pull controls for enterprise. The Chainguard Factory continuously rebuilds artifacts from source and re-publishes patched versions, which you pull and redeploy. Integrates with standard scanners (Trivy, Grype, Snyk, Wiz) to demonstrate the reduced/zero-CVE result.

**Editions & licensing.** Freemium plus enterprise subscription. A free tier offers ~50 unguarded images tagged :latest/:latest-dev without login (not covered by the CVE-remediation SLA). Production images are sold by custom/enterprise subscription (contact sales) and add the remediation SLA, private repositories, full catalog access, FIPS variants, and the entitlements/management console; pricing is generally per-image-stream/consumption and negotiated. Chainguard Libraries had a promotional free period (reported free until June 30, 2026 - verify current status). Also offered via AWS Marketplace.

**Key integrations.** Container registries and CI/CD (Docker/OCI, Kubernetes, GitHub Actions); Vulnerability scanners for verification (Trivy, Grype, Snyk, Wiz); Cloud platforms (AWS Marketplace listing, GCP, Azure); SBOM/attestation tooling (Sigstore/cosign); Works beneath any CNAPP - reduces findings in AWS Inspector/ECR, Defender for Cloud and Wiz; Guardener integration referenced by the vendor.

**Differentiators**
- Prevention at the source: eliminates CVEs by rebuilding minimal images/libraries from source daily, rather than scanning/patching after the fact
- Genuine zero-CVE (or near-zero) posture with vendor CVE-remediation SLA - cited ~97.6% average CVE reduction (vendor figure)
- Every artifact ships signed SBOM + provenance attestation, directly satisfying SLSA/supply-chain and FIPS/regulated requirements
- Wolfi/Chainguard OS undistro design (no shell/package manager) massively shrinks runtime attack surface
- Shifts patching burden from the customer to Chainguard's Factory - operational relief at scale

**Limitations & considerations**
- The 'zero-CVE' claim is contested: it reflects minimal surface + fast remediation + triage (not-affected) flags, and a 2026 analysis argues treating triage as proof of 'not vulnerable' conflates prioritization with absence of vulnerabilities - best read as near-zero known CVEs
- Migration effort: minimal images lack shells/package managers/debug tools, which breaks workflows and requires re-tooling build/debug practices (multi-stage builds, ephemeral debug images)
- Covers the image/dependency layer only - does not address your own application code's vulnerabilities, misconfigurations, or runtime threats (needs a CNAPP/scanner alongside)
- Enterprise pricing is custom/opaque; full catalog and SLA gated behind paid subscription (free tier limited to ~50 images, no SLA)
- Competition emerging (e.g. Docker Hardened Images) and some coverage/variant gaps for niche software stacks
- Not a detection or patch-orchestration tool for existing fleets - value only realized when you actually adopt and redeploy the artifacts

## Vulnerability-mitigation role

Chainguard is a preventive/remediation control that attacks the vulnerability lifecycle upstream. By shipping minimal zero-CVE images and from-source-rebuilt libraries, it removes the vulnerable packages that would otherwise need patching, collapsing attack surface before any CVE is disclosed. When a critical CVE drops, the Factory rebuilds and re-publishes a patched image typically well ahead of (or at) upstream, under an SLA - so the customer's remediation is reduced to pulling the new image and redeploying, shrinking the exposure window dramatically versus hand-patching. In the case-study framing it is the fastest path to actual remediation at the image layer and, by minimizing surface, also acts as a standing compensating control (fewer latent vulns to exploit while other patches land).

**VM lifecycle:** Mitigate · Remediate/Patch · Validate

**Framework mapping:** NIST CSF 2.0: Protect (hardened minimal images, secure dependencies), Identify (SBOM/provenance for supply-chain inventory); CIS Controls v8: 2 (software inventory/SBOM), 4 (secure configuration of base images), 7 (continuous vulnerability management via from-source rebuilds), 16 (application software security / supply chain); MITRE ATT&CK mitigations: M1051 Update Software (continuous from-source rebuilds), M1038 Execution Prevention / reduced surface (no shell/package manager), M1016 Vulnerability Scanning (SBOM-enabled); supply-chain alignment with SLSA framework

**In a critical-CVE scenario.** First 24-72h of a critical CVE in an internet-facing app's container stack: if the affected component is a Chainguard image/library, the Chainguard Factory rebuilds from source and publishes a patched, re-signed image under its remediation SLA - often faster than upstream - so the team's response is simply to pull the updated tag and redeploy (CI/CD), then verify with Trivy/Grype/Wiz that the CVE is gone. For components not yet on Chainguard, the incident becomes the trigger to migrate that base image to a Chainguard equivalent to prevent recurrence. Chainguard does not scan or shield your running fleet - it provides the clean artifact that remediates the exposure and permanently reduces surface.

## Validation & telemetry

**Log sources**
- Supply-chain hardening: the 'telemetry' is cryptographic metadata attached to the image in the OCI registry (cgr.dev/chainguard public, cgr.dev/<ORG> for org images), not a running-agent log stream.
- Signed in-toto attestations per build: (1) SPDX SBOM (predicate https://spdx.dev/Document), (2) SLSA provenance (predicate https://slsa.dev/provenance/v1) describing the build environment, (3) apko build-config (direct deps, users, entrypoint).
- Signatures: keyless Sigstore — Fulcio cert tied to the GitHub Actions OIDC identity of Chainguard's release workflow, logged in the Rekor transparency log.
- Validation/collection points: CI (cosign verify / verify-attestation), admission time (Sigstore policy-controller, Kyverno, or Chainguard/enforce policy), and the registry/scanner pipeline. Operational logs of these checks live in CI run logs, the Kubernetes admission controller / kube-audit log, and Rekor — not in Chainguard itself.
- VERIFIED: three attestation types (SLSA provenance v1, apko config, SPDX SBOM); cosign download/verify-attestation flow; keyless verify reporting Rekor-entry + cert-chain validation; retrieval guide current to July 2025.

**Telemetry format / transport.** in-toto attestation statements in a Sigstore DSSE envelope (JSON; SBOM payload base64 inside), predicate types SPDX / SLSA provenance / apko config. Transport: OCI registry referrers/attachments (cosign download sbom / download attestation). Verification evidence: cosign CLI JSON output, Kubernetes admission-review JSON, Rekor transparency-log entries.

**Control-presence check (present & configured?).** Presence is proven by a successful cosign verification pinned to Chainguard's build identity, not by the attestation merely existing. Signature: `cosign verify cgr.dev/chainguard/<image> --certificate-oidc-issuer=https://token.actions.githubusercontent.com --certificate-identity-regexp='https://github.com/chainguard-images/images.*release.*'`. Attestation by type: `cosign verify-attestation --type https://slsa.dev/provenance/v1 ...` and `--type https://spdx.dev/Document ...` — a pass reports predicate validates, Rekor entry exists (checked offline), cert chains to trusted CA. SBOM retrieval: `cosign download sbom cgr.dev/chainguard/<image>`. Cluster-side: query the ClusterImagePolicy / Kyverno policy object to confirm a rule requires these attestations for the target namespace.

**Validation signals (actually working?)**
- CONFIGURED: a ClusterImagePolicy/Kyverno/enforce policy requires the Chainguard signature+attestations for the namespace, AND standalone cosign verify-attestation passes on the image.
- EFFECTIVE: an admission-time DENY in the K8s API-server audit log / admission-controller log showing a non-conforming image (unsigned, wrong identity, failing attestation) was rejected at deploy — the active block that proves enforcement.
- EFFECTIVE (secondary): the image's vuln-scan (Grype/Trivy against the SBOM) showing zero/known-fixed CVEs, proving the hardened-image mitigation is realized.
- Distinguish: a passing cosign verify proves the provenance control is PRESENT; an admission audit entry 'denied the request: no matching signatures/attestations' proves the policy actively BLOCKED a bad image.

**Key events / fields / tables / APIs**
- cosign verify output: certificate Subject/SAN (build identity github.com/chainguard-images/images.../release.yaml@ref), OIDC issuer (token.actions.githubusercontent.com), Rekor logIndex/logID + inclusion proof, Bundle Verified=true.
- Attestation: predicateType (https://slsa.dev/provenance/v1 | https://spdx.dev/Document), predicate.buildDefinition / predicate.runDetails (SLSA builder.id, invocation), SPDX packages[].name/versionInfo/externalRefs (CPE/PURL -> CVE).
- Kubernetes admission audit: objectRef.resource=pods, responseStatus.code (403 on deny), message ('failed policy: <name>: no matching attestations'); policy-controller/Kyverno emit a Warning/Blocked event with the image digest.
- Pin by digest (@sha256:) not tag for a deterministic claim.
- NOTE: the exact certificate-identity string differs across Chainguard docs (chainguard-images/images vs images-private) — confirm the current value before pinning it in an enforcing policy.

**Example queries**

*Presence: verify SLSA provenance is present and attributed to Chainguard's release workflow* (Bash)

```bash
cosign verify-attestation --type https://slsa.dev/provenance/v1 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/chainguard-images/images.*/\.github/workflows/release\.yaml@.*' \
  cgr.dev/chainguard/nginx@sha256:<digest>
```

*Validation: pull the SPDX SBOM and scan it so the hardened-image CVE posture is proven, not assumed* (Bash)

```bash
cosign download attestation --predicate-type https://spdx.dev/Document cgr.dev/chainguard/nginx@sha256:<digest> | jq -r .payload | base64 -d | jq .predicate > sbom.spdx.json && grype sbom:sbom.spdx.json -o table
```

*Validation (admission enforcement actively blocked a bad image) against kube-audit shipped to Log Analytics/Sentinel* (KQL)

```kql
AzureDiagnostics
| where Category == 'kube-audit'
| extend d = parse_json(log_s)
| where tostring(d.responseStatus.code) == '403' and tostring(d.responseStatus.message) has_any ('no matching signatures','no matching attestations','failed policy')
| project TimeGenerated, image=tostring(d.requestObject.spec.containers[0].image), msg=tostring(d.responseStatus.message)
```

**How it mitigates (mechanism).** Mitigation is upstream (minimal, frequently-rebuilt distroless images carry far less vulnerable surface) made verifiable by signed provenance: the SLSA/SPDX attestations let an admission controller cryptographically require that only images built by Chainguard's pipeline run, so the observable block (an admission DENY on a missing/invalid attestation) is the inline enforcement point and the SBOM lets a scanner confirm the reduced CVE surface.

**Logging gotchas**
- cosign verify succeeding only proves authenticity/provenance — it says nothing about current CVE status; you still must scan the SBOM, and SBOM freshness lags a rebuild.
- No Chainguard-side log proves the image was deployed or blocked — enforcement evidence lives entirely in YOUR admission controller + K8s audit log, which must be enabled and shipped (kube-audit is off by default on many clusters).
- Verifying a floating tag instead of a digest lets content drift; always pin @sha256:.
- The certificate-identity value has changed across docs/repos (images vs images-private), so an over-tight policy can reject legitimate images after a pipeline change.
- Keyless verification depends on reaching Fulcio/Rekor roots (or a staged trust bundle) — air-gapped verification needs the bundle staged.
- Attestations are per-build/per-platform, so a multi-arch index requires verifying each platform's manifest.

## Documentation & repositories

_Official documentation & manuals_
- [Chainguard Academy (docs & guides)](https://edu.chainguard.dev/)
- [How to use Chainguard Images](https://edu.chainguard.dev/chainguard/containers/how-to-use-chainguard-images/)
- [Chainguard Images directory (per-image overview, pull commands, advisories)](https://images.chainguard.dev/)
- [Chainguard developer resources (docs bundle / llms.txt)](https://edu.chainguard.dev/developer-resources/)

_API & developer docs_
- [chainctl CLI reference](https://edu.chainguard.dev/chainguard/chainctl/)
- [apko documentation (declarative OCI image builder)](https://edu.chainguard.dev/open-source/build-tools/apko/)
- [melange documentation (apk package builder)](https://edu.chainguard.dev/open-source/build-tools/melange/)
- [Chainguard cosign Terraform provider](https://registry.terraform.io/providers/chainguard-dev/cosign/latest/docs)
- [Chainguard AI docs bundle / MCP server (ghcr.io/chainguard-dev/ai-docs)](https://edu.chainguard.dev/developer-resources/)

_GitHub (official)_
- [chainguard-dev org](https://github.com/chainguard-dev)
- [chainguard-images/images (build configs for hardened OCI images)](https://github.com/chainguard-images/images)
- [chainguard-dev/apko](https://github.com/chainguard-dev/apko)
- [chainguard-dev/melange](https://github.com/chainguard-dev/melange)
- [chainguard-dev/images-autodocs (generates Academy image reference docs)](https://github.com/chainguard-dev/images-autodocs)

_Community / integration / detection repos_
- [Wolfi OS (undistro Linux base behind Chainguard Images/Starter tier)](https://github.com/wolfi-dev/os)
- [Sigstore cosign (image signing/verification used by Chainguard supply-chain flow)](https://github.com/sigstore/cosign)
- [Sigstore project org](https://github.com/sigstore)

_Learning & reference_
- [Chainguard Academy (labs & courses)](https://edu.chainguard.dev/)
- [Chainguard Unchained blog](https://www.chainguard.dev/unchained)
- [Chainguard developer resources hub](https://edu.chainguard.dev/developer-resources/)

> Note: Supply-chain focused: minimal, distroless, 0-known-CVE hardened container images plus signing/provenance tooling. Note the two GitHub orgs — chainguard-dev (tools: apko, melange, chainctl, images-autodocs) and chainguard-images (image build configs). Images are distroless by default with a `-dev` variant (shell/package manager) for build stages. Free Starter tier is built on Wolfi; other images on Chainguard OS. Full catalog and private-registry (cgr.dev) pulls require an org account. All GitHub/edu URLs here were surfaced or corroborated in search; the Terraform cosign provider path follows Chainguard's standard registry namespace.

## Current state (2025-26)

Chainguard positions a broad product line: Containers/Images (2,000+ zero-CVE images on Wolfi), Libraries (Python/Java/JS, built from source), VMs, OS Packages, Chainguard OS, Actions, and AI Agent Skills, all produced by the Chainguard Factory (reported Factory 2.0 / DriftlessAF rebuilding from source on upstream drift). Raised a $356M Series D in April 2025 (co-led by Kleiner Perkins and IVP; ~$612M total funding). Chainguard Libraries reported free until June 30, 2026 (verify current status). Integrations with Trivy, Grype, Snyk and Wiz. The 'zero-CVE' marketing is independently contested (Feb 2026 analysis) and is best described as minimal-surface, near-zero known CVEs with an SLA. Remains independent; verify catalog size and specific FIPS/SLA terms on Chainguard's own docs.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
