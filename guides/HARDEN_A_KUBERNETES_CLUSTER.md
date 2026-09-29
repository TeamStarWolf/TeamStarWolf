# Harden a Kubernetes Cluster

> **By the end of this guide you will have taken a running Kubernetes cluster from "it works" to a defensible baseline — measured with kube-bench and Trivy, control plane and kubelet locked down, Pod Security Admission enforcing `restricted`, default-deny NetworkPolicies, RBAC pruned of cluster-admin sprawl, an admission policy engine verifying image signatures, secrets encrypted at rest, and audit logging flowing to your SIEM — with a before/after scan report and an exception register that prove it.** Written for platform engineers, SREs, and security engineers who own a cluster (managed or self-managed) and want a repeatable hardening procedure rather than a pile of one-off `kubectl` commands.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| A day for a non-prod pilot; 2–4 weeks to roll a production cluster through every step | Advanced | `cluster-admin` on a test cluster (read-level for the audit phases), kubectl, a CNI that enforces NetworkPolicy, an etcd snapshot before touching control-plane flags | A baselined cluster: kube-bench + Trivy reports, enforced PSA `restricted`, default-deny NetworkPolicies, a pruned RBAC model, an admission policy engine, encrypted secrets, audit logging, and a documented exception register |

This guide operationalizes the library's [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) — its attack-surface map, RBAC deep dive, Pod Security Standards, NetworkPolicy, secrets, and hardening checklist are the *what*; this is the *how*, in the order a practitioner actually executes it. Image-layer hardening (Dockerfiles, base images, scanning, escape defense) lives one layer down in the [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), and the discipline that frames both — where this sits in a career and a learning path — is [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md). The single most useful external companion is the [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF); keep it open beside this one.

## Before you start

- [ ] **Read the hardening-checklist and Pod Security sections** of the [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) so the control choices below make sense before you enforce them, and skim the [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [ ] **A non-production cluster you can afford to break.** `restricted` Pod Security and default-deny NetworkPolicies *will* break workloads that were never designed for them — never debut these on prod.
- [ ] **Know whether your cluster is managed or self-managed.** On EKS/GKE/AKS the cloud provider owns the control plane and etcd — you cannot set API-server flags, and you use the provider's CIS benchmark and its console equivalents. On kubeadm/self-managed clusters you own everything in Steps 3, 8, and 9. This split determines which steps you *can* execute directly.
- [ ] **Run a supported Kubernetes version.** Out-of-support releases miss security fixes and the current Pod Security / admission features. Check [kubernetes.io/releases](https://kubernetes.io/releases/) for the supported window (as of this writing the current minor is v1.37, with roughly the three latest minors supported).
- [ ] **A CNI that enforces NetworkPolicy** — Calico or Cilium. Flannel and some default CNIs silently ignore NetworkPolicy objects, so a "default-deny" you apply on them does nothing. Confirm your CNI before Step 6.
- [ ] **[kube-bench](https://github.com/aquasecurity/kube-bench)** (Aqua Security's CIS Kubernetes Benchmark checker) and **[Trivy](https://trivy.dev/)** available, plus a free account at [CIS Benchmarks](https://www.cisecurity.org/benchmark/kubernetes) to pull the matching benchmark PDF for your version and distribution.
- [ ] **An etcd snapshot (self-managed) or a tested cluster backup** before you change any control-plane flag in Step 3 — a bad `kube-apiserver` manifest edit can make the API server refuse to start.

## Step 1 — Scope the cluster and pick your benchmark

You cannot harden what you have not inventoried. Decide three things and write them down:

1. **Managed or self-managed?** This picks your benchmark edition and gates which steps you execute directly. kube-bench ships distribution-specific benchmarks — pick the one that matches (`eks`, `gke`, `aks`, `rke2`, `k3s`, OpenShift) or the upstream CIS Kubernetes Benchmark for kubeadm clusters.
2. **Which namespaces hold real workloads**, and which are infrastructure (CNI, CSI, ingress, monitoring)? Infrastructure namespaces legitimately need looser Pod Security (`privileged`/`baseline`); application namespaces are your `restricted` targets in Step 4. List them now.
3. **Your CNI, your ingress controller, and whether audit logging / encryption-at-rest already exist.** On managed clusters some of Step 9 is a console toggle you may already own.

```bash
kubectl version                 # server version — confirm it is in support
kubectl get nodes -o wide       # node count, OS image, container runtime, kernel
kubectl get ns                  # the namespaces you will label in Step 4
kubectl get pods -A -o wide     # what is actually running, and where
```

**Checkpoint:** A one-page scope note: managed vs self-managed, cluster version, CNI, the benchmark edition you'll use, and a namespace list split into "application" (→ `restricted`) and "infrastructure" (→ documented exception).

**Watch out:** On a managed cluster, do not waste a week trying to remediate control-plane and etcd findings you have no access to change — those are the provider's responsibility under the shared-responsibility model ([Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md)). Focus your effort on worker-node, RBAC, workload, and policy controls you actually own.

## Step 2 — Baseline the cluster with kube-bench and Trivy

Measure before you touch anything, so you can prove improvement in Step 9 and so a later breakage has a diff to blame.

**Configuration baseline (kube-bench → CIS Kubernetes Benchmark):** kube-bench checks control-plane, etcd, kubelet, and policy settings against the CIS benchmark and prints `[PASS]`/`[FAIL]`/`[WARN]` with the exact remediation for each item. Run it in-cluster as a Job (the repository ships manifests), or as a binary on a node:

```bash
# In-cluster, auto-detecting the running version (job manifests in the repo)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -f job/kube-bench

# On a control-plane node (binary), pinning the matching benchmark/target set
kube-bench run --targets master,controlplane,node,etcd,policies

# Managed clusters use the distribution benchmark, e.g.:
kube-bench run --benchmark eks-1.7      # confirm the current benchmark tag in the repo docs
```

**Workload and image baseline (Trivy):** kube-bench scores the cluster's *configuration*; Trivy scores the *workloads and images* running in it — vulnerabilities, misconfigurations, and exposed secrets:

```bash
# Scan the whole cluster's workloads and their images for a report
trivy k8s --report summary

# Drill into one namespace, including misconfiguration checks
trivy k8s --include-namespaces production --report all
```

Save both reports with a date in the filename. This pair is your starting score and your work plan.

**Checkpoint:** A dated `kube-bench` report (FAIL/WARN counts by target) and a dated `trivy k8s` report (critical/high findings by namespace), both stored where the Step 9 re-scan can diff against them.

**Watch out:** A `[PASS]` from kube-bench means the *setting* is correct, not that the cluster is safe — the benchmark cannot see your RBAC intent, your NetworkPolicy gaps, or an over-permissioned service account. Treat the score as a floor to clear, not a finish line. And run the benchmark edition that matches your version: scanners trail the benchmark, and the benchmark trails Kubernetes releases, so a brand-new cluster may need the newest kube-bench build.

## Step 3 — Harden the control plane, kubelet, and etcd

*Self-managed clusters only — on managed clusters, verify the provider's equivalents in their console and skip to Step 4.* Work the kube-bench FAILs from Step 2; each one names its remediation. The high-value settings:

**API server** (`/etc/kubernetes/manifests/kube-apiserver.yaml` on kubeadm nodes):

- `--anonymous-auth=false` — no unauthenticated requests.
- `--authorization-mode=Node,RBAC` — never `AlwaysAllow`.
- `--audit-log-path=...` and an audit policy (Step 9).
- `--encryption-provider-config=...` for secrets encryption at rest (Step 8).
- Confirm the deprecated insecure serving port is gone (it was removed upstream years ago) and that the profiling and legacy anonymous paths are locked down per the benchmark.

**kubelet** (the node agent — a favorite pivot; see the attack-surface map in the [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)):

- `--anonymous-auth=false` and `--authorization-mode=Webhook` — an anonymously reachable kubelet on `:10250` is remote code execution in every pod on the node.
- `--read-only-port=0` — disable the unauthenticated read-only port (`:10255`).
- `--protect-kernel-defaults=true`, and enable kubelet certificate rotation.

**etcd** — the crown jewel; it stores *all* cluster state, including Secrets:

- mTLS for client and peer traffic (`--cert-file`, `--key-file`, `--peer-*`, `--client-cert-auth=true`).
- Reachable only from the API server (host firewall / network policy), never exposed to the pod network.
- Encrypted at rest (Step 8) and backed up (`etcdctl snapshot save`) before *any* of these edits.

Apply changes one node at a time and confirm the component restarts healthy before moving on. Re-run `kube-bench run` after each batch to watch FAILs turn to PASS.

**Checkpoint:** kube-bench control-plane, kubelet, and etcd FAILs are resolved or written into the exception register with a reason; every changed component came back healthy; and you have an etcd snapshot from before the changes.

**Watch out:** A malformed static-pod manifest can stop the API server from starting, and on a single-control-plane cluster that is an outage. Change one flag group at a time, keep the etcd snapshot handy, and never do this first on production. Powering through all edits at once is how a hardening task becomes an incident.

## Step 4 — Enforce Pod Security Admission (`restricted`)

Pod Security Admission (PSA) is built into the API server and **enabled by default since Kubernetes v1.25 — the same release that removed the old PodSecurityPolicy (PSP)**. If any of your tooling or manifests still reference PSP, they are dead; PSA is the successor. PSA enforces the three [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — `privileged`, `baseline`, `restricted` — per namespace via labels.

**Discover violations before you block anything.** Apply `warn` and `audit` first, which surface violations without rejecting pods:

```bash
# Warn + audit only — nothing is blocked yet; violations show as warnings/events
kubectl label --overwrite ns production \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# See what would break
kubectl get events -n production --field-selector reason=FailedCreate
```

Fix the workloads the warnings name — the `restricted` profile requires `runAsNonRoot: true`, a non-zero `runAsUser`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault`, `readOnlyRootFilesystem` where feasible, and no `hostNetwork`/`hostPID`/`hostIPC`/`hostPath`. The full securityContext template is in the [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md).

**Then flip `enforce` on, namespace by namespace:**

```bash
kubectl label --overwrite ns production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Leave genuine infrastructure namespaces at `baseline` or `privileged` **with a written justification** — do not force a CNI or CSI driver into `restricted` and break the cluster to hit a number.

**Checkpoint:** Every application namespace enforces `restricted` (or `baseline` with a documented exception); `kubectl get ns --show-labels` shows the `enforce` labels; and no legitimate workload is stuck failing admission.

**Watch out:** PSA is coarse — it enforces one of three fixed profiles per namespace and cannot express "restricted except this one field." For anything more granular (or to *mutate* pods into compliance instead of rejecting them), you need the policy engine in Step 7. Also: PSA only evaluates pods at admission, so label a namespace *before* workloads land, and re-check existing pods, which are not retroactively evaluated.

## Step 5 — Cut RBAC down to least privilege

Over-broad RBAC is the most common serious Kubernetes finding: a service-account token from one compromised pod that can read every Secret or `exec` into any pod turns a single-pod compromise into cluster takeover. Kill cluster-admin sprawl first.

**Find who and what holds `cluster-admin`:**

```bash
# Every binding to the cluster-admin ClusterRole and its subjects
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin")
           | .metadata.name + " -> " + (.subjects // [] | map(.kind+"/"+.name) | join(", "))'

# What a specific service account can actually do
kubectl auth can-i --list \
  --as=system:serviceaccount:production:my-app -n production
```

Then work the reductions:

1. **Remove human and service-account bindings to `cluster-admin`** that don't need it. Replace with a narrowly scoped `Role`/`RoleBinding` in the one namespace they operate in.
2. **Hunt the dangerous verbs** the reference flags — wildcard `*` on `*`, `secrets` get/list, `pods/exec`, `create` on `pods` with arbitrary service accounts, and the ability to modify RBAC itself. Scope or remove each.
3. **Give every workload its own service account** with only the permissions it uses, and set `automountServiceAccountToken: false` on pods that never call the API — an unused mounted token is a free credential for an attacker.
4. **Tools that make this tractable:** `kubectl auth can-i`, plus community auditors like [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can), rbac-tool, or rakkess to reverse the question ("who can read secrets in `production`?").

This is the same least-privilege discipline as human identity governance — see the [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).

**Checkpoint:** A short, justified list of who holds `cluster-admin` (ideally only break-glass and the platform team); no application service account can read cluster-wide Secrets or `exec` into arbitrary pods; and API-less workloads no longer mount a token.

**Watch out:** Do not delete a binding you don't understand on a live cluster — controllers, operators, and the CNI hold RBAC they genuinely need, and yanking it breaks reconciliation loops silently. Test each reduction in non-prod, and prefer *adding* a scoped role and removing the broad one over editing shared ClusterRoles in place.

## Step 6 — Default-deny the network

By default every pod can talk to every other pod in the cluster — zero segmentation, so one foothold reaches everything. Flip that to default-deny per namespace, then allow only what the app needs. **This requires the NetworkPolicy-enforcing CNI you confirmed in Before you start.**

```yaml
# 1. Deny all ingress AND egress in the namespace (nothing flows until allowed)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}                      # all pods in the namespace
  policyTypes: ["Ingress", "Egress"]
---
# 2. Allow DNS egress — almost every workload needs this or it breaks immediately
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

From there, add narrow allow rules per tier (frontend→api on its port, api→database, and controlled egress to the specific external endpoints a workload legitimately calls). **Egress control is the half teams skip** — it is what stops a compromised pod from reaching the cloud metadata endpoint, an attacker's C2, or your other namespaces. Copy the allow-rule and L7 (Cilium) patterns from the [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md).

**Checkpoint:** Each application namespace has a `default-deny-all` policy plus explicit allow rules; DNS still resolves; the app's real traffic paths work; and a test pod cannot reach a service in another namespace it has no rule for.

**Watch out:** Apply DNS-egress *with* or *before* the default-deny, or you will take the namespace down the instant the deny lands — everything that resolves a hostname stops. And remember NetworkPolicy is namespaced and additive: a default-deny in one namespace does nothing for another, so every namespace needs its own.

## Step 7 — Add an admission policy engine and verify image provenance

PSA covers the three fixed pod profiles; everything else you want to *require* at admission — image signatures, no `:latest` tags, resource limits, approved registries, required labels — needs a policy engine. You have two families:

- **In-tree ValidatingAdmissionPolicy (VAP)** — CEL-based policy evaluated inside the API server, no external webhook. It went **GA in v1.30 and is on by default**; its mutating sibling, MutatingAdmissionPolicy, reached **GA in v1.36** (confirm what your version supports). Good for cluster-native guardrails with no extra components.
- **A dedicated engine — [Kyverno](https://kyverno.io/) or [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)** — richer policy libraries, mutation, generation, reporting, and (critically) **image-signature verification**. Kyverno writes policies as Kubernetes YAML; Gatekeeper uses OPA/Rego constraints.

**Verify image provenance at admission.** Sign images in CI with **[Cosign](https://github.com/sigstore/cosign)** (Sigstore, v2+; keyless signing binds signatures to an OIDC identity via Fulcio certs and the Rekor transparency log, so there is no long-lived key to steal), then enforce that only signed images from your registry run:

```bash
# In CI: keyless-sign the image you just pushed (identity from the OIDC token)
cosign sign --yes registry.example.com/team/app@sha256:<digest>
```

```yaml
# Kyverno: reject any image in production that isn't signed by your identity
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-cosign-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaces: ["production"]
      verifyImages:
        - imageReferences: ["registry.example.com/team/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/your-org/*"   # your CI identity
                    issuer: "https://token.actions.githubusercontent.com"
```

Start every policy in **audit/report mode** and only switch to `Enforce` once the report shows no legitimate workload would be blocked. Layer the everyday guardrails too — disallow `:latest`, require `resources.limits`, require `runAsNonRoot`, restrict registries — which double-lock the Pod Security posture from Step 4. Supply-chain depth (SBOMs, SLSA, attestations) is in the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) and [DevSecOps Reference](/DEVSECOPS_REFERENCE.md).

**Checkpoint:** A policy engine is running; at least the image-signature policy plus the core guardrails are live; each started in audit and only moved to enforce after a clean report; and a deliberately unsigned or `:latest` test image is rejected in `production`.

**Watch out:** A validating webhook that fails closed can wedge the cluster if the policy pod is down — scope `failurePolicy`, exclude system namespaces (`kube-system`), and give the engine its own resilient deployment. And image verification is only as good as the signing identity: if any developer laptop can mint the CI identity, the signature proves little — protect the OIDC/CI identity like the admission control it backs.

## Step 8 — Encrypt secrets and pull them from a real secrets manager

Kubernetes Secrets are only base64-encoded, and by default they sit in etcd in plaintext — anyone who reads etcd (or an over-broad `secrets` RBAC verb) reads them all. Close both gaps.

**Encrypt Secrets at rest (self-managed).** Configure an `EncryptionConfiguration` on the API server and prefer a **KMS v2** provider (an external KMS holds the key-encryption key). **KMS v2 is stable since Kubernetes v1.29, and KMS v1 is disabled by default from v1.29** — use v2.

```yaml
# EncryptionConfiguration referenced by kube-apiserver --encryption-provider-config
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          apiVersion: v2
          name: my-kms-provider
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - identity: {}          # read-only fallback for already-written data
```

After enabling it, **re-encrypt existing Secrets** (encryption only applies on write):

```bash
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

On managed clusters this is usually a console/API toggle — enable envelope encryption with your cloud KMS (EKS KMS, GKE application-layer secrets encryption, AKS KMS etcd encryption).

**Get secrets out of manifests entirely.** The stronger pattern is to store nothing sensitive in Git or etcd long-term: use the [External Secrets Operator](https://external-secrets.io/) or the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) to sync from a real vault (HashiCorp Vault or a cloud secrets manager), or Sealed Secrets for GitOps of encrypted-at-rest manifests. The trade-offs are in the [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md).

**Checkpoint:** New and re-encrypted Secrets are encrypted at rest (verify with `etcdctl get` on a self-managed cluster — the stored value is no longer readable base64), a KMS v2 provider or the managed equivalent is active, and application secrets flow from an external manager rather than living hand-written in manifests.

**Watch out:** Encryption at rest does nothing about *access* — a service account with `secrets get/list` still reads decrypted values through the API, which is why Step 5 comes first. And guard the KMS plugin and its socket like the master key it fronts: if the plugin is down, the API server cannot decrypt, and Secrets reads fail cluster-wide.

## Step 9 — Turn on audit logging, add runtime detection, then re-scan and document

Hardening you cannot observe is hardening you cannot prove or defend.

**Audit logging (self-managed).** Point the API server at an audit policy and log sink:

```yaml
# Minimal audit policy — log metadata for most calls, request bodies for sensitive ones
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts"]
  - level: Metadata            # everything else at metadata level
```

Set `--audit-policy-file` and `--audit-log-path` (with `--audit-log-maxage/maxbackup/maxsize`), and ship the log to your SIEM. On managed clusters, enable and export control-plane audit logs from the provider console. Route these into the detection pipeline described in the [SIEM Reference](/SIEM_REFERENCE.md) and build detections for the high-signal events — anonymous requests, `exec` into pods, secret access spikes, RBAC changes, and pods scheduled with `hostPath` or `privileged` ([Detection Rules Reference](/DETECTION_RULES_REFERENCE.md)).

**Runtime detection.** Add an eBPF/syscall runtime sensor — [Falco](https://falco.org/) or [Tetragon](https://tetragon.io/) — to catch what admission control cannot: a shell spawned in a container, an unexpected outbound connection, a write to a sensitive path. This is your last line when a workload is already compromised.

**Re-scan and produce the deliverable.** Re-run the Step 2 tools and diff:

```bash
kube-bench run --targets master,controlplane,node,etcd,policies    # compare FAIL/WARN counts
trivy k8s --report summary                                          # compare critical/high counts
```

Then write the **hardening record**: the before/after kube-bench and Trivy numbers, the controls enforced (PSA profiles, NetworkPolicy coverage, RBAC changes, policy engine, encryption, audit), and an **exception register** — one row per deviation (control, namespace, reason, compensating control, owner, review date). Store it with your change records and schedule the next re-scan.

**Checkpoint:** Audit logs and runtime alerts reach your SIEM; a re-scan shows FAIL/critical counts down from the Step 2 baseline; and a dated hardening record plus exception register exists that a reviewer could read without you in the room.

**Watch out:** A clean scan is a *known* posture, not a safe one — an undocumented 95% is worse than a documented 88%, because the undocumented gap is risk nobody owns. And configuration drifts: without the scheduled re-scan and drift alerting, this whole cluster quietly regresses over the next quarter.

## What good looks like

- Every application namespace enforces Pod Security Admission `restricted`; infrastructure exceptions are `baseline`/`privileged` **with written justification**, not by accident.
- Default-deny NetworkPolicies (ingress *and* egress) exist per namespace, with narrow allow rules — a compromised pod cannot reach the metadata endpoint, other namespaces, or arbitrary egress.
- `cluster-admin` is held only by break-glass and the platform team; no application service account can read cluster-wide Secrets or `exec` into arbitrary pods; API-less pods mount no token.
- An admission policy engine (Kyverno/Gatekeeper or VAP) is live and enforcing, and only Cosign-signed images from approved registries run in production — verified, not assumed.
- Secrets are encrypted at rest with KMS v2 (or the managed equivalent) and sourced from an external manager; the control plane, kubelet, and etcd have cleared their kube-bench findings or logged an exception.
- Audit logs and runtime (Falco/Tetragon) alerts flow to the SIEM with detections built on them, and a dated before/after scan plus an exception register prove the baseline — re-run on a schedule, so drift is caught, not discovered.

## Go deeper

**In this library:**

- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) — the doctrinal base: attack surface, RBAC deep dive, Pod Security Standards, NetworkPolicy patterns, secrets, etcd, and the full hardening checklist this guide sequences.
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md) — the layer below the orchestrator: Dockerfile hardening, image scanning, runtime protection, and container-escape defense.
- [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md) — the discipline overview, learning path, and certifications (CKA → CKS) this procedure lives inside.
- [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md) — Vault, External Secrets Operator, CSI driver, and Sealed Secrets trade-offs behind Step 8.
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) / [DevSecOps Reference](/DEVSECOPS_REFERENCE.md) — SBOMs, SLSA, attestations, and pipeline scanning behind the image-provenance work in Step 7.
- [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) — the shared-responsibility model that decides which control-plane steps you own on managed clusters.
- [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [SIEM Reference](/SIEM_REFERENCE.md) · [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) — least-privilege, log routing, and the detections that consume Step 9's telemetry.

**External:**

- [NSA/CISA Kubernetes Hardening Guide (v1.2)](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — the authoritative government hardening reference; read it before hardening any cluster.
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — the compliance baseline kube-bench checks against; pull the edition matching your version and distribution.
- [kube-bench](https://github.com/aquasecurity/kube-bench) · [Trivy](https://trivy.dev/) — the CIS-benchmark and workload/image scanners from Steps 2 and 9.
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) — Pod Security Standards, admission control, encryption at rest, and RBAC from the source; verify feature and version specifics here.
- [Kyverno](https://kyverno.io/) · [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) · [Sigstore / Cosign](https://docs.sigstore.dev/) · [Falco](https://falco.org/) — the policy-engine, signing, and runtime-detection tools from Steps 7 and 9.

*Guides are procedures, not gospel — Kubernetes features graduate, flags change, and benchmarks trail releases, so verify every command, version, and API against the current official documentation before you run it in production.*

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
