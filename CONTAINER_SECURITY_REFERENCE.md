# Container & Kubernetes Security Reference

> A comprehensive reference for container and Kubernetes security — Docker hardening, image scanning, SBOM, cluster security, RBAC, network policy, secrets management, OPA/Gatekeeper, Falco, and supply chain security (SLSA/Sigstore).

---

## Table of Contents

1. [Docker Security Hardening](#docker-security-hardening)
2. [Container Image Scanning](#container-image-scanning)
3. [SBOM (Software Bill of Materials)](#sbom-software-bill-of-materials)
4. [Kubernetes Cluster Hardening](#kubernetes-cluster-hardening)
5. [Pod Security](#pod-security)
6. [RBAC](#rbac)
7. [Network Policy](#network-policy)
8. [Secrets Management](#secrets-management)
9. [OPA / Gatekeeper](#opa--gatekeeper)
10. [Falco Runtime Security](#falco-runtime-security)
11. [Supply Chain Security (SLSA / Sigstore)](#supply-chain-security-slsa--sigstore)
12. [Kubernetes Attack Paths (Defense Context)](#kubernetes-attack-paths-defense-context)
13. [Tools Quick Reference](#tools-quick-reference)

---

## Docker Security Hardening

### Dockerfile Best Practices

| Practice | Why It Matters |
|---|---|
| Use non-root `USER` | Prevents root-level access inside the container |
| Minimal base image (distroless / alpine) | Reduces attack surface and CVE exposure |
| Multi-stage builds | Keeps build tools out of the final image |
| No secrets in `ENV` or `ARG` | `docker inspect` and image layers expose these values |
| `.dockerignore` file | Prevents accidentally copying `.git`, `.env`, creds into image |
| Prefer `COPY` over `ADD` | `ADD` auto-extracts archives and fetches URLs — unpredictable behavior |
| Pin base image digest | `FROM ubuntu:22.04@sha256:<digest>` prevents tag mutation attacks |
| Order layers for cache efficiency | Put rarely-changing steps first to maximize build cache |

**Example: hardened Dockerfile**

```dockerfile
# --- Build stage ---
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# --- Final stage (distroless) ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/server /server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/server"]
```

### Docker Daemon Hardening (`/etc/docker/daemon.json`)

```json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp/default.json",
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
```

| Setting | Purpose |
|---|---|
| `userns-remap` | Maps container root to unprivileged host UID |
| `no-new-privileges` | Prevents `setuid`/`setgid` privilege escalation |
| `icc: false` | Disables inter-container communication by default |
| `live-restore` | Keeps containers running during daemon restart |
| `userland-proxy: false` | Uses iptables hairpin NAT instead of proxy process |

### Container Runtime Security Flags

```bash
docker run   --read-only   --no-new-privileges   --cap-drop ALL   --cap-add NET_BIND_SERVICE   --security-opt seccomp=/etc/docker/seccomp/default.json   --security-opt apparmor=docker-default   --memory 256m   --cpus 0.5   --pids-limit 100   --network none   myimage:latest
```

| Flag | Effect |
|---|---|
| `--read-only` | Mounts root filesystem read-only |
| `--no-new-privileges` | Disables privilege escalation via setuid |
| `--cap-drop ALL` | Drops all Linux capabilities |
| `--cap-add NET_BIND_SERVICE` | Re-adds only what is needed |
| `--security-opt seccomp=...` | Applies custom syscall filter |
| `--security-opt apparmor=...` | Applies AppArmor profile |
| `--memory` / `--cpus` | Prevents resource exhaustion DoS |
| `--pids-limit` | Limits fork bombs |

### Docker Bench for Security

```bash
docker run --net host --pid host --userns host   --cap-add audit_control   -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST   -v /var/lib:/var/lib:ro   -v /var/run/docker.sock:/var/run/docker.sock:ro   -v /usr/lib/systemd:/usr/lib/systemd:ro   -v /etc:/etc:ro   --label docker_bench_security   docker/docker-bench-security
```

Checks map to CIS Docker Benchmark sections (API server config, daemon config, container images, runtime, etc.).

### Docker Socket Security

**Risk**: Mounting `/var/run/docker.sock` into a container gives that container full Docker API access — equivalent to root on the host.

**Alternatives**:
- **Rootless Docker**: Run the Docker daemon as a non-root user (`dockerd-rootless-setuptool.sh install`)
- **Podman**: Daemonless, rootless by default; compatible with Dockerfile/docker-compose
- **Socket proxy** (Tecnativa docker-socket-proxy): Expose only required API endpoints
- **gVisor / Kata Containers**: Hardware-virtualized container runtimes for stronger isolation

### Image Signing

**Docker Content Trust (DCT)**

```bash
export DOCKER_CONTENT_TRUST=1
docker push myrepo/myimage:tag   # Automatically signs on push
docker pull myrepo/myimage:tag   # Verifies signature on pull
```

**Cosign (Sigstore)**

```bash
# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key myrepo/myimage:tag

# Verify image
cosign verify --key cosign.pub myrepo/myimage:tag

# Keyless signing (GitHub Actions OIDC)
cosign sign --identity-token=$(cat $ACTIONS_ID_TOKEN_REQUEST_TOKEN) myrepo/myimage:tag
```

---

## Container Image Scanning

### Trivy

```bash
# Basic scan
trivy image nginx:latest

# Filter by severity
trivy image --severity HIGH,CRITICAL nginx:latest

# JSON output
trivy image --format json --output results.json nginx:latest

# Skip unfixed vulnerabilities
trivy image --ignore-unfixed nginx:latest

# Scan filesystem / repo
trivy fs .

# Scan IaC (Terraform, Helm, Kubernetes manifests)
trivy config ./manifests/

# SBOM generation
trivy image --format spdx-json --output sbom.json nginx:latest

# GitHub Actions with SARIF output
trivy image --format sarif --output trivy-results.sarif nginx:latest
```

**GitHub Actions integration:**

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myrepo/myimage:${{ github.sha }}
    format: sarif
    output: trivy-results.sarif
    severity: HIGH,CRITICAL
    ignore-unfixed: true

- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy-results.sarif
```

### Grype

```bash
# Scan image
grype image nginx:latest

# Scan SBOM
grype sbom:./sbom.spdx.json

# Filter by severity
grype nginx:latest --fail-on high

# Config file: .grype.yaml
```

**.grype.yaml example:**

```yaml
ignore:
  - vulnerability: CVE-2021-XXXXX
    reason: "Not exploitable in our environment"
fail-on-severity: high
output: json
```

### Snyk

```bash
# Test container image
snyk container test nginx:latest

# Monitor (continuous in Snyk dashboard)
snyk container monitor nginx:latest --project-name=nginx

# With Dockerfile for base image recommendations
snyk container test nginx:latest --file=Dockerfile
```

### Clair

Clair is an open-source static analysis tool that indexes container images and matches against CVE databases.

- **Architecture**: Clair API server + PostgreSQL + notifier
- **`clairctl`**: CLI for submitting images and retrieving reports
- **Harbor integration**: Enable Clair as the scanner in Harbor registry settings

```bash
clairctl report nginx:latest
```

### Registry Native Scanning

| Registry | Enablement |
|---|---|
| AWS ECR | Enable "Enhanced scanning" (Inspector v2) in console or: `aws ecr put-registry-scanning-configuration` |
| Azure ACR | Enable Microsoft Defender for Containers; view findings in Defender portal |
| GCR / Artifact Registry | Enable Container Analysis API; findings appear in Security Insights tab |

### CI/CD Pipeline Pattern

```
Build image → Scan (Trivy/Grype) → Fail on HIGH/CRITICAL → Push (if pass) → Sign (Cosign) → Deploy
```

---

## SBOM (Software Bill of Materials)

### Why SBOMs Matter

- **Executive Order 14028** (US, 2021) mandates SBOMs for software sold to federal government
- **NTIA Minimum Elements**: Supplier name, component name, version, unique identifiers, dependency relationships, SBOM author, timestamp
- SBOMs enable rapid CVE response — know immediately which products contain a vulnerable library

### Syft

```bash
# Scan image → SPDX JSON
syft image nginx:latest -o spdx-json > sbom.spdx.json

# Scan image → CycloneDX JSON
syft image nginx:latest -o cyclonedx-json > sbom.cdx.json

# Scan local directory
syft dir:. -o spdx-json > sbom.spdx.json

# Scan filesystem
syft packages /path/to/rootfs -o table
```

### SPDX Format Overview

- **SPDX** (Software Package Data Exchange): Linux Foundation standard, ISO/IEC 5962:2021
- Key fields: `SPDXID`, `PackageName`, `PackageVersion`, `PackageLicenseConcluded`, `PackageChecksum`
- Formats: `.spdx` (tag-value), `.spdx.json`, `.spdx.yaml`, `.spdx.rdf`

### CycloneDX Format Overview

- **CycloneDX**: OWASP standard, broader scope (VEX, SaaSBOM, OBOM)
- Key fields: `bom-ref`, `name`, `version`, `purl` (Package URL), `hashes`, `licenses`
- Formats: XML, JSON, Protocol Buffers

### SBOM in CI/CD Pipeline

```yaml
- name: Generate SBOM
  run: syft image myrepo/myimage:${{ github.sha }} -o spdx-json > sbom.spdx.json

- name: Attest SBOM with Cosign
  run: |
    cosign attest --predicate sbom.spdx.json       --type spdxjson       myrepo/myimage:${{ github.sha }}

- name: Scan SBOM with Grype
  run: grype sbom:sbom.spdx.json --fail-on high
```

---

## Kubernetes Cluster Hardening

### CIS Kubernetes Benchmark Key Areas

| Section | Focus |
|---|---|
| 1. Control Plane Components | API server flags, controller manager, scheduler |
| 2. etcd | TLS, access control, encryption at rest |
| 3. Control Plane Configuration | Logging, audit policy |
| 4. Worker Nodes | Kubelet configuration, kubelet file permissions |
| 5. Policies | RBAC, Pod Security, Network Policies |

### kube-bench

```bash
# Run all checks
kube-bench run --targets master,node,etcd,policies

# Run as Pod in cluster
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Run specific section
kube-bench run --check 1.2.1,1.2.2
```

### API Server Hardening Flags

```yaml
# kube-apiserver manifest flags
--anonymous-auth=false
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--enable-admission-plugins=NodeRestriction,PodSecurity,EventRateLimit
--tls-min-version=VersionTLS12
--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
--authorization-mode=Node,RBAC
--insecure-port=0
--profiling=false
--request-timeout=300s
```

### etcd Encryption at Rest

```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}   # Fallback (unencrypted) — remove after migration
```

Apply with `--encryption-provider-config=/etc/kubernetes/encryption-config.yaml` on the API server.

```bash
# Verify encryption
kubectl get secret mysecret -o yaml
# "data" values should be opaque; etcd raw value starts with "k8s:enc:aescbc:v1:key1:"
```

### Audit Policy

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services", "services/status"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Metadata
    omitStages: ["RequestReceived"]
```

### Kubeconfig Security

```bash
# List contexts
kubectl config get-contexts

# Switch context
kubectl config use-context prod-cluster

# View effective permissions
kubectl auth can-i --list

# Scan kubeconfigs for secrets
trufflehog filesystem ~/.kube/
```

---

## Pod Security

### Pod Security Standards

| Standard | Description | Use Case |
|---|---|---|
| **Privileged** | No restrictions | System-level workloads (CNI plugins, CSI drivers) |
| **Baseline** | Prevents known privilege escalations | General application workloads |
| **Restricted** | Heavily restricted, follows best practices | High-security workloads |

### Pod Security Admission Controller

```bash
# Apply namespace labels
kubectl label namespace production   pod-security.kubernetes.io/enforce=restricted   pod-security.kubernetes.io/enforce-version=latest   pod-security.kubernetes.io/audit=restricted   pod-security.kubernetes.io/warn=restricted
```

### SecurityContext Fields

```yaml
# Pod-level SecurityContext
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
        seccompProfile:
          type: RuntimeDefault
        # AppArmor (via annotation on older k8s)
      # annotation: container.apparmor.security.beta.kubernetes.io/app: runtime/default
```

### Example: Hardened Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
  namespace: production
spec:
  serviceAccountName: hardened-app-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myrepo/myimage:v1.2.3@sha256:<digest>
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "128Mi"
        requests:
          cpu: "250m"
          memory: "64Mi"
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
```

---

## RBAC

### ClusterRole vs Role

| Resource | Scope |
|---|---|
| `Role` | Single namespace |
| `ClusterRole` | Cluster-wide (or reusable across namespaces) |
| `RoleBinding` | Binds Role or ClusterRole within a namespace |
| `ClusterRoleBinding` | Binds ClusterRole cluster-wide |

### Principle of Least Privilege

- Never assign `cluster-admin` to workloads or developers unless strictly required
- Avoid wildcard verbs (`*`) and resources (`*`)
- Scope bindings to specific namespaces when possible
- Use `RoleBinding` referencing a `ClusterRole` to grant cluster-wide role definition with namespace-scoped binding

### Dangerous Permissions

| Permission | Risk |
|---|---|
| `get secrets` (cluster-wide) | Read all Kubernetes Secrets including credentials |
| `create pods` | Can mount hostPath, run privileged containers, escape to host |
| `create/patch deployments` | Can inject malicious containers into workloads |
| `bind clusterroles` | Can grant `cluster-admin` to any subject |
| `impersonate` | Can impersonate any user/service account |
| `exec` on pods | Interactive shell access to containers |
| `create tokenrequests` | Generate arbitrary SA tokens |
| `patch nodes` | Can taint/drain nodes or modify labels |

### RBAC Audit Tools

```bash
# Check what you can do
kubectl auth can-i --list
kubectl auth can-i --list --namespace kube-system

# Check specific permission
kubectl auth can-i get secrets --namespace production

# rakkess: matrix of permissions for current user
kubectl krew install rakkess
kubectl rakkess

# rbac-police: evaluate RBAC policies
rbac-police eval -f rules/

# rback: visualize RBAC
kubectl krew install rbac-view
kubectl rbac-view
```

### Service Account Security

```yaml
# Disable auto-mount (default: true — disables for all pods using this SA)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: production
automountServiceAccountToken: false

---
# Per-pod override (if SA-level is not set)
spec:
  automountServiceAccountToken: false
```

**Best practices**:
- Create dedicated service accounts per workload
- Never use the `default` service account for application workloads
- Project service account tokens with bounded lifetimes (`serviceAccountToken` volume projection)

---

## Network Policy

### Default Deny All (Ingress + Egress)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}    # Selects all pods in namespace
  policyTypes:
    - Ingress
    - Egress
```

### Allow Specific Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
```

### Allow DNS Egress (Required for Most Workloads)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Calico GlobalNetworkPolicy (Cluster-Wide Default Deny)

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: "all()"
  types:
    - Ingress
    - Egress
  ingress:
    - action: Log
    - action: Deny
  egress:
    - action: Log
    - action: Deny
```

### CNI Comparison

| CNI | NetworkPolicy Support | eBPF | Encryption | Notes |
|---|---|---|---|---|
| **Calico** | Full (+ GlobalNetworkPolicy) | Yes (eBPF mode) | WireGuard | Widely used, feature-rich |
| **Cilium** | Full (+ CiliumNetworkPolicy) | Native eBPF | WireGuard | Best observability (Hubble) |
| **Flannel** | None (overlay only) | No | No | Simple, not suitable for segmentation |
| **Weave** | Full | No | Yes (NaCl) | No longer actively maintained |

---

## Secrets Management

### Kubernetes Secrets Encryption at Rest

See [etcd Encryption at Rest](#etcd-encryption-at-rest) above. Use AES-CBC or AES-GCM providers.

### External Secrets Operator

Syncs secrets from external stores (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, GCP Secret Manager) into Kubernetes Secrets.

```yaml
# ExternalSecret CRD
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: db-credentials
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: prod/db/credentials
        property: password
```

```yaml
# ClusterSecretStore for AWS
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-manager
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
            namespace: external-secrets
```

### Sealed Secrets (Bitnami)

Encrypts secrets client-side so they can be safely committed to Git.

```bash
# Install kubeseal CLI
brew install kubeseal

# Encrypt a secret
kubectl create secret generic db-pass   --from-literal=password=S3cr3t!   --dry-run=client -o yaml |   kubeseal --format yaml > sealed-secret.yaml

# Apply to cluster (controller decrypts and creates Secret)
kubectl apply -f sealed-secret.yaml
```

### HashiCorp Vault Agent Injector

Injects secrets as files or environment variables via sidecar, using pod annotations:

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "my-app"
  vault.hashicorp.com/agent-inject-secret-config.txt: "secret/data/my-app/config"
  vault.hashicorp.com/agent-inject-template-config.txt: |
    {{- with secret "secret/data/my-app/config" -}}
    DB_PASSWORD={{ .Data.data.db_password }}
    {{- end }}
```

### Avoiding Secrets in Environment Variables

**Problem**: Environment variables are visible via `kubectl describe pod`, `/proc/*/environ`, and crash dumps.

**Alternatives**:
- Mount secrets as files (`volumeMounts` with `secretKeyRef`)
- Use Vault Agent Injector or CSI Secrets Store driver
- Use workload identity (IRSA, Workload Identity) to avoid secrets entirely

---

## OPA / Gatekeeper

### Architecture

- **OPA Gatekeeper** runs as a `ValidatingWebhookConfiguration` + `MutatingWebhookConfiguration`
- **Audit controller** periodically re-evaluates existing resources
- **ConstraintTemplate**: Defines a new CRD using Rego policy
- **Constraint**: An instance of a ConstraintTemplate with parameters

### ConstraintTemplate Example: Require Resource Limits

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlimits
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLimits
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlimits
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container '%v' is missing CPU limits", [container.name])
        }
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container '%v' is missing memory limits", [container.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLimits
metadata:
  name: require-resource-limits
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]
```

### Constraint: Disallow Privileged Containers

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snoprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sNoPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snoprivilegedcontainer
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged container not allowed: '%v'", [container.name])
        }
```

### Constraint: Require Specific Labels

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          required := {label | label := input.parameters.labels[_]}
          provided := {label | input.review.object.metadata.labels[label]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-team-label
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet"]
  parameters:
    labels: ["team", "app", "environment"]
```

### Conftest (Policy as Code in CI)

```bash
# Install
brew install conftest

# Test Kubernetes manifests
conftest test pod.yaml -p policy/

# Test with specific namespace
conftest test deployment.yaml --namespace kubernetes

# Example policy file: policy/deny_privileged.rego
```

```rego
# policy/deny_privileged.rego
package kubernetes

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Privileged container '%v' denied", [container.name])
}
```

---

## Falco Runtime Security

### Architecture

- **Kernel module** or **eBPF probe** (preferred): Intercepts system calls at kernel level
- **libs**: Shared libraries abstracting system call capture
- **Engine**: Matches captured events against rules
- **Outputs**: stdout, file, gRPC, webhook (Falco Sidekick)

### Key Default Rules

| Rule | Detection |
|---|---|
| `Terminal shell in container` | `execve` of shell process in a running container |
| `Privilege escalation via setuid binary` | setuid/setgid binary execution |
| `Write below etc` | Any write to `/etc/` in a container |
| `Read sensitive file untrusted` | Reads of `/etc/shadow`, `/etc/passwd`, SSH keys |
| `Unexpected outbound connection` | Container making unexpected network connections |
| `Contact K8s API server from container` | App connecting to `kubernetes.default.svc` |
| `Launch Privileged Container` | Container started with `privileged: true` |
| `Mount Sensitive Host Paths` | `hostPath` volumes mounting sensitive host dirs |

### Custom Falco Rule Example

```yaml
- rule: Detect Crypto Mining
  desc: Detects potential crypto mining activity based on known pool domains
  condition: >
    (outbound) and
    (fd.sip.name contains "pool.minergate.com" or
     fd.sip.name contains "xmrpool.eu" or
     proc.name in (xmrig, minerd, ccminer))
  output: >
    Crypto mining activity detected
    (command=%proc.cmdline container=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [network, mitre_execution]

- rule: Sensitive File Access in Container
  desc: Detects access to sensitive files within a container
  condition: >
    open_read and
    container and
    (fd.name startswith /etc/ssh/ or
     fd.name = /root/.ssh/authorized_keys or
     fd.name = /etc/shadow)
  output: >
    Sensitive file read in container
    (file=%fd.name command=%proc.cmdline container=%container.id)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
```

### Falco Sidekick

Routes Falco alerts to multiple outputs:

```bash
# Install with Helm
helm install falco-sidekick falcosecurity/falcosidekick   --set config.slack.webhookurl=https://hooks.slack.com/...   --set config.pagerduty.routingKey=...   --set config.elasticsearch.hostport=http://elastic:9200
```

Supported outputs: Slack, Teams, PagerDuty, Datadog, Elasticsearch, Loki, Webhook, AWS Lambda, GCP Pub/Sub, NATS, and more.

### falcoctl Rule Management

```bash
# Search available rules
falcoctl artifact search falco-rules

# Install/update official rules
falcoctl artifact install falco-rules:latest

# Follow rules updates automatically
falcoctl artifact follow falco-rules
```

---

## Supply Chain Security (SLSA / Sigstore)

### SLSA Framework Levels

| Level | Requirements | Benefits |
|---|---|---|
| **SLSA 1** | Documented build process | Provenance exists |
| **SLSA 2** | Version-controlled source, hosted build | Provenance from build service |
| **SLSA 3** | Hardened build service, verified source | Resistant to build compromises |
| **SLSA 4** | Two-party review, hermetic build | Highest supply chain integrity |

### Sigstore Ecosystem

| Component | Purpose |
|---|---|
| **Cosign** | Sign and verify container images and artifacts |
| **Rekor** | Immutable, append-only transparency log for signatures |
| **Fulcio** | OIDC-based certificate authority for keyless signing |
| **Gitsign** | Sign git commits using OIDC identity |

### Cosign Commands

```bash
# Generate key pair
cosign generate-key-pair

# Sign image with key
cosign sign --key cosign.key myrepo/myimage:tag

# Verify with public key
cosign verify --key cosign.pub myrepo/myimage:tag

# Keyless signing (uses OIDC — ideal for CI)
# In GitHub Actions:
cosign sign   --rekor-url https://rekor.sigstore.dev   myrepo/myimage:${{ github.sha }}

# Verify keyless
cosign verify   --rekor-url https://rekor.sigstore.dev   --certificate-identity-regexp="https://github.com/myorg/myrepo.*"   --certificate-oidc-issuer=https://token.actions.githubusercontent.com   myrepo/myimage:tag

# Attach SBOM attestation
cosign attest   --predicate sbom.spdx.json   --type spdxjson   --key cosign.key   myrepo/myimage:tag

# Verify attestation
cosign verify-attestation   --key cosign.pub   --type spdxjson   myrepo/myimage:tag
```

### SLSA Provenance Attestation (GitHub Actions)

```yaml
name: Build and Attest
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myrepo/myimage:${{ github.sha }} .

      - name: Push image
        run: docker push myrepo/myimage:${{ github.sha }}

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign image (keyless OIDC)
        run: |
          cosign sign             --rekor-url https://rekor.sigstore.dev             myrepo/myimage:${{ github.sha }}

      - name: Generate SBOM
        run: syft image myrepo/myimage:${{ github.sha }} -o spdx-json > sbom.json

      - name: Attest SBOM
        run: |
          cosign attest             --predicate sbom.json             --type spdxjson             myrepo/myimage:${{ github.sha }}
```

### Gitsign

```bash
# Install
go install sigstore/gitsign@latest

# Configure git to use gitsign
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global commit.gpgsign true

# Verify commits
gitsign verify --certificate-identity-regexp=".*" HEAD
```

---

## Kubernetes Attack Paths (Defense Context)

### Container Escape Techniques to Defend Against

| Technique | Condition | Defense |
|---|---|---|
| Privileged container escape | `securityContext.privileged: true` | Pod Security Admission (Restricted), Gatekeeper policy |
| hostPID / hostNetwork abuse | `hostPID: true` or `hostNetwork: true` | Pod Security Standards block these in Restricted |
| Writable hostPath mount | `hostPath` volume writable | Limit hostPath usage via OPA/Gatekeeper |
| docker.sock mount | `/var/run/docker.sock` as volume | Never allow in production, detect with Falco |
| Token theft | SA token in `/var/run/secrets/` | Disable auto-mount, use projected tokens |
| SYS_PTRACE / SYS_ADMIN | Dangerous capabilities | `capabilities.drop: ["ALL"]` + allowlist only required |

### K8s Privilege Escalation Paths

```
SA Token Abuse:
  Compromised Pod → Read SA Token → kubectl with token → enumerate permissions → escalate

RBAC Misconfiguration:
  Dev SA has "create pods" → deploy privileged pod → hostPath /  → host root access

Secrets Access:
  SA with get/list secrets → read cloud credentials → AWS/GCP API access → cloud pwned

Node-to-cluster pivot:
  Node compromise → kubelet client cert → API server → list all pods → extract tokens
```

### Detection: API Server Audit Policy

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all secret access at RequestResponse level
  - level: RequestResponse
    verbs: ["get", "list", "watch"]
    resources:
      - group: ""
        resources: ["secrets"]
  # Log exec sessions
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach"]
  # Log RBAC changes
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
```

### kube-hunter (Self-Assessment)

```bash
# Run from outside cluster (remote scanning)
kube-hunter --remote <cluster-ip>

# Run as Pod inside cluster
kubectl run kube-hunter --image=aquasec/kube-hunter --restart=Never -- --pod

# Network-only scan
kube-hunter --network 10.0.0.0/24
```

---

## Tools Quick Reference

| Tool | Category | Key Command / Use |
|---|---|---|
| **Trivy** | Image scanning + IaC | `trivy image nginx:latest` |
| **Grype** | Image / SBOM scanning | `grype image nginx:latest` |
| **Syft** | SBOM generation | `syft image nginx:latest -o spdx-json` |
| **Snyk** | Commercial scanning | `snyk container test nginx:latest` |
| **kube-bench** | CIS benchmark | `kube-bench run --targets master,node` |
| **Falco** | Runtime security | Rules engine on syscalls / eBPF |
| **OPA Gatekeeper** | Admission control | ConstraintTemplate + Constraint CRDs |
| **Sealed Secrets** | GitOps secrets | `kubeseal --format yaml` |
| **External Secrets Operator** | Secrets sync | ExternalSecret CRD → Vault/ASM/AKV |
| **Cosign** | Image signing | `cosign sign --key cosign.key image:tag` |
| **Conftest** | Policy as code CI | `conftest test pod.yaml -p policy/` |
| **rbac-police** | RBAC analysis | Evaluates RBAC rules against policies |
| **kube-hunter** | Pen testing | `kube-hunter --remote <ip>` |
| **Polaris** | Best practices audit | `polaris audit --audit-path ./manifests` |
| **Kubescape** | Multi-framework scan | `kubescape scan framework NSA` |
| **Rakkess** | RBAC matrix | `kubectl rakkess` |
| **Docker Bench** | Docker CIS check | docker-bench-security container |
| **Falco Sidekick** | Alert routing | Routes Falco events to Slack/PD/etc. |
| **Rekor** | Transparency log | `rekor-cli get --uuid <uuid>` |

---

## Quick-Start Security Checklist

### Docker
- [ ] Use non-root `USER` in Dockerfile
- [ ] Use distroless or minimal base image, pin by digest
- [ ] Enable Docker Content Trust (`DOCKER_CONTENT_TRUST=1`)
- [ ] Run Docker Bench for Security
- [ ] Never mount `/var/run/docker.sock` in production
- [ ] Scan images with Trivy before pushing
- [ ] Generate and attest SBOM with Syft + Cosign

### Kubernetes
- [ ] Run kube-bench against CIS benchmark
- [ ] Enable Pod Security Admission (Restricted for production namespaces)
- [ ] Apply default-deny NetworkPolicy in all namespaces
- [ ] Encrypt Secrets at rest in etcd
- [ ] Disable `automountServiceAccountToken` on workload SAs
- [ ] Install OPA Gatekeeper with policies for resource limits, no-privileged, required labels
- [ ] Deploy Falco for runtime detection
- [ ] Enable API server audit logging
- [ ] Use External Secrets Operator or Vault Agent instead of plain Secrets
- [ ] Sign all images with Cosign; verify on admission (Gatekeeper + cosign policy)
- [ ] Run kube-hunter periodically for self-assessment
- [ ] Scan Helm charts and manifests with Trivy / Kubescape / Polaris

---

*Last updated: 2026-04-21 | Part of the [TeamStarWolf Cybersecurity Reference Library](README.md)*
