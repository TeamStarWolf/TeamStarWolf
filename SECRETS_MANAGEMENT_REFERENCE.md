# Secrets Management Reference

> Comprehensive reference for secrets management practices, tools, detection, and operations in modern security engineering.

---

## Table of Contents

1. [Secrets Management Fundamentals](#1-secrets-management-fundamentals)
2. [HashiCorp Vault](#2-hashicorp-vault)
3. [CyberArk Conjur](#3-cyberark-conjur)
4. [Secret Detection in Code](#4-secret-detection-in-code)
5. [Cloud-Native Secrets Management](#5-cloud-native-secrets-management)
6. [Kubernetes Secrets Security](#6-kubernetes-secrets-security)
7. [PKI and Certificate Management](#7-pki-and-certificate-management)
8. [SSH Key Management](#8-ssh-key-management)
9. [Secrets in CI/CD Pipelines](#9-secrets-in-cicd-pipelines)
10. [Secrets Management Operations](#10-secrets-management-operations)

---

## 1. Secrets Management Fundamentals

### What Counts as a Secret

A **secret** is any piece of sensitive data that grants access to a system, resource, or encrypted artifact. Secrets require strict lifecycle controls and must never be stored in plaintext.

| Secret Type | Examples | Risk if Exposed |
|---|---|---|
| API Keys | Stripe keys, Google Maps API, OpenAI tokens | Unauthorized API usage, data exfiltration, billing fraud |
| Passwords | Database passwords, admin console credentials | Full system compromise |
| Certificates | TLS/SSL certs, mTLS client certs | Traffic interception, identity spoofing |
| Tokens | OAuth bearer tokens, JWT signing secrets, session tokens | Account takeover, privilege escalation |
| SSH Keys | Private keys, authorized_keys entries | Remote system access, lateral movement |
| Database Credentials | DB usernames/passwords, connection strings | Data breach, ransomware staging |
| Cloud Credentials | AWS access keys, Azure service principal secrets, GCP service account keys | Full cloud account takeover |
| Encryption Keys | AES keys, RSA private keys, HSM key handles | Decryption of protected data |
| Webhook Secrets | GitHub webhook secrets, Slack signing secrets | Request forgery, pipeline manipulation |
| License Keys | Software licenses, hardware dongle codes | IP theft, compliance violation |

### The Secrets Sprawl Problem

**Secrets sprawl** occurs when secrets are duplicated and distributed across multiple locations without central governance. This is endemic in organizations that rely on manual secret distribution.

**Common sprawl locations:**

- **Hardcoded in source code** — The worst form. Secrets committed to git travel in history forever. Even a single commit with an exposed key can be scanned by automated bots within seconds of a public push.
- **Configuration files (.env, application.properties, config.yaml)** — Often not in .gitignore, accidentally committed, or stored insecurely on servers.
- **CI/CD pipeline scripts** — Inline in Jenkinsfiles, GitHub Actions YAML, or GitLab CI YAML as unmasked variables.
- **Log files** — Connection strings, JWT tokens, or API keys logged during startup, errors, or debug sessions.
- **Environment variables** — Visible to all processes on the host; dumped in /proc, crash reports, or debugging tools.
- **Container images** — Baked into Docker layers during build; discoverable via `docker history`.
- **Chat/ticketing systems** — Slack messages, Jira tickets, email chains sharing secrets for "quick fixes."
- **Documentation/wikis** — Confluence pages, Notion docs, Google Docs with example values using real credentials.
- **Backup files** — Database dumps, configuration backups containing plaintext secrets.
- **Infrastructure-as-Code** — Terraform state files, Ansible playbooks, CloudFormation templates.

### Secrets Lifecycle

Proper secrets management requires governing the full lifecycle:

```
Creation → Distribution → Storage → Usage → Rotation → Revocation → Auditing
```

| Phase | Controls | Tools |
|---|---|---|
| **Creation** | Strong randomness (CSPRNG), minimum length/complexity, least privilege scope | OpenSSL, AWS Secrets Manager generation, Vault |
| **Distribution** | Encrypted channels only, pull-not-push model, no email/Slack | Vault Agent, K8s CSI driver, SSM Parameter Store |
| **Storage** | Encrypted at rest, HSM-backed where possible, access-controlled | Vault, AWS KMS, Azure Key Vault, GCP Secret Manager |
| **Usage** | Audit every access, short-lived where possible, scope-limited | Vault leases, IAM conditions, OIDC |
| **Rotation** | Automated rotation, zero-downtime blue-green, TTL enforcement | Vault dynamic secrets, AWS automatic rotation |
| **Revocation** | Immediate revocation on compromise, lease revocation, key deactivation | Vault `vault lease revoke`, AWS disable access key |
| **Auditing** | Immutable access logs, SIEM integration, anomaly detection | Vault audit log, CloudTrail, Azure Monitor |

### Principle of Least Privilege for Secrets

Each application, service, or user should access **only the secrets it needs**, with **only the permissions it requires**, for **only the duration it needs them**.

- **Scope restriction**: A payment service should only read the Stripe API key, not the database master password.
- **Time restriction**: Dynamic credentials with TTLs of minutes/hours rather than static passwords valid indefinitely.
- **Path restriction**: Vault policies restrict access to specific paths (`secret/data/payments/*`).
- **Context restriction**: AWS IAM conditions (`aws:SourceIp`, `aws:RequestedRegion`) limit where secrets can be fetched.
- **Audit accountability**: Each access must be attributable to a specific identity.

### Secrets as the #1 Initial Access Vector

Credential theft and abuse account for the majority of breaches. MITRE ATT&CK T1552 (Unsecured Credentials) and its sub-techniques are among the most exploited:

- **T1552.001** — Credentials in Files (hardcoded configs, .env files)
- **T1552.004** — Private Keys (exposed SSH/TLS private keys)
- **T1552.007** — Container API (Docker socket, container environment variables)
- **T1528** — Steal Application Access Token (OAuth token theft)
- **T1539** — Steal Web Session Cookie

Threat actors actively scan GitHub, GitLab, npm packages, Docker Hub, and public S3 buckets for exposed credentials within minutes of exposure. Tools like **truffleHog**, **GitGuardian**, and custom bots perform continuous scanning.

### Why .env Files Are Dangerous

`.env` files were designed as developer convenience tools for local development, not as secrets management solutions:

1. **Accidentally committed** — Developers forget to add `.env` to `.gitignore`; CI runners clone repos and may log contents.
2. **No encryption** — Plaintext secrets readable by any process with filesystem access.
3. **Shared across environments** — The same `.env` pattern used for dev gets copied to production with production secrets.
4. **No audit trail** — No record of who read the file, when, or why.
5. **No rotation support** — Rotating a secret requires manually updating every `.env` file on every host.
6. **Container leakage** — `docker inspect` reveals environment variables; process listing shows `/proc/<pid>/environ`.

**Mitigation**: Use `.env.example` (no real values) committed to git; fetch real secrets at runtime from a secrets manager.

### Common Exposure Vectors

| Vector | Description | Detection |
|---|---|---|
| **Git history** | Secrets committed and "removed" still exist in git history; `git log -p` or `git show` reveals them | BFG Repo Cleaner scan, gitleaks --no-git |
| **CI/CD logs** | `echo $SECRET` or failed command output prints secrets in build logs | Log masking, ggshield CI integration |
| **Docker layers** | `RUN cp secret.txt /app/` creates an image layer containing the file; `docker history --no-trunc` or layer extraction reveals it | Trivy secret scanning, Hadolint |
| **S3 buckets** | Misconfigured public bucket exposes backup files, config files, or terraform state with embedded secrets | S3 bucket policy audit, Macie sensitive data discovery |
| **npm packages** | Developers accidentally publish `.env` files or private keys inside npm packages | npm audit, Socket.dev, Snyk |
| **API responses** | Verbose error responses or debug endpoints return internal configuration including secrets | DAST scanning, API security testing |
| **Memory dumps** | Crash dumps, core files, and heap snapshots may contain in-memory secrets | Secure memory handling, immediate dump deletion |
| **Kubernetes secrets** | Default base64 encoding (not encryption) means etcd access or RBAC misconfiguration exposes secrets | etcd encryption, RBAC audit |

---

## 2. HashiCorp Vault

### Architecture Overview

HashiCorp Vault is the industry-standard open-source secrets management platform. It provides a unified interface for secrets, encryption-as-a-service, and privileged access management.

**High Availability Architecture:**

```
                    ┌─────────────────┐
    Clients ──────► │  Load Balancer  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         ┌─────────┐   ┌─────────┐   ┌─────────┐
         │ Vault   │   │ Vault   │   │ Vault   │
         │ Active  │   │Standby  │   │Standby  │
         └────┬────┘   └────┬────┘   └────┬────┘
              └─────────────┴─────────────┘
                             │
                    ┌────────▼────────┐
                    │  Integrated     │
                    │  Raft Storage   │
                    │  (or Consul)    │
                    └─────────────────┘
```

- **Active node**: Handles all reads and writes; holds unsealed state.
- **Standby nodes**: Forward requests to active node; take over via leader election if active fails.
- **Integrated Raft storage**: Built-in consensus storage (recommended since Vault 1.4); eliminates Consul dependency.
- **Performance Replication**: Vault Enterprise feature; read-capable secondary clusters for geo-distributed deployments.
- **DR Replication**: Vault Enterprise disaster recovery secondaries.

### Seal/Unseal Mechanics

When Vault starts, it is **sealed** — it knows the storage location but cannot decrypt any data. Unsealing decrypts the master key.

**Shamir's Secret Sharing (default):**
- Master encryption key is split into `N` shares using Shamir's algorithm.
- `K` of `N` shares (threshold) must be provided to reconstruct the master key.
- Example: 5 shares, 3 required — any 3 key holders can unseal.
- Shares are distributed to trusted operators; no single person holds the full key.
- **Risk**: Manual unsealing required on every Vault restart (node reboot, upgrade).

**Auto-Unseal (recommended for production):**
- Vault wraps the master key using an external KMS.
- On startup, Vault calls the KMS to unwrap — no human intervention required.

| Auto-Unseal Provider | Configuration |
|---|---|
| AWS KMS | `seal "awskms" { region = "us-east-1"; kms_key_id = "arn:aws:kms:..." }` |
| Azure Key Vault | `seal "azurekeyvault" { tenant_id = "..."; vault_name = "..." }` |
| GCP Cloud KMS | `seal "gcpckms" { project = "..."; key_ring = "..." }` |
| HSM/PKCS#11 | `seal "pkcs11" { lib = "/usr/lib/softhsm/libsofthsm2.so" }` |

### Secret Engines

Secret engines are plugins that store, generate, or encrypt data. Each is mounted at a path.

**KV v2 (Key-Value store):**
```bash
vault secrets enable -path=secret kv-v2
vault kv put secret/myapp/config db_password=s3cr3t api_key=abc123
vault kv get secret/myapp/config
vault kv get -format=json secret/myapp/config | jq '.data.data'
vault kv list secret/myapp/
vault kv delete secret/myapp/config          # soft delete (keeps versions)
vault kv destroy -versions=1,2 secret/myapp/config  # permanent destroy
vault kv metadata get secret/myapp/config    # version history
```

**Database Secret Engine (dynamic credentials):**
```bash
vault secrets enable database
vault write database/config/my-postgres \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mydb" \
    allowed_roles="app-role" \
    username="vault" \
    password="vault-password"

vault write database/roles/app-role \
    db_name=my-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

vault read database/creds/app-role
# Returns: username=v-app-AbCdEf, password=A1B2C3..., lease_duration=1h
```

**PKI Secret Engine:**
```bash
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write -field=certificate pki/root/generate/internal \
    common_name="example.com" ttl=87600h > CA_cert.crt
vault write pki/config/urls \
    issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
    crl_distribution_points="https://vault.example.com:8200/v1/pki/crl"
vault write pki/roles/example-dot-com \
    allowed_domains="example.com" allow_subdomains=true max_ttl=72h
vault write pki/issue/example-dot-com common_name=app.example.com
```

**SSH Secret Engine:**
```bash
vault secrets enable ssh
# OTP mode
vault write ssh/roles/otp_key_role key_type=otp default_user=ubuntu cidr_list=0.0.0.0/0
# CA signing mode (preferred)
vault write ssh/config/ca generate_signing_key=true
vault write ssh/roles/signed-cert key_type=ca allowed_users="*" \
    default_extensions='{"permit-pty":"","permit-port-forwarding":""}' \
    ttl=1m
```

**Transit Secret Engine (Encryption as a Service):**
```bash
vault secrets enable transit
vault write -f transit/keys/my-key
vault write transit/encrypt/my-key plaintext=$(echo "secret data" | base64)
vault write transit/decrypt/my-key ciphertext="vault:v1:..."
vault write transit/rotate/my-key   # rotate encryption key
vault write transit/keys/my-key/config min_decryption_version=2  # force re-encryption
```

### Authentication Methods

| Auth Method | Use Case | Configuration |
|---|---|---|
| **AppRole** | Machine-to-machine auth; applications | `vault auth enable approle` |
| **Kubernetes** | Pods authenticating via service account JWT | `vault auth enable kubernetes` |
| **AWS IAM** | EC2 instances, Lambda, ECS tasks | `vault auth enable aws` |
| **OIDC** | SSO via Okta, Azure AD, Google | `vault auth enable oidc` |
| **LDAP** | Active Directory authentication | `vault auth enable ldap` |
| **Token** | Direct token-based (for humans/bootstrapping) | Built-in |
| **GitHub** | Developer auth via GitHub token | `vault auth enable github` |

**AppRole configuration:**
```bash
vault auth enable approle
vault write auth/approle/role/myapp \
    secret_id_ttl=10m \
    token_num_uses=10 \
    token_ttl=20m \
    token_max_ttl=30m \
    secret_id_num_uses=40 \
    policies=myapp-policy

vault read auth/approle/role/myapp/role-id      # static; embed in app config
vault write -f auth/approle/role/myapp/secret-id  # dynamic; inject at deploy time
vault write auth/approle/login role_id="..." secret_id="..."
```

**Kubernetes auth:**
```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token
vault write auth/kubernetes/role/myapp \
    bound_service_account_names=myapp-sa \
    bound_service_account_namespaces=production \
    policies=myapp-policy \
    ttl=1h
```

### Policies (HCL Format)

```hcl
# myapp-policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "secret/data/myapp/config" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/app-role" {
  capabilities = ["read"]
}

path "pki/issue/example-dot-com" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/myapp-key" {
  capabilities = ["update"]
}

path "transit/decrypt/myapp-key" {
  capabilities = ["update"]
}

# Deny all other paths
path "*" {
  capabilities = ["deny"]
}
```

```bash
vault policy write myapp-policy myapp-policy.hcl
vault policy read myapp-policy
vault policy list
```

### Dynamic Secrets

Dynamic secrets are generated on-demand with a TTL. They are unique per request and automatically expire.

**Benefits:**
- No long-lived shared credentials
- If leaked, expire quickly
- Full audit trail per credential
- Automatic cleanup

**Supported backends for dynamic secrets:**
- Databases: PostgreSQL, MySQL/MariaDB, MSSQL, Oracle, MongoDB, Cassandra, Elasticsearch
- Cloud: AWS (IAM users/assumed roles/federation tokens), Azure (service principals), GCP (service accounts)
- SSH (OTP and CA-signed certificates)

**Lease management:**
```bash
vault lease renew database/creds/app-role/abc123
vault lease revoke database/creds/app-role/abc123
vault lease revoke -prefix database/creds/app-role/    # revoke all leases under prefix
vault lease revoke -prefix aws/creds/                   # emergency: revoke all AWS creds
vault list sys/leases/lookup/database/creds/app-role/
```

### Vault Agent

Vault Agent runs as a sidecar or daemon to handle auth and secret delivery automatically.

```hcl
# vault-agent.hcl
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role = "myapp"
    }
  }
  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

cache {
  use_auto_auth_token = true
}

listener "tcp" {
  address = "127.0.0.1:8007"
  tls_disable = true
}

template {
  source      = "/etc/vault/config.tmpl"
  destination = "/etc/myapp/config.yaml"
  command     = "systemctl reload myapp"
}
```

```
# config.tmpl — rendered by Vault Agent
database:
  host: postgres.internal
  password: {{ with secret "database/creds/app-role" }}{{ .Data.password }}{{ end }}

api:
  key: {{ with secret "secret/data/myapp/config" }}{{ .Data.data.api_key }}{{ end }}
```

### Vault CSI Provider (Kubernetes)

```yaml
# SecretProviderClass
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-secrets
spec:
  provider: vault
  parameters:
    vaultAddress: "http://vault.vault.svc:8200"
    roleName: "myapp"
    objects: |
      - objectName: "db-password"
        secretPath: "secret/data/myapp/config"
        secretKey: "db_password"
      - objectName: "api-key"
        secretPath: "secret/data/myapp/config"
        secretKey: "api_key"
---
# Pod using CSI volume
spec:
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "vault-secrets"
  containers:
    - volumeMounts:
        - name: secrets-store
          mountPath: "/mnt/secrets"
          readOnly: true
```

### Key Vault Audit Commands

```bash
vault audit enable file file_path=/vault/logs/audit.log
vault audit enable syslog tag="vault" facility="AUTH"
vault audit list
vault audit disable file/
# Audit log format: JSON; includes request path, auth token, response status
# NEVER disable audit without enabling another sink first — Vault blocks requests if no audit device is available
```

---

## 3. CyberArk Conjur

### Overview

**CyberArk Conjur** (open-source: `cyberark/conjur`) is a secrets management solution purpose-built for machine identity and DevOps pipelines. Unlike Vault's imperative configuration, Conjur uses **policy-as-code** (declarative YAML policies).

**Key differentiators:**
- Policy-as-code model — all access control defined in version-controlled YAML
- Strong machine identity focus — built for workloads, containers, CI/CD
- CyberArk Vault integration — bridges DevOps secrets with enterprise PAM
- Conjur Cloud — hosted SaaS offering

**Architecture:**
```
┌──────────────────────────────────────────────────────┐
│                  Conjur Server                       │
│  ┌─────────────┐  ┌──────────┐  ┌─────────────────┐ │
│  │  REST API   │  │ Policy   │  │  Secret Store   │ │
│  │  (HTTPS)    │  │ Engine   │  │  (PostgreSQL)   │ │
│  └─────────────┘  └──────────┘  └─────────────────┘ │
└──────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  ┌─────────────┐    ┌────────────────┐
  │  Conjur CLI │    │  SDKs          │
  │  (conjur)   │    │  Python/Ruby/  │
  └─────────────┘    │  .NET/Java/Go  │
                     └────────────────┘
```

### Policy-as-Code

Conjur policies are YAML files defining the security model: users, groups, hosts (machine identities), variables (secrets), and permissions.

```yaml
# root-policy.yml — top-level policy
- !policy
  id: production
  body:
    - !policy
      id: apps
    - !policy
      id: databases

- !group security-team
- !group developers

- !permit
  role: !group security-team
  privileges: [read, write, execute]
  resource: !policy production
```

```yaml
# apps/myapp-policy.yml
- !host myapp              # machine identity for the application
- !host myapp-staging

- !variable db/password    # the secret
- !variable api/key

- !permit
  role: !host myapp
  privileges: [read, execute]
  resources:
    - !variable db/password
    - !variable api/key
```

```bash
conjur policy load -b root -f root-policy.yml
conjur policy load -b production/apps -f myapp-policy.yml
conjur variable set -i production/apps/db/password -v "s3cr3t_password"
conjur variable get -i production/apps/db/password
conjur list --kind=variable
conjur list --kind=host
```

### REST API

```bash
# Authenticate
CONJUR_TOKEN=$(curl -s -X POST \
  https://conjur.example.com/authn/myorg/host%2Fproduction%2Fapps%2Fmyapp/authenticate \
  -H "Content-Type: text/plain" \
  -d "$API_KEY" | base64)

# Fetch secret
curl -s -H "Authorization: Token token=\"$CONJUR_TOKEN\"" \
  "https://conjur.example.com/secrets/myorg/variable/production%2Fapps%2Fdb%2Fpassword"
```

### Conjur Kubernetes Integration

**Secrets Provider Init Container** (recommended pattern):
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: myapp-sa
      initContainers:
        - name: conjur-secrets-provider
          image: cyberark/conjur-k8s-secrets-provider:latest
          env:
            - name: CONJUR_APPLIANCE_URL
              value: "https://conjur.example.com"
            - name: CONJUR_ACCOUNT
              value: "myorg"
            - name: CONJUR_AUTHN_LOGIN
              value: "host/production/apps/myapp"
            - name: SECRETS_DESTINATION
              value: file
          volumeMounts:
            - mountPath: /conjur/secrets
              name: conjur-secrets
      containers:
        - name: myapp
          volumeMounts:
            - mountPath: /conjur/secrets
              name: conjur-secrets
              readOnly: true
      volumes:
        - name: conjur-secrets
          emptyDir:
            medium: Memory
```

### Conjur OSS vs. DAP vs. Conjur Cloud

| Feature | Conjur OSS | DAP (Dynamic Access Provider) | Conjur Cloud |
|---|---|---|---|
| License | Open source (Apache 2.0) | Enterprise (CyberArk) | SaaS |
| HA | Manual PostgreSQL HA | Built-in clustering | Managed |
| CyberArk Vault integration | No | Yes | Yes |
| SCIM/LDAP | No | Yes | Yes |
| Support | Community | Enterprise | Enterprise |
| Audit/SIEM | Basic | Full | Full |

---

## 4. Secret Detection in Code

### GitGuardian ggshield

ggshield uses GitGuardian's detection engine (300+ secret types) to scan code for exposed secrets.

**Installation and pre-commit setup:**
```bash
pip install ggshield
ggshield auth login                          # authenticate with GitGuardian account

# pre-commit hook (add to .pre-commit-config.yaml)
repos:
  - repo: https://github.com/gitguardian/ggshield
    rev: v1.29.0
    hooks:
      - id: ggshield
        language: python
        entry: ggshield secret scan pre-commit

pre-commit install
```

**Scanning:**
```bash
ggshield secret scan path ./src/             # scan directory
ggshield secret scan repo .                  # full historical scan
ggshield secret scan ci                      # CI environment auto-detection
ggshield secret scan docker myimage:latest   # scan Docker image
ggshield secret scan commit HEAD             # scan latest commit
ggshield secret scan range HEAD~5..HEAD      # scan commit range
```

**GitHub Actions integration:**
```yaml
- name: GitGuardian scan
  uses: GitGuardian/ggshield/actions/secret@v1
  env:
    GITHUB_PUSH_BEFORE_SHA: ${{ github.event.before }}
    GITHUB_PUSH_BASE_SHA: ${{ github.event.base }}
    GITHUB_PULL_BASE_SHA: ${{ github.event.pull_request.base.sha }}
    GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
    GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

**Incident remediation workflow:**
1. Receive alert from GitGuardian dashboard or webhook.
2. Immediately rotate the exposed secret in its source system.
3. Assess blast radius: when was it exposed? Was the repository public? Are there forks?
4. Revoke/deactivate the old credential in all systems.
5. Rewrite git history if public exposure (BFG Repo Cleaner).
6. Update secret manager with new credential.
7. Conduct post-mortem; implement prevention controls.

### detect-secrets (Yelp)

`detect-secrets` works by maintaining a **baseline file** of known false positives, enabling teams to gradually eliminate secrets without alert fatigue.

```bash
pip install detect-secrets

# Generate initial baseline (audit existing secrets)
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline       # review each finding: real or false positive?

# Pre-commit hook
pip install pre-commit
# .pre-commit-config.yaml:
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

# Update baseline after adding known false positives
detect-secrets scan --baseline .secrets.baseline > .secrets.baseline

# Custom plugins
detect-secrets scan --plugin detect_secrets.plugins.high_entropy_string.HexHighEntropyString
```

### Gitleaks

Gitleaks is a SAST tool for detecting hardcoded secrets using regex patterns and entropy analysis.

```toml
# .gitleaks.toml
title = "Custom Gitleaks Config"

[extend]
useDefault = true    # include built-in rules

[[rules]]
id = "internal-api-key"
description = "Internal API Key"
regex = '''INTERNAL-[A-Z0-9]{32}'''
tags = ["key", "internal"]

[[rules]]
id = "database-dsn"
description = "Database DSN"
regex = '''[a-z]+://[^:]+:[^@]+@[^/]+/[a-z]+'''
entropy = 3.5

[allowlist]
paths = [
  "tests/fixtures/",
  "docs/examples/",
]
regexes = [
  '''EXAMPLE_KEY_.*''',
]
```

```bash
gitleaks detect --source . --verbose               # scan working directory
gitleaks detect --source . --log-opts="HEAD~5..HEAD"  # scan recent commits
gitleaks detect --source . --no-git                # scan files without git context
gitleaks protect --staged                          # pre-commit: scan staged files
gitleaks report --report-format=json               # output JSON report
```

**GitHub Actions:**
```yaml
- name: Run Gitleaks
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # required for Enterprise
```

### TruffleHog

TruffleHog uses both regex patterns and **Shannon entropy** analysis to find secrets that may evade pattern-only tools.

```bash
pip install trufflehog3
# or use Docker:
docker run --rm trufflesecurity/trufflehog:latest

trufflehog git https://github.com/org/repo --since-commit HEAD --only-verified
trufflehog git file://./local-repo --json
trufflehog filesystem /path/to/scan
trufflehog docker --image myimage:latest
trufflehog s3 --bucket=my-bucket
trufflehog github --org=myorg --token=$GITHUB_TOKEN --only-verified
```

**Entropy-based detection**: TruffleHog measures the Shannon entropy of strings. High entropy (> 4.5 bits/char) in contexts like variable assignments or config values indicates likely secrets.

### GitHub Secret Scanning

GitHub's native secret scanning automatically detects known secret formats in repositories.

**Push Protection** (blocks pushes containing secrets):
- Enable: Repository Settings → Security → Secret scanning → Push protection
- Supports 200+ secret types from GitHub's partner program
- Developers can bypass with justification (auditable)

**Custom patterns:**
```
# Repository Settings → Security → Secret scanning → Custom patterns
Pattern name: Internal Auth Token
Secret format regex: MYCOMPANY-[A-Za-z0-9]{40}
```

**Partner program**: GitHub notifies service providers (AWS, Stripe, Twilio, etc.) when their token formats are detected, enabling automatic revocation.

### Remediation: Git History Rewriting

After confirming a secret was committed to git history, rewrite history using BFG Repo Cleaner:

```bash
# Install BFG
brew install bfg   # or download bfg.jar

# Create mirror clone
git clone --mirror https://github.com/org/repo.git repo-mirror.git

# Remove file containing secrets from all history
bfg --delete-files .env repo-mirror.git

# Remove specific string from all blobs
echo "s3cr3t_password" > passwords.txt
bfg --replace-text passwords.txt repo-mirror.git

# Clean up and force push
cd repo-mirror.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push

# All collaborators must re-clone; origin is now clean
```

**CRITICAL**: Rotate the secret BEFORE rewriting history. History rewriting removes the secret from the repository but it may already be cached by GitHub, mirrors, forks, or scanners.

---

## 5. Cloud-Native Secrets Management

### AWS Secrets Manager

AWS Secrets Manager provides fully managed secrets storage with built-in rotation.

**Core operations:**
```bash
# Create secret
aws secretsmanager create-secret \
  --name "prod/myapp/database" \
  --description "Production database credentials" \
  --secret-string '{"username":"admin","password":"s3cr3t"}' \
  --kms-key-id "arn:aws:kms:us-east-1:123456789:key/abc-123"

# Retrieve secret
aws secretsmanager get-secret-value \
  --secret-id "prod/myapp/database" \
  --query 'SecretString' --output text | jq .

# Rotate secret (triggers Lambda)
aws secretsmanager rotate-secret \
  --secret-id "prod/myapp/database" \
  --rotation-lambda-arn "arn:aws:lambda:us-east-1:123456789:function:SecretsManagerRDSRotation"

# List secrets
aws secretsmanager list-secrets --query 'SecretList[*].{Name:Name,LastRotated:LastRotatedDate}'

# Tag secret
aws secretsmanager tag-resource \
  --secret-id "prod/myapp/database" \
  --tags Key=Environment,Value=production Key=Team,Value=payments
```

**Automatic rotation for RDS:**
```json
{
  "RotationRules": {
    "AutomaticallyAfterDays": 30
  }
}
```
AWS provides pre-built Lambda rotation functions for:
- Amazon RDS (MySQL, PostgreSQL, Oracle, MSSQL)
- Amazon Redshift
- Amazon DocumentDB
- Amazon ElastiCache

**Cross-account access (resource policy):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT-B:role/MyRole"},
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "*"
  }]
}
```

### AWS Secrets Manager vs. SSM Parameter Store

| Capability | Secrets Manager | SSM Parameter Store |
|---|---|---|
| **Cost** | ~$0.40/secret/month + API calls | Free (Standard); $0.05/10k API calls (Advanced) |
| **Automatic rotation** | Built-in with Lambda | Manual only |
| **Cross-account** | Native resource policy | Via IAM only (complex) |
| **Versioning** | Yes (with staging labels: AWSCURRENT/AWSPENDING) | Yes (with version numbers) |
| **Secret size** | Up to 65,536 bytes | 4KB (Standard), 8KB (Advanced) |
| **Replication** | Cross-region replication | No native replication |
| **Use case** | Database credentials, API keys needing rotation | Configuration, non-sensitive params, small secrets |

### Azure Key Vault

**Access models:**
- **Access Policies** (legacy): Vault-level permissions per identity.
- **Azure RBAC** (recommended): Standard Azure role assignments on the vault or individual secrets.

```bash
# Create Key Vault
az keyvault create --name mykeyvault --resource-group myRG --location eastus \
  --enable-rbac-authorization true \
  --enable-soft-delete true \
  --retention-days 90

# Assign role
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee "user@example.com" \
  --scope "/subscriptions/{sub}/resourceGroups/myRG/providers/Microsoft.KeyVault/vaults/mykeyvault"

# Secret operations
az keyvault secret set --vault-name mykeyvault --name "DbPassword" --value "s3cr3t"
az keyvault secret show --vault-name mykeyvault --name "DbPassword" --query "value" -o tsv
az keyvault secret list --vault-name mykeyvault
az keyvault secret set-attributes --vault-name mykeyvault --name "DbPassword" \
  --expires "2025-12-31T00:00:00Z"

# Purge protection — prevents permanent deletion during retention period
az keyvault update --name mykeyvault --enable-purge-protection true
```

**Managed Identity integration:**
```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()  # uses managed identity in Azure
client = SecretClient(vault_url="https://mykeyvault.vault.azure.net", credential=credential)
secret = client.get_secret("DbPassword")
print(secret.value)
```

**Soft delete + purge protection**: Deleted secrets are retained for the retention period (7-90 days). With purge protection enabled, even vault administrators cannot permanently delete secrets until the retention period expires — critical protection against ransomware.

### GCP Secret Manager

```bash
# Enable API
gcloud services enable secretmanager.googleapis.com

# Create secret
gcloud secrets create my-db-password --replication-policy automatic
echo -n "s3cr3t" | gcloud secrets versions add my-db-password --data-file=-

# Access secret
gcloud secrets versions access latest --secret=my-db-password

# List versions
gcloud secrets versions list my-db-password

# Disable/destroy version
gcloud secrets versions disable 1 --secret=my-db-password
gcloud secrets versions destroy 1 --secret=my-db-password

# Set rotation schedule
gcloud secrets update my-db-password \
  --next-rotation-time="2025-06-01T00:00:00Z" \
  --rotation-period="2592000s"  # 30 days
```

**Workload Identity for GKE access:**
```yaml
# Kubernetes ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-ksa
  namespace: production
  annotations:
    iam.gke.io/gcp-service-account: myapp@my-project.iam.gserviceaccount.com
```

```bash
# Bind GCP SA to K8s SA
gcloud iam service-accounts add-iam-policy-binding \
  myapp@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[production/myapp-ksa]"

# Grant secret access
gcloud secrets add-iam-policy-binding my-db-password \
  --role roles/secretmanager.secretAccessor \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com"
```

**CMEK (Customer-Managed Encryption Keys):**
```bash
gcloud secrets create my-secret \
  --replication-policy user-managed \
  --locations=us-east1,us-west1 \
  --kms-key-name=projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key
```

---

## 6. Kubernetes Secrets Security

### Native Secret Problems

Kubernetes Secrets are only base64-encoded, **not encrypted** by default:

```bash
kubectl get secret my-secret -o yaml
# data.password is base64 — trivially decoded:
kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d
```

**Attack surface:**
1. **etcd access**: Anyone with etcd access reads all secrets in plaintext (unless encryption configured).
2. **Overly permissive RBAC**: `get`/`list`/`watch` on `secrets` resource exposes all secrets in namespace.
3. **Node compromise**: Pods mounting secrets expose files at `/var/run/secrets/` — node-level access reads all mounted secrets.
4. **Container environment variables**: `kubectl exec -- env` reveals all environment-variable secrets.

### etcd Encryption at Rest

```yaml
# /etc/kubernetes/enc/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aesgcm:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}   # fallback for unencrypted secrets during migration
```

```bash
# Apply to kube-apiserver (add flag):
--encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml

# Verify encryption
kubectl get secret my-secret -o yaml  # encrypted in etcd
ETCDCTL_API=3 etcdctl get /registry/secrets/default/my-secret | hexdump -C
# Should show 'k8s:enc:aesgcm:v1:key1:' prefix
```

### External Secrets Operator (ESO)

ESO syncs secrets from external providers into Kubernetes Secrets.

```yaml
# SecretStore — cluster-level connection to AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets
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
---
# ExternalSecret — pull specific secret into K8s
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: myapp-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: ClusterSecretStore
  target:
    name: myapp-secrets          # K8s Secret name
    creationPolicy: Owner
  data:
    - secretKey: db-password     # K8s Secret key
      remoteRef:
        key: prod/myapp/database # AWS Secrets Manager name
        property: password       # JSON field
```

**Supported providers**: AWS Secrets Manager, AWS SSM Parameter Store, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, CyberArk Conjur, Doppler, Infisical, 1Password.

### Vault Agent Injector

The Vault Agent Injector uses a MutatingWebhook to inject sidecar containers that fetch and render secrets.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "myapp"
        vault.hashicorp.com/agent-inject-secret-config.yaml: "secret/data/myapp/config"
        vault.hashicorp.com/agent-inject-template-config.yaml: |
          {{- with secret "secret/data/myapp/config" -}}
          db_password: {{ .Data.data.db_password }}
          api_key: {{ .Data.data.api_key }}
          {{- end }}
        vault.hashicorp.com/agent-pre-populate-only: "false"  # keep refreshing
```

Secrets are written to `/vault/secrets/` as files; the application reads files rather than environment variables.

### CSI Secrets Store Driver

```yaml
# SecretProviderClass for Azure Key Vault
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-kvs
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    clientID: "${AZURE_CLIENT_ID}"
    keyvaultName: mykeyvault
    tenantId: "${AZURE_TENANT_ID}"
    objects: |
      array:
        - |
          objectName: DbPassword
          objectType: secret
          objectVersion: ""
  secretObjects:          # sync to K8s Secret
    - secretName: myapp-secret
      type: Opaque
      data:
        - objectName: DbPassword
          key: db-password
```

### Sealed Secrets (Bitnami)

Sealed Secrets encrypts secrets with the cluster's public key. Only the controller with the private key can decrypt.

```bash
# Install controller
helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system

# Get public key
kubeseal --fetch-cert > public-key.pem

# Create sealed secret
kubectl create secret generic myapp-secret --dry-run=client \
  --from-literal=db-password=s3cr3t -o yaml | \
  kubeseal --cert public-key.pem --format yaml > myapp-sealed-secret.yaml

# Apply — controller decrypts and creates real Secret
kubectl apply -f myapp-sealed-secret.yaml
```

The `SealedSecret` YAML is safe to commit to git — it can only be decrypted by the specific cluster controller.

### SOPS (Secrets OPerationS)

SOPS encrypts YAML/JSON/ENV files for git storage using age, PGP, AWS KMS, Azure Key Vault, or GCP KMS.

```bash
# Install: brew install sops age

# Generate age key
age-keygen -o ~/.config/sops/age/keys.txt

# .sops.yaml configuration
creation_rules:
  - path_regex: k8s/.*\.yaml
    age: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp..."
  - path_regex: infra/.*
    kms: "arn:aws:kms:us-east-1:123456789:key/abc-123"

# Encrypt
sops --encrypt secrets.yaml > secrets.enc.yaml
sops --encrypt --in-place secrets.yaml

# Decrypt
sops --decrypt secrets.enc.yaml
sops --decrypt --in-place secrets.enc.yaml  # for editing

# Edit in place
sops secrets.enc.yaml

# Use with kubectl
sops --decrypt k8s/production-secrets.enc.yaml | kubectl apply -f -
```

---

## 7. PKI and Certificate Management

### Vault PKI Engine

Vault's PKI secret engine creates a full internal certificate authority.

```bash
# Enable PKI engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA (self-signed; valid 10 years)
vault write -field=certificate pki/root/generate/internal \
  common_name="Example Root CA" \
  ttl=87600h > root-ca.crt

# Configure URLs
vault write pki/config/urls \
  issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.example.com:8200/v1/pki/crl" \
  ocsp_servers="https://vault.example.com:8200/v1/pki/ocsp"

# Enable intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate intermediate CSR
vault write -format=json pki_int/intermediate/generate/internal \
  common_name="Example Intermediate CA" | jq -r '.data.csr' > int-ca.csr

# Sign intermediate CSR with root
vault write -format=json pki/root/sign-intermediate \
  csr=@int-ca.csr format=pem_bundle ttl=43800h | \
  jq -r '.data.certificate' > int-ca.crt

# Set signed certificate
vault write pki_int/intermediate/set-signed certificate=@int-ca.crt

# Create issuance role
vault write pki_int/roles/server-role \
  allowed_domains="example.com,internal.example.com" \
  allow_subdomains=true \
  allow_bare_domains=false \
  max_ttl=72h \
  key_bits=2048 \
  key_type=rsa

# Issue certificate
vault write pki_int/issue/server-role common_name="app.example.com" \
  alt_names="app-staging.example.com" \
  ip_sans="10.0.0.5" \
  ttl=24h
```

### cert-manager (Kubernetes)

cert-manager automates certificate issuance and renewal within Kubernetes.

```yaml
# ClusterIssuer — Let's Encrypt via ACME
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: security@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
      - dns01:
          route53:
            region: us-east-1
            hostedZoneID: Z12345678

---
# ClusterIssuer — Vault
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vault-issuer
spec:
  vault:
    server: https://vault.example.com:8200
    path: pki_int/sign/server-role
    auth:
      kubernetes:
        role: cert-manager
        mountPath: /v1/auth/kubernetes
        serviceAccountRef:
          name: cert-manager

---
# Certificate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: myapp-tls
  namespace: production
spec:
  secretName: myapp-tls-secret
  duration: 24h
  renewBefore: 1h
  issuerRef:
    name: vault-issuer
    kind: ClusterIssuer
  commonName: myapp.example.com
  dnsNames:
    - myapp.example.com
    - myapp-internal.example.com
  ipAddresses:
    - 10.0.0.5
```

### PKCS#11 HSM Integration

PKCS#11 is the standard API for hardware security module (HSM) interaction.

```bash
# SoftHSM (testing/dev)
softhsm2-util --init-token --slot 0 --label "VaultToken" --pin 1234 --so-pin 5678
vault server -config=vault-pkcs11.hcl

# vault-pkcs11.hcl seal stanza
seal "pkcs11" {
  lib            = "/usr/lib/softhsm/libsofthsm2.so"
  slot           = "0"
  pin            = "1234"
  key_label      = "vault-key"
  hmac_key_label = "vault-hmac-key"
}
```

**Production HSM vendors**: Thales Luna, AWS CloudHSM, Azure Dedicated HSM, Utimaco, nCipher.

### mTLS Certificate Management for Microservices

Mutual TLS (mTLS) requires both client and server to present certificates — essential for zero-trust microservice communication.

```yaml
# Istio mTLS PeerAuthentication
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # require mTLS for all pod-to-pod communication

---
# Linkerd annotation
metadata:
  annotations:
    linkerd.io/inject: enabled   # automatic mTLS injection
```

**Certificate pinning**: Applications verify certificate fingerprints rather than relying solely on CA chain validation. Mitigates compromised CA attacks but increases operational burden (must update pins before certificate expiry).

### CRL and OCSP

```bash
# Vault CRL management
vault write pki/crl/rotate      # force CRL rotation
vault write pki/crl/config expiry=72h  # CRL validity period

# Revoke certificate
vault write pki/revoke serial_number="39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"

# OCSP stapling configuration (nginx)
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/chain.crt;
resolver 8.8.8.8 8.8.4.4 valid=300s;
```

---

## 8. SSH Key Management

### The SSH Key Sprawl Problem

SSH keys face the same sprawl problems as passwords, compounded by:
- Long-lived keys (years without rotation) that grant persistent access
- Multiple `authorized_keys` entries per server with no expiration
- Keys shared across team members ("the deploy key" everyone uses)
- No centralized inventory of which keys grant access to which systems
- No audit trail for individual SSH sessions when keys are shared

### Vault SSH Secrets Engine

**CA signing mode (recommended)** — short-lived certificates replace static authorized_keys:

```bash
vault secrets enable ssh
vault write ssh/config/ca generate_signing_key=true

# Retrieve public key — add to servers' /etc/ssh/trusted_user_ca_keys
vault read -field=public_key ssh/config/ca > /etc/ssh/trusted-user-ca-keys.pem

# Server sshd_config
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem

# Create signing role
vault write ssh/roles/user-role key_type=ca \
  allowed_users="*" \
  allow_user_certificates=true \
  default_extensions='{"permit-pty":"","permit-port-forwarding":"","permit-agent-forwarding":""}' \
  ttl=5m \
  max_ttl=1h

# Sign user's public key (user requests, valid 5 minutes)
vault write ssh/sign/user-role \
  public_key=@$HOME/.ssh/id_ed25519.pub \
  valid_principals="ubuntu,ec2-user" \
  ttl=5m

# SSH using signed cert
vault write -field=signed_key ssh/sign/user-role public_key=@~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
ssh -i ~/.ssh/id_ed25519 -i ~/.ssh/id_ed25519-cert.pub ubuntu@server
```

**OTP mode** (one-time password, no client cert needed):
```bash
vault write ssh/roles/otp-role key_type=otp default_user=ubuntu cidr_list=10.0.0.0/8
vault ssh -role=otp-role -mode=otp ubuntu@10.0.0.5
```

### SSH CA Setup

```bash
# Generate SSH CA keypair
ssh-keygen -t ed25519 -f ssh_ca -C "SSH Certificate Authority" -N ""

# Configure servers to trust CA
echo "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" >> /etc/ssh/sshd_config
cp ssh_ca.pub /etc/ssh/trusted-user-ca-keys.pem

# Sign user key
ssh-keygen -s ssh_ca -I "user@example.com" -n ubuntu,ec2-user \
  -V +5m ~/.ssh/id_ed25519.pub

# Inspect certificate
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub

# known_hosts CA trust (clients)
echo "@cert-authority *.example.com $(cat ssh_ca.pub)" >> ~/.ssh/known_hosts
```

### Teleport SSH Certificate Issuance

Teleport is a modern SSH/K8s/database access platform using certificate-based authentication with full session recording.

```yaml
# teleport.yaml
auth_service:
  enabled: yes
  cluster_name: "mycluster.example.com"

proxy_service:
  enabled: yes
  public_addr: teleport.example.com:443

ssh_service:
  enabled: yes
  labels:
    env: production
```

```bash
tsh login --proxy=teleport.example.com --user=myuser
tsh ssh ubuntu@production-server
tsh ls    # list accessible servers
tsh recordings ls  # session recordings audit
```

### Detecting and Removing Stale authorized_keys

```bash
# Find all authorized_keys files on a system
find / -name "authorized_keys" -type f 2>/dev/null

# Check last login per key (not directly possible — use last/lastlog for user audit)
last -n 50

# Ansible playbook to audit authorized_keys across fleet
- name: Collect authorized_keys
  hosts: all
  tasks:
    - name: Find authorized_keys
      find:
        paths: /home
        name: authorized_keys
        recurse: yes
      register: auth_keys_files
    - name: Read authorized_keys contents
      slurp:
        src: "{{ item.path }}"
      with_items: "{{ auth_keys_files.files }}"
      register: keys_content
```

**Key rotation procedure:**
1. Generate new key pairs for all service accounts.
2. Add new public keys to authorized_keys on all target systems.
3. Update CI/CD systems, automation tools with new private keys.
4. Monitor for failed logins using old keys (none expected).
5. Remove old public keys from authorized_keys on all systems.
6. Securely delete old private keys.

---

## 9. Secrets in CI/CD Pipelines

### GitHub Actions Secrets

**Repository secrets**: Available to all workflows in the repository.
**Environment secrets**: Scoped to specific environments (require environment protection rules).
**Organization secrets**: Shared across multiple repositories; repository access list controlled.

```yaml
# Using secrets in GitHub Actions
jobs:
  deploy:
    environment: production    # triggers environment protection rules
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          API_KEY: ${{ secrets.API_KEY }}
        run: ./deploy.sh
```

**GitHub Actions OIDC Federation** (eliminates stored credentials):
```yaml
jobs:
  deploy-aws:
    permissions:
      id-token: write    # required for OIDC
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/github-actions-deploy
          aws-region: us-east-1
          # No access key/secret stored — uses OIDC JWT instead

      - name: Deploy to AWS
        run: aws s3 sync ./dist s3://my-bucket/
```

**AWS IAM trust policy for GitHub OIDC:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:environment:production"}
    }
  }]
}
```

### GitLab CI Variables

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  environment: production
  script:
    - echo "DB_PASSWORD is masked in logs"
    - deploy.sh
  variables:
    # Defined in GitLab UI: Settings → CI/CD → Variables
    # - Protected: only available in protected branches/tags
    # - Masked: values never appear in job logs
    # - Environment-scoped: available only to matching environments
```

**Variable types:**
- **Protected**: Only available on protected branches/tags.
- **Masked**: Automatically redacted from job logs (must be base64-safe single-line value).
- **Hidden** (GitLab 17.4+): Cannot be revealed in UI after creation.

### Jenkins Credentials Store

```groovy
// Jenkinsfile — using credentials binding
pipeline {
  agent any
  stages {
    stage('Deploy') {
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'db-credentials',
                          usernameVariable: 'DB_USER',
                          passwordVariable: 'DB_PASS'),
          string(credentialsId: 'api-key', variable: 'API_KEY'),
          sshUserPrivateKey(credentialsId: 'deploy-key',
                           keyFileVariable: 'SSH_KEY',
                           usernameVariable: 'SSH_USER')
        ]) {
          sh './deploy.sh'
          // $DB_PASS is masked in logs as ****
        }
      }
    }
  }
}
```

**Jenkins credential types**: Username/Password, Secret Text, SSH Username with Private Key, Certificate, Docker Host Certificate Authentication.

**HashiCorp Vault Jenkins plugin:**
```groovy
withVault(vaultSecrets: [[path: 'secret/myapp/config', secretValues: [
  [envVar: 'DB_PASSWORD', vaultKey: 'db_password'],
  [envVar: 'API_KEY', vaultKey: 'api_key']
]]]) {
  sh './deploy.sh'
}
```

### Avoiding Secrets in CI Logs

Common patterns that expose secrets in logs:

```bash
# DANGEROUS — prints entire environment including secrets
env | sort
printenv
set -x && deploy.sh   # set -x echoes all commands with variable expansion

# SAFE — explicitly reference only needed vars
echo "Deploying to ${ENVIRONMENT}"   # not secrets
# Set +x before any secret-adjacent commands
{ set +x; echo "Password length: ${#DB_PASSWORD}"; } 2>/dev/null
```

**Log masking in GitHub Actions:**
```bash
# Add value to masked list at runtime
echo "::add-mask::$DYNAMIC_SECRET"
```

### Ephemeral Credentials via OIDC

OIDC federation eliminates long-lived credentials in CI/CD:

| Without OIDC | With OIDC |
|---|---|
| AWS access key stored in GitHub secret | No stored credentials |
| Key never rotates (or rotates rarely) | Token valid 1 hour max |
| If secret leaked, attacker has long-lived access | If token leaked, expires quickly |
| Key requires manual rotation | Automatic — no rotation needed |
| Audit: "GitHub Actions key used" | Audit: "Actions for repo/branch/workflow" |

**OIDC supported platforms**: GitHub Actions → AWS/Azure/GCP/Vault/Terraform Cloud; GitLab CI → AWS/Azure/GCP; CircleCI → AWS/GCP.

---

## 10. Secrets Management Operations

### Rotation Strategies

**Blue-green rotation** (zero downtime):
1. Generate new secret (v2) alongside existing (v1).
2. Add v2 to secrets manager as AWSPENDING (AWS) or new version.
3. Update application to read new secret — verify functionality.
4. Promote v2 to AWSCURRENT.
5. Deprecate v1 (keep briefly for rollback).
6. Revoke v1 after confirmation period.

**Gradual rollout rotation:**
- Deploy new secret to a canary instance first.
- Monitor error rates before rolling out fleet-wide.
- Automated rollback if errors spike.

**Rotation frequency targets:**

| Secret Type | Target Rotation | Automated? |
|---|---|---|
| Database credentials | 30-90 days | Yes (Vault dynamic / AWS rotation Lambda) |
| API keys | 90 days | Partially (depends on vendor API) |
| SSH keys (static) | 180 days → migrate to certificates | Yes (Vault SSH CA) |
| TLS certificates | Auto-renew before expiry (cert-manager) | Yes |
| Cloud IAM keys | Eliminate → use OIDC/instance profiles | N/A |
| Service account passwords | 90 days | Vault dynamic AD plugin |

### Break-Glass Emergency Access

Procedures for emergency access when normal access controls are unavailable:

1. **Vault recovery keys**: Shamir shares stored in physical safe or HSM. Requires quorum of key holders.
2. **Break-glass accounts**: Dedicated accounts with elevated access; credentials in sealed envelopes in physical safe; access triggers alerts.
3. **Emergency access workflow**:
   - Two-person rule: Requires two authorized individuals.
   - Immediate notification to security team.
   - All actions recorded (screen recording, session logging).
   - Post-incident review within 24 hours.
   - Rotate all break-glass credentials after use.

### Secrets Audit Logging

```bash
# Vault audit log — JSON format, one record per request
vault audit enable file file_path=/vault/logs/audit.log
# Log entry fields: time, type (request/response), auth.client_token_accessor,
#                  request.path, request.operation, response.secret.lease_id

# Parse Vault audit logs with jq
cat /vault/logs/audit.log | jq -r '[.time, .auth.display_name, .request.path, .request.operation] | @csv'

# AWS CloudTrail for Secrets Manager
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=secretsmanager.amazonaws.com \
  --start-time 2025-01-01T00:00:00Z \
  --query 'Events[*].{Time:EventTime,User:Username,Event:EventName,Secret:Resources[0].ResourceName}'

# Azure Monitor — Key Vault diagnostic logs
az monitor log-analytics query \
  --workspace my-workspace \
  --analytics-query "AzureDiagnostics | where ResourceType == 'VAULTS' | project TimeGenerated, OperationName, CallerIPAddress, identity_claim_oid_g"
```

### Detecting Secrets Abuse

**Indicators of compromise:**
- Access from unexpected IP geolocation or ASN
- Access outside business hours
- High-volume secret reads in short time window (bulk exfiltration)
- Access to secrets not normally accessed by an application
- API calls from unexpected user agents
- Multiple failed authentication attempts followed by success

**Detection rules (Vault + SIEM):**
```
# Bulk secret access — Sigma-style
title: Vault Bulk Secret Read
detection:
  selection:
    EventType: request
    RequestPath|contains: secret/
    RequestOperation: read
  timeframe: 5m
  condition: selection | count() > 50
```

### Incident Response for Exposed Secrets

**Immediate response (< 30 minutes):**
1. Rotate/revoke the exposed secret immediately in the target system.
2. Identify when exposure occurred (git log, CI log timestamps).
3. Determine if the repository was public during exposure.
4. Check for forks, clones, or mirrors.
5. Search for evidence of exploitation (CloudTrail, access logs, WAF logs).

**Assessment phase (< 4 hours):**
6. Identify blast radius: what systems did the credential grant access to?
7. Review access logs for unauthorized activity using the compromised credential.
8. Notify affected system owners.
9. If PII/PHI involved, initiate breach notification process.

**Remediation:**
10. Rewrite git history (BFG Repo Cleaner) if public exposure.
11. Enable push protection to prevent recurrence.
12. Update secrets manager; audit secrets access policies.
13. Deploy secret scanning to pre-commit hooks.

### Secrets Management Maturity Model

| Level | Description | Characteristics |
|---|---|---|
| **Level 0: Ad-hoc** | No formal secrets management | Hardcoded in code, shared via Slack/email, no rotation, no audit |
| **Level 1: Centralized** | Secrets stored in a vault | Secrets manager deployed, applications pull from vault, basic RBAC |
| **Level 2: Automated Distribution** | Secrets injected automatically | Vault Agent/CSI driver, no manual secret handling, environment secrets |
| **Level 3: Automated Rotation** | Secrets rotate without downtime | Dynamic credentials, auto-rotation for static secrets, regular audits |
| **Level 4: Zero Standing Secrets** | No long-lived credentials exist | OIDC federation for CI/CD, short-lived certs for SSH, dynamic DB creds everywhere |

### Vendor Comparison

| Feature | HashiCorp Vault | CyberArk Conjur | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager | Doppler | Infisical |
|---|---|---|---|---|---|---|---|
| **License** | BUSL 1.1 / Enterprise | Apache 2.0 / Enterprise | Proprietary | Proprietary | Proprietary | Proprietary | MIT / Enterprise |
| **Dynamic Secrets** | Excellent | No | Rotation only | No | No | No | No |
| **K8s Integration** | Excellent (Agent, CSI, ESO) | Good (init container) | ESO | ESO | ESO | ESO | Native |
| **PKI/CA** | Yes (full PKI engine) | No | ACM | Yes | No | No | No |
| **SSH Certificates** | Yes | No | No | No | No | No | No |
| **Encryption-as-Service** | Yes (Transit engine) | No | No | Yes (Key Vault) | Yes (Cloud KMS) | No | No |
| **Policy model** | HCL policies | YAML policy-as-code | IAM policies | Azure RBAC | IAM policies | UI/YAML | UI/YAML |
| **Audit logging** | Comprehensive | Good | CloudTrail | Azure Monitor | Cloud Audit Logs | Good | Good |
| **Open source** | Partial (BUSL) | Yes (OSS core) | No | No | No | No | Yes |
| **SaaS option** | HCP Vault | Conjur Cloud | Native | Native | Native | Native | Yes |
| **Self-hosted** | Yes | Yes | No | No | No | No | Yes |
| **Price model** | Free OSS / per-node Enterprise | Free OSS / Enterprise | Per secret/month | Per operation | Per access/month | Per seat/month | Free / per seat |

### MITRE ATT&CK Credential Access Techniques Mitigated

| ATT&CK ID | Technique | Mitigation |
|---|---|---|
| **T1552** | Unsecured Credentials | Secrets manager, secret scanning, no hardcoded credentials |
| **T1552.001** | Credentials in Files | Pre-commit hooks (gitleaks, detect-secrets), .env file elimination |
| **T1552.004** | Private Keys | Vault SSH CA (ephemeral certs), key rotation, HSM storage |
| **T1552.007** | Container API | Docker security, no secrets in image layers, runtime secret injection |
| **T1528** | Steal Application Access Token | Token rotation, short TTL, OIDC federation (no stored tokens) |
| **T1550** | Use Alternate Authentication Material | mTLS, certificate pinning, CA-signed SSH certs |
| **T1539** | Steal Web Session Cookie | HttpOnly/Secure cookies, short session TTL, session binding |
| **T1555** | Credentials from Password Stores | Vault RBAC, audit logging, HSM-backed key storage |
| **T1606** | Forge Web Credentials | Short-lived JWTs, asymmetric signing keys in HSM, key rotation |
| **T1040** | Network Sniffing (credential capture) | TLS everywhere, mTLS for service-to-service, certificate validation |

**Detection opportunities:**
- **T1552 detection**: Alert on secrets scanning tool findings, monitor for Base64-encoded strings in CI logs.
- **T1528 detection**: OAuth token usage from unexpected geolocation or user agent.
- **Vault-specific**: Monitor for lease revocation spikes (attacker revoking to cover tracks), bulk secret reads, auth from unexpected namespaces.

---

## Quick Reference

### Essential Vault Commands

```bash
vault status                          # cluster status, seal status
vault operator unseal <key>           # manual unseal
vault login -method=ldap username=me  # login
vault token lookup                    # inspect current token
vault token renew                     # extend token TTL
vault token revoke <token>            # revoke token

vault secrets list                    # list all secret engines
vault auth list                       # list auth methods
vault audit list                      # list audit devices

vault kv put secret/app key=value     # write KV secret
vault kv get secret/app               # read KV secret
vault kv patch secret/app newkey=val  # partial update (KV v2)
vault kv rollback -version=2 secret/app  # restore previous version

vault write -f auth/approle/role/myapp/secret-id  # generate SecretID
```

### Secret Scanning Quick Start

```bash
# Install all major scanners
pip install ggshield detect-secrets trufflehog3
brew install gitleaks

# Scan current repo for secrets
gitleaks detect --source . -v
ggshield secret scan repo .
trufflehog git file://. --only-verified
detect-secrets scan > .secrets.baseline

# Set up pre-commit (do all of these)
pip install pre-commit
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
  - repo: https://github.com/gitguardian/ggshield
    rev: v1.29.0
    hooks:
      - id: ggshield
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
EOF
pre-commit install
```

### Kubernetes Secrets Security Checklist

- [ ] etcd encryption at rest enabled (AES-GCM)
- [ ] RBAC: no wildcard `*` on `secrets` resource
- [ ] External Secrets Operator deployed for cloud provider integration
- [ ] Vault Agent Injector or CSI driver for Vault integration
- [ ] No secrets in container environment variables where possible (use file mounts)
- [ ] Sealed Secrets or SOPS for secrets committed to GitOps repo
- [ ] Network policies restricting pod-to-secrets-store traffic
- [ ] Audit logging for `secrets` API group in K8s audit policy
- [ ] Regular review of all ServiceAccount token permissions

---

*Last updated: 2026-04-26 | Part of the TeamStarWolf Cybersecurity Reference Library*
