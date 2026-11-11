# kubectl Command Reference

`kubectl` is the command-line client for Kubernetes. It sends requests to the API server to inspect and change cluster state. This page covers the read, apply, debug, and scaling commands engineers use most, plus the context and namespace handling that keeps you on the right cluster. Security notes focus on RBAC, Secrets, and audit-worthy actions.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Platform engineers, administrators and security teams who operate Kubernetes clusters

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (876 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the kubectl commands for a task at hand, you want a common workflow to copy and adapt, you are looking up a flag or option worth knowing, or you need the security notes that go with them

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Core commands](#core-commands), [Common workflows](#common-workflows), [Security notes](#security-notes)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Docker Command Reference](/commands/docker.md), [Terraform Command Reference](/commands/terraform.md), [curl Command Reference](/commands/curl.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it runs

`kubectl` runs on your workstation or a CI runner and authenticates to the Kubernetes API server. It reads connection details, credentials, and contexts from a kubeconfig file, by default `~/.kube/config`. A context binds a cluster, a user, and a namespace. Every command resolves against the current context unless you override it, so confirming your context before a destructive command is a habit worth keeping.

## Core commands

Read cluster state:

```bash
kubectl get pods -n web
kubectl get all -A
kubectl describe pod api-7d9 -n web
kubectl logs -f api-7d9 -n web
kubectl top pods -n web
```

| Command | Purpose |
| --- | --- |
| `kubectl get` | List resources (`-A` for all namespaces) |
| `kubectl describe` | Show detailed state and recent events |
| `kubectl logs` | Stream or print container logs |
| `kubectl top` | Show CPU and memory usage (needs metrics-server) |
| `kubectl auth can-i` | Check whether an action is permitted |

Change and create resources:

```bash
kubectl apply -f deployment.yaml
kubectl create namespace staging
kubectl edit deployment api -n web
kubectl delete -f deployment.yaml
```

| Command | Purpose |
| --- | --- |
| `kubectl apply` | Declaratively create or update from a manifest |
| `kubectl create` | Imperatively create a resource |
| `kubectl edit` | Open a resource in your editor and apply changes |
| `kubectl delete` | Remove resources by name, label, or file |

Operate workloads:

```bash
kubectl scale deployment api --replicas=5 -n web
kubectl rollout status deployment api -n web
kubectl rollout undo deployment api -n web
kubectl exec -it api-7d9 -n web -- sh
kubectl port-forward svc/api 8080:80 -n web
```

Manage contexts and namespaces:

```bash
kubectl config get-contexts
kubectl config use-context prod-cluster
kubectl config set-context --current --namespace=web
```

## Common workflows

Deploy a change and watch it roll out:

```bash
kubectl config use-context staging-cluster
kubectl apply -f deployment.yaml
kubectl rollout status deployment api -n web
kubectl get pods -n web -w
```

Diagnose a crash-looping pod:

```bash
kubectl get pods -n web
kubectl describe pod api-7d9 -n web
kubectl logs api-7d9 -n web --previous
kubectl get events -n web --sort-by=.lastTimestamp
```

Reach a cluster-internal service from your laptop:

```bash
kubectl get svc -n web
kubectl port-forward svc/api 8080:80 -n web
curl http://localhost:8080/healthz
```

Confirm your permissions before acting:

```bash
kubectl auth can-i create deployments -n web
kubectl auth can-i delete pods --all-namespaces
kubectl auth can-i '*' '*'
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `-n`, `--namespace` | Target a specific namespace |
| `-A`, `--all-namespaces` | Operate across every namespace |
| `-o yaml` / `-o json` | Change output format |
| `-o wide` | Add extra columns such as node and IP |
| `-l`, `--selector` | Filter by label, for example `-l app=api` |
| `-w`, `--watch` | Stream changes as they happen |
| `--dry-run=client` | Render without sending to the server |
| `-f`, `--filename` | Operate on a manifest file or directory |
| `--context` | Override the current context for one command |
| `--previous` | Logs from a container's prior instance |

## Security relevance

This section is the threat-facing view of `kubectl`: how an attacker turns API access into cluster control, and what the audit log records when they do. The RBAC and hardening guidance is in the "Security notes" section that follows.

### Where it appears

- Enumeration with a stolen kubeconfig or token. A leaked `~/.kube/config` or a pod's mounted service-account token lets an attacker run `kubectl auth can-i --list`, `get secrets -A`, and `get pods -A` to map permissions and harvest Secrets.
- Privilege escalation. Attackers abuse broad RBAC, `create` on pods, or a privileged service account to schedule a pod that mounts the host filesystem or runs privileged, escaping to the node and from there toward the control plane.
- Lateral movement and tunneling. `kubectl exec` lands a shell inside a running workload, and `kubectl port-forward` bypasses NetworkPolicies to reach cluster-internal services from outside.
- Telemetry. The Kubernetes audit log records each API call: `create` on `pods/exec` and `pods/portforward`, `get` and `list` on `secrets`, and verb `*` on resource `*`. Defenders alert on these and on calls from an unexpected user agent or IP.

### Dominant weakness classes

The API server mediates everything through RBAC, so the dominant risks are excess authority and weak secret handling, not memory corruption.

- Improper privilege management ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)) through over-broad Roles, ClusterRoles, and `cluster-admin` bindings.
- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) in base64-encoded Secrets in etcd.
- Execution with unnecessary privileges ([CWE-250](https://cwe.mitre.org/data/definitions/250.html)) from privileged pods and host-namespace shares.
- Improper access control ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)) where `exec` and `port-forward` reach past network boundaries.

### Why it matters

Reading an RBAC grant the way an attacker would, and watching the subresources above, is what separates a cluster where one stolen token stays contained from one where it becomes full control. Auditors run `kubectl auth can-i` and review Secret access for the same reason. See [the Kubernetes security reference](/KUBERNETES_SECURITY_REFERENCE.md) and [the container security reference](/CONTAINER_SECURITY_REFERENCE.md) for RBAC and runtime hardening.

## Security notes

Grant least privilege with RBAC. Bind Roles and ClusterRoles that allow only the verbs and resources a subject needs, and reserve `cluster-admin` for break-glass use. Test a principal's effective rights with `kubectl auth can-i` before and after changes, rather than assuming a binding is scoped correctly. A broad `*` on `*` binding is a finding, not a shortcut.

Treat Secrets as sensitive but not encrypted. By default Kubernetes stores Secret data base64-encoded in etcd, which is encoding, not encryption (CWE-312: Cleartext Storage of Sensitive Information). Enable encryption at rest for Secrets, restrict `get` and `list` on them through RBAC, and prefer an external secret manager with short-lived credentials.

Audit `exec` and `port-forward`. Both let a user reach inside running workloads and can bypass network controls, so they belong in the audit log and in alerting. Review who holds the `pods/exec` and `pods/portforward` subresources.

Enforce boundaries in the cluster. Apply NetworkPolicies so pods cannot talk freely by default, set Pod Security Standards (baseline or restricted) to block privileged pods and host namespaces, and run admission policies to reject risky manifests. See /SECURE_CODING_REFERENCE.md for secret handling and access-control guidance.

## Resources

- Kubernetes official documentation and the kubectl reference.
- Kubernetes RBAC and Pod Security Standards documentation.
- CIS Kubernetes Benchmark for cluster hardening.

## Related pages

- [Command reference](/commands/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Docker Command Reference](/commands/docker.md)
- [Terraform Command Reference](/commands/terraform.md)
- [curl Command Reference](/commands/curl.md)
