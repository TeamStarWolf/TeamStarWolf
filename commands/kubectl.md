# kubectl Command Reference

`kubectl` is the command-line client for Kubernetes. It sends requests to the API server to inspect and change cluster state. This page covers the read, apply, debug, and scaling commands engineers use most, plus the context and namespace handling that keeps you on the right cluster. Security notes focus on RBAC, Secrets, and audit-worthy actions.

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

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/docker.md
- /commands/terraform.md
- /commands/curl.md
