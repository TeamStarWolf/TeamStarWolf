# Terraform Command Reference

Terraform defines infrastructure as declarative configuration and provisions it through provider APIs. You describe the desired state in `.tf` files, and Terraform computes and applies the difference against recorded state. This page covers the core workflow, state handling, variables, and modules. Security notes focus on state secrets, credential handling, and change review.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Infrastructure, platform and cloud security engineers who manage infrastructure as code

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (923 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the Terraform commands for a task at hand, you want a common workflow to copy and adapt, you are looking up a flag or option worth knowing, or you need the security notes that go with them

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Core commands](#core-commands), [Common workflows](#common-workflows), [Security notes](#security-notes)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [AWS CLI Reference](/commands/aws-cli.md), [kubectl Command Reference](/commands/kubectl.md), [Docker Command Reference](/commands/docker.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it runs

Terraform runs as a single binary on a workstation or CI runner. It reads `.tf` files in the working directory, loads providers, and tracks what it created in a state file. The state file maps your configuration to real resource IDs. It can live locally as `terraform.tfstate` or in a remote backend such as S3, Azure Blob, or Terraform Cloud. A backend shared by a team usually adds state locking to prevent concurrent writes.

## Core commands

Set up and preview:

```bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
```

| Command | Purpose |
| --- | --- |
| `terraform init` | Download providers and configure the backend |
| `terraform fmt` | Rewrite files to canonical style |
| `terraform validate` | Check syntax and internal consistency |
| `terraform plan` | Show the changes an apply would make |

Apply and remove:

```bash
terraform apply tfplan
terraform apply -var-file=prod.tfvars
terraform destroy
terraform output db_endpoint
```

| Command | Purpose |
| --- | --- |
| `terraform apply` | Make real changes to reach desired state |
| `terraform destroy` | Tear down managed infrastructure |
| `terraform output` | Print declared output values |
| `terraform import` | Bring an existing resource under management |

Work with state and workspaces:

```bash
terraform state list
terraform state show aws_s3_bucket.logs
terraform state rm aws_instance.old
terraform state mv aws_instance.a aws_instance.b
terraform workspace new staging
terraform workspace select prod
```

| Subcommand | Purpose |
| --- | --- |
| `state list` | List resources tracked in state |
| `state show` | Print one resource's recorded attributes |
| `state rm` | Stop managing a resource without destroying it |
| `state mv` | Rename or move a resource in state |

Pass variables and import:

```bash
terraform plan -var="region=us-east-1"
terraform apply -var-file=prod.tfvars
terraform import aws_s3_bucket.logs my-existing-bucket
```

A module call reuses configuration:

```hcl
module "network" {
  source = "./modules/network"
  cidr   = "10.0.0.0/16"
}
```

## Common workflows

Standard change cycle with a saved plan:

```bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Target a specific environment with a var file:

```bash
terraform workspace select prod
terraform plan -var-file=prod.tfvars -out=prod.plan
terraform apply prod.plan
```

Adopt an unmanaged resource:

```bash
terraform import aws_db_instance.main prod-db-01
terraform plan
terraform state show aws_db_instance.main
```

Recover from drift or a bad reference:

```bash
terraform plan -refresh-only
terraform state list
terraform state rm aws_instance.ghost
terraform apply
```

## Flags and options worth knowing

| Flag | Applies to | Effect |
| --- | --- | --- |
| `-out=FILE` | `plan` | Save the plan for a later apply |
| `-var` | `plan`, `apply` | Set a single input variable |
| `-var-file` | `plan`, `apply` | Load variables from a `.tfvars` file |
| `-target` | `plan`, `apply` | Limit action to specific resources |
| `-auto-approve` | `apply`, `destroy` | Skip the interactive confirmation |
| `-refresh-only` | `plan`, `apply` | Reconcile state without changing resources |
| `-upgrade` | `init` | Update providers to newest allowed versions |
| `-recursive` | `fmt` | Format files in subdirectories too |
| `-json` | `plan`, `apply` | Machine-readable output for pipelines |

## Security relevance

This section is the threat-facing view of Terraform: how an attacker abuses configuration, modules, and state, and what the review and audit trail shows when they do. The state-handling and credential guidance is in the "Security notes" section that follows.

### Where it appears

- Pipeline abuse. Write access to `.tf` files or to the CI that runs `terraform apply` lets an attacker provision a backdoor, a new admin IAM user, or an open security group, which Terraform then creates with the pipeline's own privileged credentials.
- Malicious modules and providers. `terraform init` downloads providers and modules from registries and Git URLs, so a poisoned module, a `local-exec` provisioner, or an `external` data source can run attacker code on the runner during plan or apply.
- State as a secret store. A remote backend or a committed `terraform.tfstate` holds resource attributes in plaintext, so read access to state yields database passwords, private keys, and tokens.
- Telemetry. Plan output under review, CI logs, version-control history, and the cloud provider's own audit log (the resources an apply created) are where a defender catches an injected resource or an unexpected provider.

### Dominant weakness classes

Terraform is a userspace client that drives provider APIs, so the risks are trust and credential exposure, not memory corruption.

- Use of hard-coded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)) in `.tf` or committed `.tfvars` files.
- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) in the state file.
- Inclusion of functionality from an untrusted control sphere ([CWE-829](https://cwe.mitre.org/data/definitions/829.html)) through unpinned modules and providers.
- Improper privilege management ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)) when a pipeline applies changes with broad, long-lived credentials.

### Why it matters

Reviewing the plan and pinning module and provider sources is what stops a trusted pipeline from provisioning an attacker's backdoor or running their code on the runner. Auditors trace applied resources back to the configuration and state that created them for the same reason. See [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) for dependency-integrity and pipeline guidance.

## Security notes

The state file holds secrets in plaintext. Terraform records resource attributes verbatim, so database passwords, private keys, and generated tokens land in state unencrypted (CWE-312: Cleartext Storage of Sensitive Information). Do not commit `terraform.tfstate` to version control. Use a remote backend with encryption at rest, access controls, and state locking, and restrict who can read it.

Never hardcode provider credentials. Access keys or service-account keys written into `.tf` files or committed `.tfvars` become long-lived secrets in history (CWE-798: Use of Hard-Coded Credentials). Source credentials from environment variables, an instance or workload identity, or OIDC federation in CI, and give each provider role least privilege.

Review every plan before apply. A `plan` shows adds, changes, and destroys. Reading it is the control that catches an accidental database replacement or a wide-open security group. Avoid `-auto-approve` for human-run changes, and gate CI applies behind a reviewed plan artifact.

Add policy-as-code and keep variables out of logs. Enforce guardrails with Open Policy Agent (Conftest) or Sentinel so non-compliant plans fail before apply. Mark sensitive variables and outputs with `sensitive = true` to keep them out of console output, and scan configuration with a tool such as tfsec or Checkov. See /SECURE_CODING_REFERENCE.md for credential and secret-management guidance.

## Resources

- Terraform official documentation and the CLI command reference.
- The OpenTofu documentation for the open-source fork.
- Open Policy Agent documentation for policy-as-code.

## Related pages

- [Command reference](/commands/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [AWS CLI Reference](/commands/aws-cli.md)
- [kubectl Command Reference](/commands/kubectl.md)
- [Docker Command Reference](/commands/docker.md)
