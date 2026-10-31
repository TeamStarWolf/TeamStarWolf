# Terraform Command Reference

Terraform defines infrastructure as declarative configuration and provisions it through provider APIs. You describe the desired state in `.tf` files, and Terraform computes and applies the difference against recorded state. This page covers the core workflow, state handling, variables, and modules. Security notes focus on state secrets, credential handling, and change review.

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

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/aws-cli.md
- /commands/kubectl.md
- /commands/docker.md
