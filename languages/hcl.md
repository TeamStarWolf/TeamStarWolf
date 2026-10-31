# HCL (HashiCorp Configuration Language)

HCL (HashiCorp Configuration Language) is a declarative configuration language created by HashiCorp for defining infrastructure and tool configuration. It aims to be readable by people and still structured enough for machines, sitting between raw JSON and a full programming language. It is best known as the language of Terraform, where it describes cloud and on-premises resources as code, and it also configures Packer, Nomad, Consul, and Vault. A tool reads HCL, resolves its expressions, and acts on the result.

| Attribute | Value |
|---|---|
| Paradigm | Declarative configuration; blocks, arguments, and expressions |
| Typing | Dynamically evaluated, with optional type constraints in Terraform variables |
| First appeared | 2014 |
| Memory model | Not applicable: evaluated to a configuration, not compiled to a running program |
| Reference implementation | [hashicorp/hcl](https://github.com/hashicorp/hcl) (Go library) |
| Typical uses | Infrastructure as code, provisioning, application and service configuration |
| Governance | HashiCorp |

Related: [Nix](/languages/nix.md), [Puppet](/languages/puppet.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

HCL appeared in 2014 alongside the first HashiCorp tools as an answer to a recurring problem: configuration files that were either too rigid (INI, basic key-value) or awkward for humans to write and review (JSON, with no comments and heavy punctuation). HCL keeps a JSON-compatible data model but adds comments, string interpolation, and a block syntax that reads like a nested outline. The second major version, HCL2, unified the syntax and the expression language and is what current tools use.

HCL is a host language: it defines syntax and an expression evaluator, but the meaning of a given block (`resource`, `variable`, `job`) comes from the tool that embeds it. Terraform's schema is the most widely used, and much of what people call "writing HCL" is really writing Terraform configuration.

## Paradigm and type system

HCL is declarative: a file states the desired configuration, and the embedding tool decides how to realize it. The structure is blocks (a type, optional labels, and a body in braces) containing arguments (name-value pairs) and nested blocks. Values can be strings, numbers, booleans, lists (tuples), and maps (objects), and expressions combine them with operators, conditionals, `for` expressions, and functions.

HCL itself is dynamically typed, resolving values during evaluation. Terraform layers an optional type system on top: input variables can declare a `type` constraint such as `string`, `number`, `list(string)`, or an object shape, and Terraform checks supplied values against it.

```hcl
variable "instance_count" {
  type    = number
  default = 2
}
```

## Toolchain and ecosystem

- Core library: [hashicorp/hcl](https://github.com/hashicorp/hcl) parses and evaluates HCL in Go programs; tools embed it and define their own schemas.
- Terraform and OpenTofu: [Terraform](https://developer.hashicorp.com/terraform) and the fork [OpenTofu](https://opentofu.org/) use HCL to describe infrastructure, with `terraform fmt` for formatting and `terraform validate` for schema checks.
- Other tools: Packer (machine images), Nomad (job scheduling), Consul, and Vault accept HCL configuration.
- Linting and policy: [TFLint](https://github.com/terraform-linters/tflint) catches Terraform mistakes; policy engines such as Open Policy Agent and Sentinel enforce rules on the evaluated plan.

```bash
terraform fmt       # canonical formatting
terraform validate  # schema and type checks
terraform plan      # show the actions without applying
```

## Syntax tour

```hcl
# A block: type "resource", labels "aws_instance" and "web"
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_count = 2
  tags = {
    Name = "web-${terraform.workspace}"   # string interpolation
  }
}

# Input variable with a type constraint and default
variable "ami_id" {
  type        = string
  description = "AMI to launch"
}

# Expressions: a for expression building a list
locals {
  names = [for n in var.servers : upper(n)]
}

# Output computed after apply
output "instance_ip" {
  value = resource.aws_instance.web.private_ip
}
```

## Idioms and different approaches

- Declare inputs as typed `variable` blocks and results as `output` blocks, keeping environment-specific values out of the main configuration.
- Group reusable configuration into modules with clear inputs and outputs rather than copying blocks between files.
- Use `for_each` over a map to create a set of similar resources with stable identities, rather than `count`, which is positional and shifts when the list changes.
- Keep logic shallow: HCL has conditionals and `for` expressions, but configuration that needs real control flow is a sign the logic belongs in the tool or in generated configuration.
- Run `fmt` and `validate` in continuous integration so style and schema errors are caught before a plan.

## Design principles

HCL's design goal is a configuration language that is comfortable for humans to write and read while remaining machine-friendly and interoperable with JSON. It is deliberately not a general-purpose programming language: it offers expressions and limited iteration, but not arbitrary control flow, so configuration stays declarative and analyzable. Keeping the syntax separate from any one tool's schema lets many tools share the same parser and editor support.

## Standard library and notable functions

HCL does not ship a standard library on its own; the embedding tool supplies the functions available in expressions. Terraform provides built-in functions for strings (`format`, `join`, `replace`), collections (`merge`, `flatten`, `lookup`), encoding (`jsonencode`, `base64encode`), filesystem and template reads, and cryptographic hashing. Reuse at a larger scale happens through modules, many shared on the [Terraform Registry](https://registry.terraform.io/), and through providers that define the resource types a configuration can manage.

## Testing and packaging

Configuration is validated with `terraform validate` and previewed with `terraform plan`, which shows the actions a run would take without performing them. Terraform's own test framework (`terraform test`) and tools such as [Terratest](https://terratest.gruntwork.io/) exercise modules against real or mock infrastructure. Reusable units are packaged as modules and distributed through the Terraform Registry or version-controlled repositories, pinned by version.

```hcl
# terraform test: a run block asserting on a plan
run "sets_name_tag" {
  command = plan
  assert {
    condition     = resource.aws_instance.web.tags["Name"] != ""
    error_message = "Name tag must be set"
  }
}
```

## Performance and concurrency

HCL is evaluated, not compiled or run as a process, so its performance characteristics are about the embedding tool's evaluation model rather than execution speed:

- Terraform parses the configuration, builds a dependency graph from references between resources, and evaluates expressions to produce a plan; unrelated resources can be processed in parallel, while dependent ones are ordered by the graph.
- Expression evaluation is generally cheap; cost comes from the provider operations the plan drives (API calls to create or change real infrastructure), not from HCL itself.
- State is central: Terraform compares the configuration against recorded state to compute the minimal set of changes, so the evaluation model is diff-and-converge rather than imperative steps.

Large configurations are kept manageable by splitting them into modules and separate state files rather than by optimizing the language.

## Common pitfalls

- Treating HCL as a programming language: complex conditionals and nested `for` expressions become unreadable; move real logic out of the configuration.
- Using `count` where `for_each` is appropriate; removing an item from a `count` list renumbers and can destroy and recreate unrelated resources.
- Committing the state file, which records real infrastructure and often secrets, into version control in plain text.
- Interpolating untrusted values into resource names or commands without validation.
- Drift between declared configuration and manually changed infrastructure, which a plan reveals but cannot prevent.

## Secure coding

Infrastructure configuration grants real privileges and often touches secrets, so the secure-coding focus is secret handling and the state it manages:

- Hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): access keys, passwords, and tokens written directly into HCL end up in version control and in state. Keep them out of the source: read them from a secrets manager (Vault, cloud secret stores), environment variables, or variable files that are never committed, and mark sensitive variables and outputs as `sensitive`.
- State file exposure: Terraform state stores resource attributes, including some secrets, in plain text by default. Store it in an encrypted, access-controlled backend rather than a repository, and restrict who can read it.
- Excess privilege ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): configurations frequently open security groups, grant IAM policies, and set permissions; overly broad rules (open ingress, wildcard permissions) are a common finding. Apply least privilege and review the plan for unintended access.
- Untrusted modules and providers: a module or provider runs with your credentials and can exfiltrate them. Pin versions, prefer known-good sources, and review third-party modules. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: scan configurations with [tfsec](https://github.com/aquasecurity/tfsec) or [Checkov](https://www.checkov.io/) for insecure defaults and exposed secrets, lint with [TFLint](https://github.com/terraform-linters/tflint), and enforce organizational rules with policy as code. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Terraform documentation](https://developer.hashicorp.com/terraform), the main practical reference for HCL in use.
- [HCL native syntax specification](https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md), the language-level definition.
- [Terraform Registry](https://registry.terraform.io/), for shared modules and providers.

## Related pages

- [Nix](/languages/nix.md)
- [Puppet](/languages/puppet.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
