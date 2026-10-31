# Puppet

Puppet is a declarative language and tool for configuration management: describing the desired state of servers and other systems and keeping them in that state. It was created by Luke Kanies in 2005. A Puppet manifest declares resources (packages, files, services, users) and their properties, and the Puppet engine compiles those declarations into a catalog that an agent applies to each node, making changes only where reality differs from the declaration. It is used to provision and maintain fleets of systems consistently.

| Attribute | Value |
|---|---|
| Paradigm | Declarative, model-based configuration management; resource and dependency graph |
| Typing | Static type system for parameters and data (Puppet 4 and later) |
| First appeared | 2005 |
| Memory model | Not applicable: manifests compile to a catalog, not to a running program |
| Reference implementation | [Puppet](https://github.com/puppetlabs/puppet) (Ruby); Puppet agent and server |
| Typical uses | Server configuration management, infrastructure as code, compliance enforcement |
| Governance | [Puppet (by Perforce)](https://www.puppet.com/) and the open-source community |

Related: [HCL](/languages/hcl.md), [Nix](/languages/nix.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Puppet was released in 2005 as one of the early tools to treat system administration as code rather than as manual steps or shell scripts. Its model is declarative: an administrator states what a system should look like, and Puppet figures out the actions needed to get there, applying them idempotently so that running the same manifest repeatedly converges on the same state without repeating work. Puppet 4 (2015) introduced a formal type system and tightened the language; later versions continued on that base.

Puppet typically runs in an agent-server arrangement: a Puppet server compiles a catalog for each node from manifests and data, and the agent on the node applies it on a schedule. It can also run stand-alone with `puppet apply`.

## Paradigm and type system

Puppet code is declarative and resource-centric. The unit is the resource: a typed declaration such as a `package`, `file`, `service`, or `user`, with attributes describing its desired state. Resources are grouped into classes and into reusable modules. Puppet builds a dependency graph from relationships between resources (`require`, `before`, `notify`, `subscribe`) and applies them in a valid order, not in source order.

Since Puppet 4 the language has a static type system used for class and defined-type parameters and for data validation: types such as `String`, `Integer`, `Boolean`, `Array[String]`, `Hash`, and constrained forms like `Enum['present','absent']` or `Optional[String]`. The engine checks supplied values against these types when it compiles the catalog.

```puppet
class webserver (
  Enum['present', 'absent'] $ensure = 'present',
  Integer[1, 65535]         $port   = 80,
) {
  # resource declarations follow
}
```

## Toolchain and ecosystem

- Agent and server: the Puppet agent applies catalogs; the Puppet server compiles them. `puppet apply` runs a manifest locally.
- Data lookup: [Hiera](https://www.puppet.com/docs/puppet/latest/hiera.html) separates configuration data from code, so manifests stay general and values vary per environment or node.
- Modules: the [Puppet Forge](https://forge.puppet.com/) distributes reusable modules for common software; the Puppet Development Kit (PDK) scaffolds and validates them.
- Validation and linting: `puppet parser validate` checks syntax, and [puppet-lint](https://github.com/puppetlabs/puppet-lint) checks style and common mistakes.

```bash
puppet parser validate manifest.pp   # syntax check
puppet-lint manifest.pp               # style and lint
puppet apply manifest.pp              # apply locally
```

## Syntax tour

```puppet
class nginx (
  Enum['present', 'absent'] $ensure = 'present',
) {
  # A package resource
  package { 'nginx':
    ensure => $ensure,
  }

  # A file resource, managed from a template
  file { '/etc/nginx/nginx.conf':
    ensure  => file,
    content => template('nginx/nginx.conf.erb'),
    require => Package['nginx'],   # ordering relationship
    notify  => Service['nginx'],   # restart service on change
  }

  # A service resource kept running and enabled at boot
  service { 'nginx':
    ensure => running,
    enable => true,
  }
}
```

## Idioms and different approaches

- Describe desired state, not steps: declare that a package is `present` and a service is `running`, and let Puppet decide what to change.
- Separate data from code with Hiera, so the same module serves many nodes and environments by looking up per-node values.
- Express ordering with relationships (`require`, `notify`) rather than relying on where resources appear in the file.
- Package reusable configuration as modules with typed parameters, and pull common ones from the Forge rather than reinventing them.
- Keep resources idempotent; avoid `exec` resources that run commands unconditionally, and guard any `exec` with `onlyif`, `unless`, or `creates`.

## Design principles

Puppet's principle is declarative, idempotent convergence: you describe the end state, and the tool repeatedly brings systems to it, changing only what is out of place. Modeling configuration as typed resources with explicit relationships lets Puppet reason about order and detect conflicts, and makes configuration reviewable and testable like other code. Separating data (Hiera) from logic (manifests) keeps modules general and portable across environments.

## Standard library and notable modules

The [puppetlabs-stdlib](https://forge.puppet.com/modules/puppetlabs/stdlib) module is the de facto standard library: additional functions for strings, arrays, hashes, and validation that manifests commonly rely on. Built-in resource types cover packages, files, services, users, groups, cron entries, and more, with providers that implement them per operating system. The [Puppet Forge](https://forge.puppet.com/) hosts modules for widely used software (web servers, databases, firewalls), many maintained by Puppet or by vendors.

## Testing and packaging

Modules are tested on several levels: `puppet parser validate` and puppet-lint for syntax and style, [rspec-puppet](https://rspec-puppet.com/) for unit tests that compile the catalog and assert on the resources it contains, and [Litmus](https://github.com/puppetlabs/puppet_litmus) or similar for acceptance tests that apply a module to a real or virtual system. Modules are packaged with the Puppet Development Kit and published to the Forge, pinned by version in a `metadata.json` and a `Puppetfile`.

```ruby
# rspec-puppet unit test
describe 'nginx' do
  it { is_expected.to contain_package('nginx').with_ensure('present') }
  it { is_expected.to contain_service('nginx').with_ensure('running') }
end
```

## Performance and concurrency

Puppet's evaluation model is compile-then-apply, so performance divides accordingly:

- Catalog compilation happens on the Puppet server (or locally with `puppet apply`): manifests and Hiera data are evaluated into a catalog for a node. Large codebases and heavy data lookups make compilation slower, so servers cache and scale horizontally.
- Catalog application happens on each node: the agent walks the resource graph and makes changes. Independent resources can be applied without a fixed order, while related ones follow the graph; the cost is dominated by the real actions (installing packages, writing files, restarting services), not by the language.
- Runs are periodic and convergent: each run reconciles the node with the catalog, so the system tends toward the declared state over time rather than being configured once.

Scaling is about compilation throughput and run scheduling across a fleet, not about speeding up a single program.

## Common pitfalls

- Overusing `exec` to run arbitrary commands, which breaks the declarative, idempotent model; prefer a resource type, and guard any necessary `exec` with `onlyif`/`unless`/`creates`.
- Relying on file order instead of declared relationships, which leads to resources applied in the wrong sequence.
- Resource conflicts: declaring the same resource twice with different attributes causes a compilation error; use classes and parameters to avoid duplication.
- Putting environment-specific data in manifests instead of Hiera, which makes modules non-portable.
- Non-idempotent manifests that change something on every run, hiding real drift in the noise.

## Secure coding

Puppet configures systems with administrative privilege and often handles credentials, so the secure-coding focus is secret handling and the privilege it manages:

- Hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): passwords, keys, and tokens written into manifests or plain Hiera data land in version control and in compiled catalogs. Keep secrets out of code: use [hiera-eyaml](https://github.com/voxpupuli/hiera-eyaml) or a secrets backend so values are encrypted at rest and decrypted only at catalog compilation for the right node.
- Privilege and state risk ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): Puppet runs as root on managed nodes, so a mistaken resource (wrong file mode, overly broad sudo rule, a service exposed on a public interface) applies real, privileged changes across the fleet. Review manifests, apply least privilege, and test catalog output before rollout.
- Unsafe `exec` and template injection: an `exec` built from unvalidated data, or a template that interpolates untrusted input, can run attacker-controlled commands on managed nodes; validate inputs and prefer typed resources over shelling out.
- Module supply chain: Forge modules run with Puppet's privilege; pin versions in the `Puppetfile`, prefer approved or vendor modules, and review third-party code. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: validate and lint with `puppet parser validate` and [puppet-lint](https://github.com/puppetlabs/puppet-lint), unit-test catalogs with rspec-puppet so insecure resource attributes are caught before apply, and manage secrets with hiera-eyaml rather than plain data. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Puppet documentation](https://www.puppet.com/docs/puppet/latest/puppet_index.html), the language and resource reference.
- [Hiera documentation](https://www.puppet.com/docs/puppet/latest/hiera.html), for separating data from code.
- [Puppet Forge](https://forge.puppet.com/), for reusable modules and `stdlib`.

## Related pages

- [HCL](/languages/hcl.md)
- [Nix](/languages/nix.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
