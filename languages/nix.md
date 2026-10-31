# Nix

Nix is a purely functional, lazily evaluated language for describing software packages and system configurations reproducibly. It is the language of the Nix package manager and the NixOS Linux distribution, where an expression evaluates to a build plan (a derivation) that is built in isolation and stored by a hash of all its inputs. The result is that the same expression produces the same output, and many versions of a package can coexist. It is used for package definitions, development environments, and whole-system configuration.

| Attribute | Value |
|---|---|
| Paradigm | Purely functional, lazy, declarative |
| Typing | Dynamic, strong |
| First appeared | 2003 |
| Memory model | Garbage-collected in two senses: the evaluator manages its own memory, and the Nix store is garbage-collected by reachability |
| Reference implementation | [Nix](https://github.com/NixOS/nix) (the C++ package manager and evaluator) |
| Typical uses | Reproducible package builds, development shells, declarative system configuration |
| Governance | [NixOS Foundation](https://nixos.org/) and community |

Related: [HCL](/languages/hcl.md), [Puppet](/languages/puppet.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Nix began as Eelco Dolstra's doctoral research in the early 2000s, published around 2003 to 2006, on a purely functional approach to software deployment. The core idea is that a package is a pure function of its inputs: source, dependencies, and build steps. Nix stores each build output in `/nix/store` under a path derived from a hash of those inputs, so two builds with identical inputs share a path and a change to any input yields a new path. NixOS extends the same model to an entire operating system, describing the system declaratively and switching between generations atomically.

The language exists to produce derivations: data structures that describe how to build something. Everything else (packages, shells, system configuration) is a matter of writing expressions that evaluate to derivations.

## Paradigm and type system

Nix is purely functional: expressions have no side effects, there are no variables to reassign, and evaluation only produces values. It is lazy, so a value is computed only when needed, which lets large package sets be described without evaluating all of them. The language is small: its main values are strings, numbers, booleans, lists, functions, and attribute sets (maps written in braces), which are the workhorse data structure.

Typing is dynamic and strong: types are checked at evaluation time, and mismatches raise errors rather than coercing. Functions take one argument and curry; a function that appears to take several arguments usually takes a single attribute set and destructures it.

```nix
let
  greet = name: "hello, ${name}";   # a function
in greet "world"
```

## Toolchain and ecosystem

- Package manager and evaluator: the [Nix](https://github.com/NixOS/nix) command builds derivations, manages the store, and runs the garbage collector; `nix-collect-garbage` reclaims unreferenced store paths.
- Package set: [nixpkgs](https://github.com/NixOS/nixpkgs) is the large shared collection of package definitions and NixOS modules.
- Flakes: the flake feature standardizes how a project declares its inputs and outputs with pinned versions in a `flake.lock` file.
- Development shells: `nix develop` (flakes) or `nix-shell` drops into an environment with declared tools present, without installing them globally.
- Formatting and linting: [nixpkgs-fmt](https://github.com/nix-community/nixpkgs-fmt) or `alejandra` format, and [statix](https://github.com/nerdypepper/statix) lints for anti-patterns.

```bash
nix build .#mypackage      # build a flake output
nix develop                # enter a declared dev environment
nix flake check            # evaluate and check a flake
```

## Syntax tour

```nix
{ lib, stdenv, fetchurl }:

stdenv.mkDerivation rec {
  pname = "hello";
  version = "2.12";

  src = fetchurl {
    url = "mirror://gnu/hello/hello-${version}.tar.gz";
    # A hash pins the input so the build is reproducible
    sha256 = "0ssi1wpaf7plaswqqjwig1234567890abcdefghijklmnop";
  };

  # Attribute sets and lists
  buildInputs = [ ];
  meta = {
    description = "A program that prints a greeting";
    license = lib.licenses.gpl3Plus;
  };
}
```

## Idioms and different approaches

- Describe a package as a function of its dependencies (`{ stdenv, fetchurl, ... }: ...`) so the package set can supply them, rather than hardcoding paths.
- Pin inputs: use a `flake.lock`, or pin nixpkgs to a specific revision, so an evaluation is reproducible over time.
- Use `let ... in` for local bindings and `with` sparingly, since `with` makes it unclear where a name comes from.
- Build development environments declaratively with `nix develop` or `nix-shell` instead of documenting manual setup steps.
- Keep derivations pure: fetchers that reach the network must declare a hash, which is how Nix allows network access without breaking reproducibility.

## Design principles

Nix's organizing principle is that builds should be reproducible and isolated: a build sees only its declared inputs, runs in a sandbox, and is addressed by the hash of those inputs. Purity and laziness in the language serve that goal, since a build plan must not depend on hidden state or on evaluating things it does not use. Storing outputs by hash gives atomic upgrades and rollbacks (switch the symlink, keep the old generation) and lets conflicting versions coexist without interference.

## Standard library and notable modules

The practical standard library is `lib` within [nixpkgs](https://github.com/NixOS/nixpkgs): helper functions for lists, attribute sets, strings, and license and platform metadata, plus the builder helpers such as `stdenv.mkDerivation` and language-specific builders (for Python, Rust, Go, and others). The NixOS module system, also in nixpkgs, provides a large set of options for configuring system services declaratively. Flake inputs are the modern way to depend on other Nix projects with pinned versions.

## Testing and packaging

A package is defined as a derivation and built with `nix build`; a broken definition fails at build time in the sandbox. NixOS provides a virtual-machine test framework that boots a configuration and runs assertions against it, which is used to test services end to end. "Packaging" in Nix is writing the derivation itself; distribution is through nixpkgs or through flakes that other projects reference by pinned revision.

```nix
# A NixOS VM test asserting a service is reachable
import ./make-test-python.nix ({ pkgs, ... }: {
  nodes.machine = { services.nginx.enable = true; };
  testScript = ''
    machine.wait_for_unit("nginx.service")
    machine.succeed("curl --fail http://localhost/")
  '';
})
```

## Performance and concurrency

Nix separates evaluation from building, and the evaluation model shapes performance:

- Evaluation is lazy and single-threaded in the classic evaluator: computing a large attribute set like nixpkgs can use significant memory and time, so evaluation caching and pinned inputs matter.
- Building is where parallelism lives: independent derivations can build concurrently (and on remote builders), because each is isolated and addressed by hash; Nix schedules them according to the dependency graph.
- The content-addressed store means an input already built is reused rather than rebuilt, so incremental work is cheap once the store is warm.

Garbage collection reclaims store paths that nothing references; roots (such as the current system generation and active shells) keep paths alive.

## Common pitfalls

- Impure evaluation: depending on environment variables, the current time, or unpinned nixpkgs makes results differ between machines; pin inputs and keep derivations pure.
- Hash mismatches: a fetcher's declared hash must match the fetched content; a changed upstream tarball breaks the build until the hash is updated.
- Laziness surprises: an error in an unused part of an expression stays hidden until something forces it, so failures can appear far from their cause.
- Overusing `with`, which brings names into scope opaquely and makes expressions hard to read and shadow-prone.
- Large evaluations running out of memory; splitting work and reusing evaluation caches helps.

## Secure coding

Nix improves reproducibility, which helps supply-chain assurance, but configuration and secret handling still need care:

- Hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): the Nix store is world-readable, and anything built into a derivation lands there in plain text, so secrets written into Nix expressions are exposed to every local user and recorded in the store. Keep secrets out of derivations; deliver them at run time with tools such as [agenix](https://github.com/ryantm/agenix) or [sops-nix](https://github.com/Mic92/sops-nix), which decrypt into locations outside the store.
- Privilege in system configuration ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): NixOS modules configure services, users, and firewall rules; an over-permissive option (open ports, broad sudo rules) grants real access. Review the effective configuration and apply least privilege.
- Input provenance and pinning: a derivation builds whatever its inputs point to; an unpinned or compromised source changes what you run. Pin inputs with hashes and `flake.lock`, and review updates. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Trusting binary caches: substituting prebuilt outputs from a cache trusts that cache's signing keys; use trusted keys and substituters only.

Tooling: lint expressions with [statix](https://github.com/nerdypepper/statix), keep inputs pinned and updated deliberately, and manage secrets with a dedicated tool rather than the store. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Nix reference manual](https://nix.dev/manual/nix/stable/), the language and command reference.
- [nix.dev](https://nix.dev/), task-oriented tutorials and guides.
- [nixpkgs](https://github.com/NixOS/nixpkgs), the package set and `lib`, as worked examples.

## Related pages

- [HCL](/languages/hcl.md)
- [Puppet](/languages/puppet.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
