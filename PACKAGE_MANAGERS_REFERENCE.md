# Package Managers

This reference covers the package managers and registries that software depends on: how each one declares, resolves, locks, and installs dependencies, and the supply-chain risks that come with pulling code from a public registry. It is written for a security or vulnerability management analyst who has to understand where third-party code enters an environment and how it is attacked.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security and vulnerability management analysts tracking where third-party code enters the environment

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (869 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to know how a package manager resolves, locks, and installs dependencies, you are hardening against dependency confusion or typosquatting, or you are deciding where to enforce lockfiles and private registries

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[How package managers work](#how-package-managers-work), [Package managers by ecosystem](#package-managers-by-ecosystem), [Supply-chain risks and mitigations](#supply-chain-risks-and-mitigations)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Application Security Testing](APPSEC_TESTING_REFERENCE.md), [Scanner Platforms and Findings Catalog](SCANNER_PLATFORMS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How package managers work

Every package manager has the same moving parts, and each is a place an attacker can act.

- Registry: the server that hosts packages (for example the npm registry, PyPI, crates.io, Maven Central). Public registries accept uploads from many publishers, so trust is not uniform.
- Manifest: the file that declares direct dependencies and version ranges (`package.json`, `requirements.txt`, `Cargo.toml`, `pom.xml`).
- Resolver: the logic that turns version ranges plus the full transitive tree into concrete versions.
- Lockfile: the resolved, exact set, often with integrity hashes (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `Gemfile.lock`). The lockfile is what makes a build reproducible and what SCA scans.
- Install step: downloading and placing the packages, which for several managers also runs package-provided scripts, a key execution risk.

## Package managers by ecosystem

### JavaScript and Node.js

- `npm`: the default manager; manifest `package.json`, lockfile `package-lock.json`, registry the npm registry. Lifecycle scripts (`preinstall`, `postinstall`) run arbitrary code on install, which is a common malware vector.
- `yarn` and `pnpm`: alternative managers over the same registry; `pnpm` uses a content-addressed store, and both have their own lockfiles.

### Python

- `pip`: installs from PyPI; `requirements.txt` for pinning. A source distribution can run code through `setup.py` at install time.
- `Poetry`, `pipenv`, and `uv`: add a manifest (`pyproject.toml`) and a lockfile for reproducible resolution.
- `conda`: a cross-language manager and registry (conda-forge) for scientific stacks, managing binaries and environments.

### Compiled and systems languages

- Rust `cargo`: manifest `Cargo.toml`, lockfile `Cargo.lock`, registry crates.io.
- Go modules: manifest `go.mod`, checksums in `go.sum` verified against a checksum database, fetched through the module proxy.
- C and C++ `vcpkg` and `Conan`: dependency managers that bring manifests and lockfiles to an ecosystem that historically had none.

### JVM and .NET

- Maven: manifest `pom.xml`, registry Maven Central; Gradle uses the same repositories with its own build files.
- NuGet: the .NET manager; project files plus an optional `packages.lock.json`, registry nuget.org.

### Ruby and PHP

- RubyGems with Bundler: `Gemfile` and `Gemfile.lock`, registry rubygems.org.
- Composer: the PHP manager; `composer.json` and `composer.lock`, registry Packagist.

### Operating-system managers

These install system software rather than application libraries, and they verify packages with signatures.

- `apt` and `dpkg` (Debian, Ubuntu), `dnf` and `rpm` (Red Hat family), `apk` (Alpine), `pacman` (Arch), `zypper` (SUSE).
- Homebrew (macOS and Linux), and `winget` and Chocolatey (Windows).

### Containers

Container image registries (for example a Docker registry or an OCI registry) distribute images rather than packages, but image layers contain packages installed by the managers above, which is why container scanning reads those package databases. See [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).

## Lockfiles and reproducibility

A lockfile pins the exact resolved versions and, where supported, their integrity hashes, so a build installs the same bytes every time and a tampered package is rejected.

- Commit the lockfile, and build from it (`npm ci`, `pip install -r` with hashes, `cargo build --locked`) rather than re-resolving in production.
- A lockfile is the accurate input for software composition analysis and for a software bill of materials. See [Application Security Testing](/APPSEC_TESTING_REFERENCE.md).

## Supply-chain risks and mitigations

Pulling code from a public registry is a trust decision, and these are the recurring attacks.

- Dependency confusion: a public package is published under the same name as a private internal one, and the resolver picks the higher public version. Mitigate by scoping internal packages to a private registry and refusing public resolution for internal names.
- Typosquatting: a malicious package uses a name close to a popular one (a transposed letter, a hyphen). Mitigate by pinning exact names and versions and scanning new dependencies.
- Malicious and hijacked packages: an attacker publishes malware or takes over an abandoned or maintainer-compromised package and ships a bad version. Mitigate with lockfiles plus hash pinning so an unexpected version is rejected, delaying auto-upgrades, and monitoring advisories.
- Install-script execution: `npm` lifecycle scripts and Python `setup.py` run code on install, so a compromised package executes in the developer or CI environment immediately. Mitigate by disabling install scripts where possible, building in sandboxed CI, and using managers or flags that do not run scripts.
- Protestware and intentional sabotage: a maintainer ships destructive or disruptive behavior. Mitigate the same way: pin, review changes, and do not blindly auto-upgrade.

Program-level mitigations:

- Pin and hash-lock dependencies, and build from the lockfile.
- Route all installs through an internal proxy or private registry that enforces an allowlist and scoping, which also closes dependency confusion.
- Scan every dependency with software composition analysis and track an SBOM. See [Application Security Testing](/APPSEC_TESTING_REFERENCE.md) and [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Prefer packages and registries that support signing and provenance (for example npm provenance attestations and Sigstore), and verify it.
- Require multi-factor authentication on publishing accounts for packages you own, to prevent maintainer-account takeover.

## Learning resources

- Each manager documents its manifest, lockfile, and registry behavior; confirm install-script and verification behavior for the exact manager and version you run.
- For the weaknesses behind these attacks and the program that manages them, see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Application Security Testing](/APPSEC_TESTING_REFERENCE.md), and [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Application and supply chain security](/hubs/application-and-supply-chain.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Application Security Testing](/APPSEC_TESTING_REFERENCE.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)
- [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md)

<!-- related:end -->
