<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Wolfi

> Chainguard's container-first undistro: no kernel, glibc-based, packaged with apk, built from source, and released continuously.

Part of [Operating systems](/operating-systems/README.md) (Container and immutable hosts). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Rolling | None | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Rolling release |

- Rolling: There are no numbered versions to reach end of life; rebuilding on current packages is the support model.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Rolling | None (uses the host kernel) | x86_64, aarch64 | Independent (Chainguard) | packages.wolfi.dev |

## Where its advisories live

- [Wolfi advisories repository](https://github.com/wolfi-dev/advisories): IDs take the form `CGA-xxxx-xxxx-xxxx` (for example `CGA-3gfc-9462-mc8m`).
- [Wolfi security database (secdb)](https://packages.wolfi.dev/os/security.json): IDs take the form `CVE-YYYY-NNNN (per package)`.

## How it patches

Package manager: `apk`.

Wolfi has no kernel of its own: a container uses its host's kernel, so `uname -r` reports the host. Fixes reach a workload when its image is rebuilt on updated packages.

```sh
apk update && apk upgrade   # in an image build, then rebuild and redeploy
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `apk info -v` | Installed packages and versions in the image |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Rolling | `ID=wolfi`, `VERSION_ID=<baselayout version>` | wolfi-baselayout package definition (`ID=wolfi`) |

## Hardening

- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)
- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Chainguard](/platforms/chainguard.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Wolfi is `product:wolfi`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Open source; the package definitions are on GitHub (wolfi-dev/os).

Vendor and project pages read for this page (2026-11-03):

- [Wolfi overview](https://www.chainguard.dev/supply-chain-security-101/wolfi-overview)
- [wolfi-dev/os](https://github.com/wolfi-dev/os)
- [wolfi-baselayout package definition](https://raw.githubusercontent.com/wolfi-dev/os/main/wolfi-baselayout.yaml)
- [Wolfi advisories](https://github.com/wolfi-dev/advisories)

<!-- os-pages:end -->
