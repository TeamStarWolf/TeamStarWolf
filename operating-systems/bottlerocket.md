<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Bottlerocket

> A Linux built to run containers, with no SSH server and no shell on the host: settings change through an API, and updates replace the whole filesystem image.

Part of [Operating systems](/operating-systems/README.md) (Container and immutable hosts). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 1.x | None | Not applicable | 1.68.1 | Not applicable | Not applicable | Not applicable | Rolling release |

- 1.x: Releases replace each other; there are no versions with published end-of-life dates.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 1.x | Depends on the variant | x86_64, aarch64 | Independent (Bottlerocket project) | TUF-signed update repository |

## Where its advisories live

- [Bottlerocket security advisories (BRSA)](https://github.com/bottlerocket-os/bottlerocket/security/advisories): IDs take the form `BRSA-xxxxxxxxxxxx` (for example `BRSA-mewm3entr5hf`). Machine-readable: [updateinfo.xml.gz](https://advisories.bottlerocket.aws/updateinfo.xml.gz).

The oldest entries in the feed use GitHub advisory ids (`GHSA-...`) instead.

## How it patches

Package manager: None; whole-image updates through the Bottlerocket API.

Run `apiclient` from the control or admin container. For EKS variants the project recommends the Bottlerocket update operator, and for ECS the ECS updater (Bottlerocket README).

```sh
apiclient update check
apiclient update apply --check --reboot
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `apiclient get settings` | The host's settings through the API |
| `sudo sheltie` | From the admin container, a root shell on the host where `uname -r` and `/etc/os-release` can be read |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 1.x | `ID=bottlerocket` | Not checked on a running system |

## Hardening

- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)
- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Bottlerocket is `product:bottlerocket`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Open source under the Apache-2.0 and MIT licences (Bottlerocket repository).

Vendor and project pages read for this page (2026-11-03):

- [Bottlerocket repository](https://github.com/bottlerocket-os/bottlerocket)
- [Bottlerocket README](https://raw.githubusercontent.com/bottlerocket-os/bottlerocket/develop/README.md)
- [Bottlerocket latest release](https://github.com/bottlerocket-os/bottlerocket/releases/latest)
- [Bottlerocket security advisories](https://github.com/bottlerocket-os/bottlerocket/security/advisories)

<!-- os-pages:end -->
