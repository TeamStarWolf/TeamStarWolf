<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Flatcar Container Linux

> An immutable, container-optimized Linux that updates by writing a new image to a passive partition and swapping partitions on reboot.

Part of [Operating systems](/operating-systems/README.md) (Container and immutable hosts). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Stable channel | None | 2026-10-29 | 4757.2.3 | Not applicable | Not applicable | Not applicable | Channel moves forward |

- Stable channel: Channel releases replace each other; there are no versions with published end-of-life dates.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Stable channel | Linux 6.12 (6.12.114 in Stable 4757.2.3) | amd64, arm64 | Independent (Flatcar project) | Stable channel |

## Where its advisories live

- [Flatcar release notes](https://www.flatcar.org/releases). Machine-readable: [Stable channel JSON](https://www.flatcar.org/releases-json/releases-stable.json).
- [Flatcar security advisories on GitHub](https://github.com/flatcar/Flatcar/security/advisories).

Each release's notes list its security fixes with CVE ids; the channel JSON carries the same notes per release.

## How it patches

Package manager: None; whole-image updates through `update_engine`.

New major releases start in the Alpha channel and are promoted to Beta and then Stable; the LTS channel gets bug-fix releases only. A reboot finishes each update, by default through `locksmithd` (Flatcar update and channel documentation).

```sh
update_engine_client -check_for_update
update_engine_client -status
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `update_engine_client -status` | Update state, for example `UPDATE_STATUS_IDLE` |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Stable channel | `ID=flatcar`, `VERSION_ID=<release version>` | Not checked on a running system |

## Hardening

- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)
- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [systemd and systemctl Reference](/commands/systemctl.md)

## On the Intelligence Hub

The library's vocabulary id for Flatcar Container Linux is `product:flatcar-container-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Flatcar releases](https://www.flatcar.org/releases)
- [Flatcar Stable channel releases (JSON)](https://www.flatcar.org/releases-json/releases-stable.json)
- [Flatcar update and reboot strategies](https://www.flatcar.org/docs/latest/updates-releases/releases/update-strategies/)
- [Flatcar: switching release channels](https://www.flatcar.org/docs/latest/updates-releases/releases/switching-channels/)
- [Flatcar security](https://www.flatcar.org/security)

<!-- os-pages:end -->
