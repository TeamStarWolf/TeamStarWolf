# Chainguard

Chainguard builds secure-by-default container images and a hardened Linux base that carry few or no known vulnerabilities, which cuts the container remediation load before a scanner ever runs. Instead of hardening a general-purpose base image after the fact, it ships minimal images rebuilt continuously from source, each signed and shipped with a bill of materials. It is described at a product level as generally available in 2026; the exact image catalog and tiers depend on the subscription.

## What it is and where it fits

Most container vulnerabilities come from the base image and the packages it drags in. Chainguard's answer is to start from Wolfi, a minimal Linux build system designed for containers, and to produce distroless images that contain only what the application needs. Fewer packages means fewer CVEs, so the finding queue from image scanning shrinks. This is a shift-left supply-chain control that sits in front of [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md) and the software-composition work in [Application Security Testing](/APPSEC_TESTING_REFERENCE.md).

## Architecture and how it works

The foundation is Wolfi, an undistro with its own package build tooling (`melange` for packages, `apko` for assembling images) rather than a traditional distribution release cycle. Images are rebuilt frequently from source as fixes land upstream, so a patched version is available quickly rather than on a distribution's schedule. Each image is distributed from the Chainguard registry, signed with Sigstore, and accompanied by a software bill of materials and provenance attestations. FIPS and other hardened variants exist for regulated workloads.

## Key capabilities

- Minimal, distroless images with a low or zero count of known vulnerabilities.
- Continuous rebuilds from source, so fixes appear without waiting for a distribution release.
- A software bill of materials and Sigstore signatures and provenance for every image.
- VEX statements that communicate whether a listed vulnerability actually affects the image.
- A hardened Wolfi base for building your own images with the same properties.

## Deployment and operations

Adoption is mostly swapping base images: point a Dockerfile or build at a Chainguard image from the Chainguard registry instead of a general-purpose base, then rebuild. Operationally, the work shifts from triaging image CVEs to keeping images current and verifying signatures in the pipeline. Because the images are minimal, builds sometimes need adjustment where a tool assumed a shell or package that distroless images omit.

## Integrations and data flow

Chainguard images flow through the same registries, CI pipelines, and scanners already in use; the visible change is that scanners such as Trivy, [Snyk](/platforms/snyk.md), and [Wiz](/platforms/wiz.md) report far fewer findings against them. Signature and provenance verification fits an admission controller or a CI gate.

## Hardening and secure use

Verify image signatures and provenance before deployment with Sigstore tooling, and pin images by digest rather than a mutable tag so a rebuild cannot change what runs unseen. Protect the registry pull credentials in a secret store rather than hardcoding them (CWE-798), and keep the images current, because a low-CVE image still drifts as new vulnerabilities are disclosed.

## Where it fits in the program

Chainguard is a logical-plane preventive control for the software supply chain: it reduces the number of container vulnerabilities that ever enter the remediation queue, which is a different lever from scanning and patching after the fact. For a vulnerability management program it lowers the volume of container findings and raises the integrity of the image supply chain at the same time.

## Resources

- The Chainguard documentation and the Chainguard Academy.
- The Wolfi project documentation, and the `apko` and `melange` project documentation.

## Related pages

- [Security platforms](/platforms/README.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Application Security Testing](/APPSEC_TESTING_REFERENCE.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)
- [Docker](/commands/docker.md), [Snyk](/platforms/snyk.md), [Wiz](/platforms/wiz.md)
