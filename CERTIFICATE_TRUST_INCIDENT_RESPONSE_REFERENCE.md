# Certificate Trust Incident Response

This reference is a method for responding to a certificate-trust incident: a certificate authority that is compromised, distrusted, or removed from root stores. The work is to identify how each client verifies certificates, update the correct trust source, test the result, and record what remains unknown. The October 2026 eMudhra (emSign) intermediate-CA incident is the worked example, and the method adapts to any certificate-trust event. It is written for a vulnerability management or incident-response analyst who has to drive this across an estate.

| Attribute | Value |
|---|---|
| Trigger | CA key compromise, explicit distrust, or root-store removal |
| Unit of assessment | One client or executable path, its trust source, its deployment and network context |
| Controls involved | Revocation, explicit distrust, Certificate Transparency, root-store updates |
| Hard rule | A successful update is evidence; a passing application test is proof |

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management and incident-response analysts driving a certificate-authority distrust across an estate

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,248 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

A certificate authority is compromised, distrusted, or removed from root stores, you need to find which clients still trust it, or you are deciding whether a scanner result proves a client path is fixed

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[The response method](#the-response-method), [Trust in runtimes and languages](#trust-in-runtimes-and-languages), [The assessment decision model](#the-assessment-decision-model)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md), [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md), [Scanner Platforms and Findings Catalog](SCANNER_PLATFORMS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How certificate trust works

A certificate lets a client authenticate the service it reached. A chain links the service certificate through intermediate CAs to a trusted root in the client's trust store. If an intermediate signing key is compromised, an attacker who can also control the traffic path can present certificates that vulnerable clients accept.

Four controls are distinct, and confusing them causes false confidence:

- Revocation (CRL and OCSP): the CA marks a certificate invalid, but many non-browser clients do not check revocation by default.
- Explicit distrust: a vendor blocks a specific CA regardless of revocation.
- Certificate Transparency: public logs make misissuance detectable after the fact; they do not block it.
- Root-store update: the trusted-roots set the client uses is changed.

The trap: an operating-system update can fix one client while an application keeps using its own separate certificate bundle. A successful OS patch is one piece of evidence, not the whole answer, which is why every path ends in an application test.

## The response method

For each client, four steps:

1. Identify the verifier: which TLS backend and trust source this client actually uses (the OS store, a language runtime's bundle, a vendored library, or an environment override).
2. Update the correct trust source: patch or update the exact store that client reads, not just the OS.
3. Test the result: confirm the client now rejects the bad chain for the right reason and still succeeds against a good control endpoint.
4. Record the unknowns: note where you could not confirm, and treat those as open.

## Organization-wide response sequence

- Same day: inventory clients and served certificates across accounts, regions, sites, users, service identities, ephemeral workers, and vendors. Prioritize internet-facing services, remote administration, identity, software distribution, and clients that carry secrets. Record asset owner, business criticality, TLS backend, effective trust source, patch state, and deployment path.
- Contain: patch or update through vendor mechanisms. For confirmed accepting paths, reduce exposure with supported distrust, or restrict egress to verified endpoints while preserving required traffic. Keep a change record, exact versions, a rollback plan, and any compensating controls.
- Rebuild and recover: rebuild immutable and golden images, redeploy services, restart long-running clients, and refresh browser and application state so cached trust does not linger.

## Trust stores by platform

The operating-system CA bundle is the trust source for many, but not all, clients.

```bash
# Debian / Ubuntu
dpkg-query -W ca-certificates
sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates
sudo update-ca-certificates

# RHEL / Fedora / Rocky / Alma
rpm -q ca-certificates
sudo dnf upgrade ca-certificates
sudo update-ca-trust extract

# Alpine
apk info -v ca-certificates ca-certificates-bundle
sudo apk upgrade --no-cache ca-certificates ca-certificates-bundle && sudo update-ca-certificates

# Arch
sudo pacman -Syu ca-certificates ca-certificates-mozilla

# FreeBSD (confirm package and service policy first)
sudo pkg upgrade ca_root_nss
```

Windows uses the Schannel trust store, updated through Windows Update and certificate trust lists; macOS uses the system keychain and Security framework, updated through system updates.

## Trust in runtimes and languages

Many clients do not read the OS store. Identify the backend, then update the store that client actually uses, and test the real client.

- Node.js: reads its own bundle unless `NODE_USE_SYSTEM_CA` or `NODE_EXTRA_CA_CERTS` is set. Check `process.versions.openssl` and those environment variables, update Node, and rebuild.
- Python: check `ssl.get_default_verify_paths()`, and update `certifi` (which `requests` and others use) in addition to the OS bundle.
- curl, openssl, git: check `openssl version -a`, `curl -V`, and git's `http.sslBackend` and `http.sslCAInfo`; also the `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, and `REQUESTS_CA_BUNDLE` environment overrides.
- PHP: check `openssl_get_cert_locations()` and `curl.cainfo`.
- Ruby: check `OpenSSL::X509::DEFAULT_CERT_FILE` and the Gemfile; some gems carry their own CA data.
- Perl: `Mozilla::CA` if present (not every client uses it).
- Rust: inspect the dependency graph with `cargo tree -i rustls-webpki`, `cargo tree -i webpki-roots`, and `cargo tree -i native-tls`; update the packages present and rebuild with `--locked`.
- .NET, Swift, C and C++: record the backend (Schannel, SecureTransport, OpenSSL, BoringSSL, or a vendored library), update the runtime, OS, and package, and rebuild if TLS is vendored.
- JVM (Java, Kotlin, Scala, Groovy, Clojure): inventory each bundled JRE, its options, and any custom trust managers; test through the real application client after a JVM restart.

## Containers, cloud, and CI

- Containers and Kubernetes: a running container trusts the CA data in its image. Restarting a pod does not patch the image. Rebuild images from patched base packages, pin digests rather than mutable tags, and verify the image digest on every replica, then test in-pod egress after restart.
- Cloud and SaaS: update customer-managed layers and configuration; for managed trust, obtain the provider's confirmation; rotate served certificates if the chain is affected. Test the exact workload and service-identity path, and retain the provider advisory, ticket, and deployment IDs.
- CI and supply chain: build runners and base images carry trust too; update them so a build does not re-introduce a bad bundle.

## Testing the result

A green result requires the client to reject the intended certificate for the right reason, plus a working control path to a good endpoint. DNS failures, proxy errors, timeouts, and hostname mismatches are inconclusive, not passes. Test the actual deployed client, not a stand-in, because an OS fix does not prove an application that carries its own bundle is fixed.

## The assessment decision model

- The unit of assessment is one executable or client path, using a particular trust source, in a particular deployment and network context. A single host can have both protected and accepting clients.
- A package version, an image tag, a browser build, or a scanner result is one observation, not the whole assessment.
- A remote HTTPS scanner assesses the server's presented certificate and protocol settings. It does not prove whether that server's outbound clients trust the compromised CA. Use authenticated collection or a controlled outbound application test for client-trust findings. See [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).
- Certificate hunting: compare full SHA-256 fingerprints for exact certificate objects, and SPKI hashes for the same key across certificate representations. A root present in a store does not prove an accepting intermediate path.
- Never report source-string counts (matches in repositories or configuration) as counts of affected production assets; generated code, vendored tests, and duplicate working copies inflate them.

## The eMudhra example

In October 2026 eight eMudhra (emSign) intermediate CA keys were found to be weakly generated, and the emSign ECC Root CA G3 was distrusted across browsers, operating systems, and software ecosystems. Browsers blocked it within days through root removal and blocklists. Non-browser clients (curl, Python, Node.js, Go, Git, and container images) did not, because they do not check revocation by default and carry their own trust data, so they stayed exposed until their bundles were updated. That gap, where a browser is fixed but a server's outbound client is not, is the reason this method centers on the client path rather than the browser. See [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md).

## Learning resources

- Re-fetch the vendor and incident advisories on the day you act; listed patch guidance and version floors change.
- For the cryptography behind trust chains see [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md); for finding exposed clients see [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md) and [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md); for the response process see [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Identity and data protection](/hubs/identity-and-data-protection.md)
- [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md)

<!-- related:end -->
