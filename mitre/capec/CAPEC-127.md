# CAPEC-127: Directory Indexing

<a id="capec-127"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An adversary crafts a request to a target that results in the target listing/indexing the content of a directory as output. One common method of triggering directory contents as output is to construct a request containing a path that terminates in a directory name rather than a file name since many applications are configured to provide a list of the directory's contents when such a request is received. An adversary can use this to explore the directory tree on a target as well as learn the names of files. This can often end up revealing test files, backup files, temporary files, hidden files, configuration files, user accounts, script contents, as well as naming conventions, all of which can be used by an attacker to mount additional attacks.

## Mapped ATT&CK techniques (1)

- [T1083: File and Directory Discovery](/mitre/techniques/T1083.md): Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.

## Related CWE (7)

- [CWE-424: Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html): The product does not sufficiently protect all possible paths that a user can take to access restricted functionality or resources.
- [CWE-425: Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html): The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.
- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html): The product requires authentication, but the product has an alternate path or channel that does not require authentication.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-276: Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html): During installation, installed file permissions are set to allow anyone to modify those files.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- The target must be misconfigured to return a list of a directory's content when it receives a request that ends in a directory name rather than a file name.
- The adversary must be able to control the path that is requested of the target.
- The administrator must have failed to properly configure an ACL or has associated an overly permissive ACL with a particular directory.
- The server version or patch level must not inherently prevent known directory listing attacks from working.

## Skills required

- [Low] To issue the request to URL without given a specific file name
- [High] To bypass the access control of the directory of listings

## Consequences

- Confidentiality / Read Data

## Mitigations

- 1. Using blank index.html: putting blank index.html simply prevent directory listings from displaying to site visitors.
- 2. Preventing with .htaccess in Apache web server: In .htaccess, write "Options-indexes".
- 3. Suppressing error messages: using error 403 "Forbidden" message exactly like error 404 "Not Found" message.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
