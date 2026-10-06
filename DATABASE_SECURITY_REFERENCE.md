# Database Security Reference

> The database is where the loss actually happens. Nearly every breach that matters ends at a data store: a SQL Server holding cardholder data, a PostgreSQL cluster of PII, an unauthenticated MongoDB indexed by a scanner, a Redis instance one Lua script away from host code execution. This reference is the defensive baseline for hardening the database management systems themselves: authentication, least-privilege roles, encryption at rest and in transit, activity monitoring, privileged access, audit logging, backup, and the handful of misconfigurations that cause most database incidents. It covers SQL Server, PostgreSQL, MySQL/MariaDB, Oracle, MongoDB, Redis/Valkey, and Elasticsearch. It is not a SQL-injection guide; application-layer injection lives in [WEB_APPLICATION_SECURITY_REFERENCE.md](WEB_APPLICATION_SECURITY_REFERENCE.md).

| | |
|---|---|
| Read this when | hardening a new or existing DBMS, writing a database baseline/benchmark, scoping DAM or audit-log coverage, responding to an exposed-database finding, reviewing least-privilege on a DB, or building the data-tier controls of a Zero Trust or PCI/HIPAA program |
| Start at | [The database attack surface](#the-database-attack-surface), [Universal hardening baseline](#universal-hardening-baseline), [Per-engine hardening](#per-engine-hardening-quick-reference), then the [Defender checklist](#defender-checklist) |
| Pairs with | [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md), [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md), [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md), [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md), [WEB_APPLICATION_SECURITY_REFERENCE.md](WEB_APPLICATION_SECURITY_REFERENCE.md) |

> Version note. Product versions, editions, and CVE facts below were live-verified on 2026-09-29 and carry inline sources. Databases move fast; confirm the linked original before pinning a control to a specific version or feature name.

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| DBMS hardening: auth, roles, TDE, TLS, audit, DAM, backup, misconfig (defensive baseline) | This document |
| SQL injection, NoSQL injection, ORM abuse (application layer) | [WEB_APPLICATION_SECURITY_REFERENCE.md](WEB_APPLICATION_SECURITY_REFERENCE.md), [API_SECURITY_REFERENCE.md](API_SECURITY_REFERENCE.md) |
| Classification, DSPM discovery, DLP, minimization (the data program around the DB) | [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md) |
| Cipher choice, TDE algorithm mechanics, PKI, key rotation | [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md) |
| DB credentials, dynamic secrets, KMS/HSM, vaulting | [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md) |
| RBAC design, least privilege, just-in-time access | [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) |
| Managed/cloud DB (RDS, Aurora, Cloud SQL, Cosmos DB) posture | [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md) |
| Backup architecture, immutability, restore testing | [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md), [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md) |
| Shipping DB audit logs to detection | [SIEM_REFERENCE.md](SIEM_REFERENCE.md), [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md) |

Everything here is defender-framed and policy/configuration-level. Attacker behavior is described only to the extent a defender needs it to justify a control.

---

## The database attack surface

A DBMS is not just a place data rests; it is a network service, an authentication authority, a scripting host, and a file-system client all at once. The defensive baseline follows the ways it gets abused.

| Attack surface | What goes wrong | Primary control |
|---|---|---|
| Network exposure | DB port reachable from the internet or flat internal network | Bind to localhost/private subnet; firewall/security-group allow-lists; no public IP |
| Authentication | Default/blank/shared credentials, no MFA on admin paths, legacy auth | Strong auth, disable defaults, centralize on IdP/Kerberos, MFA on privileged access |
| Authorization | Over-privileged app accounts, `PUBLIC`/`DBA`/`root` sprawl | Least-privilege roles, object-level grants, revoke default public grants |
| Data at rest | Unencrypted files, backups, and snapshots | TDE / filesystem encryption + encrypted, access-controlled backups |
| Data in transit | Cleartext client-server traffic, sniffable replication | Enforced TLS, certificate validation, encrypted replication |
| Scripting / extensibility | Stored procs, UDFs, `xp_cmdshell`, Lua, JS engines -> OS code execution | Disable unused engines; restrict script commands; run as low-privileged OS user |
| Auditing gaps | No record of who read/changed what | Native audit + DAM, forwarded off-box to a SIEM |
| Backups & exports | Unprotected dumps, replicas, and dev/test clones | Encrypt, access-control, and minimize copies (see [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md)) |

In MITRE ATT&CK terms the database sits at the intersection of Credential Access (T1552 credentials in files/config), Collection (T1213 data from information repositories, T1005 data from local system), Exfiltration (TA0010), and Impact (T1485 data destruction, T1486 encryption for ransom, T1565 data manipulation). Database audit/DAM telemetry is the detection substrate for all of these.

---

## Universal hardening baseline

These apply to every engine before any product-specific tuning. Treat as the non-negotiable floor.

1. Reduce the network surface. Bind to `localhost` or a private interface; never a public IP. Put the DB in a private subnet, restrict the port by firewall/security group to known app hosts only, and prefer a bastion, VPN, or private-link path for admin. Change from the well-known default port only as defense-in-depth, never as the sole control.
2. Eliminate default and weak credentials. Remove or rename default admin accounts, delete sample/anonymous accounts and demo databases, and set strong unique passwords or key-based auth. Verify with the engine's own audit or a CIS-Benchmark scan.
3. Patch on a defined SLA. Track DBMS CVEs (see [CVE_REFERENCE.md](CVE_REFERENCE.md)) and vendor critical-patch cycles: Oracle's quarterly Critical Patch Update, Microsoft Patch Tuesday, and the PostgreSQL/MySQL/MariaDB minor-release cadence. Prioritize anything on the CISA KEV catalog.
4. Least privilege everywhere. Application accounts get object-level grants for exactly the operations they perform, never `DBA`, `sysadmin`, `SUPERUSER`, or `root`. One service = one DB identity. Revoke default `PUBLIC` grants.
5. Encrypt in transit and at rest. Enforce TLS for all client and replication traffic; enable TDE or filesystem/volume encryption for data files, temp/undo, and, critically, backups.
6. Turn on audit logging and forward it off the box. Local logs are the first thing an attacker with DB admin clears. Ship to a SIEM/immutable store.
7. Disable unused features. OS-command surfaces (`xp_cmdshell`), unused stored-procedure/UDF/scripting engines, network-accessible management interfaces, sample schemas, and unneeded network listeners.
8. Harden the host underneath. The DB is only as safe as its OS; see [LINUX_HARDENING_REFERENCE.md](LINUX_HARDENING_REFERENCE.md) / [WINDOWS_HARDENING_REFERENCE.md](WINDOWS_HARDENING_REFERENCE.md). Run the DB service as a dedicated, non-root, low-privileged OS account.
9. Baseline against a benchmark. Apply the relevant CIS Benchmark and/or DISA STIG (both publish database baselines) and scan for drift.

---

## Authentication & least-privilege roles

Authentication (order of preference):

1. Centralized/federated identity: Kerberos/Active Directory or Azure Entra ID for SQL Server; IAM authentication for cloud-managed engines (RDS/Aurora, Cloud SQL); LDAP/SSO where supported. Fewer standing passwords, central revocation.
2. Certificate / key-based auth for service-to-service where the engine supports it.
3. Strong local passwords only where the above are impossible: long, unique, vaulted, rotated.

Add MFA to every administrative path (jump host, VPN, or IdP step-up), disable legacy/weak auth protocols, and lock/expire dormant accounts. Keep human DBA logins distinct from application service accounts; never let an app share the DBA's credentials.

Least-privilege role model:

| Principle | Implementation |
|---|---|
| Role-based, not user-based | Grant to roles; assign users/services to roles. Keeps grants auditable and revocable. |
| Object-level grants | Grant `SELECT/INSERT/UPDATE` on the specific tables/views the app touches: not schema- or database-wide, not `ALL`. |
| Separate read vs write | Reporting/analytics accounts get read-only roles; only the write path gets DML. |
| No standing admin for apps | Schema changes run through migration tooling with a separate, gated identity, not the runtime app account. |
| Revoke `PUBLIC` | Strip default public/`PUBLIC` grants that ship enabled (Oracle, PostgreSQL). |
| Review & recertify | Periodic access review of privileged DB roles; tie to joiner/mover/leaver (see [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)). |

```sql
-- PostgreSQL: least-privilege application role (illustrative)
CREATE ROLE app_ro NOLOGIN;
GRANT CONNECT ON DATABASE appdb TO app_ro;
GRANT USAGE ON SCHEMA app TO app_ro;
GRANT SELECT ON app.orders, app.customers TO app_ro;   -- object-level, read-only
CREATE ROLE app_svc LOGIN PASSWORD '<vaulted>' IN ROLE app_ro;
REVOKE ALL ON DATABASE appdb FROM PUBLIC;              -- strip default public grant
```

---

## Encryption at rest, in transit & key management

At rest: Transparent Data Encryption (TDE) encrypts data files, logs, and (configurably) backups at the storage layer, transparent to the application. It defends against stolen files, disks, and backup media; it does not protect against a compromised DB credential, which sees plaintext. Layer it with column/field encryption or application-level encryption for the most sensitive fields.

| Engine | At-rest option |
|---|---|
| SQL Server | TDE (Enterprise, and Standard since SQL Server 2019+); Always Encrypted for column-level; backup encryption |
| PostgreSQL | No native block-level TDE in community Postgres: use filesystem/volume encryption (LUKS/dm-crypt, cloud disk encryption) or a TDE-enabled distribution/managed service; `pgcrypto` for column-level |
| MySQL / MariaDB | InnoDB tablespace encryption (keyring plugin); binlog/redo encryption |
| Oracle | TDE (column and tablespace) via Advanced Security; wallet/keystore-managed |
| MongoDB | Native encryption at rest (Enterprise/Atlas); Client-Side Field Level Encryption and Queryable Encryption for field-level |
| Redis / Valkey | No native at-rest encryption of RDB/AOF: rely on filesystem/volume encryption and protect persistence files |
| Elasticsearch | Encrypt indices via filesystem/volume encryption; the Elastic keystore protects secure settings |

Key management is the hard part. Store the master/wrapping keys in a KMS or HSM, not on the DB host. Rotate on a schedule, separate key-admin duty from DB-admin duty, and back up keystores/wallets independently: losing the key means losing the data. See [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md) for algorithm/rotation mechanics and [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md) for KMS/HSM and dynamic DB credentials.

In transit: enforce TLS for all client, admin, and replication connections; require modern TLS (1.2+/1.3), validate certificates on the client, and reject non-TLS connections rather than merely offering TLS. Example (PostgreSQL `pg_hba.conf`): use `hostssl` (not `host`) for remote records and set `ssl = on`.

```conf
# pg_hba.conf — require TLS + strong auth for remote clients, no plaintext
hostssl  appdb  app_svc  10.0.0.0/24  scram-sha-256
# (omit any 'host ... trust' or 0.0.0.0/0 lines entirely)
```

---

## Per-engine hardening quick reference

Current supported releases as of 2026-09-29 (verify before pinning):

| Engine | Current release(s) | High-value hardening moves |
|---|---|---|
| SQL Server | 2022; 2025 GA Nov 2025 ([MS](https://techcommunity.microsoft.com/blog/sqlserver/sql-server-2025-is-now-generally-available/4470570)) | Windows/Entra auth over mixed mode; `xp_cmdshell` off; TDE + backup encryption; force encryption; least-priv service account; SQL Audit -> SIEM |
| PostgreSQL | 18 (18.6, Aug 2026); 19 beta ([pg](https://www.postgresql.org/support/versioning/)) | `hostssl`+`scram-sha-256` in `pg_hba.conf`; `listen_addresses` tight; revoke `PUBLIC`; `pgaudit`; row-level security; volume encryption |
| MySQL / MariaDB | MySQL 8.4 / 9.7 LTS ([MySQL](https://endoflife.date/mysql)); MariaDB 11.8 / 12.3 LTS ([MariaDB](https://mariadb.org/11-8-lts-released/)) | `mysql_secure_installation`; remove anonymous/test DB; `require_secure_transport=ON`; audit plugin; InnoDB encryption; least-priv grants |
| Oracle | 19c (support to 2032); AI Database 26ai (Oct 2025, replaces 23ai) ([Oracle](https://www.oracle.com/news/announcement/ai-world-database-26ai-powers-the-ai-for-data-revolution-2025-10-14/)) | Quarterly CPU patching; Database Vault + least-priv; TDE + wallet in HSM; Unified Auditing; revoke `PUBLIC` on powerful packages; drop default accounts |
| MongoDB | 8.0 LTS; 9.0 newest ([MongoDB](https://www.mongodb.com/docs/manual/release-notes/)) | Enable auth (`--auth`/`security.authorization`); bind to private IP; RBAC roles; TLS; encryption at rest; Queryable Encryption for sensitive fields |
| Redis / Valkey | Redis 8.x (AGPLv3 since May 2025); Valkey BSD-3 fork ([Redis](https://redis.io/blog/agplv3/)) | `requirepass`/ACLs; `protected-mode yes`; bind localhost/private; rename or ACL-restrict `EVAL`/dangerous commands; TLS; patch RediShell (below) |
| Elasticsearch | 9.x (9.5, Aug 2026) ([Elastic](https://www.elastic.co/support/eol)) | Security enabled by default (8.x+); TLS on transport+HTTP; RBAC + API keys; never expose 9200 to the internet; audit logging |

Selected per-engine notes:

- SQL Server. Prefer Windows/Entra ID authentication over SQL mixed-mode; if mixed mode is required, harden and rotate the `sa` account and rename it. Keep `xp_cmdshell`, OLE Automation, and CLR disabled unless justified. Use SQL Server Audit and forward to the SIEM. TDE plus Always Encrypted for the most sensitive columns keeps plaintext away from DBAs.
- PostgreSQL. The two files that decide most exposure are `postgresql.conf` (`listen_addresses`, `ssl = on`) and `pg_hba.conf` (auth method and source CIDR). Use `scram-sha-256` (not `md5`/`trust`), enable `pgaudit` for statement-level logging, and use row-level security for multi-tenant tables.
- MySQL / MariaDB. Run `mysql_secure_installation` (removes anonymous users, the `test` database, and remote `root`), set `require_secure_transport=ON`, load the audit plugin, and grant per-object rather than `GRANT ALL`.
- Oracle. Apply the quarterly Critical Patch Update, use Oracle Database Vault to separate duties (even DBAs shouldn't read app data by default), enable Unified Auditing, revoke `PUBLIC` execute on powerful packages (`UTL_FILE`, `DBMS_*`), and drop/lock default sample accounts.
- MongoDB. The single most important control is enabling authentication; MongoDB ships auth *off* for local dev, and unauthenticated, internet-bound instances are the classic mass-exposure case. Bind to a private interface, enable RBAC, require TLS, and use Queryable Encryption for regulated fields.
- Redis / Valkey. Designed as a trusted-network cache, so an exposed instance is dangerous by default. Keep `protected-mode` on, require a password or ACL, bind to localhost/private, and restrict or rename the scripting and admin commands (`EVAL`, `CONFIG`, `MODULE`, `FLUSHALL`, `DEBUG`). See the RediShell entry below.
- Elasticsearch. Security features are on by default in modern releases; do not disable them. Enable TLS on both the transport and HTTP layers, use role-based access and API keys, and never expose port `9200` to the internet (the historical source of countless open-index leaks).

---

## Audit logging & Database Activity Monitoring (DAM)

Native audit is the baseline; DAM is the enrichment. Each engine can log authentication, DDL, DML, and privileged actions (SQL Server Audit, PostgreSQL `pgaudit`, MySQL/MariaDB audit plugin, Oracle Unified Auditing, MongoDB auditing). Turn these on, capture who / what / when / from where, and forward off the host; see [SIEM_REFERENCE.md](SIEM_REFERENCE.md) and [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md).

Database Activity Monitoring (DAM) adds independent, real-time monitoring (often out-of-band or via an agent), behavioral baselines, and policy blocking that a DBA cannot silently disable. Established platforms (verified current, [PeerSpot 2026](https://www.peerspot.com/categories/database-security)):

| Tool | Notes |
|---|---|
| IBM Security Guardium Data Protection | Broad multi-engine DAM with behavioral analytics; long-standing enterprise standard |
| Imperva Data Security Fabric (DSF) | DAM plus discovery, classification, masking; now part of Thales |
| Oracle Audit Vault and Database Firewall (AVDF) | Consolidates audit data and adds an inline SQL firewall; strong for Oracle estates |
| DataSunrise Database Security | DAM, database firewall, masking, and discovery across many engines |
| Native cloud | Azure Defender for SQL + SQL Auditing, AWS Database Activity Streams (Aurora/RDS), Google Cloud SQL audit logs |

Detection content worth building: failed-login spikes, off-hours privileged access, bulk `SELECT`/export, schema changes outside change windows, new grants of powerful roles, and access from unexpected source hosts. Insider misuse patterns are covered in [INSIDER_THREAT_REFERENCE.md](INSIDER_THREAT_REFERENCE.md).

---

## Privileged database access & just-in-time

Standing DBA credentials are a top-tier risk: broad blast radius, rarely rotated, hard to attribute. Move privileged DB access to a brokered, just-in-time (JIT), fully-audited model:

- No shared DBA logins. Individual identities, federated to the IdP, MFA-gated.
- Just-in-time elevation. Grant admin only for a bounded window on approval; auto-revoke. Access brokers (Teleport, StrongDM, HashiCorp Boundary, CyberArk, Delinea) proxy the connection, enforce MFA, and record the session.
- Dynamic, short-lived credentials. A secrets engine (e.g., HashiCorp Vault database secrets engine) issues per-session DB credentials that expire automatically: no long-lived password to steal. See [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md).
- Session recording & command logging for every privileged connection, stored off-box.
- Separation of duties. Oracle Database Vault, MongoDB/PostgreSQL role design, and SQL Server role separation keep even DBAs from casually reading regulated application data.

This is the data-tier expression of Zero Trust; see [ZERO_TRUST_REFERENCE.md](ZERO_TRUST_REFERENCE.md) and [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).

---

## Backup, recovery & resilience

Backups are both a recovery control and a target: ransomware crews now delete or encrypt backups first, and unprotected dumps are a breach vector of their own.

- Encrypt every backup (and replicas, snapshots, and exports) with keys managed separately from the DB.
- Immutability / air-gap. Keep at least one copy immutable (object-lock/WORM) or offline; follow 3-2-1-1-0 (three copies, two media, one off-site, one immutable/offline, zero errors on verification).
- Test restores on a schedule: an untested backup is a hope, not a control. Track recovery-point/recovery-time objectives (RPO/RTO).
- Access-control the backup store as strictly as the live database; audit access to it.
- Point-in-time recovery (WAL/binlog/redo archiving) to recover from logical corruption or malicious `DROP`/`UPDATE`.

Architecture, immutability, and restore-testing detail live in [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md) and [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md).

---

## Common misconfigurations & the exposure problem

A small set of misconfigurations causes most real database incidents. Each maps to a control above.

| Misconfiguration | Consequence | Fix |
|---|---|---|
| Default / blank / shared credentials | Trivial takeover; credential stuffing | Remove defaults, unique strong auth, centralize on IdP |
| DB port exposed to the internet | Mass scanning, direct data theft/wipe | Private subnet, firewall allow-list, no public IP |
| No authentication on NoSQL/cache (MongoDB, Elasticsearch, Redis) | Anyone who reaches the port reads/writes/deletes everything | Enable auth, bind to private interface, `protected-mode` |
| Cleartext connections | Sniffed credentials and data | Enforce TLS, reject non-TLS |
| Over-privileged app account | One app bug -> full-DB compromise | Object-level least privilege |
| Unencrypted backups / snapshots | Breach via stolen copy | Encrypt + access-control all copies |
| Enabled OS-command / scripting surface | DB compromise -> host RCE | Disable `xp_cmdshell`, restrict Lua/UDFs |
| Audit logging off or local-only | No detection, no forensics | Native audit + DAM, forwarded off-box |

Threat context: unauthenticated data stores are found and abused automatically. Internet-exposed, no-auth MongoDB, Elasticsearch, and Redis instances are routinely discovered by scanners and destroyed by automated campaigns; the 2020 "Meow" bot wiped thousands of open Elasticsearch/MongoDB databases, leaving only a `meow` marker. The lesson has not changed: never expose a data store without authentication and network restriction.

Threat context: Redis scripting RCE (RediShell, CVE-2025-49844). In October 2025 Redis patched a ~13-year-old use-after-free in the embedded Lua engine that lets an authenticated user escape the Lua sandbox and run native code on the host: CVSS 10.0, dubbed "RediShell," reported by Wiz via Pwn2Own Berlin, fixed on 2025-10-03 ([Redis advisory](https://redis.io/blog/security-advisory-cve-2025-49844/), [Wiz](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844)). It affects all versions with Lua scripting. Mitigation: upgrade, and where scripting isn't required, restrict the `EVAL`/`EVALSHA` command family via ACLs (a concrete case for the "disable unused scripting surface" rule above). Track database CVEs and KEV status via [CVE_REFERENCE.md](CVE_REFERENCE.md) and [VULNERABILITY_MANAGEMENT_REFERENCE.md](VULNERABILITY_MANAGEMENT_REFERENCE.md).

---

## Benchmarks, standards & tooling

| Resource | Use |
|---|---|
| CIS Benchmarks | Consensus hardening baselines published for Microsoft SQL Server, Oracle Database, PostgreSQL, MySQL, and MongoDB; the default starting checklist |
| DISA STIGs | DoD security technical implementation guides for major databases (SQL Server, Oracle, PostgreSQL, MongoDB); stricter, control-mapped |
| Vendor security guides | Each engine's official security/hardening docs: authoritative for feature-specific settings |
| NIST SP 800-53 / CSF 2.0 | Control catalog and program framing; the data-tier controls map to `PR.DS` and `PR.AA` (see [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md)) |
| PCI DSS / HIPAA / SOX | Regulatory drivers for encryption, access control, and audit on card/health/financial data; see [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md), [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md) |
| DAM / DB firewall | Guardium, Imperva DSF, Oracle AVDF, DataSunrise; native Defender for SQL / Database Activity Streams |
| Scanning | Vulnerability scanners and CIS-CAT / benchmark scanners for drift; DSPM for discovering *where* databases and copies live ([DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md)) |

---

## Defender checklist

- [ ] DB bound to private interface; port firewalled to known app hosts; no public IP
- [ ] Default/sample/anonymous accounts removed; strong unique or federated auth; MFA on admin paths
- [ ] Application accounts hold object-level least privilege: no `DBA`/`sysadmin`/`SUPERUSER`/`root`; `PUBLIC` grants revoked
- [ ] TLS enforced for client, admin, and replication traffic; non-TLS rejected
- [ ] TDE or volume encryption on data files and backups; master keys in KMS/HSM, rotated, duty-separated
- [ ] Unused OS-command/scripting surfaces disabled (`xp_cmdshell`, Lua/UDFs, sample schemas)
- [ ] Native audit logging on; forwarded off-box; DAM covering privileged and bulk access
- [ ] Privileged access brokered, JIT, MFA-gated, session-recorded; dynamic/short-lived DB credentials
- [ ] Backups encrypted, access-controlled, immutable/air-gapped, and restore-tested; PITR configured
- [ ] Patched to a defined SLA; KEV items expedited; CIS Benchmark / DISA STIG applied and drift-scanned
- [ ] Host OS hardened; DB service runs as a dedicated low-privileged account
- [ ] NoSQL/cache stores (MongoDB, Elasticsearch, Redis/Valkey) have authentication enabled and are not internet-exposed

---

## Related Resources

- [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md): the data program around the DB: classification, DSPM discovery, DLP, minimization
- [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md): TDE algorithms, PKI, key rotation mechanics
- [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md): DB credentials, dynamic secrets, KMS/HSM
- [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md): RBAC, least privilege, JIT access
- [WEB_APPLICATION_SECURITY_REFERENCE.md](WEB_APPLICATION_SECURITY_REFERENCE.md): SQL/NoSQL injection (application layer, out of scope here)
- [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md): managed database (RDS/Aurora/Cloud SQL/Cosmos DB) posture
- [SIEM_REFERENCE.md](SIEM_REFERENCE.md), [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md): audit-log ingestion and detection content
- [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md), [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md): backup architecture, immutability, restore testing
- [CVE_REFERENCE.md](CVE_REFERENCE.md), [VULNERABILITY_MANAGEMENT_REFERENCE.md](VULNERABILITY_MANAGEMENT_REFERENCE.md): DB CVE tracking, KEV, patch prioritization
- [INSIDER_THREAT_REFERENCE.md](INSIDER_THREAT_REFERENCE.md): DBA/insider misuse detection
- [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md), [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md): PCI/HIPAA/SOX drivers and breach-notification duties

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
