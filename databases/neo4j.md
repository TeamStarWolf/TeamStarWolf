# Neo4j

Neo4j is a graph database that stores data as nodes, relationships, and properties. It treats connections between records as first-class citizens, so traversing relationships is fast even across many hops. Queries are written in Cypher, a declarative language shaped around graph patterns. Clients connect over the Bolt binary protocol or HTTP.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Database administrators, developers and security engineers who run, query or assess Neo4j

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,228 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are modeling data or writing queries for Neo4j, you are administering or hardening a deployment, or you want a worked example to start from

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Data model and architecture](#data-model-and-architecture), [Security and hardening](#security-and-hardening), [A worked example](#a-worked-example)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [MongoDB](/databases/mongodb.md), [PostgreSQL](/databases/postgresql.md), [Redis](/databases/redis.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

Graph databases fit problems where relationships are the point: fraud rings, recommendation engines, social networks, identity and access graphs, supply chains, and network or infrastructure dependency maps. In security work, Neo4j backs attack-path analysis tools that model how a principal can reach a target through chained permissions.

The value shows when queries follow long chains of connections. A relational database answers these with repeated joins that slow down as depth grows. Neo4j follows stored pointers between connected records, so a multi-hop traversal stays fast regardless of total data size.

## Data model and architecture

The property-graph model has four parts. Nodes represent entities. Relationships connect two nodes, are directed, and always have a type such as `KNOWS` or `OWNS`. Both nodes and relationships hold properties, which are key-value pairs. Nodes also carry labels, such as `:Person` or `:Server`, that group them and anchor indexes.

A relationship stores a direct reference to the nodes at each end. Traversing from a node to its neighbors does not require a lookup through an index; the engine follows the pointer. This property, sometimes called index-free adjacency, is why deep traversals stay efficient.

Indexes and constraints keep data correct and lookups fast. A range or text index speeds up finding start nodes by property. A uniqueness constraint enforces that a property value, such as an email, appears on at most one node of a label. Node key constraints combine uniqueness with existence.

## Query language and interface

Cypher is the query language. Patterns are drawn with ASCII art: nodes in parentheses, relationships in square brackets between arrows. `MATCH` finds patterns, `WHERE` filters, `RETURN` projects results, and `CREATE` or `MERGE` write data.

```cypher
MATCH (p:Person {name: 'Alice'})-[:FRIEND]->(friend)
RETURN friend.name
```

`cypher-shell` is the command-line client. It connects over Bolt and runs statements interactively or from a file.

```
cypher-shell -a neo4j://localhost:7687 -u neo4j -p 'your-password'
```

Applications use official drivers for Java, Python, JavaScript, Go, and .NET, all speaking Bolt. The drivers expose sessions and transactions and support query parameters, which matter for both performance and security.

## Administration and operations

Neo4j ships the `neo4j-admin` command-line tool for operational tasks and `cypher-shell` for data and security statements. The server is configured in `neo4j.conf`.

Manage users, roles, and privileges with Cypher in the system database. Neo4j supports role-based access control, including fine-grained privileges on labels and properties in supported editions.

```cypher
CREATE USER analyst SET PASSWORD 'initial-pass' CHANGE REQUIRED;
CREATE ROLE reader;
GRANT MATCH {*} ON GRAPH neo4j NODES Person TO reader;
GRANT ROLE reader TO analyst;
```

Back up and restore with `neo4j-admin`. Online backups run against a live database in supported editions; dumps work on a stopped database.

```
neo4j-admin database backup --to-path=/backups neo4j
neo4j-admin database restore --from-path=/backups/neo4j.backup --overwrite-destination neo4j
```

## A worked example

Model a small access graph, then find who can reach a sensitive server through group membership. This is a traversal that would need recursive joins in a relational store.

```cypher
// Create the graph
CREATE (alice:Person {name: 'Alice'})
CREATE (admins:Group {name: 'Admins'})
CREATE (db:Server {name: 'prod-db', sensitive: true})
CREATE (alice)-[:MEMBER_OF]->(admins)
CREATE (admins)-[:CAN_ACCESS]->(db);

// Who can reach a sensitive server, through any number of groups?
MATCH path = (p:Person)-[:MEMBER_OF|CAN_ACCESS*1..5]->(s:Server {sensitive: true})
RETURN p.name AS person, s.name AS server, length(path) AS hops;
```

The variable-length pattern `*1..5` follows one to five relationships of the listed types. It returns each person who reaches a sensitive server and how many hops away they are, without you writing a join per level.

## Security relevance

This section is the threat-facing view of Neo4j: how it is reached and abused in the field, and which weakness classes dominate its record. The controls that defend against them are in the "Security and hardening" section that follows.

### Where it appears

- The data tier behind fraud-detection, recommendation, identity-graph, and attack-path tools, so it often holds exactly the relationship data an attacker wants to map. In security work it backs BloodHound, whose Active Directory attack-path graph is stored in Neo4j.
- Clients reach it over the Bolt binary protocol (default port 7687) and HTTP (7474 and 7473), which fingerprint an instance on the network. A default `neo4j` account left with a known or weak password is the common entry point.
- Cypher injection is the graph analogue of SQL injection when queries are built by concatenating untrusted input, letting an attacker close a literal and append clauses. The `apoc` procedure library, if installed and unrestricted, exposes procedures that read files and make outbound HTTP requests.
- Managed Aura removes host access but keeps the Cypher and authorization surface.

### Dominant weakness classes

Neo4j runs on the JVM, which is memory-managed, so the dominant classes are injection and access-control flaws rather than memory corruption.

- Data-query injection ([CWE-943](https://cwe.mitre.org/data/definitions/943.html)) through Cypher assembled by string concatenation rather than parameters.
- Missing authentication for a critical function ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)) from a default or weak `neo4j` password on a reachable Bolt or HTTP port.
- Improper privilege management ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)): broad `admin` grants, or unrestricted `apoc` procedures that reach the filesystem and network.
- Server-side request forgery ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)) via `apoc.load` procedures that fetch attacker-controlled URLs.

### Why it matters

Recognizing Bolt on port 7687 or the HTTP ports tells an auditor to test the default-credential path first, then Cypher injection and, where `apoc` is present, its file and HTTP procedures. Because BloodHound stores its attack-path data in Neo4j, an exposed instance can itself leak an organization's Active Directory relationships. Parameterizing Cypher, rotating the default password, and restricting `apoc` to an allowlist close the main paths. See [the database security reference](/DATABASE_SECURITY_REFERENCE.md) for the engine-agnostic hardening checklist.

## Security and hardening

Authentication is enabled by default. The initial `neo4j` user must change its password on first use, and leaving a default or weak password open on the network is the most common exposure, a form of CWE-306, missing authentication for a critical function. Disable or restrict the default user and create named accounts.

Authorization uses role-based access control. Grant each role the least privilege it needs, down to specific labels and properties where the edition supports it, rather than broad `admin` rights. Review privilege grants the way you would review IAM policies.

Encrypt connections. Enable TLS on Bolt and HTTP so credentials and query data do not cross the network in cleartext, which addresses CWE-312, cleartext storage or transmission of sensitive information. Configure certificates in `neo4j.conf` and require encrypted connections from drivers.

Cypher injection is the graph analogue of SQL injection (CWE-89) when a query is built by concatenating untrusted input into the Cypher string. An attacker can close a string literal and append clauses that read or delete data. The fix is parameters: pass values through the driver's parameter map, never string interpolation.

```cypher
// Safe: value is a parameter, not concatenated
MATCH (p:Person {email: $email})
RETURN p
```

```python
# Safe driver call
session.run("MATCH (p:Person {email: $email}) RETURN p", email=user_input)
```

Never place a database on the public internet with default credentials. Bind it to private interfaces and front it with controlled access. See /SECURE_CODING_REFERENCE.md for parameterization and secret-handling guidance.

## Performance and scaling

Performance starts with good start-node selection. A query that begins with an indexed property lookup, then traverses, is fast; a query that scans all nodes of a label is not. Create indexes on the properties used in `MATCH` and `WHERE` anchors, and bound variable-length patterns with an upper hop limit to avoid runaway traversals.

Neo4j scales reads with clustering: a primary handles writes and replicas serve reads. Very large graphs benefit from keeping the working set in the page cache, so size memory to the graph. Use `PROFILE` and `EXPLAIN` to read a query plan and confirm it uses indexes rather than full scans. Batch large writes in transactions of reasonable size to avoid long-held locks and memory pressure.

## Resources

- Neo4j documentation (official)
- The Cypher Manual (official)
- *Graph Databases* by Ian Robinson, Jim Webber, and Emil Eifrem

## Related pages

- [Databases](/databases/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [MongoDB](/databases/mongodb.md)
- [PostgreSQL](/databases/postgresql.md)
- [Redis](/databases/redis.md)
