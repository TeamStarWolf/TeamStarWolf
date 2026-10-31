# SPARQL

SPARQL (a recursive name for SPARQL Protocol and RDF Query Language) is the standard query language for data stored as RDF, the Resource Description Framework graph model. A SPARQL query matches patterns of triples (subject, predicate, object) against a graph and returns the bindings that satisfy them. It is a W3C recommendation, used to query knowledge graphs, linked-data endpoints, and semantic-web datasets such as Wikidata and DBpedia.

| Attribute | Value |
|---|---|
| Paradigm | Declarative graph query language over RDF triple patterns |
| Typing | Values are RDF terms: IRIs, literals (with XML Schema datatypes), and blank nodes |
| First appeared | 2008 (SPARQL 1.0); 2013 (SPARQL 1.1) |
| Memory model | Managed by the triple store or query engine; SPARQL defines no memory model |
| Reference implementation | No single reference; [Apache Jena](https://jena.apache.org/) and [RDF4J](https://rdf4j.org/) are common engines |
| Typical uses | Querying knowledge graphs, linked data, and RDF datasets |
| Governance | [W3C SPARQL recommendations](https://www.w3.org/TR/sparql11-overview/) |

Related: [API Security Reference](/API_SECURITY_REFERENCE.md), [GraphQL](/languages/graphql.md), [Datalog](/languages/datalog.md), [languages index](/languages/README.md).

## Overview and history

SPARQL was standardized by the W3C to provide a common query language for RDF, which represents data as a graph of subject-predicate-object triples. SPARQL 1.0 became a recommendation in 2008; SPARQL 1.1 followed in 2013, adding aggregates, subqueries, property paths, federated queries across endpoints, and an update language for modifying graphs. It is accompanied by a protocol that defines how queries travel over HTTP to a SPARQL endpoint.

SPARQL underpins public linked-data services: Wikidata, DBpedia, and many government and library datasets expose SPARQL endpoints. It is a query language only, not a general programming language; computation beyond pattern matching, filtering, and aggregation happens in the application around it.

## Paradigm and type system

A SPARQL query is declarative: it states a pattern of triples to match, and the engine finds all variable bindings that make the pattern true. Variables are written with a leading `?`. The data model's values are RDF terms: IRIs (identifiers), literals carrying an XML Schema datatype or language tag, and blank nodes (anonymous resources).

```sparql
PREFIX foaf: <http://xmlns.com/foaf/0.1/>
SELECT ?name WHERE {
  ?person foaf:name ?name .     # match any triple with the foaf:name predicate
}
```

There is no user-defined type system; typing comes from the datatypes attached to literals (for example `"42"^^xsd:integer`), which `FILTER` expressions and functions respect. Pattern matching, not assignment, is the core operation.

## Toolchain and ecosystem

- Engines and stores: [Apache Jena](https://jena.apache.org/) (with the Fuseki server), [RDF4J](https://rdf4j.org/), [Virtuoso](https://virtuoso.openlinksw.com/), and [Blazegraph](https://blazegraph.com/) store RDF and answer SPARQL.
- Protocol: the [SPARQL 1.1 Protocol](https://www.w3.org/TR/sparql11-protocol/) defines query and update requests over HTTP; endpoints accept queries as a parameter or in the request body.
- Clients: command-line tools ship with Jena (`sparql`, `arq`); language libraries such as [rdflib](https://rdflib.readthedocs.io/) (Python) run queries against local or remote graphs.
- Formats: results return as JSON, XML, or CSV for `SELECT`, and as RDF for `CONSTRUCT` and `DESCRIBE`.

```bash
# Query a SPARQL endpoint with curl (point at a live service such as query.wikidata.org/sparql)
curl -G https://example.org/sparql \
  --data-urlencode 'query=SELECT ?s WHERE { ?s ?p ?o } LIMIT 1' \
  -H 'Accept: application/sparql-results+json'
```

## Syntax tour

```sparql
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX foaf: <http://xmlns.com/foaf/0.1/>

# SELECT returns variable bindings
SELECT ?name (COUNT(?friend) AS ?friends)
WHERE {
  ?person foaf:name ?name .
  OPTIONAL { ?person foaf:knows ?friend . }   # match even if absent
  FILTER (STRLEN(?name) > 3)                   # constrain bindings
}
GROUP BY ?name
ORDER BY DESC(?friends)
LIMIT 10

# CONSTRUCT builds a new RDF graph from matches
CONSTRUCT { ?person foaf:name ?name . }
WHERE     { ?person foaf:name ?name . }

# Property paths traverse relationships of arbitrary length
SELECT ?ancestor WHERE {
  <http://example.org/alice> foaf:knows+ ?ancestor .
}
```

## Idioms and different approaches

- Declare `PREFIX` abbreviations for the IRIs you use so patterns stay readable.
- Use `OPTIONAL` for data that may be absent rather than assuming every resource has every property; a missing optional leaves its variables unbound instead of dropping the row.
- Constrain results with `FILTER` for value tests and with more specific triple patterns for structure; a tighter pattern is usually cheaper than a broad pattern plus a filter.
- Reach for property paths (`foaf:knows+`, `/`, `|`) to traverse relationships without writing recursive joins.
- Choose the query form by need: `SELECT` for tabular bindings, `ASK` for a boolean, `CONSTRUCT` to build a graph, and `DESCRIBE` to retrieve a resource's triples.

## Design principles

SPARQL is built directly on the RDF data model, so its primitive is the triple pattern and its operation is graph matching. The language is declarative and set-oriented: a query says what to match, and the engine decides how. SPARQL 1.1 extended the core with aggregation, subqueries, paths, and federation while keeping the matching model intact, and it added a separate update language rather than overloading queries with writes. The federation feature reflects a linked-data goal: a query can pull from several endpoints as if they were one graph.

## Standard functions and features

SPARQL's built-in functions operate on RDF terms: string functions (`STRLEN`, `SUBSTR`, `REPLACE`, `REGEX`, `CONCAT`), numeric and date functions, type tests (`isIRI`, `isLiteral`, `BOUND`), and construction functions (`IRI`, `STRDT`, `BNODE`). Aggregates include `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, and `GROUP_CONCAT`. The query forms (`SELECT`, `CONSTRUCT`, `ASK`, `DESCRIBE`), solution modifiers (`ORDER BY`, `LIMIT`, `OFFSET`, `DISTINCT`), and the `SERVICE` keyword for federated queries make up the rest of the language. The SPARQL 1.1 Update language adds `INSERT`, `DELETE`, and graph-management operations.

## Testing and tooling

SPARQL queries are tested by running them against fixture datasets and comparing result sets; the W3C publishes conformance test suites that engines use to validate their implementations.

```sparql
# A boolean check usable as a test assertion
ASK {
  <http://example.org/alice> <http://xmlns.com/foaf/0.1/name> "Alice" .
}
```

Engines provide query explain or profiling output to inspect how a query is evaluated, and validation tools such as [SHACL](https://www.w3.org/TR/shacl/) check that the underlying RDF data conforms to a shape, which complements query testing.

## Performance and query execution

SPARQL performance depends on the engine's query planner, which reorders triple patterns and chooses join strategies and indexes. The main lever an author controls is selectivity: put the most constraining patterns first conceptually, bind to specific IRIs where possible, and avoid patterns where subject, predicate, and object are all variables, which can scan the whole graph. Property paths of unbounded length (`+`, `*`) and large `OPTIONAL` blocks can be expensive, so constrain them.

Federated queries (`SERVICE`) send sub-queries to remote endpoints; a selective pattern sent to the remote side transfers less data than pulling a graph back and filtering locally. Concurrency is a property of the triple store, not the language: stores serve many queries in parallel and may evaluate parts of one query concurrently, but SPARQL itself specifies results, not execution threads.

## Common pitfalls

- A fully unbound triple pattern (`?s ?p ?o`) without other constraints can match the entire dataset; always add `LIMIT` when exploring and tighten patterns for real queries.
- `OPTIONAL` semantics surprise newcomers: an unmatched optional leaves variables unbound rather than removing the solution, and the order of optionals can change results.
- Missing or wrong `PREFIX` declarations cause patterns to match nothing silently, because an IRI typo is just a different IRI.
- Datatype and language-tag mismatches make a `FILTER` comparison fail even when the lexical values look equal; compare with the right datatype.
- Default versus named graphs: querying the wrong graph, or assuming a single default graph when the store uses several, returns empty or partial results.

## Secure coding

When applications build SPARQL queries from user input, the central risk is injection into the generated query:

- SPARQL injection: concatenating untrusted input into a query string lets an attacker alter the query, read data outside the intended scope, or, with the update language, modify or delete graph data. Build queries with parameterized APIs or a query builder that escapes and binds values as RDF terms rather than string concatenation; this is the SPARQL case of query injection, related to [CWE-943](https://cwe.mitre.org/data/definitions/943.html) and the injection family at [CWE-89](https://cwe.mitre.org/data/definitions/89.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Update-language exposure: SPARQL 1.1 Update can change data, so an endpoint that accepts updates from untrusted clients, or an application that routes user input into an update, risks unauthorized modification. Separate read and write endpoints, and require authorization for updates. Missing checks map to [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
- Resource exhaustion: broad or unbounded queries (full-graph scans, unbounded property paths) can exhaust server resources; enforce query timeouts, result-size limits, and complexity limits on public endpoints, which addresses uncontrolled resource consumption, [CWE-770](https://cwe.mitre.org/data/definitions/770.html). See [API Security Reference](/API_SECURITY_REFERENCE.md).
- Federation trust: a `SERVICE` clause makes the engine contact another endpoint; a query that directs federation at an attacker-controlled or internal address can be used to probe internal services, a server-side request forgery concern, [CWE-918](https://cwe.mitre.org/data/definitions/918.html). Restrict which endpoints federation may reach.

Tooling: use the query-building APIs of engines such as [Apache Jena](https://jena.apache.org/) and [RDF4J](https://rdf4j.org/) that bind parameters rather than concatenating strings, and apply SHACL validation to data; see also [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) for the libraries involved.

## Learning resources

- [SPARQL 1.1 Query Language](https://www.w3.org/TR/sparql11-query/), the W3C recommendation.
- [SPARQL 1.1 Overview](https://www.w3.org/TR/sparql11-overview/), a map of the SPARQL 1.1 documents.
- [Apache Jena ARQ documentation](https://jena.apache.org/documentation/query/), a practical guide to writing and running queries.

## Related pages

- [API Security Reference](/API_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [GraphQL](/languages/graphql.md)
- [Datalog](/languages/datalog.md)
- [All languages](/languages/README.md)
