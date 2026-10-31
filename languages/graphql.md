# GraphQL

GraphQL is a query language for APIs and a runtime for answering those queries against a typed schema. It was developed at Facebook in 2012 for internal use and released publicly in 2015. A client sends a query that names exactly the fields it wants, and the server returns a response shaped like the query, so a single request can retrieve a graph of related data and nothing more. The specification is maintained by the GraphQL Foundation, and GraphQL is used widely for web and mobile API layers.

| Attribute | Value |
|---|---|
| Paradigm | Declarative query language over a typed schema |
| Typing | Strongly typed schema: object, scalar, enum, interface, union, and input types |
| First appeared | 2012 (internal); 2015 (public); specification since 2018 |
| Memory model | Managed by the executing server runtime; GraphQL defines no memory model |
| Reference implementation | [GraphQL.js](https://github.com/graphql/graphql-js) |
| Typical uses | API query layers for web and mobile clients, API gateways, data aggregation |
| Governance | [GraphQL specification](https://spec.graphql.org/) under the GraphQL Foundation |

Related: [API Security Reference](/API_SECURITY_REFERENCE.md), [SPARQL](/languages/sparql.md), [languages index](/languages/README.md).

## Overview and history

GraphQL grew out of Facebook's need to serve data to mobile clients efficiently, where over-fetching and multiple round trips were costly. The design lets the client specify its data requirements in one request against a schema the server publishes. Facebook open-sourced the specification and a reference implementation in 2015, and in 2018 governance moved to the GraphQL Foundation under the Linux Foundation, which maintains the specification as a versioned document.

GraphQL is transport-agnostic but is almost always served over HTTP from a single endpoint. It is not a database query language and does not replace SQL; it sits in front of back ends (databases, services, other APIs) and the server's resolvers fetch the underlying data. This indirection is its strength for clients and a source of performance and security concerns for servers.

## Paradigm and type system

GraphQL is declarative: a query describes the desired shape of the result, and the server resolves each field. The schema is strongly typed, defined in the Schema Definition Language (SDL), with object types, scalars, enums, interfaces, unions, and input types. Three root operation types, `Query`, `Mutation`, and `Subscription`, define read, write, and event-stream entry points.

```graphql
type User {
  id: ID!
  name: String!
  posts(first: Int = 10): [Post!]!
}

type Query {
  user(id: ID!): User
}
```

A `!` marks a non-null field, and `[Post!]!` is a non-null list of non-null posts. The type system is what lets tools validate a query against the schema before it runs and generate client code from it.

## Toolchain and ecosystem

- Reference library: [GraphQL.js](https://github.com/graphql/graphql-js) implements the specification; server and client libraries exist for most languages.
- Servers and clients: [Apollo](https://www.apollographql.com/) and [urql](https://formidable.com/open-source/urql/) are common client and server stacks; many back ends expose GraphQL through their own libraries.
- Exploration: [GraphiQL](https://github.com/graphql/graphiql) is an in-browser query editor with schema-aware completion.
- Validation and linting: [GraphQL ESLint](https://github.com/B2o5T/graphql-eslint) and schema-diff tools check queries and detect breaking schema changes.

```bash
# Query over HTTP POST
curl -X POST https://api.example.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id:\"1\"){ name } }"}'
```

## Syntax tour

```graphql
# A query selecting a graph of related data, with variables and an alias
query GetUser($id: ID!) {
  user(id: $id) {
    name
    recent: posts(first: 3) {   # alias "recent"
      title
      comments {
        author { name }
      }
    }
  }
}

# A mutation changes data and returns the updated shape
mutation AddPost($input: PostInput!) {
  createPost(input: $input) {
    id
    title
  }
}

# A fragment factors out a reused selection set
fragment PostFields on Post {
  id
  title
}
```

## Idioms and different approaches

- Request only the fields a view needs; the point of GraphQL is that the client, not the server, decides the shape.
- Pass dynamic values as typed variables (`$id: ID!`) rather than interpolating them into the query string, which keeps queries cacheable and avoids a class of injection.
- Use fragments to share selection sets across queries and keep them consistent.
- Prefer a connection pattern (edges and page info) for lists that paginate, so clients page consistently.
- Batch and cache field resolution on the server (for example with a per-request data loader) to avoid the N+1 query problem, where resolving a list issues one back-end query per item.

## Design principles

The specification states a few guiding ideas: the schema is the contract, queries are hierarchical and mirror the data, the type system is the source of validation and tooling, and the server is introspectable so clients can discover capabilities. GraphQL favors evolving a schema by adding fields and deprecating old ones over versioning the endpoint. These choices optimize for client flexibility and tooling, and they shift complexity, including cost control, onto the server.

## Standard library and notable packages

GraphQL has no standard library in the sense a programming language does; the specification defines the language, the type system, validation rules, and execution algorithm. Built-in scalar types are `Int`, `Float`, `String`, `Boolean`, and `ID`; servers define custom scalars (such as `DateTime`) themselves. Introspection is a built-in schema (`__schema`, `__type`) that describes the API. Notable ecosystem projects include [Apollo Server](https://www.apollographql.com/docs/apollo-server/), [GraphQL Yoga](https://the-guild.dev/graphql/yoga-server), schema-stitching and federation tools for composing multiple services, and persisted-query libraries.

## Testing and tooling

GraphQL APIs are tested by running queries against a schema and asserting on responses, and by validating that queries conform to the schema before deployment.

```graphql
# A query used as a test fixture; the runner asserts on the JSON result
query {
  user(id: "1") {
    name
  }
}
```

Schema-diff tools detect breaking changes between versions of a schema, client code generators produce typed query bindings from the schema, and query-complexity analyzers estimate the cost of a query before execution. These tools stand in for the compiler and test framework of a general-purpose language.

## Performance and query execution

Because the client chooses the query shape, the server's execution cost is not fixed: a deeply nested query can fan out into many back-end calls. The classic problem is N+1 resolution, where fetching a list and then a field on each item issues one query per item; the standard remedy is to batch and cache within a request using a data loader. Field-level resolver design, caching, and limiting result sizes determine throughput.

Concurrency is handled by the server runtime, not by GraphQL itself: resolvers for sibling fields can run concurrently, and many servers resolve independent fields in parallel. The specification defines execution order constraints (mutations run serially at the top level) but leaves the concurrency mechanism to the implementation.

## Common pitfalls

- The N+1 resolver problem: resolving a list and a nested field naively issues a back-end query per element; batch with a data loader.
- Unbounded queries: without depth, complexity, or pagination limits, a single query can request an expensive or effectively unbounded amount of data.
- Error handling shape: GraphQL can return partial data alongside an `errors` array, so a response with a `200` status may still contain failures; clients must check both.
- Over-broad schemas: exposing every field and relationship makes cost control and authorization harder; design the schema for the clients that exist.
- Caching: a single POST endpoint does not benefit from HTTP caching the way distinct URLs do, so caching must be designed at the field or persisted-query level.

## Secure coding

GraphQL's flexibility is also its attack surface, because the client controls query shape and cost:

- Introspection exposure: introspection lets any client download the full schema, which aids attackers in mapping the API. Disable or restrict introspection in production, or gate it behind authentication, and do not rely on hiding fields that are still resolvable. See [API Security Reference](/API_SECURITY_REFERENCE.md).
- Query depth and complexity denial of service: a nested or aliased query can force the server to do a large amount of work from a small request. Enforce maximum query depth, a complexity or cost limit, pagination limits, and timeouts, and consider persisted queries that only allow a known set. Uncontrolled resource consumption maps to [CWE-770](https://cwe.mitre.org/data/definitions/770.html).
- Injection through resolvers: resolvers that build database queries or shell commands from arguments are vulnerable just as any back end is. Use parameterized queries and pass GraphQL arguments as data, not as concatenated strings, to avoid injection such as [CWE-89](https://cwe.mitre.org/data/definitions/89.html) and [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Authorization: GraphQL does not provide authorization; enforce it in resolvers per field and per object, because a client can reach a sensitive field through any path the schema allows. Missing checks map to [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
- Batching abuse: aliases and query batching can multiply an operation (for example, many login attempts in one request), bypassing per-request rate limits; account for operation count, not just request count.

Tooling: query-complexity and depth-limiting libraries enforce cost bounds, [GraphQL ESLint](https://github.com/B2o5T/graphql-eslint) checks query and schema hygiene, and schema linters flag over-exposure. See also the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for transport and authentication concerns.

## Learning resources

- [GraphQL specification](https://spec.graphql.org/), the authoritative definition of the language and execution.
- [graphql.org Learn](https://graphql.org/learn/), the official introduction to queries, schemas, and execution.
- [GraphQL.js](https://github.com/graphql/graphql-js), the reference implementation and its documentation.

## Related pages

- [API Security Reference](/API_SECURITY_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [SPARQL](/languages/sparql.md)
- [All languages](/languages/README.md)
