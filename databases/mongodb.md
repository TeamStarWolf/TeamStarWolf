# MongoDB

MongoDB is a document database that stores records as BSON, a binary form of JSON. Each record is a document, and documents live in collections that need no fixed schema. It is used for content stores, catalogs, user profiles, event data, and application backends that evolve their shape over time.

## What it is and where it is used

MongoDB keeps related data together in a single document instead of spreading it across normalized tables. An order document can hold the customer, the line items, and the shipping address in one place. This fits applications where a read returns one aggregate at a time.

Common uses include single-view customer records, product catalogs with varying attributes, session and profile stores, and append-heavy event logging. Managed MongoDB runs as Atlas on the major clouds. Self-managed deployments run on Linux, Windows, and containers.

The document model trades join-based normalization for locality. You denormalize on purpose, then maintain consistency in application code or with multi-document transactions.

## Data model and architecture

The storage unit is a document, a set of field and value pairs encoded as BSON. BSON adds types that JSON lacks, including `ObjectId`, `Date`, `Decimal128`, and binary data. Every document carries an `_id` field, which is unique within its collection and acts as the primary key.

A collection groups documents and is the usual unit of indexing and sharding. A database holds collections. The default server storage engine is WiredTiger, which provides document-level concurrency and compression.

Indexes are B-tree structures on one or more fields. Beyond single-field and compound indexes, MongoDB supports multikey indexes on arrays, text indexes, geospatial indexes, and partial or TTL indexes. A query that is not covered by an index forces a collection scan.

## Query language and interface

Queries use a document as the filter. The filter `{ status: "active", age: { $gt: 18 } }` matches documents where `status` equals `active` and `age` is greater than 18. Operators such as `$gt`, `$in`, `$and`, and `$regex` express conditions.

The aggregation pipeline transforms documents through ordered stages. Stages include `$match` to filter, `$group` to aggregate, `$project` to reshape, `$lookup` to join collections, and `$sort`. Each stage passes its output to the next.

```javascript
db.orders.aggregate([
  { $match: { status: "shipped" } },
  { $group: { _id: "$customerId", total: { $sum: "$amount" } } },
  { $sort: { total: -1 } }
])
```

The interactive shell is `mongosh`, a JavaScript environment. Official drivers exist for Node.js, Python (PyMongo), Java, Go, C#, and more. Drivers accept the same filter and pipeline documents.

## Administration and operations

Connect with the shell and select a database.

```bash
mongosh "mongodb://localhost:27017"
use appdb
```

Create a user with a built-in role. Built-in roles include `read`, `readWrite`, `dbAdmin`, `userAdmin`, and the cluster roles `clusterAdmin` and `root`.

```javascript
use admin
db.createUser({
  user: "appuser",
  pwd: passwordPrompt(),
  roles: [ { role: "readWrite", db: "appdb" } ]
})
```

Back up and restore a database with the BSON tools.

```bash
mongodump --uri="mongodb://localhost:27017" --db=appdb --out=/backups/
mongorestore --uri="mongodb://localhost:27017" /backups/
```

Inspect server and index state.

```javascript
db.orders.getIndexes()
db.serverStatus().connections
rs.status()
```

The server configuration file is YAML, usually `mongod.conf`. It sets the data path, the bind address, the port, authorization, and TLS options.

## A worked example

Start the shell, insert documents, index a field, and read them back.

```javascript
mongosh "mongodb://localhost:27017"
use shop

db.products.insertMany([
  { name: "Cable", price: 9.5, tags: ["usb", "audio"] },
  { name: "Mixer", price: 349, tags: ["audio"] }
])

db.products.createIndex({ price: 1 })

db.products.find({ price: { $lt: 100 } }).sort({ price: 1 })

db.products.updateOne(
  { name: "Cable" },
  { $set: { price: 8.75 }, $push: { tags: "sale" } }
)

db.products.aggregate([
  { $unwind: "$tags" },
  { $group: { _id: "$tags", count: { $sum: 1 } } }
])
```

The update uses `$set` to change a field and `$push` to append to an array in one atomic operation on that document.

## Security and hardening

Authentication is off until you enable `security.authorization: enabled` and create users. SCRAM is the default mechanism. MongoDB also supports x509 certificate authentication and, in Enterprise builds, LDAP and Kerberos. Never run a reachable instance with authentication disabled, which is a missing authentication weakness (CWE-306).

Authorization is role-based. Grant each user the narrowest built-in or custom role that the application needs. Separate administrative accounts from application accounts.

Early MongoDB releases bound to all network interfaces with no authentication by default. Thousands of databases were exposed and harvested on the public internet. Current releases bind to `127.0.0.1` by default. Set `net.bindIp` to an explicit list, place the server behind a firewall, and require authentication.

Enable TLS for client and intra-cluster traffic with `net.tls.mode: requireTLS`. Enterprise builds offer at-rest encryption of the storage engine, and client-side field-level encryption keeps sensitive fields encrypted before they reach the server. Storing sensitive values in plaintext is CWE-312, cleartext storage.

NoSQL injection happens when untrusted input builds a query object. A JSON body of `{ "username": { "$ne": null } }` bound directly into a filter can return every user. The `$where` operator and `mapReduce` run server-side JavaScript and widen the risk. Cast input to the expected type, reject operator keys, and disable server-side JavaScript with `security.javascriptEnabled: false`. This is NoSQL injection, CWE-943. See /SECURE_CODING_REFERENCE.md.

## Performance and scaling

A replica set is a group of `mongod` processes that hold the same data. One primary takes writes and the secondaries replicate its oplog. If the primary fails, the set elects a new one, which gives automatic failover and high availability.

Sharding partitions a collection across shards by a shard key. The `mongos` router sends each query to the shards that hold the relevant key ranges. A well-chosen shard key spreads writes and avoids hot shards. A poor key, such as a monotonically increasing value, concentrates load.

Reads offer tunable consistency. Read concern ranges from `local` to `majority` and `linearizable`. Write concern controls how many members must acknowledge a write before it returns. `w: "majority"` protects against rollback during failover at the cost of latency.

## Resources

- MongoDB Manual (official documentation)
- *MongoDB: The Definitive Guide* by Shannon Bradshaw, Eoin Brazil, and Kristina Chodorow

## Related pages

- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/redis.md
- /databases/cassandra.md
- /databases/dynamodb.md
- /databases/elasticsearch.md
