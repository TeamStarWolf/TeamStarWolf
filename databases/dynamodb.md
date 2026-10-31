# Amazon DynamoDB

Amazon DynamoDB is a managed, serverless key-value and document database from AWS. It runs as a fully hosted service, so there are no servers, patches, or clusters to operate. It delivers single-digit millisecond reads and writes at any scale, with capacity that grows automatically. Access is controlled entirely through AWS Identity and Access Management (IAM).

## What it is and where it is used

DynamoDB suits workloads with high request volume and predictable access patterns, such as session stores, shopping carts, user profiles, event tracking, and IoT telemetry. It is a common choice for serverless applications built on AWS Lambda because it scales the same way and bills per request.

It is not a relational database. There are no joins, no `SELECT *` across the table, and no ad hoc querying. You design the table around the queries the application needs. When access patterns are known in advance, DynamoDB offers consistent latency that relational databases struggle to match at scale.

## Data model and architecture

Data lives in tables of items. Each item is a set of attributes, similar to a JSON object, and items in the same table need not share the same attributes beyond the key. Every table has a primary key that uniquely identifies each item.

The primary key is either a single partition key or a composite of a partition key and a sort key. DynamoDB hashes the partition key to place the item in a partition, a unit of storage and throughput. The sort key orders items within a partition, which enables range queries such as all events for a user between two dates.

Secondary indexes add more query patterns. A global secondary index (GSI) has its own partition and sort key and spans all partitions. A local secondary index (LSI) shares the table partition key but uses a different sort key. Single-table design puts multiple entity types in one table, using key prefixes and a GSI to serve every access pattern from as few tables as possible.

Capacity comes in two modes. On-demand bills per request and scales with no configuration. Provisioned mode reserves read and write capacity units, optionally with auto scaling, and costs less for steady, predictable traffic.

## Query language and interface

You work with DynamoDB through the AWS SDK or the `aws dynamodb` CLI, using a typed request API rather than a query string. `GetItem` fetches one item by key. `Query` reads items sharing a partition key, filtered by sort key conditions. `Scan` reads the whole table and should be rare. `PutItem`, `UpdateItem`, and `DeleteItem` change data.

```
aws dynamodb get-item \
  --table-name Orders \
  --key '{"pk": {"S": "USER#42"}, "sk": {"S": "ORDER#1001"}}'
```

PartiQL, a SQL-compatible query language, is also available for those who prefer SQL syntax, but it maps to the same underlying operations and the same key constraints still apply.

## Administration and operations

There is no server to manage, no operating system to patch, and no cluster to size. AWS handles replication across Availability Zones, hardware, and software. Operational work shifts to table design, capacity settings, IAM policy, and monitoring through Amazon CloudWatch.

Durability features are built in. Point-in-time recovery (PITR) keeps a continuous backup and lets you restore the table to any second in the last 35 days. On-demand backups capture a full snapshot you keep as long as you need.

```
aws dynamodb update-continuous-backups \
  --table-name Orders \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true

aws dynamodb create-backup \
  --table-name Orders \
  --backup-name orders-2026-10-31
```

Create a table from the CLI by declaring the key schema and attributes.

```
aws dynamodb create-table \
  --table-name Orders \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
```

## A worked example

Write an item, then query a partition for a range of sort keys. This is the common pattern of fetching all records for one entity.

```
aws dynamodb put-item \
  --table-name Orders \
  --item '{
    "pk":     {"S": "USER#42"},
    "sk":     {"S": "ORDER#2026-10-01"},
    "total":  {"N": "59.90"},
    "status": {"S": "shipped"}
  }'

aws dynamodb query \
  --table-name Orders \
  --key-condition-expression "pk = :u AND begins_with(sk, :p)" \
  --expression-attribute-values '{":u": {"S": "USER#42"}, ":p": {"S": "ORDER#2026"}}'
```

The `Query` reads only the items under partition `USER#42` whose sort key begins with `ORDER#2026`. It never scans the whole table, so latency and cost stay bounded regardless of table size.

## Security and hardening

DynamoDB has no database users or passwords. All authentication and authorization flow through IAM, so there is no missing-authentication gap of the kind that CWE-306 describes as long as the table is not left reachable through an over-broad role. The risk shifts to the policies you write.

Grant least privilege. An over-broad policy that allows `dynamodb:*` on `Resource: "*"` is the main hazard and maps to CWE-862, missing authorization, by letting a principal act on tables it should never touch. Scope actions and resources tightly, and use IAM condition keys such as `dynamodb:LeadingKeys` for fine-grained access that limits a principal to items whose partition key matches their identity.

```
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:Query"],
  "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
  "Condition": { "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": ["${aws:userid}"] } }
}
```

Encryption at rest is on by default using AWS Key Management Service, which addresses CWE-312, cleartext storage of sensitive information. For network isolation, use a VPC gateway endpoint so traffic to DynamoDB stays on the AWS network and never traverses the public internet.

Injection is avoided by design when you use the typed request API. Values go into `ExpressionAttributeValues` placeholders rather than being concatenated into an expression string, which keeps data separate from query structure. If you use PartiQL, use parameterized statements for the same reason; building PartiQL strings from untrusted input reintroduces CWE-943, improper neutralization of data within a query. See /SECURE_CODING_REFERENCE.md for parameterization and IAM policy guidance.

## Performance and scaling

Performance depends on key design. A good partition key spreads requests evenly across partitions. A hot partition, where one key takes a large share of traffic, throttles because each partition has a throughput ceiling. Add randomness or a composite key to spread load when one logical entity is very active.

Use `Query` and `GetItem`, not `Scan`, for predictable cost and latency. Project only the attributes you need into secondary indexes to keep them small. On-demand mode absorbs spiky traffic without planning, while provisioned mode with auto scaling is cheaper for steady load. DynamoDB Accelerator (DAX) adds an in-memory cache for read-heavy workloads that tolerate slightly stale data.

## Resources

- Amazon DynamoDB Developer Guide (official documentation)
- AWS CLI Command Reference, the `dynamodb` section

## Related pages

- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/mongodb.md
- /databases/redis.md
- /databases/cassandra.md
