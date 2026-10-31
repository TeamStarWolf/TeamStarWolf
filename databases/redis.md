# Redis

Redis is an in-memory key-value store and data-structure server. It keeps data in RAM for low-latency reads and writes, with optional persistence to disk. It is used for caching, session storage, rate limiting, queues, leaderboards, and pub/sub messaging.

## What it is and where it is used

Redis maps keys to values, but the values are typed structures, not just blobs. A value can be a string, a hash, a list, a set, a sorted set, or a stream. Operations run as server-side commands against these structures.

The common role is a cache in front of a slower database. Redis also backs session stores, token buckets for rate limiting, job queues, real-time leaderboards through sorted sets, and lightweight message fan-out through pub/sub. Managed offerings include AWS ElastiCache and Redis Cloud.

Because the working set lives in memory, capacity is bounded by RAM. Persistence and replication exist to survive restarts and failures, not to extend capacity beyond memory.

## Data model and architecture

Redis is single-threaded for command execution, so each command runs to completion without interleaving. This makes individual operations atomic. The event loop handles many client connections over one core, and modern versions use extra threads for I/O only.

The core types each have their own commands. Strings hold text, numbers, or bytes. Hashes hold field-value maps under one key. Lists are ordered and support push and pop at both ends. Sets hold unique members. Sorted sets attach a score to each member and keep them ordered. Streams are append-only logs with consumer groups.

Keys can carry a time to live. An expired key is removed on access or by a background sampler. Eviction policies such as `allkeys-lru` decide what to drop when `maxmemory` is reached.

Persistence has two forms. RDB writes point-in-time snapshots on an interval. AOF (append-only file) logs every write command and replays it on restart. You can run both, trading durability against disk cost.

## Query language and interface

Redis has no query language. You call commands named after the type you touch. `SET key value`, `GET key`, `HSET hash field value`, `LPUSH list value`, `SADD set member`, and `ZADD zset score member` are typical.

```bash
SET session:42 "token" EX 3600
HSET user:7 name "Ada" role "admin"
ZADD board 100 "player1" 250 "player2"
ZREVRANGE board 0 9 WITHSCORES
```

Pub/sub uses `SUBSCRIBE channel` and `PUBLISH channel message`. Subscribers receive messages pushed to channels they hold. Streams use `XADD`, `XREAD`, and consumer groups for durable fan-out.

Lua scripting runs a script atomically on the server with `EVAL`. The script sees keys and arguments and executes without interruption, which avoids race conditions across several commands.

```bash
EVAL "return redis.call('INCR', KEYS[1])" 1 counter
```

The command-line client is `redis-cli`. Official and community clients exist for Python (`redis-py`), Node.js (`ioredis`), Java (Jedis, Lettuce), and Go.

## Administration and operations

Connect and check the server.

```bash
redis-cli -h 127.0.0.1 -p 6379
PING
INFO server
```

Read and change configuration at runtime. Persist changes to the config file with `CONFIG REWRITE`.

```bash
CONFIG GET maxmemory
CONFIG SET maxmemory 512mb
CONFIG SET maxmemory-policy allkeys-lru
```

Manage access control lists, available in Redis 6 and later. Each user has a password, allowed commands, and allowed key patterns.

```bash
ACL SETUSER appuser on ">s3cret" ~app:* +@read +@write -@dangerous
ACL LIST
```

Take a backup by copying the RDB file the server produces, or pull one through the client.

```bash
redis-cli --rdb /backups/dump.rdb
```

Trigger persistence and inspect state.

```bash
BGSAVE
LASTSAVE
DBSIZE
```

## A worked example

Use several structures to build a small counter, profile, and leaderboard.

```bash
redis-cli

SET visits 0
INCR visits
INCRBY visits 9

HSET profile:12 name "Cadi" city "STL"
HGETALL profile:12

LPUSH jobs "resize:img1" "resize:img2"
RPOP jobs

ZADD scores 42 "alice" 67 "bob"
ZINCRBY scores 10 "alice"
ZRANGE scores 0 -1 WITHSCORES

EXPIRE profile:12 600
TTL profile:12
```

`INCR` is atomic, so concurrent clients incrementing the same counter never lose an update. `EXPIRE` sets a 600-second lifetime on the profile key.

## Security and hardening

Older Redis shipped with no authentication and bound to all interfaces. An instance on a public IP accepted any command from anyone, so attackers read data, overwrote keys, and in some cases wrote SSH keys through the config. This is missing authentication, CWE-306.

Current Redis enables `protected-mode`, which refuses non-loopback connections when no password and no bind address are set. Set `bind` to explicit addresses, set a strong `requirepass`, and prefer ACL users over the single default user. Keep the port off the public internet behind a firewall or private network.

```bash
# redis.conf
bind 127.0.0.1 10.0.0.5
protected-mode yes
requirepass "a-long-random-secret"
```

Enable TLS so credentials and data do not cross the network in cleartext. Redis supports TLS on its port with certificate and key files. Storing secrets or tokens unencrypted at rest is cleartext storage, CWE-312.

Dangerous commands deserve limits. `FLUSHALL`, `CONFIG`, `DEBUG`, and `KEYS` can wipe or stall a server. Rename or disable them with `rename-command`, or deny them through ACL categories such as `-@dangerous` and `-@admin`.

`EVAL` runs arbitrary Lua on the server, and loadable modules run native code. Restrict who can call scripting and module commands, and do not load untrusted modules. Treat script bodies built from user input as an injection risk. See /SECURE_CODING_REFERENCE.md.

## Performance and scaling

Replication copies data from a primary to one or more replicas. Replicas serve reads and provide a warm copy for failover. Redis Sentinel watches a primary and promotes a replica automatically when the primary fails.

Redis Cluster shards the keyspace across nodes using 16384 hash slots. Each node owns a range of slots, and clients route each key to its slot. Cluster supports replicas per shard for availability. Multi-key operations must keep their keys in the same slot, often forced with hash tags.

Consistency is asynchronous by default, so a write acknowledged by the primary can be lost if the primary fails before replication. The `WAIT` command blocks until a number of replicas confirm, which tightens durability at the cost of latency. Plan for eventual consistency on reads from replicas.

## Resources

- Redis documentation (official documentation)

## Related pages

- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/mongodb.md
- /databases/cassandra.md
- /databases/dynamodb.md
