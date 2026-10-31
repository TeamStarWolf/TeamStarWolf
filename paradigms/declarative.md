# Declarative Programming

Declarative programming describes the result you want and lets an execution engine decide the steps to produce it. It is the opposite stance from imperative code, which spells out the control flow explicitly. The style matters because it moves scheduling, optimization, and ordering decisions out of your code and into a runtime that can do them better.

## Core idea

The defining move is to separate the specification of what from the strategy of how. You state constraints, relations, or a target state. A solver, query planner, or build engine searches for a plan that satisfies the specification.

This is an umbrella, not a single technique. Functional, logic, query, and configuration languages are all declarative, because none of them require the programmer to write the loop that produces the answer. What they share is that the program is a description, and the system supplies the execution.

The practical consequence is that two correct programs in the same declarative language can run with very different performance after the engine optimizes them. You give up fine control of execution order. In return you get code that is shorter, easier to verify against the specification, and often parallelizable without change.

## How it works

A declarative program names relationships and lets the engine resolve them. Consider SQL. You describe the shape of the result set with `SELECT`, `WHERE`, `JOIN`, and `GROUP BY`. You do not say whether the engine should use a hash join or a nested loop, or which table to scan first.

```sql
SELECT c.name, SUM(o.total) AS lifetime_value
FROM customers c
JOIN orders o ON o.customer_id = c.id
WHERE o.status = 'paid'
GROUP BY c.name
HAVING SUM(o.total) > 1000;
```

The query planner reads statistics, picks join order and access methods, and may run parts in parallel. The same text can produce different plans as the data grows. Your code stays fixed while the engine adapts.

Idempotence is central to declarative configuration and infrastructure as code. The program states a desired end state, and the engine computes the difference from the current state, applying only what is needed. Running it twice yields the same result as running it once. A Terraform configuration declares resources; the engine builds, updates, or leaves them alone to converge on the declared state.

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-prod"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

This file names resources and a dependency between them. It does not call an API in sequence. The engine orders the operations from the dependency graph and skips resources already in the declared state.

Build systems work the same way. A `Makefile` rule declares that a target depends on sources and gives a recipe to rebuild it. The engine reads timestamps, computes which targets are stale, and chooses an order that respects dependencies, often running independent branches in parallel.

```makefile
report.pdf: report.tex figures.png
	pdflatex report.tex
```

Referential transparency supports this model. When an expression can be replaced by its value without changing meaning, the engine is free to reorder, cache, or skip work. Logic languages like Prolog and Datalog take the idea furthest: you state facts and rules, and the engine performs a search to answer queries, with the resolution strategy hidden behind the declarations.

## Strengths and trade-offs

Declarative code is shorter and closer to the specification, so it is easier to review for correctness. The engine can optimize and parallelize without you rewriting anything, and idempotent tools make deployments repeatable and safe to retry. Much of the data-processing and operations world has moved this way for these reasons.

The costs are a loss of control and a harder performance story. When a query is slow, you tune it indirectly through indexes, statistics, and hints, not by editing the algorithm. The engine is a large dependency with its own failure modes, and a leaky abstraction forces you to understand the planner you were trying to ignore. Some logic simply does not fit a declarative mold and fights the model.

## Languages and tools

Query and data languages are the most used declarative languages: [SQL](/languages/sql.md) and [SPARQL](/languages/sparql.md). Logic languages include [Prolog](/languages/prolog.md) and [Datalog](/languages/datalog.md). Purely functional languages such as [Haskell](/languages/haskell.md) are declarative in their core evaluation model.

Beyond general-purpose languages, declarative tools dominate configuration and operations. Terraform, Kubernetes manifests, Ansible, and `make` all describe a desired state or dependency graph. Markup and styling languages such as HTML and CSS are declarative: they describe structure and presentation, not rendering steps.

## Secure-coding considerations

The dominant risk in query languages is injection. Building a query by concatenating untrusted strings lets an attacker change its meaning, which is CWE-89 (SQL Injection). The fix is paradigm-aligned: use parameterized queries so user data is bound as values, never parsed as part of the declaration. The same principle extends to any declarative query surface, including LDAP and XPath filters.

Infrastructure as code carries its own hazards. A declared resource can over-permit access, so a misconfigured policy opens a bucket or security group to the world. Secrets committed into declarative configuration are exposed to everyone with repository access, which maps to CWE-798 (Use of Hard-coded Credentials). Treat state files as sensitive, because they can contain resolved secrets and the full topology of your systems.

Review declarative code against the declared state, not the apparent intent, and run policy checks that read the plan before it is applied. See /SECURE_CODING_REFERENCE.md for parameterization and least-privilege guidance that applies across these tools.

## Resources

- John W. Lloyd, *Practical Advantages of Declarative Programming*, 1994, GULP-PRODE Joint Conference on Declarative Programming
- Ben Moseley and Peter Marks, *Out of the Tar Pit*, 2006
- Harold Abelson and Gerald Jay Sussman, *Structure and Interpretation of Computer Programs*, 1996, MIT Press
- Robert Kowalski, *Algorithm = Logic + Control*, 1979, CACM

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/functional.md
- /paradigms/logic.md
- /paradigms/constraint.md
- /paradigms/dataflow.md
- /paradigms/imperative.md
