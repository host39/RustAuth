# Parallel Database Reads

Independent `SELECT` queries outside a transaction may run concurrently on the pool with `tokio::try_join!`. Follow the paginated-list pattern:

```rust
let (rows, total) = tokio::try_join!(
    rows_query.fetch_all(&self.pool),
    count_query.fetch_one(&self.pool),
)?;
```

**Do not** run queries concurrently inside a transaction: a `Transaction` is one connection, so there is no benefit (and sqlx needs `&mut` access for each query).

**Do not** parallelize writes without a transaction.

## Reads Before Transactions

```text
Good:  parallel reads on the pool  ->  transaction with writes only
Bad:   transaction with parallel reads + writes
```

Prefetch independent reads outside the transaction. Read inside the transaction only when the read must share the snapshot of the writes, or when a decision must be made under a lock (first registration takes `pg_advisory_xact_lock` and counts users inside the same transaction; the last-administrator guard checks inside the transaction that changes the role).

## Pool Size

The library runs on the `PgPool` the application passes in, which may be small (the RustInit template uses 4 connections) and is shared with the application's own queries. Join at most two or three queries per request. For larger fan-outs, bound concurrency (for example `futures::stream::iter(...).buffer_unordered(2)`) instead of an unbounded join, and keep the request hot path (`verify` on every authenticated request) to as few queries as possible.
