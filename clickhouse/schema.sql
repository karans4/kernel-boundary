CREATE DATABASE IF NOT EXISTS kb;

-- Every decision the kernel made about a guarded agent, allowed or denied.
CREATE TABLE IF NOT EXISTS kb.events
(
    ts DateTime64(9),
    agent LowCardinality(String),
    cgroup UInt64,
    pid UInt32,
    ppid UInt32,
    uid UInt32,
    comm LowCardinality(String),
    kind Enum8('open' = 1, 'connect' = 2, 'exec' = 3),
    verdict Enum8('allow' = 0, 'deny' = 1),
    mode LowCardinality(String),
    path String,
    addr String,
    port UInt16,
    ino UInt64,
    dev UInt64,
    INDEX path_tokens path TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (agent, ts);

-- Denials land here the instant they are inserted: the incident feed.
CREATE TABLE IF NOT EXISTS kb.incidents AS kb.events
ENGINE = MergeTree
ORDER BY ts;

CREATE MATERIALIZED VIEW IF NOT EXISTS kb.incidents_mv TO kb.incidents AS
SELECT * FROM kb.events WHERE verdict = 'deny';

-- Per-agent activity per second, kept incrementally for the live dashboard.
CREATE TABLE IF NOT EXISTS kb.activity
(
    second DateTime,
    agent LowCardinality(String),
    kind Enum8('open' = 1, 'connect' = 2, 'exec' = 3),
    verdict Enum8('allow' = 0, 'deny' = 1),
    hits UInt64
)
ENGINE = SummingMergeTree
ORDER BY (second, agent, kind, verdict);

CREATE MATERIALIZED VIEW IF NOT EXISTS kb.activity_mv TO kb.activity AS
SELECT toStartOfSecond(ts) AS second, agent, kind, verdict, count() AS hits
FROM kb.events
GROUP BY second, agent, kind, verdict;

-- Where each agent has ever tried to talk: a first-seen destination right
-- after a sensitive read is the exfiltration shape.
CREATE TABLE IF NOT EXISTS kb.destinations
(
    agent LowCardinality(String),
    addr String,
    port UInt16,
    first_seen SimpleAggregateFunction(min, DateTime64(9)),
    last_seen SimpleAggregateFunction(max, DateTime64(9)),
    attempts SimpleAggregateFunction(sum, UInt64),
    denied SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
ORDER BY (agent, addr, port);

CREATE MATERIALIZED VIEW IF NOT EXISTS kb.destinations_mv TO kb.destinations AS
SELECT agent, addr, port,
    min(ts) AS first_seen, max(ts) AS last_seen,
    count() AS attempts, countIf(verdict = 'deny') AS denied
FROM kb.events
WHERE kind = 'connect'
GROUP BY agent, addr, port;

-- What an agent says it did, to hold against what the kernel saw.
CREATE TABLE IF NOT EXISTS kb.claims
(
    ts DateTime64(9),
    agent LowCardinality(String),
    task String,
    kind Enum8('open' = 1, 'connect' = 2, 'exec' = 3),
    target String
)
ENGINE = MergeTree
ORDER BY (agent, ts);

-- Every call the broker made on an agent's behalf: a placeholder swapped for a
-- real credential only when the request was in scope, or refused.
CREATE TABLE IF NOT EXISTS kb.broker
(
    ts DateTime64(9),
    agent LowCardinality(String),
    route LowCardinality(String),
    method LowCardinality(String),
    target String,
    decision Enum8('forward' = 0, 'refuse' = 1),
    reason String,
    status UInt16,
    latency_ms Float32
)
ENGINE = MergeTree
ORDER BY ts;

-- Local Semgrep CE gate findings and completed scan summaries (rule_id='').
CREATE TABLE IF NOT EXISTS kb.semgrep
(
 ts DateTime64(6), run_id String, scan_id String, artifact String,
 decision LowCardinality(String), rule_id String, severity LowCardinality(String),
 path String, line UInt32, message String, findings UInt32, scanner_version String
)
ENGINE=MergeTree ORDER BY (run_id, ts);
