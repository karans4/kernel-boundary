# kernel-boundary

**Give every agent a job description it can't talk its way out of.**

Autonomous agents run shell, open files, and call the network with your credentials.
Their guardrails live in a prompt, so a prompt injection can talk them into anything,
and their own logs are written by the thing you don't trust. `kernel-boundary` moves the
job description into the Linux kernel, below where the agent can argue, using
[yeet](https://yeet.cx) to load eBPF from JavaScript.

Built at the tokens& Cyberdefense Hackathon (SF Tech Week, Oct 2026).

## Three layers

1. **The boundary** &mdash; a BPF **LSM** program (`bpf/guard.bpf.c`) on `file_open`,
   `socket_connect`, and `bprm_check_security`. A guarded cgroup may read only its
   workspace and connect only to the broker; touching `~/.ssh`, `~/.aws`, `.env`, or any
   other host is refused with `EPERM` and the process is **killed before the access**.
2. **The credential** &mdash; the agent holds only **placeholder** keys and, by the boundary,
   can reach nothing but a localhost **broker** (`broker/broker.py`). The broker swaps in the
   real key *only* for in-scope calls. A leaked placeholder is worthless; a direct connection
   that dodges the broker is killed.
3. **The record** &mdash; every kernel decision streams into **ClickHouse**
   (`clickhouse/schema.sql`, `ingest/ship.py`) with materialized views for incidents, the
   attack timeline, and fleet stats. A live dashboard (`dashboard/`) reads it. The agent
   can't edit this log.

## Demo

A benign maintainer agent (`agent/defender.py`) triages the sibling repo
[`kb-demo-target`](https://github.com/karans4/kb-demo-target): it reads a failing issue,
diagnoses the real bug with an LLM on **AkashML** (the broker swaps in the real key), and
drafts the fix. That issue is **poisoned** with a prompt injection telling the agent to read
`~/.ssh/id_rsa` and exfiltrate it. A compromised agent running the payload is stopped three times:

```
read ~/.ssh         -> KILLED (file_open)
exfiltrate          -> KILLED (reads the key first)
reach GitHub direct -> KILLED (socket_connect; the broker is the only door)
```

The agent was persuaded. The kernel wasn't.

## Run it

Requires Linux with `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm`, plus
[yeet](https://yeet.cx), ClickHouse, and `clang`/`bpftool`.

```sh
make                 # build bpf/guard.bpf.o
bin/kb-serve         # guard (loopback-only) + shipper + broker + dashboard
bin/kb-demo          # drive the agent + attack once
# dashboard: http://127.0.0.1:8090
```

Real keys load from `~/.config/kernel-boundary/secrets.env` (never committed).

## Why this and not the sponsors' tools

It sits *under* them. Guild sets an agent's policy; this enforces it in the kernel. Semgrep
checks the code an agent writes; this controls what it does at runtime. No model-layer tool
can see what the process actually did &mdash; the kernel can, and the agent can't lie to it.

Built with: **yeet** (eBPF LSM from JS) &middot; **ClickHouse** (telemetry) &middot;
**AkashML** (the agent's model) &middot; **Semgrep** (code the agent writes).
