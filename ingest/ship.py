"""Batches the guard's JSON lines into ClickHouse.

    kb-guard | python3 ingest/ship.py

Env: CH_URL (default http://localhost:8123), CH_USER, CH_PASSWORD.
"""

import base64
import json
import os
import queue
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

CH_URL = os.environ.get("CH_URL", "http://localhost:8123")
CH_USER = os.environ.get("CH_USER", "default")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "")
CGROUP_ROOT = Path("/sys/fs/cgroup/kernel-boundary")
FLUSH_ROWS = 2000
FLUSH_SECONDS = 0.2

# ts_ns is CLOCK_BOOTTIME; anchor it to the wall clock once.
BOOT_TO_WALL = time.time_ns() - time.clock_gettime_ns(time.CLOCK_BOOTTIME)

agents: dict[int, str] = {}


def agent_name(cgroup: int) -> str:
    if cgroup not in agents:
        for child in CGROUP_ROOT.iterdir():
            if child.is_dir():
                agents[child.stat().st_ino] = child.name
    return agents.setdefault(cgroup, str(cgroup))


def insert(rows: list[dict]) -> None:
    body = "\n".join(json.dumps(row) for row in rows).encode()
    query = "INSERT INTO kb.events FORMAT JSONEachRow"
    request = urllib.request.Request(
        f"{CH_URL}/?query={urllib.parse.quote(query)}", data=body, method="POST"
    )
    token = base64.b64encode(f"{CH_USER}:{CH_PASSWORD}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    urllib.request.urlopen(request, timeout=10).read()


def row(event: dict) -> dict:
    wall_ns = BOOT_TO_WALL + int(event["ts_ns"])
    return {
        "ts": f"{wall_ns // 1_000_000_000}.{wall_ns % 1_000_000_000:09d}",
        "agent": agent_name(int(event["cgroup"])),
        **{k: event[k] for k in ("cgroup", "pid", "ppid", "uid", "comm", "kind",
                                  "verdict", "mode", "path", "addr", "port", "ino", "dev")},
    }


def flusher(rows: "queue.Queue[dict]") -> None:
    batch: list[dict] = []
    deadline = time.monotonic() + FLUSH_SECONDS
    while True:
        try:
            batch.append(rows.get(timeout=max(0.0, deadline - time.monotonic())))
        except queue.Empty:
            pass
        if batch and (len(batch) >= FLUSH_ROWS or time.monotonic() >= deadline):
            try:
                insert(batch)
            except Exception as error:  # Keep the guard streaming through a ClickHouse hiccup.
                print(f"ship: insert failed, dropped {len(batch)} rows: {error}", file=sys.stderr)
            batch = []
        if time.monotonic() >= deadline:
            deadline = time.monotonic() + FLUSH_SECONDS


def main() -> None:
    rows: "queue.Queue[dict]" = queue.Queue()
    threading.Thread(target=flusher, args=(rows,), daemon=True).start()
    for line in sys.stdin:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            print(line, end="", file=sys.stderr)
            continue
        if record.get("type") != "event":
            print(line, end="", file=sys.stderr)
            continue
        if record["verdict"] == "deny":
            target = record["path"] or f"{record['addr']}:{record['port']}"
            print(f"DENY {record['comm']} {record['kind']} {target}", file=sys.stderr)
        rows.put(row(record))


if __name__ == "__main__":
    main()
