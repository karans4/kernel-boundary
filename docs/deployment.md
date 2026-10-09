# Install PatchMedic on a Linux runner

PatchMedic is a self-hosted application. Accounts, password hashes, sessions and task history are persisted in `demo/data/accounts.sqlite3`. Back up this directory privately; do not commit it. Session tokens expire after 24 hours and sign-out revokes them. Each browser keeps its session in sessionStorage; account-specific UI runs in a yeetkit client island. The loopback backend checks authentication and ownership for every task/history request.

## Runtime prerequisites

Use a Linux host or VM with BPF LSM enabled, BTF, cgroup v2, clang, bpftool, Python 3, Node >=22, Semgrep OSS and the compiled yeet/yeetd runtime. The current validated stack is Lima `yeet-sdi-demo`; a separate Ubuntu graphical VM has yeetd but has not yet received the full application stack.

1. Install the application checkout and frontend dependencies. Run `make`, then `cd frontend && npm run build`. No yeet Rust source is part of this repository.
2. Start ClickHouse on loopback and create the tables using `clickhouse/schema.sql`. Keep its HTTP port private.
3. Store real upstream keys in `~/.config/kernel-boundary/secrets.env` with mode 600. Start `broker/broker.py` with those variables in its environment. The app backend and agent workers do not load that file.
4. Start `KB_ALLOW_HOSTS='' bin/kb-guard kill | python3 ingest/ship.py` under a supervised service. Existing kb-run needs configured sudo/cgroup permissions. Validate the guard before accepting agent jobs; do not expose a runner with an inactive guard.
5. Run `bin/kb-app` from the application user, with Node/yeet/Semgrep on PATH. It starts the loopback account/task backend and yeetkit web application. Use a process supervisor to restart it and preserve the data directory.
6. Open the app, create a local account and workspace, and start a repository task. Email identifies a local account; it is not verified and no password-reset mail is sent.

## Public server exposure

Serve the frontend through HTTPS, including its WebSocket transport. A Caddy reverse proxy can use:

```
patchmedic.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

Leave the backend (8091), broker (8899), ClickHouse (8123), isolate portal (3001), and daemon private. Restrict account creation to trusted users at the reverse proxy until invitation controls exist. Apply request/connection limits there. HTTPS is required for remote login; localhost HTTP is for development only.

This release is an installable single-runner application, not a hardened public multi-tenant service. It supports persistent accounts and owner-scoped histories, but lacks email verification, password recovery, invitations, multi-runner scheduling and per-workspace kernel policies. A single runner serializes tasks. Accounts do not create separate OS users or separate kernel policy; the operator manages one shared policy. Public-source inspection is bounded and does not execute repository code.
