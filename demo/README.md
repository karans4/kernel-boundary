# Antibody local recording backend

Run in the existing yeet-sdi-demo VM, from ~/kb:

    bin/kb-antibody-backend

Requires the existing guard + shipper, ClickHouse kb schema, and demo protected key
fixture at ~/.ssh/kb_demo_key. Uses the existing kernel-boundary cgroup guard
without changing policy. API binds 127.0.0.1:8091; frontend trusted Node server
should fetch this loopback API.

- GET /api/state: complete JSON state.
- POST /api/run with {}: 202, async fixed-action run; concurrent runs return 409.
- POST /api/reset with {}: clears presentation state; returns 409 during a run.
- Unknown routes: 404. Extra body fields: 400. No command execution endpoint.

Advisory triage makes a real guarded AkashML request through the existing broker
using only its inference placeholder. Bounded JSON selects patch or decline;
no model output is executed. Unavailable/invalid responses are explicitly labeled
deterministic fallback in state. A declined recommendation stops without patching.

The patch is a deterministic vendored dependency teaching fixture, not a real
published advisory/CVE. The model selects the fixed vetted patch tool; code is not model-generated. It repairs a real failing
regression fixture. Poisoned advisory instructions are displayed as untrusted
demo content. Separate simulated compromised-agent Python processes attempt
a protected-file read and off-allowlist TCP connection under kb-run. Incidents
are reported only when ClickHouse contains a real kernel denial matching the
exact target, process PID, unique cgroup agent label, and bounded probe time.
No protected content is captured or returned; probe output is discarded.
No real credentials are handled, no GitHub writes are made, and no claim is
made that a model complied with the injection.

Local artifacts: demo/runs/<runId>/review.md and patch.diff. Reset retains local
review artifacts and ClickHouse history while clearing current UI state.

Verification:

    python3 demo/test_service.py

Tests cover endpoint scope, run serialization, patch regression checks, review
creation, and correlated real kernel denials. The tests reset state to idle.
