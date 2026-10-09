# PatchMedic operator workflow

The operator starts a run against a teaching dependency fixture. Semgrep CE scans the malicious incoming update before application, records three findings to ClickHouse and rejects it. Four guarded AkashML requests then perform advisory intake, exploitability, bounded code synthesis and a second-model review through the existing `/llm` broker. Agents carry only a placeholder credential.

The generated Python replacement must fit the allowed module/function syntax (VERSION 1.0.1 and normalize_slug(value); only local string operations and error handling). It is materialized in an inert candidate directory, scanned by Semgrep, and applied only after review approval and a clean scan. Four regression tests follow. A model or scan/storage failure stops the workflow; no fallback code is represented as model synthesis. Invalid/unavailable model responses retry once with visible feedback.

The existing protected-file and egress attack simulations remain separate from model reasoning. Real kernel kill decisions are matched by PID, cgroup and time in ClickHouse; they do not demonstrate that a model was actually compromised.

The UI runs outside the agent through supported yeetkit JS APIs. ClickHouse is prototype loopback storage, not an immutable audit boundary. GitHub publishing is not performed. See `presentation/demo-guide.md`, `semgrep/README.md` and `docs/ssl-swap.md` for narrative and limitations.

Run verification in Lima: `PYTHONPATH=. python3 demo/test_pipeline.py` (real local Semgrep, generation bounds and failure gates), then `python3 demo/test_service.py` with the stack running (real inference and kernel probes). Never build/run on the host.
