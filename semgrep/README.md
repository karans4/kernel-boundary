# Local static gate

Semgrep Community Edition (OSS CLI) scans the incoming dependency files **before they are applied or executed**, then scans the materialized AkashML-generated replacement before application. Every scan summary (including zero findings) and every finding is stored in `kb.semgrep`, joined by run ID in the UI. Storage failure closes the gate.

`bin/kb-semgrep-setup` installs pinned Semgrep 1.180.0 into a VM-only virtualenv. No login/token required. Scans use checked-in `rules.yml`, `--oss-only`, `--metrics=off`, and disabled version checks. Source is not uploaded to Semgrep. We use custom OSS rules for install hooks, sensitive-file reads, outbound HTTP, dynamic execution and out-of-task Python network/filesystem calls. These rules are intentionally conservative and limited; they are **not** Semgrep's commercial Supply Chain/Secrets products or a comprehensive vulnerability database. No claim is made that `p/supply-chain` or `p/secrets` is available unauthenticated.

The `demo/fixtures/incoming` update contains a malicious teaching postinstall hook, sensitive file read and outbound HTTP send. It is scanned as text and never executed. It differs from the existing **separate** kernel-enforcement attack simulations; no claim is made that the live model was actually compromised.

Static findings reject the update. A clean generated candidate still needs bounded syntax checks, model self-review, tests and human review. Linux LSM policy is the runtime backstop for configured file and destination rules. Neither layer proves complete safety.
