# Local agent workspace

Open http://localhost:3000. Enter a public GitHub repository and describe a review task. The yeetkit interface calls the loopback operator API and polls its progress. Tasks are interpreted within a bounded source-review toolset; they are not arbitrary shell commands.

The operator fetches GitHub source pinned to a commit (up to 16 sampled files, 20 KB per file), runs Semgrep locally and queries OSV for up to eight exact-version direct npm dependencies. Repository code is never installed or executed. Source fetching and scanning belong to the trusted operator, outside the guarded model worker.

Two AkashML passes assess the task and review the evidence. Each request runs in its own guarded cgroup through kb-run and carries a placeholder to the scoped credential broker. yeet loads the eBPF LSM policy; Linux enforces configured protected file access and network destinations. The broker, not a TLS buffer rewrite, keeps upstream API keys outside the agent worker.

The optional boundary tests are independent, explicit attack probes: protected file read and off-allowlist connection. Kernel decisions are PID-correlated in ClickHouse. These probes do not demonstrate that an AI followed malicious instructions. They do demonstrate the actual boundary enforcement.

Results are local review.json artifacts. No publication, dependency installation, repository scripts or automatic patch application occurs. Sampled-source review, Semgrep findings and direct-dependency matches are not a complete security audit. GitHub API limits and model availability can stop a run; errors are shown rather than replaced with invented results.

## Separate Ubuntu desktop runtime

A local graphical Ubuntu VM named patchmedic-desktop has been provisioned separately from yeet-sdi-demo. It has XFCE, local VNC, key-based SSH, BPF LSM enabled and the compiled yeet/yeetd runtime. The current demo remains in yeet-sdi-demo until its application stack is migrated and validated. No proprietary Rust source is included.
