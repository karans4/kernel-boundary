# Antibody demo guide

Start inside Lima `yeet-sdi-demo`, repo `~/kb`: `bin/kb-antibody`. If Semgrep is missing, install Debian `python3-venv`, then run `bin/kb-semgrep-setup`. Model credentials remain in `~/.config/kernel-boundary/secrets.env`; agents receive only the broker placeholder.

Open http://localhost:3000. Reset, then **Run demo**. Allow several minutes for four real inference passes (each can retry once). Watch each separate AkashML card progress. A model decline or outage closes the patch gate; it is shown honestly, never substituted with a deterministic AI-looking result.

1. Open **Semgrep gate**: the incoming update contains a poisoned postinstall, SSH-file read and outbound HTTP. Show three actual findings, **BLOCKED**, and ClickHouse storage. This update is never executed.
2. Watch intake / legitimacy: GPT OSS 120B flags agent-targeted instructions. It cannot externally verify our teaching advisory.
3. Watch exploitability: GPT OSS checks the call site and tests. The function is reached.
4. Watch patch synthesis: Llama 3.3 70B generates a minimal version bump and normalization fix within the supported syntax envelope.
5. Watch self-review: a second GPT OSS pass reviews the diff for scope, network and filesystem changes.
6. Show the second Semgrep scan: generated candidate source scanned before application, **PASSED**, zero findings. This is not a safety proof.
7. Open **Patch diff** and **Test results**. Show the generated change and 4/4 tests.
8. Show the two separate runtime attack simulations: protected file read and off-allowlist connection. Match actual kernel denials to PID, run and cgroup. Do not claim the live model followed the poison.

Narration: **AI judgment is the first line; the kernel is the backstop when judgment fails. Semgrep is the static gate before code runs; the kernel is the runtime gate for what static misses.**

Sponsor tools counted toward 3+: **ClickHouse + AkashML + Semgrep**. yeet is the **core engine**, not a counted sponsor. yeetkit is the supported public JS framework powering the review UI. No Guild or MongoDB.

Why AkashML: triage and synthesis use open models hosted on Akash. The workflow does not call a closed frontier API. Context still goes to hosted AkashML infrastructure; do not claim on-device privacy, zero retention or confidential computing.

Broker is the shipped credential path. TLS swapping is not shipped: overwriting SSL buffers would place real keys in agent memory. No yeet daemon or proprietary Rust changes are needed.

Static rules are local custom Semgrep OSS rules with metrics off. Do not describe this as licensed Semgrep Supply Chain/Secrets or exhaustive malicious-code detection. ClickHouse is loopback-accessible prototype storage, not immutable authenticated audit storage. Kernel policy covers configured file/destination access, not all execution or exfiltration paths.

Review stays local. Real GitHub posting is optional and is not performed. You record the demo yourself.
