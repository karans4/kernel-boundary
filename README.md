# Antibody · kernel-boundary

**Patch the dependency. Contain the attacker.**

Antibody is a **prototype autonomous security engineer for dependency updates**.
Urgent vulnerabilities pressure teams to patch quickly; trusted updates can also
carry malicious code. It assesses the advisory, checks reachability, generates a
bounded fix, scans the candidate and prepares a local review artifact.

**Patch with AI. Enforce with the kernel.** Another model's review adds judgment.
Linux eBPF LSM rules separately check actual protected file reads and connection
destinations. The runtime policy verdict does not depend on whether the agent
thinks its action is justified. Real API keys stay in the scoped broker.

Counted sponsor tools: **ClickHouse + AkashML + Semgrep**. **yeet is the core engine**, not a counted sponsor; **yeetkit** powers the review UI. The frontend uses
the public JavaScript yeetkit framework through supported interfaces. No yeet or
yeetd changes, proprietary Rust source, or Rust vendoring are included.

## Try the product

In the configured Lima VM:

```sh
limactl shell yeet-sdi-demo -- bash -lc 'export PATH=$HOME/kb-runtime/node_modules/node/bin:$HOME/.local/bin:$PATH; cd ~/kb; bin/kb-antibody'
```

- Product: http://localhost:3000
- Presentation: http://localhost:3000/presentation/index.html
- Existing telemetry dashboard: http://localhost:8090

Install local Semgrep once with `bin/kb-semgrep-setup` (Debian requires `python3-venv`).
Click **Run demo**, watch the four AkashML cards, inspect **Semgrep gate**, **Advisory**, **Patch diff**, **Test results**, and
**Run details**. Reset clears the current screen while retaining audit history
and local review artifacts. The launcher reuses running services rather than
killing unrelated yeet processes. It requires the existing guard build,
ClickHouse schema, and configured broker secrets. Node 22+ is required; the
configured VM uses Node 24 at `~/kb-runtime` outside the repository.

## What the live run does

1. Finds three failing regressions in the teaching dependency fixture.
2. Semgrep OSS scans an incoming poisoned update and rejects its postinstall,
   protected-file read and outbound HTTP. These files are never executed.
3. Four guarded AkashML requests through broker `/llm`: GPT OSS 120B assesses
   advisory legitimacy and agent-targeted instructions, then exploitability;
   Llama 3.3 70B synthesizes a minimal version bump and fix; a second GPT OSS
   pass reviews the diff for scope and new network/filesystem calls.
4. The generated replacement must pass a strict syntax envelope and a local
   Semgrep scan before application. Four regression tests check its behavior.
5. Two **separate simulated compromised-agent processes** attempt a protected
   file read and off-allowlist connection. The yeet-loaded eBPF LSM guard kills them.
6. ClickHouse stores scan summaries/findings in `kb.semgrep`, broker calls, and
   kernel decisions matched by PID, cgroup and time. The UI presents a local review.

**AI judgment is the first line; the kernel is the backstop when judgment fails.**
Semgrep is the static gate before code runs; the boundary checks runtime access
for what static analysis and models miss.

Why AkashML: these are open models hosted on Akash. Proprietary code and
advisories do not go to a closed frontier API in this workflow. Hosted inference
still sends context to AkashML; this is not on-device privacy or a retention guarantee.

The advisory is a teaching fixture, not a verified published CVE. The patch is
actually model-generated, limited to VERSION and normalize_slug(value) with
small allowed string/conditional operations. A failed or declined pass stops
application; invalid/unavailable responses retry once visibly, with no hidden
fallback. See `semgrep/README.md` for local rule coverage and OSS limitations.
The attack probes do not establish that the model followed injected instructions.
No GitHub posting, automatic merging or registry publishing is performed.

## Trust boundaries

`bpf/guard.bpf.c`, `guard/guard.js`, and `bin/kb-run` enforce the configured
protected paths and connection destinations on guarded cgroups. Execution is
observed; there is no executable allowlist. File access is not restricted to
only the workspace. The shipped demo policy permits loopback and rejects
other destinations; `bin/kb-guard` can also configure destination IPs.

`broker/broker.py` holds the real API credentials and validates placeholder,
HTTP method, and route before forwarding. The guarded triage process gets a
placeholder. The experimental SSL uprobe swap is **not** shipped here: writing
a real key into an agent's TLS buffer does not make it unreadable by that agent.

The yeetkit operator UI runs outside the guarded triage process. The Node
`use server` bridge calls a loopback fixed-action service; no arbitrary shell
endpoint or browser credential is present. Guard-originated decisions are
collected in ClickHouse rather than relying on agent claims. This prototype's
loopback services are reachable by the guarded process; audit storage is not
an immutable or authenticated security boundary. Kernel event collection can
also lose events under load. The demo verifies the records actually observed.
A passing test and configured access rules do not prove every patch is safe.

## Verification

Build and run only inside `yeet-sdi-demo`:

```sh
export PATH=$HOME/kb-runtime/node_modules/node/bin:$HOME/.local/bin:$PATH
cd ~/kb/frontend
npm ci
npm run build
# With the existing guard, ClickHouse, and backend running:
npm run check
```

`PYTHONPATH=. python3 demo/test_pipeline.py` additionally checks real local Semgrep scans, generated-code bounds and scanner/storage failure gates.

The checks verify four real model passes, incoming rejection and clean candidate scan, bounded recommendations, restricted API actions, concurrent
run/reset rejection, the repaired regressions, local artifacts, and both real
kernel denials. See `frontend/QA.md`, `demo/README.md`, and
`presentation/demo-guide.md` for the tested flow.

The existing triage/dashboard demo remains available through `bin/kb-serve`
and `bin/kb-demo`. Real keys stay in `~/.config/kernel-boundary/secrets.env`;
never commit that file or include it in a source archive.
