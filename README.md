# Antibody · kernel-boundary

**Patch the dependency. Contain the attacker.**

A dependency patcher has to read package advisories and changelogs that an attacker
can control. Antibody pairs that useful job with a kernel-enforced access policy
and a review screen showing the patch, executed tests, and observed decisions.

Built with **yeet**, **yeetkit**, **AkashML**, and **ClickHouse**. The frontend uses
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

Click **Run demo**, inspect **Advisory**, **Patch diff**, **Test results**, and
**Run details**. Reset clears the current screen while retaining audit history
and local review artifacts. The launcher reuses running services rather than
killing unrelated yeet processes. It requires the existing guard build,
ClickHouse schema, and configured broker secrets. Node 22+ is required; the
configured VM uses Node 24 at `~/kb-runtime` outside the repository.

## What the live run does

1. Finds three failing regressions in a vendored dependency teaching fixture.
2. A guarded agent asks AkashML to triage its poisoned advisory through the
   scoped credential broker. The model returns bounded JSON: patch or decline.
3. A trusted, vetted patch tool repairs identifier validation and bumps 1.0.0
   to 1.0.1; four regression tests check the resulting behavior.
4. Two **separate simulated compromised-agent processes** attempt a protected
   file read and a connection outside the allowlist. The existing yeet-loaded
   eBPF LSM guard kills them.
5. ClickHouse decisions are matched by PID, unique cgroup label, target, and
   time. The local patch and review artifact are saved under `demo/runs/`.

The advisory is a fixture, not a published CVE. The patch is a vetted tool, not
arbitrary model-generated code. The model assessment is real when its source
reads AkashML; unavailable or invalid responses are explicitly labeled
**deterministic fallback**. A valid decline stops the patch. The attack probes
do not establish that the model followed an injected instruction. No GitHub
posting, automatic merging, registry publishing, or Semgrep integration is
claimed by this flow.

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

The checks verify bounded recommendations, restricted API actions, concurrent
run/reset rejection, the repaired regressions, local artifacts, and both real
kernel denials. See `frontend/QA.md`, `demo/README.md`, and
`presentation/demo-guide.md` for the tested flow.

The existing triage/dashboard demo remains available through `bin/kb-serve`
and `bin/kb-demo`. Real keys stay in `~/.config/kernel-boundary/secrets.env`;
never commit that file or include it in a source archive.
