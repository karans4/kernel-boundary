# Antibody demo guide

Open http://localhost:3000 and http://localhost:3000/presentation/index.html.
Deck: arrow keys navigate, N toggles speaker notes, F toggles fullscreen.

If services need starting:

```sh
limactl shell yeet-sdi-demo -- bash -lc 'export PATH=$HOME/kb-runtime/node_modules/node/bin:$HOME/.local/bin:$PATH; cd ~/kb; bin/kb-antibody'
```

The current app is ready for review. Click Reset for a fresh starting screen,
then Run demo. The actual sequence is:

1. Inspect the intentionally vulnerable local dependency fixture.
2. Ask AkashML to triage the poisoned advisory through the scoped broker.
3. Apply the vetted patch recommended by bounded JSON, run four tests.
4. Run two explicitly separate compromised-agent simulations: protected-file
   read and connection to a documentation-only IP outside the allowlist.
5. Match both kernel denials by PID, unique cgroup label, target, and time in
   ClickHouse. Save the diff and review document locally.

Use Advisory to show the hostile text; Patch diff to show the repair; Test
results to show actual executed tests; Run details for model provenance and raw
kernel incidents. The evidence timeline remains visible alongside the patch.

Useful framing: “A patching agent has to read attacker-controlled text. We make
the patch useful, constrain its configured access, and give the reviewer
independent evidence.”

Be precise: this is a vendored teaching fixture, not a real CVE patch. AkashML
triage is real; the patch tool is fixed and vetted. If the model is unavailable
or returns invalid JSON, the UI explicitly reports deterministic fallback.
A valid decline stops patching. The attack probes are separate simulations;
they do not prove that the model followed an injected instruction. The actual
kernel guard kills the probes, and ClickHouse stores their decisions.

The shipped credential path remains the trusted broker. The unsafe TLS uprobe
swap is not used. No GitHub PR or publishing occurs; review artifacts are local.
No yeet Rust source or yeetd patches are part of this application.
