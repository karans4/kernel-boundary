# Real source and historical replay

These review paths fetch public data and prepare local artifacts. They never install the target repository's dependencies, execute its scripts, or push to its remotes. Generated pages are review snapshots, not continuous monitoring. Re-run the scripts to refresh them.

## Historical event-stream replay

Source: `qimingnan/copay`, commit `23a0eae16283549d0e53cc4f6a5719d2cca6d89e`, a preserved 2018 Copay fork. Its real npm lockfile pins event-stream 3.3.6 and flatmap-stream 0.1.1. OSV/GitHub advisory GHSA-mh6f-8j2x-4483 identifies the malicious dependency. npm's incident report documents the Copay-targeted wallet theft; we do not assert this individual fork shipped an infected app.

`python3 demo/historical.py` requires that pinned repository at `demo/repositories/copay-2018`, the existing broker/guard/ClickHouse stack, and local Semgrep. Four guarded AkashML passes assess intake, dependency reachability, the proposed rollback, and review. The trusted operator constructs a deterministic lockfile proposal using npm metadata; models assess it rather than execute arbitrary generated code. `semgrep/historical.yml` checks explicit known-malicious version pins, not the original encrypted payload.

The proposal rolls back event-stream to the prior 3.3.4 release and removes flatmap-stream. JSON structure, absence of residual flatmap requirements, and the static gate are checked. Installation consistency, build compatibility, and repository tests remain pending. No fix is applied to the source checkout.

The script separately runs inert protected-file and off-allowlist-connection probes under the existing yeet-loaded policy and correlates actual kill decisions in ClickHouse. It never executes the original malware and does not prove containment of wallet secrets already resident in an application's memory.

Result: `/historical/index.html`, plus local `demo/historical-review/report.json` and `patch.diff`. These are historical evidence, not claims about current BitPay products. Public repository snapshots are excluded from our Git history.

## Real advisory review

`python3 demo/real_repo.py` reviews `PanJiaChen/vue-admin-template`, pinned locally to commit `4c18a3f47bdb417ad8a25f09910f848cb574dee2`. Its manifest pins Axios 0.18.1. OSV matches GHSA-cph5-m8f7-6c5x (CVE-2021-3749). Four guarded model passes examine supplied source and propose a targeted 0.21.2 change. Other advisories still match that version; this is not a complete upgrade recommendation. Browser use does not establish vulnerable Node-adapter reachability. No lockfile was available for proving transitive node-ipc exposure.

Result: `/real-repo/index.html`; the candidate manifest is scanned with local Semgrep and findings stored in ClickHouse. Static syntax rules are separate from advisory/version matching. No dependencies installed and no compatibility tests claimed.

## Recording

Use the historical page for the real-world story, then the main UI for the existing live fixture pipeline. Clearly say which screen is a completed historical review and which is a fresh live run. Never present cached model output as a new live request. Actual source, model assessments, proposed diff, and probe IDs are available for inspection.
