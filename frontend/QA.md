# Frontend verification

Concept: outputs/antibody-ui-concept.png in the Codex task. Implemented native
Solid/yeetkit UI with the same warm paper, ink sidebar, serif headline, lime
selection, split patch/evidence workspace, and colored code diff. The unified
Python diff intentionally replaces the concept's generic package.json example;
all results come from the live demo, never fabricated concept data.

Verified in Codex's in-app browser: start/run disabled state, advisory text,
patch diff, four executed test results, real model provenance, two correlated
kernel denials, reset, and presentation navigation. Desktop 1440x1000 and mobile
390x844 checked; mobile had no horizontal document overflow. Concept and final
full-page screenshot inspected with view_image. Headline and subtitle match the
concept. Diff colors, spacing, nav, tabs, button states, and timeline checked.

All builds/runtime checks ran inside Lima yeet-sdi-demo. npm run build passed;
npm run check is the project's three meaningful backend safety/integration
tests. The upstream yeetkit check command is a demo-template test harness
(counter/procs/BPF sample), so its sample-specific assertions do not apply to
this application. Supported hub/render/server bridge worked in the browser.

Node 24 is installed outside the repository at ~/kb-runtime. No framework or
daemon source patches were made. No Rust source is vendored. Upstream model
latency exceeded the original 35-second timeout once; 90-second HTTP timeout
now handles it, with explicit labeled fallback if the request still fails.

## Sponsor pipeline verification — 2026-10-09

Lima-only builds passed. Five gate tests and three live API integration tests passed. The live run exercised four real AkashML requests (GPT OSS intake/exploitability/review and Llama synthesis), local Semgrep rejection with three findings, candidate scan with zero findings, 4/4 regressions and two PID/cgroup-correlated kernel kill decisions. The backend closes application after model decline, scanner failure, empty scans or ClickHouse storage failure.

In-app browser at localhost:3000, 1280×720: run/reset, four separate completed cards, expandable assessments, patch/scan tabs and actual findings verified; no console errors or framework overlay. Deck sponsor, model pipeline, Akash rationale, static gate and architecture slides inspected. Browser viewport override did not change the rendered dimensions; this update does not claim a fresh mobile verification.
