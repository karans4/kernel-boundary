# PatchMedic console

Solid components execute in a yeet isolate through the public yeetkit framework. Supported `use server` functions bridge the operator's fixed-action local API; credentials never enter page props or browser state. No yeet/yeetd source modifications.

Build and run in Lima `yeet-sdi-demo`, repo `~/kb`:

```sh
export PATH=$HOME/kb-runtime/node_modules/node/bin:$HOME/.local/bin:$PATH
cd ~/kb/frontend
npm ci
npm run build
npm start
```

Requires Node 22+ with global WebSocket (recording runtime: Node 24 installed outside repo at ~/kb-runtime). Public yeetkit JavaScript dependency is pinned to a commit. Do not vendor proprietary Rust.

Backend: `../bin/kb-antibody-backend`, localhost8091. UI: localhost3000. Deck: /presentation/. Reset clears current display, retaining audit history and local artifacts. The demo is a teaching dependency fixture with explicit, separately executed attack probes. The broker remains the shipped credential boundary.
