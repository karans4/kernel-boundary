const Q = {
  total: "SELECT count() c FROM kb.events",
  rate: "SELECT round(count()/10, 1) c FROM kb.events WHERE ts > now() - 10",
  deny: "SELECT count() c FROM kb.events WHERE verdict = 'deny'",
  swap: "SELECT count() c FROM kb.broker WHERE decision = 'forward'",
  agents: "SELECT agent, count() total, countIf(verdict='deny') denied, max(ts) last FROM kb.events GROUP BY agent ORDER BY agent",
  feed: "SELECT toString(ts) t, agent, comm, kind, verdict, if(path != '', path, concat(addr, ':', toString(port))) target FROM kb.events ORDER BY ts DESC LIMIT 28",
  incidents: "SELECT toString(ts) t, agent, comm, kind, if(path != '', path, concat(addr, ':', toString(port))) target FROM kb.incidents ORDER BY ts DESC LIMIT 14",
  broker: "SELECT toString(ts) t, agent, route, method, decision, reason, toString(status) status FROM kb.broker ORDER BY ts DESC LIMIT 14",
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
const hhmmss = (t) => (t || "").slice(11, 19);
let latencies = [];

async function q(sql) {
  const started = performance.now();
  const res = await fetch("/q?sql=" + encodeURIComponent(sql));
  const json = await res.json();
  latencies.push(performance.now() - started);
  if (latencies.length > 20) latencies.shift();
  return json.data || [];
}

const one = async (sql) => Number(((await q(sql))[0] || {}).c || 0);

function row(cells) {
  return "<tr>" + cells.map((c) => `<td>${c}</td>`).join("") + "</tr>";
}
const pill = (cls, text) => `<span class="pill ${cls}">${text}</span>`;

async function tick() {
  try {
    const [total, rate, deny, swap] = await Promise.all([one(Q.total), one(Q.rate), one(Q.deny), one(Q.swap)]);
    $("s-total").textContent = total.toLocaleString();
    $("s-rate").textContent = rate;
    $("s-deny").textContent = deny;
    $("s-swap").textContent = swap;

    const agents = await q(Q.agents);
    $("agents").innerHTML = agents.map((a) => {
      const bad = Number(a.denied) > 0;
      return `<div class="agent ${bad ? "bad" : ""}"><div class="name">${esc(a.agent)}</div>
        <div class="meta">${bad ? "&#9632; " + a.denied + " blocked" : "&#9679; clean"} &middot; ${a.total} acts</div></div>`;
    }).join("") || '<div class="agent"><div class="meta">no agents yet</div></div>';

    const feed = await q(Q.feed);
    $("feed").innerHTML = feed.map((e) => row([
      hhmmss(e.t), esc(e.agent), esc(e.comm), e.kind,
      e.verdict === "deny" ? pill("deny", "KILL") : pill("allow", "ok"),
      `<span class="${e.verdict === "deny" ? "deny" : ""}">${esc(e.target)}</span>`,
    ])).join("");

    const inc = await q(Q.incidents);
    $("incidents").innerHTML = inc.map((e) => row([
      hhmmss(e.t), esc(e.agent), `<span class="deny">${esc(e.comm)}</span>`,
      `${e.kind} &rarr; <span class="deny">${esc(e.target)}</span>`,
    ])).join("") || row(["&mdash;", "", "", "no incidents"]);

    const broker = await q(Q.broker);
    $("broker").innerHTML = broker.map((b) => row([
      hhmmss(b.t), esc(b.agent), esc(b.route), b.method,
      b.decision === "forward" ? pill("fwd", "INJECT") : pill("refuse", "REFUSE"),
      esc(b.reason), b.status,
    ])).join("") || row(["&mdash;", "", "", "", "", "no brokered calls", ""]);

    const p50 = latencies.slice().sort((a, b) => a - b)[Math.floor(latencies.length / 2)] || 0;
    $("foot").innerHTML = `ClickHouse query latency p50: ${p50.toFixed(1)} ms &middot; ${agents.length} agents &middot; refreshed ${new Date().toLocaleTimeString()}`;
    $("live").textContent = "live";
  } catch (err) {
    $("live").textContent = "reconnecting";
  }
}

tick();
setInterval(tick, 1000);
