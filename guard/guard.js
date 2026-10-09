// Loads the boundary, fills its policy, and streams every decision as one
// JSON line on stdout for the shipper.
//
//   yeet run guard/guard.js -q -y -- --guard CGID:MODE ... --protect INO:DEV ...
//     --allow4 A.B.C.D ... --allow6 HEX32 ...
import { BpfObject, HashMap, RingBuf } from "yeet:bpf";

const MODES = { audit: 1, deny: 2, kill: 3 };
const KINDS = { 1: "open", 2: "connect", 3: "exec" };

const list = (value) => (value === undefined ? [] : [value].flat().map(String));
const args = yeet.args;

const control = await new BpfObject({ exe: "../build/guard.bpf.o", base: import.meta.dirname })
  .bind("events", { kind: "ringbuf", btf_struct: "event", capacity: 65536 })
  .bind("guarded", { kind: "hash" })
  .bind("protected", { kind: "hash" })
  .bind("allowed_v4", { kind: "hash" })
  .bind("allowed_v6", { kind: "hash" })
  .start();

const guarded = new HashMap(control, "guarded");
for (const entry of list(args.guard)) {
  const [cgroup, mode = "kill"] = entry.split(":");
  await guarded.update(BigInt(cgroup), MODES[mode]);
}

const protectedInodes = new HashMap(control, "protected");
for (const entry of list(args.protect)) {
  const [ino, dev] = entry.split(":");
  await protectedInodes.update({ ino: BigInt(ino), dev: BigInt(dev) }, 1);
}

// s_addr is read straight from memory, so the key is the address bytes in
// host (little-endian) order.
const allowedV4 = new HashMap(control, "allowed_v4");
for (const ip of list(args.allow4)) {
  const [a, b, c, d] = ip.split(".").map(Number);
  await allowedV4.update((a | (b << 8) | (c << 16) | (d << 24)) >>> 0, 1);
}

const allowedV6 = new HashMap(control, "allowed_v6");
for (const hex of list(args.allow6)) {
  const addr = Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
  await allowedV6.update({ addr }, 1);
}

const ip = (family, bytes) =>
  family === 2
    ? Array.from(bytes.slice(0, 4)).join(".")
    : Array.from({ length: 8 }, (_, i) => ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16)).join(":");

const emit = (record) =>
  console.log(JSON.stringify(record, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

emit({ type: "armed", guard: list(args.guard), protect: list(args.protect), allow4: list(args.allow4) });

await new RingBuf(control, "events").subscribe(
  ({ event: e }) =>
    emit({
      type: "event",
      ts_ns: e.ts_ns,
      cgroup: e.cgroup,
      pid: e.pid,
      ppid: e.ppid,
      uid: e.uid,
      comm: e.comm,
      kind: KINDS[e.kind],
      verdict: e.verdict ? "deny" : "allow",
      mode: Object.keys(MODES).find((m) => MODES[m] === e.mode),
      path: e.path,
      ino: e.ino,
      dev: e.dev,
      addr: e.family ? ip(e.family, e.addr) : "",
      port: e.port,
    }),
  (error) => emit({ type: "error", error: String(error) }),
);
