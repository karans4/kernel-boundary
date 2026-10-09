"use server";
const base = "http://127.0.0.1:8091";
async function call(path, method="GET") {
  const response = await fetch(base + path, {method, headers:{"Content-Type":"application/json"}, ...(method === "POST" ? {body:"{}"} : {}), signal:AbortSignal.timeout(5000)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Operator service unavailable");
  return result;
}
export async function snapshot() { return call("/api/state"); }
export async function runDemo() { return call("/api/run", "POST"); }
export async function resetDemo() { return call("/api/reset", "POST"); }
