"use server";
const base = "http://127.0.0.1:8091";
async function call(path, method="GET", payload={}, token="") {
  const response = await fetch(base + path, {method, headers:{"Content-Type":"application/json", ...(token?{Authorization:"Bearer "+token}:{})}, ...(method === "POST" ? {body:JSON.stringify(payload)} : {}), signal:AbortSignal.timeout(10000)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Service unavailable");
  return result;
}
export async function snapshot(token) { return call("/api/state","GET",{},token); }
export async function signUp(details) { return call("/api/signup","POST",details); }
export async function signIn(details) { return call("/api/login","POST",details); }
export async function signOut(token) { return call("/api/logout","POST",{},token); }
export async function settings(token,workspace) { return call("/api/settings","POST",{workspace},token); }
export async function runWorkspace(token,job) { return call("/api/workspace", "POST", job,token); }

export async function connectRunner(token) { return call("/api/runner","GET",{},token); }
