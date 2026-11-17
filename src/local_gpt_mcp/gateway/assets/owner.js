// Self-contained OAuth 2.1 PKCE + passkey owner consent. Access tokens stay in memory.
const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const status = (message) => { $("status").textContent = message; };
let config;
let accessToken = "";
let credentialIds = [];
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function fromBase64url(encoded) {
  if (typeof encoded !== "string" || !/^[a-zA-Z0-9_-]+$/.test(encoded)) throw new Error("A real registered WebAuthn credential is required");
  const value = atob(encoded.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(encoded.length / 4) * 4, "="));
  return Uint8Array.from(value, (char) => char.charCodeAt(0));
}
async function digest(data) { return new Uint8Array(await crypto.subtle.digest("SHA-256", data)); }
async function signIn() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(await digest(encoder.encode(verifier)));
  sessionStorage.setItem("owner-pkce", JSON.stringify({ state, verifier }));
  const url = new URL(config.authorization_endpoint);
  for (const [key, value] of [
    ["response_type", "code"], ["client_id", config.client_id], ["redirect_uri", config.redirect_uri],
    ["scope", "openid approvals:manage"], ["resource", config.resource], ["state", state],
    ["code_challenge", challenge], ["code_challenge_method", "S256"]
  ]) url.searchParams.set(key, value);
  location.assign(url.toString());
}
async function finishSignIn() {
  const params = new URLSearchParams(location.search);
  if (!params.has("code") && !params.has("error")) return false;
  history.replaceState(null, "", location.pathname);
  const saved = sessionStorage.getItem("owner-pkce");
  sessionStorage.removeItem("owner-pkce");
  if (!saved || !params.get("code") || params.get("error")) throw new Error("Owner sign-in was not completed");
  const { state, verifier } = JSON.parse(saved);
  if (!state || params.get("state") !== state) throw new Error("OAuth state did not match");
  const body = new URLSearchParams({
    grant_type: "authorization_code", code: params.get("code"), client_id: config.client_id,
    redirect_uri: config.redirect_uri, code_verifier: verifier, resource: config.resource,
  });
  const response = await fetch(config.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    cache: "no-store",
  });
  if (!response.ok) throw new Error("Owner sign-in exchange was refused");
  const token = await response.json();
  if (typeof token.access_token !== "string" || token.token_type?.toLowerCase() !== "bearer") throw new Error("No valid owner OAuth bearer was received");
  accessToken = token.access_token;
  return true;
}
async function api(path, method = "GET", data) {
  if (!accessToken) throw new Error("Sign in as the owner to use this action");
  const response = await fetch(path, {
    method,
    headers: { "Authorization": `Bearer ${accessToken}`, ...(data ? { "Content-Type": "application/json" } : {}) },
    body: data ? JSON.stringify(data) : undefined,
    cache: "no-store",
    credentials: "omit",
  });
  if (!response.ok) throw new Error("Request denied, expired, or no longer available");
  return response.json();
}
function row(label, value, parent) {
  const dt = document.createElement("dt"); const dd = document.createElement("dd");
  dt.textContent = label; dd.textContent = String(value);
  parent.append(dt, dd);
}
function requestCard(request) {
  const card = document.createElement("article");
  const title = document.createElement("h3");
  title.textContent = "Confirm PC action";
  const details = document.createElement("dl");
  row("Device", request.device_id, details);
  row("Window / target", request.target, details);
  row("Action", request.operation, details);
  row("Coordinates", JSON.stringify(request.parameters), details);
  row("Session", request.session_id, details);
  row("Expires", new Date(request.expires_at * 1000).toLocaleTimeString(), details);
  card.append(title, details);
  if (request.approved) {
    const label = document.createElement("p");
    label.textContent = "Approved; awaiting the Windows PC."; card.append(label);
    return card;
  }
  const chooser = document.createElement("select");
  chooser.setAttribute("aria-label", "Passkey for this approval");
  for (const credentialId of credentialIds) {
    const option = document.createElement("option");
    option.value = credentialId; option.textContent = credentialId;
    chooser.append(option);
  }
  const approve = document.createElement("button"); approve.textContent = "Approve once with passkey";
  approve.disabled = !credentialIds.length;
  approve.addEventListener("click", () => run(() => confirmAction(request.job_id, chooser.value)));
  const deny = document.createElement("button"); deny.textContent = "Deny";
  deny.addEventListener("click", () => run(async () => {
    await api("/api/owner/approvals/deny", "POST", { job_id: request.job_id });
    await refresh();
  }));
  card.append(chooser, approve, deny);
  return card;
}
async function confirmAction(jobId, credentialId) {
  if (!navigator.credentials?.get) throw new Error("Passkeys are unavailable in this browser");
  const started = await api("/api/owner/approvals/begin", "POST", { job_id: jobId, credential_id: credentialId });
  const timeout = Math.max(1000, Math.min(60000, started.expires_at * 1000 - Date.now()));
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64url(started.challenge),
      rpId: started.rp_id,
      timeout,
      userVerification: "required",
      allowCredentials: [{ type: "public-key", id: fromBase64url(credentialId) }],
    },
  });
  if (!credential || !credential.response) throw new Error("No passkey assertion was provided");
  await api("/api/owner/approvals/finish", "POST", {
    job_id: jobId,
    credential_id: credentialId,
    challenge: started.challenge,
    client_data: base64url(new Uint8Array(credential.response.clientDataJSON)),
    authenticator_data: base64url(new Uint8Array(credential.response.authenticatorData)),
    signature: base64url(new Uint8Array(credential.response.signature)),
  });
  status("Owner approval recorded for one action. Your PC still applies its local safety checks.");
  await refresh();
}
async function refresh() {
  if (!accessToken) return;
  const [keys, requests] = await Promise.all([api("/api/owner/approvals/credentials"), api("/api/owner/approvals")]);
  credentialIds = keys.credential_ids;
  const list = $("requests"); list.replaceChildren();
  for (const request of requests.approvals) list.append(requestCard(request));
  if (!requests.approvals.length) {
    const empty = document.createElement("p");
    empty.textContent = "No pending PC requests."; list.append(empty);
  }
  if (!credentialIds.length) status("No owner passkey is registered. Trusted enrollment is required.");
}
async function run(task) { try { await task(); } catch (error) { status(error.message || "Request unavailable"); } }
async function main() {
  try {
    const response = await fetch("/owner/approve-config", { cache: "no-store" });
    if (!response.ok) throw new Error("Owner portal configuration unavailable");
    config = await response.json();
    $("sign-in").addEventListener("click", () => run(signIn));
    $("refresh").addEventListener("click", () => run(refresh));
    $("halt").addEventListener("click", () => run(async () => {
      await api("/api/owner/approvals/halt", "POST", {});
      status("Cloud approval queue stopped. This does NOT replace the PC's local emergency STOP.");
      await refresh();
    }));
    if (await finishSignIn()) {
      $("sign-in").disabled = true;
      $("refresh").disabled = false;
      $("halt").disabled = false;
      status("Signed in. Review the exact target before approving.");
      await refresh();
    }
  } catch (error) {
    status(error.message || "Owner portal unavailable");
  }
}
void main();