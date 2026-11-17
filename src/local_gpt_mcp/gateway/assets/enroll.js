// Owner-only PKCE + native WebAuthn creation. No token or operator code persistence.
const element = (name) => document.getElementById(name);
const setStatus = (message) => { element("status").textContent = message; };
const encoder = new TextEncoder();
let configuration;
let accessToken = "";

function base64url(bytes) {
  let result = "";
  for (const byte of bytes) result += String.fromCharCode(byte);
  return btoa(result).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function signIn() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  sessionStorage.setItem("owner-enroll-pkce", JSON.stringify({ state, verifier, issued: Date.now() }));
  const url = new URL(configuration.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", configuration.client_id);
  url.searchParams.set("redirect_uri", configuration.redirect_uri);
  url.searchParams.set("scope", "openid owner:enroll");
  url.searchParams.set("resource", configuration.resource);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", base64url(new Uint8Array(hash)));
  url.searchParams.set("code_challenge_method", "S256");
  location.assign(url.toString());
}

async function finishSignIn() {
  const params = new URLSearchParams(location.search);
  if (!params.has("code") && !params.has("error")) return false;
  history.replaceState(null, "", location.pathname);
  const saved = sessionStorage.getItem("owner-enroll-pkce");
  sessionStorage.removeItem("owner-enroll-pkce");
  if (!saved || !params.get("code") || params.has("error")) throw new Error("Owner sign-in was denied");
  const { state, verifier, issued } = JSON.parse(saved);
  if (
    typeof state !== "string" || typeof verifier !== "string" ||
    params.get("state") !== state || !Number.isSafeInteger(issued) ||
    Date.now() - issued < 0 || Date.now() - issued > 300000
  ) throw new Error("Owner sign-in state expired or mismatched");

  const response = await fetch(configuration.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.get("code"),
      client_id: configuration.client_id,
      redirect_uri: configuration.redirect_uri,
      code_verifier: verifier,
      resource: configuration.resource,
    }),
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok) throw new Error("Owner sign-in exchange was denied");
  const token = await response.json();
  if (
    typeof token.access_token !== "string" || !token.access_token ||
    token.access_token.length > 8192 || token.token_type?.toLowerCase() !== "bearer"
  ) throw new Error("A verified owner OAuth bearer is required");
  accessToken = token.access_token;
  return true;
}

async function post(path, data) {
  if (!accessToken) throw new Error("Sign in independently before enrollment");
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok) throw new Error("Enrollment denied or expired; request a fresh operator code");
  return response.json();
}

async function enroll() {
  const input = element("operator-code");
  let code = input.value.trim();
  input.value = "";
  element("register").disabled = true;
  try {
    if (!/^[A-Za-z0-9_-]{43}$/.test(code)) throw new Error("Enter the operator-issued one-time code");
    if (
      typeof PublicKeyCredential === "undefined" ||
      typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function" ||
      typeof navigator.credentials?.create !== "function"
    ) throw new Error("A browser with native WebAuthn registration support is required");
    const begin = await post("/api/owner/passkey/begin", { operator_code: code });
    code = "";
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(begin.options);
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential || typeof credential.toJSON !== "function") {
      throw new Error("A verified browser passkey response is required");
    }
    const result = await post("/api/owner/passkey/finish", {
      ceremony_id: begin.ceremony_id,
      challenge: begin.options.challenge,
      credential: credential.toJSON(),
    });
    if (result.registered !== true) throw new Error("Owner passkey was not registered");
    accessToken = "";
    element("operator-code").disabled = true;
    setStatus("Passkey registered. A separate owner presence check is required for every remote action.");
  } finally {
    code = "";
    input.value = "";
    if (accessToken) element("register").disabled = false;
  }
}

async function run(task) {
  try {
    await task();
  } catch {
    setStatus("Request denied or unavailable. Sign in again or ask the operator for a new code.");
  }
}

async function main() {
  try {
    const response = await fetch("/owner/enroll-config", { credentials: "omit", cache: "no-store" });
    if (!response.ok) throw new Error("Owner browser registration not configured");
    configuration = await response.json();
    element("sign-in").addEventListener("click", () => run(signIn));
    element("register").addEventListener("click", () => run(enroll));
    if (await finishSignIn()) {
      element("sign-in").disabled = true;
      element("operator-code").disabled = false;
      element("register").disabled = false;
      setStatus("Signed in independently. Enter your operator-issued code to create a passkey.");
    }
  } catch {
    setStatus("Owner browser registration unavailable.");
  }
}
void main();
