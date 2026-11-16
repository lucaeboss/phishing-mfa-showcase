// Minimal, dependency-free WebAuthn client glue.
// Converts between the base64url JSON that the server (py_webauthn) speaks and
// the ArrayBuffers that navigator.credentials expects. Kept small on purpose so
// it can be read and explained in the project write-up, and so the lab runs
// fully offline (no CDN).

function b64urlToBuf(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const str = atob(b64 + pad);
  const buf = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, data: await r.json() };
}

async function registerPasskey(username, out) {
  try {
    const { ok, data: options } = await postJSON("/api/webauthn/register/options", { username });
    if (!ok) return out(false, options.error || "Could not start registration.");

    options.challenge = b64urlToBuf(options.challenge);
    options.user.id = b64urlToBuf(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }

    const cred = await navigator.credentials.create({ publicKey: options });
    const payload = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    };
    const res = await postJSON("/api/webauthn/register/verify", { username, credential: payload });
    out(res.data.verified === true, res.data.verified ? "Passkey registered." : (res.data.error || "Verification failed."));
  } catch (e) {
    out(false, "Ceremony aborted: " + e.message);
  }
}

async function loginPasskey(username, out) {
  try {
    const { ok, data: options } = await postJSON("/api/webauthn/login/options", { username });
    if (!ok) return out(false, options.error || "Could not start login.");

    options.challenge = b64urlToBuf(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }

    const assertion = await navigator.credentials.get({ publicKey: options });
    const payload = {
      id: assertion.id,
      rawId: bufToB64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
        authenticatorData: bufToB64url(assertion.response.authenticatorData),
        signature: bufToB64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
      },
      clientExtensionResults: assertion.getClientExtensionResults(),
    };
    const res = await postJSON("/api/webauthn/login/verify", { username, credential: payload });
    out(res.data.verified === true, res.data.verified ? "Signed in with passkey." : (res.data.error || "Verification failed."));
  } catch (e) {
    out(false, "Ceremony aborted: " + e.message);
  }
}
