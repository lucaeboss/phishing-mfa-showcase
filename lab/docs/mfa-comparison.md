# MFA Methods vs. the Phishing Chain

A good closing slide. The columns are the attack stages from
[`attack-chain.md`](attack-chain.md); the rows are authentication methods.

| Method | Stops password-only phishing (Stage 1–2) | Stops real-time AiTM / session theft (Stage 3) | Shared secret on server? | Notes |
|---|:--:|:--:|:--:|---|
| Password only | ❌ | ❌ | yes (hash) | Baseline; one phished secret = full access |
| SMS OTP | ✅ | ❌ | no (per-code) | Also exposed to SIM-swap and SS7 interception |
| TOTP (authenticator app) | ✅ | ❌ | yes (seed) | Relayed in real time by an AiTM proxy |
| Push approval | ✅ | ❌ | no | Defeated by relay + "MFA fatigue" prompt-bombing |
| Push + number matching | ✅ | ⚠️ partial | no | Raises effort; still relayable in principle |
| **FIDO2 / passkey** | ✅ | ✅ | **no (public key)** | **Origin-bound; the assertion can't be relayed** |

Legend: ✅ stops it · ⚠️ raises the bar · ❌ does not stop it

## Why the last row is different

Every method above FIDO2 produces a secret the user can be tricked into handing over —
directly (Stage 1) or by completing it on a proxy (Stage 3). FIDO2 produces a signature
that is cryptographically tied to the origin the browser is talking to. A phishing page
lives on a different origin, so any signature the victim makes there is worthless to the
attacker against the real site. There is nothing bearer-shaped to steal and replay at the
authentication step.

## Layering the session-side defenses

FIDO2 fixes the *authentication* step. The *session* that follows is still a bearer token
unless you also harden it. Defense-in-depth for the session:

- **Short session lifetimes** + silent re-authentication (cheap with passkeys).
- **Token binding / DPoP** — tie the token to a key the client proves it holds, so a
  copied token is useless elsewhere.
- **Re-authentication (step-up)** for sensitive actions (transfers, changing recovery
  info), so a stolen session can't quietly do the worst things.
- **Conditional access / anomaly detection** — device posture, impossible-travel,
  new-device checks.

## The recommendation to end on

> Deploy **phishing-resistant MFA (FIDO2/passkeys)** for the authentication step, and
> **bind and time-limit sessions** for the step after it. Together they close both the
> door the attacker knocks on and the window they climbed through instead.
