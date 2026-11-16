# MFA Phishing-Resistance Lab

A self-contained teaching lab for a senior security project. It walks an audience
through the **modern credential-phishing chain** and then demonstrates the defense
that actually breaks it — **passkeys / FIDO2**.

Everything runs locally against a **fictional service called "ExampleCorp."** The lab
**never** clones, proxies, or contacts any real website or identity provider. That is
a deliberate design choice and a selling point on an ethics review — see
[`docs/scope-and-ethics.md`](docs/scope-and-ethics.md).

---

## The story it tells (5 stages)

| Stage | What the audience sees | The lesson |
|------|------------------------|-----------|
| 0 | Enroll an account with password **+ TOTP** | A normal, reasonably-secured login |
| 1 | The **evil portal** harvests username + password in plaintext | Credential phishing — what you already built on the T-Embed |
| 2 | Those creds hit the **TOTP wall** at the real login | A phished password **alone** is not enough — TOTP works here |
| 3 | A stolen **session cookie** is replayed → full access, no 2FA | The real prize is the *session*, not the password (the AiTM insight) |
| 4 | A **passkey** login the portal can't phish and a relay can't forward | Origin-bound crypto defeats the entire chain |

This arc is the thesis of the project: *second factors protect the login event; they
do not protect the session that follows — and only phishing-resistant,
origin-bound authentication closes that gap.*

---

## Requirements

- Windows (tested on Windows 11), Python 3.11+ — the project was built with 3.14.
- A browser with WebAuthn support (Edge or Chrome) and, ideally, **Windows Hello**
  set up, or a FIDO2 security key, or a phone passkey. Needed only for Stage 4.
- No internet needed at run time (dependencies are installed once, up front).

## Setup

From the project folder:

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install Flask pyotp qrcode webauthn
```

## Run

```powershell
.\venv\Scripts\python.exe app.py
```

Then open **http://localhost:5000** in your browser.

> Use `localhost`, **not** `127.0.0.1` — the passkey origin is pinned to
> `http://localhost:5000` and the ceremony will refuse a mismatched origin
> (which is itself the Stage-4 lesson).

A demo account is seeded on first run and its TOTP secret is printed to the console:

```
username: victim@examplecorp.test
password: Password123!
```

To get a live TOTP code without a phone:

```powershell
.\venv\Scripts\python.exe totp_now.py victim@examplecorp.test
```

---

## Running the live demo (suggested script for your presentation)

**Stage 1 — capture.** Open `/portal`. Type the seeded creds. They appear in plaintext
on screen and in `data/captured.log`. *"This is the attack I built on the T-Embed —
a fake AP plus this page."*

**Stage 2 — the wall.** Go to `/login`, enter the same creds. You're stopped at the
TOTP step. *"Good news: the stolen password alone failed. So how do real attackers get
past this?"*

**Stage 3 — session hijack.** Log in fully (password + TOTP) to reach `/dashboard`.
Open DevTools → Application → Cookies → copy `demo_session`. In a terminal:

```powershell
.\venv\Scripts\python.exe replay_demo.py <paste-the-cookie-value>
```

The script is a separate "attacker" client that never logs in — it just presents the
token and walks into `/api/me`. *"The second factor was never re-checked. Whoever holds
the session is the user. That's what adversary-in-the-middle phishing steals."*

**Stage 4 — the fix.** Open `/secure`, register a passkey for the account, then sign in
with it. *"There's no password to type into the evil portal, and the signature is bound
to this origin — a relay on a different origin can't forward it. The chain is broken at
the root."*

Close with the comparison table in [`docs/mfa-comparison.md`](docs/mfa-comparison.md).

---

## What's in here

```
app.py                     The ExampleCorp lab app (all routes)
replay_demo.py             Stage 3: standalone session-replay "attacker" client
totp_now.py                Convenience: print a current TOTP code
templates/                 All pages (login, totp, dashboard, portal, passkey, ...)
static/style.css           Styling
static/webauthn.js         Minimal, readable WebAuthn client glue (no CDN)
data/                      users.json, captured.log  (created at run time)
docs/scope-and-ethics.md   Rules of engagement — read this first
docs/attack-chain.md       The conceptual write-up (for your report)
docs/mfa-comparison.md     MFA methods vs. the attack (your closing slide)
```

## Boundaries (important)

This lab deliberately stops short of a real adversary-in-the-middle proxy. Stage 3
demonstrates the *consequence* of session theft (replay against this app) without
shipping a reusable tool that captures live sessions from real providers. That keeps
the project within legal and ethical scope while still proving the point end to end.
Use it only on systems you own or are explicitly authorized to test.
