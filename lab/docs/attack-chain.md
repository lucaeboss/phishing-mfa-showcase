# The Credential-Phishing Chain, and Where Each Defense Fits

This is the conceptual backbone of the project. The lab makes each stage concrete.

## Stage 1 — Credential capture

The attacker presents a login page that looks like the target's. The victim types a
username and password, which the attacker records. On your T-Embed this was a rogue
access point + captive portal; in email-based phishing it is a lookalike link. The
mechanism is identical: **the human trusts the page, not the origin.**

- **What it reveals:** users authenticate to *what looks right*, not to a verified
  identity. Transport encryption (HTTPS) protects data in transit but does nothing if
  the user is willingly typing into the attacker's own server.
- **Defenses that help a little:** user training, URL inspection, a password manager
  that refuses to autofill on the wrong origin (a machine check the human lacks).
- **Why it's not enough:** people make mistakes, and the next stage removes the need to
  fool anyone at all.

## Stage 2 — The second factor raises the bar

With TOTP/SMS/push 2FA, a stolen password is insufficient: the attacker is prompted for
a code they don't have. This genuinely stops **basic, credential-only** phishing, which
is why MFA was such an important control. In the lab, this is the TOTP wall at `/login`.

- **What it reveals:** 2FA shifts the attacker's target. If they can't get *past* the
  login prompt, they'll try to steal what exists *after* it.

## Stage 3 — Adversary-in-the-middle and session theft

Modern phishing kits don't just collect a password — they sit **between** the victim and
the real site (a reverse proxy). The victim completes the *entire* real login, including
the 2FA step, on the attacker's proxy. The attacker relays everything and, crucially,
captures the **session token** the real site issues on success.

That token is a **bearer credential**: whoever presents it is treated as the user, with
no second factor re-checked. SMS, TOTP, and push approvals are all defeated, because the
attacker let the *victim* satisfy them in real time.

- **In the lab (safely):** `replay_demo.py` presents a copied `demo_session` cookie to
  `/api/me` and gets the protected data back — no password, no code. This reproduces the
  *consequence* of AiTM against the lab app only, without building a real-provider proxy.
- **What it reveals:** `HttpOnly` stops JavaScript from reading the cookie but does not
  stop a network/proxy position from capturing it. 2FA protects the **login event**, not
  the **session** that follows.
- **Partial defenses:** short session lifetimes, re-authentication for sensitive actions,
  binding the token to the device (**token binding / DPoP**), and anomaly/conditional
  access (impossible-travel, device posture). These reduce the value and lifetime of a
  stolen token but don't make phishing impossible.

## Stage 4 — Phishing-resistant authentication (FIDO2 / passkeys)

WebAuthn replaces the shared secret with a public/private key pair. The private key never
leaves the authenticator (Windows Hello, a security key, a phone). At sign-in the browser
signs a server challenge, and the signed data **includes the origin the browser is
actually talking to**, checked by the authenticator against the credential's bound origin.

Consequences for each earlier stage:
- **Stage 1 is neutralized:** there is no password or code to type into a fake page.
- **Stage 3's relay fails:** the assertion the victim produces is bound to the proxy's
  origin, not the real site's, so the real site rejects it. An AiTM proxy cannot forward
  a usable login.
- **Server breach is less catastrophic:** the server stores only public keys.

- **In the lab:** register and use a passkey at `/secure`. The same evil portal now has
  nothing to harvest.

## One-sentence summary

> Each factor you add protects the step it guards; passkeys are different because they
> bind authentication to the real origin, which is the one thing a phishing page can
> never fake.

## Further reading (for your bibliography)

- W3C **Web Authentication (WebAuthn)** specification
- FIDO Alliance material on FIDO2 / passkeys and phishing resistance
- CISA / NCSC guidance on **phishing-resistant MFA**
- Public write-ups of **AiTM phishing** campaigns and session-cookie theft
- RFC 6238 (TOTP); documentation on **token binding** and **DPoP**
