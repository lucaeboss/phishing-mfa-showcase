# Phishing & MFA — Senior Project

**Live showcase:** https://lucaeboss.github.io/phishing-mfa-showcase/

A study of the modern credential-phishing chain — from rogue access points to
real-time adversary-in-the-middle session theft — and the phishing-resistant
authentication (FIDO2 / passkeys) that defeats it.

## What's in this repository

- **`/` (root)** — the public **showcase site** (`index.html`), deployed with
  GitHub Pages. This is the presentation-facing part of the project.
- **`/lab`** — the interactive **training lab** (Python / Flask). It reproduces the
  full attack-and-defense chain against a *fictional* service on an isolated host.

## Why the lab is not deployed

The lab runs **locally only**. It is deliberately not hosted on the public site
for two reasons: GitHub Pages is static and cannot run the Flask backend the lab
needs, and the lab contains a credential-capture page that must never sit on a
public URL. The showcase presents the lab visually; the lab itself is driven live
during the demonstration. See [`lab/README.md`](lab/README.md) and
[`lab/docs/scope-and-ethics.md`](lab/docs/scope-and-ethics.md).

## Scope & ethics

Everything targets a fictional service built for the lab. The project never
clones, proxies, or contacts a real website or identity provider, and is for
education and defense only.

---
Author: **Luca Caramihai** · Advisor: **Dr. Stephanos Mavromoustakos** · Field: **Cybersecurity**
