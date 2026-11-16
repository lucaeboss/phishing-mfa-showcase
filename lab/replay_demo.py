"""
replay_demo.py  --  Stage 3: the session-token hijack, demonstrated safely.

This is a standalone "attacker" client. It NEVER logs in and never sees a
password or a TOTP code. It simply presents a session token (the value of the
victim's `demo_session` cookie) and asks the app for protected data.

The lesson: once the token exists, the second factor is irrelevant. Whoever
holds the token is the user. That is exactly how adversary-in-the-middle
phishing defeats TOTP/SMS/push 2FA in the real world -- the attacker's goal is
the post-authentication session, not the password.

This runs ONLY against the local ExampleCorp lab app. It talks to nothing else.

Usage:
    python replay_demo.py <demo_session cookie value>

Get the value from the browser after a full login:
    DevTools -> Application -> Cookies -> http://localhost:5000 -> demo_session
"""

import sys
import json
import urllib.request
import urllib.error

BASE = "http://localhost:5000"


def call(path, cookie=None):
    req = urllib.request.Request(BASE + path)
    if cookie:
        req.add_header("Cookie", f"demo_session={cookie}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError as e:
        print(f"\n  Could not reach {BASE} -- is app.py running?  ({e.reason})")
        sys.exit(1)


def banner(t):
    print("\n" + "-" * 64 + f"\n  {t}\n" + "-" * 64)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    token = sys.argv[1].strip()

    banner("1) Baseline: request protected data with NO token")
    status, body = call("/api/me")
    print(f"  GET /api/me   ->  HTTP {status}")
    print(f"  {body.strip()}")
    print("  As expected: locked out.")

    banner("2) Replay the stolen session token (no password, no TOTP)")
    status, body = call("/api/me", cookie=token)
    print(f"  GET /api/me   ->  HTTP {status}   (Cookie: demo_session=<stolen>)")
    if status == 200:
        data = json.loads(body)
        print("  ACCESS GRANTED on the strength of the token alone:")
        for k, v in data.items():
            print(f"     {k:16}: {v}")
        print("\n  The second factor was never re-checked. The session WAS the prize.")
    else:
        print(f"  {body.strip()}")
        print("  Token rejected -- did you copy a current, fully-authenticated value?")

    banner("Takeaway")
    print("  TOTP protects the LOGIN EVENT, not the SESSION that follows it.")
    print("  Defenses that actually help: phishing-resistant auth (FIDO2/passkeys),")
    print("  token binding / DPoP, short session lifetimes, and re-auth on")
    print("  sensitive actions. See docs/mfa-comparison.md.\n")


if __name__ == "__main__":
    main()
