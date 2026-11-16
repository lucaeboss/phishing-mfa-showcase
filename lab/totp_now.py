"""
totp_now.py  --  print the current TOTP code for a lab account.

Convenience for live demos when you don't want to pull out a phone. It reads the
local users.json created by the app. Lab-only helper.

Usage:
    python totp_now.py <username>
    python totp_now.py            (lists known accounts)
"""

import os
import sys
import json
import pyotp

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.json")


def main():
    if not os.path.exists(USERS_FILE):
        print("No users.json yet -- start app.py and enroll an account first.")
        return
    with open(USERS_FILE, encoding="utf-8") as f:
        users = json.load(f)

    if len(sys.argv) != 2:
        print("Known accounts:")
        for u in users:
            print("  " + u)
        print("\nUsage: python totp_now.py <username>")
        return

    username = sys.argv[1].strip().lower()
    user = users.get(username)
    if not user:
        print(f"No such account: {username}")
        return
    code = pyotp.TOTP(user["totp_secret"]).now()
    print(f"Current TOTP code for {username}:  {code}")
    print("(valid for ~30s)")


if __name__ == "__main__":
    main()
