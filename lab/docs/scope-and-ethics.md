# Scope & Rules of Engagement

Put a version of this page at the front of your report. A clearly-documented scope is
treated as a strength on an academic ethics review, not a limitation.

## Authorization
- All testing is performed against systems and accounts **I own or am explicitly
  authorized to test**.
- Human participants (if any) take part **with informed consent**, know they are part
  of a security demonstration, and use **throwaway credentials**, never real ones.

## What this lab targets
- A **single local application** ("ExampleCorp") that I wrote and run on my own machine.
- It is a **fictional** service. It does not use any real brand's name, logo, or domain.

## What this lab deliberately does NOT do
- It does **not** clone, proxy, or relay any real website or identity provider.
- It does **not** implement a reusable adversary-in-the-middle (AiTM) proxy that could
  capture live sessions from real services. Stage 3 demonstrates the *consequence* of
  session theft by replaying a token **against this lab app only**.
- It does **not** capture, store, or transmit any real person's credentials.

## Containment
- The radio side of the project (rogue AP / captive portal on the T-Embed) is run at
  low power in a controlled space, broadcasting an SSID that cannot be mistaken for a
  real venue, and is never pointed at unsuspecting third parties.
- Captured **test** data lives only in `data/captured.log` and is wiped at the end of
  the project.

## Legal note (not legal advice)
Operating a rogue access point against other people's devices, intercepting their
traffic, or cloning a real login to collect real credentials can violate computer-misuse,
wiretap, and fraud statutes **even if you intend no harm**. The entire point of the lab
design above is to demonstrate the techniques without ever doing any of that.

## Data handling checklist
- [ ] Only synthetic / throwaway credentials used
- [ ] `data/users.json` and `data/captured.log` deleted after the final demo
- [ ] No real brand assets used in the portal
- [ ] Radio testing confined to owned devices in a controlled space
