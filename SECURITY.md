# Security Policy

Tallystick is a **research prototype**. It has not been independently audited, and it is intended for **synthetic data only** — never real constituent data. Please keep that in mind when deciding how urgent a finding is: there are no production deployments to protect.

## Supported versions

There are no releases yet. Only the current `main` branch is maintained; there is nothing older to backport to.

## Reporting a vulnerability

Please use the **"Report a vulnerability"** button on this repository's **Security** tab (GitHub's private vulnerability reporting). Your report is visible only to you and the maintainers.

A good report includes:

- what you expected the system to guarantee, and what it actually does;
- the steps or code path that demonstrate it;
- which component it lives in (`client/`, `server/`, `shared/`, or the protocol design itself).

If the private-reporting form is unavailable for any reason, open a GitHub issue instead — the prototype handles synthetic data only, so public disclosure does not put anyone at risk.

## What counts

The project's security claims are defined by its threat model, which states precisely what the server can and cannot see and which adversaries are in scope. A finding is most valuable when it shows a gap between a stated claim and the implementation — or a claim that should not be made at all. Findings against limitations the threat model already records as accepted are still welcome as design input, but are not treated as vulnerabilities.

Thank you for looking!
