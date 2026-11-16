# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 (pengwius/ksef-client-rust) | no — use the original repository |

## Reporting a vulnerability

Please do not open a public issue. Report it privately via GitHub:
**Security → Report a vulnerability** in this repository
(https://github.com/seweryn-siewert/ksef-client-rust/security/advisories/new).

Include the affected version or commit, a description, and steps to reproduce if possible.
You can expect an answer within 14 days. This is a personal open-source project maintained
in spare time — there is no bug bounty and no guaranteed fix time.

## Scope

In scope: this library's code (authentication, XAdES signing, encryption, QR codes, KSeF API
calls). Out of scope: the KSeF system itself (report to the Ministry of Finance), and
vulnerabilities in dependencies that are already fixed in a newer version listed in `Cargo.lock`.
