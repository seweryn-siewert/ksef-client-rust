[Polska wersja](README.md) / English version

# ksef-client — a KSeF 2.0 client in Rust

A Rust library for integrating with the Polish **National e-Invoicing System (KSeF 2.0)**
run by the Ministry of Finance: authentication, sending FA(3) invoices, statuses, UPO,
QR codes and KSeF certificates.

This is a fork of [pengwius/ksef-client-rust](https://github.com/pengwius/ksef-client-rust)
with fixes needed for production use. The original has not been developed since March 2026.

**Version 1.0.0 — as of November 2026.**

## What it is for

The library handles communication with the KSeF 2.0 API. It does not generate the invoice
itself: the FA(3) document (XML conforming to the `FA (3)` schema) is prepared by the
application, and the library encrypts it, sends it and tracks its status.

A typical invoice flow:

1. authentication (KSeF token or KSeF certificate — XAdES signature),
2. opening an online session, encrypting and sending the FA(3) XML,
3. reading the status and the KSeF number,
4. downloading the UPO (official receipt),
5. a QR code for the invoice visualisation (KOD I, and in offline mode also KOD II).

## Features

| Area | Functions |
|---|---|
| Authentication | KSeF token; KSeF certificate — XAdES signature with an **RSA** or **ECDSA P-256** key; access token refresh |
| Online sessions | open, send an invoice, close; **offline mode** (`offlineMode`) for invoices issued in offline24 / emergency mode |
| Batch sessions | sending invoice packages (ZIP, parts, encryption) |
| Statuses and UPO | invoice and session status, KSeF number, UPO download |
| QR codes | KOD I (invoice verification), KOD II (issuer verification, signed with an Offline-type certificate: ECDSA P-256 `r‖s` or RSA-PSS) |
| KSeF certificates | limits, enrollment data, CSR, enrollment, status, retrieval, list, revocation |
| KSeF tokens | creation, list, revocation |
| Fetching invoices | invoice metadata and content from KSeF |
| Permissions | granting, revoking and searching permissions |
| Peppol | list of Peppol service providers |
| Environments | TEST, DEMO, PRODUCTION |

## Changes compared to the original

| Change | Description |
|---|---|
| Access token redeemed once | `get_access_token()` after a successful `get_auth_status()` no longer fails with error 21301 |
| XAdES with EC keys | ECDSA P-256 signature (`ecdsa-sha256`, `r‖s` value per RFC 4050) — certificates issued by the KSeF taxpayer application (Aplikacja Podatnika KSeF) have EC keys |
| Offline mode | sending invoices issued offline (`offlineMode: true`): `submit_offline_invoice`, `send_invoice_with_mode` |
| License | GPL-3.0-or-later (original: MIT) |

## Testing status (November 2026)

**KSeF production** — the library has been used by an invoicing application of a
sole proprietorship since 28 October 2026:
- login with a KSeF certificate with an ECDSA P-256 key (XAdES),
- sending FA(3) invoices in an online session (domestic buyer and buyer outside the EU),
  statuses, KSeF numbers, UPO.

**KSeF TEST environment:**
- login with a token and with RSA 2048 and ECDSA P-256 certificates,
- sending invoices and corrective invoices (KOR), UPO,
- offline mode: enrolling an Offline-type certificate via the API, KOD II, sending with
  `offlineMode`,
- the library's integration tests: 75 of 82 pass. The remaining 7 (certificate tests) fail
  because the certificate limit (400/400) of the shared test NIP used by the tests is
  exhausted — not because of a bug in the code.

**Not separately verified in practice:** batch sessions, permissions, Peppol, token
management and fetching invoices — covered only by the library's integration tests on the
TEST environment.

## Known limitations

- XML canonicalisation in the XAdES signature is simplified (based on regular expressions).
  It works for KSeF authentication requests but is not a full C14N implementation.
- The library does not build or validate FA(3) XML — that is the application's job.
- KSeF tokens work until 31 December 2026; from 2027 only KSeF certificates can be used to
  log in.

## Installation

The library is not published on crates.io (the original's version is there). Add a
dependency on this repository to your `Cargo.toml` — preferably pinned to a commit:

```toml
[dependencies]
ksef-client = { git = "https://github.com/seweryn-siewert/ksef-client-rust", branch = "main" }
# or: rev = "<commit>"
```

## Example: certificate login and sending an invoice

```rust
use ksef_client::{
    KsefClient,
    auth::SubjectIdentifierType,
    prelude::{ContextIdentifier, ContextIdentifierType, Environment},
    traits::{KsefAuth, KsefSessions},
};

let context = ContextIdentifier { id_type: ContextIdentifierType::Nip, value: nip };
let mut client = KsefClient::new(Environment::Test, context);

// KSeF certificate (PKCS#12: key + certificate, RSA or EC P-256).
client.xades.load_pkcs12(&std::fs::read("auth.p12")?, &password)?;
let request = client.get_auth_token_request(SubjectIdentifierType::CertificateSubject).await?;
let signed = client.xades.sign(&request.to_xml())?;
client.authenticate_by_xades_signature(signed).await?;
client.get_auth_status().await?; // waits for the result and redeems the access token

// FA(3) invoice prepared by the application.
let sent = client.submit_online(fa3_xml.as_bytes(), None, None, None).await?;
// Invoice issued offline: client.submit_offline_invoice(...)
```

## Documentation

Details in the `docs/` directory:

*   [Authentication](docs/authentication.en.md)
*   [KSeF Tokens](docs/ksef_tokens.en.md)
*   [Sessions](docs/sessions.en.md)
*   [Permissions](docs/permissions.en.md)
*   [KSeF Certificates](docs/ksef_certificates.en.md)
*   [Sending an Invoice in an Online Session](docs/online_session.en.md)
*   [Sending Invoices in a Batch Session](docs/batch_session.en.md)
*   [Fetching Invoices](docs/fetching_invoices.en.md)
*   [QR Codes](docs/qr.en.md)
*   [Peppol Service Providers](docs/peppol.en.md)
*   [Official Receipt (UPO)](docs/upo.en.md)

Sources of truth for the API: [CIRFMF/ksef-api](https://github.com/CIRFMF/ksef-api),
[CIRFMF/ksef-docs](https://github.com/CIRFMF/ksef-docs), schemas:
[CIRFMF/ksef-schematy](https://github.com/CIRFMF/ksef-schematy).

## Security

- The library **has not undergone an independent security audit**. It is distributed without
  any warranty (GPL-3.0, sections 15–16).
- Connections to KSeF: TLS via `rustls` (server certificate verification enabled), 30 s
  timeout. Tokens and private keys are kept in the `Secret` type (they do not end up in logs via
  `Debug`); the library does not print anything to the console.
- No `unsafe` blocks in the code.
- Dependencies checked against the OSV/RustSec database (16 November 2026): no known
  vulnerabilities in `Cargo.lock`. Applications using the library have their own `Cargo.lock` —
  check it regularly (e.g. `cargo audit`).
- Known limitation: simplified XML canonicalisation in the XAdES signature (the library signs only
  XML it builds itself).
- Reporting vulnerabilities: see [`SECURITY.md`](SECURITY.md).

## License

The project is distributed under the **GNU GPL version 3 or any later version**
(GPL-3.0-or-later) — full text in [`LICENSE`](LICENSE).

It contains code from [pengwius/ksef-client-rust](https://github.com/pengwius/ksef-client-rust)
(Copyright (c) 2026 pengwius) released under the MIT license; the original license notice is
in [`LICENSE-MIT`](LICENSE-MIT).
