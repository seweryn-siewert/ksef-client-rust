Polska wersja / [English version](README.en.md)

# ksef-client — klient KSeF 2.0 w Rust

Biblioteka w Rust do integracji z **Krajowym Systemem e-Faktur (KSeF 2.0)** Ministerstwa
Finansów: logowanie, wysyłka faktur FA(3), statusy, UPO, kody QR i certyfikaty KSeF.

To fork [pengwius/ksef-client-rust](https://github.com/pengwius/ksef-client-rust) z
poprawkami potrzebnymi w produkcyjnym użyciu. Oryginał nie jest rozwijany od marca 2026.

**Wersja 1.0.0 — stan na listopad 2026.**

## Do czego służy

Biblioteka obsługuje komunikację z API KSeF 2.0. Nie generuje treści faktury: dokument
FA(3) (XML zgodny ze schematem `FA (3)`) przygotowuje aplikacja, a biblioteka go szyfruje,
wysyła i śledzi jego status.

Typowy przebieg wystawienia faktury:

1. uwierzytelnienie (token KSeF albo certyfikat KSeF — podpis XAdES),
2. otwarcie sesji interaktywnej, zaszyfrowanie i wysłanie XML FA(3),
3. odczyt statusu i numeru KSeF,
4. pobranie UPO,
5. kod QR do wizualizacji faktury (KOD I, a w trybie offline także KOD II).

## Co obsługuje

| Obszar | Funkcje |
|---|---|
| Uwierzytelnianie | token KSeF; certyfikat KSeF — podpis XAdES kluczem **RSA** lub **ECDSA P-256**; odświeżanie tokenu dostępu |
| Sesje interaktywne | otwarcie, wysyłka faktury, zamknięcie; **tryb offline** (`offlineMode`) dla faktur wystawionych w trybie offline24 / awaryjnym |
| Sesje wsadowe | wysyłka paczek faktur (ZIP, części, szyfrowanie) |
| Statusy i UPO | status faktury i sesji, numer KSeF, pobieranie UPO |
| Kody QR | KOD I (weryfikacja faktury), KOD II (weryfikacja wystawcy, podpis certyfikatem typu Offline: ECDSA P-256 `r‖s` lub RSA-PSS) |
| Certyfikaty KSeF | limity, dane do wniosku, CSR, wniosek, status, pobranie, lista, unieważnienie |
| Tokeny KSeF | tworzenie, lista, unieważnianie |
| Pobieranie faktur | metadane i treść faktur z KSeF |
| Uprawnienia | nadawanie, odbieranie i wyszukiwanie uprawnień |
| Peppol | lista dostawców usług Peppol |
| Środowiska | TEST, DEMO, PRODUKCJA |

## Zmiany względem oryginału

| Zmiana | Opis |
|---|---|
| Token dostępu odbierany raz | `get_access_token()` po udanym `get_auth_status()` nie kończy się już błędem 21301 |
| XAdES z kluczami EC | podpis ECDSA P-256 (`ecdsa-sha256`, wartość `r‖s` wg RFC 4050) — certyfikaty wydawane przez Aplikację Podatnika KSeF mają klucze EC |
| Tryb offline | wysyłka faktur wystawionych offline (`offlineMode: true`): `submit_offline_invoice`, `send_invoice_with_mode` |
| Licencja | GPL-3.0-or-later (oryginał: MIT) |

## Stan przetestowania (listopad 2026)

**Produkcja KSeF** — biblioteka działa w aplikacji do fakturowania jednoosobowej
działalności od 28.10.2026:
- logowanie certyfikatem KSeF z kluczem ECDSA P-256 (XAdES),
- wysyłka faktur FA(3) w sesji interaktywnej (nabywca krajowy i spoza UE), statusy, numery
  KSeF, UPO.

**Środowisko TEST KSeF:**
- logowanie tokenem oraz certyfikatem RSA 2048 i ECDSA P-256,
- wysyłka faktur i faktur korygujących (KOR), UPO,
- tryb offline: wniosek o certyfikat typu Offline przez API, KOD II, wysyłka z `offlineMode`,
- testy integracyjne biblioteki: 75 z 82 przechodzi. Pozostałe 7 (testy certyfikatów) nie
  przechodzi z powodu wyczerpanego limitu certyfikatów (400/400) na wspólnym NIP-ie
  testowym używanym w testach — nie z powodu błędu w kodzie.

**Nie weryfikowane osobno w praktyce:** sesje wsadowe, uprawnienia, Peppol, zarządzanie
tokenami i pobieranie faktur — pokrywają je jedynie testy integracyjne biblioteki na
środowisku TEST.

## Znane ograniczenia

- Kanonikalizacja XML w podpisie XAdES jest uproszczona (oparta na wyrażeniach
  regularnych). Działa dla żądań uwierzytelnienia KSeF, ale nie jest pełną implementacją C14N.
- Biblioteka nie buduje ani nie waliduje XML FA(3) — to zadanie aplikacji.
- Tokeny KSeF działają do 31.12.2026; od 2027 r. logowanie wyłącznie certyfikatem KSeF.

## Instalacja

Biblioteka nie jest opublikowana na crates.io (tam jest wersja oryginału). Dodaj do
`Cargo.toml` zależność z tego repozytorium — najlepiej przypiętą do konkretnego commita:

```toml
[dependencies]
ksef-client = { git = "https://github.com/seweryn-siewert/ksef-client-rust", branch = "main" }
# albo: rev = "<commit>"
```

## Przykład: logowanie certyfikatem i wysyłka faktury

```rust
use ksef_client::{
    KsefClient,
    auth::SubjectIdentifierType,
    prelude::{ContextIdentifier, ContextIdentifierType, Environment},
    traits::{KsefAuth, KsefSessions},
};

let context = ContextIdentifier { id_type: ContextIdentifierType::Nip, value: nip };
let mut client = KsefClient::new(Environment::Test, context);

// Certyfikat KSeF (PKCS#12: klucz + certyfikat, RSA lub EC P-256).
client.xades.load_pkcs12(&std::fs::read("auth.p12")?, &password)?;
let request = client.get_auth_token_request(SubjectIdentifierType::CertificateSubject).await?;
let signed = client.xades.sign(&request.to_xml())?;
client.authenticate_by_xades_signature(signed).await?;
client.get_auth_status().await?; // czeka na wynik i odbiera token dostępu

// Faktura FA(3) przygotowana przez aplikację.
let sent = client.submit_online(fa3_xml.as_bytes(), None, None, None).await?;
// Faktura wystawiona offline: client.submit_offline_invoice(...)
```

## Dokumentacja

Szczegóły w katalogu `docs/`:

*   [Proces Uwierzytelniania](docs/authentication.md)
*   [Zarządzanie Tokenami KSeF](docs/ksef_tokens.md)
*   [Zarządzanie Sesjami](docs/sessions.md)
*   [Zarządzanie Uprawnieniami](docs/permissions.md)
*   [Certyfikaty KSeF](docs/ksef_certificates.md)
*   [Wysyłanie Faktury w Sesji Interaktywnej](docs/online_session.md)
*   [Wysyłanie Faktury w Sesji Wsadowej](docs/batch_session.md)
*   [Pobieranie Faktur](docs/fetching_invoices.md)
*   [Kody QR](docs/qr.md)
*   [Pobieranie Dostawców Usług Peppol](docs/peppol.md)
*   [Urzędowe Poświadczenie Odbioru (UPO) Faktur](docs/upo.md)

Źródła prawdy o API: [CIRFMF/ksef-api](https://github.com/CIRFMF/ksef-api),
[CIRFMF/ksef-docs](https://github.com/CIRFMF/ksef-docs), schematy:
[CIRFMF/ksef-schematy](https://github.com/CIRFMF/ksef-schematy).

## Licencja

Projekt jest rozpowszechniany na licencji **GNU GPL w wersji 3 lub dowolnej późniejszej**
(GPL-3.0-or-later) — pełny tekst w pliku [`LICENSE`](LICENSE).

Zawiera kod z [pengwius/ksef-client-rust](https://github.com/pengwius/ksef-client-rust)
(Copyright (c) 2026 pengwius) udostępniony na licencji MIT; oryginalna nota licencyjna
znajduje się w pliku [`LICENSE-MIT`](LICENSE-MIT).
