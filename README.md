# Email Header Analyzer

A free, single-page email header analyzer. Live at [headers.hbenali.ovh](https://headers.hbenali.ovh).

Paste raw headers (or a whole `.eml`) and read the message's trail. Everything runs in your browser: the page makes **no network request** (CSP `connect-src 'none'`), so your headers never leave your machine. No backend, no build step, no dependencies.

## Features

- **Unfolding** of folded header lines (RFC 5322), tolerant of malformed input (invalid lines are reported, not fatal)
- **Received chain**, oldest first: from / by / with / TLS / timestamp per hop, delay between hops, RFC 5322 date and time-zone parsing, flags for negative delays (clock skew), very large delays and a Date header out of line with the first hop
- **Identity**: From, Sender, Reply-To, Return-Path, Message-ID, Date, Subject, To, with a domain comparison (From vs Return-Path vs Reply-To vs Message-ID), duplicate From headers and display-name impersonation
- **Authentication-Results** (SPF, DKIM, DMARC, ARC with domain and selector) and **Received-SPF**
- **DKIM-Signature**: d=, s=, a=, canonicalization, signed headers h=, whether From is signed and aligned, weak algorithms, l=, expiry
- **ARC** sets (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results) and chain validation result
- **Spam and bulk headers**: X-Spam-Status / Score / Flag, X-Mailer, List-Unsubscribe (and one-click), SCL and others
- **Plain-English summary** of whether the message looks authenticated, plus a list of red flags
- Two clearly labelled **SAMPLE** buttons with invented headers (example.org, example.net, documentation IP ranges)
- Links to the sibling SPF / DMARC / MX / BIMI / DKIM tools for the sender domain (plain links; nothing is sent unless you click)
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## What it cannot do

It reads the authentication results recorded in the headers; it cannot re-verify SPF, DKIM or DMARC because that needs DNS lookups, which the strict offline policy forbids. Treat results as trustworthy only when your own mail provider added them. Same-organisation domain matching is approximate (no Public Suffix List offline).

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
