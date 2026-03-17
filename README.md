# SiteGuard

SiteGuard is a passive public web security posture scanner. Enter a URL and it inspects publicly observable transport and browser security signals such as HTTPS, redirects, TLS certificate status, HSTS, CSP, cookie flags, CORS, stack exposure, mixed content, and insecure login form hints.

## Why this exists

Fast AI-assisted shipping often leaves out boring but essential security basics. SiteGuard focuses on the first layer that operators actually forget:

- HTTPS and redirect posture
- TLS certificate validity
- Secure headers
- Cookie hardening
- Obvious browser-facing misconfigurations
- Evidence and remediation instead of raw warnings

## Safety model

This app is intentionally limited to passive scanning of public URLs.

- It does not brute force or fuzz.
- It does not attempt SQLi, XSS, auth bypass, or IDOR exploitation.
- It blocks localhost, private IP space, and internal-style hostnames to reduce SSRF risk.

## Local run

```bash
npm install
npm run build
npm run dev
```

Or:

```bash
npm start
```

Then open [http://localhost:3000](http://localhost:3000).

## Test

```bash
npm test
```

## Frontend styling

The UI is built with Tailwind CSS and compiled to `public/tailwind.css`.

```bash
npm run build
```

## Deploy

This project uses a single Node server and plain static assets, so it deploys cleanly to platforms like Render, Railway, or Fly.

- Build command: none
- Start command: `npm start`
- Runtime: Node 20+

Included deployment assets:

- `Dockerfile`
- `render.yaml`

Useful environment variables:

- `PORT`
- `MAX_CONCURRENT_SCANS`
- `RATE_LIMIT_MAX`
- `RATE_LIMIT_WINDOW_MS`
- `SCAN_CACHE_TTL_MS`
- `SCAN_CACHE_MAX_ENTRIES`

## Scope note

This tool is best used as a first-line public configuration scanner. It should be followed by authenticated testing, manual review, and secure SDLC practices for deeper application security guarantees.
