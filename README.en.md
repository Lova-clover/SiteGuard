# SiteGuard

SiteGuard is a passive public web security posture scanner.

It checks what is visible from a public URL, summarizes the findings with evidence and remediation guidance, and presents the results in a report-oriented UI. The project is intentionally focused on fast, external, unauthenticated checks rather than full penetration testing.

## What SiteGuard is for

SiteGuard is useful when you want to quickly answer questions like:

- Is HTTPS available and enforced?
- Is the TLS certificate valid?
- Are common security headers missing or weak?
- Are cookies missing important hardening flags?
- Is mixed content visible from the public page?
- Is there a public `security.txt` contact path?

This makes SiteGuard a good fit for:

- pre-release security checks
- quick external reviews of public sites
- baseline hardening reviews
- teaching or demo environments for passive web security checks

## What SiteGuard does not do

SiteGuard is intentionally limited.

It does **not**:

- log in to applications
- fuzz parameters or exploit endpoints
- verify SQL injection, XSS, IDOR, SSRF, or auth bypasses
- test business logic vulnerabilities
- scan private networks, localhost, or internal-only hosts

In other words, SiteGuard is a **first-pass external scanner**, not a substitute for authenticated testing, code review, or a full security assessment.

## Features

- Passive scanning of a public `http://` or `https://` URL
- Evidence-first reports with issue summaries, findings, and raw proof
- Risk classification that separates:
  - direct security risks
  - hardening gaps
  - operational maturity signals
- Safer runtime behavior for outbound scanning:
  - localhost/private target blocking
  - DNS rebinding hardening
  - pinned resolution and socket address validation
  - absolute timeouts and body size caps
  - rate limiting, concurrency guard, and TTL cache
- Web dashboard for scans and local history
- Private admin analytics dashboard at `/admin`
- Optional Redis-backed metrics storage for durable visit and scan analytics
- Vercel, Render, Docker, and plain Node.js deployment support

## What it checks today

SiteGuard currently focuses on public, passive signals such as:

- HTTPS support
- HTTP -> HTTPS redirect behavior
- TLS certificate validity and expiry
- `Strict-Transport-Security`
- `Content-Security-Policy`
- clickjacking protection (`X-Frame-Options`, `frame-ancestors`)
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- cookie hardening (`Secure`, `HttpOnly`, `SameSite`)
- broad CORS behavior visible from the response
- stack exposure headers
- mixed content signals from public HTML
- login form transport safety hints
- `security.txt`

## Quick start

### Requirements

- Node.js 20+
- npm

### Install and run

```bash
npm install
npm run build
npm run dev
```

Then open:

```text
http://localhost:3000
```

For production-style local execution:

```bash
npm start
```

## Available scripts

| Script | Description |
| --- | --- |
| `npm run dev` | Start the local server with file watching |
| `npm run build` | Build the Tailwind CSS bundle into `public/tailwind.css` |
| `npm run build:css` | Build CSS once |
| `npm run dev:css` | Watch and rebuild CSS during UI work |
| `npm test` | Run the Node.js test suite |
| `npm start` | Start the production server |

## API endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health and runtime status |
| `GET` | `/api/ready` | Same readiness payload as health |
| `POST` | `/api/scan` | Run a passive scan |
| `POST` | `/api/metrics/visit` | Record a page visit for analytics |
| `POST` | `/api/admin/login` | Log in to the admin dashboard |
| `POST` | `/api/admin/logout` | Clear the admin session |
| `GET` | `/api/admin/session` | Check admin auth state |
| `GET` | `/api/admin/metrics` | Read private admin analytics |

Example scan request:

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Environment variables

### Core scanner and server

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | HTTP server port | `3000` |
| `SCAN_CACHE_TTL_MS` | Scan result cache TTL | `300000` |
| `SCAN_CACHE_MAX_ENTRIES` | Maximum cache entries | `300` |
| `RATE_LIMIT_WINDOW_MS` | Fixed-window rate limit duration | `60000` |
| `RATE_LIMIT_MAX` | Maximum scan requests per IP per window | `10` |
| `MAX_CONCURRENT_SCANS` | Maximum concurrent scans | `4` |

### Admin dashboard

| Variable | Description | Default |
| --- | --- | --- |
| `ADMIN_USERNAME` | Admin login username | none |
| `ADMIN_PASSWORD_HASH` | Preferred hashed admin password | none |
| `ADMIN_PASSWORD` | Plain password fallback (use only if needed) | none |
| `ADMIN_SESSION_SECRET` | Secret used to sign admin session cookies | none |
| `ADMIN_SESSION_TTL_SEC` | Admin session lifetime in seconds | `1209600` |

`ADMIN_PASSWORD_HASH` is preferred over `ADMIN_PASSWORD`.

Generate a password hash with the built-in helper:

```bash
node --input-type=module -e "import { createPasswordHash } from './src/admin-auth.js'; console.log(createPasswordHash('YOUR_PASSWORD'))"
```

Generate a random session secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Metrics and analytics

| Variable | Description | Default |
| --- | --- | --- |
| `SITEGUARD_METRICS_TIMEZONE` | Time zone used for daily analytics grouping | `Asia/Seoul` |
| `SITEGUARD_METRICS_TTL_SEC` | TTL for daily Redis metric keys | `10368000` |
| `SITEGUARD_RECENT_SCAN_LIMIT` | Number of recent scans kept in analytics | `20` |
| `SITEGUARD_TOP_DOMAIN_LIMIT` | Number of top scanned domains returned | `5` |
| `UPSTASH_REDIS_REST_URL` | Upstash Redis REST URL | none |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash Redis REST token | none |
| `KV_REST_API_URL` | Vercel KV-compatible Redis URL fallback | none |
| `KV_REST_API_TOKEN` | Vercel KV-compatible Redis token fallback | none |

If Redis variables are not configured, SiteGuard falls back to in-memory analytics. That works locally, but it is not a durable or globally accurate option in serverless environments.

## Admin analytics

SiteGuard ships with a private admin dashboard at `/admin`.

The admin dashboard shows:

- total unique visitors
- page views
- scan request counts
- success / failure / cache ratios
- 7-day activity series
- most scanned domains
- recent scan activity

To use it safely in production:

1. configure admin auth variables
2. configure Redis-backed metrics storage
3. redeploy the app

For Vercel projects, connecting Upstash Redis from the Vercel Storage / Marketplace UI is the easiest setup. SiteGuard supports both explicit Upstash variables and Vercel-style `KV_*` variables.

## Deployment

### Vercel

This repository includes a `vercel.json` configuration and serverless API routes under `api/`.

Recommended project settings:

- Framework Preset: `Other`
- Build Command: `npm run build`
- Output Directory: `public`

If you use the private admin analytics dashboard on Vercel, configure admin auth variables and attach Upstash Redis for durable metrics.

### Render

A sample `render.yaml` is included for a web service deployment.

### Docker

Build and run locally with Docker:

```bash
docker build -t siteguard .
docker run -p 3000:3000 siteguard
```

## Project structure

```text
.
├─ api/                  # Vercel serverless API entrypoints
├─ public/               # Static UI assets and admin dashboard
├─ src/                  # Scanner, auth, metrics, and runtime logic
├─ test/                 # Node.js tests
├─ server.js             # Local Node.js server entrypoint
├─ vercel.json           # Vercel configuration
├─ render.yaml           # Render deployment example
├─ Dockerfile            # Container image build
└─ package.json
```

## Safety and runtime guardrails

Because SiteGuard makes outbound network requests, the scanner includes several runtime protections:

- blocks localhost, private IPs, and internal targets
- validates public DNS resolution before connect
- pins resolved targets to reduce DNS rebinding risk
- validates connected socket addresses
- applies absolute request timeouts
- caps response body collection size
- rate-limits by client IP
- limits concurrent scans
- caches scan results briefly to reduce repeated load

These controls improve safety, but they do not turn SiteGuard into a complete security boundary. Always treat it as one layer in a broader review process.

## Testing

Run the full test suite:

```bash
npm test
```

Build assets:

```bash
npm run build
```

## Responsible use

Only scan targets you are authorized to assess.

SiteGuard is designed for public, passive checks, but you are still responsible for complying with local law, platform terms, and organizational policy.

## Security policy

If you believe you found a vulnerability in SiteGuard itself, please read [SECURITY.md](./SECURITY.md) before opening a public issue.

## License

This project is licensed under the [MIT License](./LICENSE).
