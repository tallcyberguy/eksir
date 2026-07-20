# EKSIR Landing

Marketing site for `eksir.com`. Separate Next.js 14 app from the platform under `../frontend`.
Theme tokens are mirrored so both surfaces read as the same product.

## Stack

- Next.js 14 (App Router, standalone output)
- Tailwind CSS — tokens copied from `frontend/tailwind.config.ts`
- lucide-react icons
- nodemailer for the demo form

## Local dev

```bash
cp .env.example .env.local
# (optional) fill SMTP_* to test the demo form against your inbox
npm install
npm run dev          # http://localhost:3100
```

The site renders without SMTP — the demo form just returns a friendly 503 telling the
visitor to email `hello@eksir.com` directly.

## Pages

| Route             | What it is                                                    |
| ----------------- | ------------------------------------------------------------- |
| `/`               | Landing: hero, problem, features, how-it-works, pricing, CTA  |
| `/request-demo`   | Two-column form → POST `/api/demo`                            |
| `/api/demo` (POST)| Validates input, rate-limits, sends lead via SMTP             |

## Environment

| Var                 | Notes                                                          |
| ------------------- | -------------------------------------------------------------- |
| `NEXT_PUBLIC_APP_URL` | Where "Sign in" buttons point. Default `https://platform.eksir.com`. |
| `DEMO_INBOX`        | Where demo requests are emailed. Default `hello@eksir.com`.   |
| `SMTP_HOST`         | Empty → demo form returns 503 with a friendly message.        |
| `SMTP_PORT`         | Default 587.                                                  |
| `SMTP_USER`         | Optional. If empty, SMTP runs without auth.                   |
| `SMTP_PASSWORD`     | Required when `SMTP_USER` is set.                             |
| `SMTP_FROM`         | The `From:` header. Default `noreply@eksir.com`.              |
| `SMTP_USE_TLS`      | `false` to disable STARTTLS. Default `true`.                  |

## Deploy

Built as a standalone Docker image (`Dockerfile`). Drop it behind Cloudflare with
DNS pointing `eksir.com` → this image, and `platform.eksir.com` → the existing
`isoc-frontend` service. See `../docs/` for the broader Cloudflare/Hetzner plan.
