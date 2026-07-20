# EKSIR Deployment Guide — Hetzner + Cloudflare

Step-by-step for the first production deploy. Assumes you have **none** of:
domain, VM, DNS, or backups. Total wall-clock time: ~90 minutes
(half of that is waiting for Hetzner's identity check).

Total recurring cost: **~€9 / $10 per month** all-in.

> **Skip ahead** if you already have any of these:
> - § [1. Buy a domain](#1-buy-a-domain) — only if no domain yet
> - § [2. Provision a VM](#2-provision-a-vm) — only if no server yet
> - § [3. Point domain → VM](#3-point-the-domain-at-the-vm) — even if you have both
> - § [4. SSH + install Docker](#4-first-ssh-and-install-docker)
> - § [5. Clone repo + configure secrets](#5-clone-repo-and-configure-secrets)
> - § [6. Authenticate to GHCR](#6-authenticate-to-ghcr-for-image-pulls)
> - § [7. First boot](#7-first-boot)
> - § [8. Smoke test](#8-smoke-test)
> - § [9. Post-deploy hardening](#9-post-deploy-hardening)

---

## 1. Get a domain (or subdomain)

Two paths depending on your situation. **Skip to whichever matches yours.**

### Path A: Buy a new domain via Cloudflare (independent setup)

Open https://dash.cloudflare.com (sign up if needed — free) → **Registrar**
→ search for the name you want.

**Recommended TLDs and prices** (at-cost via Cloudflare Registrar):

| TLD | Price/year |
|---|---|
| `.com` | $10.44 |
| `.app` | $14.18 |
| `.io` | $35.00 (premium) |
| `.dev` | $11.66 |
| `.security` | $34.00 |
| `.tr` | not available via Cloudflare — get from a .tr registrar if you want |

**Pick a subdomain** for EKSIR, not the apex. E.g. if you bought
`yourname.com`, run EKSIR at `eksir.yourname.com`. This leaves the apex
free for a marketing landing page later. Throughout this guide I'll
use `eksir.example.com` — substitute your actual subdomain.

Complete the checkout (~$10 + a few minutes).

**Free WHOIS privacy is on by default** at Cloudflare — your home
address won't show up in WHOIS queries.

### Path B: Use a subdomain on a company / partner domain

If you have access to an existing organization that already runs a
domain (with Microsoft 365, Google Workspace, etc.), you can run EKSIR
on a subdomain of theirs. No registrar purchase needed.

Send this exact request to their IT contact:

> Could you please:
> 1. Add a DNS A record:
>    - Name: `eksir.theirdomain.com` (or whichever subdomain we agree on)
>    - Type: A
>    - Value: `<my Hetzner IPv4>`  *(you'll fill this in after § 2)*
>    - TTL: auto / 3600
>    - **Proxy / CDN: OFF**  ← important — Caddy needs direct port 80
>      for Let's Encrypt validation
> 2. If we want EKSIR to send customer email notifications:
>    create a service mailbox like `eksir-noreply@theirdomain.com`
>    with SMTP AUTH enabled on `smtp.office365.com:587`
>    (or `smtp.gmail.com:587` for Google Workspace)
>
> I'll handle the rest from my end.

Once they confirm, use `eksir.theirdomain.com` (or whatever you both
agreed on) throughout this guide. Verify the DNS:

```bash
dig +short eksir.theirdomain.com    # should return your Hetzner IPv4
```

**Things to consider for Path B:**
- **Branding**: customers will see `eksir.theirdomain.com` in incident
  reports → they'll associate EKSIR with that company. Confirm this
  fits how you want EKSIR positioned.
- **Continuity**: if your relationship with the company ends, you lose
  the subdomain. Mitigations: also register a $10/yr fallback domain
  via Cloudflare and park it (no DNS records until needed); when ready
  to migrate, the move is ~30 min of DNS work + a Caddy re-issue.
- **Mail dependency**: if EKSIR sends via their M365 SMTP, you inherit
  their domain's mail reputation (good) but also their rate limits
  (M365: 30 msg/min, 10k msg/day per mailbox — plenty for EKSIR).

---

## 2. Provision a VM

### 2a. Sign up at Hetzner

https://hetzner.com/cloud → create account.

Hetzner does a **one-time identity verification** with a photo of your
ID and a selfie. This is automated and takes ~30 minutes to ~24 hours.
Without it you can't start servers. Do this step first; the rest of
the guide can wait.

### 2b. Pick a project + add SSH key

Once verified, create a **Project** (call it "eksir" or whatever).

**Security tab → SSH Keys → Add Key**. On your local Mac:

```bash
# Generate a key dedicated to this server (don't reuse personal SSH keys).
ssh-keygen -t ed25519 -f ~/.ssh/eksir_hetzner -C "eksir-deploy"
cat ~/.ssh/eksir_hetzner.pub        # paste this into Hetzner UI
```

### 2c. Create the server

**Servers → Add Server**:

- **Location**: Falkenstein (Germany) or Helsinki (Finland) — both
  give ~50ms latency from Istanbul; pick whichever's cheaper at the
  moment (they're identically priced as of writing).
- **Image**: Ubuntu 26.04 LTS
- **Type**: **CX33** (4 vCPU shared / 8 GB RAM / 80 GB SSD) — €6.99/mo
- **Networking**: leave defaults (IPv4 + IPv6 both included free)
- **SSH keys**: pick the key you just added
- **Volumes**, **Firewalls**: skip for now (firewall comes in § 9)
- **Backups**: opt-in costs +20% (~€1.40/mo). **Recommended.** Hetzner
  takes daily snapshots automatically; saves you building a custom
  pgdump pipeline.
- **Name**: `eksir-prod` or similar

Click **Create & Buy now**. ~30 seconds later the server is up. Copy
its **IPv4 address**.

---

## 3. Point the domain at the VM

In Cloudflare dashboard → your domain → **DNS** → **Records** →
**Add record**:

| Type | Name | IPv4 address | Proxy status | TTL |
|---|---|---|---|---|
| **A** | `eksir` (or whatever subdomain) | `<your hetzner IPv4>` | **DNS only** (grey cloud) | Auto |

**Critical**: the Cloudflare proxy must be **OFF** (grey cloud, not
orange). Caddy on your VM needs to talk directly to Let's Encrypt to
get its TLS cert; Cloudflare's proxy mode intercepts and breaks this.

DNS propagates in ~30 seconds globally with Cloudflare. Verify:

```bash
dig +short eksir.example.com           # should return your Hetzner IPv4
```

---

## 4. First SSH and install Docker

```bash
ssh -i ~/.ssh/eksir_hetzner root@<hetzner-ipv4>
```

On the server:

```bash
# Update package index
apt update && apt upgrade -y

# Install Docker + compose plugin (Ubuntu 26.04 LTS ships compose-v2 in apt)
apt install -y docker.io docker-compose-v2 git ufw fail2ban

# Verify
docker --version
docker compose version
```

Quick sanity:

```bash
docker run --rm hello-world          # should print "Hello from Docker!"
```

---

## 5. Clone repo and configure secrets

```bash
mkdir -p /opt && cd /opt
git clone https://github.com/tallcyberguy/eksir.git
cd eksir/deploy
cp .env.example .env
```

**Edit `.env`** (`nano .env` or `vim .env`). The minimum changes you
MUST make before first boot:

```bash
# Public-facing domain
ISOC_DOMAIN=eksir.example.com
ISOC_PUBLIC_URL=https://eksir.example.com

# Strong Postgres password — generate fresh
POSTGRES_PASSWORD=$(openssl rand -hex 24)
# Then also update DATABASE_URL below to match!
DATABASE_URL=postgresql+asyncpg://isoc:<same-password>@postgres:5432/isoc

# Fresh JWT signing secret — invalidates all prior tokens
JWT_SECRET=$(openssl rand -hex 64)

# Bootstrap admin — set a STRONG password before first boot
ISOC_BOOTSTRAP_ADMIN_EMAIL=admin@eksir.example.com
ISOC_BOOTSTRAP_ADMIN_PASSWORD=<at-least-20-chars-strong>

# LiteLLM master key (any random string)
LITELLM_MASTER_KEY=$(openssl rand -hex 32)

# LLM provider keys — at minimum one of these:
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...

# Webhook ingest secret (per-source secrets are created via admin UI later,
# this is the global fallback)
INGEST_HMAC_SECRET=$(openssl rand -hex 32)

# Threat intel (optional but recommended)
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...

# ── Email (only required if you'll send customer-case notifications) ──
#
# If using Microsoft 365 (your company's tenant), ask IT to:
#   1. Provision a service mailbox (e.g. eksir-noreply@theirdomain.com)
#   2. Enable SMTP AUTH on it (or generate an app password if MFA is on)
# Then set:
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=eksir-noreply@theirdomain.com
SMTP_PASSWORD=<app-password-from-M365>
SMTP_FROM=eksir-noreply@theirdomain.com
SMTP_STARTTLS=true
# Note: M365 rate-limits to 30 msg/min, 10k msg/day per mailbox.
# Plenty for EKSIR, but a runaway loop could lock the account.

# If using Google Workspace instead:
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=eksir-noreply@theirdomain.com
# SMTP_PASSWORD=<app-password>
# (Workspace also requires SMTP relay enabled in Admin console)

# If using Resend (independent setup, free tier 3k/month):
# SMTP_HOST=smtp.resend.com
# SMTP_PORT=587
# SMTP_USER=resend
# SMTP_PASSWORD=<resend-api-key>
# SMTP_FROM=noreply@yourdomain.com  # must match a domain verified in Resend
```

For the `openssl rand` ones, run the command in your local terminal
first and paste the output into `.env`. Don't leave the literal
`$(...)` expressions in the file.

**Verify the file**:

```bash
grep -E "CHANGE-ME|<.+>" .env || echo "✓ no placeholder values left"
```

If anything shows up, you missed a substitution. Fix before continuing.

---

## 6. Authenticate to GHCR for image pulls

The container images are in a **private** GHCR repo, so the VM needs
credentials to pull them.

### 6a. Create a Personal Access Token

On your local Mac (or browser):

1. Go to https://github.com/settings/tokens/new
2. **Note**: "EKSIR prod VM — image pulls"
3. **Expiration**: 90 days (set a calendar reminder to rotate)
4. **Scopes**: check **`read:packages`** only
5. Click **Generate token**, copy it immediately (won't show again)

### 6b. Login on the VM

```bash
# On the VM:
echo '<paste-token-here>' | docker login ghcr.io -u tallcyberguy --password-stdin
```

Should print `Login Succeeded`. The credentials are saved to
`/root/.docker/config.json` and persist across reboots.

---

## 7. First boot

```bash
cd /opt/eksir/deploy

# Pin to the latest tagged release (recommended) or :latest for HEAD of main
export EKSIR_VERSION=latest         # or v0.1.0, etc.

# Pull all images first (catches auth issues before starting anything)
docker compose -f docker-compose.prod.yml pull

# Bring up the stack
docker compose -f docker-compose.prod.yml up -d

# Watch the boot
docker compose -f docker-compose.prod.yml logs -f
```

You should see in order:
1. `postgres` → `database system is ready to accept connections`
2. `redis` → `Ready to accept connections`
3. `qdrant` → `Qdrant HTTP listening on 6333`
4. `litellm` → boots and connects to postgres
5. `backend` → schema backfill runs, bootstrap admin created, FastAPI listens
6. `worker` → ARQ picks up the queue
7. `frontend` → Next.js standalone server starts on :3000
8. `caddy` → grabs TLS cert from Let's Encrypt (~30 seconds the first time)

Ctrl-C to detach from logs (containers keep running).

---

## 8. Smoke test

From your local Mac, in order:

```bash
DOMAIN=eksir.example.com   # substitute yours

# 1. TLS cert + reverse proxy working
curl -sI https://$DOMAIN/health
# → HTTP/2 200 + JSON body {"status":"ok",...}

# 2. Deep readiness (all dependencies reachable)
curl -s https://$DOMAIN/health/deep | python3 -m json.tool
# → status: "ok", postgres/redis/qdrant all ok:true

# 3. Login as bootstrap admin
TOKEN=$(curl -sX POST https://$DOMAIN/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d "{\"email\":\"admin@$DOMAIN\",\"password\":\"<your-bootstrap-pw>\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "Token: $TOKEN"

# 4. Dashboard returns empty stats (fresh DB)
curl -s https://$DOMAIN/api/v1/dashboard/stats -H "authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('incidents:',d['total_incidents'],'iocs:',d['unique_iocs'])"
# → incidents: 0  iocs: 0

# 5. Paste a test alert end-to-end
curl -sX POST https://$DOMAIN/api/v1/alerts/paste \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"raw_text":"Smoke test alert from DEPLOY.md","customer":"smoke-test"}'
# → returns {"incident_id":"...", "case_number":"CASE-001000", "status":"received"}

# 6. Wait ~30s, check it processed through the pipeline
sleep 30
curl -s "https://$DOMAIN/api/v1/incidents?customer=smoke-test" \
  -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0]['status'])"
# → "closed" or "synthesized" — anything but "received"/"failed" is good
```

If all 6 pass, **you're live in production.**

Open https://eksir.example.com in a browser, log in with the bootstrap
admin email + password. You should see an empty dashboard.

---

## 9. Post-deploy hardening

Do these within 24 hours of the first deploy.

### 9a. Change the bootstrap admin password

Even though you set it via env, log in via the UI and change it once
more from the user settings. Reduces the surface where the password
exists in plaintext (it's still in `.env`, but…).

### 9b. Configure the firewall

Hetzner Cloud Firewall (in their dashboard) → **Firewalls → Create Firewall**:

| Direction | Source/Destination | Protocol | Port | Description |
|---|---|---|---|---|
| Inbound | Any IPv4/IPv6 | TCP | 22 | SSH (or restrict to your home IP) |
| Inbound | Any IPv4/IPv6 | TCP | 80 | HTTP (Let's Encrypt validation) |
| Inbound | Any IPv4/IPv6 | TCP | 443 | HTTPS (real traffic) |
| Inbound | Any IPv4/IPv6 | ICMP | — | Ping (useful for monitoring) |

Apply it to the `eksir-prod` server. Everything else is blocked.

**Don't** also enable UFW on the host — Hetzner's network firewall
already does the job and host-level UFW can get confused with Docker's
iptables rules.

### 9c. Disable SSH password login

Even though you only use keys, lock it down:

```bash
# On the VM:
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart ssh

# Test from a NEW terminal before closing your current session:
ssh -i ~/.ssh/eksir_hetzner root@<ipv4> "echo still works"
```

### 9d. Set up automatic security updates

```bash
# On the VM:
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades   # answer "Yes"
```

This applies critical security patches automatically. Won't restart
the server though — review uptime monthly and reboot if needed.

### 9e. Monitor uptime

Free option: https://uptimerobot.com — sign up, add monitor:
- **Type**: HTTP(s)
- **URL**: `https://eksir.example.com/health`
- **Interval**: 5 min
- **Alert contacts**: your email

You'll get an email if the site goes down for >5 minutes. Good enough
for a solo dev.

---

## Operational cheatsheet

### Deploy a new version
On your local Mac:
```bash
git tag v0.2.0
git push --tags
# Wait ~3 min for the GHA release workflow to build + push images
```

On the VM:
```bash
cd /opt/eksir/deploy
export EKSIR_VERSION=v0.2.0
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs -f --tail 50
```

### View logs
```bash
docker compose -f docker-compose.prod.yml logs -f backend          # tail one service
docker compose -f docker-compose.prod.yml logs --since 1h          # last hour
docker compose -f docker-compose.prod.yml logs --tail 100 worker   # last 100 lines
```

### Restart one service without downtime for others
```bash
docker compose -f docker-compose.prod.yml restart backend
```

### Stop everything (e.g. before snapshot)
```bash
docker compose -f docker-compose.prod.yml stop
# data volumes persist; bring back up with `up -d`
```

### Backup (manual — until proper backups land in Phase 4)
```bash
# Postgres dump
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U isoc isoc | gzip > /root/eksir-pg-$(date +%F).sql.gz

# Qdrant snapshot (creates a tarball in /qdrant/storage/snapshots/)
curl -X POST http://localhost:6333/collections/alerts_v2/snapshots
```

Hetzner's snapshot feature (€1.40/mo Backup add-on) handles full-VM
snapshots automatically — simpler than this for now.

### Rollback to a previous version
```bash
export EKSIR_VERSION=v0.1.0     # the version you want
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

This works **only for code**. If a DB migration happened in v0.2.0
that's incompatible with v0.1.0, you'd need to restore from a backup
too. Migrations should always be backward-compatible for one release.

---

## Troubleshooting

### Caddy doesn't get a TLS cert
- Check Cloudflare DNS is **DNS-only (grey cloud), not Proxied (orange)**
- Check port 80 is open in Hetzner firewall (Let's Encrypt validates via HTTP)
- `docker compose logs caddy` will show the ACME error

### "Login failed" against bootstrap admin
- Email is case-sensitive in the lookup; use exactly what you set
- Check `docker compose logs backend` for the actual error
- Verify `.env` has no Windows line endings (`file .env`)

### Backend health check fails
- `/health/deep` will tell you which dep is unreachable
- Most common: `QDRANT_URL` still points at `host.docker.internal` from
  a copy-paste; should be `http://qdrant:6333` in prod `.env`

### Out of disk
```bash
df -h                                                    # check usage
docker system prune -af --volumes                        # nuclear option (don't run lightly)
docker compose -f docker-compose.prod.yml exec postgres vacuumdb -a -f -U isoc
```

### GHCR pull fails with `unauthorized`
- PAT expired (90-day default) — generate a new one, `docker login` again
- Or run `docker logout ghcr.io && docker login ghcr.io -u tallcyberguy --password-stdin`

---

## When to revisit hosting choices

You picked Hetzner CX33 because it's cheap and adequate. Re-evaluate when
any of these hits:

| Trigger | Move to |
|---|---|
| Memory usage stays >85% for a week | CX43 (8 vCPU / 16 GB / 160 GB), €12.49/mo |
| Postgres > 30 GB | Hetzner Cloud Volume (€0.0476/GB/mo, mountable) — cheaper than upgrading the whole VM |
| First Turkish customer with on-shore data clause | Vargonen Istanbul (~3× cost, KVKK-explicit) |
| Need PITR backups for compliance | Migrate Postgres to Neon ($19/mo) or set up pgbackrest |
| 10+ users / 20k+ incidents/day | This is when the Scaling Notes section of DEVSECOPS_PLAN.md kicks in |

For now: ship it on what you have.
