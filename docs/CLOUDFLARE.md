# EKSIR — Cloud Deployment Runbook (Hetzner + Cloudflare)

End-to-end playbook for hosting EKSIR on a single Hetzner VM, fronted by
Cloudflare Tunnel + Cloudflare Zero Trust Access. No exposed ports, no
Let's Encrypt plumbing, no public IP visible in DNS.

This is the deployment target once the project hits feature-complete for
**ingestion** — email parser, webhook intake from SIEM/SOAR, and a stable
REST API. Until those exist, paste-ingestion via the UI is the only entry
point and you can run everything on a laptop.

---

## 0. Prerequisites checklist

Before you start, you should have:

- [ ] A domain you control (e.g. `eksir.io`)
- [ ] Cloudflare account (free plan is enough)
- [ ] Hetzner Cloud account with a payment method
- [ ] Anthropic API key (for Claude synthesis)
- [ ] Optional: Vision One API key (`V1_API_KEY`) if you want response actions
- [ ] Optional: VirusTotal / AbuseIPDB / IPInfo API keys (for enrichment)
- [ ] The repo cloned locally and tested with `docker compose up` on a laptop

Feature-readiness gates this deployment assumes are met:

- [ ] **Webhook ingestion** — `POST /v1/ingest/*` accepts HMAC-signed payloads
      from SIEM/SOAR (QRadar, Wazuh, SentinelOne, Splunk).
- [ ] **Email ingestion** — IMAP poller or SMTP receive that parses inbound
      mailbox alerts and pushes them through the same pipeline as paste-ingest.
- [ ] **API ingestion** — authenticated `POST /api/v1/alerts/*` for direct
      programmatic submission from scripts / cron jobs.
- [ ] **Outbound webhooks** — optional but useful: post case verdicts back to
      Slack / Teams / Jira / ServiceNow.

---

## 1. Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │  Cloudflare edge (DNS + WAF + Access + TLS)  │
                  │                                              │
   Browser ──▶ app.eksir.io ────┐                                │
                                │                                │
   SIEM    ──▶ ingest.eksir.io ─┤  Cloudflare Tunnel             │
                                │  (outbound from VM)            │
   Script  ──▶ api.eksir.io ────┘                                │
                  └──────────────────────────────────────────────┘
                                         │
                                  cloudflared daemon (on VM)
                                         │
                  ┌──────────────────────▼──────────────────────┐
                  │ Hetzner VM (CCX23 + 200 GB Volume)          │
                  │                                             │
                  │   docker compose: frontend, backend,        │
                  │   worker, postgres, redis, qdrant, litellm, │
                  │   remnux, cloudflared                       │
                  │                                             │
                  │   UFW: only port 22 (SSH) open inbound      │
                  └─────────────────────────────────────────────┘
```

**Key property:** the VM has UFW set to `default deny incoming` with only SSH
allowed. All app traffic enters via Cloudflare → outbound tunnel → local
ports. There is no public DNS A record pointing at the VM's IP.

---

## 2. Hetzner provisioning

### 2.1. Server + Volume

| Resource | Spec | Cost (May 2026) |
|---|---|---|
| Server | CCX23 (4 vCPU AMD / 16 GB RAM / 160 GB NVMe) | ~€20/mo |
| Volume | 200 GB at `/srv/eksir` | ~€8/mo |
| Storage Box | 1 TB (off-server backups) | ~€3/mo |

Provision via [console.hetzner.cloud](https://console.hetzner.cloud):

1. **Image:** Ubuntu 24.04 LTS
2. **Type:** CCX23 (Shared vCPU AMD, *not* the cheapest CX22 — Postgres + Qdrant + LiteLLM together need >8 GB RAM under load)
3. **Location:** pick the region closest to your customers (FSN1 / NBG1 = Germany, HEL1 = Finland)
4. **SSH key:** upload your public key (no passwords)
5. **Volume:** attach a 200 GB volume in the same datacenter; format as ext4
6. **Cloud Firewall:** Hetzner's network-level firewall — allow port 22 from your IPs only; leave everything else closed (CF Tunnel needs zero inbound)

### 2.2. OS hardening

SSH in as root, then:

```bash
# 1) Updates + tools
apt update && apt upgrade -y
apt install -y ufw fail2ban git curl jq htop unattended-upgrades

# 2) Non-root user
adduser --disabled-password --gecos "" eksir
usermod -aG sudo eksir
mkdir -p /home/eksir/.ssh
cp /root/.ssh/authorized_keys /home/eksir/.ssh/
chown -R eksir:eksir /home/eksir/.ssh
chmod 700 /home/eksir/.ssh
chmod 600 /home/eksir/.ssh/authorized_keys

# 3) Disable root SSH + password auth
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'     /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# 4) Firewall — only SSH inbound, everything else outbound
ufw default deny  incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable

# 5) Auto-updates
dpkg-reconfigure -plow unattended-upgrades

# 6) Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker eksir
```

Reboot. From now on, SSH in as `eksir`.

### 2.3. Volume layout

```bash
sudo mkdir -p /srv/eksir/{postgres,qdrant,redis,caddy,workspace,hfcache,backups}
sudo chown -R eksir:eksir /srv/eksir
```

Update the `docker-compose.yml` volume targets to bind-mount these paths
(instead of named volumes), so they live on the bigger attached disk and
survive `docker volume prune`:

```yaml
volumes:
  postgres_data:   { driver: local, driver_opts: { type: none, o: bind, device: /srv/eksir/postgres } }
  redis_data:      { driver: local, driver_opts: { type: none, o: bind, device: /srv/eksir/redis } }
  caddy_data:      { driver: local, driver_opts: { type: none, o: bind, device: /srv/eksir/caddy } }
  isoc_workspace:  { driver: local, driver_opts: { type: none, o: bind, device: /srv/eksir/workspace } }
  hf_cache:        { driver: local, driver_opts: { type: none, o: bind, device: /srv/eksir/hfcache } }
```

---

## 3. Domain + Cloudflare account setup

### 3.1. Move DNS to Cloudflare

1. Buy / own a domain (Cloudflare Registrar or Porkbun — avoid GoDaddy)
2. In Cloudflare: **+ Add a site** → enter `eksir.io` → choose the free plan
3. Cloudflare gives you two nameservers — set them at your registrar
4. Wait for activation (usually <1 hour). You'll get an email.

### 3.2. SSL/TLS mode

Cloudflare → SSL/TLS → Overview → set to **Full (strict)**. (Tunnel traffic
is already encrypted between cloudflared and CF, so the origin sees plain
HTTP; "Full strict" still applies to the browser → CF leg.)

### 3.3. Browser security baseline

Cloudflare → Security → Settings:

- **Security Level:** Medium
- **Bot Fight Mode:** On
- **Challenge passage:** 30 minutes

Cloudflare → Security → WAF → enable the Cloudflare Managed Ruleset.

---

## 4. Cloudflare Tunnel (the core of this setup)

### 4.1. Create the tunnel

In Cloudflare → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel**:

1. Connector type: **Cloudflared**
2. Tunnel name: `eksir-prod`
3. Copy the install token shown — you'll paste it into `.env`

### 4.2. Add public hostnames

Inside the tunnel, **Public Hostnames** → add three:

| Subdomain | Domain | Service | Path |
|---|---|---|---|
| `app` | `eksir.io` | `http://frontend:3000` | *(empty)* |
| `api` | `eksir.io` | `http://backend:8000` | *(empty)* |
| `ingest` | `eksir.io` | `http://backend:8000` | `v1/ingest` |

Cloudflare will auto-create proxied CNAME records (`app.eksir.io`,
`api.eksir.io`, `ingest.eksir.io`) pointing to `<tunnel-id>.cfargotunnel.com`.

> **Service URLs use Docker service names** (`frontend`, `backend`) because
> `cloudflared` runs inside the same compose network and resolves them via
> Docker DNS. No published ports, no `localhost`.

### 4.3. Add cloudflared to the compose stack

Append to `deploy/docker-compose.yml`:

```yaml
  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel --no-autoupdate run --token ${CLOUDFLARE_TUNNEL_TOKEN}
    depends_on:
      - frontend
      - backend
    networks:
      - default
```

And in `.env`:

```bash
CLOUDFLARE_TUNNEL_TOKEN=<paste-the-token-from-step-4.1>
```

### 4.4. Remove or shrink Caddy

Cloudflare now terminates TLS. You have two choices:

**Option A — Delete caddy entirely** (recommended):

```yaml
# delete the caddy: service block, and its port bindings
# delete caddy_data, caddy_config volumes
```

**Option B — Keep caddy as an internal-only HTTP router** (if you have
path-based rules you want to keep): remove the `80:80` / `443:443` port
bindings, keep it on the internal docker network, and point cloudflared at
`http://caddy:80` instead of the individual services. Most setups don't
need this.

### 4.5. Frontend env vars

In `.env`:

```bash
ISOC_DOMAIN=eksir.io
ISOC_PUBLIC_URL=https://app.eksir.io

NEXT_PUBLIC_API_BASE=https://api.eksir.io/api
NEXT_PUBLIC_WS_BASE=wss://api.eksir.io/ws
```

Rebuild frontend after changing these — Next.js bakes `NEXT_PUBLIC_*` at
build time.

---

## 5. Cloudflare Zero Trust Access (login wall in front of the UI)

Wrap `app.eksir.io` behind Cloudflare Access — no unauthenticated request
ever reaches your VM.

### 5.1. Set up identity provider

Cloudflare → **Zero Trust** → **Settings** → **Authentication** →
**Login methods**. Pick one:

- **Google Workspace** — easiest, email-domain restricted
- **GitHub** — fine for small teams
- **One-time PIN** — emails a code, no IdP needed (good for clients)

### 5.2. Create the Access application

Cloudflare → **Zero Trust** → **Access** → **Applications** → **Add an application** → **Self-hosted**:

| Field | Value |
|---|---|
| Application name | EKSIR |
| Session duration | 24 hours |
| Application domain | `app.eksir.io` |
| Identity providers | (whichever you set up in 5.1) |

Then add a **policy**:

| Action | Allow |
|---|---|
| Rules | Email matches `*@yourcompany.com` (or specific emails) |

### 5.3. Why this is "belt + braces"

- The app's JWT login at `/login` keeps working — analysts still sign in to
  EKSIR with their analyst account, which is what controls role-based
  access *inside* the app (admin vs. analyst vs. viewer).
- Cloudflare Access blocks the **request** before it ever hits FastAPI.
  Even an unauth'd vuln scan or zero-day login bypass doesn't get past CF.

### 5.4. Leave `api.eksir.io` and `ingest.eksir.io` open

These have their own auth:

- `api.eksir.io` — JWT (Bearer token from `/api/v1/auth/login`)
- `ingest.eksir.io` — HMAC-signed (`X-EKSIR-Signature` + `X-EKSIR-Timestamp`)

Adding Access in front of these would break script-based / SIEM-based use.

---

## 6. Ingestion endpoints — what to give clients

Once feature-complete, you'll have three intake paths. Document these for
end users / integrators:

### 6.1. Webhook (SIEM/SOAR push)

```
POST https://ingest.eksir.io/<source>
Headers:
  Content-Type: application/json
  X-EKSIR-Signature: <hex HMAC-SHA256(secret, timestamp + "." + body_bytes)>
  X-EKSIR-Timestamp: <unix seconds>
Body: <SIEM-native JSON or text>
```

Sources currently planned: `qradar`, `wazuh`, `sentinelone`, `splunk`,
`defender`. Webhook secret is generated per-source in the EKSIR admin UI
(Administration → Webhook sources).

### 6.2. Email ingestion

Configure your SIEM / monitoring tool to send notification emails to a
mailbox EKSIR polls (e.g. `alerts@eksir.io`). The mail ingester:

- IMAP-polls every minute
- Parses subject + body
- Routes through the same pipeline as paste-ingest
- Marks messages as read; moves to `Processed` folder
- Email auth via DKIM check — drops anything failing DKIM

Set `MAIL_INGEST_HOST` / `MAIL_INGEST_USER` / `MAIL_INGEST_PASSWORD` in `.env`.

### 6.3. REST API

```
POST https://api.eksir.io/api/v1/alerts/json
Headers:
  Authorization: Bearer <jwt>
  Content-Type: application/json
Body:
  { "raw_text": "...", "customer": "AcmeCorp", "source_hint": "qradar" }
```

Get the JWT once via `POST /api/v1/auth/login`. Tokens last 24 h by
default (configurable via `JWT_TTL_MINUTES`).

---

## 7. Deployment steps (in order)

```bash
# On the Hetzner VM, as the eksir user:

# 1. Clone
cd /srv/eksir
git clone https://github.com/<your-org>/eksir.git
cd eksir

# 2. Bring in alert-memory-mcp (referenced by the parser adapter)
cd /srv/eksir
git clone https://github.com/<your-org>/alert-memory-mcp.git

# 3. Configure
cd eksir/deploy
cp ../deploy/.env.example .env
$EDITOR .env
# Set:
#   ANTHROPIC_API_KEY, JWT_SECRET, POSTGRES_PASSWORD
#   ISOC_BOOTSTRAP_ADMIN_EMAIL, ISOC_BOOTSTRAP_ADMIN_PASSWORD
#   INGEST_HMAC_SECRET
#   CLOUDFLARE_TUNNEL_TOKEN
#   ISOC_DOMAIN, ISOC_PUBLIC_URL
#   NEXT_PUBLIC_API_BASE, NEXT_PUBLIC_WS_BASE
#   Optional: V1_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, IPINFO_TOKEN

# 4. Pull / build
docker compose pull
docker compose build

# 5. Start
docker compose up -d

# 6. Watch the tunnel come up
docker compose logs -f cloudflared
# Look for: "Registered tunnel connection" × 4

# 7. Smoke test
curl https://api.eksir.io/health
# {"status":"ok","service":"isoc-api","version":"0.1.0"}

# 8. First login
# Open https://app.eksir.io → Cloudflare Access challenge → sign in
# → app's own login page → use ISOC_BOOTSTRAP_ADMIN_EMAIL/PASSWORD
# → IMMEDIATELY change the bootstrap admin password in Admin → Users
```

---

## 8. Backups

### 8.1. Hetzner Storage Box

In the Hetzner Console → Storage Boxes → create a 1 TB box. Note the
hostname (`uXXXXXX.your-storagebox.de`) and credentials.

### 8.2. Nightly Postgres + Qdrant dumps

On the VM:

```bash
sudo apt install -y rclone
mkdir -p ~/.config/rclone
$EDITOR ~/.config/rclone/rclone.conf
```

Paste:

```
[hetzner-box]
type = sftp
host = uXXXXXX.your-storagebox.de
user = uXXXXXX
pass = <obscured-via-rclone-obscure>
port = 23
```

Backup script `/srv/eksir/backups/run.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/srv/eksir/backups/staging

mkdir -p "$OUT"

# Postgres dump
docker compose -f /srv/eksir/eksir/deploy/docker-compose.yml \
  exec -T postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" \
  | gzip > "$OUT/postgres-$TS.sql.gz"

# Qdrant snapshot
docker compose -f /srv/eksir/eksir/deploy/docker-compose.yml \
  exec -T qdrant curl -s -X POST \
  "http://localhost:6333/collections/eksir-alerts/snapshots" >/dev/null
# Then rclone copy the snapshot file out from /srv/eksir/qdrant/snapshots/

# Off-server push
rclone sync "$OUT/" hetzner-box:eksir-backups/

# Retention: keep last 14 days locally, 90 on the box
find "$OUT" -type f -mtime +14 -delete
rclone delete --min-age 90d hetzner-box:eksir-backups/
```

Add to `crontab -e`:

```cron
0 3 * * * /srv/eksir/backups/run.sh >> /var/log/eksir-backup.log 2>&1
```

### 8.3. Test the restore

Quarterly: spin up an empty Postgres, `gunzip < dump.sql.gz | psql`,
verify row counts. **A backup you've never restored isn't a backup.**

---

## 9. Monitoring

### 9.1. Uptime — Cloudflare's free health checks

Cloudflare → Traffic → Health Checks → add monitor for
`https://api.eksir.io/health`. Email alert on failure.

### 9.2. Application metrics — keep it simple

For now: `docker stats` + `docker compose logs` + the EKSIR Reports page
(once monthly summaries land). Skip Prometheus/Grafana until you actually
need traceable SLOs.

### 9.3. SSH break-glass

If Cloudflare ever has an outage (rare), you can still reach the VM via
SSH on port 22. Make sure your Hetzner Cloud Firewall allows SSH from a
trusted IP range, not 0.0.0.0/0.

---

## 10. Updates + maintenance

```bash
# On the VM:
cd /srv/eksir/eksir
git pull
cd deploy
docker compose pull
docker compose build
docker compose up -d --remove-orphans

# Verify
docker compose ps
curl https://api.eksir.io/health
```

For database migrations (Alembic):

```bash
docker compose exec backend alembic upgrade head
```

---

## 11. Cost summary (monthly)

| Item | Cost |
|---|---|
| Hetzner CCX23 server | ~€20 |
| Hetzner Volume 200 GB | ~€8 |
| Hetzner Storage Box 1 TB | ~€3 |
| Cloudflare (DNS + Tunnel + WAF + Access ≤ 50 users) | **Free** |
| Domain (`.io` ≈ $40/yr, `.com` ≈ $10/yr) | ~$1–4 |
| Anthropic API | variable (typically €5–50/mo at small SOC volume) |
| **Floor** | **~€32/mo + LLM tokens** |

Scale up the server when you hit:

- Postgres response time > 500 ms — bump to CCX33 (more vCPU + RAM)
- Sustained CPU > 80 % during synthesis bursts — same
- Disk > 70 % full — extend the volume (Hetzner allows live grow)

---

## 12. Troubleshooting

### Tunnel won't connect

```bash
docker compose logs cloudflared | tail -40
```

Look for:
- `Unauthorized: Failed to get tunnel` → token in `.env` is wrong or revoked
- `dial tcp: lookup frontend on …: no such host` → cloudflared isn't on the
  same network as `frontend` / `backend`. Check `networks:` in compose.

### Browser sees 502 Bad Gateway

- Service is down — `docker compose ps`
- Wrong service URL in CF tunnel config — should be `http://frontend:3000`
  not `http://localhost:3000`

### Webhook returns 401

- Timestamp drift > 5 min — sync the sender's clock or widen the window
- HMAC mismatch — verify secret is the one shown at webhook source creation
  (it's only shown once; rotate if lost)

### Cloudflare Access blocking analysts

- Check Zero Trust → Logs → Access — see why the policy rejected them
- Add their email to the policy's allow list

### Postgres data lost after rebuild

- Bind mount target on `/srv/eksir/postgres` was missing or wrong
  permissions. Restore from latest dump, fix the volume mount, redeploy.

---

## 13. Hardening checklist (post-launch)

- [ ] Bootstrap admin password rotated
- [ ] `JWT_SECRET` is 64+ random bytes (`openssl rand -hex 64`)
- [ ] `INGEST_HMAC_SECRET` is unique per webhook source (admin UI generates)
- [ ] Cloudflare Access policy restricts to your email domain, not "any"
- [ ] Hetzner Cloud Firewall: SSH allowed only from your IP, not the world
- [ ] Backups verified by a test restore
- [ ] Anthropic API key is workspace-scoped, not your account-wide key
- [ ] Health check alerts route to a channel you actually read
- [ ] DNS records for `app`, `api`, `ingest` are **proxied** (orange cloud) — never grey
