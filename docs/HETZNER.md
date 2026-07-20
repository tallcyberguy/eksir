# Hetzner deployment guide

This walks you through standing ISOC up on a Hetzner box — either a CPU-only
Cloud Server or a GPU plan that also runs vLLM locally.

---

## 1. Pick a plan

| Plan | Use it for | Cost (May 2026) |
|---|---|---|
| **CCX23** (4 vCPU AMD / 16GB RAM / 160GB NVMe, no GPU) | Backend + frontend + Postgres + Qdrant. **Claude API only**, no local model. | ~€20/month |
| **GEX44** (8 vCPU / 32GB / 1× RTX 4000 SFF Ada 20GB) | Same as above + vLLM Qwen2.5-32B AWQ-4bit @ 8K context. Adequate "isoc-local" fallback. | ~€189/month |
| **GEX130** (16 vCPU / 64GB / 1× RTX 6000 Ada 48GB) | Comfortable local model — Qwen2.5-72B AWQ-4bit @ 32K context. Realistic Claude replacement for FP-class cases. | ~€499/month |
| **GEX260** (24 vCPU / 128GB / 2× RTX 6000 Ada) | Future: Llama-3.3-70B FP8 or DeepSeek-V3 quantized. | ~€999/month |

**Recommended starting point:** **CCX23** with Anthropic API. If you want to
experiment with vLLM later, upgrade to GEX44 — same image, just add the
`gpu` profile to docker compose.

> **Disk sizing:** Add a 200-500 GB volume mounted at `/srv/isoc` for
> Postgres + Qdrant + HF model cache. Hetzner Volumes are €0.04/GB/month and
> survive server resets.

---

## 2. OS prep (Ubuntu 24.04 LTS)

```bash
# 1) Base hardening
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw fail2ban git curl jq htop

# 2) Firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp           # SSH
sudo ufw allow 80,443/tcp       # Caddy / HTTPS
sudo ufw enable

# 3) Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker

# 4) NVIDIA Container Toolkit (skip on CPU-only plans)
distribution=$(. /etc/os-release; echo $ID$VERSION_ID)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt update && sudo apt install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi   # sanity check
```

---

## 3. Clone + configure

```bash
sudo mkdir -p /srv/isoc && sudo chown -R $USER /srv/isoc
cd /srv/isoc
git clone https://github.com/<your-org>/claude-cyber-space.git source
cd source/isoc

cp deploy/.env.example deploy/.env
$EDITOR deploy/.env
```

**Bare minimum env vars to set:**

| Variable | Required | Value |
|---|---|---|
| `ISOC_DOMAIN` | yes | e.g. `isoc.yourdomain.tld` (DNS A record → server IP) |
| `ISOC_PUBLIC_URL` | yes | `https://isoc.yourdomain.tld` |
| `POSTGRES_PASSWORD` | yes | `openssl rand -base64 32` |
| `JWT_SECRET` | yes | `openssl rand -base64 48` |
| `INGEST_HMAC_SECRET` | yes | `openssl rand -hex 32` |
| `LITELLM_MASTER_KEY` | yes | `sk-litellm-$(openssl rand -hex 24)` |
| `ANTHROPIC_API_KEY` | yes (or use vLLM) | from console.anthropic.com |
| `ISOC_BOOTSTRAP_ADMIN_PASSWORD` | yes | first-login password |
| `VIRUSTOTAL_API_KEY` | recommended | from virustotal.com |
| `ABUSEIPDB_API_KEY` | recommended | from abuseipdb.com |
| `OTX_API_KEY` | recommended | from otx.alienvault.com |
| `IPINFO_TOKEN` | recommended | from ipinfo.io |

After saving the file, regenerate `DATABASE_URL` and `LITELLM_DATABASE_URL` with the
new Postgres password (they share that password).

---

## 4. Bring up the stack

**CPU-only (Claude API):**

```bash
cd /srv/isoc/source/isoc/deploy
docker compose up -d
docker compose ps        # all services healthy?
docker compose logs -f backend
```

**With local GPU model (vLLM):**

```bash
cd /srv/isoc/source/isoc/deploy
docker compose --profile gpu up -d
docker compose logs -f vllm   # wait for "Application startup complete" — ~3-5 min on first run
```

First boot does the following automatically:
1. Caddy fetches Let's Encrypt certs for `ISOC_DOMAIN`
2. Postgres initialises; backend runs `init_db()` → creates the `isoc_case_seq` sequence + all tables
3. Backend creates the bootstrap admin user from env vars
4. ARQ worker connects to Redis and starts polling for jobs
5. LiteLLM proxy reads `litellm.config.yaml` and starts serving on port 4000 (localhost only)

Hit `https://ISOC_DOMAIN` — login with `ISOC_BOOTSTRAP_ADMIN_EMAIL` + password.

---

## 5. Pick a local model (GPU plans only)

The `litellm.config.yaml` has placeholders for **Qwen2.5-72B-Instruct-AWQ**.
Other good choices:

| Model | VRAM (AWQ-4bit) | Quality vs Claude Sonnet | Notes |
|---|---|---|---|
| `Qwen/Qwen2.5-72B-Instruct-AWQ`  | ~40GB | 90 %+ on triage-style tasks | Recommended for GEX130 |
| `Qwen/Qwen2.5-32B-Instruct-AWQ`  | ~20GB | ~85 % | Fits GEX44 (RTX 4000 SFF 20GB) |
| `meta-llama/Llama-3.3-70B-Instruct` (FP8) | ~70GB | 92 %+ | Needs GEX260 (2× RTX 6000) |
| `microsoft/Phi-4-14B`             | ~10GB | ~80 % | Smaller fallback |

Set `VLLM_MODEL`, `VLLM_QUANTIZATION`, `VLLM_MAX_MODEL_LEN` in `.env`, then
`docker compose --profile gpu up -d --force-recreate vllm`.

To **route specific cases to local model** (e.g. when the alert contains
customer PII), expose a per-investigation flag in the UI that picks
`isoc-local` instead of `isoc-deep` — wire it through `pipeline/orchestrator.py`
at the synthesis step.

---

## 6. Webhook ingestion — SIEM senders

1. In ISOC → Administration → Webhook sources → Create.
2. The HMAC secret is shown **once**. Copy it.
3. Configure the SIEM/SOAR to POST JSON to:

   ```
   POST https://ISOC_DOMAIN/v1/ingest/<source_id>
   Headers:
     Content-Type: application/json
     X-ISOC-Timestamp: <unix seconds>
     X-ISOC-Signature: hmac_sha256(secret, f"{ts}." + body_bytes).hex()
   ```

4. Sample sender (curl):

   ```bash
   SECRET=...           # the one shown at creation
   SOURCE_ID=...        # UUID from the admin UI
   TS=$(date +%s)
   BODY='{"raw":"<original alert>","customer":"CONTOSO"}'
   SIG=$(printf "%s.%s" "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
   curl -X POST "https://ISOC_DOMAIN/v1/ingest/$SOURCE_ID" \
     -H "Content-Type: application/json" \
     -H "X-ISOC-Timestamp: $TS" \
     -H "X-ISOC-Signature: $SIG" \
     -d "$BODY"
   ```

---

## 7. Backup

```bash
# Cron at 03:00 daily
0 3 * * * cd /srv/isoc/source/isoc/deploy && \
  docker compose exec -T postgres pg_dump -U isoc isoc | gzip > /srv/isoc/backup/pg-$(date +%F).sql.gz
0 4 * * * tar czf /srv/isoc/backup/qdrant-$(date +%F).tgz /var/lib/docker/volumes/isoc_qdrant_data
```

Push to Hetzner Storage Box / S3-compatible weekly.

---

## 8. Monitoring (lightweight)

- `docker compose logs -f backend worker | grep -i error`
- The LiteLLM admin UI at `http://localhost:4000` (SSH tunnel: `ssh -L 4000:127.0.0.1:4000 isoc`)
  shows per-model token + cost graphs.
- Optional: add **Langfuse** via `LANGFUSE_*` env vars for full LLM call tracing.

---

## 9. Upgrades

```bash
cd /srv/isoc/source && git pull
cd isoc/deploy && docker compose pull && docker compose up -d --build
# Apply migrations
docker compose exec backend alembic upgrade head
```

---

## 10. Things to revisit as you scale

- **Postgres** — at >10K cases/month, partition `incidents` by month + set up read replica.
- **Qdrant** — single node is fine to ~1M vectors; cluster when >5M.
- **REMnux** — currently shares the host. For aggressive samples, move it to a separate
  VPS over WireGuard and adjust `remnux_adapter._exec()` to ssh-exec instead of docker-exec.
- **Multi-tenant** — current schema is single-org. Multi-tenancy requires adding
  `org_id` to every table + RLS policies in Postgres. ADR-0002 will cover this when it's needed.
