"""Centralised configuration loaded from environment variables.

Every module that needs config imports `settings` from this file rather than
reading os.environ directly. This makes the surface easy to audit.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Identity ─────────────────────────────────────────────────────────
    isoc_domain: str = "localhost"
    isoc_public_url: str = "http://localhost"
    log_level: str = "INFO"
    # Deployment posture: "dev" (default) | "staging" | "prod". Controls the
    # fail-closed startup secret checks (weak secrets abort boot only when this
    # is a production-like value) and CORS tightening (localhost origins are
    # allowed only in dev). Left at "dev" it never blocks a local/test boot;
    # set ISOC_ENV=prod before exposing the product. ENV ISOC_ENV.
    isoc_env: str = "dev"

    # ── PostgreSQL ───────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://isoc:isoc@localhost:5432/isoc"

    # ── Redis / ARQ ──────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Qdrant (shared with alert-memory-mcp) ────────────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: SecretStr | None = None
    qdrant_alerts_collection: str = "alerts_v2"
    qdrant_kb_collection: str = "knowledge_base_v2"

    # ── LLM router (LiteLLM) ─────────────────────────────────────────────
    litellm_base_url: str = "http://localhost:4000"
    litellm_master_key: SecretStr = SecretStr("sk-dev-only")
    isoc_model_deep: str = "isoc-deep"
    isoc_model_fast: str = "isoc-fast"
    # Output-token ceiling for the deep L2 synthesis. The canonical report + the
    # trailing AnalysisVerdict JSON block don't fit in 4096 on a rich alert, so
    # the report truncates and the verdict block is lost. 8192 gives headroom;
    # Claude (the deep tier) handles it easily. ENV ISOC_DEEP_MAX_TOKENS.
    deep_max_tokens: int = 8192
    # When true, the deep-tier synthesis may call read-only enrichment tools
    # (e.g. lookup_ioc_history) via function calling. Needs a tool-capable model
    # routed through LiteLLM (e.g. Claude). Off by default.
    isoc_enable_llm_tools: bool = False

    # ── LLM cost governance (fail-safe budget caps) ──────────────────────
    # USD ceilings on deep-tier synthesis spend. When a cap is exceeded the
    # deep L2 call is SKIPPED and the incident parks at awaiting_review for a
    # human — it never auto-decides. 0 = disabled (the default). Local/self-
    # hosted models price at $0, so caps never fire on a local deployment.
    #   daily    — rolling calendar-day (UTC) total across all incidents
    #   incident — total for a single incident's LLM calls
    llm_daily_cost_cap_usd: float = 0.0
    llm_incident_cost_cap_usd: float = 0.0

    # ── Agentic substrate (F8 — LangGraph) ───────────────────────────────
    # When true, the persona synthesis (_step_synthesis) is orchestrated by a
    # LangGraph StateGraph instead of the legacy inline sequence. Both paths
    # call the SAME phase helpers, so behavior is identical — the graph just
    # owns the control flow + checkpointing. Off by default; flip once the
    # graph path is exercised on the stack.
    isoc_use_langgraph: bool = False
    # Checkpointer backend for the synthesis graph: "memory" (in-process, the
    # default) or "postgres" (durable, resumable — requires the
    # langgraph-checkpoint-postgres package + a DSN; see synthesis_graph.py).
    isoc_langgraph_checkpointer: str = "memory"

    # ── LLM egress contract (F3) ─────────────────────────────────────────
    # Fail-closed guard that inspects every outbound prompt BEFORE it leaves
    # for the LLM (the deep tier is routed to Claude, a third party). Strict
    # policy: refuse raw OCSF/log shapes, secrets, and oversize payloads.
    #   off     — disabled (no inspection)
    #   report  — log would-be violations but never block (safe rollout default)
    #   enforce — block violating calls (LLMResult.status == "blocked")
    isoc_llm_contract_mode: str = "report"
    # Per-message hard size cap (chars). A single prompt larger than this is a
    # violation regardless of content — protects context window + cost and
    # catches "someone sent the whole alert".
    isoc_llm_contract_max_chars: int = 60000

    # ── LLM settings encryption ───────────────────────────────────────────
    # Fernet key used to encrypt the admin-configured LLM API key at rest.
    # Generate once:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # If unset the system derives a key from JWT_SECRET (dev-only convenience).
    settings_encryption_key: SecretStr | None = None

    # ── Auth ─────────────────────────────────────────────────────────────
    jwt_secret: SecretStr = SecretStr("change-me-dev-only")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 60
    isoc_bootstrap_admin_email: str = "admin@isoc.local"
    isoc_bootstrap_admin_password: SecretStr = SecretStr("change-me")

    # ── Ingestion ────────────────────────────────────────────────────────
    ingest_hmac_secret: SecretStr = SecretStr("change-me-32-char-random")
    ingest_timestamp_skew_seconds: int = 300

    # ── Pull ingest (scheduled console API poll → RECEIVED incident) ──────
    # Master switch for the worker `pull_ingest` cron. Off by default so it
    # ships dark; a source must also have an `ingest_sources` row with
    # enabled=true and credentials in the Integration store before it polls.
    pull_ingest_enabled: bool = False

    # ── Microsoft Graph mail (outbound send, app-only client-credentials) ─
    # Used by the customer-notification mailer when email_send_via="graph".
    # The old inbound mailbox-ingest poller was retired in favour of connectors.
    #   tenant/client/secret -> the Entra app registration (Mail.Send)
    #   mailbox              -> UPN the mail is sent as (also the default sender)
    graph_tenant_id: str | None = None
    graph_client_id: str | None = None
    graph_client_secret: SecretStr | None = None
    graph_mailbox: str | None = None

    # ── Outbound customer mail backend ───────────────────────────────────
    # "smtp" (stdlib smtplib; needs SMTP AUTH) or "graph" (app-only Mail.Send,
    # reusing the GRAPH_* creds above — no SMTP AUTH / passwords).
    email_send_via: str = "smtp"
    # Sender mailbox for Graph send; defaults to graph_mailbox when unset.
    graph_send_from: str | None = None

    # ── External enrichment (handed to triage.py via env) ────────────────
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    # abuse.ch unified auth key — covers MalwareBazaar, ThreatFox, URLhaus.
    # Get one (free) at https://auth.abuse.ch/. triage.py reads this exact
    # env var name (canonical, see scripts/triage.py:165).
    abusech_auth_key: SecretStr | None = None
    ipinfo_token: SecretStr | None = None

    # ── Paths (inside the container) ─────────────────────────────────────
    alert_memory_mcp_path: Path = Path("/opt/alert-memory-mcp")
    # triage.py is vendored into the backend image at /app/scripts/triage.py.
    # The SKILL workflow keeps its own copy at ~/.claude/skills/malware-analysis/;
    # ISOC does not depend on that path being present.
    triage_script_path: Path = Path("/app/scripts/triage.py")
    auto_close_yaml_path: Path = Path("/opt/alert-memory-mcp/auto_close_rules.yaml")
    workspace_path: Path = Path("/workspace")

    # ── Trend Micro Vision One ───────────────────────────────────────────
    # API key from Vision One console → Administration → API Keys.
    # Region codes: us, eu, jp, au, sg, in, mea
    v1_api_key: SecretStr | None = None
    v1_region: str = "eu"
    # Customer name → V1 tenant mapping (comma-separated "customer:tenant" pairs).
    # e.g. "acme:acme,clientB:tenantB"
    # If set, endpoint actions are only shown for matching customers.
    v1_customers: str = ""
    # ── V1 workbench auto-enrichment (ADR-0005, read-only) ───────────────
    # When true, a visionone alert triggers a fail-soft GET of its Workbench
    # detail during _step_enrich; the result feeds the persona briefing.
    # Off by default so the parser/adapter can ship dark (zero external calls).
    v1_autofetch_enabled: bool = False
    # Also pull Observed Attack Techniques (broader on-host detection stream).
    # Separate flag — OAT is high-volume and optional context.
    v1_oat_enabled: bool = False
    v1_oat_window_hours: int = 6  # window each side of the alert time
    v1_oat_max_items: int = 20  # cap rows stored/rendered
    v1_oat_risk_floor: str = "medium"  # drop info/low OAT noise (low|medium|high|critical)
    # ── V1 verdict write-back (ADR-0005) — mirror the analyst/auto verdict back to the
    # Workbench alert (status + investigationResult) so V1 stops accruing tenant threat score.
    # Default OFF: this is an OUTBOUND WRITE to the customer's V1 tenant. Fail-soft + gated.
    v1_status_writeback_enabled: bool = False
    # Mirror the analyst verdict back to the Microsoft Defender alert on approve
    # (Graph SecurityAlert.ReadWrite.All). Default OFF: OUTBOUND WRITE, fail-soft + gated.
    defender_status_writeback_enabled: bool = False
    # Multi-tenant credential isolation. When ON, a NAMED customer must have its OWN
    # EDR/XDR credential row — the 'default' row and the V1 env-var key fallbacks are
    # refused, so an unmapped customer fails closed instead of borrowing a shared key.
    # Recommended for multi-customer deployments; leave OFF for a single-tenant box
    # that relies on a global 'default'/env key.
    strict_tenant_creds: bool = False
    # ── V1 Endpoint Activity Data search (read-only hunt tool) ────────────
    # When true, an analyst-triggered hunt re-task (manager chat) gives the
    # Threat Hunter a live read-only endpoint-activity search tool. Automated
    # hunts stay query-building only. Off by default (local-first / gated).
    # Needs the API key's "Agentic SIEM and XDR → XDR Data Explorer" role.
    v1_activity_search_enabled: bool = False
    v1_activity_window_hours: int = 24  # search window each side of the alert time
    v1_activity_max_records: int = 200  # cap records followed across nextLink pages

    # Microsoft Defender read tools for the deep tier (hunt + machine/file/ip
    # detail). Off by default; also respects isoc_enable_llm_tools and requires a
    # microsoft_defender integration row for the customer. Needs the Graph
    # ThreatHunting.Read.All + WindowsDefenderATP Machine/File/Ip.Read.All perms.
    defender_tools_enabled: bool = False

    # ── REMnux ───────────────────────────────────────────────────────────
    remnux_container_name: str = "isoc-remnux-1"
    remnux_default_timeout_seconds: int = 600

    # ── SMTP (customer notifications — Phase-CC5) ───────────────────────
    # All optional. If SMTP_HOST is empty, the "Send to customer" button is
    # disabled and the endpoint returns 503 with a clear "not configured"
    # message. No background jobs, no startup checks — only used at send time.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None  # e.g. "EKSIR SOC <soc@eksir.io>"
    smtp_use_tls: bool = True  # STARTTLS on submission port

    # ── LLM transcript logging ───────────────────────────────────────────
    # When true (default), every LLM call persists its full system + user
    # prompt and the response on the LLMCall row. Used for audit/GRC and
    # debug. Set false on deployments where you can't keep raw prompts.
    log_llm_transcripts: bool = True

    # Autonomy guardrails (3.9): optional path to a git-committed YAML policy
    # (layer between code defaults and DB overrides). Empty = code+DB only.
    isoc_autonomy_policy: str = ""

    # ── Alert correlation (Phase 2a — cluster-of-incidents) ──────────────
    # Off by default. When true, a best-effort `_step_correlate` runs after
    # entity resolution and groups same-tenant incidents that share a STRONG
    # entity within the window into a reversible IncidentCluster.
    correlation_enabled: bool = False  # ENV ISOC_CORRELATION_ENABLED
    correlation_window_hours: int = 24
    # Skip an entity linked to more than this many in-tenant incidents (a
    # high-fan-out shared entity would over-correlate everything together).
    correlation_fanout_cap: int = 50
    # Min shared strong entities required to form a correlation edge.
    correlation_min_shared: int = 1

    # ── Pipeline ─────────────────────────────────────────────────────────
    pipeline_max_enrichment_seconds: int = 180
    pipeline_max_llm_seconds: int = 120

    @property
    def is_dev(self) -> bool:
        return self.log_level.upper() == "DEBUG"

    @property
    def is_production(self) -> bool:
        """True for production-like deployments (prod/staging). Drives the
        fail-closed secret guard and CORS tightening. Anything else (incl. the
        "dev" default and an unrecognised value) is treated as non-production."""
        return self.isoc_env.strip().lower() in {"prod", "production", "staging"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
