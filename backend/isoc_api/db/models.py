"""SQLAlchemy 2.0 models — see docs/DATA-MODEL.md for the rationale."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin
from .enums import (
    AutoCloseSource,
    CaseStatus,
    Confidence,
    CustomerCaseStatus,
    ForensicsKind,
    IngestSource,
    IOCType,
    JobStatus,
    LLMStatus,
    Role,
    Severity,
    TenantTier,
    UserStatus,
    Verdict,
)


# ── Users / Auth ────────────────────────────────────────────────────────
class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[Role] = mapped_column(String(16), nullable=False, default=Role.ANALYST)
    status: Mapped[UserStatus] = mapped_column(
        String(16), nullable=False, default=UserStatus.ACTIVE
    )
    full_name: Mapped[str | None] = mapped_column(String(255))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # MFA (TOTP, Stage 3b) — opt-in per user. `totp_secret` is Fernet-encrypted
    # at rest (via llm.config_store helpers) and only set during enrollment;
    # `mfa_enabled` flips true once the user confirms a code from their app.
    totp_secret: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    # Revocation (Stage 3c): every access token carries `ver`; current_user
    # rejects a token whose `ver` != this. Logout / revoke-sessions bump it,
    # invalidating all outstanding tokens without server-side session storage.
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    # Per-user dashboard layout override (react-grid-layout shape).
    # NULL = use tenant default; tenant default NULL = use built-in default.
    dashboard_layout: Mapped[dict | None] = mapped_column(JSONB)


# ── Tenants (multi-tenancy: HOST → MSSP → CLIENT) ───────────────────────
class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    tier: Mapped[TenantTier] = mapped_column(String(16), nullable=False, default=TenantTier.CLIENT)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    # Optional display label, e.g. "Platinum" / "Gold" — purely cosmetic for now.
    tier_label: Mapped[str | None] = mapped_column(String(32))

    # Customer-notification routing (Phase-CC1). All nullable — only used when
    # the tenant has been configured for customer-facing notifications.
    notification_email: Mapped[str | None] = mapped_column(String(255))
    notification_email_cc: Mapped[str | None] = mapped_column(String(512))
    locale: Mapped[str | None] = mapped_column(String(8))

    # Tenant-default dashboard layout (admin sets). Users may override via
    # users.dashboard_layout; the effective layout is computed at /me/dashboard-layout.
    dashboard_layout: Mapped[dict | None] = mapped_column(JSONB)

    parent: Mapped["Tenant | None"] = relationship(remote_side="Tenant.id", backref="children")


class UserTenantMembership(Base, UUIDMixin, TimestampMixin):
    """A user's role inside a specific tenant. A user can belong to many tenants."""

    __tablename__ = "user_tenant_memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[Role] = mapped_column(String(16), nullable=False, default=Role.ANALYST)

    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant"),)


# ── RBAC (3.10) — fine-grained roles/permissions, enforced on NEW routes only ──
# NB: the ORM model is `RBACRole` (table "roles") to avoid colliding with the
# coarse `Role` enum already imported into this module.
class Permission(Base, UUIDMixin):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    category: Mapped[str | None] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(Text)


class RBACRole(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "roles"

    # NULL tenant_id = global / system role; non-null = tenant-scoped custom role.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
        # SQL treats NULLs as distinct, so the constraint above doesn't dedupe
        # global (tenant_id NULL) roles — this partial index does.
        Index(
            "uq_roles_global_name",
            "name",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


# ── Incidents ───────────────────────────────────────────────────────────
class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    case_number: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
        server_default=text("'INC-' || lpad(nextval('isoc_case_seq')::text, 6, '0')"),
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[CaseStatus] = mapped_column(
        String(32), nullable=False, default=CaseStatus.RECEIVED, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        String(16), nullable=False, default=Severity.MEDIUM, index=True
    )
    verdict: Mapped[Verdict] = mapped_column(
        String(16), nullable=False, default=Verdict.PENDING, index=True
    )
    confidence: Mapped[Confidence | None] = mapped_column(String(16))

    customer: Mapped[str | None] = mapped_column(String(128), index=True)
    # Phase-1 tenancy: tenant_id is the eventual source of truth. The legacy
    # `customer` string column stays for one release as a fallback so the
    # backfill is reversible and old code keeps working.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    rule_name: Mapped[str | None] = mapped_column(Text, index=True)
    source_product: Mapped[str | None] = mapped_column(String(32))

    ingest_source: Mapped[IngestSource] = mapped_column(
        String(16), nullable=False, default=IngestSource.PASTE
    )
    webhook_source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhook_sources.id", ondelete="SET NULL")
    )

    raw_payload: Mapped[dict | None] = mapped_column(JSONB)
    normalized: Mapped[dict | None] = mapped_column(JSONB)
    # MutableDict so in-place mutations (`obj.enrichment["k"] = v`) are tracked.
    # Plain JSONB only flags dirty on assignment — without the wrapper, every
    # pipeline step that did `enrichment["x"] = y` was silently dropped.
    enrichment: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSONB))
    autoclose_match: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSONB))
    short_circuit: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSONB))

    llm_report_markdown: Mapped[str | None] = mapped_column(Text)
    llm_input_tokens: Mapped[int | None] = mapped_column(Integer)
    llm_output_tokens: Mapped[int | None] = mapped_column(Integer)
    llm_model_used: Mapped[str | None] = mapped_column(String(64))

    analyst_notes: Mapped[str | None] = mapped_column(Text)
    # The analyst's short "why" captured at verdict time. Indexed to Qdrant as
    # the case's verdict_reason so future identical alerts retrieve the analyst's
    # actual rationale (not the LLM report). Free-form analyst_notes stays separate.
    verdict_reason: Mapped[str | None] = mapped_column(Text)
    # Free-form note the analyst leaves for the NEXT shift (shown on the Shift
    # Handoff board). Overrides the auto-generated handoff note when set.
    handoff_note: Mapped[str | None] = mapped_column(Text)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Investigation Queue (3.6) — ownership + scheduling ONLY. Orthogonal to the
    # analyst gate: claim/release/snooze never touch verdict/status/closed_at.
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    snoozed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    # L1 → L2 escalation. Orthogonal to status/gate (like the queue): escalated
    # = escalated_at IS NOT NULL. Set by POST /incidents/{id}/escalate. New
    # columns on an EXISTING table → added by db/escalation_backfill.py (+ Alembic
    # 0017), NOT create_all.
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    escalated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    escalation_note: Mapped[str | None] = mapped_column(Text)

    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # F1 — gate attribution: who signed off the verdict and when. Set ONLY at the
    # human gate (`cases._commit_verdict`); NULL for auto-closed/short-circuit
    # cases. Feeds Team Analytics, SLA Tracking and the MSSP/Cost "who/when".
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    signed_off_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    qdrant_alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)

    # Soft-delete. NULL = visible. Set by POST /incidents/{id}/archive.
    # Hard delete (DELETE /incidents/{id}) removes the row entirely.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    timeline: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOCRecord"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    forensics_jobs: Mapped[list["ForensicsJob"]] = relationship(back_populates="incident")
    llm_calls: Mapped[list["LLMCall"]] = relationship(back_populates="incident")

    # Fused confidence/threat scores live in enrichment["scores"] (written by the
    # pipeline, no column). Surface them as read-only attributes so IncidentSummary
    # (from_attributes) can render them on list rows without shipping the whole blob.
    @property
    def confidence_score(self) -> int | None:
        return ((self.enrichment or {}).get("scores") or {}).get("confidence")

    @property
    def threat_score(self) -> int | None:
        return ((self.enrichment or {}).get("scores") or {}).get("threat")

    __table_args__ = (
        Index("ix_incidents_normalized_gin", "normalized", postgresql_using="gin"),
        Index("ix_incidents_enrichment_gin", "enrichment", postgresql_using="gin"),
        Index("ix_incidents_created_at", "created_at", postgresql_ops={"created_at": "DESC"}),
    )


# ── SLA lifecycle ledger (F1) ───────────────────────────────────────────
class SLAEvent(Base, UUIDMixin):
    """Append-only lifecycle ledger — one row per state transition of a case.

    `kind` ∈ detected / acknowledged / resolved / closed. Emitted best-effort at
    the single commit point (`cases._commit_verdict`) and the auto-close/short-
    circuit terminal (`orchestrator.run_pipeline`). The Incident row stays the
    system of record; this exists so SLA Tracking / Team Analytics / MSSP rollups
    have an honest, time-stamped, attributable event stream to read.
    """

    __tablename__ = "sla_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # Analyst who caused the transition; NULL for system/auto transitions.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    meta: Mapped[dict | None] = mapped_column(JSONB)


class SLATarget(Base, TimestampMixin):
    """Admin-editable per-severity SLA targets (minutes), 24/7 wall-clock.

    `target_minutes` = time-to-resolve; `response_target_minutes` = time-to-first-
    response (nullable → falls back to `DEFAULT_RESPONSE_MINUTES`). Defaults live in
    `pipeline/sla.py`; a row here overrides one severity. One row per severity
    (severity is the PK).
    """

    __tablename__ = "sla_targets"

    severity: Mapped[str] = mapped_column(String(16), primary_key=True)
    target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    # Time-to-first-response target; NULL → DEFAULT_RESPONSE_MINUTES for that severity.
    response_target_minutes: Mapped[int | None] = mapped_column(Integer)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class AutonomyThreshold(Base, UUIDMixin, TimestampMixin):
    """Autonomy guardrails (3.9) — per-action-kind confidence ladder. Code
    defaults in `pipeline/guardrails.py`; a row here overrides one kind globally
    (`tenant_id` NULL) or per-tenant. v1 is recommendation-only — these thresholds
    decide the auto/review/escalate BADGE, never an execution. Effect kinds stay
    clamped to escalate in code regardless of these values (defense in depth).
    """

    __tablename__ = "autonomy_threshold"

    action_kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    blast_radius: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    auto_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.01)
    review_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    escalation_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="db")
    reason: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("action_kind", "tenant_id", name="uq_autonomy_kind_tenant"),
        CheckConstraint(
            "escalation_confidence <= review_confidence AND review_confidence <= auto_confidence",
            name="ck_autonomy_order",
        ),
    )


class SavedHunt(Base, UUIDMixin, TimestampMixin):
    """Hunt (3.13) — a saved natural-language threat hunt. v1 is TRANSLATE-ONLY:
    we persist the analyst's English question + its translated query envelope
    ({s1ql, kql, sigma, explanation}). Execution against SentinelOne is a deferred
    fast-follow — nothing here runs a query or writes a verdict."""

    __tablename__ = "saved_hunts"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    nl_query: Mapped[str] = mapped_column(Text, nullable=False)
    # {s1ql, kql, sigma, explanation} snapshot taken at save/translate time.
    translated: Mapped[dict | None] = mapped_column(JSONB)
    language: Mapped[str] = mapped_column(String(16), nullable=False, default="s1ql")
    time_range: Mapped[str | None] = mapped_column(String(32))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EASMAsset(Base, UUIDMixin, TimestampMixin):
    """EASM (Phase 3) — an external asset the analyst is watching (domain / IP /
    URL / subdomain). On-demand recon (DNS, SPF/DMARC posture, TLS expiry, WHOIS)
    is read-only and stored in `last_result`; scanning never changes external
    state. Starts empty — no seeder."""

    __tablename__ = "easm_assets"

    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(16), nullable=False, default="domain")
    tags: Mapped[list | None] = mapped_column(JSONB)
    notes: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_result: Mapped[dict | None] = mapped_column(JSONB)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


# ── Timeline ────────────────────────────────────────────────────────────
class TimelineEvent(Base, UUIDMixin):
    __tablename__ = "timeline_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict | None] = mapped_column(JSONB)
    display: Mapped[str | None] = mapped_column(Text)
    # Pipeline-visibility metadata (live-log / stage-checklist UI):
    #   level — running | ok | warn | error | info  (drives status colour)
    #   step  — canonical stage key (groups detail events under a stage row)
    #   duration_ms — wall-clock for a completed stage
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    step: Mapped[str | None] = mapped_column(String(32), index=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    incident: Mapped[Incident] = relationship(back_populates="timeline")


# ── IOCs ────────────────────────────────────────────────────────────────
class IOCRecord(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ioc_records"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ioc_type: Mapped[IOCType] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tenant: Mapped[str | None] = mapped_column(String(128), index=True)

    incident: Mapped[Incident] = relationship(back_populates="iocs")
    enrichments: Mapped[list["IOCEnrichment"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("incident_id", "ioc_type", "value", name="uq_ioc_per_case"),)


class IOCEnrichment(Base, UUIDMixin):
    __tablename__ = "ioc_enrichments"

    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ioc_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    verdict: Mapped[str | None] = mapped_column(String(32))
    score: Mapped[int | None] = mapped_column(Integer)
    raw: Mapped[dict | None] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    ioc: Mapped[IOCRecord] = relationship(back_populates="enrichments")


# ── Forensics jobs ──────────────────────────────────────────────────────
class ForensicsJob(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "forensics_jobs"

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[ForensicsKind] = mapped_column(String(16), nullable=False, index=True)
    ioc_or_file: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        String(16), nullable=False, default=JobStatus.QUEUED, index=True
    )
    result: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    arq_job_id: Mapped[str | None] = mapped_column(String(64), index=True)

    incident: Mapped[Incident | None] = relationship(back_populates="forensics_jobs")


# ── Webhook sources ─────────────────────────────────────────────────────
class WebhookSource(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "webhook_sources"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    hmac_secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ip_allowlist: Mapped[list[str] | None] = mapped_column(ARRAY(INET))
    customer_default: Mapped[str | None] = mapped_column(String(128))
    source_product: Mapped[str | None] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ── Pull ingestion sources (scheduled API poll → RECEIVED incident) ──────
class IngestSourceConfig(Base, UUIDMixin, TimestampMixin):
    """One pull source: which console to poll, how often, and its cursor.

    `(provider, identifier)` is unique. `provider` is a connectors-catalog key
    (e.g. `vision_one`); `identifier` is the Integration row the credentials
    live in (`integration_store`); `customer` is the tenant that created
    incidents are attributed to. The `pull_ingest` cron reads enabled rows,
    polls each when due, and never auto-disables one on error — it just backs
    off and records `consecutive_errors` / `last_error`.
    """

    __tablename__ = "ingest_sources"

    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    identifier: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    customer: Mapped[str | None] = mapped_column(String(128), index=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    min_severity: Mapped[str | None] = mapped_column(String(16))
    max_items: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # Phase 2 seam: config-driven field mapping for sources without a bespoke parser.
    field_map: Mapped[dict | None] = mapped_column(JSONB)

    # Persisted per-source watermark (e.g. {"last_poll_at": "<iso>"}). Empty on
    # cold start — adapters treat empty as "from now" and do NOT backfill.
    cursor: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    consecutive_errors: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Observability: last poll's wall-clock (ms) + alerts ingested, and a running total.
    last_poll_ms: Mapped[int | None] = mapped_column(Integer)
    last_poll_count: Mapped[int | None] = mapped_column(Integer)
    total_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # ADR-0006 P1a schema-drift sentinel: SHA-256 of the union of top-level field names the
    # source last emitted. A change between polls means a vendor renamed/dropped a field, which
    # would silently rot a field_map mapping — the cron logs a warning when it flips.
    field_fingerprint: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("provider", "identifier", name="uq_ingest_source_provider_identifier"),
    )


class ImportJob(Base, UUIDMixin, TimestampMixin):
    """One batch / historical import run.

    A file (uploaded, or a path under the shared /workspace volume) is streamed
    record-by-record into RECEIVED incidents on the exact same pipeline a webhook
    or pulled alert rides — so parse → field-map → normalize → enrich → human gate
    all run downstream unchanged. The `batch_import` ARQ job updates the progress
    counters here as it streams; the Sources → Import tab polls this row. Admin-only,
    sitting beside the pull sources it complements.
    """

    __tablename__ = "import_jobs"

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    customer: Mapped[str | None] = mapped_column(String(128), index=True)

    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    # Path under the shared /workspace volume the worker streams from.
    path: Mapped[str] = mapped_column(Text, nullable=False)
    fmt: Mapped[str] = mapped_column(String(16), default="auto", nullable=False)
    source_hint: Mapped[str | None] = mapped_column(String(64))
    field_map: Mapped[dict | None] = mapped_column(JSONB)
    # Content-hash dedup so re-importing the same file is idempotent.
    dedupe: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    status: Mapped[str] = mapped_column(
        String(16), default="queued", nullable=False, index=True
    )  # queued | running | completed | failed
    total: Mapped[int | None] = mapped_column(Integer)
    processed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)


# ── Auto-close rules (UI-editable mirror of YAML) ───────────────────────
class AutoCloseRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "auto_close_rules"

    rule_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    customer: Mapped[str | None] = mapped_column(String(128), index=True)
    match: Mapped[dict] = mapped_column(JSONB, nullable=False)
    verdict: Mapped[Verdict] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    source: Mapped[AutoCloseSource] = mapped_column(
        String(8), default=AutoCloseSource.UI, nullable=False
    )


# ── LLM call accounting ─────────────────────────────────────────────────
class LLMCall(Base, UUIDMixin):
    __tablename__ = "llm_calls"

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(32))
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[LLMStatus] = mapped_column(String(16), nullable=False)
    prompt_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Full transcripts (nullable for legacy rows and for deployments that
    # opt out via ISOC_LOG_LLM_TRANSCRIPTS=false). Sized as TEXT — Postgres
    # has no length cap and these stay tiny in practice (briefings ~10KB).
    system_prompt: Mapped[str | None] = mapped_column(Text)
    user_prompt: Mapped[str | None] = mapped_column(Text)
    response_text: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)

    # Discriminator so the UI can label calls: "analyst_fast", "analyst_deep",
    # "customer_brief", etc. Free-form by design — adding a call site doesn't
    # require a migration.
    purpose: Mapped[str | None] = mapped_column(String(32), index=True)

    incident: Mapped[Incident | None] = relationship(back_populates="llm_calls")


# ── Audit log ───────────────────────────────────────────────────────────
class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_log"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    # Phase-5: tenant the action affected. Null = platform-level (auth, global
    # admin ops, ad-hoc V1 ops). Used both for filtering and audit scope.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    diff: Mapped[dict | None] = mapped_column(JSONB)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


# ── Customer notification cases ─────────────────────────────────────────
class CustomerCase(Base, UUIDMixin, TimestampMixin):
    """A customer-facing notification derived from one or more incidents.

    Separate from the analyst-facing `Incident` row: different audience,
    different prompt, different lifecycle. The legacy `routes/cases.py`
    actually serves incidents (kept for backward compat); these "customer
    cases" are served from a new route file.
    """

    __tablename__ = "customer_cases"

    case_number: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
        server_default=text("'CASE-' || lpad(nextval('eksir_customer_case_seq')::text, 6, '0')"),
    )
    # Canonical source incident (the one the analyst promoted from). The
    # case_incidents join table holds the full set when bundling.
    source_incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )

    status: Mapped[CustomerCaseStatus] = mapped_column(
        String(16),
        nullable=False,
        default=CustomerCaseStatus.DRAFT,
        index=True,
    )
    locale: Mapped[str] = mapped_column(String(8), nullable=False, default="en")

    # Editable customer-facing content (Phase-CC1: analyst types; Phase-CC2:
    # LLM pre-fills). Free-form text fields; the HTML template (Phase-CC3)
    # decides how each is rendered.
    title: Mapped[str | None] = mapped_column(Text)
    incident_analysis: Mapped[str | None] = mapped_column(Text)
    attack_type_label: Mapped[str | None] = mapped_column(String(255))
    critical_impact_summary: Mapped[str | None] = mapped_column(Text)
    recommended_actions: Mapped[list | None] = mapped_column(JSONB)  # list[str]
    # What the SOC already DID for the customer (block/isolate/collect), grounded
    # in the incident's executed response actions (enrichment.v1_actions). list[str].
    actions_taken: Mapped[list | None] = mapped_column(JSONB)
    threat_intel_summary: Mapped[str | None] = mapped_column(Text)
    # New 1-liners that sit BELOW the structured TI table. The table itself
    # is rendered from incident.enrichment (factual data); these two are the
    # narrative bits the LLM adds — who's behind this, and any prior history.
    attribution: Mapped[str | None] = mapped_column(String(255))
    prior_cases_note: Mapped[str | None] = mapped_column(String(255))

    # Analyst HTML override (customer-notification editor). When
    # body_source == 'edited', preview + send use edited_html verbatim
    # (sanitized on send) instead of rendering from the fields above.
    edited_html: Mapped[str | None] = mapped_column(Text)
    body_source: Mapped[str] = mapped_column(String(16), nullable=False, default="generated")

    # Send tracking — only populated once status=sent.
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    # Snapshot of the addresses + subject at send time (immutable audit trail).
    sent_recipients_to: Mapped[str | None] = mapped_column(String(512))
    sent_recipients_cc: Mapped[str | None] = mapped_column(String(512))
    sent_subject: Mapped[str | None] = mapped_column(Text)


class CustomerCaseIncident(Base, UUIDMixin):
    """M2M join — a case can bundle multiple related incidents."""

    __tablename__ = "customer_case_incidents"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    attached_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    __table_args__ = (UniqueConstraint("case_id", "incident_id", name="uq_case_incident"),)


# ── Entities (OCSF resolution) ──────────────────────────────────────────
class Entity(Base, UUIDMixin, TimestampMixin):
    """A resolved OCSF entity (device / user / network_endpoint / file / observable).

    Per-customer for most kinds; GLOBAL (customer NULL) for file + file-hash
    observables. Deduped on (customer, entity_type, canonical_key) with a partial
    unique index covering the NULL-customer (global) rows the composite UNIQUE cannot.
    """

    __tablename__ = "entities"

    # NULL customer = global entity (file / file-hash); non-null = customer-scoped.
    customer: Mapped[str | None] = mapped_column(String(128), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    # Plain JSONB (whole-value writes) — not MutableDict.
    attributes: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    risk_score: Mapped[float | None] = mapped_column(Float)

    incident_links: Mapped[list[IncidentEntity]] = relationship(
        back_populates="entity", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "customer", "entity_type", "canonical_key", name="uq_entity_customer_type_key"
        ),
        # SQL treats NULLs as distinct, so the constraint above doesn't dedupe
        # global (customer NULL) entities — this partial index does.
        Index(
            "uq_entity_global_type_key",
            "entity_type",
            "canonical_key",
            unique=True,
            postgresql_where=text("customer IS NULL"),
        ),
    )


class IncidentEntity(Base, UUIDMixin):
    """M2M link — an incident references an entity in a given role."""

    __tablename__ = "incident_entities"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    entity: Mapped[Entity] = relationship(back_populates="incident_links")

    __table_args__ = (
        UniqueConstraint("incident_id", "entity_id", "role", name="uq_incident_entity_role"),
    )


# ── Alert correlation (Phase 2a — cluster-of-incidents) ─────────────────
# A reversible layer over the 1-alert-1-incident model: same-tenant incidents
# sharing a STRONG entity within a window are grouped into an IncidentCluster.
# Written best-effort by `pipeline/_step_correlate` (adapters/cluster_store).
class IncidentCluster(Base, UUIDMixin, TimestampMixin):
    """A group of related same-tenant incidents (share a strong entity)."""

    __tablename__ = "incident_clusters"

    # NULL tenant_id = global/unattributed cluster; non-null = tenant-scoped.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    # Oldest member (the cluster's anchor). SET NULL (not RESTRICT) so hard-
    # deleting/purging an incident can never wedge the cluster row.
    seed_incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    cluster_key: Mapped[str | None] = mapped_column(String(64), index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'open'")
    )  # open|closed
    member_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    members: Mapped[list["IncidentClusterMember"]] = relationship(
        back_populates="cluster", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # tenant_id + cluster_key indexes already come from the column-level
        # index=True above (SQLAlchemy auto-names them ix_incident_clusters_<col>,
        # matching the 0013 migration). Re-declaring them here would double-emit
        # CREATE INDEX and crash Base.metadata.create_all on a fresh DB.
        Index("ix_incident_clusters_created_at", "created_at"),
    )


class IncidentClusterMember(Base, UUIDMixin):
    """M2M-ish membership — one incident belongs to at most one cluster."""

    __tablename__ = "incident_cluster_members"

    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incident_clusters.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The strong entity that pulled this incident in (best-effort; may be NULL).
    shared_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL")
    )
    method: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'auto'")
    )  # auto|manual
    attached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    attached_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    cluster: Mapped[IncidentCluster] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("cluster_id", "incident_id", name="uq_cluster_incident"),
        # One incident -> at most one cluster (the whole point of the layer).
        UniqueConstraint("incident_id", name="uq_cluster_member_incident"),
    )


# ── Threat intelligence: feeds + IOCs ───────────────────────────────────
# These tables are *global* (no tenant_id): threat intel is universal, and
# tenant scoping would just duplicate the same IOCs N times. Access is gated
# at the route layer (admin-only for feed CRUD + manual sync; any auth user
# can read the IOC list).
class ThreatFeed(Base, UUIDMixin, TimestampMixin):
    """A subscribed threat-intel feed (typically a SOCRadar feed-list URL)."""

    __tablename__ = "threat_feeds"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # "auto" lets the sync service pick per-line; an explicit hint short-circuits
    # detection for feeds we know are single-type.
    kind_hint: Mapped[str] = mapped_column(String(16), nullable=False, default="auto")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str | None] = mapped_column(String(32))  # ok / error
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    last_sync_count: Mapped[int | None] = mapped_column(Integer)  # rows in feed
    last_sync_new_count: Mapped[int | None] = mapped_column(Integer)  # net-new this run

    # Optional per-feed parsing config. NULL = line-based parsing (one IOC per
    # line, current default). Set to {"format": "csv", "value_column": "...",
    # "type_column": "...", "type_mapping": {...}, "skip_comment_lines": true}
    # for CSV feeds like ThreatFox / SSLBL. See sync.py for the full schema.
    parser_config: Mapped[dict | None] = mapped_column(JSONB)


class ThreatIOC(Base, UUIDMixin):
    """One indicator. (value, ioc_type) is unique — the same string CAN
    legitimately appear as both a domain and a URL, so the type is part of
    the key. `sources` is a JSONB array of ThreatFeed UUIDs for provenance."""

    __tablename__ = "threat_iocs"

    value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)  # ip | domain | url

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    # JSONB array of feed UUIDs that have ever surfaced this IOC.
    sources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("value", "ioc_type", name="uq_threat_ioc_value_type"),
        # Lookups during enrichment hit this index heavily.
        Index("ix_threat_iocs_value", "value"),
        Index("ix_threat_iocs_type", "ioc_type"),
    )


# ── Exclusions (analyst-curated allowlist) ──────────────────────────────
# Global table. An exclusion suppresses an IOC from triage / TI match — used
# for known-good internal infrastructure, public DNS resolvers, vendor URLs,
# etc. The LLM still sees what was excluded (and why) so it knows the analyst
# made a judgement call.
class Exclusion(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "exclusions"

    # ioc_type ∈ {ip, cidr, domain, hash}. Match semantics differ per type:
    #   ip      — exact IP string match
    #   cidr    — CIDR network contains the alert's IP
    #   domain  — exact match OR alert is subdomain (endswith ".value")
    #   hash    — exact hash string (any algo)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Optional per-customer scope. NULL = global (applies to every tenant).
    # A scoped rule only suppresses IOCs on incidents for the same customer —
    # so one tenant's benign-internal IP never silences another tenant's.
    customer: Mapped[str | None] = mapped_column(String(128), index=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    __table_args__ = (
        UniqueConstraint("value", "ioc_type", name="uq_exclusion_value_type"),
        Index("ix_exclusions_value", "value"),
        Index("ix_exclusions_type", "ioc_type"),
    )


class ExclusionSuggestion(Base, UUIDMixin, TimestampMixin):
    """Auto-tuning (feature F8): candidate exclusions learned from repeated
    analyst FP/Benign verdicts on the SAME IOC for the SAME customer.

    NEVER auto-applied — a suggestion is surfaced in the admin review queue and
    an analyst one-click approves it into a real (scoped) Exclusion, or dismisses
    it. Guardrails at the verdict hook prevent suggesting an IOC that ever
    appeared in a TP or that threat intel flags malicious.
    """

    __tablename__ = "exclusion_suggestions"

    value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)  # ip/cidr/domain/hash
    customer: Mapped[str | None] = mapped_column(String(128), index=True)
    fp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Distinct rule_names + incident ids that contributed (so we can require
    # corroboration across >1 rule and show evidence in the review queue).
    seen_rules: Mapped[list | None] = mapped_column(JSONB)
    seen_incidents: Mapped[list | None] = mapped_column(JSONB)
    last_rule_name: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 0–100 heuristic; higher = stronger case for suppression.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # pending | approved | dismissed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)

    __table_args__ = (
        UniqueConstraint("value", "ioc_type", "customer", name="uq_suggestion_value_type_customer"),
        Index("ix_suggestions_status", "status"),
    )


# ── Platform-wide LLM configuration (singleton — at most one row) ────────────
class LLMConfig(Base, TimestampMixin):
    """Admin-managed LLM endpoint, key, model and generation parameters.

    Always stored with id=1.  Routes upsert via on_conflict_do_update so there
    is never more than one row.  The API key is Fernet-encrypted at rest;
    the GET endpoint returns only the masked form (sk-***…last4).
    """

    __tablename__ = "llm_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    endpoint_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str] = mapped_column(String(200), nullable=False)
    temperature: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=0.2)
    max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    updated_by: Mapped["User | None"] = relationship("User", foreign_keys=[updated_by_id])


class TenantLLMCredential(Base, TimestampMixin):
    """BYOK — a per-tenant LLM provider override (Settings → Deployment & AI).

    One row per tenant. Layers ABOVE the global `llm_config`: at inference the
    resolver prefers an *enabled* tenant credential, else the admin global config,
    else env defaults. The API key is Fernet-encrypted at rest and is **write-only**
    — GET exposes only `has_api_key`, never the key (nor a masked form to non-admins).
    """

    __tablename__ = "tenant_llm_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500))
    model: Mapped[str | None] = mapped_column(String(200))
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class Integration(Base, UUIDMixin, TimestampMixin):
    """Admin-managed per-tenant EDR/XDR API credentials (ADR-0003 / ADR-0005).

    Keyed by (provider, identifier):
      - provider:   "vision_one" | "sentinelone" (extensible)
      - identifier: the customer name for vision_one, or the console host for
        sentinelone. provider='vision_one' + identifier='default' is the global
        fallback used when a customer has no specific row.

    The API key is Fernet-encrypted at rest (reusing llm.config_store helpers);
    the list endpoint returns only the masked form. Admin-only (routes/admin.py).
    """

    __tablename__ = "integrations"
    __table_args__ = (
        UniqueConstraint("provider", "identifier", name="uq_integration_provider_identifier"),
    )

    provider: Mapped[str] = mapped_column(String(32), index=True)
    identifier: Mapped[str] = mapped_column(String(128))
    label: Mapped[str | None] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # vision_one: region (us|eu|jp|au|sg|in|mea). sentinelone: null (console host carries it).
    region: Mapped[str | None] = mapped_column(String(16))
    # sentinelone console host (e.g. euce1-105.sentinelone.net). vision_one: null.
    base_url: Mapped[str | None] = mapped_column(String(256))
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    # OAuth client credentials for providers that don't use a single API token
    # (crowdstrike: client_id+client_secret; microsoft_defender: + oauth_tenant_id
    # = the Azure AD tenant). client_secret is Fernet-encrypted like api_key.
    client_id: Mapped[str | None] = mapped_column(String(256))
    client_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    oauth_tenant_id: Mapped[str | None] = mapped_column(String(128))
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    updated_by: Mapped["User | None"] = relationship("User", foreign_keys=[updated_by_id])


# ── Branded reports (Feature 7) ─────────────────────────────────────────
class TenantBranding(Base, TimestampMixin):
    """Per-tenant report branding (B2): a logo PNG + accent colour, layered into
    the report header at render time. One row per tenant (tenant_id is the PK).
    The SOC's own theme is baked into the templates; this only overlays the
    customer's mark. New table → auto-created on boot (no backfill).
    """

    __tablename__ = "tenant_branding"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    # Raw image bytes + mime; embedded as a data-URI in the rendered HTML so the
    # report is self-contained (no external asset fetch — matches the email
    # precedent and keeps the PDF renderer offline).
    logo_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    logo_mime: Mapped[str | None] = mapped_column(String(64))
    # Hex accent (#RRGGBB) overlaid on the SOC theme header; NULL → theme default.
    accent_color: Mapped[str | None] = mapped_column(String(9))
    # Optional display-name override for the header (else Tenant.name).
    display_name: Mapped[str | None] = mapped_column(String(128))
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class ReportSchedule(Base, UUIDMixin, TimestampMixin):
    """A recurring report to generate (Feature 7). The cron scans due rows
    (`next_run_at <= now`), generates a DRAFT GeneratedReport, then bumps
    next_run_at. Generation is deterministic + read-only; it never sends.
    """

    __tablename__ = "report_schedules"

    # NULL tenant = an all-scope (MSSP) report; non-null = a single customer.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    template_key: Mapped[str] = mapped_column(String(64), nullable=False)
    # "monthly" | "weekly" — the pure schedule_due() advances next_run_at.
    cadence: Mapped[str] = mapped_column(String(16), default="monthly", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    # Forward-compat opt-in; NOT wired — the cron always generates to draft and
    # delivery stays analyst-gated (honours the Approve-gate invariant).
    auto_send: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class GeneratedReport(Base, UUIDMixin, TimestampMixin):
    """A rendered report artifact (Feature 7) — the point-in-time HTML snapshot
    an analyst reviews, downloads (PDF rendered on the fly from this HTML), and
    explicitly sends. status: draft → sent (or failed). schedule_id NULL = an
    on-demand generation; non-null = produced by the cron.
    """

    __tablename__ = "generated_reports"

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("report_schedules.id", ondelete="SET NULL"), index=True
    )
    template_key: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    # The report window + the params used to build it (year/month/customer/window),
    # kept so the row is self-describing.
    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    params: Mapped[dict | None] = mapped_column(JSONB)
    # The rendered HTML — the canonical reviewed artifact. PDF is derived from it.
    html: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(16), default="draft", nullable=False, index=True
    )  # draft | sent | failed
    error: Mapped[str | None] = mapped_column(Text)
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    sent_to: Mapped[str | None] = mapped_column(String(512))


# ── Notifications (B1) + case collaboration (Feature 8) ─────────────────
class Notification(Base, UUIDMixin, TimestampMixin):
    """In-app notification for one recipient (B1 substrate). Kept generic so
    other producers (e.g. SLA breach alerting) can reuse it; Feature 8 emits
    'mention'/'comment' notifications for customer-case collaboration. New table
    → auto-created on boot (no backfill).
    """

    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # mention | comment | ...
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    # In-app deep link, e.g. "/cases/<id>" — resolved client-side.
    link: Mapped[str | None] = mapped_column(String(512))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class CaseComment(Base, UUIDMixin, TimestampMixin):
    """Threaded comment on a customer case (Feature 8). Append-only child of the
    case (CASCADE), mirroring TimelineEvent. `mentions` is the resolved list of
    mentioned user-id strings (which also drives the notifications on create).
    """

    __tablename__ = "case_comments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    mentions: Mapped[list | None] = mapped_column(JSONB)  # list[str] of user ids


class CaseWatcher(Base, UUIDMixin, TimestampMixin):
    """A user watching a customer case — receives a notification on each new
    comment (Feature 8). Mirrors the CustomerCaseIncident join shape.
    """

    __tablename__ = "case_watchers"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    __table_args__ = (UniqueConstraint("case_id", "user_id", name="uq_case_watcher"),)


class IncidentComment(Base, UUIDMixin, TimestampMixin):
    """Threaded comment on an incident (Feature 8, incident mirror of CaseComment).
    Append-only child of the incident (CASCADE). `mentions` is the resolved list of
    mentioned user-id strings, which also drives the notifications on create.
    New table → auto-created on boot (no backfill).
    """

    __tablename__ = "incident_comments"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    mentions: Mapped[list | None] = mapped_column(JSONB)  # list[str] of user ids


class IncidentWatcher(Base, UUIDMixin, TimestampMixin):
    """A user watching an incident: receives a notification on each new comment
    (Feature 8, incident mirror of CaseWatcher). New table, auto-created on boot.
    """

    __tablename__ = "incident_watchers"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    __table_args__ = (UniqueConstraint("incident_id", "user_id", name="uq_incident_watcher"),)
