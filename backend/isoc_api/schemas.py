"""Pydantic request/response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field

from .db.enums import (
    CaseStatus,
    Confidence,
    ForensicsKind,
    IngestSource,
    IOCType,
    JobStatus,
    Role,
    Severity,
    UserStatus,
    Verdict,
)


# ── Auth ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    user: "UserOut"


class LoginResult(BaseModel):
    """`/auth/login` result. Either a full session (token + user) OR, when the
    account has MFA enabled, an `mfa_required` challenge to be completed at
    `/auth/login/mfa`. Backward compatible: a non-MFA login still returns
    `token` + `user`, with the mfa fields null."""

    mfa_required: bool = False
    mfa_token: str | None = None  # short-lived challenge token; present iff mfa_required
    token: str | None = None  # full access token; present iff not mfa_required
    user: "UserOut | None" = None


class MfaLoginRequest(BaseModel):
    """Second step of an MFA login: the challenge token + the 6-digit code."""

    mfa_token: str
    code: str


class MfaCodeRequest(BaseModel):
    """A bare TOTP code — used to activate or disable MFA on the current user."""

    code: str


class MfaEnrollResponse(BaseModel):
    """Enrollment payload shown once. `secret` is for manual entry; `otpauth_uri`
    encodes the same secret; `qr_data_uri` is a scannable inline-SVG QR of it."""

    secret: str
    otpauth_uri: str
    qr_data_uri: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: EmailStr
    role: Role
    status: UserStatus
    full_name: str | None = None
    last_login_at: datetime | None = None
    mfa_enabled: bool = False

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    # Optional: when omitted, the server generates a temporary password, emails
    # it to the new user, and returns it once in UserCreateResult.temp_password.
    password: str | None = Field(default=None, min_length=10)
    role: Role = Role.ANALYST
    full_name: str | None = None


class UserCreateResult(UserOut):
    """UserOut plus the one-time temporary password, populated only when the
    server generated it (password omitted at create time). Shown once so the
    admin can relay it if email delivery is not configured."""

    temp_password: str | None = None


class UserUpdate(BaseModel):
    """Admin edit of a user. Every field optional; only provided ones change."""

    role: Role | None = None
    status: UserStatus | None = None
    full_name: str | None = None


class AdminResetPasswordResult(BaseModel):
    """Returned by the admin password-reset endpoint. The temp password is shown
    once (and emailed to the user); it is never stored in the clear."""

    temp_password: str


class PasswordChange(BaseModel):
    """Self-service password change: prove the current password, set a new one."""

    current_password: str
    new_password: str = Field(min_length=10)


# ── Alerts / Ingest ─────────────────────────────────────────────────────
class PasteIngestRequest(BaseModel):
    raw_text: str = Field(min_length=10)
    customer: str | None = None
    source_hint: str | None = None  # 'qradar' / 'wazuh' / …
    severity: Severity | None = None


class IngestResponse(BaseModel):
    incident_id: uuid.UUID
    case_number: str
    status: CaseStatus


# ── Incidents ───────────────────────────────────────────────────────────
class IncidentSummary(BaseModel):
    id: uuid.UUID
    case_number: str
    title: str
    status: CaseStatus
    severity: Severity
    verdict: Verdict
    confidence: Confidence | None = None
    # Fused scores (0-100); sourced from enrichment["scores"] via Incident props.
    confidence_score: int | None = None
    threat_score: int | None = None
    # Correlation cluster size — member_count of the incident's cluster, or None
    # when it isn't clustered. Attached by the list route, not a stored column.
    cluster_size: int | None = None
    customer: str | None = None
    rule_name: str | None = None
    source_product: str | None = None
    ingest_source: IngestSource
    assignee_id: uuid.UUID | None = None
    # Assignee display name (full_name or email); attached by the list route.
    assignee_name: str | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None

    model_config = {"from_attributes": True}


class IncidentDetail(IncidentSummary):
    normalized: dict[str, Any] | None = None
    enrichment: dict[str, Any] | None = None
    autoclose_match: dict[str, Any] | None = None
    short_circuit: dict[str, Any] | None = None
    llm_report_markdown: str | None = None
    llm_input_tokens: int | None = None
    llm_output_tokens: int | None = None
    llm_model_used: str | None = None
    analyst_notes: str | None = None
    verdict_reason: str | None = None
    handoff_note: str | None = None
    qdrant_alert_id: uuid.UUID | None = None
    # Response-SLA anchor: when an analyst first took ownership (claim/assign).
    claimed_at: datetime | None = None


class IncidentPatch(BaseModel):
    title: str | None = None
    customer: str | None = None
    rule_name: str | None = None
    source_product: str | None = None
    verdict: Verdict | None = None
    confidence: Confidence | None = None
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    analyst_notes: str | None = None
    verdict_reason: str | None = None
    handoff_note: str | None = None
    status: CaseStatus | None = None


class TimelineEventOut(BaseModel):
    id: uuid.UUID
    ts: datetime
    actor: str
    event_type: str
    display: str | None = None
    payload: dict[str, Any] | None = None
    level: str = "info"
    step: str | None = None
    duration_ms: int | None = None

    model_config = {"from_attributes": True}


class IOCOut(BaseModel):
    id: uuid.UUID
    ioc_type: IOCType
    value: str
    excluded: bool
    tenant: str | None = None

    model_config = {"from_attributes": True}


# ── Entities (OCSF resolution) ──────────────────────────────────────────
class EntitySummary(BaseModel):
    id: uuid.UUID
    customer: str | None = None
    entity_type: str
    canonical_key: str
    display_name: str
    attributes: dict[str, Any] | None = None
    risk_score: float | None = None
    first_seen: datetime
    last_seen: datetime
    # Correlated count of linked incidents (in-scope), attached by the route.
    incident_count: int = 0

    model_config = {"from_attributes": True}


class EntityIncidentLink(BaseModel):
    """One incident an entity is linked to, in a given role. Confidence/threat
    are read from the Incident's read-only props (enrichment['scores'])."""

    role: str
    incident_id: uuid.UUID
    case_number: str
    title: str
    status: CaseStatus
    severity: Severity
    verdict: Verdict
    customer: str | None = None
    created_at: datetime
    closed_at: datetime | None = None
    confidence_score: int | None = None
    threat_score: int | None = None

    model_config = {"from_attributes": True}


class EntityDetail(EntitySummary):
    incidents: list[EntityIncidentLink] = []


# ── Incident clusters (Phase 2a correlation) ────────────────────────────
class ClusterMember(BaseModel):
    """One incident in a cluster. Confidence/threat are read from the Incident's
    read-only props (enrichment['scores']); is_seed / shared_entity are attached
    by the route."""

    incident_id: uuid.UUID
    case_number: str
    title: str
    severity: Severity
    status: CaseStatus
    verdict: Verdict
    created_at: datetime
    confidence_score: int | None = None
    threat_score: int | None = None
    is_seed: bool = False
    shared_entity: str | None = None

    model_config = {"from_attributes": True}


class ClusterSummary(BaseModel):
    """A cluster of correlated same-tenant incidents + its members (newest first)."""

    id: uuid.UUID
    cluster_key: str | None = None
    title: str | None = None
    status: str
    member_count: int
    seed_incident_id: uuid.UUID | None = None
    members: list[ClusterMember] = []

    model_config = {"from_attributes": True}


class IncidentEntityLink(BaseModel):
    """An entity linked to one incident, in a given role — the /incidents/{id}/
    entities projection (mirror of IOCOut for entities)."""

    role: str
    entity_id: uuid.UUID
    entity_type: str
    canonical_key: str
    display_name: str
    customer: str | None = None
    risk_score: float | None = None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


# ── Forensics ───────────────────────────────────────────────────────────
class TriageRequest(BaseModel):
    ioc: str
    type: str | None = None  # 'ip'|'hash'|'domain'|'url'


class JobOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None = None
    kind: ForensicsKind
    ioc_or_file: str
    status: JobStatus
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


# ── Dashboard ───────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_incidents: int
    unique_iocs: int
    avg_sla_minutes: float | None
    false_positive_count: int
    total_closed: int
    status_breakdown: dict[str, int]
    severity_breakdown: dict[str, int]
    verdict_series: list[dict[str, Any]]  # [{date, TP, FP, benign}]
    monthly_cases: list[dict[str, Any]]  # [{month, incidents}]
    top_indicators: list[dict[str, Any]]  # [{value, type, count}]
    top_rules: list[dict[str, Any]]  # [{rule, count}]
    sla_trend: list[dict[str, Any]] = []  # [{date, critical, high, medium, low, overall, count}]
    sla_distribution: list[dict[str, Any]] = []  # [{bucket, count}]
    sla_by_severity: list[dict[str, Any]] = []  # [{severity, avg, count}]

    # ── Optional KPIs + series (opt-in dashboard panels) ────────────────
    true_positive_count: int = 0
    daily_incidents: list[dict[str, Any]] = []  # [{date, count}]
    fp_rate_trend: list[dict[str, Any]] = []  # [{month, closed, fps, rate}]
    llm_input_tokens_month: int = 0
    llm_output_tokens_month: int = 0
    llm_cost_month_usd: float = 0.0
    llm_call_count_month: int = 0
