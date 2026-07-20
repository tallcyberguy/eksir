"""Shared string enums for DB columns and API responses.

We use Python str-Enums (vs SA Enum types) so the same value travels cleanly
through Pydantic, JSON, and Postgres without case-juggling.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TenantTier(StrEnum):
    HOST = "host"  # The platform operator. Sees everything.
    MSSP = "mssp"  # Managed service provider. Sees own + child clients.
    CLIENT = "client"  # End customer. Sees only own data.


class CustomerCaseStatus(StrEnum):
    """Lifecycle of a customer-facing notification case."""

    DRAFT = "draft"
    REVIEWED = "reviewed"
    SENT = "sent"


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class CaseStatus(StrEnum):
    RECEIVED = "received"
    PARSED = "parsed"
    AUTO_CLOSED_CANDIDATE = "auto_closed_candidate"
    ENRICHING = "enriching"
    DECIDED_SHORT_CIRCUIT = "decided_short_circuit"
    AWAITING_SYNTHESIS = "awaiting_synthesis"
    SYNTHESIZED = "synthesized"
    AWAITING_REVIEW = "awaiting_review"
    # Persona pipeline parked at the human gate: manager has proposed a verdict
    # (+ optional response actions); an analyst must approve/reject before commit.
    AWAITING_SIGNOFF = "awaiting_signoff"
    CLOSED = "closed"
    FAILED = "failed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    TP = "TP"
    FP = "FP"
    BENIGN = "benign"
    PENDING = "pending"
    INCONCLUSIVE = "inconclusive"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AutonomyDecision(StrEnum):
    """Autonomy guardrails (3.9) — graduated recommendation per proposed action.
    v1 never drops an action (no `reject`); it only badges it."""

    AUTO = "auto"  # read-only / no-effect, high confidence → pre-checkable
    REVIEW = "review"  # default — analyst should look
    ESCALATE = "escalate"  # containment / low confidence → always analyst-gated


class BlastRadius(StrEnum):
    READ = "read"
    LOW = "low"
    MED = "med"
    HIGH = "high"
    CRITICAL = "critical"


class IngestSource(StrEnum):
    PASTE = "paste"
    WEBHOOK = "webhook"
    FILE = "file"
    EMAIL = "email"
    PULL = "pull"  # API-pulled from a console on a schedule (ingest_sources)
    BATCH = "batch"  # bulk/historical file import streamed in (import_jobs)


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    SHA256 = "sha256"
    MD5 = "md5"
    SHA1 = "sha1"
    DOMAIN = "domain"
    URL = "url"
    EMAIL_ADDR = "email"


class ForensicsKind(StrEnum):
    TRIAGE = "triage"
    STATIC = "static"
    DYNAMIC = "dynamic"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AutoCloseSource(StrEnum):
    YAML = "yaml"
    UI = "ui"


class LLMStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
