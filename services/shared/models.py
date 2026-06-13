"""
Typed payloads exchanged between Mir[AI]ge services.

This module is the single source of truth for all data contracts:
  - A2A signals (Sentinel -> Orchestrator)
  - MCP tool I/O (Orchestrator -> MCP Server)
  - State machine context (Orchestrator internal)
  - Ghost Shell session state (Ghost Shell internal)
  - Metrics events (Mirage Metrics)

All services import from here. Adding a new payload? Add it here first.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────
# Enums · shared vocabulary
# ──────────────────────────────────────────────────────────────────────


class AttackVector(str, Enum):
    """Categorical vector of attack identified by the Sentinel.

    ⚠ INCONSISTENT separator convention by legacy: `brute_force` (underscore)
    coexists with `ai-recon` (hyphen). These values are serialized everywhere (A2A
    signals, CLI aliases, YAML), so we don't change them. Any code that builds an
    AttackVector from an external label must tolerate both separators
    (see classifier._coerce_vector).
    """
    RECON = "recon"
    BRUTE_FORCE = "brute_force"
    TRAVERSAL = "traversal"
    INJECTION = "injection"
    AI_RECON = "ai-recon"
    UNKNOWN = "unknown"


class MorphState(str, Enum):
    """Orchestrator state machine, see ADR-013."""
    IDLE = "idle"
    DETECTING = "detecting"
    ASSIGNING = "assigning"        # allocates a Ghost Shell session (vs the old CLONING)
    REROUTING = "rerouting"         # L7 PATCH Octavia via XFF
    MONITORING = "monitoring"
    TERMINATING = "terminating"
    ERROR = "error"
    ROLLBACK = "rollback"


class GhostPersona(str, Enum):
    """Persona presented by Ghost Shell, Host header routing."""
    PORTAL_OVH = "portal_ovh"
    MYSQL = "mysql"
    K8S_APISERVER = "k8s_apiserver"
    ADMIN_PANEL = "admin_panel"


# ──────────────────────────────────────────────────────────────────────
# Log ingestion (fake_portal -> Sentinel)
# ──────────────────────────────────────────────────────────────────────


class LogEvent(BaseModel):
    """A single HTTP log line as ingested by Sentinel."""
    timestamp: datetime
    source: Literal["lb", "vm", "auth", "syslog"]
    src_ip: str
    session_id: str | None = None    # mg_session cookie (non-spoofable identity), if present
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    raw: str


# ──────────────────────────────────────────────────────────────────────
# Detection · cascade types (Sentinel internal)
# ──────────────────────────────────────────────────────────────────────


SigmaSeverity = Literal["info", "low", "medium", "high", "critical"]


class SigmaHit(BaseModel):
    """A Sigma rule match against an event (Tier 0)."""
    rule_id: str
    rule_title: str
    severity: SigmaSeverity
    matched_at: datetime
    event_index: int  # index in batch
    fields_matched: dict[str, str] = Field(default_factory=dict)


class WindowFeatures(BaseModel):
    """Feature vector for Tier 1 XGBoost classifier.

    Extracted per 10s window. Order matters for the model, keep stable.
    """
    rate_rps: float
    n_events: int
    n_unique_paths: int
    unique_path_ratio: float        # n_unique_paths / n_events
    ua_entropy: float                # Shannon entropy of User-Agent strings
    ratio_4xx: float                 # n events with 4xx status / n_events
    ratio_5xx: float
    ratio_200: float
    inter_arrival_mean_ms: float
    inter_arrival_p95_ms: float
    n_distinct_status: int
    n_distinct_methods: int
    sigma_hits_in_window: int        # T0 hits accumulated
    owasp_coverage: float = 0.0      # S4 · fraction of OWASP recon families touched [0,1]


class TierVerdict(BaseModel):
    """Output of one tier in the cascade.

    `behavioral` = cumulative non-velocity detector (OWASP recon breadth),
    a 4th path alongside the T0/T1/T2 cascade, see _cumulative_recon_check.
    """
    tier: Literal["T0", "T1", "T2", "behavioral"]
    triggered: bool                  # this tier wants to escalate to MTD
    confidence: float = Field(ge=0.0, le=1.0)
    vector: AttackVector | None = None
    rationale: str


class DetectionVerdict(BaseModel):
    """Output of the Sentinel cascade for a window of events.

    Carries the final verdict (which tier triggered) + the per-tier breakdown
    for audit / debug.
    """
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    attacker_ip: str
    attacker_session: str | None = None   # offending session (cookie) to reroute, if known
    vector: AttackVector
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    rate_rps: float
    window_start: datetime
    window_end: datetime
    # Cascade trace (optional, for observability)
    tier_trace: list[TierVerdict] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# A2A signal (Sentinel -> Orchestrator, HMAC-SHA256 signed)
# ──────────────────────────────────────────────────────────────────────


class AttackSignal(BaseModel):
    """A2A payload sent from Sentinel to Orchestrator. See §10."""
    request_id: str
    attacker_ip: str
    attacker_session: str | None = None
    target_instance_id: str
    vector: AttackVector
    confidence: float
    rate_rps: float
    emitted_at: datetime = Field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────────────────────────────
# Orchestrator FSM context
# ──────────────────────────────────────────────────────────────────────


class MorphContext(BaseModel):
    """In-flight context held by the Orchestrator for one incident."""
    request_id: str
    attacker_ip: str
    attacker_session: str | None = None
    target_instance_id: str
    state: MorphState = MorphState.IDLE
    ghost_session_id: str | None = None
    ghost_persona: GhostPersona | None = None
    lb_rule_id: str | None = None
    rollback_token: str | None = None
    expires_at: datetime | None = None
    last_transition_at: datetime = Field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────────────────────────────
# MCP tool I/O schemas (mirror docs/diagrams/04-mcp-tools)
# ──────────────────────────────────────────────────────────────────────


class RouteToGhostShellInput(BaseModel):
    """Tool 1 · allocates a Ghost Shell session for the attacker."""
    session_id: str
    attacker_cidr: str
    persona: GhostPersona = GhostPersona.PORTAL_OVH
    ttl_seconds: int = 1800
    lb_id: str
    request_id: str


class RouteToGhostShellOutput(BaseModel):
    ghost_session_id: str
    persona: GhostPersona
    expires_at: int  # unix ts


class RerouteLbInput(BaseModel):
    """Tool 2 · L7 PATCH Octavia via XFF header."""
    lb_id: str
    attacker_ips: list[str]
    attacker_session: str | None = None   # offending session cookie (targeted revocation)
    ghost_pool_id: str
    persistence_seconds: int = 7200
    request_id: str


class RerouteLbOutput(BaseModel):
    rule_id: str
    applied_at: int
    rollback_token: str


class TerminateHoneypotInput(BaseModel):
    """Tool 3 · releases the Ghost Shell session + restores LB."""
    ghost_session_id: str
    lb_rule_id: str
    rollback_token: str
    collect_ttps: bool = True
    request_id: str


class TerminateHoneypotOutput(BaseModel):
    destroyed: bool
    ttps_archive_url: str | None
    tokens_burned: int
    asymmetric_ratio: float


# ──────────────────────────────────────────────────────────────────────
# Ghost Shell session state (Ghost Shell internal, Redis-backed)
# ──────────────────────────────────────────────────────────────────────


class SessionSignals(BaseModel):
    """Behavioural signals observed during a session."""
    pi_canary_compliance: bool = False
    confidence_llm_agent: float = 0.0
    timing_under_2s_count: int = 0
    methodical_coverage_score: float = 0.0


class SessionState(BaseModel):
    """Per-attacker session state. Stored in Redis with TTL."""
    id: str
    attacker_ip: str
    persona: GhostPersona
    created_at: datetime
    expires_at: datetime
    counters: dict[str, int] = Field(default_factory=dict)
    discovered_creds: list[dict] = Field(default_factory=list)
    signals: SessionSignals = Field(default_factory=SessionSignals)
    tokens_burned: int = 0
    # Tracking fields for the monitoring dashboard
    requests_total: int = 0
    endpoints_visited: list[str] = Field(default_factory=list)    # capped at 120
    mechanisms_triggered: list[str] = Field(default_factory=list) # deduplicated


# ──────────────────────────────────────────────────────────────────────
# Metrics events (Mirage Metrics)
# ──────────────────────────────────────────────────────────────────────


class MetricsSnapshot(BaseModel):
    """Operational snapshot of the Ghost Net, pushed to the Dashboard (WebSocket / GET /current).

    ACTIVITY metrics only (prod tool): no more € cost or energy/CO₂.
    """
    timestamp: datetime
    active_sessions: int            # active attacker sessions in the Ghost Net
    tokens_served_attacker: int     # tokens served to the decoy (measured with tiktoken o200k_base)
