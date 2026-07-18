# ADR: Audit Log Core — Event Emission & Sink Pipeline

- **Status:** Proposed
- **Date:** 2026-07-18
- **Author:** @sky
- **Related:** [Audit Log & Usage Dashboard RFC](audit-log-dashboard.md) (umbrella), [Secrets Management](secrets-management.md), [Identity Trust-None Default](identity-trust-none.md), [Lifecycle Hooks](hooks.md)
- **Tracking issues:** #1356 (L1 audit warning)

---

## 1. Context & Problem

OpenAB is increasingly deployed in team and enterprise environments, but today the
only observability is `tracing` output to stdout — ephemeral, unstructured, and
debug-oriented. There is no reliable answer to "who did what, when, on which
platform, and did it succeed?"

The [Audit Log & Usage Dashboard RFC](audit-log-dashboard.md) proposes the overall
system (pluggable `AuditEvent` / `AuditSink` in `openab-core`, plus a separate
`openab-dashboard` container). That RFC is intentionally broad and leaves several
questions open (fail behaviour, thread correlation, retention, redaction detail).

**This ADR scopes down to the Phase 1 core** and makes those decisions concrete, so
implementation can start without blocking on the dashboard. It defines the event
schema, the emitter, the sink trait, the two lowest-cost sinks (file + webhook),
and the operational policies (fail-open, redaction, retention). S3 / OTLP sinks and
the dashboard remain under the umbrella RFC.

**Non-goals:** dashboard UI, cost-attribution modelling, multi-tenant partitioning
(deferred to the RFC).

### Why not just use the tracing logs we already have?

An audit log is a different artifact from a system/debug log. Conflating them is the
root cause of the current gap.

| | System / `tracing` log | Audit log (this ADR) |
|---|---|---|
| Purpose | Debugging, observability | Accountability, compliance, incident forensics |
| Audience | Developers | Auditors, security team |
| Structure | Free-form, noisy | Fixed schema, one event per line |
| Content | Everything, incl. stack traces | Metadata only; secrets redacted / not stored |
| Integrity | Overwritable, rotated away | Append-only, tamper-evident, retained by risk class |
| Retention | Short (days) | Tiered: debug 7d / audit 30–90d / regulated longer |

## 2. Prior Art

Surveyed how comparable agent platforms handle this (informs the decisions below):

- **Hermes Agent (Nous Research)** — centralized structured logging since v0.8.0,
  written to `~/.hermes/logs/` with `RotatingFileHandler` (5 MB × 3 backups).
  Notably, **all output passes through a `RedactingFormatter`** (`agent/redact.py`)
  that strips credential patterns (`sk-`, `sk-ant-`, OAuth tokens, env-var patterns)
  *before* anything hits disk. We adopt this redaction-at-the-boundary approach —
  the RFC did not specify redaction mechanics.
- **OpenClaw** — gateway logs at `/tmp/openclaw/openclaw-YYYY-MM-DD.log` (plain text
  by default, `logging.format: "json"` to structure), session transcripts as
  per-session JSONL. Guidance: one immutable event per line, redact secrets, tier
  retention by risk (7 / 30–90 days). OpenClaw's audit trail is **spread across
  per-session transcripts**; because OpenAB sandboxes the agent from day one and all
  I/O flows through the gateway, we can emit from a **single trusted choke point**,
  which is harder to bypass or forge.

**Takeaways applied:** (1) redact at the emit boundary (Hermes); (2) local
append-only JSONL + daily rotation as the always-on baseline (both); (3) centralized
gateway-side emission rather than per-session files (OpenAB's sandbox advantage).

## 3. Approaches Considered

### A. Tracing subscriber with a JSON file layer (status quo+)

Add a `tracing_subscriber` JSON layer writing audit spans to a file.

- **Pros:** almost zero new code; reuses existing instrumentation.
- **Cons:** tracing events are debug-shaped, not audit-shaped; no typed schema; audit
  events drown in debug noise; no batching/redaction/back-pressure control for remote
  sinks. Rejected by the umbrella RFC for the same reasons.

### B. Dedicated audit event system with pluggable sinks (RFC direction)

A typed `AuditEvent` emitted at instrumented choke points, fanned out to configurable
`AuditSink` implementations.

- **Pros:** typed schema; audit/debug separation; per-sink buffering, redaction, and
  failure policy; matches the umbrella RFC so Phase 2/3 (S3/OTLP/dashboard) slot in.
- **Cons:** ~500–800 lines of new Rust; one more subsystem to maintain.

### C. External sidecar (Vector / Fluentd) scraping stdout

- **Pros:** proven log-shipping tooling.
- **Cons:** fragile stdout parsing, no typed schema, redaction happens too late (secrets
  already on stdout), extra deployment burden. Rejected.

## 4. Decision

Adopt **B**, scoped to Phase 1: a typed `AuditEvent`, an `AuditEventEmitter`, an
`AuditSink` trait, and two built-in sinks — **File (JSONL)** and **Webhook** — plus a
mandatory **redaction pass** and a configurable **fail policy**. S3 / OTLP sinks and
the dashboard are explicitly deferred to the umbrella RFC.

### Design principles (inherited from the RFC)

1. **Zero-cost when disabled** — compiles in, does nothing unless `[audit]` is set.
2. **Pluggable sinks** — File and Webhook now; S3/OTLP later, same trait.
3. **Privacy-first** — no prompt/response content by default; metadata only.
4. **Redact at the boundary** — every event passes a redactor before any sink.

## 5. Specification

### 5.1 Event schema

Extends the RFC struct with `thread_id` (resolves RFC Open Question #1 — multi-turn
correlation is needed for incident reconstruction) and a `schema_version`.

```rust
#[derive(Serialize)]
pub struct AuditEvent {
    pub schema_version: u16,        // starts at 1; bump on breaking change
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub agent: String,              // e.g. "kiro", "claude", "hermes"
    pub platform: String,           // e.g. "discord", "slack", "teams"
    pub channel_id: String,
    pub user_id: String,            // platform user ID (hashed if configured)
    pub session_id: Option<String>,
    pub thread_id: Option<String>,  // NEW: correlate a multi-turn conversation
    pub metadata: serde_json::Value,
}

pub enum AuditEventType {
    SessionStart,
    SessionEnd,
    Prompt,          // metadata: { token_count, model }
    Response,        // metadata: { token_count, duration_ms }
    ToolCall,        // metadata: { tool_name, status, duration_ms }
    PermissionGrant, // metadata: { permission, auto_approved }
    Error,           // metadata: { error_category, message }
}
```

Serialized as JSONL — **one immutable JSON object per line**.

### 5.2 What is NOT stored (default)

Prompt text, response text, tool-call arguments (tool name only), and file contents.
Opt-in content logging follows the RFC (`include_content = true` requires
`content_encryption_key`).

### 5.3 Redaction (mandatory, pre-sink)

Every event passes through a `Redactor` before reaching **any** sink — including
`metadata`. Patterns (following Hermes' approach): `sk-`, `sk-ant-`, `sk-or-`,
`ghp_`/`github_pat_`, bearer/OAuth tokens, and `${secrets.*}`-resolved values known to
the process. Redaction is not opt-out; it is the last line of defence even when
`include_content = true`.

### 5.4 Sink trait

```rust
#[async_trait]
pub trait AuditSink: Send + Sync + 'static {
    async fn emit(&self, event: &AuditEvent) -> Result<()>; // may buffer internally
    async fn flush(&self) -> Result<()>;                    // called on graceful shutdown
}
```

### 5.5 Built-in sinks (Phase 1)

| Sink | Config key | Transport | Storage | Buffering |
|------|-----------|-----------|---------|-----------|
| File (JSONL) | `audit.file` | local write | append-only file, daily rotation | line-buffered |
| Webhook | `audit.webhook` | HTTP POST JSON | user endpoint | per-event or batched |

The **File sink is the always-on durable baseline**: even when a remote sink is
configured, events are written locally first so a network outage never creates an
audit gap. The webhook sink ships asynchronously off that record.

### 5.6 Fail policy (resolves RFC Open Question on failure behaviour)

Audit-write failures are **fail-open by default** — a failed sink must not block a
user's message (unlike [secrets resolution](secrets-management.md), which is
fail-closed because the process genuinely cannot run without the secret). A degraded
audit path logs a `WARN` and increments a metric, then continues.

For regulated deployments, `critical_events_fail_closed` upgrades **only**
`PermissionGrant` and `Error` events to fail-closed: if those cannot be durably
recorded, the triggering action is rejected. Routine `Prompt`/`Response`/`ToolCall`
events remain fail-open regardless.

```toml
[audit]
enabled = true
sinks = ["file", "webhook"]
hash_user_ids = true                 # privacy: hash platform user IDs
critical_events_fail_closed = false  # true → block PermissionGrant/Error on sink failure

[audit.file]
path = "/var/log/openab/audit.jsonl"
rotation = "daily"
retention_days = 30                  # see risk tiers below

[audit.webhook]
url = "https://my-company.com/api/openab-audit"
headers = { "Authorization" = "Bearer ${secrets.audit_webhook_token}" }
batch_size = 10
timeout_secs = 5
```

### 5.7 Retention by risk class

Per prior-art guidance, retention is tiered rather than one-size-fits-all:

| Class | Events | Default retention |
|-------|--------|-------------------|
| Debug/low | `SessionStart/End`, `Prompt`, `Response` | 7 days |
| Audit/normal | `ToolCall`, `PermissionGrant` | 30–90 days |
| Regulated | any, when compliance requires | operator-set, longer |

`retention_days` sets the file-sink floor; downstream sinks (S3/SIEM) may extend it.

## 6. Architecture

```
Discord/Slack/Teams msg
        │
        ▼
┌──────────────────────────────┐
│  Gateway (single choke point)│
│                              │
│   emit(AuditEvent) ──► Redactor ──► fan-out
└──────────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
   FileSink (JSONL)   WebhookSink (HTTP POST)
   append-only,       async, batched,
   daily rotation     fail-open
        │
        ▼
   local disk  ──(later: S3 / OTLP / openab-dashboard — see umbrella RFC)
```

## 7. Implementation Plan

### Phase 1a — emitter + file sink
- Add `AuditEvent`, `AuditEventType`, `AuditSink`, `Redactor` to `openab-core`.
- Implement `FileSink` (JSONL, daily rotation, `retention_days`).
- Instrument the gateway choke points: session start/end, prompt/response token
  counts, tool-call outcomes, permission grants, errors.
- `[audit]` config parsing. Deps: `uuid` (already in tree).

### Phase 1b — webhook sink + fail policy
- Implement `WebhookSink` (batched HTTP POST, timeout, retry-with-backoff).
- Wire `critical_events_fail_closed` gating for `PermissionGrant`/`Error`.
- Graceful-shutdown `flush()` on all sinks.

### Deferred to umbrella RFC
- S3 / OTLP sinks, `openab-dashboard`, cost attribution, multi-tenant partitioning.

## 8. Consequences

**Positive:**
- Enterprise-grade "who did what" trail with zero cost when disabled.
- Redaction-at-boundary means secrets never reach any sink, even on opt-in content logging.
- File-first durability closes the network-outage audit gap.
- Slots cleanly under the dashboard RFC — Phase 2/3 add sinks, not rewrites.

**Negative:**
- New subsystem (~500–800 lines) to maintain and instrument.
- Fail-open default means a misconfigured sink can silently drop routine events —
  mitigated by the WARN + metric and the file-first baseline.
- Redaction patterns need upkeep as new credential formats appear.

## 9. Open Questions (deferred to umbrella RFC)

1. Cost-attribution model — estimate dollar cost per session in core, or in dashboard?
2. Real-time streaming / live tail vs. batch query for the dashboard.
3. Multi-tenant isolation when one instance serves several teams.

## 10. References

- [Audit Log & Usage Dashboard RFC](audit-log-dashboard.md) — umbrella
- [Secrets Management ADR](secrets-management.md) — fail-closed contrast, `exec://`/webhook precedent
- Hermes Agent logging & redaction — https://github.com/NousResearch/hermes-agent/blob/main/hermes_logging.py
- OpenClaw gateway security & logging — https://docs.openclaw.ai/gateway/security
- JSONL format — https://jsonlines.org/
- OpenTelemetry Logs — https://opentelemetry.io/docs/specs/otel/logs/
- GDPR Art. 17 (right to erasure) — https://gdpr-info.eu/art-17-gdpr/
