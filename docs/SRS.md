# Software Requirements Specification — Secure Agent Tool Gateway (PNC3)

**Version:** MVP (Level 1–2) · **Working name:** Secure Agent Tool Gateway

## 1. Purpose and scope

Enforce least-privilege, destination-aware authorization on every AI-agent tool
call, and prove its accuracy and latency with a reproducible benchmark. The
gateway is a zero-trust proxy: agents reach tools only through it, and tool
servers accept connections only from it.

**In scope:** MCP `tools/call` and `tools/list` over Streamable HTTP; tool
manifest pinning; policy authoring and hot reload; the approval workflow;
signed audit; the benchmark.

**Out of scope for the MVP:** model fine-tuning, chat-layer prompt filtering,
non-MCP tool protocols (added later via adapters). These do not weaken the
security model — the gateway constrains what a persuaded agent may *do*,
regardless of how it was persuaded.

**Why a gateway is needed.** The MCP specification says hosts must obtain user
consent before invoking a tool and must treat tool descriptions as untrusted,
but also states MCP cannot enforce these at the protocol level — enforcement is
left to implementers. This gateway is that enforcement point.

## 2. Actors

| Actor | Goal |
|---|---|
| AI agent | Call tools to complete a task |
| Human principal | The person the agent acts for; approves risky actions |
| Security admin | Writes policies, registers tools, reviews the audit log |
| Tool server | Executes a call; trusts only the gateway |
| Attacker | Hijacks the agent via injected content or a poisoned tool |

## 3. Functional requirements

| ID | Requirement | Where |
|---|---|---|
| FR-1 | Intercept every `tools/call` and `tools/list`; no direct agent-to-tool path | `internal/gateway`, tool-side credential |
| FR-2 | Authenticate agents with short-lived tokens; reject unknown or expired ones | `internal/auth` |
| FR-3 | Canonicalize arguments (Unicode, encodings, paths, URLs) before any check | `internal/canon` |
| FR-4 | Validate arguments against the tool's pinned JSON Schema; reject undeclared args | `internal/manifest` |
| FR-5 | Resolve and check all outbound destinations; block private and metadata IPs | `internal/inspect` |
| FR-6 | Decide allow / deny / require-approval with a rule id and reason | `internal/policy` |
| FR-7 | Hold require-approval calls until a human decides or a timeout denies them | `internal/approval` |
| FR-8 | Detect tool description/schema changes and quarantine the tool | `internal/manifest` |
| FR-9 | Label tool outputs by source; block private-to-external flows in untrusted sessions | `internal/session`, `internal/inspect` |
| FR-10 | Log every decision; expose a live feed and search | `internal/audit`, dashboard |
| FR-11 | Provide a kill switch that revokes an agent in under one second | `internal/session` |
| FR-12 | Run the benchmark and export results as JSON and a table | `cmd/bench` |

## 4. Non-functional requirements (design targets)

- **Latency:** gateway overhead p50 < 10 ms, p99 < 50 ms on the deterministic path (the optional classifier path is reported separately). *Measured full-profile: p50 ≈ 0.37 ms, p99 ≈ 0.9 ms — well within target.*
- **Fail closed:** if the policy engine or session store errors, the call is denied.
- **Auditability:** every decision is logged with agent id, tool, normalized-args hash, rule id, reason and per-stage latency, signed and hash-chained.
- **Secret hygiene:** the agent never holds tool credentials; the gateway injects them after an allow decision; credential-shaped strings in arguments are blocked and redacted from logs.

These are engineering goals to be measured, not sourced facts; any number shown
in a demo comes from the project's own benchmark run.

## 5. Data model

| Entity | Key fields |
|---|---|
| Agent | agent_id, owner, allowed_tools[], scopes, status |
| Tool | tool_id, server, description_hash (pinned), risk_level, destructive |
| Policy | policy_id, version, cedar_source, active |
| Decision | decision_id, ts, agent_id, tool, args_hash, canonical_args, verdict, rule_id, reason, latency per stage |
| Approval | approval_id, decision_id, approver, outcome, decided_at |
| SessionTaint | session_id, labels[], private/untrusted fingerprints, ttl |

See `migrations/001_init.sql`.

## 6. External interface (admin plane)

| Method + path | Purpose |
|---|---|
| `POST /mcp` | Agent-facing MCP endpoint (proxied) |
| `GET /admin/state`, `/admin/decisions`, `/admin/tools`, `/admin/policies`, `/admin/agents` | Read gateway state and audit |
| `PUT /admin/policies/{file}` | Save and hot-reload a policy file |
| `POST /admin/approvals/{id}` | Approve or deny a held call |
| `POST /admin/tools/{name}/approve` | Re-approve a quarantined tool |
| `POST /admin/agents/{id}/revoke` / `/restore` | Kill switch |
| `GET /admin/audit/verify` | Verify the audit chain |
| `GET /metrics` | Prometheus metrics |

## 7. Threat model (OWASP Top 10 for Agentic Applications, 2026)

| Threat | ID | Control in this gateway |
|---|---|---|
| Agent goal hijack via indirect injection | ASI01 | Taint tracking, destination policy, approval gate |
| Tool misuse and exploitation | ASI02 | Schema validation, per-tool scopes |
| Identity and privilege abuse | ASI03 | Per-agent tokens, least-privilege allowlists, secret brokering |
| Agentic supply chain (poisoned tool) | ASI04 | Manifest pinning, rug-pull quarantine |
| Unexpected code execution | ASI05 | Argv/env validation; sandbox harness (Level 3) |
| Rogue / runaway agent | ASI10 | Rate limits, kill switch |
| Gateway itself attacked | — | Fail closed, body-size limits, tool servers accept only the gateway |

## 8. Evaluation

Let TP = attacks blocked, FN = attacks allowed, FP = benign blocked, TN = benign allowed.

- **Containment rate** = attacks that achieved no effect / all attacks (the security metric)
- **Block rate (recall)** = TP / (TP + FN)
- **False-positive rate** = FP / (FP + TN)
- **Added latency** = gateway overhead per call at p50/p95/p99, deterministic and classifier paths separately

**Corpus categories:** direct and indirect injection, encoded payloads
(base64/percent/hex), homoglyph and zero-width tricks, path traversal, SSRF to
private/metadata IPs, allowlisted-command abuse, exfiltration via URL query,
cross-call data-flow exfiltration, tool-description rug pull, destructive action
without approval, privilege escalation. Payloads use canary tokens only.

## 9. Assumptions and constraints

- The tool servers in this repo are mock servers that simulate dangerous effects; no real files, shells or external hosts are touched.
- The demo intranet (`*.acme.example`) resolves via a static map in the config, so it never depends on public DNS.
- Cedar (`cedar-go`) is used for policy; some Rust-only schema tooling is not yet in the Go port, so policies are validated on save and (in CI) with the Cedar CLI.
