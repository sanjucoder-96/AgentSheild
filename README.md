# Secure Agent Tool Gateway (PNC3)

A zero-trust proxy that sits between an AI agent and its tools and decides
**allow, deny or require-approval** for every tool call — checking who asked,
what the call carries, where its arguments came from, and where data is going.

> The model can be persuaded. The gateway decides what a persuaded agent is
> allowed to do. Every decision is deterministic, explainable, and measured on
> a corpus anyone can rerun.

Built for the NRCM hackathon problem statement **PNC3 — Secure Agent Tool
Gateway** (Cybersecurity and Threat Intelligence). This repository is the
Level 1–2 deliverable: a working MVP plus the architecture, stack and
evaluation behind it.

---

## What it does (mapped to the problem statement)

| PNC3 requirement | How this MVP meets it |
|---|---|
| **Multi-component architecture** — proxy, policy engine, execution harness | Go proxy speaking MCP; Cedar policy engine in-process; tool servers run behind a credential the agent never holds (the harness), with a Docker sandbox for Level 3 |
| **Deep parameter & destination validation** | Every argument is canonicalized, then checked: JSON-Schema validation, email/URL/IP allowlists, private + cloud-metadata IP blocking, path-escape, command and SQL inspection |
| **Adversarial resilience** | Canonicalizer decodes percent/base64/hex/HTML layers, strips zero-width and bidi characters, folds Unicode homoglyphs, and detects lookalike domains; strict JSON-RPC parser rejects duplicate/case-variant keys and batches |
| **Zero-trust execution guardrails** | Deny-by-default; per-agent tool allowlists; human approval for destructive calls; kill switch; the gateway injects credentials so the agent never sees them; credential-shaped strings in arguments are blocked |
| **Production-ready evaluation** | A benchmark replays an attack + benign corpus across three baselines and reports containment, block rate, false-positive rate and p50/p95/p99 latency |

Plus the two differentiators: **argument provenance / cross-call data-flow
rules** (a recipient copied from an untrusted ticket may not receive private
data read earlier in the session) and **manifest pinning** (a tool whose
description or schema silently changes is quarantined until re-approved).

---

## Quick start

Two ways to run it. Both need the repo and about a minute.

### A. Docker (nothing else to install)

```bash
docker compose up --build
# dashboard: http://localhost:8080   (admin token: dev-admin-token)
```

This starts the gateway, three mock tool servers, the attacker sink, PostgreSQL
and Redis. Then, from another shell:

```bash
pip install -r tools/requirements.txt      # only the demo client runs on the host
python3 demo/run_demo.py                    # the five-step attack demo
```

### B. Local (Go 1.26+, Node 18+, Python 3.11+)

```bash
make deps        # Go modules, Python deps, dashboard deps
make build       # builds the dashboard + gateway, gatewayctl, bench
make run         # starts tool servers, attacker sink and the gateway
make demo        # runs the five-step demo
make bench       # runs the benchmark across all three baselines
make stop        # stops everything
```

Open **http://localhost:8080** for the dashboard (live feed, approvals, tools,
policies, benchmark, audit). Default admin token: `dev-admin-token`.

Mint an agent token to drive the gateway yourself:

```bash
./bin/gatewayctl token --agent support-agent
```

---

## The five-minute demo

`make demo` (or `python3 demo/run_demo.py`) runs a normal MCP agent through the
gateway and narrates each step. Watch it on the dashboard's **Live feed**.

1. **Benign task works** — reads a ticket, emails a colleague on the allowlist. Allowed, with the added latency shown (well under a millisecond).
2. **Indirect prompt injection** — a ticket hides an instruction to email the customer database out. The agent obeys; the gateway blocks the send because a recipient from untrusted content would receive private data.
3. **Obfuscated retry** — the same address as base64 and as a homoglyph domain. Still blocked, because everything is canonicalized before the check.
4. **Destructive action** — `delete_all_emails` is held for a human; the reviewer denies it in the dashboard.
5. **Rug pull** — the tool server rewrites `send_email`'s description; the gateway quarantines the tool until an admin re-approves it.

Then verify the audit log is tamper-evident:

```bash
./bin/gatewayctl audit verify              # OK
./bin/gatewayctl audit tamper --seq 3      # edit one record
./bin/gatewayctl audit verify              # FAIL at record 3
```

---

## Benchmark

```bash
make bench      # writes results/summary.json; also shown on the dashboard
```

Measured on this repo's corpus (27 attacks, 15 benign, plus a cross-call
scenario), three baselines:

| Profile | Contained | Blocked | False positives | p50 | p99 |
|---|---|---|---|---|---|
| `off` (no gateway) | 55.6% | 0% | 0% | ~0.24 ms | ~0.6 ms |
| `allowlist_only` (tool-name allowlist) | 55.6% | 7.4% | 0% | ~0.25 ms | ~0.6 ms |
| **`full` (this gateway)** | **100%** | **100%** | **0%** | **~0.37 ms** | **~0.9 ms** |

Only the full gateway stops the argument-level and cross-call attacks that a
name-only allowlist misses, and it adds well under the 10 ms / 50 ms latency
targets. *Contained* = the attack achieved no effect; *blocked* = the gateway
denied it by policy. Numbers vary by machine; regenerate them with `make bench`.

Everything dangerous is **simulated** — the mock tools never delete files, run
shells, or reach the real internet, and the corpus uses canary tokens, never
live malware.

---

## How a call flows through the gateway

```
agent ──MCP──> gateway
                 1  authenticate            (JWT / OIDC; kill-switch + rate check)
                 2  strict parse            (reject duplicate keys, batches, junk)
                 3  manifest check          (hash pinned? else quarantine)
                 4  canonicalize + decode   (NFKC, strip invisibles, un-encode)
                 5  schema validate         (pinned JSON Schema; no smuggled args)
                 6  inspect -> facts        (destinations, IPs, paths, cmds, secrets, taint)
                 7  Cedar policy decision    ─┬─> ALLOW ── inject creds, run in harness
                                              ├─> APPROVE? ─ hold for a human (timeout = deny)
                                              └─> DENY ──── reason code, no internals
                 8  inspect response        (redact secrets, flag injection, update taint)
                 9  sign + append audit     (Ed25519 hash chain) + live dashboard
```

Steps 1–7 are deterministic, so every verdict is explainable. The gateway
**fails closed**: if the policy engine or session store errors, the call is
denied. A classifier (Level 3) may only *escalate* to approval; it can never
override a deny.

---

## Tech stack

| Layer | Choice |
|---|---|
| Proxy | Go, official **MCP Go SDK**, Streamable HTTP |
| Policy | **Cedar** (`cedar-go`), in-process, hot-reloaded; `@approval` annotation for the third outcome |
| Validation | JSON Schema 2020-12, custom canonicalizer, `net/netip`, Gitleaks-style secret rules |
| Harness | tool credential the agent never holds; Docker sandbox (Level 3) |
| Identity | dev HS256 tokens, or OIDC / Keycloak |
| Audit | Ed25519-signed SHA-256 hash chain → JSONL file **or** PostgreSQL |
| Sessions / kill switch | in-memory, or Redis |
| Dashboard | React + Vite, embedded in the Go binary |

Why Cedar over OPA: policies read almost like English (good for a jury), and a
`forbid` always beats a `permit`, so zero-trust is built into the language.
Cedar decides on clean facts the Go code extracts — "code extracts facts,
policy decides" — which keeps the policies short enough to show on a slide.
See `config/policies/*.cedar`.

---

## Layout

```
cmd/gateway      the gateway service
cmd/gatewayctl   CLI: mint tokens, verify/tamper the audit log
cmd/bench        the benchmark runner
internal/        rpc, canon, inspect, policy, manifest, upstream, session,
                 audit, approval, auth, gateway, config
config/          gateway.yaml + Cedar policy files
tools/           three mock MCP tool servers (Python)
attacker/        local sink that logs anything leaked to it
demo/            the scripted five-step demo
bench/           attack + benign corpus (JSONL)
web/             React dashboard (built into the binary)
migrations/      PostgreSQL schema (Level 2)
docs/            SRS, architecture and data-flow diagrams
```

See **docs/SRS.md** for the full specification, requirements and threat model,
and **docs/ARCHITECTURE.md** for the diagrams.

---

## Configuration

Everything is in `config/gateway.yaml` except secrets, which come from the
environment:

| Variable | Purpose | Dev default |
|---|---|---|
| `GATEWAY_JWT_SECRET` | signs dev agent tokens | `dev-jwt-secret-change-me` |
| `ADMIN_TOKEN` | protects the admin API and dashboard | `dev-admin-token` |
| `TOOL_SHARED_SECRET` | the credential the gateway sends upstream | `dev-tool-secret-change-me` |
| `DATABASE_URL` | Postgres audit log (optional; file log otherwise) | unset |
| `REDIS_URL` | Redis sessions + kill switch (optional; memory otherwise) | unset |
| `GATEWAY_PROFILE` | `full`, `allowlist_only` or `off` | `full` |

Change the dev secrets before running anything real.

---

## Roadmap

- **Level 1 (done)** — idea, architecture, data-flow diagram, wireframe (the dashboard), locked stack, attack taxonomy, SRS.
- **Level 2 (this MVP)** — proxy, validators, Cedar policies, approval queue, signed audit log, dashboard, benchmark, database schema.
- **Level 3** — PromptGuard-2 classifier as escalate-only, full session provenance, gVisor sandbox, mTLS, CI/CD with SHA-pinned actions, cloud deploy.
- **Level 4** — Kubernetes autoscaling, Redis-cluster caching, Prometheus/Grafana alerts, load test.
