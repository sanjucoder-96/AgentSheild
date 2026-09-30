# PNC3 · Secure Agent Tool Gateway: Project Handoff README

> **Purpose of this file.** This is the running memory for our work with Claude. Our chats happen in incognito sessions, so Claude remembers nothing between them. To continue, start a new chat, upload this README (plus the deck and any files listed in §2), and say: *"Continue from this README."* Claude should read the whole file, treat §10 (Decisions log) as settled unless we reopen something, and pick up from §11 (Next steps).
>
> **Version:** v2 · **Last updated:** 30 Sep 2026 (night before Level 3) · **Maintainer rule:** after every meaningful change, Claude updates the relevant sections, adds a changelog entry (§14), and bumps the version.

---

## ⭐ CURRENT STATUS (v2) — read this first; it supersedes older sections where they differ

**Project name in code/UI:** AgentShield (repo `github.com/sanjucoder-96/AgentSheild`, branch `V1-WorkingCopy`). Team member **Umesh** added Groq features.

**Evaluations:** Round 1 scored 18/25 (lost marks explaining the problem statement). Round 2 went well. **Level 3 evaluation: tomorrow 09:30. Final Level 4: 14:30–16:30.**

**Latest deliverable:** `agentshield-level3.zip` = Umesh's code + all Level 2 fixes + full Level 3 build. Upload it (not older zips) in a new session. Key docs inside: `docs/DEPLOY_AWS.md` (step-by-step EC2+RDS), `docs/LEVEL3_CHANGES.md` (fixes, evidence, judge talking points), `README.md` (Level 3 table + implemented-vs-next scope).

**Stack (final, as built):** Go 1.26 gateway · cedar-go 1.8 · MCP Go SDK 1.8 · Python `mcp` 2.2 tool servers (`MCPServer` API) · React/Vite dashboard embedded in the binary · Postgres (RDS) audit log · Redis sessions/kill switch · Caddy HTTPS · GitHub Actions → GHCR → EC2 · Groq (`openai/gpt-oss-20b`) for AI features.

**Umesh's additions (reviewed, kept):** Groq English→Cedar policy generator (validated, human-reviewed, never auto-saved), Groq agent console, per-tool agent scope / arg-size limit / require-approval, tool suspend/resume/revoke, SQLite CRM, restricted real `run_shell`, `/admin/metrics`, policy delete, run-benchmark button.

**Level 2 fixes done:** duplicate `package` line broke tests · `run_shell` sandbox escape (`cat ../../.env` read the Groq key) · bench button broken in Docker · approval metric always 0 · stray debug files + runtime state committed · warnings for over-broad AI-generated permits. **Team action: rotate the Groq key** (it was inside the shared zip).

**Level 3 done and verified:** dashboard login (bcrypt, HttpOnly/Secure/SameSite=Strict cookie, CSRF header, 5/min throttle, audited) · production guard (refuses to boot with default/weak secrets) · HTTPS + HSTS + CSP via Caddy · RDS over `sslmode=verify-full` · hardened tool containers (read-only, non-root, no capabilities, **no internet route**) = real execution harness · CI/CD with SHA-pinned actions · setup/deploy/check_rds/demo_rugpull scripts · Plan B (build on server) and Plan C (local Postgres).

**Measured numbers (current):** full profile 100% contained, 0% false positives, p50 ≈ 0.38–0.54 ms, p99 ≈ 0.81–0.93 ms. Baselines (off / allowlist_only) contain 63% (was 56% before the real SQLite CRM). Tests: 23 Go + 5 Python passing.

**Not verifiable in the build sandbox:** real AWS/RDS, Let's Encrypt issuance, GitHub runners, Docker runtime. Everything else ran for real (production mode behind Caddy HTTPS with TLS Postgres + password Redis).

**AWS plan:** Mumbai `ap-south-1`, free plan ($100 credits enough). EC2 Ubuntu 24.04 **x86** t3.small/micro + Elastic IP; RDS PostgreSQL 16 smallest class, not public, encrypted; SG rule `aegis-rds-sg` 5432 ← `aegis-ec2-sg` is the EC2↔RDS link. Domain: none yet → DuckDNS recommended.

**Next steps:** (1) do DEPLOY_AWS.md steps 0–9 tonight; (2) update the deck (stack, Umesh's AI features, Level 3 table, new numbers, dashboard screenshots); (3) rehearse on the public URL; (4) Level 4 prep: K8s manifests + HPA, Grafana dashboard + alerts from existing Prometheus metrics, load test for throughput.

**New decisions:** D11 keep Umesh's Groq features but the LLM stays out of the per-call path · D12 admins use cookie sessions, machines use bearer tokens, no tokens in URLs · D13 policies-as-code; dashboard edits persist in a volume until reset · D14 build images in CI, not on the small EC2 · D15 RDS for the audit log; Redis stays in Docker.

---

## 1. Project at a glance

| Item | Value |
|---|---|
| Problem statement | **PNC3 – Secure Agent Tool Gateway** |
| Theme | Cybersecurity and Threat Intelligence |
| Organiser | Career Development Center, Narsimha Reddy Engineering College (NRCM), an autonomous institution, affiliated to JNTUH, approved by AICTE |
| Format | Four levels (L1 idea & architecture → L2 MVP → L3 intelligence, security & deployment → L4 scale & reliability) |
| Our one-line idea | A zero-trust proxy that decides **allow, deny or require-approval** for every AI agent tool call |
| Pitch line | **"Go code extracts facts, Cedar policy decides, Docker contains, and every decision is signed."** |
| Closing line (deck) | "The model can be persuaded. The gateway decides what a persuaded agent is allowed to do." |
| Current phase | Level 1 (idea, architecture, planning). Deck exists (v1) and has been reviewed; fixes are pending. |

---

## 2. Files in this project

| File | What it is | Status |
|---|---|---|
| `PNC3.md` / problem statement PDF | Official problem statement (summarised in full in §3) | Reference |
| `PNC3_Secure_Agent_Tool_Gateway.pptx` | Our 16-slide pitch deck (generated by Claude in an earlier session) | v1, needs fixes listed in §9 |
| Research document (pasted as text, no filename) | Full research report: winners, incidents, competitors, SRS, stack, roadmap (summarised in §6) | Needs updates listed in §9 |
| `README.md` | This file | Keep updating |

**Re-upload the deck and this README in every new session.** The problem statement and research document are summarised here, so re-uploading them is optional.

---

## 3. Problem statement (PNC3), full summary

**Problem statement:** Build a robust security gateway that intercepts and strictly validates AI agent tool calls, parameters and data destinations to prevent unauthorised execution and data exfiltration.

**Description:** Enterprise AI agents with access to APIs, databases and internal tools are prime targets for prompt injection and manipulation. A compromised agent could execute destructive commands or route sensitive data to unauthorised destinations. The gateway must be a **zero-trust proxy** between agent and execution environment that dynamically inspects every tool call, validating **exact parameters, data destinations, permissions and runtime context** before allowing execution. It must defend against adversarial edge cases (**parameter smuggling, payload obfuscation**) and use **measurable evaluation frameworks** to enforce strict security **without unacceptable latency**.

**Features & requirements (the five judged areas):**
1. **Multi-component architecture:** a low-latency **proxy layer**, a **dynamic policy engine** and an **execution harness** to intercept, inspect and route tool calls.
2. **Deep parameter & destination validation:** context-aware inspection of arguments, payloads and outbound destinations for least privilege.
3. **Adversarial resilience:** detect and block parameter smuggling, obfuscated payloads and prompt injections hijacking tools.
4. **Zero-trust execution guardrails:** automatically block unauthorised actions, destructive commands and leaks to unverified endpoints.
5. **Production-ready evaluation:** auditing that tracks **validation accuracy, false-positive blocking rate and latency**.

**Levels (official deliverables):**
- **L1 – Idea, architecture & planning:** SRS, system architecture and **data flow diagrams**, **UI wireframes**, finalised tech stack and roadmap.
- **L2 – Core functionality:** MVP, **database schemas**, primary business logic, essential APIs, a functional app where users complete core tasks.
- **L3 – Intelligence, security & real deployment:** advanced algorithms or AI features, authentication, encryption, CI/CD, cloud launch.
- **L4 – Scalability, reliability & enterprise readiness:** Docker/Kubernetes autoscaling, caching, monitoring and alert dashboards.

---

## 4. Current deck (v1): slide-by-slide

16:9 at 10" × 5.625". **Palette:** navy background `0E1B2C` / `1B2E45`, body text `1A2433`, muted text `5B6B7F`, card fill `EEF2F6`, card border `D5DDE6`, accent orange `F2A83B`, ALLOW teal `1F9D8B`, DENY red `D64545`, white. **Fonts:** Arial (headings), Calibri (body). Clean, no overflow found in v1.

| # | Title | Content summary |
|---|---|---|
| 1 | Secure Agent Tool Gateway | Title, one-liner, ALLOW / DENY / APPROVE? chips; "PNC3 · Cybersecurity and Threat Intelligence · NRCM CDC Hackathon". **No team names yet.** |
| 2 | Agents turn a hidden sentence into a real action | Lethal trifecta (private data, untrusted content, outbound channel), Simon Willison; Meta "Agents Rule of Two"; MCP spec says it can't enforce safety at protocol level. |
| 3 | The 2026 record, in four numbers | ~47,000 backdoored LiteLLM downloads in ~3 h (Mar 2026); 492 unauthenticated MCP servers (Trend Micro); 43% of MCP servers vulnerable to command injection (cited as arXiv 2604.23338, **suspect: see §12**); 75% of Unit 42 incidents had evidence in logs. |
| 4 | Real incidents: each was an unchecked tool call | Timeline: OpenClaw (Feb 26), LiteLLM/TeamPCP (Mar 26), Vertex AI "Double Agent" (Mar 26), GrafanaGhost (Apr 26), Sentry MCP agentjacking (Jun 26), Hugging Face intrusion (Jul 26). Notes mention postmark-mcp, EchoLeak CVE-2025-32711, Cursor CVE-2026-22708. |
| 5 | Where the systems are failing | Five gaps: no trust boundary in context; broad credentials; tool metadata trusted and mutable; hijack looks like a healthy run; allowlists check names, not arguments. |
| 6 | Why we locked PNC3 | Compared with PNC1 (AI SOC) and PNC2 (supply-chain attack graph); PNC3 needs no private dataset, allows a live demo, and gives measurable results. |
| 7 | What past winners did | Solo.io MCP hackathon 2026, DARPA AIxCC 2025, Neurobots (TUESDAY, Aug 2026), IEEE SA 2026 (Maya). |
| 8 | Policy, allowlists and signed logs already exist | Competitors (Microsoft Agent Governance Toolkit, ScopeBlind/obsigno, agentgateway/Bifrost, AWS Bedrock AgentCore Gateway, Meta LlamaFirewall, Snyk Agent Scan/Cisco mcp-scanner) + CaMeL callout (77% vs 84% AgentDojo). |
| 9 | Our angle | Argument provenance, cross-call data-flow rules, manifest pinning, credential isolation, published benchmark. |
| 10 | Every call passes one deny-by-default pipeline | Agent → 1 Authenticate → 2 Check manifest hash → 3 Canonicalize + decode → 4 Validate schema, path, URL, secrets → 5 Cedar policy + provenance → ALLOW / APPROVE? / DENY. Signed hash-chained audit log; classifier may only escalate. |
| 11 | Tech stack | **Outdated** (Python + FastAPI + Cedar). Replace with §7. |
| 12 | MVP: ten features | MCP proxy, Cedar engine, canonicalizer, destination guard, secret scanner, manifest pinning, approval queue, signed audit log, live dashboard, benchmark runner. |
| 13 | Demo and evaluation plan | Six-step demo; metrics (block rate, FP rate, p50/p95/p99, reason codes); baselines (a) no gateway, (b) allowlist only, (c) full, (d) full + classifier. |
| 14 | Roadmap across the four levels | L1–L4 columns; build order: passthrough proxy → validators → Cedar deny path → signed log + dashboard → approvals + pinning → benchmark. |
| 15 | Risks we are managing | "Just another MCP gateway"; blocking benign calls; latency in Python (**outdated**); unbacked claims; scope creep. |
| 16 | Closing | Closing line + key sources. |

---

## 5. Review of deck v1 against PNC3 (done 30 Sep 2026)

**Coverage:** all five feature areas are covered (parameter/destination validation, adversarial resilience and guardrails are strong). Gaps are mainly the **L1 deliverables**.

| PNC3 item | Status in v1 |
|---|---|
| Proxy + policy engine | Covered |
| Execution harness | **Not named anywhere** |
| Deep parameter & destination validation | Strong |
| Adversarial resilience | Strong |
| Zero-trust guardrails | Strong |
| Evaluation metrics | Good, but **no latency target** and the word "accuracy" is missing |
| L1 SRS | **Missing** (only in the research doc) |
| L1 data flow diagram | **Partial** (slide 10 is a pipeline, not a DFD) |
| L1 UI wireframes | **Missing** |
| L1 tech stack + roadmap | Present (stack slide outdated) |
| L2 DB schemas | Not on the roadmap |

**Other issues found:**
- Slide 9 calls provenance and cross-call data-flow rules "our angle", but slide 12 notes and the roadmap push them to L3, so the differentiator isn't in the MVP. Fix: a minimal taint rule in L2 (values from tool output are untrusted; they can't be sent to destinations the user didn't provide), full provenance in L3.
- Slide 13 subtitle ("Numbers go on the final slide only after our own benchmark run") and slide 12 ("The one slide with real numbers") read like internal notes.
- Slide 10: the only down-arrow runs from step 5 straight into DENY, so it looks like everything is denied. Fan it out to all three outcomes; show that failures at steps 1–4 short-circuit to deny.
- Slides 6–7 are the first to cut if slides are limited.
- Sources to re-verify: see §12.

---

## 6. Research document: condensed record

*(Written by Claude in an earlier session; pasted back by us. Key content kept here so it isn't lost.)*

### 6.1 Past winners (lessons)
- **Solo.io Hackathon for MCP & AI Agents (Feb–Apr 2026):** Secure & Govern winner Huzefa Hamdard (India): Kubernetes-native MCP governance, per-server security score, agentgateway + kagent, Gemini/Ollama risk analysis. Runner-up Mehmet Hilmi Emel (Turkey): **MCP.STORE**, agentgateway + **Keycloak JWT** + CEL rules at the MCP protocol level, Google ADK. Open-source winners (Kevin Cao, Yitaek Hwang, Jaden Lee): 9 PRs making agentgateway identity-aware (OTel, multi-provider). Building Cool Agents runner-up Oswaldo Gomez (Poland): clinical MCP federation on MIMIC-IV.
- **DARPA AIxCC Final (DEF CON 33, Aug 2025):** Team Atlanta $4M, Trail of Bits $3M, Theori $1.5M; AI agents + fuzzing/program analysis; 86% of synthetic bugs found, 68% patched, ~$152 per task.
- **AWS AI Agents Hackathon (SF, late 2025):** AgentSafe was highlighted (placement not stated): pre-flight MCP server risk check (Vanta, Semgrep, Bedrock).
- **Lessons:** enforce at the protocol boundary; deterministic rules decide and AI only scores or explains; show numbers.

### 6.2 Incidents mapped to fixes
| Date | Incident | Failure | Gateway fix |
|---|---|---|---|
| Apr 7 2026 | GrafanaGhost | Outbound image URL carried data | Destination allowlist; block data-bearing query strings |
| Apr 7 2026 | Flowise CVE-2025-59528 (12–15k instances) | JS injection via CustomMCP config | Schema-validate configs; sandbox |
| Mar 31 2026 | Vertex AI "Double Agent" (Unit 42) | Excess default service-account permissions | Per-agent, per-tool least privilege; short-lived creds |
| Mar 2026 | Meta internal agent leak (~2 h) | No policy check on an access change | Human approval for permission changes |
| Mar 19–24 2026 | TeamPCP → Trivy Actions, Checkmarx, LiteLLM 1.82.7/1.82.8 | Non-atomic credential rotation | Pin packages; the gateway limits reach |
| Feb 23 2026 | OpenClaw inbox deletion | No confirmation; ignored stop | Destructive-action gate + kill switch |
| Jan–Feb 2026 | ClawHavoc: 824 malicious skills (vendor-reported) | No signing or scanning | Signed, pinned tool manifests |
| Dec 2025–Feb 2026 | Mexican government breach (~150 GB) | Unpatched systems; AI sped up recon | (PNC1 territory) |
| 2026 | Cursor CVE-2026-22708 | Allowlisted `git` commands carried payloads | Validate full argv + environment |
| 2025 | postmark-mcp | 15 clean versions, then an exfiltration BCC | Outbound destination policy |
| Jun 2025 | EchoLeak CVE-2025-32711 (M365 Copilot, CVSS 9.3) | Zero-click indirect injection | Taint tracking to external sinks |

Common thread: the lethal trifecta was present in every case; name-only allowlists fail; OWASP notes most AI incidents get no CVE because they're design failures.

### 6.3 Why PNC3 over PNC1 / PNC2
PNC3 has the highest urgency, needs only self-generated traffic, and gives high measurability (attack corpus + latency), a clear live demo and medium build risk. PNC1 needs realistic telemetry, is a crowded space, and its report quality is subjective. PNC2 needs SBOMs/configs, and path correctness is hard to prove. Weakness of PNC3: an active vendor market, so we must win on depth of validation plus honest benchmarks.

### 6.4 Competitors and our gap
LlamaFirewall (Meta; probabilistic, not a proxy); Invariant Guardrails (Snyk-acquired; custom DSL, no obfuscation decoding); Snyk Agent Scan (scan-time only); Docker MCP Gateway (isolation, not argument validation); agentgateway (Solo.io, Rust; deep checks left to you); Bifrost (Maxim; vendor claims 11 µs at 5k RPS); TrueFoundry (closed); Lakera Guard (Check Point; claims <50 ms); LLM Guard (Palo Alto; stale since May 2025); NeMo Guardrails (NVIDIA; dialog-oriented); enterprise platforms (Prisma AIRS, F5/CalypsoAI, Cisco AI Defense, Prompt Security, Pillar, Straiker); **CaMeL** (DeepMind/ETH; 77% vs 84% AgentDojo; needs an agent rewrite).
**Positioning:** a framework-agnostic, open, deterministic-first gateway with CaMeL-style data-flow labels at the proxy, adversarial normalisation and a reproducible benchmark. Classifiers are a second opinion only.

### 6.5 SRS core
- **Scope:** MCP `tools/call` over Streamable HTTP, manifests, policy authoring, approvals, audit, benchmark. Out of scope: fine-tuning, chat-layer prompt filtering, non-MCP protocols.
- **Actors:** AI agent, human principal, security admin, tool server, attacker.
- **Functional requirements:**
  - FR-1 intercept all `tools/call` and `tools/list`
  - FR-2 short-lived JWTs
  - FR-3 canonicalise before checks
  - FR-4 pinned JSON Schema validation
  - FR-5 destination allowlists + private/metadata IP block
  - FR-6 allow/deny/approval with rule ID and reason
  - FR-7 approval hold with timeout = deny
  - FR-8 quarantine on description change
  - FR-9 label outputs; block private→external flows in untrusted sessions
  - FR-10 log everything; live feed and search
  - FR-11 kill switch in under 1 s
  - FR-12 benchmark exports CSV and a table
- **Data model:**
  - Agent (agent_id, owner, allowed_tools[], scopes, status)
  - Tool (tool_id, server_url, schema, description_hash, risk_level, destructive)
  - Policy (policy_id, version, **cedar_source** *(was rego_source; changed, see §10)*, active)
  - Decision (decision_id, timestamp, agent_id, tool_id, args_hash, canonical_args, verdict, rule_id, reason, latency_ms per stage)
  - Approval (approval_id, decision_id, approver, outcome, decided_at)
  - SessionTaint (session_id, labels[], sensitive_fingerprints[], ttl)
- **Admin API:**
  - `POST /mcp` (agent endpoint)
  - `POST /admin/tools`
  - `PUT /admin/policies/{id}`
  - `GET /admin/decisions`
  - `POST /admin/approvals/{id}`
  - `POST /admin/agents/{id}/revoke`
  - `GET /metrics`
- **Threat model (OWASP Agentic Top 10 2026):**
  - ASI01 goal hijack → taint, destination policy, approval
  - ASI02 tool misuse → schema, scopes
  - ASI03 identity/privilege abuse → JWT, least privilege, secret brokering
  - ASI04 supply chain → manifest pinning
  - ASI05 code execution → sandbox, argv/env validation
  - ASI10 rogue agent → rate limits, kill switch
  - Gateway attacked → fail closed, size limits, mTLS-only tool servers

### 6.6 Request pipeline (11 stages)
1. Authenticate (JWT → agent, principal, session, scope)
2. Strict parse (reject malformed JSON-RPC, duplicate keys, oversize, unknown fields)
3. Canonicalise (NFKC, strip zero-width/bidi, bounded recursive decode, path resolve, URL → scheme/host/IP)
4. Validate against the pinned manifest (schema + description hash; rug pull → quarantine)
5. Check destinations (resolve; allowlist; block private/metadata ranges)
6. Taint / data flow (private-labelled data to an external sink in an untrusted session → block or approve)
7. Policy decision (allow / deny / approval + rule ID)
8. Optional risk score (classifier + sequence rules; can escalate, never override a deny)
9. Execute in the harness (credentials injected; sandbox)
10. Inspect the response (injection markers, secrets; label untrusted)
11. Audit + per-stage trace span

### 6.7 Evaluation
TP = attacks blocked, FN = attacks allowed, FP = benign blocked, TN = benign allowed.
- **Block rate (recall)** = TP/(TP+FN)
- **FP rate** = FP/(FP+TN)
- **Added latency** at p50/p95/p99 (deterministic and classifier paths reported separately)
- **Task utility** = share of benign tasks still completed (CaMeL-style trade-off)
- Add **precision / accuracy** wording to match the statement's "validation accuracy".

Corpus categories: direct injection, indirect injection in tool output, Base64/percent/hex encodings, homoglyph/zero-width, path traversal, SSRF to metadata IPs, allowlisted-command abuse, exfiltration via URL query, rug pull, destructive action without approval. Use canary tokens and benign markers only, never live malware.

### 6.8 Demo script (5 min)
1. Benign task: read a ticket, email a summary to an allowlisted colleague → allowed (show the measured ms).
2. Indirect injection in the ticket → email the customer DB outside → blocked at the destination check, rule shown.
3. Obfuscated retry (Base64 + homoglyph domain) → still blocked.
4. `delete_all_emails` → held for approval → presenter denies.
5. Tool description swapped → quarantined on the next `tools/list`.
6. Benchmark table + latency histogram.
Extra jury moment: **edit a Cedar rule live and watch a call flip from allow to deny.**

### 6.9 Suggested team split (4 people)
(1) proxy + canonicaliser, (2) policies + taint, (3) dashboard + approvals, (4) attack corpus + benchmark + demo agent.

---

## 7. FINAL TECH STACK (locked 30 Sep 2026)

### Level 2: Core MVP
| Component | Pick |
|---|---|
| Proxy language | **Go** (`net/http`, `log/slog`) |
| MCP handling | Official **MCP Go SDK**, Streamable HTTP first (stdio via wrapper later) |
| Policy engine | **Cedar via `cedar-go`** (pure Go, official cedar-policy org), in-process, hot reload via `fsnotify` |
| Approval outcome | `@approval("required")` annotation on permit policies (see §8) |
| Strict parsing | Explicit **duplicate-key check** (Go `encoding/json` silently keeps the last duplicate), size limits, unknown fields rejected |
| Argument validation | JSON Schema 2020-12 (`santhosh-tekuri/jsonschema`) |
| Canonicaliser | `golang.org/x/text/unicode/norm` (NFKC), zero-width/bidi stripping, bounded recursive percent/Base64/hex decode, Unicode confusables table, `net/url`, `path/filepath` |
| Destination guard | DNS resolve → `net/netip` CIDR checks (private, link-local, 169.254.169.254) |
| Secret scanner | Gitleaks detection rules |
| **Execution harness** | Docker per tool server: no network, read-only FS, dropped capabilities, CPU/time limits (**L2, minimal**) |
| Identity | Keycloak JWT, verified with `coreos/go-oidc` |
| Audit log | `crypto/ed25519` + SHA-256 hash chain → PostgreSQL (JSONB) via `pgx` |
| Session / kill switch | Redis (`go-redis`) |
| Dashboard | React + Vite + Tailwind, WebSocket live feed |
| Local deploy | Docker Compose |

### Demo & evaluation (also L2)
| Purpose | Pick |
|---|---|
| Demo agent | Any MCP-capable agent on a local model via **Ollama** |
| Mock tools | 4–5 MCP servers (email, file, DB, HTTP fetch, shell) in the **Python MCP SDK** (shows the gateway is framework-agnostic) |
| Attacker server | Local HTTP endpoint logging leaks (canary tokens only) |
| Corpus | Own JSONL + AgentDojo-derived tasks + benign corpus |
| Fuzzing | `go test -fuzz` on the canonicaliser |
| Latency | k6 (p50/p95/p99) |
| Regression | promptfoo |

### Level 3
| Component | Pick |
|---|---|
| AI feature | PromptGuard 2 (22M) as a Python sidecar, **escalate-only** |
| Provenance | Full session taint tracking (Redis) |
| Credentials | Secret brokering (gateway injects after allow) |
| Transport | TLS everywhere; mTLS gateway ↔ tool servers |
| CI/CD | GitHub Actions **pinned by commit SHA**, `golangci-lint`, `govulncheck`, Trivy, Cedar CLI policy validation |
| Cloud | One VM (student credits provider) with Docker Compose |

### Level 4
Kubernetes (k3s or managed) + HPA · Redis cluster caching (decisions, DNS) · OpenTelemetry + Prometheus + Grafana + Alertmanager · gVisor (`runsc`) sandbox · k6 load test to a stated RPS.

### Non-functional targets (design goals, to be measured)
- Added latency p50 **< 10 ms**, p99 **< 50 ms** (deterministic path; classifier path reported separately)
- **Fail closed** on any decision-path error
- Kill switch **< 1 s**
- Support MCP spec **2026-07-28** (newest; Go SDK v1.7.0+) while keeping **2025-11-25** compatibility

### Deliberately excluded
OPA, CEL, Kafka/RabbitMQ, vector DB, one microservice per check. Rewriting in another language at L4 is also out (Go from the start avoids it).

---

## 8. Cedar decisions and example policies

**Why Cedar (for the jury):** it reads almost like English; **`forbid` always beats `permit`** (zero-trust built into the language); and it is designed for automated-reasoning analysis. Rego is more expressive but harder to read on a slide.

**Design constraints and our answers:**
- Cedar returns only Allow/Deny → we use an `@approval("required")` annotation. If the decision is Allow and a determining policy has the annotation, the gateway holds the call. A forbid still wins, so approval can never unblock a denial.
- Cedar has no regex (only `like` wildcards) → Go code extracts **facts** (decoded recipient domain, is_private_ip, taint labels, etc.) into `context`; Cedar decides on clean facts. Slogan: **"Code extracts facts, policy decides."**
- `cedar-go` lags the Rust implementation on some features (check its README list) → validate policies in CI with the Rust Cedar CLI.

**Example policies (for the slide; 3–4 of these):**
```cedar
@id("block-tainted-exfil")
forbid (principal, action == Action::"send_email", resource)
when { context.session_tainted && !context.recipient_allowlisted };

@id("destructive-needs-approval")
@approval("required")
permit (principal, action in [Action::"delete_email", Action::"run_shell"], resource);
```
Still to write: metadata/private IP block, manifest quarantine rule.

---

## 9. Pending fixes (not done yet)

**Deck:**
- [ ] Slide 1: add team name, member names and college
- [ ] Slide 11: replace the stack with §7 (Go + cedar-go + Docker harness row)
- [ ] Slide 10: fan the arrow out to all three outcomes; show steps 1–4 failing → deny; consider naming the execution harness
- [ ] Slide 12: reword "The one slide with real numbers"; ensure minimal taint rule is in the MVP
- [ ] Slide 13: reword the subtitle (e.g. "All metrics come from our own rerunnable benchmark"); add precision/accuracy
- [ ] Slide 14: add DB schemas to L2; move minimal harness + minimal taint into L2
- [ ] Slide 15: replace "Latency in Python" with "Team ramp-up on Go"
- [ ] **New slides:** UI wireframes (live feed, approval queue, policy editor, benchmark view); data flow diagram (agent, gateway, policy store, credential vault, tool servers + harness, audit DB, dashboard, human approver); SRS summary (key FRs + NFR targets); Cedar policies slide
- [ ] Optional: cut slides 6–7 if slide count is limited
- [ ] Verify the sources in §12 before presenting

**Research document:**
- [ ] Stack section: Go + OPA → **Go + cedar-go**; drop CEL
- [ ] Data model: `rego_source` → `cedar_source`
- [ ] Roadmap: sandbox harness **L3 → L2 (minimal)**
- [ ] Add the duplicate-key check to strict parsing
- [ ] MCP spec reference: add 2026-07-28

---

## 10. Decisions log (settled unless reopened)

| # | Decision | Reason |
|---|---|---|
| D1 | Chose **PNC3** over PNC1/PNC2 | Strongest incident record, self-generated data, live demo, measurable |
| D2 | Deterministic core decides; ML classifier is escalate-only | Explainable, provable with tests; classifiers can be fooled |
| D3 | **Go** for the proxy (not Python) | Latency targets; avoids an L4 rewrite; in-process policy |
| D4 | **Cedar** (not OPA) via `cedar-go` | Must show policies to the jury; readability; forbid-wins |
| D5 | Approval via `@approval` annotation | Cedar has only Allow/Deny |
| D6 | Execution harness in **L2 (minimal)** | Named in the problem statement as a core component |
| D7 | Minimal taint rule in L2, full provenance in L3 | Differentiator must appear in the MVP |
| D8 | Build our own proxy (not extend agentgateway) | Our contribution is the inspection logic; keeps the work clearly ours |
| D9 | PostgreSQL + Redis from L2 | Consistency with the research doc; Redis needed for kill switch |
| D10 | Claims only from our own benchmark run; label secondary sources | Credibility with judges |

**Superseded:** (a) the deck's Python + FastAPI + Cedar stack; (b) the research doc's Go + OPA + CEL stack; (c) Claude's interim "Python + Cedar, SQLite first" answer. All are replaced by §7.

---

## 11. Next steps

Waiting for instructions from us. Likely next tasks, in order:
1. Apply the §9 deck fixes and add the new L1 slides (wireframes, DFD, SRS, Cedar policies) → deck v2
2. Update the research document per §9
3. Write the full SRS document (L1 deliverable)
4. Draw the architecture and data flow diagrams
5. Draft the dashboard wireframes
6. Write the first real Cedar policy set + context schema
7. Start L2: passthrough proxy → validators with tests → Cedar deny path → signed log + dashboard → approvals + pinning → benchmark

---

## 12. Verification notes and caveats

- Claude's reliable knowledge ends around **June 2026**. Items dated after that (Hugging Face intrusion Jul 2026, TUESDAY/Neurobots Aug 2026, MCP spec 2026-07-28) came from search results or earlier research. **Open the source links once before presenting.**
- **43% command-injection figure (slide 3):** attributed to arXiv 2604.23338 on the slide. Claude recalls it originally came from a 2025 security-firm scan. Verify or re-cite.
- Trend Micro "492" and the Sentry MCP item came via secondary write-ups.
- Vendor performance claims (Bifrost, Lakera, Straiker) are self-reported.
- Mexico breach dates differ by source; shown as a range.
- AgentSafe was "highlighted", not confirmed as a winner.
- CaMeL 77% vs 84% on AgentDojo is from the paper's updated version.
- Latency targets are **our design goals**, not measured facts.
- No dark-web sources were used; the attack corpus uses canary tokens only.

---

## 13. Instructions for Claude in the next session

- Read this whole file first. Don't re-litigate §10 decisions unless we ask.
- If the deck is re-uploaded, check it against §4 to confirm the version before editing.
- Keep the deck's palette and fonts (§4) for any new slides.
- After completing any task, **update this README** (relevant sections + §9 checkboxes + §11 + §14 changelog), bump the version, and give us the new file.
- Use web search for anything time-sensitive (library versions, MCP spec, incident details).

---

## 14. Changelog

| Version | Date | Change |
|---|---|---|
| v2 | 30 Sep 2026 | Reviewed Umesh's Groq version; Level 2 fixes; full Level 3 build (auth, HTTPS, RDS TLS, hardened harness, CI/CD, AWS guide) verified in production mode; delivered agentshield-level3.zip. |
| v1 | 30 Sep 2026 | Created. Captures problem statement, deck v1 review, research doc summary, final stack (Go + cedar-go + Docker harness), Cedar design, decisions, pending fixes, next steps. |
