# Level 2 fixes and Level 3 build — what changed and how it was verified

Base: Umesh's `V1-WorkingCopy` branch (Groq policy generator, agent console,
registry controls, SQLite CRM, restricted shell). Everything below was built on
top of it and **verified by running it**, not only by reading code.

## Level 2 fixes

| # | Problem found in review | Fix | Verified by |
|---|---|---|---|
| 1 | `policy_test.go` declared `package policy` twice, so `go test` failed to compile | Removed the duplicate line | `go test ./...` passes |
| 2 | **`run_shell` could read files outside its sandbox**: `cat ../../.env` returned the real `.env` (with the Groq key); `/proc/self/environ` was readable. Only the human-approval prompt stood in the way | Every `ls`/`cat` path argument must resolve inside the sandbox | `tools/test_workspace.py` (5 tests) + the same attack through the gateway |
| 3 | Dashboard "Run benchmark" looked for the corpus relative to the binary's parent folder — right locally, wrong in Docker | Explicit corpus, output and gateway paths from the working directory and config | Button run in production mode: 100% contained, 0% FP |
| 4 | `approval_requests` metric was always 0 (held calls are logged under their final verdict) | Count decisions whose record carries an approval outcome | Metrics showed `approval 3` after the demo |
| 5 | Nine stray debug files and runtime state (`crm.sqlite3`, sandbox files, `__pycache__`) were committed | Deleted / untracked; `.gitignore` updated | `git status` |
| 6 | An AI-generated `permit(principal, action, resource);` is valid Cedar, passes validation, and bypasses the tool allowlist | The generator now returns warnings for unconditional permits and for replacements that remove forbid rules; the UI shows them before saving | Code path + UI message |
| 7 | Local Docker stack: tool servers crashed on start (non-root user could not create `/sandbox`, `/data`), policy saving failed (config mounted read-only), benchmark button failed on Linux (results bind mount not writable) | Directories created in the tools image; named volumes for state, results and policies | Real `docker compose up --build`: 7/7 containers up; demo, bench button and policy save all work |
| 8 | Startup race: the gateway exited if the database wasn't ready yet, and Caddy gave up waiting, so HTTPS never came up although `deploy.sh` reported success | Gateway retries the database for 60 s; Caddy no longer waits on gateway health; gateway waits for local Postgres when that profile is used | Production stack restarted clean: 8/8 up, **0 gateway restarts** |
| 9 | The Groq key travelled inside the zip | Not committed to git (checked history). **Action for the team: rotate it** (DEPLOY_AWS.md step 0) | — |

## Level 3 build

**Authentication.** Dashboard sign-in with a bcrypt-checked password and a signed
session cookie (`HttpOnly; Secure; SameSite=Strict`, 8 hours). Every state-changing
request needs the `X-Aegis-CSRF` header, which other websites cannot send. Logins
are throttled to 5 per minute per client, and successes, failures and throttling
are written to the signed audit log. The WebSocket authenticates with the cookie;
tokens in URLs are no longer accepted. Scripts and CI keep using the
`ADMIN_TOKEN` bearer header.

**Production secret guard.** With `GATEWAY_ENV=production`, the gateway refuses to
start if any secret is a development default or shorter than 32 characters, and
lists what is wrong. A forgotten default can't reach the public server.

**Encryption.** Caddy provides HTTPS with automatic Let's Encrypt certificates,
HSTS, a strict Content-Security-Policy, and `X-Frame-Options: DENY`. `/metrics` is
hidden from the internet. The gateway connects to RDS with
`sslmode=verify-full` against Amazon's CA bundle. RDS storage and the EC2 disk
are encrypted at rest.

**Execution harness (now real containment).** In production, the tool servers run
read-only, as non-root, with every Linux capability dropped, `no-new-privileges`,
memory and process limits, and on an internal Docker network **with no route to
the internet**. Even a compromised tool can't phone home. Only Caddy publishes ports.

**CI/CD.** `.github/workflows/ci-cd.yml`: vet → unit tests → `govulncheck` →
sandbox tests → dashboard build → both images to GitHub Container Registry →
copy `deploy/` to EC2 and roll out. Every third-party action is pinned by commit
SHA (the TeamPCP lesson).

**Cloud.** One EC2 host running Docker Compose (Caddy, gateway, 3 tool servers,
attacker sink, Redis with a password) + Amazon RDS PostgreSQL for the audit log.
`deploy/setup_ec2.sh` prepares a fresh server and generates all secrets;
`deploy/check_rds.sh` proves the TLS connection; `deploy/deploy.sh` rolls out;
Plan B builds on the server; Plan C uses a local Postgres.

## Verification (run in this environment)

| Check | Result |
|---|---|
| Go tests | 23 passing (auth, config guard, canon, inspect, policy, rpc) |
| Python sandbox tests | 5 passing |
| `go vet`, `govulncheck` | clean; 0 vulnerabilities reachable from our code |
| `actionlint` on the workflow | clean |
| `docker compose config` (pull, build and local-DB modes) | valid |
| All base images exist | golang:1.26, node:22-alpine, python:3.12-slim, caddy:2.10-alpine, redis:7-alpine, postgres:16-alpine, distroless |
| Production guard with default secrets | refuses to start, lists 5 problems |
| Full production mode behind Caddy HTTPS | security headers present; `/metrics` 404 outside; admin API 401 without login; old dev token 401; wrong password 401; login sets `Secure; HttpOnly; SameSite=Strict`; POST without CSRF 403, with CSRF 200; WebSocket 101 with cookie, 401 without; brute force → 429 |
| Audit log in Postgres over TLS (RDS stand-in, `sslmode=verify-ca`) | connection `ssl=true TLSv1.3`; hash chain verifies |
| Demo (5 steps) in production mode | all verdicts as expected |
| Benchmark from the dashboard button | full profile: 100% contained, 0% false positives, p50 0.54 ms, p99 0.81 ms |
| Browser login flow (headless Chromium over HTTPS) | wrong password shows an error; correct password opens the console; live stream connects; no console errors |

| **Real Docker: development stack** (`docker compose up --build`) | 7/7 containers up, gateway healthy; login, demo (6 verdicts), bench button, policy save; audit chain valid in Postgres; attacker sink received nothing |
| **Real Docker: production stack** (`deploy/`, local-Postgres mode) | 8/8 up; HTTP→HTTPS 308; `/metrics` 404; login 200; exfiltration denied over HTTPS; rug-pull helper works; bench 100% / 0% FP |
| **Harness isolation (inside the comms container)** | uid 10001; root filesystem read-only; **internet blocked**; effective capabilities `0000000000000000`; no_new_privs = 1; gateway reachable on the internal network |

Docker tests used a test-only copy of the Dockerfiles that trusts this build environment's network proxy certificate; otherwise identical (verified by diff). Your machine and AWS don't need it.

**Not verifiable here:** a real AWS account, real RDS, real Let's Encrypt issuance
and GitHub Actions runners. Those are covered by the step-by-step guide and its
troubleshooting table. The Postgres TLS path was tested with `verify-ca` against a
local server; RDS uses `verify-full` with Amazon's bundle, which pgx supports the
same way.

## What to say to the judges (Level 3)

- **AI:** "Groq writes the rules and drives a live agent; deterministic code
  enforces them. The model is never in the per-call decision path, so enforcement
  stays sub-millisecond and fail-closed."
- **Authentication:** "Bcrypt login, HttpOnly Secure SameSite-Strict cookie, CSRF
  header, throttled and audited logins. Machines use separate tokens."
- **Encryption:** "HTTPS with HSTS at the edge, verified TLS to RDS, encryption at
  rest for the database and the disk."
- **Secure by default:** "In production the gateway refuses to boot with a default
  or weak secret." Show the error message; it lands well.
- **Harness:** "The tool containers have no internet route at all, are read-only,
  and have no Linux capabilities. Policy stops the call; the harness contains
  anything that slips through."
- **CI/CD:** "Every push is tested, scanned and deployed. Actions are pinned by SHA
  because tags can be hijacked — that's how the TeamPCP campaign spread."

---

## Round 3: merge with Umesh's version, UI/UX pass, review fixes

**Merge.** Umesh's version was built on the first Level 3 zip, before the real-Docker
test round, so it lacked four fixes. They are ported back: database retry on startup,
`/sandbox` and `/data` in the tools image, production compose dependency fixes, and the
rewritten local `docker-compose.yml`. Umesh's additions are kept: per-page URLs
(`/home`, `/agent`, `/tools`…, so Back works), Windows support in the Makefile and the
benchmark button, approval events in the audit log, and new tests.

| # | Problem | Fix | Verified by |
|---|---|---|---|
| 1 | **A real Groq key was in `deploy/.env.example`**, a template meant for git | Blanked. **Rotate that key** | secret scan of the zip: 0 keys |
| 2 | Mobile navigation broke: nav items became links, but the mobile CSS still targeted buttons, so labels wrapped, numbers showed and items ran off-screen | A proper mobile menu: Menu button, two-column page grid, Escape closes it, closes after navigating, approval badge on the button | headless Chromium at 390 px |
| 3 | **No Log out on mobile** (the header chips were hidden) | Account chip and Log out inside the mobile menu | browser test: logout returns to sign-in |
| 4 | Stat strip left an empty grey cell on narrow screens ("stat deny container"); and allowed + blocked + held didn't add up to the total | Flex rows that always fill; labels "human reviews — counted in final verdict" and "total decisions — allowed + blocked" | screenshots at 390 / 1366 px |
| 5 | Logo styled two ways (sidebar vs login), no favicon, tab title not branded | One `BrandMark`/`BrandLockup` component everywhere; matching `favicon.svg`; title "AgentShield · Secure Agent Tool Gateway" | screenshots; favicon served 200 |
| 6 | Tool registry table cut off on phones; policy names wrapped 4–5 lines | Tables scroll horizontally inside their panel on small screens | overflow audit: 0 pages overflow at either size |
| 7 | Audit records broke one word per line on phones | Description spans the full row | screenshot |
| 8 | **Approval outcome never reached the RDS audit log**: held and outcome events shared one id, and the PostgreSQL table requires unique ids | Distinct ids per stage; regression test | real PostgreSQL: events `pending, denied`, 0 append errors |
| 9 | Approval events didn't appear in the live feed | Feed now shows them | code path |
| 10 | 108 exported Go identifiers and 16 React components had no documentation | Doc comment on every one (Go convention: starts with the name) | scan: 0 undocumented |

**Verification of the merged build:** `gofmt` clean; `go vet` clean; 8 Go test packages
+ 5 Python sandbox tests pass; `actionlint` clean; demo ALLOW + 5×DENY; benchmark full
profile 100% contained, 0% false positives, p99 0.58 ms; real `docker compose up --build`:
7/7 containers, gateway healthy, login, favicon, deep links and audit chain all verified.

---

## Round 4: human approval demo, agent console, agent guardrails

**Demo.** `demo/run_demo.py` now has six steps. Step 4: a human **denies**
`delete_all_emails`. Step 5 (new): a human **approves** `run_shell ls`, which then
really runs and returns the file list. Run with `--human` to click Approve / Deny
yourself in the dashboard instead of the script deciding.

**Agent console.**
- Real agent loop: plan → tool calls through the gateway → results back to the model
  → final answer (at most 4 steps). Before, the model never saw tool results and gave
  no real answer.
- **Inline approval:** when the gateway holds a call, an Approve / Deny card with a
  countdown appears inside the conversation. Previously, approving meant leaving the
  console, which lost the result.
- One-click examples: Normal task, Needs a human, Prompt injection, Off-topic.
- Fixed a latent bug: tool results lost their `tool_call_id`, which model providers reject.
- Approve / Deny buttons were pale and looked disabled; now solid green and red.

**Agent guardrails** (`internal/gateway/agent_guard.go`). Stated in the system prompt
*and* enforced in code, so they hold even if the model ignores the prompt:

| Guardrail | Enforced by |
|---|---|
| Stays on purpose: tickets, customer records, team email, workspace notes; fixed refusal for anything else | System prompt |
| Plain text, **no Markdown** (the `**` problem) | Prompt + `plainText()` strips it from every reply |
| **Not too short, not too long:** 12–90 words, 2–4 sentences | Prompt + one automatic rewrite request when out of range + `clampWords()` cuts at a sentence boundary |
| Ignores instructions inside tickets, emails and files | Prompt; the gateway still blocks any harmful resulting call |
| Browser cannot inject its own system prompt | `sanitizeAgentHistory()` drops client "system" messages |
| Size limits | 1,000-character instruction, 4,000-character tool output, 16-message history, 3 tool calls per step |
| Stable output | temperature 0.2, max_tokens 1024 |

**Verified:** unit tests for Markdown stripping, length clamping and history
sanitising; browser test against a deliberately misbehaving stand-in model (Markdown,
over-long and one-word answers) — inline approval appeared with a countdown, Approve
and Deny both work, final answers had no `**` and 37 words, instructions capped at
1,000 characters, no mobile overflow. The real Groq model was not called (no key here).
