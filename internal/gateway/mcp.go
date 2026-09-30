package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"

	"pnc3-gateway/internal/approval"
	"pnc3-gateway/internal/audit"
	"pnc3-gateway/internal/canon"
	"pnc3-gateway/internal/config"
	"pnc3-gateway/internal/inspect"
	"pnc3-gateway/internal/manifest"
	"pnc3-gateway/internal/policy"
	"pnc3-gateway/internal/rpc"
)

var supportedVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const (
	sessionHeader  = "Mcp-Session-Id"
	overheadHeader = "X-Gateway-Overhead-Us"
	approvalHeader = "X-Approval-Wait-Ms"
)

// stopwatch records how long each pipeline stage took.
type stopwatch struct {
	last   time.Time
	stages map[string]int64
}

func newStopwatch() *stopwatch { return &stopwatch{last: time.Now(), stages: map[string]int64{}} }

func (s *stopwatch) lap(stage string) {
	now := time.Now()
	s.stages[stage] += now.Sub(s.last).Microseconds()
	s.last = now
}

// skip excludes time we do not own (waiting for a human or the tool itself).
func (s *stopwatch) skip(stage string) time.Duration {
	now := time.Now()
	d := now.Sub(s.last)
	s.stages[stage] += d.Microseconds()
	s.last = now
	return d
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		if id := r.Header.Get(sessionHeader); id != "" {
			g.mcpSessions.Delete(id)
		}
		w.WriteHeader(http.StatusOK)
		return
	default:
		// No server-initiated stream: the gateway only answers requests.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	sw := newStopwatch()

	token, err := auth_bearer(r)
	if err != nil {
		writeHTTPError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	ident, err := g.auth.Verify(r.Context(), token)
	if err != nil {
		writeHTTPError(w, http.StatusUnauthorized, "invalid agent token: "+err.Error())
		return
	}
	sw.lap("authenticate")

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		g.recordParseFailure(ident.AgentID, "body_too_large", sw, start)
		writeRPCError(w, nil, -32600, "request body too large", "body_too_large")
		return
	}
	strict := g.cfg.Profile == config.ProfileFull
	var req *rpc.Request
	if strict {
		req, err = rpc.ParseStrict(body, g.cfg.MaxJSONDepth)
	} else {
		req, err = rpc.ParseLenient(body)
	}
	sw.lap("parse")
	if err != nil {
		g.recordParseFailure(ident.AgentID, rpc.Code(err), sw, start)
		writeRPCError(w, nil, -32600, "request rejected by gateway", rpc.Code(err))
		return
	}

	sessionID := r.Header.Get(sessionHeader)
	if req.Method != "initialize" && sessionID != "" {
		owner, ok := g.mcpSessions.Load(sessionID)
		if !ok || owner.(string) != ident.AgentID {
			writeHTTPError(w, http.StatusNotFound, "unknown session; re-initialize")
			return
		}
	}
	if sessionID == "" {
		sessionID = "agent:" + ident.AgentID // stateless clients share one session per agent
	}

	switch req.Method {
	case "initialize":
		g.handleInitialize(w, req, ident.AgentID)
	case "ping":
		writeRPCResult(w, req.ID, map[string]any{}, 0)
	case "tools/list":
		g.handleToolsList(w, r.Context(), req, ident.AgentID)
	case "tools/call":
		g.handleToolsCall(w, r, req, ident.AgentID, sessionID, strict, sw, start)
	default:
		if strings.HasPrefix(req.Method, "notifications/") || req.IsNotification() {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Includes server/discover: modern clients fall back to the initialize handshake.
		writeRPCError(w, req.ID, -32601, "method not found: "+req.Method, "")
	}
}

func auth_bearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	const p = "bearer "
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimSpace(h[len(p):]), nil
}

func (g *Gateway) handleInitialize(w http.ResponseWriter, req *rpc.Request, agent string) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &p)
	version := supportedVersions[0]
	for _, v := range supportedVersions {
		if v == p.ProtocolVersion {
			version = v
		}
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	g.mcpSessions.Store(id, agent)
	w.Header().Set(sessionHeader, id)
	writeRPCResult(w, req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "pnc3-secure-agent-gateway", "version": Version},
		"instructions":    "All tool calls pass through a zero-trust security gateway. Blocked calls return a reason code.",
	}, 0)
}

func (g *Gateway) handleToolsList(w http.ResponseWriter, ctx context.Context, req *rpc.Request, agent string) {
	g.refreshIfStale(ctx, 2*time.Second)
	tools := []map[string]any{}
	for _, t := range g.registry.All() {
		visible := false
		desc, schema := t.Description, t.InputSchema
		switch g.cfg.Profile {
		case config.ProfileFull:
			visible = t.Status == manifest.StatusActive && g.cfg.AgentAllows(agent, t.Name)
		case config.ProfileAllowlistOnly:
			visible = t.Status != manifest.StatusUnavailable && g.cfg.AgentAllows(agent, t.Name)
		default:
			visible = t.Status != manifest.StatusUnavailable
		}
		if t.Status == manifest.StatusQuarantined && t.PendingDesc != "" {
			desc = t.PendingDesc // baselines pass the changed manifest straight through
		}
		if !visible {
			continue
		}
		var s any
		_ = json.Unmarshal(schema, &s)
		if s == nil {
			s = map[string]any{"type": "object"}
		}
		tools = append(tools, map[string]any{"name": t.Name, "description": desc, "inputSchema": s})
	}
	writeRPCResult(w, req.ID, map[string]any{"tools": tools}, 0)
}

// callOutcome is everything the audit record and the response need.
type callOutcome struct {
	tool     string
	args     map[string]any
	verdict  string // allow | deny | approval | error
	ruleIDs  []string
	reason   string
	report   inspect.Report
	approval string
}

func (g *Gateway) handleToolsCall(w http.ResponseWriter, r *http.Request, req *rpc.Request, agent, sessionID string, strict bool, sw *stopwatch, start time.Time) {
	ctx := r.Context()
	out := &callOutcome{verdict: policy.VerdictDeny}
	var excluded time.Duration
	decisionID := audit.NewID("dec")

	finish := func(result map[string]any) {
		overhead := time.Since(start) - excluded
		g.recordDecision(decisionID, agent, sessionID, out, sw, overhead)
		if result == nil {
			result = blockedResult(decisionID, out)
		}
		writeRPCResult(w, req.ID, result, overhead)
	}

	params, err := rpc.ParseToolCall(req.Params, strict)
	if err != nil {
		out.reason, out.ruleIDs = rpc.Code(err), []string{"strict-parse"}
		finish(nil)
		return
	}
	out.tool, out.args = params.Name, params.Arguments

	if revoked, _ := g.sessions.IsRevoked(ctx, agent); revoked {
		out.reason, out.ruleIDs = "agent_revoked", []string{"kill-switch"}
		finish(nil)
		return
	}
	if g.cfg.Profile != config.ProfileOff && !g.limiter(agent).Allow() {
		out.reason, out.ruleIDs = "rate_limited", []string{"rate-limit"}
		finish(nil)
		return
	}
	sw.lap("identity_checks")

	t := g.registry.Get(params.Name)
	switch g.cfg.Profile {
	case config.ProfileOff:
		if t == nil {
			out.reason, out.ruleIDs = "unknown_tool", []string{"unknown-tool"}
			finish(nil)
			return
		}
		out.verdict, out.reason = policy.VerdictAllow, "profile_off"
	case config.ProfileAllowlistOnly:
		if t == nil || !g.cfg.AgentAllows(agent, params.Name) {
			out.reason, out.ruleIDs = "tool_not_allowlisted", []string{"allowlist"}
			finish(nil)
			return
		}
		out.verdict, out.reason = policy.VerdictAllow, "allowlisted"
	default:
		spec := g.cfg.Tools[params.Name]
		if len(spec.AllowedAgents) > 0 && !containsString(spec.AllowedAgents, agent) {
			out.reason, out.ruleIDs = "tool_agent_scope", []string{"tool-agent-scope"}
			finish(nil)
			return
		}
		argsJSON, _ := json.Marshal(params.Arguments)
		if spec.MaxArgsBytes > 0 && int64(len(argsJSON)) > spec.MaxArgsBytes {
			out.reason, out.ruleIDs = "tool_argument_limit", []string{"tool-argument-limit"}
			finish(nil)
			return
		}
		if !g.fullPipeline(ctx, r, agent, sessionID, t, params, out, sw, &excluded, decisionID) {
			finish(nil)
			return
		}
	}

	// Execute through the harness: the gateway injects credentials upstream.
	res, err := g.upstreams.CallTool(ctx, t.Server, params.Name, params.Arguments)
	excluded += sw.skip("upstream")
	if err != nil {
		out.verdict, out.reason, out.ruleIDs = "error", "upstream_error", []string{"harness"}
		finish(errorResult(decisionID, "The tool server did not respond: "+err.Error()))
		return
	}
	result := g.inspectResult(ctx, res, t, sessionID, out)
	sw.lap("inspect_response")
	result["_meta"] = map[string]any{
		"gateway/decision_id": decisionID,
		"gateway/verdict":     out.verdict,
		"gateway/trust":       trustLabel(t, out),
	}
	finish(result)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// fullPipeline runs every check. It returns false when the call must not execute.
func (g *Gateway) fullPipeline(ctx context.Context, r *http.Request, agent, sessionID string, t *manifest.Tool,
	params *rpc.ToolCallParams, out *callOutcome, sw *stopwatch, excluded *time.Duration, decisionID string) bool {

	ag, known := g.cfg.Agent(agent)
	if !known {
		out.reason, out.ruleIDs = "unknown_agent", []string{"agent-registry"}
		return false
	}
	if t == nil || t.Status == manifest.StatusUnregistered {
		out.reason, out.ruleIDs = "unknown_tool", []string{"tool-registry"}
		return false
	}
	if t.Status == manifest.StatusQuarantined {
		out.reason, out.ruleIDs = "tool_quarantined", []string{"manifest-pinning"}
		return false
	}
	if t.Status != manifest.StatusActive {
		out.reason, out.ruleIDs = "tool_unavailable", []string{"tool-registry"}
		return false
	}
	sw.lap("manifest")

	c := canon.Canonicalize(params.Arguments, g.cfg.MaxDecodeDepth)
	sw.lap("canonicalize")
	if c.DepthExceeded {
		out.reason, out.ruleIDs = "excessive_encoding", []string{"canonicalizer"}
		out.report.Findings = c.Notes
		return false
	}
	if err := t.ValidateArgs(params.Arguments, true); err != nil {
		out.reason, out.ruleIDs = "schema_violation", []string{"schema"}
		out.report.Findings = []string{err.Error()}
		return false
	}
	sw.lap("schema")

	st, err := g.sessions.Get(ctx, sessionID)
	if err != nil {
		out.reason, out.ruleIDs = "session_store_error", []string{"fail-closed"}
		return false
	}
	spec := g.cfg.Tools[t.Name]
	out.report = g.inspector.Inspect(ctx, spec, c, inspect.SessionView{
		Tainted: st.Tainted, HasPrivate: st.HasPrivate,
		UntrustedValues: st.UntrustedValues, PrivateValues: st.PrivateValues,
	})
	sw.lap("inspect")

	entities, req := cedarRequest(ag, t, out.report.Facts)
	d := g.policy.Decide(entities, req)
	sw.lap("policy")
	if d.Verdict == policy.VerdictAllow && spec.RequireApproval {
		d.Verdict, d.Reason = policy.VerdictApproval, "tool_requires_approval"
		d.RuleIDs = append(d.RuleIDs, "tool-approval-requirement")
	}
	out.verdict, out.ruleIDs, out.reason = d.Verdict, d.RuleIDs, d.Reason
	if len(d.Errors) > 0 {
		out.report.Findings = append(out.report.Findings, d.Errors...)
	}

	switch d.Verdict {
	case policy.VerdictAllow:
		return true
	case policy.VerdictApproval:
		wait := g.cfg.ApprovalTimeout.Duration
		if v := r.Header.Get(approvalHeader); v != "" {
			if ms, err := strconv.Atoi(v); err == nil && time.Duration(ms)*time.Millisecond < wait {
				wait = time.Duration(ms) * time.Millisecond // agents may only shorten the wait
			}
		}
		argsJSON, _ := json.Marshal(redactArgs(params.Arguments))
		outcome := g.approvals.Wait(ctx, &approval.Pending{
			ID: audit.NewID("apr"), DecisionID: decisionID, AgentID: agent, SessionID: sessionID,
			Tool: t.Name, Args: argsJSON, RuleIDs: d.RuleIDs, Reason: g.reasonText(d.Reason), Findings: out.report.Findings,
		}, wait)
		*excluded += sw.skip("approval_wait")
		out.approval = outcome
		if outcome == approval.Approved {
			out.verdict = policy.VerdictAllow
			out.reason = "approved_by_human"
			return true
		}
		out.verdict = policy.VerdictDeny
		out.reason = "approval_" + outcome
		return false
	default:
		return false
	}
}

func cedarRequest(ag config.Agent, t *manifest.Tool, f inspect.Facts) (cedar.EntityMap, cedar.Request) {
	agentUID := cedar.NewEntityUID("Agent", cedar.String(ag.ID))
	toolUID := cedar.NewEntityUID("Tool", cedar.String(t.Name))
	allowed := make([]cedar.Value, 0, len(ag.AllowedTools))
	for _, a := range ag.AllowedTools {
		allowed = append(allowed, cedar.String(a))
	}
	entities := cedar.EntityMap{
		agentUID: {UID: agentUID, Attributes: cedar.NewRecord(cedar.RecordMap{
			"owner":         cedar.String(ag.Owner),
			"allowed_tools": cedar.NewSet(allowed...),
		})},
		toolUID: {UID: toolUID, Attributes: cedar.NewRecord(cedar.RecordMap{
			"name":            cedar.String(t.Name),
			"server":          cedar.String(t.Server),
			"destructive":     cedar.Boolean(t.Destructive),
			"sends_external":  cedar.Boolean(t.SendsExternal),
			"reads_untrusted": cedar.Boolean(t.ReadsUntrusted),
			"reads_private":   cedar.Boolean(t.ReadsPrivate),
		})},
	}
	ctxMap := cedar.RecordMap{}
	for k, v := range f.Map() {
		ctxMap[cedar.String(k)] = cedar.Boolean(v)
	}
	return entities, cedar.Request{
		Principal: agentUID,
		Action:    cedar.NewEntityUID("Action", cedar.String(t.Name)),
		Resource:  toolUID,
		Context:   cedar.NewRecord(ctxMap),
	}
}

// inspectResult labels, taints and redacts what comes back from the tool.
func (g *Gateway) inspectResult(ctx context.Context, res any, t *manifest.Tool, sessionID string, out *callOutcome) map[string]any {
	raw, _ := json.Marshal(res)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m == nil {
		m = map[string]any{"content": []any{}}
	}
	var texts []string
	redacted := false
	if items, ok := m["content"].([]any); ok {
		for _, it := range items {
			if c, ok := it.(map[string]any); ok && c["type"] == "text" {
				s, _ := c["text"].(string)
				if rs, changed := inspect.Redact(s); changed {
					c["text"], redacted = rs, true
					s = rs
				}
				texts = append(texts, s)
			}
		}
	}
	if sc, ok := m["structuredContent"]; ok {
		b, _ := json.Marshal(sc)
		if rs, changed := inspect.Redact(string(b)); changed {
			var v any
			if json.Unmarshal([]byte(rs), &v) == nil {
				m["structuredContent"], redacted = v, true
			}
		}
	}
	if redacted {
		out.report.Findings = append(out.report.Findings, "secret redacted from tool output")
	}
	text := strings.Join(texts, "\n")
	markers := inspect.InjectionMarkers(text)
	if len(markers) > 0 {
		out.report.Findings = append(out.report.Findings, "injection markers in tool output: "+strings.Join(markers, " | "))
	}
	if g.cfg.Profile == config.ProfileFull {
		if t.ReadsUntrusted || len(markers) > 0 {
			_ = g.sessions.AddUntrusted(ctx, sessionID, inspect.UntrustedValues(text))
		}
		if t.ReadsPrivate {
			_ = g.sessions.AddPrivate(ctx, sessionID, inspect.PrivateFingerprints(text))
		}
	}
	if len(markers) > 0 {
		out.report.Facts.SessionTainted = true
	}
	return m
}

func trustLabel(t *manifest.Tool, out *callOutcome) string {
	for _, f := range out.report.Findings {
		if strings.HasPrefix(f, "injection markers") {
			return "untrusted"
		}
	}
	if t.ReadsUntrusted {
		return "untrusted"
	}
	return "trusted"
}

func (g *Gateway) reasonText(code string) string {
	if s := g.policy.ReasonText(code); s != "" {
		return s
	}
	if s, ok := builtinReasons[code]; ok {
		return s
	}
	return code
}

var builtinReasons = map[string]string{
	"agent_revoked":           "This agent has been revoked by an administrator.",
	"rate_limited":            "Too many tool calls; slow down.",
	"unknown_tool":            "This tool is not registered with the gateway.",
	"unknown_agent":           "This agent is not registered with the gateway.",
	"tool_quarantined":        "The tool's description or schema changed and is waiting for review.",
	"tool_unavailable":        "The tool server is not offering this tool right now.",
	"tool_not_allowlisted":    "This agent may not use this tool.",
	"tool_agent_scope":        "This agent is outside the tool's explicit registry scope.",
	"tool_argument_limit":     "The tool arguments exceed the registry size limit.",
	"tool_requires_approval":  "This registry entry requires human approval before execution.",
	"excessive_encoding":      "An argument is wrapped in too many layers of encoding.",
	"schema_violation":        "The arguments do not match the tool's declared schema.",
	"no_permit_matched":       "No policy allows this call (deny by default).",
	"approval_denied":         "A human reviewer denied this call.",
	"approval_timeout":        "Nobody approved this call in time, so it was denied.",
	"approval_cancelled":      "The request was cancelled while waiting for approval.",
	"session_store_error":     "The gateway could not read session state, so it failed closed.",
	"policy_evaluation_error": "A policy failed to evaluate, so the gateway failed closed.",
}

func blockedResult(decisionID string, out *callOutcome) map[string]any {
	verdict := out.verdict
	if verdict != "error" {
		verdict = policy.VerdictDeny
	}
	return map[string]any{
		"content": []any{map[string]any{"type": "text",
			"text": fmt.Sprintf("Blocked by the security gateway: %s (decision %s)", out.reason, decisionID)}},
		"isError": true,
		"_meta": map[string]any{
			"gateway/decision_id": decisionID, "gateway/verdict": verdict, "gateway/reason": out.reason,
		},
	}
}

func errorResult(decisionID, msg string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": msg}},
		"isError": true,
		"_meta":   map[string]any{"gateway/decision_id": decisionID, "gateway/verdict": "error"},
	}
}

func (g *Gateway) recordDecision(id, agent, sessionID string, out *callOutcome, sw *stopwatch, overhead time.Duration) {
	argsJSON, _ := json.Marshal(redactArgs(out.args))
	sum := sha256.Sum256(argsJSON)
	dests, _ := json.Marshal(out.report.Destinations)
	rec := &audit.Record{
		ID: id, Type: "decision", AgentID: agent, SessionID: sessionID, Tool: out.tool,
		Verdict: out.verdict, RuleIDs: out.ruleIDs, Reason: out.reason, Profile: g.cfg.Profile,
		ArgsHash: hex.EncodeToString(sum[:]), Args: argsJSON, Findings: out.report.Findings,
		StageMicros: sw.stages, OverheadMicros: overhead.Microseconds(),
	}
	if len(out.report.Destinations) > 0 {
		rec.Destinations = dests
	}
	if g.cfg.Profile == config.ProfileFull {
		rec.Facts = out.report.Facts.Map()
	}
	if out.approval != "" {
		rec.Detail, _ = json.Marshal(map[string]string{"approval": out.approval})
	}
	if err := g.audit.Append(rec); err != nil {
		g.log.Error("audit append failed", "err", err)
	}
	g.metrics.Observe(out.verdict, overhead, sw.stages)
	g.hub.Broadcast("decision", rec)
}

func (g *Gateway) recordParseFailure(agent, code string, sw *stopwatch, start time.Time) {
	out := &callOutcome{verdict: policy.VerdictDeny, reason: code, ruleIDs: []string{"strict-parse"}}
	g.recordDecision(audit.NewID("dec"), agent, "", out, sw, time.Since(start))
}

func redactArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		switch t := v.(type) {
		case string:
			s, _ := inspect.Redact(t)
			out[k] = s
		case map[string]any:
			out[k] = redactArgs(t)
		default:
			out[k] = v
		}
	}
	return out
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any, overhead time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	if overhead > 0 {
		w.Header().Set(overheadHeader, strconv.FormatInt(overhead.Microseconds(), 10))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg, reason string) {
	w.Header().Set("Content-Type", "application/json")
	e := map[string]any{"code": code, "message": msg}
	if reason != "" {
		e["data"] = map[string]any{"gateway/reason": reason}
	}
	if id == nil {
		id = json.RawMessage("null")
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
}

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
