import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

// The admin token gates the API. In dev it defaults to dev-admin-token; the
// operator can paste a different one. It is kept only in this browser tab.
function useToken() {
  const [token, setToken] = useState(() => sessionStorage.getItem("gw_admin") || "dev-admin-token");
  const save = (t) => { sessionStorage.setItem("gw_admin", t); setToken(t); };
  return [token, save];
}

function api(token) {
  const headers = { Authorization: `Bearer ${token}` };
  return {
    get: (p) => fetch(p, { headers }).then((r) => (r.ok ? r.json() : Promise.reject(r))),
    post: (p, body) => fetch(p, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => { const value = await r.json(); if (!r.ok) throw new Error(value.error || `Request failed: HTTP ${r.status}`); return value; }),
    del: (p) => fetch(p, { method: "DELETE", headers }).then(async (r) => { const value = await r.json(); if (!r.ok) throw new Error(value.error || `Request failed: HTTP ${r.status}`); return value; }),
    put: (p, body) => fetch(p, { method: "PUT", headers: { ...headers, "Content-Type": "text/plain" }, body }).then((r) => r.json()),
  };
}

const VERDICT_LABEL = { allow: "ALLOW", deny: "DENY", approval: "APPROVE?", error: "ERROR" };

function App() {
  const [token, setToken] = useToken();
  const client = useMemo(() => api(token), [token]);
  const tabFromLocation = () => location.pathname === "/agent" ? "agent" : "live";
  const [tab, setTab] = useState(tabFromLocation);
  const [state, setState] = useState(null);
  const [connected, setConnected] = useState(false);
  const [decisions, setDecisions] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [tools, setTools] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const wsRef = useRef(null);

  const refreshState = useCallback(() => client.get("/admin/state").then(setState).catch(() => setState(null)), [client]);
  const refreshMetrics = useCallback(() => client.get("/admin/metrics").then(setMetrics).catch(() => setMetrics(null)), [client]);
  const selectTab = (next) => {
    const path = next === "agent" ? "/agent" : "/";
    if (location.pathname !== path) history.pushState({}, "", path);
    setTab(next);
  };

  const navItems = [
    ["live", "Live feed", "01"], ["agent", "Agent console", "02"], ["approvals", "Approvals", "03"],
    ["architecture", "Architecture", "04"], ["tools", "Tool registry", "05"], ["policies", "Policies", "06"], ["benchmark", "Benchmark", "07"], ["audit", "Audit chain", "08"],
  ];

  useEffect(() => {
    const onPopState = () => setTab(tabFromLocation());
    addEventListener("popstate", onPopState);
    return () => removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    refreshState();
    client.get("/admin/decisions?limit=100&type=decision").then(setDecisions).catch(() => {});
    client.get("/admin/approvals").then(setApprovals).catch(() => {});
    client.get("/admin/tools").then(setTools).catch(() => {});
    refreshMetrics();
    const t = setInterval(() => { refreshState(); refreshMetrics(); }, 5000);
    return () => clearInterval(t);
  }, [client, refreshState]);

  // Live event stream over WebSocket.
  useEffect(() => {
    let stop = false;
    function connect() {
      if (stop) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/admin/ws?token=${encodeURIComponent(token)}`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); if (!stop) setTimeout(connect, 1500); };
      ws.onmessage = (e) => {
        const { type, data } = JSON.parse(e.data);
        if (type === "decision") { setDecisions((d) => [data, ...d].slice(0, 200)); refreshMetrics(); }
        else if (type === "approvals") setApprovals(data || []);
        else if (type === "tools") setTools(data || []);
        else if (type === "event") setDecisions((d) => [data, ...d].slice(0, 200));
        else if (type === "policies" || type === "manifest") {
          refreshState();
          client.get("/admin/tools").then(setTools).catch(() => {});
        }
      };
    }
    connect();
    return () => { stop = true; wsRef.current?.close(); };
  }, [token, refreshState]);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">AS</div>
          <div><strong>AGENTSHIELD</strong><small>CONTROL PLANE / PNC3</small></div>
        </div>
        <div className="side-label">Navigation</div>
        <nav className="side-nav">
          {navItems.map(([id, label, number]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => selectTab(id)}><span>{number}</span>{label}{id === "approvals" && approvals.length > 0 && <b>{approvals.length}</b>}</button>)}
        </nav>
        <div className="sidebar-foot"><span className={"signal-dot " + (connected ? "on" : "")}></span><span>{connected ? "Gateway online" : "Connecting"}</span><small>v0.1.0-mvp</small></div>
      </aside>

      <section className="workspace">
        <header className="top">
          <div><div className="eyebrow">SECURITY OPERATIONS / {tab.toUpperCase()}</div><h1>{navItems.find(([id]) => id === tab)?.[1] || "Live feed"}</h1></div>
          <div className="status-pills">
            {state && <span className="system-chip"><i className="signal-dot on"></i> {state.profile} / {state.policies_loaded} policies</span>}
            <TokenBox token={token} setToken={setToken} />
          </div>
        </header>
        <div className="status-strip"><span><i className={"signal-dot " + (connected ? "on" : "")}></i> STREAM {connected ? "CONNECTED" : "RECONNECTING"}</span><span>UPSTREAMS {state ? Object.keys(state.upstreams || {}).length : "--"}</span><span>AUDIT {state?.audit_backend?.split(":")[0]?.toUpperCase() || "--"}</span><span className="strip-right">ZERO TRUST / DENY BY DEFAULT</span></div>
        <main>
        {tab === "live" && <LiveFeed metrics={metrics} decisions={decisions} />}
        {tab === "agent" && <Agent client={client} />}
        {tab === "approvals" && <Approvals approvals={approvals} client={client} />}
        {tab === "architecture" && <Architecture state={state} tools={tools} metrics={metrics} decisions={decisions} connected={connected} />}
        {tab === "tools" && <Tools tools={tools} client={client} state={state} />}
        {tab === "policies" && <Policies client={client} />}
        {tab === "benchmark" && <Benchmark client={client} />}
        {tab === "audit" && <Audit client={client} state={state} />}
      </main>
      </section>
    </div>
  );
}

function Architecture({ state, tools, metrics, decisions, connected }) {
  const upstreams = state?.upstreams || {};
  const activeTools = tools.filter((tool) => tool.status === "active").length;
  const recent = decisions.filter((item) => item.type === "decision").slice(0, 4);
  return (
    <div className="architecture-page">
      <div className="architecture-intro"><div><div className="eyebrow">SYSTEM TOPOLOGY / LIVE CONTROL PATH</div><h2>Multi-component architecture</h2><p>A low-latency proxy intercepts every agent tool call, the live Cedar engine evaluates it, and the execution harness forwards only approved calls to registered tools.</p></div><span className={"architecture-live " + (connected ? "on" : "")}>{connected ? "LIVE PATH CONNECTED" : "PATH RECONNECTING"}</span></div>
      <div className="architecture-flow">
        <ArchitectureNode number="01" title="Proxy layer" tone="cyan" status={connected ? "intercepting" : "reconnecting"} body="MCP authentication · strict JSON-RPC parsing · session and rate checks" metrics={[["Requests", metrics?.total_requests ?? 0], ["p50 overhead", metrics ? `${(metrics.p50_latency_us / 1000).toFixed(2)} ms` : "--"]]} />
        <div className="flow-arrow">→</div>
        <ArchitectureNode number="02" title="Policy engine" tone="lime" status={state ? `${state.policies_loaded} policies loaded` : "loading"} body="Canonicalization · deep inspection · Cedar decision · approval gate" metrics={[["Allowed", metrics?.allowed_requests ?? 0], ["Blocked", metrics?.blocked_requests ?? 0]]} />
        <div className="flow-arrow">→</div>
        <ArchitectureNode number="03" title="Execution harness" tone="orange" status={`${activeTools} active tools`} body="Gateway-held credentials · manifest pins · upstream execution · response inspection" metrics={[["Upstreams", Object.keys(upstreams).length], ["Audit", state?.audit_backend?.split(":")[0] || "--"]]} />
      </div>
      <div className="architecture-grid">
        <div className="panel"><h2>Connected upstreams</h2><div className="body">{Object.entries(upstreams).map(([name, status]) => <div className="architecture-row" key={name}><span className={"signal-dot " + (String(status).toLowerCase().includes("ok") || String(status).toLowerCase().includes("ready") ? "on" : "")}></span><span className="mono">{name}</span><span>{status}</span></div>)}{Object.keys(upstreams).length === 0 && <div className="empty">No upstream status available.</div>}</div></div>
        <div className="panel"><h2>Last routed decisions <small className="live-caption">LIVE / AUDIT STREAM</small></h2><div className="body">{recent.length === 0 && <div className="empty">No tool calls yet.</div>}{recent.map((item) => <div className="decision-row" key={item.id}><span className={`verdict ${item.verdict}`}>{VERDICT_LABEL[item.verdict] || item.verdict}</span><span className="mono decision-tool">{item.tool}</span><span className="decision-reason">{item.reason}</span><time>{item.time ? new Date(item.time).toLocaleTimeString() : ""}</time></div>)}</div></div>
      </div>
      <div className="architecture-proof"><span className="proof-label">CALL PATH PROOF</span><span>Agent / MCP</span><b>→</b><span>Proxy intercept</span><b>→</b><span>Inspect + Cedar</span><b>→</b><span>Allow / deny / approval</span><b>→</b><span>Harness</span><b>→</b><span>Audit + live stream</span></div>
    </div>
  );
}

function ArchitectureNode({ number, title, tone, status, body, metrics }) {
  return <div className={`architecture-node ${tone}`}><div className="node-number">{number}</div><div className="node-title">{title}</div><div className="node-status"><i className="signal-dot on"></i>{status}</div><p>{body}</p><div className="node-metrics">{metrics.map(([label, value]) => <div key={label}><b>{value}</b><small>{label}</small></div>)}</div></div>;
}

function Agent({ client }) {
  const [instruction, setInstruction] = useState("");
  const [messages, setMessages] = useState([]);
  const [history, setHistory] = useState([]);
  const [busy, setBusy] = useState(false);

  const append = (message) => setMessages((items) => [...items, message]);

  const callGateway = async (token, session, tool, args) => {
    const response = await fetch("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(session ? { "Mcp-Session-Id": session } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method: "tools/call", params: { name: tool, arguments: args } }),
    });
    const body = await response.json();
    const meta = body.result?._meta || {};
    const text = (body.result?.content || []).map((item) => item.text || "").join("\n") || body.error?.message || "No tool output.";
    return { session: response.headers.get("Mcp-Session-Id") || session, verdict: meta["gateway/verdict"] || "error", reason: meta["gateway/reason"] || "", text };
  };

  const initialize = async (token) => {
    const response = await fetch("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method: "initialize", params: { protocolVersion: "2025-11-25" } }),
    });
    if (!response.ok) throw new Error(`Gateway initialize failed: HTTP ${response.status}`);
    return response.headers.get("Mcp-Session-Id");
  };

  const run = async () => {
    const text = instruction.trim();
    if (!text || busy) return;
    setInstruction("");
    append({ kind: "user", text });
    setBusy(true);
    try {
      const { token, agent } = await client.post("/admin/agent/token", { agent: "support-agent" });
      const nextHistory = [...history, { role: "user", content: text }];
      const plan = await client.post("/admin/agent/plan", { messages: nextHistory });
      append({ kind: "agent", text: plan.content || `The model selected ${plan.tool_calls?.length || 0} tool call(s).` });
      let session = await initialize(token);
      const toolMessages = [];
      for (const call of plan.tool_calls || []) {
        let args;
        try { args = JSON.parse(call.function.arguments || "{}"); } catch { append({ kind: "error", text: `Model returned invalid arguments for ${call.function.name}.` }); continue; }
        append({ kind: "call", tool: call.function.name, args, status: "sending" });
        const result = await callGateway(token, session, call.function.name, args);
        session = result.session;
        append({ kind: "result", tool: call.function.name, verdict: result.verdict, reason: result.reason, text: result.text });
        toolMessages.push({ role: "tool", tool_call_id: call.id, content: result.text });
      }
      setHistory([...nextHistory, { role: "assistant", content: plan.content || "", tool_calls: plan.tool_calls || [] }, ...toolMessages]);
    } catch (error) {
      append({ kind: "error", text: error.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="agent-layout">
      <div className="panel agent-chat">
        <h2>Customer Support Agent · live gateway client</h2>
        <div className="agent-messages">
          {messages.length === 0 && <div className="empty">No instruction yet. The agent will choose a tool and send the call through the running gateway.</div>}
          {messages.map((m, i) => (
            <div className={`agent-message ${m.kind}`} key={i}>
              <div className="agent-label">{m.kind === "user" ? "User" : m.kind === "call" ? `Tool call · ${m.tool}` : "Agent"}</div>
              {m.kind === "call" && <pre>{prettyArgs(m.args)}</pre>}
              {m.kind === "result" && <><span className={`verdict ${m.verdict}`}>{VERDICT_LABEL[m.verdict] || m.verdict}</span>{m.reason && <span className="agent-reason"> {m.reason}</span>}<pre>{m.text}</pre></>}
              {m.text && m.kind !== "result" && <div>{m.text}</div>}
            </div>
          ))}
        </div>
        <div className="agent-compose">
          <textarea value={instruction} onChange={(e) => setInstruction(e.target.value)} placeholder="Give the agent a real support instruction..." onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); run(); } }} />
          <button className="act approve" disabled={busy} onClick={run}>{busy ? "Running..." : "Send to agent"}</button>
        </div>
      </div>
      <div className="panel agent-evidence">
        <h2>Live evidence</h2>
        <div className="body"><p>Evidence from this session is shown from actual gateway responses.</p>{messages.filter((item) => item.kind === "result").length === 0 && <div className="empty">No tool execution yet.</div>}{messages.filter((item) => item.kind === "result").map((item, index) => <div className="evidence-item" key={index}><div><span className="mono">{item.tool}</span> <span className={`verdict ${item.verdict}`}>{VERDICT_LABEL[item.verdict] || item.verdict}</span></div>{item.reason && <div className="hint">Reason: {item.reason}</div>}<pre>{item.text}</pre></div>)}</div>
      </div>
    </div>
  );
}

function TokenBox({ token, setToken }) {
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(token);
  if (!editing) return <span className="pill" onClick={() => setEditing(true)} style={{ cursor: "pointer" }}>admin token ✎</span>;
  return (
    <span className="pill">
      <input value={val} onChange={(e) => setVal(e.target.value)} style={{ background: "transparent", border: "none", color: "inherit", font: "inherit", width: 120 }} />
      <button className="act" style={{ padding: "1px 8px", marginLeft: 6 }} onClick={() => { setToken(val); setEditing(false); }}>set</button>
    </span>
  );
}

function verdictClass(v) { return "verdict " + v; }

function LiveFeed({ metrics, decisions }) {
  return (
    <>
      <div className="stats">
        <div className="stat allow"><div className="n">{metrics?.allowed_requests ?? 0}</div><div className="l">allowed</div></div>
        <div className="stat deny"><div className="n">{metrics?.blocked_requests ?? 0}</div><div className="l">blocked</div></div>
        <div className="stat approval"><div className="n">{metrics?.approval_requests ?? 0}</div><div className="l">held for approval</div></div>
        <div className="stat"><div className="n">{metrics?.total_requests ?? 0}</div><div className="l">total requests</div></div>
        <div className="stat"><div className="n">{metrics ? `${(metrics.p50_latency_us / 1000).toFixed(2)} ms` : "0 ms"}</div><div className="l">p50 gateway latency</div></div>
      </div>
      <KPICharts metrics={metrics} />
      <div className="panel feed">
        <h2>Live decision feed — every tool call, with its verdict, reason and the facts behind it</h2>
        {decisions.length === 0 && <div className="empty">No calls yet. Run the demo or the benchmark.</div>}
        {decisions.map((d, i) => <FeedRow key={d.id + i} d={d} />)}
      </div>
    </>
  );
}

function KPICharts({ metrics }) {
  const total = metrics?.total_requests || 0;
  const bars = [
    ["Allowed", metrics?.allowed_requests || 0, "var(--allow)"],
    ["Blocked", metrics?.blocked_requests || 0, "var(--deny)"],
    ["Approval", metrics?.approval_requests || 0, "var(--approve)"],
  ];
  return (
    <div className="kpi-grid">
      <div className="panel chart-panel"><div className="chart-title"><span>Decision distribution</span><small>LIVE / AUDIT LOG</small></div><div className="bars">{bars.map(([label, value, color]) => <div className="bar-row" key={label}><span>{label}</span><div className="bar-track"><i style={{ width: `${total ? Math.max(2, value / total * 100) : 0}%`, background: color }} /></div><b>{value}</b></div>)}</div><div className="formula">coverage = audited decisions / received tool calls</div></div>
      <div className="panel chart-panel"><div className="chart-title"><span>Deterministic KPI</span><small>MEASURED / MICROSECONDS</small></div><div className="latency-grid"><div><b>{metrics ? `${(metrics.p50_latency_us / 1000).toFixed(2)} ms` : "--"}</b><span>p50 overhead</span></div><div><b>{metrics ? `${(metrics.p95_latency_us / 1000).toFixed(2)} ms` : "--"}</b><span>p95 overhead</span></div><div><b>{metrics ? `${(metrics.p99_latency_us / 1000).toFixed(2)} ms` : "--"}</b><span>p99 overhead</span></div></div><div className="formula">pN = sorted measured overhead at percentile N</div></div>
      <div className="panel chart-panel"><div className="chart-title"><span>Validation accuracy</span><small>BENCHMARK EVIDENCE</small></div><div className="accuracy-value">{metrics?.validation_accuracy == null ? "--" : `${(metrics.validation_accuracy * 100).toFixed(1)}%`}</div><div className="empty-chart">{metrics?.validation_accuracy == null ? "Run the live benchmark to calculate accuracy from expected versus observed decisions." : `${metrics.benchmark_cases} executed cases in the latest full-profile run.`}</div><div className="formula">accuracy = correct decisions / executed benchmark cases</div></div>
    </div>
  );
}

function FeedRow({ d }) {
  const t = new Date(d.time).toLocaleTimeString();
  if (d.type !== "decision") {
    return (
      <div className="feed-row">
        <time>{t}</time>
        <div className="feed-main">
          <span className="tag">{d.type}</span> {d.tool && <span className="tool">{d.tool} </span>}
          <span className="reason">{d.reason}</span>
        </div>
        <span className="verdict error">{(d.verdict || "event").toUpperCase()}</span>
      </div>
    );
  }
  return (
    <div className="feed-row">
      <time>{t}</time>
      <div className="feed-main">
        <span className="tool">{d.tool}</span> <span className="agent">· {d.agent_id}</span>
        <div className="reason">{d.reason}{d.rule_ids?.length ? ` (${d.rule_ids.join(", ")})` : ""}</div>
        {d.findings?.length > 0 && <div className="findings">↳ {d.findings.join(" · ")}</div>}
      </div>
      <span className={verdictClass(d.verdict)}>{VERDICT_LABEL[d.verdict] || d.verdict}</span>
    </div>
  );
}

function Approvals({ approvals, client }) {
  const resolve = (id, outcome) => client.post(`/admin/approvals/${id}`, { outcome });
  return (
    <div className="panel">
      <h2>Human approval queue — destructive and high-risk calls wait here</h2>
      <div className="body">
        {approvals.length === 0 && <div className="empty">Nothing waiting. Calls that need a human show up here in real time.</div>}
        {approvals.map((a) => (
          <div className="approval-card" key={a.id}>
            <div><span className="tool">{a.tool}</span> <span className="mono" style={{ color: "var(--muted)" }}>· {a.agent_id}</span></div>
            <div className="why">{a.reason}</div>
            {a.findings?.length > 0 && <div className="why">↳ {a.findings.join(" · ")}</div>}
            <div className="args">{prettyArgs(a.args)}</div>
            <div className="row-actions">
              <button className="act approve" onClick={() => resolve(a.id, "approve")}>Approve</button>
              <button className="act deny" onClick={() => resolve(a.id, "deny")}>Deny</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function prettyArgs(args) {
  try { return JSON.stringify(typeof args === "string" ? JSON.parse(args) : args, null, 2); }
  catch { return String(args); }
}

function Tools({ tools, client, state }) {
  const [items, setItems] = useState(tools);
  useEffect(() => setItems(tools), [tools]);
  const refresh = () => client.post("/admin/tools/refresh").then(setItems);
  const approve = (name) => client.post(`/admin/tools/${name}/approve`);
  const lifecycle = (name, action) => client.post(`/admin/tools/${name}/${action}`).then(setItems);
  return (
    <div className="panel">
      <h2>Registered tools — pinned by hash; a changed manifest is quarantined until reviewed</h2>
      <div className="body">
        <button className="act" onClick={refresh} style={{ marginBottom: 12 }}>Refresh manifests</button>
        <table>
          <thead><tr><th>Tool</th><th>Server</th><th>Status</th><th>Pinned hash</th><th>Flags</th><th></th></tr></thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.name}>
                <td className="mono">{t.name}</td>
                <td className="mono">{t.server}</td>
                <td><span className={"badge " + t.status}>{t.status}</span></td>
                <td className="mono">{(t.pinned_hash || t.hash || "").slice(0, 12)}</td>
                <td>
                  {t.destructive && <span className="tag">destructive</span>}
                  {t.sends_external && <span className="tag">external</span>}
                  {t.reads_untrusted && <span className="tag">untrusted</span>}
                  {t.reads_private && <span className="tag">private</span>}
                  {t.require_approval && <span className="tag">approval</span>}
                  {t.allowed_agents?.length > 0 && <span className="tag">agents: {t.allowed_agents.join(", ")}</span>}
                  {t.max_args_bytes && <span className="tag">args ≤ {Math.round(t.max_args_bytes / 1024)}KB</span>}
                </td>
                <td className="tool-actions">{t.status === "quarantined" && <button className="act approve" onClick={() => approve(t.name)}>Re-approve</button>}{t.status === "active" && <><button className="act" onClick={() => lifecycle(t.name, "suspend")}>Suspend</button><button className="act deny" onClick={() => lifecycle(t.name, "revoke")}>Revoke</button></>}{(t.status === "suspended" || t.status === "revoked") && <button className="act approve" onClick={() => lifecycle(t.name, "resume")}>Resume</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {state?.upstreams && <div className="hint">Upstreams: {Object.entries(state.upstreams).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>}
      </div>
    </div>
  );
}

function Policies({ client }) {
  const [status, setStatus] = useState(null);
  const [file, setFile] = useState("90-custom.cedar");
  const [prompt, setPrompt] = useState("");
  const [generated, setGenerated] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => { client.get("/admin/policies").then(setStatus).catch(() => {}); }, [client]);
  if (!status) return <div className="empty">Loading policies…</div>;
  const refresh = () => client.get("/admin/policies").then(setStatus);
  const generate = async () => {
    try {
      const result = await client.post("/admin/policies/generate", { file, prompt, source: status.files?.[file] || "" });
      setGenerated(result.cedar); setMessage("Groq generated a complete validated Cedar replacement.");
    } catch (error) { setMessage(error.message); }
  };
  const saveGenerated = async () => {
    try { await client.put(`/admin/policies/${file}`, generated); setMessage("Complete policy file replaced and reloaded."); await refresh(); }
    catch (error) { setMessage(error.message); }
  };
  return (
    <div className="grid">
      <div className="panel">
        <h2>Policy control · {status.policies?.length || 0} active rules / {Object.keys(status.files || {}).length} files</h2>
        <div className="body">
          <table>
            <thead><tr><th>Rule</th><th>Effect</th><th>File</th></tr></thead>
            <tbody>
              {status.policies?.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.id}{p.approval ? " ⏸" : ""}</td>
                  <td><span className={"mini-verdict"} style={{ background: p.effect === "permit" ? "var(--allow)" : "var(--deny)" }} />{p.effect}</td>
                  <td className="mono">{p.file}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="hint">⏸ marks rules that require human approval. A forbid always overrides a permit.</div>
          {status.last_error && <div className="hint" style={{ color: "var(--deny)" }}>Reload error: {status.last_error}</div>}
        </div>
      </div>
      <div className="panel">
        <h2>Natural language policy builder · Groq → complete Cedar replacement</h2>
        <div className="body">
          <div className="policy-builder">
            <div className="policy-builder-row"><label>Policy filename</label><input list="policy-file-options" value={file} onChange={(e) => { setFile(e.target.value); setGenerated(""); }} placeholder="90-custom.cedar" /><datalist id="policy-file-options">{Object.keys(status.files || {}).map((name) => <option key={name} value={name} />)}</datalist><span className="hint">Use an existing name to edit it, or enter a new .cedar name to create a backend file.</span></div>
            <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Example: Allow support-agent to read tickets, but deny every external email when the session contains private customer data." />
            <div className="row-actions"><button className="act approve" disabled={!prompt.trim()} onClick={generate}>Generate Cedar with Groq</button>{generated && <button className="act" onClick={saveGenerated}>Replace policy and reload</button>}</div>
            {message && <div className="hint">{message}</div>}
            {generated && <pre className="cedar-preview">{generated}</pre>}
          </div>
          {status.files && Object.entries(status.files).map(([name, text]) => (
            <PolicyEditor key={name} name={name} text={text} client={client} onSaved={refresh} />
          ))}
        </div>
      </div>
    </div>
  );
}

function PolicyEditor({ name, text, client, onSaved }) {
  const [val, setVal] = useState(text);
  const [msg, setMsg] = useState("");
  const [open, setOpen] = useState(false);
  const save = async () => {
    const res = await client.put(`/admin/policies/${name}`, val);
    if (res.last_error) setMsg("rejected: " + res.last_error);
    else { setMsg("saved · reloaded"); onSaved?.(); }
    setTimeout(() => setMsg(""), 4000);
  };
  const remove = async () => {
    if (!window.confirm(`Delete complete policy file ${name}?`)) return;
    const res = await client.del(`/admin/policies/${name}`);
    if (res.last_error) setMsg("rejected: " + res.last_error);
    else { setMsg("deleted · reloaded"); onSaved?.(); }
  };
  return (
    <details className="policy-file" open={open} onToggle={(e) => setOpen(e.target.open)}>
      <summary>{name} {msg && <span style={{ color: msg.startsWith("rejected") ? "var(--deny)" : "var(--allow)" }}>— {msg}</span>}</summary>
      {open && (
        <div style={{ border: "1px solid var(--line)", borderTop: "none", borderRadius: "0 0 8px 8px" }}>
            <textarea value={val} onChange={(e) => setVal(e.target.value)} spellCheck={false}
            style={{ width: "100%", minHeight: 200, background: "#f3f7f7", color: "#173238", border: "none", padding: 12, fontFamily: "var(--mono)", fontSize: 12, resize: "vertical" }} />
          <div style={{ padding: 10, display: "flex", gap: 8 }}><button className="act approve" onClick={save}>Replace & reload</button><button className="act deny" onClick={remove}>Delete file</button></div>
        </div>
      )}
    </details>
  );
}

function Benchmark({ client }) {
  const [data, setData] = useState(null);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => { client.get("/admin/bench").then(setData).catch(() => setData({ available: false })); }, [client]);
  const run = async () => {
    setRunning(true); setMessage("Running real cases through the gateway...");
    try { setData(await client.post("/admin/bench/run")); setMessage("Benchmark complete. Results came from executed cases."); }
    catch (error) { setMessage(error.message); }
    finally { setRunning(false); }
  };
  if (!data) return <div className="empty">Loading…</div>;
  if (data.available === false || !data.results) return <div className="panel"><div className="body"><div className="empty">No benchmark results yet.</div><button className="act approve" disabled={running} onClick={run}>{running ? "Running..." : "Run live benchmark"}</button>{message && <div className="hint">{message}</div>}</div></div>;
  return (
    <div className="panel">
      <h2>Benchmark — {data.cases} cases, generated {new Date(data.generated_at).toLocaleString()} <button className="act approve bench-run" disabled={running} onClick={run}>{running ? "Running..." : "Run again"}</button></h2>
      <div className="body">
        <table className="bench-table">
          <thead><tr><th>Profile</th><th>Contained</th><th>Blocked</th><th>False positives</th><th>p50</th><th>p95</th><th>p99</th></tr></thead>
          <tbody>
            {data.results.map((r) => (
              <tr key={r.profile}>
                <td className="mono">{r.profile}</td>
                <td className="num">{(r.containment_rate * 100).toFixed(1)}%</td>
                <td className="num">{(r.block_rate * 100).toFixed(1)}%</td>
                <td className="num">{(r.false_positive_rate * 100).toFixed(1)}%</td>
                <td className="num">{(r.latency_p50_us / 1000).toFixed(2)} ms</td>
                <td className="num">{(r.latency_p95_us / 1000).toFixed(2)} ms</td>
                <td className="num">{(r.latency_p99_us / 1000).toFixed(2)} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.targets && <div className="hint">Targets: p50 &lt; {(data.targets.latency_p50_us / 1000)} ms, p99 &lt; {(data.targets.latency_p99_us / 1000)} ms. Latency is gateway overhead only.</div>}
        {message && <div className="hint">{message}</div>}
        <div className="hint">Contained = attack achieved no effect. Blocked = gateway denied by policy. Only the full profile blocks argument-level and data-flow attacks.</div>
      </div>
    </div>
  );
}

function Audit({ client, state }) {
  const [res, setRes] = useState(null);
  const [records, setRecords] = useState([]);
  const verify = () => client.get("/admin/audit/verify").then(setRes);
  useEffect(() => { client.get("/admin/decisions?limit=12").then(setRecords).catch(() => {}); }, [client]);
  return (
    <div className="panel">
      <h2>Audit log — Ed25519-signed, hash-chained; any edit breaks verification</h2>
      <div className="body">
        <button className="act" onClick={verify}>Verify chain now</button>
        {res && (
          <div style={{ marginTop: 12 }}>
            <span className={"verdict " + (res.ok ? "allow" : "deny")}>{res.ok ? "VALID" : "TAMPERED"}</span>
            <span className="mono" style={{ marginLeft: 12 }}>{res.records} records</span>
            {res.problem && <div className="hint" style={{ color: "var(--deny)" }}>{res.problem} (at record {res.broken_at})</div>}
          </div>
        )}
        {state && <div className="hint">Signing key (public): <span className="mono">{state.audit_public_key?.slice(0, 32)}…</span> · backend: {state.audit_backend}</div>}
        <div className="audit-process"><div><b>01</b><span>Record decision</span><small>tool, agent, verdict, facts</small></div><i>→</i><div><b>02</b><span>Hash record</span><small>SHA-256 content hash</small></div><i>→</i><div><b>03</b><span>Link chain</span><small>previous hash included</small></div><i>→</i><div><b>04</b><span>Sign</span><small>Ed25519 signature</small></div></div>
        <h3 className="audit-subtitle">Recent signed records</h3>
        {records.length === 0 ? <div className="empty">No audit records yet.</div> : <div className="audit-chain">{records.map((record) => <div className="audit-record" key={record.id}><span className="mono">#{record.seq}</span><span className="mono">{record.type}</span><span>{record.tool || record.reason}</span><small>prev {record.prev_hash?.slice(0, 10)}… → hash {record.hash?.slice(0, 10)}… · sig {record.sig?.slice(0, 10)}…</small></div>)}</div>}
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
