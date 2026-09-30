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
    post: (p, body) => fetch(p, { method: "POST", headers, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json()),
    put: (p, body) => fetch(p, { method: "PUT", headers: { ...headers, "Content-Type": "text/plain" }, body }).then((r) => r.json()),
  };
}

const VERDICT_LABEL = { allow: "ALLOW", deny: "DENY", approval: "APPROVE?", error: "ERROR" };

function App() {
  const [token, setToken] = useToken();
  const client = useMemo(() => api(token), [token]);
  const [tab, setTab] = useState("live");
  const [state, setState] = useState(null);
  const [connected, setConnected] = useState(false);
  const [decisions, setDecisions] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [tools, setTools] = useState([]);
  const wsRef = useRef(null);

  const refreshState = useCallback(() => client.get("/admin/state").then(setState).catch(() => setState(null)), [client]);

  useEffect(() => {
    refreshState();
    client.get("/admin/decisions?limit=100&type=decision").then(setDecisions).catch(() => {});
    client.get("/admin/approvals").then(setApprovals).catch(() => {});
    client.get("/admin/tools").then(setTools).catch(() => {});
    const t = setInterval(refreshState, 5000);
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
        if (type === "decision") setDecisions((d) => [data, ...d].slice(0, 200));
        else if (type === "approvals") setApprovals(data || []);
        else if (type === "tools") setTools(data || []);
        else if (type === "event") setDecisions((d) => [data, ...d].slice(0, 200));
        else if (type === "policies" || type === "manifest") refreshState();
      };
    }
    connect();
    return () => { stop = true; wsRef.current?.close(); };
  }, [token, refreshState]);

  const counts = useMemo(() => {
    const c = { allow: 0, deny: 0, approval: 0, error: 0 };
    for (const d of decisions) if (d.type === "decision" && c[d.verdict] !== undefined) c[d.verdict]++;
    return c;
  }, [decisions]);

  return (
    <div className="app">
      <header className="top">
        <div className="brand">Secure Agent Tool Gateway <small>PNC3 · zero-trust proxy for AI agent tool calls</small></div>
        <div className="status-pills">
          <span className={"pill " + (connected ? "live" : "down")}>{connected ? "● live" : "○ reconnecting"}</span>
          {state && <span className="pill">profile: {state.profile}</span>}
          {state && <span className="pill">policies: {state.policies_loaded}</span>}
          {state && <span className="pill">audit: {state.audit_backend?.split(":")[0]}</span>}
          <TokenBox token={token} setToken={setToken} />
        </div>
      </header>

      <nav className="tabs">
        <button data-active={tab === "live"} onClick={() => setTab("live")}>Live feed</button>
        <button data-active={tab === "approvals"} onClick={() => setTab("approvals")}>
          Approvals <span className="count">{approvals.length}</span>
        </button>
        <button data-active={tab === "tools"} onClick={() => setTab("tools")}>Tools</button>
        <button data-active={tab === "policies"} onClick={() => setTab("policies")}>Policies</button>
        <button data-active={tab === "benchmark"} onClick={() => setTab("benchmark")}>Benchmark</button>
        <button data-active={tab === "audit"} onClick={() => setTab("audit")}>Audit</button>
      </nav>

      <main>
        {tab === "live" && <LiveFeed counts={counts} decisions={decisions} />}
        {tab === "approvals" && <Approvals approvals={approvals} client={client} />}
        {tab === "tools" && <Tools tools={tools} client={client} state={state} />}
        {tab === "policies" && <Policies client={client} />}
        {tab === "benchmark" && <Benchmark client={client} />}
        {tab === "audit" && <Audit client={client} state={state} />}
      </main>
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

function LiveFeed({ counts, decisions }) {
  return (
    <>
      <div className="stats">
        <div className="stat allow"><div className="n">{counts.allow}</div><div className="l">allowed</div></div>
        <div className="stat deny"><div className="n">{counts.deny}</div><div className="l">denied</div></div>
        <div className="stat approval"><div className="n">{counts.approval}</div><div className="l">held for approval</div></div>
        <div className="stat"><div className="n">{decisions.filter((d) => d.type === "decision").length}</div><div className="l">total decisions</div></div>
      </div>
      <div className="panel feed">
        <h2>Live decision feed — every tool call, with its verdict, reason and the facts behind it</h2>
        {decisions.length === 0 && <div className="empty">No calls yet. Run the demo or the benchmark.</div>}
        {decisions.map((d, i) => <FeedRow key={d.id + i} d={d} />)}
      </div>
    </>
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
  const refresh = () => client.post("/admin/tools/refresh");
  const approve = (name) => client.post(`/admin/tools/${name}/approve`);
  return (
    <div className="panel">
      <h2>Registered tools — pinned by hash; a changed manifest is quarantined until reviewed</h2>
      <div className="body">
        <button className="act" onClick={refresh} style={{ marginBottom: 12 }}>Refresh manifests</button>
        <table>
          <thead><tr><th>Tool</th><th>Server</th><th>Status</th><th>Pinned hash</th><th>Flags</th><th></th></tr></thead>
          <tbody>
            {tools.map((t) => (
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
                </td>
                <td>{t.status === "quarantined" && <button className="act approve" onClick={() => approve(t.name)}>Re-approve</button>}</td>
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
  useEffect(() => { client.get("/admin/policies").then(setStatus).catch(() => {}); }, [client]);
  if (!status) return <div className="empty">Loading policies…</div>;
  return (
    <div className="grid two">
      <div className="panel">
        <h2>Policy rules in force ({status.policies?.length || 0})</h2>
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
        <h2>Cedar source — edit a file, save, and calls re-evaluate live</h2>
        <div className="body">
          {status.files && Object.entries(status.files).map(([name, text]) => (
            <PolicyEditor key={name} name={name} text={text} client={client} onSaved={() => client.get("/admin/policies").then(setStatus)} />
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
  return (
    <details className="policy-file" open={open} onToggle={(e) => setOpen(e.target.open)}>
      <summary>{name} {msg && <span style={{ color: msg.startsWith("rejected") ? "var(--deny)" : "var(--allow)" }}>— {msg}</span>}</summary>
      {open && (
        <div style={{ border: "1px solid var(--line)", borderTop: "none", borderRadius: "0 0 8px 8px" }}>
          <textarea value={val} onChange={(e) => setVal(e.target.value)} spellCheck={false}
            style={{ width: "100%", minHeight: 200, background: "var(--bg)", color: "#cdd9ea", border: "none", padding: 12, fontFamily: "var(--mono)", fontSize: 12, resize: "vertical" }} />
          <div style={{ padding: 10 }}><button className="act approve" onClick={save}>Save & reload</button></div>
        </div>
      )}
    </details>
  );
}

function Benchmark({ client }) {
  const [data, setData] = useState(null);
  useEffect(() => { client.get("/admin/bench").then(setData).catch(() => setData({ available: false })); }, [client]);
  if (!data) return <div className="empty">Loading…</div>;
  if (data.available === false || !data.results) return <div className="empty">No benchmark yet. Run <span className="mono">make bench</span> to generate results.</div>;
  return (
    <div className="panel">
      <h2>Benchmark — {data.cases} cases, generated {new Date(data.generated_at).toLocaleString()}</h2>
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
        <div className="hint">Contained = attack achieved no effect. Blocked = gateway denied by policy. Only the full profile blocks argument-level and data-flow attacks.</div>
      </div>
    </div>
  );
}

function Audit({ client, state }) {
  const [res, setRes] = useState(null);
  const verify = () => client.get("/admin/audit/verify").then(setRes);
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
        <div className="hint">Try tampering: <span className="mono">./bin/gatewayctl audit tamper --seq 3</span>, then verify again.</div>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
