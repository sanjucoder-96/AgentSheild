# Architecture and data flow

## System architecture

The gateway is the only network path from any agent to any tool. Tool servers
accept connections only from the gateway (a shared credential the agent never
holds), so an agent cannot skip it.

```mermaid
flowchart LR
    agent["AI agent<br/>(MCP client)"]
    subgraph GW["Secure Agent Tool Gateway"]
        proxy["MCP proxy<br/>(Go, Streamable HTTP)"]
        pipe["Deny-by-default pipeline<br/>parse · canonicalize · inspect"]
        policy["Cedar policy engine<br/>(in-process, hot reload)"]
        reg["Manifest registry<br/>(hash pins, quarantine)"]
        appr["Approval broker<br/>(human queue)"]
        vault["Credential store<br/>(gateway-held)"]
        audit["Audit log<br/>(Ed25519 hash chain)"]
        sess["Session store<br/>(taint · kill switch)"]
    end
    admin["Security admin<br/>+ dashboard"]
    human["Human approver"]
    subgraph TOOLS["Tool servers (harness)"]
        ws["workspace"]
        cm["comms"]
        crm["crm"]
    end

    agent -->|"tools/call"| proxy
    proxy --> pipe
    pipe --> reg
    pipe --> policy
    policy -->|approve?| appr
    appr <-->|decide| human
    pipe --> sess
    proxy -->|"allow: inject creds"| vault
    vault -->|"forward"| ws & cm & crm
    proxy --> audit
    admin <-->|"policies, approvals,<br/>kill switch, verify"| GW
    audit --> admin
```

Any stage can end a call with **deny** or **require-approval**. Only calls that
clear the policy decision reach a tool server, and every decision is written to
the audit log and streamed to the dashboard.

## Request data flow

```mermaid
sequenceDiagram
    participant A as AI agent
    participant G as Gateway
    participant P as Cedar policy
    participant H as Human
    participant T as Tool server

    A->>G: tools/call (name, arguments)
    G->>G: 1 authenticate (JWT/OIDC) · kill-switch · rate
    G->>G: 2 strict parse (reject dup keys, batches)
    G->>G: 3 manifest check (hash pinned?)
    G->>G: 4 canonicalize + decode arguments
    G->>G: 5 schema validate (no smuggled args)
    G->>G: 6 inspect → facts (dests, IPs, paths, cmds, secrets, taint)
    G->>P: 7 decide(principal, action, resource, facts)
    alt DENY
        P-->>G: forbid rule matched
        G-->>A: blocked + reason code
    else APPROVE?
        P-->>G: permit with @approval
        G->>H: hold in queue
        H-->>G: approve / deny (timeout = deny)
        G->>T: 8 forward with injected credentials
        T-->>G: result
        G->>G: 9 inspect response (redact, flag injection, update taint)
        G-->>A: result (labelled)
    else ALLOW
        P-->>G: permit
        G->>T: 8 forward with injected credentials
        T-->>G: result
        G->>G: 9 inspect response
        G-->>A: result (labelled)
    end
    G->>G: 10 sign + append audit · push to dashboard
```

## Data-flow (provenance) tracking

The cross-call rule that a name-only allowlist cannot express:

```mermaid
flowchart TD
    t1["read_ticket T-1006<br/>(reads_untrusted)"] -->|"extract recipients,<br/>mark session tainted"| S[("session state")]
    t2["query_customers<br/>(reads_private)"] -->|"fingerprint canaries,<br/>mark has-private"| S
    t3["send_email to it-archive@acme.example"] --> chk{"recipient from untrusted<br/>AND carries private data?"}
    S --> chk
    chk -->|yes| deny["DENY<br/>block-injected-recipient-with-private-data"]
    chk -->|no| allow["continue to policy"]
```

## Deployment (Level 2 → Level 4)

```mermaid
flowchart LR
    subgraph L2["Level 2: docker compose"]
        g2["gateway"] --- pg[("PostgreSQL")]
        g2 --- rd[("Redis")]
        g2 --- ts["tool servers"]
    end
    subgraph L4["Level 4: Kubernetes"]
        lb["ingress"] --> g4["gateway (HPA)"]
        g4 --- pgc[("Postgres")]
        g4 --- rdc[("Redis cluster")]
        g4 --> prom["Prometheus + Grafana"]
    end
    L2 -->|"CI/CD, SHA-pinned"| L4
```
