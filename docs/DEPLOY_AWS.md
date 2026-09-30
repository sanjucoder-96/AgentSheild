# Deploying AgentShield to AWS (EC2 + RDS)

This guide takes you from an empty AWS account to a public HTTPS URL, with the
audit log in Amazon RDS for PostgreSQL. Budget about **60 minutes** the first
time, most of it waiting for RDS to start. Follow the steps in order.

## What you are building

```
                 ┌──────────────── EC2 (Ubuntu 24.04, Docker) ────────────────┐
 Internet ─443──▶│ Caddy (HTTPS, Let's Encrypt) ──▶ Gateway ──▶ Tool servers  │
                 │                                    │   └──▶ Redis           │
                 └────────────────────────────────────┼───────────────────────┘
                                                      │ TLS (certificate verified)
                                                      ▼
                                   Amazon RDS PostgreSQL (private, encrypted)
```

- Only ports **80 and 443** are open to the internet (plus SSH from your IP only).
- The tool servers and Redis sit on an internal Docker network with no internet access.
- RDS has **no public address**. Only the EC2 instance can reach it, because of one
  security-group rule (step 2). That rule *is* the connection between EC2 and RDS.

**Cost:** a small EC2 instance plus the smallest RDS instance cost a few cents an
hour, a few dollars for the whole event. Your credits cover it easily.

---

## Step 0 — Before you start (5 min)

1. **Region:** select **Asia Pacific (Mumbai) `ap-south-1`** in the top-right of the
   console, and use it for *everything* below. EC2 and RDS must be in the same region.
2. **Budget alert:** Billing → Budgets → Create budget → "Zero spend" or a $10
   monthly budget with your email. (Creating a budget also earns $20 of credit.)
3. **Rotate the Groq key.** The old key travelled inside a zip file. In the Groq
   console, create a new key and delete the old one. You'll paste the new one in step 6.

---

## Step 1 — Security groups (5 min)

EC2 → Network & Security → **Security Groups** → Create security group. Make two:

**`aegis-ec2-sg`** (VPC: the default VPC)

| Type | Port | Source |
|---|---|---|
| SSH | 22 | **My IP** |
| HTTP | 80 | Anywhere-IPv4 (0.0.0.0/0) |
| HTTPS | 443 | Anywhere-IPv4 (0.0.0.0/0) |

**`aegis-rds-sg`** (same default VPC)

| Type | Port | Source |
|---|---|---|
| PostgreSQL | 5432 | **Custom → select `aegis-ec2-sg`** (the security group, not an IP) |

> This rule means "only machines in `aegis-ec2-sg` may open a database connection".
> Nothing on the internet can reach RDS, even if it knew the address and password.
> Port 80 must stay open: Let's Encrypt uses it to issue your HTTPS certificate.

---

## Step 2 — Launch the EC2 instance (5 min)

EC2 → Instances → **Launch instances**:

| Setting | Value |
|---|---|
| Name | `aegis-server` |
| AMI | **Ubuntu Server 24.04 LTS**, architecture **64-bit (x86)** — not Arm |
| Instance type | `t3.small` if offered, otherwise `t3.micro` (the setup script adds swap) |
| Key pair | Create new → `aegis-key` → .pem → download and keep it safe |
| Network | Default VPC, **Auto-assign public IP: Enable**, existing SG **`aegis-ec2-sg`** |
| Storage | 20 GiB **gp3**, open *Advanced* and set **Encrypted: Yes** |

Then give it a fixed address: EC2 → **Elastic IPs** → Allocate → Actions →
Associate → choose `aegis-server`. Note this IP; it stays the same across restarts.

> Why x86: the CI pipeline builds `linux/amd64` images. An Arm (t4g) instance would
> not run them.

---

## Step 3 — A domain name for HTTPS (5 min)

Let's Encrypt needs a domain name, not a bare IP. Use either:

- **Your own domain:** add an `A` record pointing to the Elastic IP, or
- **DuckDNS (free):** sign in at duckdns.org, create a subdomain such as
  `agentshield-team`, and set its IP to the Elastic IP.

Check it resolves (from your laptop): `nslookup agentshield-team.duckdns.org` must
show the Elastic IP. Your `DOMAIN` is `agentshield-team.duckdns.org`.

---

## Step 4 — Create the RDS database (5 min to click, ~10 min to start)

RDS → Databases → **Create database**:

| Setting | Value |
|---|---|
| Creation method | Standard create |
| Engine | **PostgreSQL**, version 16.x |
| Template | **Free tier** (or Dev/Test, Single-AZ) |
| DB instance identifier | `aegis-db` |
| Master username | `aegis_admin` |
| Credentials | **Self managed**, type a password: **letters and digits only**, 20+ characters |
| Instance class | the smallest offered (`db.t4g.micro` or `db.t3.micro`) |
| Storage | 20 GiB gp3, turn **off** storage autoscaling |
| Connectivity: compute resource | Don't connect to an EC2 compute resource |
| VPC | Default VPC |
| **Public access** | **No** |
| VPC security group | Choose existing → **`aegis-rds-sg`** (remove `default`) |
| Additional configuration → Initial database name | **`aegis`** |
| Backups | 1 day retention is fine |
| **Encryption** | **Enabled** (default AWS key) |

Create it. When the status is **Available**, open it and copy the **Endpoint**
(like `aegis-db.abc123xyz.ap-south-1.rds.amazonaws.com`).

> Letters-and-digits password: the password goes inside a URL. Symbols such as
> `@ : / ? #` would break it unless URL-encoded.
>
> Alternative: choosing "Connect to an EC2 compute resource" and picking
> `aegis-server` makes AWS create the two security groups for you. Either way works.

Your connection string (step 6) will be:

```
postgres://aegis_admin:YOURPASSWORD@YOUR-ENDPOINT:5432/aegis?sslmode=verify-full&sslrootcert=/certs/global-bundle.pem
```

`sslmode=verify-full` encrypts the connection **and** checks that the server
certificate is signed by Amazon's RDS certificate authority and matches the
endpoint name. The setup script downloads Amazon's CA bundle to `certs/`.

---

## Step 5 — Prepare the server (5 min)

From the repository folder on your laptop (Git Bash, WSL, macOS or Linux):

```bash
chmod 400 aegis-key.pem
scp -i aegis-key.pem -r deploy ubuntu@<ELASTIC-IP>:/tmp/aegis-deploy
ssh -i aegis-key.pem ubuntu@<ELASTIC-IP> 'sudo bash /tmp/aegis-deploy/setup_ec2.sh'
```

The script installs Docker, adds swap on small instances, creates `/opt/aegis`,
downloads the RDS CA bundle, and writes `/opt/aegis/.env` with random secrets. It
prints the **dashboard password once**. Note it (it is also in `.env`).

---

## Step 6 — Fill in `.env` (3 min)

```bash
ssh -i aegis-key.pem ubuntu@<ELASTIC-IP>
nano /opt/aegis/.env
```

Set these four lines and leave the generated secrets alone:

```
DOMAIN=agentshield-team.duckdns.org
IMAGE_OWNER=sanjucoder-96
DATABASE_URL=postgres://aegis_admin:YOURPASSWORD@YOUR-ENDPOINT:5432/aegis?sslmode=verify-full&sslrootcert=/certs/global-bundle.pem
MODEL_API_KEY=<your NEW Groq key>
```

Then **log out and SSH back in** (so your user can run Docker without sudo).

---

## Step 7 — Prove EC2 can reach RDS (1 min)

```bash
cd /opt/aegis && ./check_rds.sh
```

Expected: the PostgreSQL version, then a row showing `ssl = t` and `TLSv1.3` (or 1.2).
That's your evidence for the judges that the database connection is encrypted and verified.

If it hangs, it's the security group (step 1). If it says "password authentication
failed", check the password and the letters-and-digits rule. If it mentions a
certificate, check that `certs/global-bundle.pem` exists.

---

## Step 8 — Deploy

### Option A: GitHub Actions (the Level 3 CI/CD story)

In the GitHub repository → **Settings**:

1. **Environments** → New environment `production` → add *environment secrets*:
   - `EC2_HOST` = the Elastic IP (or the domain)
   - `EC2_USER` = `ubuntu`
   - `EC2_SSH_KEY` = the full contents of `aegis-key.pem`, including the BEGIN/END lines
2. **Secrets and variables → Actions → Variables** → New repository variable
   `DEPLOY_ENABLED` = `true`
3. Commit and push to `V1-WorkingCopy` (or `main`). Watch **Actions**: `test` →
   `images` → `deploy`. The first run takes ~8 minutes; later runs are faster (cached).

The pipeline tests everything, builds both images, pushes them to GitHub Container
Registry, copies `deploy/` to the server and runs `./deploy.sh <commit-sha>`.

### Option B: deploy from the server by hand

After Option A has built images once, you can redeploy manually:

```bash
cd /opt/aegis && ./deploy.sh
```

GHCR packages start private. For manual pulls, either make the two packages public
(GitHub → your profile → Packages → package settings → Change visibility), or run
`docker login ghcr.io` with a personal access token that has `read:packages`.

### Plan B: CI isn't working at 2 a.m.

Build on the server itself (slower, ~10 minutes on a small instance):

```bash
git clone <your-repo-url> ~/aegis-src && cd ~/aegis-src/deploy
cp /opt/aegis/.env . && cp -r /opt/aegis/certs .
./deploy.sh --build
```

### Plan C: RDS isn't ready

Put the commented `Plan B` `DATABASE_URL` line from `.env` into effect, then
`LOCALDB=1 ./deploy.sh`. Postgres runs in Docker instead. Switch back to RDS later
by restoring the RDS line and running `./deploy.sh` again.

---

## Step 9 — Verify (2 min)

1. Open `https://<DOMAIN>` → the padlock shows a valid certificate → sign in as
   `admin` with the generated password.
2. The live feed connects; the Tools page shows 10 active tools.
3. Audit → **Verify chain** → VALID. The records are in RDS.
4. Benchmark → **Run benchmark** → full profile: 100% contained, 0% false positives.

Run the scripted demo from your laptop against the public URL:

```bash
GATEWAY_URL=https://<DOMAIN> ADMIN_TOKEN=<from .env> GATEWAY_JWT_SECRET=<from .env> \
  python3 demo/run_demo.py
```

Steps 1–4 run exactly as locally. For step 5 (rug pull), the tool servers are not
reachable from the internet by design, so trigger it on the server instead:

```bash
cd /opt/aegis && ./demo_rugpull.sh     # then Tools → Refresh: send_email is quarantined
```

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Browser shows a certificate error | DNS doesn't point at the Elastic IP yet, or port 80 is closed. Check `nslookup` and `aegis-ec2-sg`. `docker compose -f docker-compose.prod.yml logs caddy` shows the ACME error. |
| `deploy.sh` says gateway is unhealthy, logs say "refusing to start in production" | A secret in `.env` is missing or still a default. The log lists which one. |
| Gateway log: `dial tcp ... 5432: i/o timeout` | RDS security group: the inbound source must be `aegis-ec2-sg`. |
| `password authentication failed` | Wrong password, or special characters in the URL. |
| `x509: certificate signed by unknown authority` | `certs/global-bundle.pem` missing. Re-run `setup_ec2.sh` or download it again. |
| `pull access denied` / `denied` | GHCR packages are private: use the pipeline, make them public, or `docker login ghcr.io`. |
| Instance freezes during `--build` | Out of memory: use CI-built images, or a bigger instance. Swap is added by setup. |
| AI features say "Groq is not configured" | `MODEL_API_KEY` is empty in `.env`; run `./deploy.sh` after setting it. |

Useful commands on the server (from `/opt/aegis`):

```bash
alias dc='docker compose -f docker-compose.prod.yml --env-file .env --env-file release.env'
dc ps                      # status of every container
dc logs -f gateway         # gateway logs
dc restart gateway         # restart one service
```

---

## After the event: stop the charges

1. RDS → `aegis-db` → Actions → **Delete** (no final snapshot).
2. EC2 → `aegis-server` → Instance state → **Terminate**.
3. EC2 → Elastic IPs → **Release** the address (unattached IPs are charged).
4. Delete the Groq key you used for the demo.
