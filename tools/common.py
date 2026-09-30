"""Shared plumbing for the mock MCP tool servers.

Every tool server only accepts requests that carry the gateway's credential
(header ``X-Gateway-Credential``). The agent never holds this value, so it
cannot bypass the gateway and talk to a tool server directly.

The ``--allow-direct`` flag turns that check off. It exists only for the
"no gateway" baseline in the demo, which shows what happens today when an
agent holds tool credentials itself.
"""

from __future__ import annotations

import argparse
import hmac
import os
import sys

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Receive, Scope, Send

CREDENTIAL_HEADER = b"x-gateway-credential"


class GatewayCredentialMiddleware:
    """Rejects any HTTP request that lacks the gateway credential."""

    def __init__(self, app: ASGIApp, secret: str, allow_direct: bool) -> None:
        self.app = app
        self.secret = secret.encode()
        self.allow_direct = allow_direct

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self.allow_direct:
            supplied = dict(scope.get("headers", [])).get(CREDENTIAL_HEADER, b"")
            if not hmac.compare_digest(supplied, self.secret):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body",
                            "body": b'{"error":"tool servers only accept calls from the gateway"}'})
                return
        await self.app(scope, receive, send)


def serve(server: MCPServer, default_port: int) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("TOOL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TOOL_PORT", default_port)))
    parser.add_argument("--allow-direct", action="store_true",
                        help="accept calls without the gateway credential (baseline demo only)")
    args = parser.parse_args()

    secret = os.environ.get("TOOL_SHARED_SECRET", "dev-tool-secret-change-me")
    app = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        # Host-header protection is replaced by the credential check above.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host=args.host,
    )
    wrapped = GatewayCredentialMiddleware(app, secret, args.allow_direct)
    mode = "DIRECT ACCESS ALLOWED (baseline)" if args.allow_direct else "gateway-only"
    print(f"[{server.name}] listening on http://{args.host}:{args.port}/mcp ({mode})", file=sys.stderr)
    uvicorn.run(wrapped, host=args.host, port=args.port, log_level="warning")
