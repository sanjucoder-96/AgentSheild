"""A fake attacker endpoint for the demo. It only listens on localhost and logs
whatever reaches it, so you can see on screen when data leaks.

Run:  python3 attacker/attacker_server.py      (port 9999)
View: http://127.0.0.1:9999/                   (everything captured so far)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CAPTURED: list[dict] = []
RED, RESET = "\033[91m", "\033[0m"


class Handler(BaseHTTPRequestHandler):
    def _capture(self, body: str) -> None:
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "method": self.command,
                 "path": self.path, "body": body[:2000]}
        CAPTURED.append(entry)
        print(f"{RED}[ATTACKER] data received {entry['time']}: {self.path} {body[:300]}{RESET}",
              file=sys.stderr, flush=True)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", 0))
        self._capture(self.rfile.read(length).decode(errors="replace"))

    def do_GET(self) -> None:
        if self.path in ("/", "/captured"):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(CAPTURED, indent=2).encode())
            return
        self._capture("")

    def do_DELETE(self) -> None:
        CAPTURED.clear()
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


if __name__ == "__main__":
    host = os.environ.get("ATTACKER_HOST", "127.0.0.1")
    port = int(os.environ.get("ATTACKER_PORT", "9999"))
    print(f"[attacker] capturing on http://{host}:{port}/", file=sys.stderr)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
