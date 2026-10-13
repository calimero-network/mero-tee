#!/usr/bin/env python3
"""A stand-in agent for building and probing the agent image.

The image takes any program as /usr/local/bin/mero-agent (docs/design/
private-agents.md). This one does nothing an agent would: it serves /health on
loopback and reports which secrets the gate has provisioned, by NAME, so a
debug image can be booted end to end before a real agent exists. It never
reads a secret's value.

Environment (from /run/mero-agent/agent.env, written by agent-init):
  MERO_AGENT_SECRETS_DIR, MERO_AGENT_STATE_DIR, MERO_AGENT_RELAY_URL
"""

import http.server
import json
import os

LISTEN = ("127.0.0.1", int(os.environ.get("MERO_AGENT_STUB_PORT", "8081")))
SECRETS_DIR = os.environ.get("MERO_AGENT_SECRETS_DIR", "/mnt/agent/secrets")


def provisioned():
    try:
        return sorted(n for n in os.listdir(SECRETS_DIR) if not n.startswith("."))
    except OSError:
        return []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server's name)
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps(
            {
                "status": "ok",
                "stub": True,
                "relay": os.environ.get("MERO_AGENT_RELAY_URL", ""),
                "secrets": provisioned(),
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print(f"stub mero-agent on {LISTEN[0]}:{LISTEN[1]}; secrets in {SECRETS_DIR}", flush=True)
    http.server.ThreadingHTTPServer(LISTEN, Handler).serve_forever()
