#!/usr/bin/env python3
"""A stand-in agent for building and probing the agent image.

The image takes any program as /usr/local/bin/mero-agent (docs/design/
private-agents.md). This one does nothing an agent would: it serves /health on
loopback and reports which secrets the gate has provisioned, by NAME, so a
debug image can be booted end to end before a real agent exists. It never
reads a secret's value.

One runs per slot (mero-agent@<n>.service). Environment: MERO_AGENT_DATA_DIR
and MERO_AGENT_RELAY_URL (from /run/mero-agent/agent.env, written by
agent-init) and MERO_AGENT_SLOT (the unit's instance). It reads the slot's
secrets directory, $MERO_AGENT_DATA_DIR/agents/<slot>/secrets, and listens on
127.0.0.1:<18080 + slot> (clear of the gate on 8090 and node_exporter on 9100).
"""

import http.server
import json
import os

SLOT = int(os.environ.get("MERO_AGENT_SLOT", "1"))
LISTEN = ("127.0.0.1", int(os.environ.get("MERO_AGENT_STUB_PORT", str(18080 + SLOT))))
SECRETS_DIR = os.environ.get(
    "MERO_AGENT_SECRETS_DIR",
    os.path.join(os.environ.get("MERO_AGENT_DATA_DIR", "/mnt/agent"), "agents", str(SLOT), "secrets"),
)


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
                "slot": SLOT,
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
    print(f"stub mero-agent, slot {SLOT}, on {LISTEN[0]}:{LISTEN[1]}; secrets in {SECRETS_DIR}", flush=True)
    http.server.ThreadingHTTPServer(LISTEN, Handler).serve_forever()
