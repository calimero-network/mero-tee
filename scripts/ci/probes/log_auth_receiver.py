#!/usr/bin/env python3
"""Stand-in log sink that reports whether each push carried the expected token.

Runs on a throwaway VM next to a staging-probe node (see
node_secret_fetch_probe.sh). The node's vector is pointed here as its
`logs-endpoint`, with `logs-secret-name` naming a Secret Manager secret, so the
bearer token on each push is whatever `fetch_secret.sh gcp` fetched on the node.
A locked-read-only node has no shell and no serial console to ask, so this is
where the result becomes visible.

Only the SHA-256 of the expected token is given to this process, so the token
itself is never on this VM. Each request is classified and written as one line:

    PROBE_AUTH_OK        Authorization: Bearer <token whose sha256 matches>
    PROBE_AUTH_MISMATCH  a bearer token, but not the expected one
    PROBE_AUTH_NONE      no Authorization header: the node's fetch failed and
                         vector pushed unauthenticated

The probe reads these lines from the VM's serial console. Every request gets a
200 with an empty Elasticsearch bulk response, so vector keeps pushing instead
of backing off.
"""

import hashlib
import http.server
import os


WANT = os.environ["WANT_SHA256"].strip().lower()
PORT = int(os.environ.get("PROBE_PORT", "9200"))
OUT = open(os.environ.get("PROBE_OUT", "/dev/ttyS0"), "a", buffering=1)


def classify(authorization):
    if not authorization:
        return "NONE"
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        return "MISMATCH"
    if hashlib.sha256(token.encode()).hexdigest() == WANT:
        return "OK"
    return "MISMATCH"


class Handler(http.server.BaseHTTPRequestHandler):
    def _reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        verdict = classify(self.headers.get("Authorization", ""))
        OUT.write(f"PROBE_AUTH_{verdict} {self.command} {self.path}\n")
        self._reply(b'{"took":0,"errors":false,"items":[]}')

    do_PUT = do_POST

    def do_GET(self):
        # Answered, not classified: a version probe carries no log data.
        self._reply(b'{"version":{"number":"8.0.0"}}')

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    OUT.write(f"PROBE_RECEIVER_READY port={PORT}\n")
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
