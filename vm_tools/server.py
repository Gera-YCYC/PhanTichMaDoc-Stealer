"""Small authenticated VM-only tool endpoint. No uploads, file browsing or shell API."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from stealer_agent.contracts import PROTOCOL
from stealer_agent.journal import Journal
from .isolation import inspect_isolation
from .service import ToolService


def build_handler(service: ToolService, config: dict, token: str, isolation: dict, journal: Journal):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "StealerLab/0.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass

        def respond(self, status: int, value: dict):
            encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def authorized(self) -> bool:
            if self.client_address[0] != config["allowed_client_ip"]:
                self.respond(403, {"error": "Client IP is not allowed"})
                return False
            if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                self.respond(401, {"error": "Unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            if self.path != "/health":
                self.respond(404, {"error": "Unknown endpoint"})
                return
            try:
                current = inspect_isolation(config)
            except Exception as exc:
                self.respond(503, {"error": str(exc)})
                return
            self.respond(200, {"protocol": PROTOCOL, "environment": "vm", "lab_id": config["lab_id"],
                               "isolation": current, "tools": service.capabilities()})

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != "/call":
                self.respond(404, {"error": "Unknown endpoint"})
                return
            if not lock.acquire(blocking=False):
                self.respond(409, {"error": "A tool call is already running"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 16384 or self.headers.get("Transfer-Encoding"):
                    raise ValueError("Invalid request size")
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict) or set(request) != {"action", "arguments"}:
                    raise ValueError("Expected action and arguments")
                inspect_isolation(config)
                journal.append("tool_requested", request=request)
                result = service.call(request["action"], request["arguments"])
                journal.append("tool_completed", result=result)
                self.respond(200, result)
            except Exception as exc:
                journal.append("request_rejected", error=f"{type(exc).__name__}: {exc}")
                self.respond(400, {"error": str(exc)})
            finally:
                lock.release()

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="VM-only static tools")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8-sig"))
    host = ipaddress.ip_address(config["bind_host"])
    if host.is_unspecified or host.is_multicast or not (host.is_private or host.is_loopback):
        raise ValueError("Bind only to the explicit host-only VM address")
    token = os.environ.get(config.get("token_env", "STEALER_LAB_TOKEN"), "")
    if len(token) < 32:
        raise ValueError("Lab bearer token must contain at least 32 characters")
    isolation = inspect_isolation(config)
    service = ToolService(config)
    from datetime import datetime, timezone
    journal = Journal(Path(config["evidence_dir"]) / ("server_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
    journal.append("server_started", isolation=isolation, tools=service.capabilities())
    server = ThreadingHTTPServer((str(host), config["port"]), build_handler(service, config, token, isolation, journal))
    print(f"VM tool server ready on {host}:{config['port']}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
