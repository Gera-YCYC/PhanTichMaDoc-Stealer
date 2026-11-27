"""Bounded local HTTP transport. No proxies, redirects, cloud fallback or file uploads."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .contracts import ACTION_SCHEMA, PROTOCOL
from .security import check_endpoint


class TransportError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TransportError("HTTP redirects are disabled")


class LocalHTTP:
    def __init__(self, base_url: str, *, loopback_only: bool, token: str = "", timeout: int = 180):
        self.base_url = check_endpoint(base_url, loopback_only=loopback_only)
        self.timeout = timeout
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path: str, payload: dict | None = None) -> dict:
        if not path.startswith("/") or ".." in path:
            raise TransportError("Invalid API path")
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise TransportError("API response exceeded limit")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise TransportError("API response must be an object")
                return result
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise TransportError(f"Local API request failed: {type(exc).__name__}: {exc}") from exc


class OllamaClient:
    def __init__(self, config: dict):
        self.config = config
        self.http = LocalHTTP(config["ollama_url"], loopback_only=True, timeout=config.get("timeout_s", 180))
        self.model = config["model"]

    def inspect(self) -> dict:
        tags = self.http.request("/api/tags")
        entry = next((m for m in tags.get("models", []) if m.get("name") == self.model), None)
        if entry is None:
            raise TransportError(f"Exact model tag not installed: {self.model}; no auto-download")
        show = self.http.request("/api/show", {"model": self.model})
        return {"tag": self.model, "digest": entry.get("digest"), "size_bytes": entry.get("size"),
                "details": show.get("details", {}), "model_info": show.get("model_info", {}),
                "ollama_version": self.http.request("/api/version").get("version")}

    def chat(self, messages: list[dict], schema: dict = ACTION_SCHEMA) -> tuple[dict, dict]:
        start = time.perf_counter()
        payload = {
            "model": self.model, "messages": messages, "stream": False, "format": schema,
            "keep_alive": "2m",
            "options": {"temperature": 0, "seed": self.config.get("seed", 42),
                        "num_ctx": self.config.get("num_ctx", 4096),
                        "num_predict": self.config.get("num_predict", 900)},
        }
        if 'think' in self.config:
            if type(self.config['think']) is not bool:
                raise ValueError('This client supports an explicit boolean think setting only')
            payload['think']=self.config['think']
        data = self.http.request("/api/chat", payload)
        content = data.get("message", {}).get("content", "")
        metrics = {"latency_s": round(time.perf_counter() - start, 4),
                   "prompt_tokens": data.get("prompt_eval_count"), "completion_tokens": data.get("eval_count"),
                   "total_duration_ns": data.get("total_duration"), "done_reason": data.get("done_reason"),
                   "raw_response": content}
        try:
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError("Model output is not a JSON object")
        except ValueError as exc:
            # Preserve the malformed response so the caller can log it.
            return {"_parse_error": str(exc)}, metrics
        return result, metrics

    def vram_bytes(self) -> int | None:
        try:
            models = self.http.request("/api/ps").get("models", [])
            return next((m.get("size_vram") for m in models if m.get("name") == self.model), None)
        except TransportError:
            return None

    def unload(self):
        return self.http.request('/api/generate',{'model':self.model,'keep_alive':0})


class ToolClient:
    def __init__(self, config: dict, token: str):
        if len(token) < 32:
            raise ValueError("STEALER_LAB_TOKEN must contain at least 32 characters")
        self.http = LocalHTTP(config["tool_server_url"], loopback_only=False, token=token,
                              timeout=config.get("timeout_s", 180))

    def inspect(self) -> dict:
        health = self.http.request("/health")
        checks = health.get("isolation", {}).get("checks", {})
        if health.get("protocol") != PROTOCOL or health.get("environment") != "vm":
            raise TransportError("Tool server is not a verified VM endpoint")
        required = {"vm_hardware", "no_default_gateway", "operator_attestations"}
        if not required <= checks.keys() or not all(checks[k] is True for k in required):
            raise TransportError("VM isolation preflight is incomplete")
        return health

    def call(self, action: str, arguments: dict) -> dict:
        return self.http.request("/call", {"action": action, "arguments": arguments})
