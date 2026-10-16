"""Small HTTP toolkit shared by the aggregator and bank nodes (standard library only).

Each node is a ThreadingHTTPServer with:
  * JSON API routes registered as (method, path) -> handler(query, body, headers)
  * static pages from web/<role>/ ("/" -> index.html, "/ledger" -> ledger.html)
  * shared assets from web/static/
"""
from __future__ import annotations

import json
import mimetypes
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"


class ApiError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class NodeServer:
    def __init__(self, role: str, host: str, port: int):
        self.role, self.host, self.port = role, host, port
        self.routes: dict[tuple[str, str], callable] = {}
        self.pages = WEB / role
        self.httpd: ThreadingHTTPServer | None = None

    def route(self, method: str, path: str):
        def deco(fn):
            self.routes[(method, path)] = fn
            return fn
        return deco

    def _handler(self):
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code: int, obj) -> None:
                self._send(code, json.dumps(obj, default=_default).encode(), "application/json")

            def _dispatch(self, method: str):
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                body = None
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > 20_000_000:
                        return self._json(413, {"error": "payload too large"})
                    raw = self.rfile.read(n) if n else b"{}"
                    try:
                        body = json.loads(raw or b"{}")
                    except json.JSONDecodeError:
                        return self._json(400, {"error": "invalid JSON"})
                fn = server.routes.get((method, u.path))
                if fn is not None:
                    try:
                        out = fn(q, body, self.headers)
                        if isinstance(out, tuple) and out and out[0] == "__raw__":
                            return self._send(200, out[1].encode(), out[2])
                        return self._json(200, out)
                    except ApiError as e:
                        return self._json(e.code, {"error": e.message})
                    except Exception as e:  # never crash the node on one bad request
                        return self._json(500, {"error": f"{type(e).__name__}: {e}"})
                if method == "GET":
                    return self._static(u.path)
                return self._json(404, {"error": "unknown endpoint"})

            def _static(self, path: str):
                if path.startswith("/static/"):
                    base, rel = WEB / "static", path[len("/static/"):]
                else:
                    base, rel = server.pages, ("index" if path in ("/", "") else path.strip("/")) + ".html"
                f = (base / rel).resolve()
                if base.resolve() not in f.parents or not f.is_file():
                    return self._json(404, {"error": "not found"})
                self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

        return H

    def start(self, background: bool = False):
        self.httpd = ThreadingHTTPServer((self.host, self.port), self._handler())
        self.httpd.daemon_threads = True
        if background:
            threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        else:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                pass

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()


def _default(o):
    try:
        import numpy as np
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, (np.floating, np.integer)):
            return o.item()
    except ImportError:
        pass
    return str(o)


def http_json(method: str, url: str, body: dict | None = None, timeout: float = 30.0, headers: dict | None = None) -> dict:
    data = json.dumps(body, default=_default).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", str(e))
        except Exception:
            msg = str(e)
        raise ApiError(e.code, msg) from None


def payload_size(obj) -> int:
    return len(json.dumps(obj, default=_default).encode())
