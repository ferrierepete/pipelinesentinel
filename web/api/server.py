"""PipelineSentinel API server.

Lightweight async HTTP server using Python stdlib (no FastAPI dependency).
Serves the LangGraph agent as a REST API for the web UI.

Usage:
    python -m web.api.server [--port 8742] [--host 127.0.0.1]

Endpoints:
    POST /api/scan   — Run vulnerability scan on dependency file content
    GET  /api/health — Health check
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Ensure project root is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.graph import build_graph


class PipelineSentinelHandler(BaseHTTPRequestHandler):
    """HTTP request handler for PipelineSentinel API."""

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            self._json_response({"status": "ok", "service": "PipelineSentinel"})
        else:
            self._json_response({"error": "Not found"}, status=404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/scan":
            self._handle_scan()
        else:
            self._json_response({"error": "Not found"}, status=404)

    def _handle_scan(self):
        """Run vulnerability scan from posted file content."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            if not body:
                self._json_response({"error": "Empty request body"}, status=400)
                return

            data = json.loads(body)
            file_content = data.get("file_content", "")
            file_name = data.get("file_name", "requirements.txt")

            if not file_content.strip():
                self._json_response({"error": "Empty file content"}, status=400)
                return

        except json.JSONDecodeError:
            self._json_response({"error": "Invalid JSON"}, status=400)
            return
        except Exception as e:
            self._json_response({"error": f"Bad request: {e}"}, status=400)
            return

        # Run the graph synchronously
        try:
            graph = build_graph()
            initial_state = {
                "file_path": file_name,
                "file_content": file_content,
            }
            result = asyncio.run(self._run_graph(graph, initial_state))

            response_data = {
                "dependencies": result.get("dependencies", []),
                "ai_ml_deps": [
                    {"name": d["name"], "version": d.get("version", "")}
                    for d in result.get("ai_ml_deps", [])
                ],
                "osv_vulns": result.get("osv_vulns", []),
                "ghsa_vulns": result.get("ghsa_vulns", []),
                "kev_entries": [
                    {
                        "cve_id": k["cve_id"],
                        "vulnerability_name": k.get("vulnerability_name", ""),
                    }
                    for k in result.get("kev_entries", [])
                ],
                "findings": result.get("findings", []),
                "briefing": result.get("briefing", ""),
            }

            self._json_response(response_data)

        except Exception as e:
            self._json_response({"error": f"Scan failed: {e}"}, status=500)

    async def _run_graph(self, graph, initial_state: dict) -> dict:
        """Execute the LangGraph and return final state."""
        result = {}
        async for event in graph.astream_events(initial_state, version="v2"):
            if event.get("event") == "on_chain_end" and not event.get("tags"):
                output = event.get("data", {}).get("output")
                if output:
                    result = output
        return result

    def _json_response(self, data: dict, status: int = 200):
        """Send JSON response with CORS headers."""
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # CORS headers for web UI
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        """Override to add timestamp to logs."""
        sys.stderr.write(f"[PipelineSentinel] {args[0]}\n")


class ThreadedHTTPServer(HTTPServer):
    """HTTP server that handles each request in a new thread."""
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description="PipelineSentinel API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8742, help="Bind port (default: 8742)")
    args = parser.parse_args()

    server = ThreadedHTTPServer((args.host, args.port), PipelineSentinelHandler)
    print(f"🛡️ PipelineSentinel API server running on http://{args.host}:{args.port}")
    print(f"   POST /api/scan — Scan dependencies")
    print(f"   GET  /api/health — Health check")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
