"""
Sanctioned Local Vulnerability Lab Server (Juice Shop / crAPI benchmark simulation)
Exposes known vulnerabilities (BOLA, SQLi, XSS, Exposed .env Secret, OpenAPI schema)
for live verification of the REVENANT Autonomous Red Teaming loop.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Sanctioned Lab API", "version": "1.0.0"},
    "paths": {
        "/api/v1/users/{id}": {
            "get": {
                "summary": "Get user profile (BOLA vulnerable)",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "User data"}, "500": {"description": "Unhandled crash on negative id"}},
            }
        },
        "/api/Feedbacks": {
            "get": {
                "summary": "Feedback search (XSS vulnerable)",
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Search results"}},
            }
        },
    },
}


class LabServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silent logging to avoid test clutter
        pass

    def end_headers(self):
        self.send_header("Connection", "close")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Sanctioned-Lab/1.0 Express/4.18.2")
            self.end_headers()
            html = """<!DOCTYPE html>
<html>
<head><title>OWASP Juice Shop / crAPI Lab</title></head>
<body>
    <h1>Welcome to Sanctioned Lab</h1>
    <nav>
        <a href='/rest/user/login'>Login API</a>
        <a href='/api/Feedbacks'>Feedbacks</a>
        <a href='/redirect?next=/dashboard'>Safe Redirect</a>
        <a href='/view?file=intro.txt'>Document Viewer</a>
    </nav>
    <section>
        <h2>Search Application</h2>
        <form action="/search" method="GET">
            <input type="text" name="query" placeholder="Search products..." />
            <button type="submit">Search</button>
        </form>
    </section>
    <section>
        <h2>User Authentication</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Sign In</button>
        </form>
    </section>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))

        elif path == "/.env":
            # Exposed credential / secret vulnerability
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret_revenant_lab\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nJWT_SECRET=insecure_token_key\n")

        elif path == "/rest/user/login":
            # SQL injection simulation
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "success", "message": "SQL Injection vulnerability: authentication bypassable", "user": "admin"}')

        elif path == "/api/Feedbacks":
            # Reflected XSS
            q = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            resp = f"<html><body>Search Results for: {q}</body></html>"
            self.wfile.write(resp.encode("utf-8"))

        elif path.startswith("/api/v1/users/"):
            # BOLA / unhandled exception crash on invalid input
            uid_str = path.split("/")[-1]
            try:
                uid = int(uid_str)
                if uid < 0:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Internal Server Error: Unhandled Negative Index Exception in UserManager.java:142"}')
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"id": uid, "username": f"user_{uid}", "role": "admin" if uid == 1 else "user"}).encode())
            except ValueError:
                self.send_response(400)
                self.end_headers()

        elif path == "/search":
            # Reflected XSS vulnerability in parameter 'query'
            query_val = query.get("query", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<!DOCTYPE html><html><body><h1>Search Results</h1><p>Results for: {query_val}</p></body></html>".encode("utf-8"))

        elif path == "/redirect":
            # Open redirect vulnerability in parameter 'next'
            target_url = query.get("next", [""])[0]
            if target_url:
                self.send_response(302)
                self.send_header("Location", target_url)
                self.end_headers()
            else:
                self.send_response(400)
                self.end_headers()

        elif path == "/view":
            # Path traversal vulnerability in parameter 'file'
            file_param = query.get("file", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if "win.ini" in file_param or "passwd" in file_param:
                self.wfile.write(b"; for 16-bit app support\n[extensions]\nroot:x:0:0:root:/root:/bin/bash\n")
            else:
                self.wfile.write(b"Document content: Hello from sanctioned lab file server.")

        elif path == "/openapi.json" or path == "/swagger.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(OPENAPI_SPEC).encode())

        elif path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Admin Dashboard</h1><p>Superuser administration panel.</p>")

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="ignore")
        post_data = parse_qs(body)

        if path == "/login":
            username = post_data.get("username", [""])[0]
            if "'" in username or "OR" in username:
                # Simulated SQL injection error
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Internal Error: sqlite3.OperationalError: unrecognized token: '' OR '1'='1'")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "authenticated", "user": "test_user"}')
        else:
            self.send_response(404)
            self.end_headers()


def run_server(port=3000):
    server = ThreadedHTTPServer(("0.0.0.0", port), LabServerHandler)
    print(f"Sanctioned Lab Server listening on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
