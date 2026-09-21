"""Loopback-only library update demo; accepts data, never user-supplied templates."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlsplit

import jinja2
from jinja2.sandbox import SandboxedEnvironment


# Report the library this process actually imported, even while files on disk
# are replaced by a subsequent deployment.
LIBRARY_VERSION = jinja2.__version__


TEMPLATE = SandboxedEnvironment(autoescape=True).from_string("""<!doctype html>
<html lang="ko"><meta charset="utf-8"><title>EOLWatch 데모 앱</title>
<style>body{font:18px system-ui;max-width:720px;margin:80px auto;padding:24px;background:#f4f7fb;color:#172334}
main{background:white;padding:36px;border-radius:16px}small{color:#526477}code{background:#e7eef8;padding:6px}</style>
<main><small>EOLWATCH · DEPENDENCY UPDATE DEMO</small><h1>서버 안내 페이지</h1>
<p>{{ message }}</p><p>설치된 Jinja2: <code>{{ library_version }}</code></p>
<p>라이브러리 업데이트 전후에 같은 페이지가 정상 출력되는지 확인합니다.</p></main></html>""")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == "/health":
            body = json.dumps({"status": "ok", "jinja2": LIBRARY_VERSION}).encode()
            content_type = "application/json"
        elif path.path == "/":
            message = parse_qs(path.query).get("message", ["실습 서버의 서비스가 정상 실행 중입니다."])[0][:200]
            body = TEMPLATE.render(message=message, library_version=LIBRARY_VERSION).encode()
            content_type = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 19090), Handler).serve_forever()
