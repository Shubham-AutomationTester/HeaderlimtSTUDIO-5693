import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))
DEFAULT_HEADER_SIZE = 13267


class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        try:
            header_size = int(
                params.get("size", [DEFAULT_HEADER_SIZE])[0]
            )
        except ValueError:
            header_size = DEFAULT_HEADER_SIZE

        header_size = max(1, min(header_size, 100000))

        self.send_response(200)

        self.send_header(
            "Content-Security-Policy",
            "a" * header_size
        )

        self.send_header("Content-Type", "text/html")
        self.end_headers()

        html = f"""
        <html>
        <head>
            <title>Large Header Test</title>
        </head>
        <body>
            <h1>SearchStax Crawler Header Test</h1>
            <p>Header size: {header_size} bytes</p>

            <ul>
                <li><a href="/?size=5000">5000 bytes</a></li>
                <li><a href="/?size=10000">10000 bytes</a></li>
                <li><a href="/?size=13267">13267 bytes</a></li>
                <li><a href="/?size=65536">65536 bytes</a></li>
                <li><a href="/?size=70000">70000 bytes</a></li>
            </ul>
        </body>
        </html>
        """

        self.wfile.write(html.encode())


if __name__ == "__main__":
    print(f"Starting server on port {PORT}")
    HTTPServer((HOST, PORT), TestHandler).serve_forever()