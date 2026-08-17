import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 100000))
DEFAULT_HEADER_SIZE = 13267


class TestHandler(BaseHTTPRequestHandler):

    def get_header_size(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        try:
            size = int(params.get("size", [DEFAULT_HEADER_SIZE])[0])
        except ValueError:
            size = DEFAULT_HEADER_SIZE

        return max(1, min(size, 1000000))

    def send_test_headers(self, header_size):
        self.send_response(200)
        self.send_header(
            "Content-Security-Policy",
            "a" * header_size
        )
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.end_headers()

    def do_HEAD(self):
        header_size = self.get_header_size()
        self.send_test_headers(header_size)

    def do_GET(self):
        header_size = self.get_header_size()
        self.send_test_headers(header_size)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SearchStax Header Test</title>
         <footer>
        <p><strong>Author:</strong> Shubham Sharma </p>
    </footer>
        </head>
        <body>
            <h1>SearchStax Crawler Header Test</h1>
            <p>Header size: {header_size} bytes</p>

            <a href="/?size=5000">5000</a><br>
            <a href="/?size=8000">8000</a><br>
            <a href="/?size=8190">8190</a><br>
            <a href="/?size=8200">8200</a><br>
            <a href="/?size=10000">10000</a><br>
            <a href="/?size=70000">70000</a><br>
            <a href="/?size=65500">65536</a><br>
            <a href="/?size=65502">65537</a><br>
            <a href="/?size=13267">13267</a>
        </body>
        </html>
        """

        self.wfile.write(html.encode("utf-8"))


if __name__ == "__main__":
    print(f"Starting on {HOST}:{PORT}")
    HTTPServer((HOST, PORT), TestHandler).serve_forever()
