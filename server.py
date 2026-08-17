import os
import asyncio
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import aiohttp


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))

DEFAULT_HEADER_SIZE = 13267
DEFAULT_MANAGER_LIMIT = 65536

AUTHOR_NAME = "Shubham Sharma"


# ---------------------------------------------------------
# CSP generation
# ---------------------------------------------------------

def build_realistic_csp(target_size):
    """
    Build a realistic Content-Security-Policy header whose value
    is approximately/exactly target_size ASCII bytes.

    Because all characters are ASCII:
        len(string) == number of bytes.
    """

    target_size = max(500, min(target_size, 200000))

    csp = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'self'; "
        "script-src 'self' https://cdn.example.com "
        "https://scripts.example.com; "
        "style-src 'self' https://styles.example.com; "
        "font-src 'self' https://fonts.example.com; "
        "img-src 'self' data: https://images.example.com; "
        "media-src 'self'; "
        "frame-src 'self' https://frames.example.com; "
        "connect-src 'self' https://api.example.com"
    )

    counter = 1

    # Add realistic-looking allowed connection sources.
    while True:
        source = f" https://api-{counter}.example.com"

        # Leave one character for the final semicolon.
        if len(csp) + len(source) + 1 > target_size:
            break

        csp += source
        counter += 1

    # Fill the remaining bytes with legal CSP whitespace.
    remaining = target_size - len(csp) - 1

    if remaining > 0:
        csp += " " * remaining

    csp += ";"

    return csp


# ---------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------

def page(title, content):
    return f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>{html.escape(title)}</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family:
                Inter,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Roboto,
                Arial,
                sans-serif;
            background: #f3f6fa;
            color: #172033;
            line-height: 1.55;
        }}

        .topbar {{
            background:
                linear-gradient(
                    135deg,
                    #101828,
                    #1d2939
                );
            color: white;
            padding: 42px 20px;
        }}

        .topbar-inner {{
            max-width: 1100px;
            margin: auto;
        }}

        .ticket {{
            display: inline-block;
            padding: 5px 11px;
            border-radius: 20px;
            background: rgba(255,255,255,.13);
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 12px;
        }}

        h1 {{
            margin: 0 0 8px;
            font-size: 34px;
        }}

        .subtitle {{
            color: #d0d5dd;
            margin: 0;
            max-width: 760px;
        }}

        main {{
            max-width: 1100px;
            margin: 28px auto;
            padding: 0 20px;
        }}

        .grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(290px, 1fr));
            gap: 20px;
        }}

        .card {{
            background: white;
            border: 1px solid #e4e7ec;
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow:
                0 4px 14px rgba(16,24,40,.05);
        }}

        .card h2 {{
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 20px;
        }}

        .muted {{
            color: #667085;
        }}

        .metric {{
            font-size: 34px;
            font-weight: 750;
            margin: 5px 0;
        }}

        .badge {{
            display: inline-block;
            border-radius: 20px;
            padding: 6px 12px;
            font-weight: 650;
            font-size: 13px;
        }}

        .pass {{
            background: #dcfae6;
            color: #067647;
        }}

        .fail {{
            background: #fee4e2;
            color: #b42318;
        }}

        .warning {{
            background: #fef0c7;
            color: #b54708;
        }}

        .info {{
            background: #e0f2fe;
            color: #075985;
        }}

        .buttons {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 18px;
        }}

        .button {{
            padding: 13px 14px;
            text-decoration: none;
            border-radius: 9px;
            text-align: center;
            font-weight: 650;
            background: #eef4ff;
            color: #3538cd;
            border: 1px solid #c7d7fe;
        }}

        .button:hover {{
            background: #e0eaff;
        }}

        .button.danger {{
            background: #fef3f2;
            color: #b42318;
            border-color: #fecdca;
        }}

        .button.special {{
            background: #ecfdf3;
            color: #067647;
            border-color: #abefc6;
        }}

        code {{
            background: #f2f4f7;
            border-radius: 5px;
            padding: 3px 6px;
            font-family:
                "SFMono-Regular",
                Consolas,
                monospace;
            font-size: 13px;
        }}

        pre {{
            overflow-x: auto;
            background: #101828;
            color: #eaecf0;
            padding: 18px;
            border-radius: 10px;
            line-height: 1.65;
        }}

        pre code {{
            background: transparent;
            color: inherit;
            padding: 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }}

        th,
        td {{
            padding: 13px;
            text-align: left;
            border-bottom: 1px solid #eaecf0;
        }}

        th {{
            color: #475467;
            background: #f9fafb;
        }}

        .flow {{
            font-family: monospace;
            white-space: pre;
            overflow-x: auto;
            background: #101828;
            color: #f2f4f7;
            padding: 20px;
            border-radius: 10px;
        }}

        .notice {{
            padding: 15px;
            border-radius: 9px;
            background: #eff8ff;
            border-left: 4px solid #2e90fa;
            margin-top: 15px;
        }}

        .result {{
            padding: 18px;
            border-radius: 10px;
            margin-top: 15px;
        }}

        .result.pass {{
            border: 1px solid #abefc6;
        }}

        .result.fail {{
            border: 1px solid #fecdca;
        }}

        input {{
            padding: 11px;
            border: 1px solid #d0d5dd;
            border-radius: 7px;
            width: 170px;
            font-size: 15px;
        }}

        button {{
            padding: 11px 17px;
            border: 0;
            background: #175cd3;
            color: white;
            font-weight: 650;
            border-radius: 7px;
            cursor: pointer;
        }}

        .form-row {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: end;
        }}

        label {{
            display: block;
            font-size: 13px;
            font-weight: 650;
            margin-bottom: 5px;
        }}

        footer {{
            text-align: center;
            color: #667085;
            padding: 30px 20px 45px;
            font-size: 14px;
        }}

        @media (max-width: 600px) {{
            h1 {{
                font-size: 27px;
            }}

            .metric {{
                font-size: 29px;
            }}
        }}

    </style>
</head>

<body>

    <header class="topbar">
        <div class="topbar-inner">

            <div class="ticket">
                STUDIO-5693
            </div>

            <h1>
                SearchStax Crawler Header Limit Test
            </h1>

            <p class="subtitle">
                Reproducible QA site for testing large HTTP
                response headers, aiohttp field limits,
                URL validation, and crawler job handling.
            </p>

        </div>
    </header>

    <main>
        {content}
    </main>

    <footer>
        Created by <strong>{html.escape(AUTHOR_NAME)}</strong>
        <br>
        SearchStax Crawler QA Utility
        · STUDIO-5693
    </footer>

</body>
</html>
"""


# ---------------------------------------------------------
# aiohttp simulation
# ---------------------------------------------------------

async def aiohttp_validation_check(size, limit):
    """
    This simulates the important portion of Manager URL validation:

        aiohttp.ClientSession(max_field_size=...)

    requesting a response containing a large CSP header.
    """

    test_url = (
        f"http://127.0.0.1:{PORT}"
        f"/test?size={size}"
    )

    try:

        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            timeout=timeout,
            max_field_size=limit
        ) as session:

            async with session.get(test_url) as response:

                csp = response.headers.get(
                    "Content-Security-Policy",
                    ""
                )

                return {
                    "success": True,
                    "status": response.status,
                    "received_bytes": len(
                        csp.encode("utf-8")
                    ),
                    "error": None,
                }

    except Exception as exc:

        return {
            "success": False,
            "status": None,
            "received_bytes": None,
            "error": (
                f"{type(exc).__name__}: {exc}"
            ),
        }


# ---------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------

class TestHandler(BaseHTTPRequestHandler):

    def send_html(self, body, status=200):
        encoded = body.encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(encoded))
        )

        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(encoded)

    def dashboard(self):

        content = """

        <div class="grid">

            <section class="card">
                <h2>Original Problem</h2>

                <div class="metric">
                    ~13,267 bytes
                </div>

                <p class="muted">
                    Approximate size of the large BHF
                    Content-Security-Policy response header.
                </p>

                <span class="badge warning">
                    BHF-like response
                </span>
            </section>


            <section class="card">
                <h2>aiohttp Old/Default Threshold</h2>

                <div class="metric">
                    ~8,190 bytes
                </div>

                <p class="muted">
                    A header larger than this can fail during
                    HTTP response-header parsing when the larger
                    field size is not configured.
                </p>

                <span class="badge fail">
                    13,267 &gt; 8,190
                </span>
            </section>


            <section class="card">
                <h2>Ticket Default</h2>

                <div class="metric">
                    65,536 bytes
                </div>

                <p class="muted">
                    Default value for
                    URL_VALIDATION_MAX_FIELD_SIZE.
                </p>

                <span class="badge pass">
                    13,267 &lt; 65,536
                </span>
            </section>

        </div>


        <section class="card">

            <h2>What is being reproduced?</h2>

            <div class="flow">SearchStax Manager
       │
       │ validates crawler URL
       ▼
aiohttp.ClientSession
       │
       │ HTTP GET / HEAD
       ▼
Demo /test endpoint
       │
       │ HTTP Response
       ▼
Content-Security-Policy: [large field]
       │
       ▼
aiohttp parses response headers
       │
       ├── within max_field_size → PASS
       │
       └── exceeds max_field_size → FAIL</div>

        </section>


        <section class="card">

            <h2>Realistic CSP Example</h2>

            <p>
                The test endpoint does not simply send an arbitrary
                <code>X-Test</code> header. It generates a
                realistic
                <code>Content-Security-Policy</code>
                field containing directives such as:
            </p>

            <pre><code>Content-Security-Policy:
default-src 'self';
script-src 'self' https://cdn.example.com;
style-src 'self' https://styles.example.com;
img-src 'self' data: https://images.example.com;
connect-src 'self'
            https://api.example.com
            https://api-1.example.com
            https://api-2.example.com
            ...;</code></pre>

            <div class="notice">
                <strong>connect-src 'self'</strong> means that
                browser connection APIs such as fetch, XHR and
                WebSocket can connect back to the same origin.
                The crawler ticket is concerned with the total
                size of this HTTP header field, not with the
                meaning of an individual CSP directive.
            </div>

        </section>


        <section class="card">

            <h2>Crawler Test URLs</h2>

            <p>
                These links return different CSP header sizes.
                Use the public Render version of these URLs as
                crawler start URLs.
            </p>

            <div class="buttons">

                <a class="button"
                   href="/test?size=5000">
                    5,000
                </a>

                <a class="button"
                   href="/test?size=8000">
                    8,000
                </a>

                <a class="button"
                   href="/test?size=8190">
                    8,190
                </a>

                <a class="button"
                   href="/test?size=8200">
                    8,200
                </a>

                <a class="button danger"
                   href="/test?size=10000">
                    10,000
                </a>

                <a class="button special"
                   href="/test?size=13267">
                    13,267 BHF-like
                </a>

                <a class="button"
                   href="/test?size=65535">
                    65,535
                </a>

                <a class="button danger"
                   href="/test?size=65536">
                    65,536
                </a>

                <a class="button danger"
                   href="/test?size=65537">
                    65,537
                </a>

                <a class="button danger"
                   href="/test?size=70000">
                    70,000
                </a>

            </div>

        </section>


        <section class="card">

            <h2>Run aiohttp Simulation</h2>

            <p>
                This executes a real
                <code>aiohttp.ClientSession</code>
                request from this application and configures
                <code>max_field_size</code>.
            </p>

            <form method="GET" action="/simulate">

                <div class="form-row">

                    <div>
                        <label>
                            Response Header Size
                        </label>

                        <input
                            type="number"
                            name="size"
                            value="13267"
                        >
                    </div>

                    <div>
                        <label>
                            aiohttp max_field_size
                        </label>

                        <input
                            type="number"
                            name="limit"
                            value="65536"
                        >
                    </div>

                    <button type="submit">
                        Run Simulation
                    </button>

                </div>

            </form>

            <div class="notice">
                Try
                <code>size=13267 / limit=65536</code>
                and then
                <code>size=13267 / limit=10000</code>.
            </div>

        </section>


        <section class="card">

            <h2>STUDIO-5693 Expected Results</h2>

            <table>

                <thead>
                    <tr>
                        <th>
                            Manager Limit
                        </th>

                        <th>
                            Response Header
                        </th>

                        <th>
                            Expected
                        </th>
                    </tr>
                </thead>

                <tbody>

                    <tr>
                        <td>
                            <code>65536</code>
                        </td>

                        <td>
                            13,267
                        </td>

                        <td>
                            <span class="badge pass">
                                Crawl starts
                            </span>
                        </td>
                    </tr>

                    <tr>
                        <td>
                            <code>10000</code>
                        </td>

                        <td>
                            13,267
                        </td>

                        <td>
                            <span class="badge fail">
                                FAILED
                            </span>
                        </td>
                    </tr>

                    <tr>
                        <td>
                            <code>65536</code>
                        </td>

                        <td>
                            65,537+
                        </td>

                        <td>
                            <span class="badge fail">
                                Validation fails gracefully
                            </span>
                        </td>
                    </tr>

                </tbody>

            </table>

        </section>


        <section class="card">

            <h2>Manager Configuration</h2>

            <pre><code>URL_VALIDATION_MAX_FIELD_SIZE=65536</code></pre>

            <p class="muted">
                After changing the environment value, restart
                the Manager before running the crawler again.
            </p>

        </section>

        """

        self.send_html(
            page(
                "SearchStax Header Limit Test",
                content
            )
        )

    def test_endpoint(self, params):

        try:
            size = int(
                params.get(
                    "size",
                    [DEFAULT_HEADER_SIZE]
                )[0]
            )
        except ValueError:
            size = DEFAULT_HEADER_SIZE

        size = max(
            500,
            min(size, 200000)
        )

        csp = build_realistic_csp(size)

        body = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Large CSP Test</title>
</head>

<body>

    <h1>Large HTTP Header Test</h1>

    <p>
        Generated CSP value size:
        <strong>{len(csp.encode("utf-8")):,} bytes</strong>
    </p>

    <p>
        This URL is intended to be used as a
        SearchStax crawler validation target.
    </p>

    <p>
        <a href="/">
            Return to dashboard
        </a>
    </p>

</body>
</html>
"""

        encoded = body.encode("utf-8")

        self.send_response(200)

        self.send_header(
            "Content-Security-Policy",
            csp
        )

        self.send_header(
            "X-Demo-CSP-Bytes",
            str(len(csp.encode("utf-8")))
        )

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(encoded))
        )

        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(encoded)

    def simulation(self, params):

        try:
            size = int(
                params.get(
                    "size",
                    [DEFAULT_HEADER_SIZE]
                )[0]
            )
        except ValueError:
            size = DEFAULT_HEADER_SIZE

        try:
            limit = int(
                params.get(
                    "limit",
                    [DEFAULT_MANAGER_LIMIT]
                )[0]
            )
        except ValueError:
            limit = DEFAULT_MANAGER_LIMIT

        size = max(
            500,
            min(size, 200000)
        )

        limit = max(
            500,
            min(limit, 200000)
        )

        expected_pass = size <= limit

        result = asyncio.run(
            aiohttp_validation_check(
                size,
                limit
            )
        )

        expected_label = (
            "PASS"
            if expected_pass
            else "FAIL"
        )

        expected_class = (
            "pass"
            if expected_pass
            else "fail"
        )

        actual_label = (
            "PASS"
            if result["success"]
            else "FAIL"
        )

        actual_class = (
            "pass"
            if result["success"]
            else "fail"
        )

        if result["success"]:
            actual_details = f"""
                HTTP status:
                <code>{result["status"]}</code>
                <br><br>

                CSP bytes received by aiohttp:
                <code>
                    {result["received_bytes"]:,}
                </code>
            """
        else:
            actual_details = f"""
                aiohttp raised:
                <br><br>

                <code>
                    {html.escape(result["error"])}
                </code>
            """

        content = f"""

        <section class="card">

            <h2>aiohttp Validation Simulation</h2>

            <div class="grid">

                <div>
                    <p class="muted">
                        Response CSP size
                    </p>

                    <div class="metric">
                        {size:,}
                    </div>

                    <p>bytes</p>
                </div>

                <div>
                    <p class="muted">
                        aiohttp max_field_size
                    </p>

                    <div class="metric">
                        {limit:,}
                    </div>

                    <p>bytes</p>
                </div>

            </div>

        </section>


        <div class="grid">

            <section class="card">

                <h2>Expected Result</h2>

                <span class="badge {expected_class}">
                    {expected_label}
                </span>

                <p>
                    Because
                    <code>{size:,}</code>
                    {"≤" if expected_pass else ">"}
                    <code>{limit:,}</code>.
                </p>

            </section>


            <section class="card">

                <h2>Actual aiohttp Result</h2>

                <span class="badge {actual_class}">
                    {actual_label}
                </span>

                <div class="result {actual_class}">
                    {actual_details}
                </div>

            </section>

        </div>


        <section class="card">

            <h2>Equivalent aiohttp Concept</h2>

            <pre><code>async with aiohttp.ClientSession(
    max_field_size={limit}
) as session:

    async with session.get(
        "/test?size={size}"
    ) as response:

        print(response.status)</code></pre>

        </section>


        <section class="card">

            <a class="button"
               href="/">
                Back to Dashboard
            </a>

            <a
                class="button special"
                href="/simulate?size=13267&limit=65536"
            >
                Test 13,267 vs 65,536
            </a>

            <a
                class="button danger"
                href="/simulate?size=13267&limit=10000"
            >
                Test 13,267 vs 10,000
            </a>

        </section>

        """

        self.send_html(
            page(
                "aiohttp Simulation",
                content
            )
        )

    def health(self):

        body = "OK"

        encoded = body.encode("utf-8")

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/plain"
        )

        self.send_header(
            "Content-Length",
            str(len(encoded))
        )

        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(encoded)

    def route(self):

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            self.dashboard()

        elif parsed.path == "/test":
            self.test_endpoint(params)

        elif parsed.path == "/simulate":
            self.simulation(params)

        elif parsed.path == "/health":
            self.health()

        else:
            self.send_html(
                page(
                    "Not Found",
                    """
                    <section class="card">
                        <h2>404</h2>
                        <p>Page not found.</p>
                        <a class="button" href="/">
                            Dashboard
                        </a>
                    </section>
                    """
                ),
                status=404
            )

    def do_GET(self):
        self.route()

    def do_HEAD(self):
        self.route()

    def log_message(self, format, *args):
        print(
            f"{self.client_address[0]} "
            f"- {format % args}"
        )


# ---------------------------------------------------------
# Start server
# ---------------------------------------------------------

if __name__ == "__main__":

    print()
    print(
        "SearchStax STUDIO-5693 "
        "Header Test Site"
    )

    print(
        f"Starting on "
        f"http://{HOST}:{PORT}"
    )

    print(
        f"Author: {AUTHOR_NAME}"
    )

    print()

    server = ThreadingHTTPServer(
        (HOST, PORT),
        TestHandler
    )

    server.serve_forever()
