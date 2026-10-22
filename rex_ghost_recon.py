#!/usr/bin/env python3
"""Rex's Ghost Recon — public-record desk. Authorized hosts only. No exploits."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

UA = "RexGhostRecon/1.0 (authorized public lookup)"
def install_root() -> Path:
    here = Path(__file__).resolve().parent
    candidates = [
        here,
        Path("/usr/share/rex-ghost-recon"),
        Path("/usr/local/share/rex-ghost-recon"),
        Path.home() / ".local" / "share" / "rex-ghost-recon",
        Path(os.environ.get("LOCALAPPDATA", "")) / "RexGhostRecon" if os.environ.get("LOCALAPPDATA") else here,
    ]
    for candidate in candidates:
        if (candidate / "assets" / "crew.jpg").is_file():
            return candidate
    return here


ROOT = install_root()
CTX = ssl._create_unverified_context()
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)
PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (587, "Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "Postgres"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
]


def parse_target(raw: str) -> str:
    value = raw.strip()
    if not value or len(value) > 300 or any(ch.isspace() for ch in value) or "@" in value:
        raise ValueError("Enter a domain or IP.")
    if "://" in value or "/" in value:
        if "://" not in value:
            value = "https://" + value
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in ("http", "https") or parsed.username:
            raise ValueError("Only an http(s) URL, domain, or IP.")
        value = parsed.hostname or ""
    elif value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    elif re.match(r"^[^:]+:\d+$", value):
        value = value.rsplit(":", 1)[0]
    value = value.strip(".").lower()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        parts = value.split(".")
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            raise ValueError("Write the IPv4 address without leading zeros.")
        if any(int(part) > 255 for part in parts):
            raise ValueError("That IPv4 address is not valid.")
        return ".".join(str(int(part)) for part in parts)
    if ":" in value:
        if not re.fullmatch(r"[0-9a-f:]+", value, re.I):
            raise ValueError("That IPv6 address is not valid.")
        return value
    if not HOST_RE.fullmatch(value):
        raise ValueError("Enter a plain domain or IP.")
    return value


def fetch(url: str, limit: int = 400_000, timeout: int = 12) -> tuple[int, dict[str, str], str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=timeout, context=CTX) as response:
        body = response.read(limit).decode("utf-8", "replace")
        headers = {key.lower(): value for key, value in response.headers.items() if key.lower() != "set-cookie"}
        return response.status, headers, body, response.geturl()


def doh(name: str, kind: str) -> list[str]:
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": kind})
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    return [str(row.get("data", "")).strip('"') for row in payload.get("Answer", []) if row.get("data")]


def row(label: str, value: str) -> dict[str, str]:
    return {"label": label, "value": value}


def pack(title: str, ok: bool, summary: str, rows: list[dict[str, str]]) -> dict:
    return {"title": title, "ok": ok, "summary": summary, "rows": rows[:30]}


def mod_dns(host: str) -> dict:
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) or ":" in host:
        try:
            names = socket.gethostbyaddr(host)[0]
            found = [names] if names else []
        except OSError:
            found = []
        return pack("DNS", bool(found), "Reverse name." if found else "No reverse name.", [row("PTR", n) for n in found])
    rows: list[dict[str, str]] = []
    for kind in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            values = doh(host, kind)
        except Exception:
            values = []
        rows.extend(row(kind, value[:180]) for value in values[:6])
    return pack("DNS", bool(rows), f"{len(rows)} public records." if rows else "No public DNS records.", rows)


def mod_registration(host: str) -> dict:
    kind = "ip" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) or ":" in host else "domain"
    url = f"https://rdap.org/{kind}/{urllib.parse.quote(host)}"
    status, _headers, body, _final = fetch(url, timeout=12)
    if status >= 400:
        return pack("Registration", False, "No public registration record.", [])
    data = json.loads(body)
    rows: list[dict[str, str]] = []
    if data.get("ldhName") or data.get("name"):
        rows.append(row("Name", str(data.get("ldhName") or data.get("name"))))
    if isinstance(data.get("status"), list):
        rows.append(row("Status", ", ".join(str(item) for item in data["status"])))
    servers = [item.get("ldhName", "") for item in data.get("nameservers", []) if isinstance(item, dict)]
    if servers:
        rows.append(row("Name servers", ", ".join(servers)))
    for event in data.get("events", []):
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", ""))
        if re.search(r"registration|expiration|last changed", action, re.I):
            rows.append(row(action, str(event.get("eventDate", ""))[:10]))
    if data.get("startAddress"):
        rows.append(row("Range", f"{data.get('startAddress')} – {data.get('endAddress', '')}".strip(" –")))
    return pack("Registration", bool(rows), "Public registration record." if rows else "Empty registry answer.", rows)


def page(host: str) -> tuple[int, dict[str, str], str, str]:
    try:
        return fetch(f"https://{host}/", timeout=10)
    except Exception:
        return fetch(f"http://{host}/", timeout=10)


def mod_headers(host: str) -> dict:
    status, headers, _body, final = page(host)
    interesting = (
        "server",
        "content-type",
        "x-powered-by",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "cf-ray",
    )
    rows = [row("Status", str(status)), row("Final", final)]
    rows.extend(row(key, headers[key][:240]) for key in interesting if headers.get(key))
    return pack("Headers", True, f"HTTP {status}. Cookie values are not shown.", rows)


def mod_framing(host: str) -> dict:
    _status, headers, _body, _final = page(host)
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    ancestors = ""
    match = re.search(r"frame-ancestors[^;]*", csp, re.I)
    if match:
        ancestors = match.group(0)
    guarded = bool(re.search(r"deny|sameorigin", xfo, re.I) or re.search(r"frame-ancestors", csp, re.I))
    summary = (
        "Homepage tells browsers not to frame it freely."
        if guarded
        else "Homepage does not publish a frame restriction."
    )
    return pack("Frame policy", True, summary, [row("X-Frame-Options", xfo or "Not set"), row("frame-ancestors", ancestors or "Not set")])


def mod_robots(host: str) -> dict:
    try:
        status, _headers, body, _final = fetch(f"https://{host}/robots.txt", timeout=8)
    except Exception:
        status, _headers, body, _final = fetch(f"http://{host}/robots.txt", timeout=8)
    lines = [line.strip() for line in body.splitlines() if line.strip() and not line.strip().startswith("#")]
    disallows = sum(1 for line in lines if line.lower().startswith("disallow:"))
    return pack(
        "robots.txt",
        200 <= status < 300,
        f"{disallows} Disallow lines." if 200 <= status < 300 else f"HTTP {status}.",
        [row(str(index + 1), line[:160]) for index, line in enumerate(lines[:24])],
    )


def mod_links(host: str) -> dict:
    _status, _headers, body, final = page(host)
    found: list[str] = []
    for match in re.finditer(r"""\s(?:href|src)\s*=\s*(?:"([^"]+)"|'([^']+)')""", body, re.I):
        raw = match.group(1) or match.group(2) or ""
        if not raw or raw.startswith("#") or re.match(r"^(javascript|mailto|data|tel):", raw, re.I):
            continue
        try:
            url = urllib.parse.urljoin(final, raw)
        except ValueError:
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme in ("http", "https") and url not in found:
            found.append(url)
    return pack("Links", True, f"{len(found)} http(s) links on the homepage.", [row("Link", href) for href in found[:30]])


def mod_location(host: str) -> dict:
    try:
        ip = host if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) else socket.getaddrinfo(host, None)[0][4][0]
    except OSError as exc:
        raise ValueError("No address for that host.") from exc
    status, _headers, body, _final = fetch(f"https://ipwho.is/{urllib.parse.quote(ip)}", timeout=8)
    data = json.loads(body) if status < 400 else {}
    if not data.get("success"):
        return pack("Network home", False, "No public network record.", [])
    place = ", ".join(part for part in (data.get("city"), data.get("region"), data.get("country")) if part)
    conn = data.get("connection") or {}
    rows = [
        row("Address", str(data.get("ip") or ip)),
        row("Place", place or "Unknown"),
        row("Network", str(conn.get("org") or conn.get("isp") or "Unknown")),
        row("ASN", f"AS{conn['asn']}" if conn.get("asn") else "Unknown"),
    ]
    return pack("Network home", True, "Public network home. Not a street address.", rows)


def mod_stack(host: str) -> dict:
    _status, headers, body, _final = page(host)
    rules = [
        ("WordPress", r"wp-content|wp-includes"),
        ("Drupal", r"drupal-settings|sites/default/files"),
        ("Joomla", r"/media/system/js|com_content"),
        ("Shopify", r"cdn\.shopify\.com"),
        ("Squarespace", r"squarespace"),
        ("Wix", r"wixstatic|wix\.com"),
        ("Ghost", r"ghost-portal"),
        ("Next.js", r"__NEXT_DATA__|_next/static"),
        ("Webflow", r"webflow"),
    ]
    hits = [name for name, pattern in rules if re.search(pattern, body, re.I)]
    if headers.get("cf-ray") or re.search(r"cloudflare", headers.get("server", ""), re.I):
        hits.append("Cloudflare")
    rows = [row("Signature", name) for name in hits]
    if headers.get("server"):
        rows.append(row("Server", headers["server"]))
    if headers.get("x-powered-by"):
        rows.append(row("X-Powered-By", headers["x-powered-by"]))
    return pack("Stack hint", True, ", ".join(hits) if hits else "No familiar homepage signature.", rows)


def mod_certificate(host: str) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=None if ":" in host or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) else host) as tls:
            cert = tls.getpeercert()
    if not cert:
        return pack("Certificate", False, "No certificate was presented.", [])
    subject = dict(item[0] for item in cert.get("subject", ()))
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    names = ", ".join(str(value) for _kind, value in cert.get("subjectAltName", ())[:8])
    rows = [
        row("Subject", str(subject.get("commonName", host))),
        row("Issuer", str(issuer.get("organizationName") or issuer.get("commonName") or "Unknown")),
        row("Valid from", str(cert.get("notBefore", ""))),
        row("Valid to", str(cert.get("notAfter", ""))),
    ]
    if names:
        rows.append(row("Names", names))
    return pack("Certificate", True, "Certificate presented for this name.", rows)


def mod_transparency(host: str) -> dict:
    if ":" in host or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return pack("Cert log", False, "Certificate logs are queried by domain.", [])
    status, _headers, body, _final = fetch(f"https://crt.sh/?q={urllib.parse.quote(host)}&output=json", timeout=12)
    if status >= 400:
        return pack("Cert log", False, "The public certificate log did not answer.", [])
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return pack("Cert log", False, "The certificate log did not return a list.", [])
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for item in data:
        name = str(item.get("name_value", "")).split("\n")[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        rows.append(row(str(item.get("not_after", ""))[:10] or "Logged", name[:160]))
        if len(rows) >= 18:
            break
    return pack("Cert log", bool(rows), f"{len(seen)} names in the sample." if rows else "No logged names.", rows)


def mod_ports(host: str) -> dict:
    rows = []
    open_ports = []
    for port, name in PORTS:
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.9)
        try:
            sock.connect((host, port))
            state = "open"
            open_ports.append(str(port))
        except OSError:
            state = "closed"
        finally:
            sock.close()
        rows.append(row(f"{port} {name}", state))
    summary = (
        "Open on this list: " + ", ".join(open_ports) + ". Open or closed only. This does not log in."
        if open_ports
        else "None of the common ports answered."
    )
    return pack("Ports", True, summary, rows)


def mod_trace(host: str) -> dict:
    exe = shutil.which("traceroute") or shutil.which("tracert")
    if not exe:
        return pack("Traceroute", False, "traceroute is not installed on this machine.", [])
    if Path(exe).name.lower().startswith("tracert"):
        command = [exe, "-h", "12", "-w", "1000", host]
    else:
        command = [exe, "-m", "12", "-w", "1", host]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except subprocess.TimeoutExpired:
        return pack("Traceroute", False, "Traceroute timed out.", [])
    text = (completed.stdout or completed.stderr).strip()
    lines = [line for line in text.splitlines() if line.strip()][:16]
    return pack("Traceroute", completed.returncode == 0, "System traceroute.", [row(str(i + 1), line[:160]) for i, line in enumerate(lines)])


def mod_nmap(host: str) -> dict:
    exe = shutil.which("nmap")
    if not exe:
        return pack("Nmap", False, "nmap is not installed. The common-port check still runs without it.", [])
    command = [exe, "-Pn", "-T3", "--top-ports", "50", "--open", "-oG", "-", host]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    except subprocess.TimeoutExpired:
        return pack("Nmap", False, "nmap timed out.", [])
    rows = []
    for line in completed.stdout.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            rows.append(row("Open", line.split("Ports:", 1)[1].strip()[:240]))
    if not rows and completed.returncode == 0:
        rows.append(row("Open", "none in the top 50"))
    return pack(
        "Nmap",
        completed.returncode == 0,
        "Top 50 ports, no scripts, no login attempts.",
        rows or [row("Output", (completed.stderr or "nmap failed")[:200])],
    )


CHECKS = {
    "1": ("DNS", mod_dns),
    "2": ("Registration", mod_registration),
    "3": ("Headers", mod_headers),
    "4": ("Frame policy", mod_framing),
    "5": ("robots.txt", mod_robots),
    "6": ("Links", mod_links),
    "7": ("Network home", mod_location),
    "8": ("Stack hint", mod_stack),
    "9": ("Certificate", mod_certificate),
    "10": ("Cert log", mod_transparency),
    "11": ("Ports", mod_ports),
    "12": ("Traceroute", mod_trace),
    "13": ("Nmap top 50", mod_nmap),
}


def run_ids(host: str, ids: list[str]) -> list[dict]:
    reports = []
    for item in ids:
        title, func = CHECKS[item]
        try:
            reports.append(func(host))
        except Exception as exc:
            reports.append(pack(title, False, str(exc), []))
    return reports


def print_report(host: str, reports: list[dict]) -> None:
    print(f"\n== {host} ==")
    for report in reports:
        mark = "RECORD" if report["ok"] else "MISS"
        print(f"\n[{mark}] {report['title']}")
        print(report["summary"])
        for item in report["rows"]:
            print(f"  {item['label']}: {item['value']}")


def menu() -> None:
    print("Rex's Ghost Recon")
    print("Authorized hosts only. Public records and open/closed checks. No exploits.")
    while True:
        print("\n1 DNS   2 Registration   3 Headers   4 Frame policy")
        print("5 robots.txt   6 Links   7 Network home   8 Stack hint")
        print("9 Certificate   10 Cert log   11 Ports   12 Traceroute")
        print("13 Nmap top 50, only if nmap is already installed")
        print("a all public records    q quit")
        choice = input("Choice: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return
        if choice == "a":
            ids = [str(number) for number in range(1, 11)]
        else:
            ids = [part for part in re.split(r"[\s,]+", choice) if part]
            if not ids or any(part not in CHECKS for part in ids):
                print("Pick numbers from the menu.")
                continue
        try:
            host = parse_target(input("Target: ").strip())
        except ValueError as exc:
            print(exc)
            continue
        confirm = input("Confirm you are allowed to look up this host [y/N]: ").strip().lower()
        if confirm not in {"y", "yes"}:
            print("Stopped.")
            continue
        print_report(host, run_ids(host, ids))


def once(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: rex_ghost_recon.py --once example.com 1,3,9", file=sys.stderr)
        return 2
    host = parse_target(argv[0])
    wanted = argv[1] if len(argv) > 1 else "a"
    ids = [str(number) for number in range(1, 11)] if wanted == "a" else [part for part in wanted.split(",") if part]
    if any(part not in CHECKS for part in ids):
        print("Unknown module.", file=sys.stderr)
        return 2
    print_report(host, run_ids(host, ids))
    return 0


PAGE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rex's Ghost Recon</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font-family: Barlow, sans-serif; background: #070a09; color: #e7f3ec; }
  header, main { max-width: 880px; margin: 0 auto; padding: 16px; }
  img { width: 100%; border: 1px solid #24312b; border-radius: 8px; display: block; }
  h1 { font-size: 1.6rem; margin: 12px 0 4px; }
  p { color: #8ea399; }
  form, article { border: 1px solid #24312b; background: #101614; border-radius: 8px; padding: 16px; margin-top: 12px; }
  input[type=text] { width: 100%; box-sizing: border-box; height: 44px; background: #070a09; color: #e7f3ec; border: 1px solid #24312b; border-radius: 4px; padding: 0 12px; }
  button { height: 44px; margin-top: 12px; background: #3ddc97; color: #070a09; border: 0; border-radius: 4px; padding: 0 16px; font-weight: 700; }
  .miss { color: #d3122f; }
  .ok { color: #3ddc97; }
  dd { margin: 0 0 8px; font-family: ui-monospace, monospace; overflow-wrap: anywhere; }
  dt { color: #8ea399; font-size: 12px; }
</style>
<header>
  <img src="/crew.jpg" alt="WolfSec crew">
  <h1>Rex's Ghost Recon</h1>
  <p>Local desk. Stays on this machine. Authorized hosts only.</p>
</header>
<main>
  <form id="desk">
    <input id="target" type="text" value="example.com" autocomplete="off" spellcheck="false">
    <label><input id="ok" type="checkbox"> I am allowed to look up this host.</label>
    <div><button type="submit">Run recon</button></div>
  </form>
  <div id="out"></div>
</main>
<script>
  const form = document.getElementById("desk");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!document.getElementById("ok").checked) { alert("Confirm you are allowed to look up this host."); return; }
    const out = document.getElementById("out");
    out.textContent = "Pulling records…";
    const response = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target: document.getElementById("target").value }) });
    const report = await response.json();
    out.innerHTML = "";
    if (report.error) { out.textContent = report.error; return; }
    for (const item of report.results) {
      const article = document.createElement("article");
      const title = document.createElement("h2");
      title.textContent = item.title + " ";
      const mark = document.createElement("span");
      mark.className = item.ok ? "ok" : "miss";
      mark.textContent = item.ok ? "RECORD" : "MISS";
      title.append(mark);
      const summary = document.createElement("p");
      summary.textContent = item.summary;
      article.append(title, summary);
      const list = document.createElement("dl");
      for (const line of item.rows) {
        const dt = document.createElement("dt");
        dt.textContent = line.label;
        const dd = document.createElement("dd");
        dd.textContent = line.value;
        list.append(dt, dd);
      }
      article.append(list);
      out.append(article);
    }
  });
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/crew.jpg"):
            image = ROOT / "assets" / "crew.jpg"
            if image.exists():
                self._send(200, image.read_bytes(), "image/jpeg")
            else:
                self._send(404, b"missing", "text/plain")
            return
        self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api/run":
            self._send(404, b"{}", "application/json")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 4000:
            self._send(400, b'{"error":"Too large."}', "application/json")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            host = parse_target(str(payload.get("target", "")))
        except Exception as exc:
            self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json")
            return
        results = run_ids(host, [str(number) for number in range(1, 11)])
        self._send(200, json.dumps({"target": host, "results": results}).encode("utf-8"), "application/json")


def serve() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8787), Handler)
    print("Rex's Ghost Recon local desk: http://127.0.0.1:8787")
    print("This listens on this machine only. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


def main() -> int:
    args = sys.argv[1:]
    if not args:
        menu()
        return 0
    if args[0] == "--web":
        serve()
        return 0
    if args[0] == "--once":
        return once(args[1:])
    print("Usage: rex_ghost_recon.py [--web | --once HOST 1,3,9]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
