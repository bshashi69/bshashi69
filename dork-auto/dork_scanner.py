#!/usr/bin/env python3
"""
dork_scanner.py — Automated OSINT / Google Dorking Tool for Kali Linux
Searches DuckDuckGo automatically (no API key needed).
Optionally uses Google Custom Search API when --google-key is supplied.

Usage:
    python3 dork_scanner.py -d braintrustcollectivesllp.com
    python3 dork_scanner.py -d example.com --cats login files --out report.html
    python3 dork_scanner.py -d example.com --google-key KEY --google-cx CX
"""

import argparse
import html as html_mod
import json
import os
import sys
import time
import datetime
from pathlib import Path

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    from duckduckgo_search import DDGS
    DDG_OK = True
except ImportError:
    DDG_OK = False

try:
    import requests
    REQ_OK = True
except ImportError:
    REQ_OK = False

try:
    from colorama import Fore, Back, Style, init as _cinit
    _cinit(autoreset=True)
    C = {
        'R': Style.RESET_ALL,
        'bold': Style.BRIGHT,
        'dim': Style.DIM,
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'cyan': Fore.CYAN,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'white': Fore.WHITE,
    }
    def col(key, text): return C.get(key, '') + text + C['R']
except ImportError:
    def col(_key, text): return text

# ── dork definitions ──────────────────────────────────────────────────────────
# {D}    = domain (as entered, e.g. www.example.com)
# {BARE} = domain without www
# {BRAND}= first label of bare domain
DORK_CATEGORIES = {
    "index": {
        "label": "Site Indexing & Discovery",
        "icon": "[*]",
        "queries": [
            ("All indexed pages",        "site:{D}"),
            ("No-www results",           "site:{BARE} -www"),
            ("Cache snapshot",           "cache:{D}"),
            ("Info record",              "info:{D}"),
            ("Related sites",            "related:{D}"),
            ("All subdomains",           "site:*.{BARE}"),
            ("Dev/staging subs",         "site:dev.{BARE} OR site:staging.{BARE} OR site:test.{BARE} OR site:beta.{BARE}"),
            ("API subdomain",            "site:api.{BARE}"),
        ]
    },
    "files": {
        "label": "Exposed Files & Documents",
        "icon": "[F]",
        "queries": [
            ("PDF files",                "site:{D} filetype:pdf"),
            ("Word documents",           "site:{D} filetype:doc OR filetype:docx"),
            ("Spreadsheets",             "site:{D} filetype:xls OR filetype:xlsx OR filetype:csv"),
            ("Text / config",            "site:{D} filetype:txt OR filetype:cfg OR filetype:conf OR filetype:env"),
            ("XML / JSON",               "site:{D} filetype:xml OR filetype:json"),
            ("SQL dumps",                "site:{D} filetype:sql"),
            ("Log files",                "site:{D} filetype:log"),
            ("Backup files",             "site:{D} filetype:bak OR filetype:backup OR filetype:old"),
        ]
    },
    "login": {
        "label": "Login Pages & Admin Panels",
        "icon": "[!]",
        "queries": [
            ("Login pages",              "site:{D} inurl:login OR inurl:signin OR inurl:auth"),
            ("Admin panels",             "site:{D} inurl:admin OR inurl:administrator OR inurl:wp-admin"),
            ("Dashboard / control",      "site:{D} inurl:dashboard OR inurl:control OR inurl:panel"),
            ("CMS backends",             "site:{D} inurl:wp-login OR inurl:joomla/administrator OR inurl:umbraco"),
            ("Password reset",           "site:{D} inurl:forgot OR inurl:reset-password"),
        ]
    },
    "errors": {
        "label": "Error Messages & Debug Info",
        "icon": "[E]",
        "queries": [
            ("PHP errors",               "site:{D} \"PHP Parse error\" OR \"PHP Warning\" OR \"PHP Fatal error\""),
            ("Database errors",          "site:{D} \"SQL syntax\" OR \"mysql_fetch\" OR \"ORA-\" OR \"ODBC error\""),
            ("Stack traces",             "site:{D} \"stack trace\" OR \"Traceback (most recent call last)\""),
            ("Directory listings",       "site:{D} intitle:\"Index of /\" OR intitle:\"Directory listing\""),
            ("Debug endpoints",          "site:{D} inurl:debug OR inurl:test.php OR inurl:phpinfo"),
        ]
    },
    "secrets": {
        "label": "Sensitive Paths & Config Leaks",
        "icon": "[S]",
        "queries": [
            (".git exposed",             "site:{D} inurl:\"/.git/\""),
            (".env file",                "site:{D} inurl:\".env\" OR inurl:\"/.env\""),
            ("wp-config",                "site:{D} inurl:\"wp-config.php\""),
            ("robots.txt",               "site:{D} inurl:robots.txt"),
            ("sitemap",                  "site:{D} inurl:sitemap.xml"),
            ("API keys in source",       "site:{D} intext:\"api_key\" OR intext:\"apikey\" OR intext:\"client_secret\""),
            ("AWS / S3 refs",            "site:{D} \"s3.amazonaws.com\" OR \"s3://\""),
        ]
    },
    "email": {
        "label": "Email Addresses & Contacts",
        "icon": "[@]",
        "queries": [
            ("@domain mentions",         "\"@{BARE}\" email"),
            ("Contact pages",            "site:{D} inurl:contact OR inurl:about"),
            ("Team / staff pages",       "site:{D} intitle:\"team\" OR intitle:\"staff\" OR intitle:\"about us\""),
        ]
    },
    "code": {
        "label": "Code Repositories",
        "icon": "[G]",
        "queries": [
            ("GitHub repos",             "site:github.com \"{BARE}\" OR \"{BRAND}\""),
            ("GitLab repos",             "site:gitlab.com \"{BARE}\" OR \"{BRAND}\""),
            ("Bitbucket repos",          "site:bitbucket.org \"{BARE}\" OR \"{BRAND}\""),
            ("GitHub Gists",             "site:gist.github.com \"{BARE}\""),
        ]
    },
    "leaks": {
        "label": "Paste Sites & Leaked Data",
        "icon": "[L]",
        "queries": [
            ("Pastebin",                 "site:pastebin.com \"{BARE}\" OR \"{BRAND}\""),
            ("Paste.ee",                 "site:paste.ee \"{BARE}\""),
            ("Hastebin",                 "site:hastebin.com \"{BARE}\""),
            ("Ghostbin",                 "site:ghostbin.co \"{BARE}\""),
            ("JustPaste.it",             "site:justpaste.it \"{BARE}\""),
        ]
    },
    "social": {
        "label": "Social Media & Profiles",
        "icon": "[P]",
        "queries": [
            ("LinkedIn company",         "site:linkedin.com/company \"{BRAND}\""),
            ("LinkedIn people",          "site:linkedin.com/in \"{BRAND}\""),
            ("Twitter / X",              "site:twitter.com OR site:x.com \"{BRAND}\""),
            ("Crunchbase",               "site:crunchbase.com \"{BRAND}\""),
            ("AngelList",                "site:angel.co \"{BRAND}\""),
        ]
    },
    "intel": {
        "label": "Public Mentions & Business Intel",
        "icon": "[I]",
        "queries": [
            ("News mentions",            "\"{BRAND}\" site:news.google.com OR site:reuters.com OR site:economictimes.com"),
            ("Job postings",             "\"{BRAND}\" site:linkedin.com/jobs OR site:indeed.com OR site:naukri.com"),
            ("Company registry",         "\"{BRAND}\" site:mca.gov.in OR site:zaubacorp.com OR site:falconebiz.com"),
            ("Wayback Machine",          "site:web.archive.org \"{BARE}\""),
        ]
    },
    "tech": {
        "label": "Technology Fingerprinting",
        "icon": "[T]",
        "queries": [
            ("Cloudflare markers",       "site:{D} \"Cloudflare\" OR \"cf-ray\""),
            ("WordPress",                "site:{D} inurl:wp-content OR inurl:wp-includes"),
            ("React / Next.js",          "site:{D} intext:\"__NEXT_DATA__\" OR intext:\"_next/static\""),
            ("Google Analytics",         "site:{D} intext:\"UA-\" OR intext:\"G-\" OR intext:\"gtag\""),
        ]
    },
    "security": {
        "label": "Security Config & Disclosures",
        "icon": "[#]",
        "queries": [
            ("security.txt",             "site:{D} inurl:security.txt OR inurl:\"/.well-known/security.txt\""),
            ("Bug bounty refs",          "\"{BARE}\" \"bug bounty\" OR \"vulnerability disclosure\""),
            ("CVE mentions",             "\"{BARE}\" \"CVE-\" site:cve.mitre.org OR site:nvd.nist.gov"),
            ("Shodan listing",           "site:shodan.io \"{BARE}\""),
        ]
    },
}

ALL_CATS = list(DORK_CATEGORIES.keys())

# ── helpers ───────────────────────────────────────────────────────────────────
def parse_domain(raw: str) -> str:
    return raw.strip().lstrip("htps:/").replace("//", "").split("/")[0].lower()

def bare(d: str) -> str:
    return d[4:] if d.startswith("www.") else d

def brand(d: str) -> str:
    return bare(d).split(".")[0]

def apply(tpl: str, d: str) -> str:
    return (tpl
            .replace("{D}", d)
            .replace("{BARE}", bare(d))
            .replace("{BRAND}", brand(d)))

def ddg_url(q: str) -> str:
    from urllib.parse import quote_plus
    return f"https://duckduckgo.com/?q={quote_plus(q)}"

def google_url(q: str) -> str:
    from urllib.parse import quote_plus
    return f"https://www.google.com/search?q={quote_plus(q)}"

# ── search back-ends ──────────────────────────────────────────────────────────
def search_ddg(query: str, max_results: int = 8) -> list[dict]:
    """Return list of {title, url, body} via DuckDuckGo."""
    if not DDG_OK:
        return []
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        return [{"title": r.get("title",""), "url": r.get("href",""), "body": r.get("body","")} for r in results]
    except Exception as exc:
        return [{"error": str(exc)}]

def search_google_cse(query: str, api_key: str, cx: str, max_results: int = 5) -> list[dict]:
    """Return list of {title, url, body} via Google Custom Search API."""
    if not REQ_OK:
        return []
    try:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {"key": api_key, "cx": cx, "q": query, "num": min(max_results, 10)}
        resp = requests.get(url, params=params, timeout=15)
        data = resp.json()
        items = data.get("items", [])
        return [{"title": i.get("title",""), "url": i.get("link",""), "body": i.get("snippet","")} for i in items]
    except Exception as exc:
        return [{"error": str(exc)}]

# ── runner ────────────────────────────────────────────────────────────────────
def run_scan(domain: str, cats: list[str], delay: float,
             max_results: int, google_key: str | None, google_cx: str | None,
             verbose: bool) -> dict:

    d = parse_domain(domain)
    report = {
        "target": d,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "categories": {}
    }

    total_q = sum(len(DORK_CATEGORIES[c]["queries"]) for c in cats)
    done = 0

    print(col("cyan", f"\n  Target  : ") + col("bold", d))
    print(col("cyan", f"  Queries : ") + col("bold", str(total_q)))
    print(col("cyan", f"  Engine  : ") + col("bold", "Google CSE" if google_key else "DuckDuckGo"))
    print(col("cyan", f"  Delay   : ") + col("bold", f"{delay}s between queries"))
    print()

    for cat_key in cats:
        cat = DORK_CATEGORIES[cat_key]
        icon  = cat["icon"]
        label = cat["label"]
        print(col("yellow", f"  {icon} {label}"))
        cat_results = []

        for qlabel, qtpl in cat["queries"]:
            query = apply(qtpl, d)
            done += 1
            pct = int(done / total_q * 100)
            bar = ("█" * (pct // 5)).ljust(20)
            sys.stdout.write(f"\r    [{bar}] {pct:3d}%  {qlabel:<35}")
            sys.stdout.flush()

            if google_key and google_cx:
                hits = search_google_cse(query, google_key, google_cx, max_results)
            else:
                hits = search_ddg(query, max_results)

            entry = {
                "label": qlabel,
                "query": query,
                "ddg_url": ddg_url(query),
                "google_url": google_url(query),
                "hits": hits,
            }
            cat_results.append(entry)

            if verbose and hits and "url" in hits[0]:
                print()
                for h in hits[:3]:
                    if "url" in h:
                        print(col("green", f"      + {h['url']}"))
            elif verbose and hits and "error" in hits[0]:
                print()
                print(col("red", f"      ! {hits[0]['error']}"))

            time.sleep(delay)

        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()
        hit_count = sum(len(e["hits"]) for e in cat_results if "error" not in (e["hits"][0] if e["hits"] else {}))
        print(col("green", f"    ✓ {len(cat_results)} queries — {hit_count} results"))
        report["categories"][cat_key] = {"label": label, "entries": cat_results}

    print()
    return report

# ── HTML report ───────────────────────────────────────────────────────────────
HTML_STYLE = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;font-size:13px;line-height:1.6}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;font-weight:700;margin-bottom:4px}
.meta{color:#8b949e;font-size:12px;margin-bottom:28px}
.cat{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px;overflow:hidden}
.cat-h{padding:12px 16px;background:#21262d;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-weight:600;font-size:13px}
.cat-h:hover{background:#2d333b}
.badge{background:rgba(88,166,255,.15);color:#58a6ff;border-radius:20px;padding:1px 10px;font-size:11px;font-weight:600}
.entry{border-bottom:1px solid #21262d;padding:10px 16px}
.entry:last-child{border-bottom:none}
.qlabel{color:#8b949e;font-size:11px;font-weight:500;margin-bottom:4px}
.query{font-family:'Consolas','JetBrains Mono',monospace;font-size:11.5px;color:#e6edf3;margin-bottom:6px;word-break:break-all}
.query .op{color:#58a6ff}.query .val{color:#3fb950}.query .kw{color:#d29922}
.hits{margin-top:6px}
.hit{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:8px 10px;margin-bottom:4px}
.hit-url{color:#58a6ff;font-size:11.5px;word-break:break-all}
.hit-title{font-weight:600;font-size:12px;margin-bottom:2px}
.hit-body{color:#8b949e;font-size:11px;margin-top:2px}
.no-hits{color:#484f58;font-size:11px;font-style:italic}
.links{display:flex;gap:8px;margin-top:4px}
.lnk{font-size:11px;background:#21262d;border:1px solid #30363d;border-radius:4px;padding:3px 8px;color:#8b949e}
.lnk:hover{color:#e6edf3;border-color:#58a6ff}
.err{color:#f85149;font-size:11px}
details>summary{list-style:none}details>summary::-webkit-details-marker{display:none}
</style>
<script>
function tog(id){var el=document.getElementById(id);if(el)el.open=!el.open}
</script>
"""

def highlight_query(q: str) -> str:
    import re
    q = html_mod.escape(q)
    q = re.sub(r'\b(site|filetype|inurl|intitle|intext|cache|info|related|link):', r'<span class="op">\1:</span>', q)
    q = re.sub(r'"([^"]+)"', r'"<span class="val">\1</span>"', q)
    q = re.sub(r'\b(OR|AND|NOT)\b', r'<span class="kw">\1</span>', q)
    return q

def build_html(report: dict) -> str:
    target = report["target"]
    ts     = report["timestamp"]
    total_hits = sum(
        sum(len(e["hits"]) for e in cat["entries"])
        for cat in report["categories"].values()
    )
    total_q = sum(len(cat["entries"]) for cat in report["categories"].values())

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>",
        f"<title>OSINT Report — {html_mod.escape(target)}</title>",
        HTML_STYLE,
        "</head><body><div class='wrap'>",
        f"<h1>🔍 OSINT Dork Report</h1>",
        f"<div class='meta'>Target: <strong>{html_mod.escape(target)}</strong> &nbsp;·&nbsp; "
        f"Scanned: {html_mod.escape(ts)} &nbsp;·&nbsp; {total_q} queries &nbsp;·&nbsp; {total_hits} hits</div>",
    ]

    for ci, (cat_key, cat) in enumerate(report["categories"].items()):
        entries = cat["entries"]
        hit_count = sum(
            len([h for h in e["hits"] if "url" in h])
            for e in entries
        )
        uid = f"cat_{ci}"
        parts.append(
            f"<div class='cat'>"
            f"<div class='cat-h' onclick=\"document.getElementById('{uid}').toggleAttribute('open')\">"
            f"<span>{html_mod.escape(cat['label'])}</span>"
            f"<span><span class='badge'>{hit_count} hits / {len(entries)} queries</span></span></div>"
            f"<details id='{uid}'><summary></summary>"
        )
        for entry in entries:
            q_hi = highlight_query(entry["query"])
            parts.append(
                f"<div class='entry'>"
                f"<div class='qlabel'>{html_mod.escape(entry['label'])}</div>"
                f"<div class='query'>{q_hi}</div>"
                f"<div class='links'>"
                f"<a class='lnk' href='{html_mod.escape(entry['ddg_url'])}' target='_blank' rel='noopener noreferrer'>DuckDuckGo ↗</a>"
                f"<a class='lnk' href='{html_mod.escape(entry['google_url'])}' target='_blank' rel='noopener noreferrer'>Google ↗</a>"
                f"</div>"
            )
            hits = entry.get("hits", [])
            real_hits = [h for h in hits if "url" in h]
            errors    = [h for h in hits if "error" in h]
            if real_hits:
                parts.append("<div class='hits'>")
                for h in real_hits:
                    title = html_mod.escape(h.get("title","(no title)"))
                    url   = html_mod.escape(h.get("url",""))
                    body  = html_mod.escape(h.get("body",""))
                    parts.append(
                        f"<div class='hit'>"
                        f"<div class='hit-title'>{title}</div>"
                        f"<a class='hit-url' href='{url}' target='_blank' rel='noopener noreferrer'>{url}</a>"
                        f"<div class='hit-body'>{body[:200]}</div>"
                        f"</div>"
                    )
                parts.append("</div>")
            elif errors:
                parts.append(f"<div class='err'>Error: {html_mod.escape(errors[0]['error'])}</div>")
            else:
                parts.append("<div class='no-hits'>No results found.</div>")
            parts.append("</div>")  # /entry
        parts.append("</details></div>")  # /cat

    parts.append("</div></body></html>")
    return "\n".join(parts)

# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Automated OSINT / Google Dorking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dork_scanner.py -d braintrustcollectivesllp.com
  python3 dork_scanner.py -d example.com --cats login files secrets
  python3 dork_scanner.py -d example.com --delay 2 --max 10 --verbose
  python3 dork_scanner.py -d example.com --google-key AIza... --google-cx 123:abc
  python3 dork_scanner.py -d example.com --out /tmp/report.html --json results.json

Available categories:
  """ + "  ".join(ALL_CATS)
    )
    p.add_argument("-d", "--domain",     required=True, help="Target domain (e.g. example.com)")
    p.add_argument("--cats",             nargs="+", choices=ALL_CATS, default=ALL_CATS,
                                         metavar="CAT",
                                         help="Categories to scan (default: all)")
    p.add_argument("--delay",            type=float, default=1.5,
                                         help="Seconds between queries (default: 1.5)")
    p.add_argument("--max",              dest="max_results", type=int, default=8,
                                         help="Max results per query (default: 8)")
    p.add_argument("--verbose", "-v",    action="store_true",
                                         help="Print hit URLs to terminal in real time")
    p.add_argument("--out",              default="",
                                         help="HTML report output path (default: <domain>_dork_<ts>.html)")
    p.add_argument("--json",             dest="json_out", default="",
                                         help="JSON results output path (optional)")
    p.add_argument("--google-key",       default="",
                                         help="Google Custom Search API key (optional)")
    p.add_argument("--google-cx",        default="",
                                         help="Google Custom Search engine ID (optional)")
    p.add_argument("--no-browser",       action="store_true",
                                         help="Do not auto-open the HTML report after scan")
    return p.parse_args()

def banner():
    print(col("cyan", """
  ╔══════════════════════════════════════════════════╗
  ║   OSINT Dork Scanner  ·  Passive Recon Tool      ║
  ║   Engine: DuckDuckGo (or Google CSE w/ key)      ║
  ╚══════════════════════════════════════════════════╝"""))

def check_deps():
    ok = True
    if not DDG_OK:
        print(col("red", "  [!] duckduckgo-search not installed — run: pip3 install duckduckgo-search"))
        ok = False
    if not REQ_OK:
        print(col("yellow", "  [~] requests not installed (needed for Google CSE) — run: pip3 install requests"))
    return ok

def main():
    args = parse_args()
    banner()

    if not check_deps():
        sys.exit(1)

    google_key = args.google_key or None
    google_cx  = args.google_cx  or None
    if google_key and not google_cx:
        print(col("red", "  [!] --google-cx is required when --google-key is set"))
        sys.exit(1)

    # run
    report = run_scan(
        domain      = args.domain,
        cats        = args.cats,
        delay       = args.delay,
        max_results = args.max_results,
        google_key  = google_key,
        google_cx   = google_cx,
        verbose     = args.verbose,
    )

    # save HTML
    ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    d_safe = parse_domain(args.domain).replace(".", "_")
    out_path = args.out or f"{d_safe}_dork_{ts_str}.html"
    Path(out_path).write_text(build_html(report), encoding="utf-8")
    print(col("green", f"  [+] HTML report saved : {out_path}"))

    # save JSON
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(col("green", f"  [+] JSON saved        : {args.json_out}"))

    # summary
    total_hits = sum(
        sum(1 for h in e["hits"] if "url" in h)
        for cat in report["categories"].values()
        for e in cat["entries"]
    )
    print(col("cyan", f"\n  Total hits found : ") + col("bold", str(total_hits)))
    print(col("cyan", f"  Report           : ") + col("bold", str(Path(out_path).resolve())))

    # open browser
    if not args.no_browser:
        try:
            import webbrowser
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        except Exception:
            pass

if __name__ == "__main__":
    main()
