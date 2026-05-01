import asyncio
import socket
import ssl
import re
import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8764847094:AAGurxxPQXRcjLRqmhwmdBfI0SjlkuXjMz0")
PORT = int(os.environ.get("PORT", 8080))

# ---------------------------------------------------------------------------
# HackerOne VRT'ye gore severity tanimlari
# ---------------------------------------------------------------------------
SEV = {
    "critical": {"label": "Critical · P1", "bounty": "$5000+",      "emoji": "🔴"},
    "high":     {"label": "High · P2",     "bounty": "$1000–5000",  "emoji": "🟠"},
    "medium":   {"label": "Medium · P3",   "bounty": "$200–1000",   "emoji": "🟡"},
    "low":      {"label": "Low · P4",      "bounty": "$50–200",     "emoji": "🔵"},
    "info":     {"label": "Info · P5",     "bounty": "$0–50",       "emoji": "⚪"},
    "none":     {"label": "Gecersiz / Kapsam Disi", "bounty": "$0", "emoji": "❌"},
}

INTERESTING_PATHS_IN_ROBOTS = [
    "/admin", "/administrator", "/api", "/internal", "/private",
    "/backup", "/staging", "/dev", "/test", "/dashboard", "/manage",
]

CRITICAL_PATHS = [
    {"path": "/.env",            "check": "env_content",  "sev": "critical"},
    {"path": "/.env.local",      "check": "env_content",  "sev": "critical"},
    {"path": "/.env.backup",     "check": "env_content",  "sev": "critical"},
    {"path": "/.env.production", "check": "env_content",  "sev": "critical"},
    {"path": "/.git/config",     "check": "git_content",  "sev": "high"},
    {"path": "/.git/HEAD",       "check": "git_content",  "sev": "high"},
    {"path": "/backup.sql",      "check": "sql_content",  "sev": "critical"},
    {"path": "/dump.sql",        "check": "sql_content",  "sev": "critical"},
    {"path": "/database.sql",    "check": "sql_content",  "sev": "critical"},
    {"path": "/phpinfo.php",     "check": "phpinfo",      "sev": "medium"},
    {"path": "/info.php",        "check": "phpinfo",      "sev": "medium"},
    {"path": "/server-status",   "check": "apache_status","sev": "low"},
    {"path": "/server-info",     "check": "apache_status","sev": "low"},
    {"path": "/adminer.php",     "check": "login_page",   "sev": "medium"},
    {"path": "/phpmyadmin/",     "check": "login_page",   "sev": "medium"},
    {"path": "/wp-login.php",    "check": "login_page",   "sev": "low"},
    {"path": "/swagger-ui.html", "check": "swagger",      "sev": "low"},
    {"path": "/openapi.json",    "check": "swagger",      "sev": "low"},
    {"path": "/api-docs",        "check": "swagger",      "sev": "low"},
    {"path": "/graphql",         "check": "graphql",      "sev": "low"},
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

BOUNTY_QA = [
    {
        "keywords": ["hsts", "strict-transport"],
        "answer": (
            "*HSTS Eksikligi — Gercek Durum:*\n\n"
            "Tek basina raporlandigi zaman cogu program P5 (Informational) olarak isaret eder, $0 oder. "
            "HTTPS kullanan bir sitede HSTS olmamasi teorik risk, dogrudan exploit edilemez. "
            "Bunu raporlamak istiyorsan baska baslik eksiklikleriyle birlikte 'hardening onerisi' olarak tek raporda sun."
        ),
    },
    {
        "keywords": ["csp", "content security policy"],
        "answer": (
            "*CSP Eksikligi — Gercek Durum:*\n\n"
            "CSP yok = otomatik XSS riski anlamina GELMEZ. CSP eksikligi = P5, $0-50.\n\n"
            "Eger sitede ayrica XSS bulduysan, CSP'nin yoklugu o bulgunu P2-P3'e yukseltiyor "
            "cunku mitigasyon katmani da yok. Once XSS bul, sonra CSP eksikligini agravating factor ekle."
        ),
    },
    {
        "keywords": ["cors", "cross origin", "access-control"],
        "answer": (
            "*CORS Misconfiguration — Gercek Durum:*\n\n"
            "Sadece `Access-Control-Allow-Origin: *` varsa genellikle intentional, reddedilir.\n\n"
            "Raporlanabilir senaryo:\n"
            "1. `Origin: https://evil.com` header'iyla istek at\n"
            "2. Response'da `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` varsa — HIGH\n"
            "3. Bu sayede authenticated endpoint'e baska originden istek atabiliyorsan PoC hazir"
        ),
    },
    {
        "keywords": ["open redirect", "yonlendirme", "redirect"],
        "answer": (
            "*Open Redirect — Gercek Durum:*\n\n"
            "Standalone P4, $50-200. Bazi programlar hic kabul etmez.\n\n"
            "Degerini artirmak icin OAuth flow'una bagla:\n"
            "1. 'Google ile Giris' gibi OAuth var mi?\n"
            "2. Varsa redirect_uri + open redirect ile token calmayi dene\n"
            "3. Bu kombinasyon Account Takeover'a yol acarsa P1-P2"
        ),
    },
    {
        "keywords": ["env", ".env", "ortam degisken"],
        "answer": (
            "*.env Dosyasi — Gercek Durum:*\n\n"
            "Eger `/.env` 200 OK ve icerik KEY=VALUE ise Critical (P1).\n\n"
            "Once dogrula:\n"
            "1. Icerige bak — bos veya template mi, gercek deger var mi?\n"
            "2. DB_PASSWORD, SECRET_KEY, AWS_SECRET gibi degerler var mi?\n"
            "3. ASLA bu credential'lari kullanma, sadece varligini dogrula\n"
            "PoC: curl komutu + response screenshot yeterli."
        ),
    },
    {
        "keywords": ["git", ".git", "kaynak kod"],
        "answer": (
            "*.git Dizini — Gercek Durum:*\n\n"
            "`.git/config` 200 donuyorsa High (P2).\n"
            "`pip install git-dumper && git-dumper https://hedef.com/.git ./output`\n\n"
            "Kaynak kodda hardcoded secret varsa Critical'e yukselir."
        ),
    },
    {
        "keywords": ["sql injection", "sqli", "sql"],
        "answer": (
            "*SQL Injection — Gercek Durum:*\n\n"
            "Gercek SQLi = P1-P2, $1000-30000+.\n\n"
            "Test:\n"
            "1. Input alanlarina `'` ekle — 500 hatasi veya DB hatasi var mi?\n"
            "2. Blind: `' AND SLEEP(5)--` — sayfa 5 sn gecikti mi?\n"
            "3. `sqlmap -u 'https://hedef.com/page?id=1' --risk=1 --level=1`\n\n"
            "Sadece izinli hedefte, --risk=1 ile kullan."
        ),
    },
    {
        "keywords": ["subdomain", "takeover", "alt alan"],
        "answer": (
            "*Subdomain Takeover — Gercek Durum:*\n\n"
            "P2-P3, $200-3000.\n\n"
            "1. `subfinder -d hedef.com -o subs.txt`\n"
            "2. CNAME'i olan ama 404 veren domainlere bak\n"
            "3. CNAME'in isgaret ettigi serviste (Heroku, Netlify, GitHub Pages) o ismi kayit edebiliyorsan takeover mumkun\n"
            "PoC: kendi sayfani oraya koy, screenshot al."
        ),
    },
    {
        "keywords": ["nasil rapor", "rapor yaz", "raporlama"],
        "answer": (
            "*Profesyonel Bug Bounty Raporu:*\n\n"
            "Baslik: `[Tip] — [Endpoint] — [Etki]`\n\n"
            "Icerik:\n"
            "• Vulnerability Type (HackerOne VRT)\n"
            "• Affected URL\n"
            "• Steps to Reproduce (numarali)\n"
            "• Impact (gercek etki)\n"
            "• PoC (ekran goruntusu SART)\n"
            "• Suggested Fix\n\n"
            "PoC olmadan triaj 'Needs more info' der."
        ),
    },
    {
        "keywords": ["ne kadar", "kac para", "odul", "bounty", "deger"],
        "answer": (
            "*HackerOne VRT Odul Bantlari:*\n\n"
            "P1 Critical: $5000-30000+ (RCE, SQLi+veri, Account Takeover)\n"
            "P2 High: $1000-5000 (Stored XSS, SSRF, CORS+creds, .git ifsa)\n"
            "P3 Medium: $200-1000 (Reflected XSS, Open Redirect+OAuth, CSRF)\n"
            "P4 Low: $50-200 (Clickjacking hassas sayfada, bilgi ifsa)\n"
            "P5 Info: $0-50 (Baslik eksiklikleri, versiyon ifsa)\n\n"
            "Her zaman once programin kendi odul tablosuna bak."
        ),
    },
    {
        "keywords": ["wordpress", "wp", "wpscan"],
        "answer": (
            "*WordPress Bug Bounty:*\n\n"
            "1. `wpscan --url https://hedef.com --enumerate p,t,u --api-token TOKENIN`\n"
            "2. `/wp-json/wp/v2/users` — kullanici adi goruntuleniyor mu?\n"
            "3. xmlrpc.php aktif mi? `curl -s https://hedef.com/xmlrpc.php`\n"
            "4. Eski plugin CVE'si bulduysan exploit edilebilir mi dogrula\n\n"
            "'WordPress kullaniyor' diye rapor acma, exploit edilebilir acik bul."
        ),
    },
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_domain(url: str) -> str:
    return urlparse(url).netloc


def is_env_content(text: str) -> bool:
    lines = text.strip().splitlines()
    env_lines = [l for l in lines if re.match(r'^[A-Z][A-Z0-9_]+=.+', l.strip())]
    return len(env_lines) >= 2


def is_git_content(text: str) -> bool:
    return "[core]" in text or "repositoryformatversion" in text or "ref: refs/" in text


def is_sql_content(text: str) -> bool:
    return any(m in text for m in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- phpMyAdmin"])


def check_content(text: str, check_type: str) -> bool:
    if check_type == "env_content":
        return is_env_content(text)
    elif check_type == "git_content":
        return is_git_content(text)
    elif check_type == "sql_content":
        return is_sql_content(text)
    elif check_type == "phpinfo":
        return "phpinfo()" in text or "PHP Version" in text
    elif check_type == "apache_status":
        return "Apache Server Status" in text or "Server Version" in text
    elif check_type in ("login_page", "swagger", "graphql"):
        return True
    return True


def fetch_url(url: str, timeout: int = 8):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
    except Exception:
        return None


def check_headers(url: str) -> dict:
    result = {"reachable": False, "status": 0, "missing_headers": [],
              "server": "", "powered_by": "", "tech": [],
              "cors": None, "cors_credentials": False}
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"})
        result["reachable"] = True
        result["status"] = resp.status_code
        h = resp.headers
        for header in SECURITY_HEADERS:
            if header not in h:
                result["missing_headers"].append(header)
        result["server"] = h.get("Server", "")
        result["powered_by"] = h.get("X-Powered-By", "")
        cors = h.get("Access-Control-Allow-Origin", "")
        if cors:
            result["cors"] = cors
            result["cors_credentials"] = h.get("Access-Control-Allow-Credentials", "").lower() == "true"
        body = resp.text
        if "wp-content/themes" in body or "wp-includes" in body:
            result["tech"].append("WordPress")
        if "Drupal.settings" in body or "/sites/default/files" in body:
            result["tech"].append("Drupal")
        if "csrfmiddlewaretoken" in body:
            result["tech"].append("Django")
        if "laravel_session" in h.get("Set-Cookie", ""):
            result["tech"].append("Laravel")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl(domain: str) -> dict:
    result = {"valid": True, "issue": "", "issuer": "", "expires": ""}
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "?")
        result["expires"] = cert.get("notAfter", "")
    except ssl.SSLCertVerificationError as e:
        result["valid"] = False
        result["issue"] = str(e)
    except ConnectionRefusedError:
        result["valid"] = None
        result["issue"] = "Port 443 kapali"
    except Exception as e:
        result["valid"] = None
        result["issue"] = str(e)
    return result


def check_cors_reflection(url: str) -> bool:
    try:
        resp = requests.get(url, timeout=8,
                            headers={"User-Agent": "Mozilla/5.0",
                                     "Origin": "https://evil-attacker.com"})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        return "evil-attacker.com" in acao and acac == "true"
    except Exception:
        return False


def check_sensitive_files(base_url: str) -> list:
    findings = []
    for item in CRITICAL_PATHS:
        resp = fetch_url(base_url + item["path"])
        if resp is None:
            continue
        if resp.status_code == 200:
            confirmed = check_content(resp.text, item["check"])
            findings.append({
                "path": item["path"], "status": 200,
                "sev": item["sev"] if confirmed else "info",
                "confirmed": confirmed, "size": len(resp.content),
            })
    return findings


def check_robots_txt(base_url: str) -> dict:
    result = {"exists": False, "interesting_paths": []}
    resp = fetch_url(base_url + "/robots.txt")
    if resp and resp.status_code == 200 and resp.text.strip():
        result["exists"] = True
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[-1].strip()
                if any(ip in path.lower() for ip in INTERESTING_PATHS_IN_ROBOTS):
                    result["interesting_paths"].append(path)
    return result


def check_open_redirect(base_url: str):
    for param in ["redirect", "url", "next", "return", "goto", "redir", "target"]:
        try:
            resp = requests.get(f"{base_url}/?{param}=https://evil-attacker.com",
                                timeout=5, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
            if "evil-attacker.com" in resp.headers.get("Location", ""):
                return param
        except Exception:
            pass
    return None


def build_report(url, header_data, ssl_data, files, robots, redirect_param, cors_reflected):
    domain = get_domain(url)
    findings = []

    if ssl_data["valid"] is False:
        findings.append(("medium", "Gecersiz SSL Sertifikasi",
                         f"Sertifika dogrulanamadi: {ssl_data['issue']}",
                         f"curl -v https://{domain}"))
    elif ssl_data["valid"] is None:
        findings.append(("low", "HTTPS Desteklenmiyor",
                         "Port 443 kapali, site HTTP ile calisiyor.",
                         f"curl -v http://{domain}"))

    if cors_reflected:
        findings.append(("high", "CORS Origin Reflection + Credentials",
                         "Sunucu keyfi origin'i yansitiyor, credentials: true donuyor. "
                         "Baska bir siteden authenticated API istegi mumkun.",
                         f"fetch('https://{domain}/api/...', {{credentials:'include'}}) evil-attacker.com'dan calistir"))
    elif header_data.get("cors") == "*" and header_data.get("cors_credentials"):
        findings.append(("high", "CORS Wildcard + Credentials",
                         "Access-Control-Allow-Origin: * ile credentials: true ayni anda aktif.",
                         "Tarayici normalde reddeder ama test et"))
    elif header_data.get("cors") == "*":
        findings.append(("info", "CORS Wildcard (Dusuk Risk)",
                         "Public API icin intentional olabilir. Credentials yoksa raporlanabilir degil.",
                         "Origin reflection test et"))

    if redirect_param:
        findings.append(("low", f"Open Redirect — ?{redirect_param}= parametresi",
                         "Parametre dogrulamasi yok, disariya yonlendirme mumkun. Standalone P4.",
                         f"PoC: {url}/?{redirect_param}=https://evil-attacker.com"))

    for f in files:
        if not f["confirmed"]:
            continue
        path, sev, size = f["path"], f["sev"], f["size"]
        if ".env" in path:
            findings.append((sev, f"Ortam Degiskeni Ifsa — {path}",
                             "KEY=VALUE formati dogrulandi. API anahtari/DB sifresi iceriyor olabilir.",
                             f"curl {url}{path} — icerige bak, programi hemen bildir"))
        elif ".git" in path:
            findings.append((sev, f"Git Deposu Ifsa — {path}",
                             "git-dumper ile kaynak kod indirilebilir.",
                             f"git-dumper {url}/.git ./output"))
        elif ".sql" in path or "dump" in path or "backup" in path:
            findings.append((sev, f"Veritabani Yedegi Ifsa — {path}",
                             f"SQL dump erisime acik ({size} byte), icerik dogrulandi.",
                             f"curl -o dump.sql {url}{path}"))
        elif "phpinfo" in path or "info.php" in path:
            findings.append((sev, "phpinfo() Sayfasi Acik",
                             "PHP versiyonu, modul listesi, sistem yollari gorunuyor.",
                             f"{url}{path}"))
        elif "phpmyadmin" in path or "adminer" in path:
            findings.append((sev, f"DB Yonetim Paneli Acik — {path}",
                             "Brute-force veya varsayilan sifre denenebilir.",
                             f"root/root, admin/admin dene: {url}{path}"))
        elif "swagger" in path or "openapi" in path or "api-docs" in path:
            findings.append(("low", "API Dokumantasyonu Acik",
                             "Tum endpoint listesi, parametre yapisi gorunuyor. Dogrudan P4.",
                             f"{url}{path}"))
        elif "graphql" in path:
            findings.append(("low", "GraphQL Introspection",
                             "Schema sorgulanabilir olabilir.",
                             f'POST {url}{path} body: {{"query":"{{__schema{{types{{name}}}}}}"}}'))
        elif "server-status" in path:
            findings.append(("low", "Apache Sunucu Durum Sayfasi",
                             "Aktif baglantilari ve islem listesini gosteriyor.",
                             f"{url}{path}"))
        elif "wp-login" in path:
            findings.append(("info", "WordPress Giris Sayfasi",
                             "Standart WP sayfasi, tek basina raporlanabilir degil.",
                             f"/wp-json/wp/v2/users endpoint'ini kontrol et"))

    if robots["interesting_paths"]:
        findings.append(("info", "robots.txt'de Ilginc Path'ler",
                         "robots.txt standart dosyadir, bulgu degil. Icindeki path'ler bilgi verir: "
                         + ", ".join(robots["interesting_paths"]),
                         "Bu path'leri manuel ziyaret et"))

    if header_data.get("missing_headers"):
        findings.append(("info",
                         f"Eksik Guvenlik Basliklari ({len(header_data['missing_headers'])} adet)",
                         "Tek basina raporlandigi zaman cogu program P5/$0 oder. "
                         "Zayif yapilandirma, guvenlik acigi degil. Eksikler: "
                         + ", ".join(header_data["missing_headers"]),
                         "Bunu tek rapor olarak gonderme"))

    if header_data.get("server") and any(c.isdigit() for c in header_data["server"]):
        findings.append(("info", f"Sunucu Versiyon Bilgisi: {header_data['server']}",
                         "CVE aramasini kolaylastirir. Tek basina raporlanabilir degil.",
                         f"searchsploit '{header_data['server']}'"))

    if header_data.get("powered_by"):
        findings.append(("info", f"X-Powered-By: {header_data['powered_by']}",
                         "Teknoloji ifsa ediliyor. Tek basina raporlanabilir degil.", "-"))

    lines = []
    lines.append(f"📋 *Triaj Raporu — {domain}*")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    if header_data.get("tech"):
        lines.append(f"🔧 Teknoloji: {', '.join(header_data['tech'])}")
    if ssl_data.get("issuer"):
        lines.append(f"🔐 SSL: Gecerli — {ssl_data['issuer']}")
    lines.append("")

    priority_order = ["critical", "high", "medium", "low", "info"]
    grouped = {k: [] for k in priority_order}
    for sev, title, details, poc in findings:
        grouped.get(sev, grouped["info"]).append((title, details, poc))

    reportable = sum(len(grouped[k]) for k in ["critical", "high", "medium", "low"])
    info_count = len(grouped["info"])

    if not findings:
        lines.append("✅ *Otomatik tarama belirgin sorun tespit etmedi.*")
        lines.append("")
        lines.append("Bu site guvenlidir anlamina GELMEZ. Otomatik tarama sadece yuzey kontrolu yapar.")
        lines.append("Manuel test icin:")
        lines.append("• Input alanlarina XSS payload dene")
        lines.append("• URL parametrelerini SQLi icin test et")
        lines.append("• `subfinder -d " + get_domain(url) + "` ile subdomain tara")
        lines.append("• Authenticated endpoint'leri dene (IDOR)")
    else:
        for sev_key in priority_order:
            items = grouped[sev_key]
            if not items:
                continue
            s = SEV[sev_key]
            lines.append(f"\n{s['emoji']} *{s['label']}* — {s['bounty']}")
            for title, details, poc in items:
                lines.append(f"\n*{title}*")
                lines.append(details)
                if poc != "-":
                    lines.append(f"_PoC: {poc}_")

    lines.append("\n━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"📊 {reportable} raporlanabilir bulgu, {info_count} bilgi notu")

    if reportable == 0:
        lines.append("⚠️ Raporlanabilir otomatik bulgu yok. Manuel test yapilmali.")
    elif grouped.get("critical") or grouped.get("high"):
        lines.append("🔴 Yuksek oncelikli bulgular var — hizla raporla.")
    else:
        lines.append("🟡 PoC'u kuvvetlendir, sonra raporla.")

    lines.append("\n💬 _Soru sor: 'CORS ne zaman raporlanir?', 'nasil rapor yazarim?' vb._")
    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*BugWol — Bug Bounty Triaj Asistani*\n\n"
        "HackerOne VRT standartlarina gore gercek severity degerleri. Abartisiz.\n\n"
        "*Kullanim:*\n"
        "`hedef.com` — site tara\n"
        "`CORS ne zaman raporlanir?` — soru sor\n"
        "`nasil rapor yazarim?` — rehber\n\n"
        "_Sadece kapsam ici, izinli hedeflerde kullan._",
        parse_mode="Markdown"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    text_lower = text.lower()
    for qa in BOUNTY_QA:
        if any(kw in text_lower for kw in qa["keywords"]):
            await update.message.reply_text(qa["answer"], parse_mode="Markdown")
            return
    if re.match(r"^(https?://)?[\w\-]+(\.[\w\-]+)+(/\S*)?$", text):
        await do_scan(update, normalize_url(text))
    else:
        await update.message.reply_text(
            "URL yaz ya da soru sor.\nOrnek: `example.com` veya `CORS ne zaman raporlanir?`",
            parse_mode="Markdown"
        )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Kullanim: `/scan https://hedef.com`", parse_mode="Markdown")
        return
    await do_scan(update, normalize_url(" ".join(context.args)))


async def do_scan(update: Update, url: str):
    domain = get_domain(url)
    wait_msg = await update.message.reply_text(
        f"⏳ *{domain}* taranıyor...\n_~20-30 saniye_",
        parse_mode="Markdown"
    )
    try:
        loop = asyncio.get_event_loop()
        header_data, ssl_data, files, robots, redirect_param, cors_reflected = await asyncio.gather(
            loop.run_in_executor(None, check_headers, url),
            loop.run_in_executor(None, check_ssl, domain),
            loop.run_in_executor(None, check_sensitive_files, url),
            loop.run_in_executor(None, check_robots_txt, url),
            loop.run_in_executor(None, check_open_redirect, url),
            loop.run_in_executor(None, check_cors_reflection, url),
        )
        if not header_data.get("reachable"):
            await wait_msg.edit_text(
                f"❌ *{domain}* adresine ulasilamadi.\n"
                f"Hata: {header_data.get('error', 'Bilinmiyor')}",
                parse_mode="Markdown"
            )
            return
        report = build_report(url, header_data, ssl_data, files, robots, redirect_param, cors_reflected)
        await wait_msg.delete()
        if len(report) > 4000:
            for i in range(0, len(report), 4000):
                await update.message.reply_text(report[i:i+4000], parse_mode="Markdown")
        else:
            await update.message.reply_text(report, parse_mode="Markdown")
    except Exception as e:
        await wait_msg.edit_text(f"Hata: {e}")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, *args):
        pass


def start_health_server():
    server = HTTPServer(("0.0.0.0", PORT), HealthHandler)
    server.serve_forever()


def make_app():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return app


def main():
    # Health server: non-daemon → process hep ayakta kalir
    t = threading.Thread(target=start_health_server, daemon=False)
    t.start()
    print(f"Health server baslatildi, port: {PORT}")

    # Bot: hata olursa yeniden baslat
    while True:
        try:
            print("Bot polling baslatiliyor...")
            make_app().run_polling(drop_pending_updates=True)
        except Exception as e:
            print(f"Bot hatasi: {e!r} — 5s sonra yeniden baslatiliyor...")
            time.sleep(5)


if __name__ == "__main__":
    main()
