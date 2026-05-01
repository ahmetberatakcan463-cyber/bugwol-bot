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

SEV = {
    "critical": {"label": "Critical · P1", "bounty": "$5000+",      "emoji": "🔴"},
    "high":     {"label": "High · P2",     "bounty": "$1000–5000",  "emoji": "🟠"},
    "medium":   {"label": "Medium · P3",   "bounty": "$200–1000",   "emoji": "🟡"},
    "low":      {"label": "Low · P4",      "bounty": "$50–200",     "emoji": "🔵"},
    "info":     {"label": "Info · P5",     "bounty": "$0–50",       "emoji": "⚪"},
}

INTERESTING_PATHS_IN_ROBOTS = [
    "/admin", "/administrator", "/api", "/internal", "/private",
    "/backup", "/staging", "/dev", "/test", "/dashboard", "/manage",
]

CRITICAL_PATHS = [
    {"path": "/.env",            "check": "env",   "sev": "critical"},
    {"path": "/.env.local",      "check": "env",   "sev": "critical"},
    {"path": "/.env.backup",     "check": "env",   "sev": "critical"},
    {"path": "/.env.production", "check": "env",   "sev": "critical"},
    {"path": "/.git/config",     "check": "git",   "sev": "high"},
    {"path": "/.git/HEAD",       "check": "git",   "sev": "high"},
    {"path": "/backup.sql",      "check": "sql",   "sev": "critical"},
    {"path": "/dump.sql",        "check": "sql",   "sev": "critical"},
    {"path": "/phpinfo.php",     "check": "php",   "sev": "medium"},
    {"path": "/info.php",        "check": "php",   "sev": "medium"},
    {"path": "/server-status",   "check": "apache","sev": "low"},
    {"path": "/adminer.php",     "check": "login", "sev": "medium"},
    {"path": "/phpmyadmin/",     "check": "login", "sev": "medium"},
    {"path": "/wp-login.php",    "check": "login", "sev": "low"},
    {"path": "/swagger-ui.html", "check": "api",   "sev": "low"},
    {"path": "/openapi.json",    "check": "api",   "sev": "low"},
    {"path": "/api-docs",        "check": "api",   "sev": "low"},
    {"path": "/graphql",         "check": "api",   "sev": "low"},
]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

BOUNTY_QA = [
    {"keywords": ["hsts", "strict-transport"], "answer": "*HSTS Eksikligi:* P5, cogu program $0 oder. Tek basina raporlama."},
    {"keywords": ["csp", "content security policy"], "answer": "*CSP Eksikligi:* P5, $0-50. XSS ile birlesirse P2-P3'e cikar."},
    {"keywords": ["cors", "cross origin"], "answer": "*CORS:* Sadece wildcard raporlanabilir degil. Origin reflection + credentials=true ise HIGH ($500-3000). Test: evil.com origin'iyle istek at."},
    {"keywords": ["open redirect", "redirect"], "answer": "*Open Redirect:* P4, $50-200. OAuth ile birlestirilebilirse P1-P2."},
    {"keywords": ["env", ".env"], "answer": "*.env:* Icerik KEY=VALUE ise Critical P1. ASLA credential kullanma, sadece varligini raporla."},
    {"keywords": ["git", ".git"], "answer": "*.git:* P2 HIGH. `git-dumper URL/.git ./output` ile kaynak kodu cek."},
    {"keywords": ["sql injection", "sqli"], "answer": "*SQLi:* P1-P2, $1000-30000+. `' AND SLEEP(5)--` ile blind test et."},
    {"keywords": ["subdomain", "takeover"], "answer": "*Subdomain Takeover:* P2-P3, $200-3000. CNAME'i olan ama 404 veren subdomainlere bak."},
    {"keywords": ["nasil rapor", "rapor"], "answer": "*Rapor Formati:*\n1. Baslik: [Tip] — [Endpoint]\n2. Steps to Reproduce (numarali)\n3. Impact\n4. PoC (screenshot SART)\n5. Fix onerisi"},
    {"keywords": ["ne kadar", "kac para", "odul", "bounty"], "answer": "*HackerOne VRT:*\nP1 Critical: $5000+\nP2 High: $1000-5000\nP3 Medium: $200-1000\nP4 Low: $50-200\nP5 Info: $0-50"},
    {"keywords": ["wordpress", "wp"], "answer": "*WordPress:* wpscan calistir, /wp-json/wp/v2/users kontrol et, xmlrpc.php aktif mi bak."},
]


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def get_domain(url):
    return urlparse(url).netloc

def fetch(url, timeout=8):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (SecurityAudit/1.0)"})
    except:
        return None

def check_content(text, t):
    if t == "env":
        return len([l for l in text.splitlines() if re.match(r'^[A-Z][A-Z0-9_]+=.+', l.strip())]) >= 2
    if t == "git":
        return "[core]" in text or "ref: refs/" in text
    if t == "sql":
        return any(k in text for k in ["CREATE TABLE", "INSERT INTO"])
    if t == "php":
        return "PHP Version" in text or "phpinfo()" in text
    if t == "apache":
        return "Apache Server Status" in text
    return True

def check_headers(url):
    r = {"reachable": False, "missing": [], "server": "", "powered_by": "", "tech": [], "cors": None, "cors_creds": False}
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (SecurityAudit/1.0)"})
        r["reachable"] = True
        h = resp.headers
        r["missing"] = [hdr for hdr in SECURITY_HEADERS if hdr not in h]
        r["server"] = h.get("Server", "")
        r["powered_by"] = h.get("X-Powered-By", "")
        cors = h.get("Access-Control-Allow-Origin", "")
        if cors:
            r["cors"] = cors
            r["cors_creds"] = h.get("Access-Control-Allow-Credentials", "").lower() == "true"
        body = resp.text
        if "wp-content/themes" in body or "wp-includes" in body: r["tech"].append("WordPress")
        if "csrfmiddlewaretoken" in body: r["tech"].append("Django")
        if "laravel_session" in h.get("Set-Cookie", ""): r["tech"].append("Laravel")
        if "Drupal.settings" in body: r["tech"].append("Drupal")
    except Exception as e:
        r["error"] = str(e)
    return r

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {"valid": True, "issuer": issuer.get("organizationName", "?"), "expires": cert.get("notAfter", "")}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "issue": "Sertifika gecersiz"}
    except:
        return {"valid": None, "issue": "HTTPS yok veya ulasılamaz"}

def check_cors_reflect(url):
    try:
        resp = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0", "Origin": "https://evil-attacker.com"})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        return "evil-attacker.com" in acao and acac == "true"
    except:
        return False

def check_files(base):
    found = []
    for item in CRITICAL_PATHS:
        r = fetch(base + item["path"])
        if r and r.status_code == 200 and check_content(r.text, item["check"]):
            found.append({"path": item["path"], "sev": item["sev"], "size": len(r.content)})
    return found

def check_robots(base):
    paths = []
    r = fetch(base + "/robots.txt")
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                p = line.split(":", 1)[-1].strip()
                if any(ip in p.lower() for ip in INTERESTING_PATHS_IN_ROBOTS):
                    paths.append(p)
    return paths

def check_redirect(base):
    for param in ["redirect", "url", "next", "return", "goto"]:
        try:
            r = requests.get(f"{base}/?{param}=https://evil-attacker.com", timeout=5,
                             allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
            if "evil-attacker.com" in r.headers.get("Location", ""):
                return param
        except:
            pass
    return None

def build_report(url, hdr, ssl_data, files, robots, redir, cors_reflect):
    domain = get_domain(url)
    findings = []

    if ssl_data.get("valid") is False:
        findings.append(("medium", "Gecersiz SSL", ssl_data.get("issue",""), f"curl -v https://{domain}"))
    elif ssl_data.get("valid") is None:
        findings.append(("low", "HTTPS Yok", "Port 443 kapali", ""))

    if cors_reflect:
        findings.append(("high", "CORS Origin Reflection + Credentials",
                         "Baska bir siteden authenticated API istegi mumkun.",
                         f"fetch('https://{domain}/api/...', {{credentials:'include'}})"))
    elif hdr.get("cors") == "*" and hdr.get("cors_creds"):
        findings.append(("high", "CORS Wildcard + Credentials", "Teorik risk, test et.", ""))
    elif hdr.get("cors") == "*":
        findings.append(("info", "CORS Wildcard", "Public API icin normal olabilir, credentials yoksa raporlanamaz.", ""))

    if redir:
        findings.append(("low", f"Open Redirect (?{redir}=)",
                         "Parametre dogrulamasi yok. Standalone P4.",
                         f"{url}/?{redir}=https://evil-attacker.com"))

    for f in files:
        p, sev = f["path"], f["sev"]
        if ".env" in p:
            findings.append((sev, f"Ortam Degiskeni Ifsa: {p}", "KEY=VALUE dogrulandi.", f"curl {url}{p}"))
        elif ".git" in p:
            findings.append((sev, f"Git Deposu Ifsa: {p}", "Kaynak kod indirilebilir.", f"git-dumper {url}/.git ./out"))
        elif ".sql" in p:
            findings.append((sev, f"DB Yedegi Ifsa: {p}", f"{f['size']} byte", f"curl -o dump.sql {url}{p}"))
        elif "phpinfo" in p or "info.php" in p:
            findings.append((sev, "phpinfo() Acik", "PHP konfig, path, env gorunuyor.", f"{url}{p}"))
        elif "phpmyadmin" in p or "adminer" in p:
            findings.append((sev, f"DB Paneli Acik: {p}", "Brute-force denenebilir.", f"{url}{p}"))
        elif "swagger" in p or "api-docs" in p or "graphql" in p or "openapi" in p:
            findings.append(("low", f"API Dok. Acik: {p}", "Endpoint listesi herkese acik.", f"{url}{p}"))

    if robots:
        findings.append(("info", "robots.txt'de Ilginc Pathler",
                         "Standart dosya, bulgu degil. Pathler: " + ", ".join(robots), "Manuel ziyaret et"))

    if hdr.get("missing"):
        findings.append(("info", f"Eksik Guvenlik Basliklari ({len(hdr['missing'])})",
                         "P5/$0. Zayif yapilandirma, acik degil: " + ", ".join(hdr["missing"]), "Tek rapor gonderme"))

    if hdr.get("server") and any(c.isdigit() for c in hdr["server"]):
        findings.append(("info", f"Sunucu Versiyonu: {hdr['server']}", "P5, tek basina raporlanamaz.", ""))

    lines = [f"📋 *Triaj Raporu — {domain}*", "━━━━━━━━━━━━━━━━━━━━"]
    if hdr.get("tech"): lines.append(f"🔧 {', '.join(hdr['tech'])}")
    if ssl_data.get("issuer"): lines.append(f"🔐 SSL: {ssl_data['issuer']}")
    lines.append("")

    grouped = {k: [] for k in ["critical","high","medium","low","info"]}
    for sev, title, detail, poc in findings:
        grouped.get(sev, grouped["info"]).append((title, detail, poc))

    reportable = sum(len(grouped[k]) for k in ["critical","high","medium","low"])

    if not findings:
        lines += ["✅ Otomatik tarama belirgin sorun bulamadi.", "",
                  "Manuel test yap:", "• Input → XSS payload", "• URL param → SQLi",
                  f"• subfinder -d {domain}"]
    else:
        for sk in ["critical","high","medium","low","info"]:
            if not grouped[sk]: continue
            s = SEV[sk]
            lines.append(f"\n{s['emoji']} *{s['label']}* — {s['bounty']}")
            for title, detail, poc in grouped[sk]:
                lines.append(f"\n*{title}*\n{detail}")
                if poc: lines.append(f"_PoC: {poc}_")

    lines.append(f"\n━━━━━━━━━━━━━━━━━━━━\n📊 {reportable} raporlanabilir bulgu")
    if reportable == 0: lines.append("⚠️ Manuel test yapilmali.")
    elif grouped["critical"] or grouped["high"]: lines.append("🔴 Yuksek oncelik — hizla raporla.")
    else: lines.append("🟡 PoC guclendir, sonra raporla.")
    lines.append("\n💬 _Soru sor: 'CORS ne zaman raporlanir?', 'SQLi nasil test edilir?' vb._")
    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*BugWol — Bug Bounty Triaj Asistani*\n\n"
        "HackerOne VRT standartlarina gore. Abartisiz.\n\n"
        "`hedef.com` — site tara\n"
        "`CORS ne zaman raporlanir?` — soru sor\n\n"
        "_Sadece izinli hedeflerde kullan._", parse_mode="Markdown")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    tl = text.lower()
    for qa in BOUNTY_QA:
        if any(k in tl for k in qa["keywords"]):
            await update.message.reply_text(qa["answer"], parse_mode="Markdown")
            return
    if re.match(r"^(https?://)?[\w\-]+(\.[\w\-]+)+(/\S*)?$", text):
        await do_scan(update, normalize_url(text))
    else:
        await update.message.reply_text("URL yaz ya da soru sor. Ornek: `example.com`", parse_mode="Markdown")

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Kullanim: `/scan https://hedef.com`", parse_mode="Markdown")
        return
    await do_scan(update, normalize_url(" ".join(context.args)))

async def do_scan(update: Update, url: str):
    domain = get_domain(url)
    msg = await update.message.reply_text(f"⏳ *{domain}* taranıyor...", parse_mode="Markdown")
    try:
        loop = asyncio.get_event_loop()
        hdr, ssl_d, files, robots, redir, cors_r = await asyncio.gather(
            loop.run_in_executor(None, check_headers, url),
            loop.run_in_executor(None, check_ssl, domain),
            loop.run_in_executor(None, check_files, url),
            loop.run_in_executor(None, check_robots, url),
            loop.run_in_executor(None, check_redirect, url),
            loop.run_in_executor(None, check_cors_reflect, url),
        )
        if not hdr.get("reachable"):
            await msg.edit_text(f"❌ {domain} adresine ulasilamadi: {hdr.get('error','')}", parse_mode="Markdown")
            return
        report = build_report(url, hdr, ssl_d, files, robots, redir, cors_r)
        await msg.delete()
        for i in range(0, len(report), 4000):
            await update.message.reply_text(report[i:i+4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"Hata: {e}")


# Health check server (Render icin)
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, *args): pass

def run_health_server():
    HTTPServer(("0.0.0.0", PORT), HealthHandler).serve_forever()


def main():
    # 1. Health server: non-daemon thread — process hep ayakta
    threading.Thread(target=run_health_server, daemon=False).start()
    print(f"Health server port {PORT}")

    # 2. Bot: hata olursa yeniden baslat
    while True:
        try:
            app = Application.builder().token(BOT_TOKEN).build()
            app.add_handler(CommandHandler("start", start))
            app.add_handler(CommandHandler("help", start))
            app.add_handler(CommandHandler("scan", scan_command))
            app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            print("Bot polling basliyor...")
            app.run_polling(drop_pending_updates=True)
        except Exception as e:
            print(f"Bot hatasi: {e!r} — 10s sonra yeniden deneniyor")
            time.sleep(10)

if __name__ == "__main__":
    main()
