import asyncio
import socket
import ssl
import re
import os
from urllib.parse import urlparse
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8764847094:AAGurxxPQXRcjLRqmhwmdBfI0SjlkuXjMz0")

# ---------------------------------------------------------------------------
# HackerOne VRT'ye gore severity tanimlari
# Kaynak: hackerone.com/vulnerability-rating-taxonomy
# ---------------------------------------------------------------------------
SEV = {
    "critical": {"label": "Critical · P1", "bounty": "$5000+",      "emoji": "🔴"},
    "high":     {"label": "High · P2",     "bounty": "$1000–5000",  "emoji": "🟠"},
    "medium":   {"label": "Medium · P3",   "bounty": "$200–1000",   "emoji": "🟡"},
    "low":      {"label": "Low · P4",      "bounty": "$50–200",     "emoji": "🔵"},
    "info":     {"label": "Info · P5",     "bounty": "$0–50",       "emoji": "⚪"},
    "none":     {"label": "Geçersiz / Kapsam Dışı", "bounty": "$0", "emoji": "❌"},
}

# Robots.txt/sitemap icinde gecen bu path'ler varsa NOT edilir (bilgi amacli)
INTERESTING_PATHS_IN_ROBOTS = [
    "/admin", "/administrator", "/api", "/internal", "/private",
    "/backup", "/staging", "/dev", "/test", "/dashboard", "/manage",
]

# Gercekten kritik olabilecek dosya yollari (icerik kontroluyle birlikte)
CRITICAL_PATHS = [
    {"path": "/.env",           "check": "env_content",  "sev": "critical"},
    {"path": "/.env.local",     "check": "env_content",  "sev": "critical"},
    {"path": "/.env.backup",    "check": "env_content",  "sev": "critical"},
    {"path": "/.env.production","check": "env_content",  "sev": "critical"},
    {"path": "/.git/config",    "check": "git_content",  "sev": "high"},
    {"path": "/.git/HEAD",      "check": "git_content",  "sev": "high"},
    {"path": "/backup.sql",     "check": "sql_content",  "sev": "critical"},
    {"path": "/dump.sql",       "check": "sql_content",  "sev": "critical"},
    {"path": "/database.sql",   "check": "sql_content",  "sev": "critical"},
    {"path": "/phpinfo.php",    "check": "phpinfo",      "sev": "medium"},
    {"path": "/info.php",       "check": "phpinfo",      "sev": "medium"},
    {"path": "/server-status",  "check": "apache_status","sev": "low"},
    {"path": "/server-info",    "check": "apache_status","sev": "low"},
    {"path": "/adminer.php",    "check": "login_page",   "sev": "medium"},
    {"path": "/phpmyadmin/",    "check": "login_page",   "sev": "medium"},
    {"path": "/wp-login.php",   "check": "login_page",   "sev": "low"},
    {"path": "/swagger-ui.html","check": "swagger",      "sev": "low"},
    {"path": "/openapi.json",   "check": "swagger",      "sev": "low"},
    {"path": "/api-docs",       "check": "swagger",      "sev": "low"},
    {"path": "/graphql",        "check": "graphql",      "sev": "low"},
]

# Guvenlik basliklarinin eksikligi = her zaman P5 / Informational
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
            "*HSTS Eksikliği — Gerçek Durum:*\n\n"
            "Tek başına raporlandığında çoğu program bunu *P5 (Informational)* olarak işaretler ve $0 öder. "
            "HTTPS'i zaten kullanan bir sitede HSTS olmaması teorik bir riski temsil eder ama doğrudan exploit edilemez. "
            "Bunu raporlamak istiyorsan, başka güvenlik başlığı eksiklikleriyle birlikte 'Hardening önerileri' olarak tek raporda sun — "
            "bazı programlar buna $50–100 verir. Aksi halde zamanını boşa harcama."
        ),
    },
    {
        "keywords": ["csp", "content security policy"],
        "answer": (
            "*CSP Eksikliği — Gerçek Durum:*\n\n"
            "CSP yoksa bu otomatik olarak XSS riski anlamına GELMEZ. "
            "CSP eksikliği = P5, $0-50 arası. Ancak eğer sitede *ayrıca* XSS bulursan, "
            "CSP'nin yokluğu o bulgunu P2-P3'e yükseltebilir çünkü mitigasyon katmanı da yok demektir. "
            "Yani: önce XSS bul, sonra CSP eksikliğini agravating factor olarak ekle."
        ),
    },
    {
        "keywords": ["cors", "cross origin", "access-control"],
        "answer": (
            "*CORS Misconfiguration — Gerçek Durum:*\n\n"
            "Sadece `Access-Control-Allow-Origin: *` varsa bu genellikle *intentional* (kasıtlı) bir yapılandırmadır — "
            "özellikle public API'lerde. Tek başına raporlama, reddedilir.\n\n"
            "Raporlanabilir CORS senaryosu:\n"
            "1. `Origin: https://evil.com` header'ıyla istek at\n"
            "2. Response'da `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` varsa — bu HIGH\n"
            "3. Eğer bu sayede authenticated endpoint'e başka originden istek atabiliyorsan PoC hazır\n\n"
            "Bunu test etmeden rapor yazarsan triaj anında reddeder."
        ),
    },
    {
        "keywords": ["open redirect", "yönlendirme", "redirect"],
        "answer": (
            "*Open Redirect — Gerçek Durum:*\n\n"
            "Standalone open redirect çoğu programda P4, $50–200 arası. Bazı programlar hiç kabul etmez.\n\n"
            "Değerini artırmak için OAuth flow'una bağla:\n"
            "1. Uygulamada 'Google ile Giriş' gibi OAuth var mı?\n"
            "2. Varsa `redirect_uri` parametresini open redirect ile birleştirerek token çalmayı dene\n"
            "3. Bu kombinasyon Account Takeover'a yol açabilir → P1-P2\n\n"
            "PoC olmadan, sadece URL'i göstererek rapor yazma."
        ),
    },
    {
        "keywords": ["env dosya", ".env", "ortam değişken"],
        "answer": (
            "*.env Dosyası — Gerçek Durum:*\n\n"
            "Eğer `/.env` 200 OK dönüyor ve içinde gerçek KEY=VALUE çiftleri varsa bu *Critical (P1)*.\n\n"
            "Raporlamadan önce:\n"
            "1. İçeriği mutlaka doğrula — boş veya template olabilir\n"
            "2. Varsa: DB_PASSWORD, SECRET_KEY, AWS_SECRET, API_KEY değerlerini gör\n"
            "3. Bu bilgileri TEST ET — aslında geçerli mi? Geçerliyse impact çok yüksek\n"
            "4. ASLA bu credential'ları kullanma, sadece varlığını doğrula\n\n"
            "PoC: curl komutu + response screenshot yeterli."
        ),
    },
    {
        "keywords": ["git", ".git", "kaynak kod"],
        "answer": (
            "*.git Dizini — Gerçek Durum:*\n\n"
            "`.git/config` veya `.git/HEAD` 200 dönüyorsa bu *High (P2)*.\n\n"
            "git-dumper aracıyla tüm kaynak kodu çekebilirsin:\n"
            "`pip install git-dumper`\n"
            "`git-dumper https://hedef.com/.git ./output`\n\n"
            "Sonra kaynak kodda hardcoded secret, DB bilgisi vb. ara. "
            "Bunları bulursan bulgu *Critical*'e yükselir. "
            "Sadece config dosyasını göstermek P2 için yeterli PoC."
        ),
    },
    {
        "keywords": ["sql injection", "sqli", "sql"],
        "answer": (
            "*SQL Injection — Gerçek Durum:*\n\n"
            "Gerçek SQLi = P1-P2, $1000-30000+. Ama bulmak zor.\n\n"
            "Test adımları:\n"
            "1. Her input alanına ve URL parametresine `'` ekle — 500 hatası veya DB hatası var mı?\n"
            "2. `' OR '1'='1` dene\n"
            "3. Blind ise: `' AND SLEEP(5)--` — sayfa 5 sn gecikti mi?\n"
            "4. sqlmap: `sqlmap -u 'https://hedef.com/page?id=1' --risk=1 --level=1`\n\n"
            "UYARI: sqlmap'i sadece izinli hedefte ve --risk=1 ile kullan. "
            "Rate limit veya WAF varsa --delay=2 ekle."
        ),
    },
    {
        "keywords": ["subdomain", "takeover", "alt alan"],
        "answer": (
            "*Subdomain Takeover — Gerçek Durum:*\n\n"
            "P2-P3, $200–3000 arası. Bulmak nispeten kolay.\n\n"
            "Nasıl bulunur:\n"
            "1. `subfinder -d hedef.com -o subs.txt`\n"
            "2. `cat subs.txt | httpx -silent` ile canlı olanları filtrele\n"
            "3. CNAME'i olan ama 404/'This site can't be reached' veren domainlere bak\n"
            "4. CNAME'in işaret ettiği servisi (Heroku, Netlify, GitHub Pages, Shopify) kontrol et\n"
            "5. O serviste o ismi kayıt edebiliyorsan takeover mümkün\n\n"
            "PoC: kendi kontrolündeki bir sayfayı oraya koy, screenshot al. ASLA kötüye kullanma."
        ),
    },
    {
        "keywords": ["nasıl rapor", "rapor yaz", "raporlama"],
        "answer": (
            "*Profesyonel Bug Bounty Raporu Formatı:*\n\n"
            "**Başlık:** `[Tip] — [Etkilenen Endpoint] — [Kısa etki]`\n"
            "Örnek: `Reflected XSS — /search?q= — Cookie çalma mümkün`\n\n"
            "**İçerik:**\n"
            "• Vulnerability Type (HackerOne VRT'den seç)\n"
            "• Affected URL/Endpoint\n"
            "• Description (ne buldun, neden önemli)\n"
            "• Steps to Reproduce (numaralı, net adımlar)\n"
            "• Impact (kullanıcıya veya sisteme gerçek etkisi)\n"
            "• PoC (ekran görüntüsü veya video ŞART)\n"
            "• Suggested Fix\n\n"
            "**İpucu:** Triaj ekibi PoC olmayan raporu genellikle 'Needs more info' ile geri yollar. "
            "Raporu göndermeden önce başka bir tarayıcıda reproduce et."
        ),
    },
    {
        "keywords": ["ne kadar", "kaç para", "ödül", "bounty", "değer"],
        "answer": (
            "*HackerOne VRT Ödül Bantları (ortalama):*\n\n"
            "🔴 P1 Critical: $5000–30000+ (RCE, SQLi+veri, Account Takeover)\n"
            "🟠 P2 High: $1000–5000 (Stored XSS, SSRF, CORS+creds, .git ifşası)\n"
            "🟡 P3 Medium: $200–1000 (Reflected XSS, Open Redirect+OAuth, CSRF)\n"
            "🔵 P4 Low: $50–200 (Clickjacking hassas sayfada, bilgi ifşası)\n"
            "⚪ P5 Info: $0–50 (Başlık eksiklikleri, versiyon ifşası)\n\n"
            "Program büyüklüğü önemli: Google/Microsoft/Meta çok daha fazla öder. "
            "Küçük programlar tablodaki minimumları bile ödemeyebilir. "
            "Her zaman önce programın kendi ödeme tablosuna bak."
        ),
    },
    {
        "keywords": ["wordpress", "wp", "wpscan"],
        "answer": (
            "*WordPress Bug Bounty — Nereye Bakmalı:*\n\n"
            "1. `wpscan --url https://hedef.com --enumerate p,t,u --api-token TOKENIN`\n"
            "   (wpscan.io'dan ücretsiz token al)\n\n"
            "2. Eski plugin açığı bulduysan CVE'yi WPScan DB'den doğrula, gerçekten exploitable mı?\n\n"
            "3. `/wp-json/wp/v2/users` → kullanıcı adları görünüyor mu?\n\n"
            "4. XML-RPC aktif mi? `curl -s https://hedef.com/xmlrpc.php` → 200 dönüyorsa sistem.listMethods dene\n\n"
            "5. Plugin/theme kaynak kodunda arbitrary file read veya upload var mı?\n\n"
            "NOT: 'WordPress kullanıyor' diye rapor açma, exploit edilebilir açık bul."
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
    """Gercek .env icerigi mi? KEY=VALUE patternine bak."""
    lines = text.strip().splitlines()
    env_lines = [l for l in lines if re.match(r'^[A-Z][A-Z0-9_]+=.+', l.strip())]
    return len(env_lines) >= 2


def is_git_content(text: str) -> bool:
    return "[core]" in text or "repositoryformatversion" in text or "ref: refs/" in text


def is_sql_content(text: str) -> bool:
    markers = ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- phpMyAdmin"]
    return any(m in text for m in markers)


def check_content(response_text: str, check_type: str) -> bool:
    """Dosyanin icerigi gercekten tehlikeli mi?"""
    if check_type == "env_content":
        return is_env_content(response_text)
    elif check_type == "git_content":
        return is_git_content(response_text)
    elif check_type == "sql_content":
        return is_sql_content(response_text)
    elif check_type == "phpinfo":
        return "phpinfo()" in response_text or "PHP Version" in response_text
    elif check_type == "apache_status":
        return "Apache Server Status" in response_text or "Server Version" in response_text
    elif check_type == "login_page":
        return True  # Erisim yeterli
    elif check_type == "swagger":
        return "swagger" in response_text.lower() or "openapi" in response_text.lower()
    elif check_type == "graphql":
        return "__schema" in response_text or "query" in response_text.lower()
    return True


def fetch_url(url: str, timeout: int = 8) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}
        )
    except Exception:
        return None


def check_headers(url: str) -> dict:
    result = {
        "reachable": False,
        "status": 0,
        "missing_headers": [],
        "server": "",
        "powered_by": "",
        "tech": [],
        "cors": None,
        "cors_credentials": False,
        "final_url": url,
        "redirects_to_https": False,
    }
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}
        )
        result["reachable"] = True
        result["status"] = resp.status_code
        result["final_url"] = resp.url
        h = resp.headers

        for header in SECURITY_HEADERS:
            if header not in h:
                result["missing_headers"].append(header)

        result["server"] = h.get("Server", "")
        result["powered_by"] = h.get("X-Powered-By", "")

        # CORS — sadece credentials ile birlikte tehlikeli
        origin_header = h.get("Access-Control-Allow-Origin", "")
        creds = h.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if origin_header:
            result["cors"] = origin_header
            result["cors_credentials"] = creds

        # Teknoloji tespiti — sadece guclu sinyaller
        body = resp.text
        if "wp-content/themes" in body or "wp-includes" in body:
            result["tech"].append("WordPress")
        if "Drupal.settings" in body or "/sites/default/files" in body:
            result["tech"].append("Drupal")
        if "joomla" in body.lower() and "/components/com_" in body:
            result["tech"].append("Joomla")
        if "csrfmiddlewaretoken" in body:
            result["tech"].append("Django")
        if "laravel_session" in resp.headers.get("Set-Cookie", ""):
            result["tech"].append("Laravel")

        # HTTPS yonlendirme
        if url.startswith("http://") and resp.url.startswith("https://"):
            result["redirects_to_https"] = True

    except requests.exceptions.SSLError:
        result["reachable"] = True
        result["ssl_error"] = True
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
        result["valid"] = None  # HTTPS yok
        result["issue"] = "Port 443 kapalı"
    except Exception as e:
        result["valid"] = None
        result["issue"] = str(e)
    return result


def check_cors_reflection(url: str) -> bool:
    """Origin reflection var mi? En kritik CORS senaryosu."""
    try:
        resp = requests.get(
            url, timeout=8,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Origin": "https://evil-attacker.com"
            }
        )
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
            content_confirmed = check_content(resp.text, item["check"])
            if content_confirmed:
                findings.append({
                    "path": item["path"],
                    "status": 200,
                    "sev": item["sev"],
                    "confirmed": True,
                    "size": len(resp.content),
                })
            else:
                # Erisim var ama icerik beklenmedik (bos/redirect gibi)
                findings.append({
                    "path": item["path"],
                    "status": 200,
                    "sev": "info",
                    "confirmed": False,
                    "size": len(resp.content),
                })
        elif resp.status_code == 403:
            # 403 = var ama erisim yok. Bazi programlar bunu raporlanabilir bulur, cogu bulmaz.
            if item["sev"] in ("critical", "high"):
                findings.append({
                    "path": item["path"],
                    "status": 403,
                    "sev": "info",
                    "confirmed": False,
                    "note": "Erisim engellendi, varligini dogrulaniyor — raporlanabilir degil"
                })
    return findings


def check_robots_txt(base_url: str) -> dict:
    """robots.txt icindeki ilginc path'leri cek."""
    result = {"exists": False, "interesting_paths": []}
    resp = fetch_url(base_url + "/robots.txt")
    if resp and resp.status_code == 200 and "text/plain" in resp.headers.get("Content-Type", ""):
        result["exists"] = True
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[-1].strip()
                if any(ip in path.lower() for ip in INTERESTING_PATHS_IN_ROBOTS):
                    result["interesting_paths"].append(path)
    return result


def check_open_redirect(base_url: str) -> str | None:
    """Calisip calismayan parametreyi dondur."""
    params = ["redirect", "url", "next", "return", "goto", "redir", "target", "to", "location"]
    for param in params:
        try:
            resp = requests.get(
                f"{base_url}/?{param}=https://evil-attacker.com",
                timeout=5, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            loc = resp.headers.get("Location", "")
            if "evil-attacker.com" in loc:
                return param
        except Exception:
            pass
    return None


def build_report(url: str, header_data: dict, ssl_data: dict,
                 files: list, robots: dict, redirect_param: str | None,
                 cors_reflected: bool) -> str:

    domain = get_domain(url)
    findings = []  # (severity_key, title, details, poc_hint)

    # --- SSL ---
    if ssl_data["valid"] is False:
        findings.append((
            "medium",
            "Gecersiz SSL Sertifikasi",
            f"Sertifika dogrulanamadi: {ssl_data['issue']}",
            f"curl -v https://{domain} — sertifika hatasini dogrula"
        ))
    elif ssl_data["valid"] is None:
        findings.append((
            "low",
            "HTTPS Desteklenmiyor",
            "Port 443 kapali, site HTTP uzerinden calisiyor.",
            f"curl -v http://{domain} — trafik sifrelenmiyor"
        ))

    # --- CORS reflection (en tehlikeli senaryo) ---
    if cors_reflected:
        findings.append((
            "high",
            "CORS Origin Reflection + Credentials",
            "Sunucu, keyfi origin'i yansıtiyor ve credentials: true doniyor. "
            "Baska bir siteden authenticated API istegi mumkun.",
            "PoC: fetch('https://" + domain + "/api/...', {credentials:'include'}) "
            "— evil-attacker.com'dan calistir, response okunabilir mi dogrula"
        ))
    elif header_data.get("cors") == "*" and header_data.get("cors_credentials"):
        findings.append((
            "high",
            "CORS Wildcard + Credentials",
            "Access-Control-Allow-Origin: * ile Access-Control-Allow-Credentials: true ayni anda aktif.",
            "Tarayici bu kombinasyonu normalde reddeder, fakat test et."
        ))
    elif header_data.get("cors") == "*":
        findings.append((
            "info",
            "CORS Wildcard (Dusuk Risk)",
            "Access-Control-Allow-Origin: * var. Public API'ler icin intentional olabilir. "
            "Credentials kullanilmiyorsa raporlanabilir degil.",
            "Origin reflection var mi test et: origin: https://evil.com header'iyla istek at"
        ))

    # --- Open Redirect ---
    if redirect_param:
        findings.append((
            "low",
            f"Open Redirect — ?{redirect_param}= parametresi",
            "Parametre dogrulama yok, disariya yonlendirme mumkun. "
            "Standalone P4. OAuth ile birlestirilebilirse P2'ye cikar.",
            f"PoC: {url}/?{redirect_param}=https://evil-attacker.com"
        ))

    # --- Hassas dosyalar ---
    for f in files:
        if not f["confirmed"]:
            continue
        sev = f["sev"]
        path = f["path"]
        if ".env" in path:
            findings.append((
                sev,
                f"Ortam Degiskeni Dosyasi Ifşası — {path}",
                "Dosya erisime acik ve icerik KEY=VALUE formatinda dogrulandi. "
                "API anahtarlari, DB sifresi, uygulama sirri iceriyor olabilir.",
                f"PoC: curl {url}{path} — ciktiyi screenshot al, sonra programi hemen bildir"
            ))
        elif ".git" in path:
            findings.append((
                sev,
                f"Git Deposu Ifşası — {path}",
                "Git meta verisi erisime acik. git-dumper ile kaynak kod indirilebilir.",
                f"git-dumper {url}/.git ./output && grep -r 'password\\|secret\\|key' ./output"
            ))
        elif ".sql" in path or "dump" in path or "backup" in path:
            findings.append((
                sev,
                f"Veritabani Yedegi Ifşası — {path}",
                "SQL dump dosyasi erisime acik ve icerik dogrulandi.",
                f"PoC: curl -o dump.sql {url}{path} — boyut: {f['size']} byte"
            ))
        elif "phpinfo" in path or "info.php" in path:
            findings.append((
                sev,
                "PHP Yapilandirma Sayfasi Acik",
                "phpinfo() ciktisi PHP versiyonunu, module listesini, "
                "sistem yollarini ve environment degiskenlerini ifsa ediyor.",
                f"PoC: {url}{path} — DOCUMENT_ROOT, memory_limit vb. gozlemle"
            ))
        elif "phpmyadmin" in path or "adminer" in path:
            findings.append((
                sev,
                f"Veritabani Yonetim Paneli Acik — {path}",
                "DB yonetim arayuzu internete acik. Brute-force veya default credentials denenebilir.",
                f"PoC: {url}{path} — varsayilan sifre dene: root/root, admin/admin"
            ))
        elif "swagger" in path or "openapi" in path or "api-docs" in path:
            findings.append((
                "low",
                "API Dokumantasyonu Herkese Acik",
                "Tum API endpoint listesi, parametre yapisi ve authentication yontemi gorunuyor. "
                "Dogrudan P4, ama manuel test icin cok degerli bilgi.",
                f"Swagger UI: {url}{path} — auth gerektiren endpointleri listele"
            ))
        elif "graphql" in path:
            findings.append((
                "low",
                "GraphQL Endpoint Acik",
                "Introspection aktifse tum schema goruntulenebiilir.",
                f"PoC: {{\\\"query\\\":\\\"{{__schema{{types{{name}}}}}}\\\"}}"
                f" body ile POST {url}{path}"
            ))
        elif "server-status" in path or "server-info" in path:
            findings.append((
                "low",
                "Apache Sunucu Durum Sayfasi",
                "Aktif baglantilari, islem listesini ve sunucu yapisini gosteriyor.",
                f"PoC: {url}{path}"
            ))
        elif "wp-login" in path:
            findings.append((
                "info",
                "WordPress Giris Sayfasi",
                "Standart WP giris sayfasi. Tek basina raporlanabilir degil. "
                "Kullanici enumeration veya brute-force korunmasi yok mu incele.",
                f"Test: /wp-json/wp/v2/users — kullanici listesi acik mi?"
            ))

    # --- robots.txt ilginc path'ler ---
    if robots["interesting_paths"]:
        findings.append((
            "info",
            "robots.txt'de Ilginc Path'ler",
            "robots.txt standarttir, bulgu degil. Ancak icindeki path'ler saldirganin "
            "hedeflemesi icin ipucu olusturuyor: " + ", ".join(robots["interesting_paths"]),
            "Bu path'leri manuel olarak ziyaret et, icerige bak"
        ))

    # --- Guvenlik basliklarinin eksikligi --- her zaman P5 ---
    if header_data.get("missing_headers"):
        missing = header_data["missing_headers"]
        findings.append((
            "info",
            f"Eksik Guvenlik Basliklari ({len(missing)} adet)",
            "Tek basina raporlandigi zaman cogu program P5 olarak deger biciyor ve $0 oduyor. "
            "Basliklarin eksikligi guvenlik acigi degil, zayif yapilan yapilandirmadir. "
            "Eksikler: " + ", ".join(missing),
            "Bunu tek rapor olarak gonderme. Daha somut bir bulguyla birlestir."
        ))

    # --- Sunucu versiyon bilgisi ---
    if header_data.get("server") and any(c.isdigit() for c in header_data["server"]):
        findings.append((
            "info",
            "Sunucu Versiyon Bilgisi Ifsa Ediliyor",
            f"Server: {header_data['server']} — Bu versiyon bilinen CVE'leri aramayi kolaylastirir. "
            "Tek basina P5, raporlanabilir degil.",
            "searchsploit '" + header_data["server"] + "' ile CVE ara"
        ))

    if header_data.get("powered_by"):
        findings.append((
            "info",
            "X-Powered-By Basliginda Teknoloji Ifsa Ediliyor",
            f"X-Powered-By: {header_data['powered_by']}",
            "Tek basina raporlanabilir degil"
        ))

    # --- RAPOR OLUSTUR ---
    lines = []
    lines.append(f"📋 *Triaj Raporu — {domain}*")
    lines.append(f"━━━━━━━━━━━━━━━━━━━━")

    if header_data.get("tech"):
        lines.append(f"🔧 Teknoloji: {', '.join(header_data['tech'])}")
    if ssl_data.get("issuer"):
        lines.append(f"🔐 SSL: Gecerli — {ssl_data['issuer']}")
    lines.append("")

    # Severity'e gore grupla
    priority_order = ["critical", "high", "medium", "low", "info"]
    grouped = {k: [] for k in priority_order}
    for sev, title, details, poc in findings:
        grouped.get(sev, grouped["info"]).append((title, details, poc))

    reportable_count = sum(len(grouped[k]) for k in ["critical", "high", "medium", "low"])
    info_count = len(grouped["info"])

    if not findings:
        lines.append("✅ *Otomatik tarama belirgin bir sorun tespit etmedi.*")
        lines.append("")
        lines.append("Bu, sitenin guvenli oldugu anlamina GELMEZ.")
        lines.append("Otomatik tarama sadece dusuk asili meyveler icin bakar.")
        lines.append("Manuel test icin sirayla:")
        lines.append("• Tum input alanlarina XSS payload'i dene")
        lines.append("• URL parametrelerini SQLi icin test et")
        lines.append("• Subdomain enumerasyonu yap")
        lines.append("• Authenticated endpoint'leri dene (IDOR, BOLA)")
    else:
        for sev_key in priority_order:
            s = SEV[sev_key]
            items = grouped[sev_key]
            if not items:
                continue
            lines.append(f"{s['emoji']} *{s['label']}* — {s['bounty']}")
            for title, details, poc in items:
                lines.append(f"\n*{title}*")
                lines.append(details)
                lines.append(f"_PoC ipucu: {poc}_")
            lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"📊 *Ozet:* {reportable_count} raporlanabilir bulgu, {info_count} bilgi notu")

    if reportable_count == 0:
        lines.append("⚠️ Raporlanabilir otomatik bulgu yok. Manuel test yapilmali.")
    elif any(grouped["critical"]) or any(grouped["high"]):
        lines.append("🔴 Yuksek oncelikli bulgular var — hizla raporla.")
    else:
        lines.append("🟡 Orta/dusuk bulgular var. PoC'u kuvvetlendir, sonra raporla.")

    lines.append("")
    lines.append("💬 _Soru sor: 'CORS ne zaman raporlanir?', 'nasil rapor yazarim?' vb._")

    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "*BugWol — Bug Bounty Triaj Asistani*\n\n"
        "Otomatik tarama yapiyorum, sonuclari HackerOne VRT standartlarina gore derecelendiriyorum. "
        "Abartisiz, gercek severity degerleri.\n\n"
        "*Kullanim:*\n"
        "`hedef.com` — site tara\n"
        "`/scan https://hedef.com` — ayni\n\n"
        "*Soru-cevap:*\n"
        "CORS, XSS, SQLi, subdomain, rapor yazimi gibi konularda soru sorabilirsin.\n\n"
        "_Sadece kapsam ici, izinli hedeflerde kullan._"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # Soru mu?
    text_lower = text.lower()
    for qa in BOUNTY_QA:
        if any(kw in text_lower for kw in qa["keywords"]):
            await update.message.reply_text(qa["answer"], parse_mode="Markdown")
            return

    # URL mi?
    if re.match(r"^(https?://)?[\w\-]+(\.[\w\-]+)+(/\S*)?$", text):
        await do_scan(update, normalize_url(text))
    else:
        await update.message.reply_text(
            "Bir URL yaz ya da soru sor.\nOrnek: `example.com` veya `CORS ne zaman raporlanir?`",
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
                f"Hata: {header_data.get('error', 'Bilinmiyor')}\n"
                "Bug bounty programinda scope'ta mi? URL dogru mu?",
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


def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("BugWol calisiyor...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
