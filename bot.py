import asyncio
import socket
import ssl
import re
import json
from urllib.parse import urlparse
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = "8764847094:AAGurxxPQXRcjLRqmhwmdBfI0SjlkuXjMz0"

# Kullanicinin son tarama sonuclarini tutan bellegi
user_sessions = {}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "Medium", "bounty_min": 100, "bounty_max": 500},
    "Content-Security-Policy": {"severity": "High", "bounty_min": 200, "bounty_max": 2000},
    "X-Frame-Options": {"severity": "Medium", "bounty_min": 50, "bounty_max": 500},
    "X-Content-Type-Options": {"severity": "Low", "bounty_min": 50, "bounty_max": 200},
    "Referrer-Policy": {"severity": "Info", "bounty_min": 0, "bounty_max": 100},
    "Permissions-Policy": {"severity": "Info", "bounty_min": 0, "bounty_max": 100},
}

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/.env.backup", "/.env.local",
    "/backup.zip", "/backup.sql", "/dump.sql",
    "/phpinfo.php", "/info.php",
    "/server-status", "/server-info",
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/adminer.php", "/dashboard",
    "/swagger", "/api-docs", "/swagger-ui.html", "/openapi.json",
    "/graphql", "/graphiql",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/crossdomain.xml",
]

BOUNTY_QA = [
    {
        "keywords": ["hsts", "strict-transport", "ssl stripping", "mitm"],
        "answer": (
            "HSTS (HTTP Strict Transport Security) eksikliği orta seviye bir bulgudur. "
            "Saldırgan aynı ağdaysa SSL stripping yaparak HTTP'ye düşürebilir. "
            "Çoğu bug bounty programı buna $100-500 arasında ödüyor, ama tek başına "
            "raporlanırsa düşük değerleniyor. CSP gibi başka eksiklerle birlikte rapor et, değeri artar."
        ),
    },
    {
        "keywords": ["csp", "content security policy", "xss"],
        "answer": (
            "CSP eksikliği oldukça değerli bir bulgudur, özellikle XSS ile birleşince. "
            "Eğer sitede hem CSP yok hem de XSS açığı bulduysan, bu durum Critical seviyeye "
            "çıkabilir ve $1000-10000+ ödül getirebilir. Sadece CSP eksikliği ise $200-1000 bandında. "
            "Önemli: CSP eksikliğini XSS kanıtıyla birlikte raporla, etkisi çok daha güçlü olur."
        ),
    },
    {
        "keywords": ["cors", "cross origin", "access-control"],
        "answer": (
            "CORS misconfiguration çok değerli! Özellikle 'Access-Control-Allow-Origin: *' "
            "ile birlikte 'Access-Control-Allow-Credentials: true' varsa, bu Critical sayılır "
            "ve $1000-10000 arası ödül getirebilir. Sadece wildcard varsa High seviye, $500-3000. "
            "Test için: Tarayıcı konsolunda fetch() ile hedef API'ye istek at ve response'u oku."
        ),
    },
    {
        "keywords": ["open redirect", "yönlendirme", "redirect"],
        "answer": (
            "Open Redirect genelde Low-Medium seviye, $100-500 arası. Ama dikkat: "
            "eğer OAuth flow'u varsa (Google ile giriş, GitHub ile giriş gibi), "
            "open redirect + OAuth kombinasyonu token çalmaya yol açar ve bu High/Critical olur, "
            "$1000-5000+ ödül. Login akışında redirect parametresi var mı diye bak mutlaka."
        ),
    },
    {
        "keywords": ["env", ".env", "git", ".git", "dosya", "kaynak kod", "source"],
        "answer": (
            "Bu çok ciddi! Eğer /.env veya /.git/config erişilebiliyorsa bu Critical seviyedir. "
            ".env içinde API anahtarları, veritabanı şifreleri olabilir. "
            "/.git üzerinden tüm kaynak kodu indirebilirsin (git-dumper aracıyla). "
            "Bu tür bulgular $1000-10000+ ödül getirir. Bulduğunda hemen raporla, "
            "çünkü production ortamında ciddi veri sızıntısı riski var."
        ),
    },
    {
        "keywords": ["clickjacking", "x-frame", "iframe"],
        "answer": (
            "Clickjacking (X-Frame-Options eksikliği) Low-Medium seviye. $50-500 arası. "
            "Tek başına raporlanınca değeri düşük, ama kullanıcı etkileşimi gerektiren "
            "hassas sayfalar varsa (şifre değiştir, para transferi gibi) değeri artar. "
            "PoC için: basit bir HTML sayfasına hedefi iframe ile göm ve ekran görüntüsü al."
        ),
    },
    {
        "keywords": ["wordpress", "wp", "plugin"],
        "answer": (
            "WordPress siteler bug bounty için altın maden! "
            "Yapman gerekenler sırayla: "
            "1) wpscan ile plugin/theme listesi çıkar "
            "2) eski/vulnerable plugin var mı diye WPScan veritabanında kontrol et "
            "3) /wp-json/wp/v2/users endpoint'i açık mı? (kullanıcı adı enumeration) "
            "4) xmlrpc.php aktif mi? (brute force riski) "
            "WordPress açıkları $100-5000 arasında değişiyor programa göre."
        ),
    },
    {
        "keywords": ["sql", "injection", "sqli"],
        "answer": (
            "SQL Injection bug bounty'nin kraliçesi! Critical seviye, $1000-30000+. "
            "Otomatik tarama yeterli değil, manuel test şart. "
            "Şunları dene: URL parametrelerine ' (tek tırnak) ekle, hata mesajı var mı? "
            "sqlmap kullanabilirsin ama izinli hedefte. "
            "Blind SQLi bile bulsan çok değerli, PoC'u net göster."
        ),
    },
    {
        "keywords": ["subdomain", "alt alan", "takeover"],
        "answer": (
            "Subdomain takeover çok değerli, High seviye $500-5000! "
            "Nasıl bulunur: subfinder/amass ile subdomainleri listele, "
            "sonra her birinin DNS'ini kontrol et — CNAME kaydı var ama hedef silinmişse takeover mümkün. "
            "Genelde Heroku, GitHub Pages, Netlify, Shopify platformlarında olur. "
            "Takeover yapıp sadece proof page koy, asla kötüye kullanma."
        ),
    },
    {
        "keywords": ["ne kadar", "para", "ödül", "bounty", "değer", "değeri ne", "kaç para", "kaç dolar"],
        "answer": (
            "Bug bounty ödülleri programa ve önem derecesine göre değişiyor:\n\n"
            "• Info / Low: $0–200\n"
            "• Medium: $200–1000\n"
            "• High: $1000–5000\n"
            "• Critical: $5000–30000+\n\n"
            "Büyük programlar (Google, Microsoft, Apple, Meta) çok daha yüksek ödüyor. "
            "HackerOne ve Bugcrowd üzerinden programa bak, scope ve ödeme tablosuna dikkat et. "
            "İpucu: scope dışı bulgu raporlarsan para alamazsın, önce neyin kapsama girdiğini oku!"
        ),
    },
    {
        "keywords": ["nasıl rapor", "rapor", "raporlama", "yazmak", "rapor yaz"],
        "answer": (
            "İyi rapor = yüksek ödül! Şu formatı kullan:\n\n"
            "1. *Başlık:* Kısa ve net — 'XSS on /search via q parameter'\n"
            "2. *Özet:* 2-3 cümle, ne buldun?\n"
            "3. *Adımlar:* Adım adım nasıl reproduce edilir?\n"
            "4. *PoC:* Ekran görüntüsü veya video ŞART\n"
            "5. *Etki:* Bu açık kullanılırsa ne olur?\n"
            "6. *Öneri:* Nasıl düzeltilebilir?\n\n"
            "Triaj sürecinde genelde 1-3 gün içinde ilk yanıt gelir. "
            "Yanıt gelmezse nazikçe ping at."
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


def check_headers(url: str) -> dict:
    result = {"headers": {}, "server": "", "powered_by": "", "tech": [], "cors": None, "status_code": 0}
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 BugWol/1.0"})
        h = resp.headers
        for header in SECURITY_HEADERS:
            result["headers"][header] = header in h
        result["server"] = h.get("Server", "")
        result["powered_by"] = h.get("X-Powered-By", "")
        cors = h.get("Access-Control-Allow-Origin", "")
        creds = h.get("Access-Control-Allow-Credentials", "")
        if cors == "*":
            result["cors"] = "wildcard"
        elif cors:
            result["cors"] = cors
        result["cors_creds"] = creds.lower() == "true"
        tech = []
        body = resp.text.lower()
        if "wp-content" in body or "wordpress" in body:
            tech.append("WordPress")
        if "drupal" in body:
            tech.append("Drupal")
        if "joomla" in body:
            tech.append("Joomla")
        if "laravel" in body:
            tech.append("Laravel")
        if "django" in body or "csrfmiddlewaretoken" in body:
            tech.append("Django")
        if "react" in body and "__react" in body:
            tech.append("React")
        if "angular" in body:
            tech.append("Angular")
        result["tech"] = tech
        result["status_code"] = resp.status_code
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl(domain: str) -> dict:
    result = {"valid": False, "issuer": "", "expires": "", "error": ""}
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        result["valid"] = True
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "?")
        result["expires"] = cert.get("notAfter", "")
    except ssl.SSLCertVerificationError:
        result["error"] = "Sertifika geçersiz veya süresi dolmuş"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_sensitive_paths(base_url: str) -> list:
    found = []
    for path in SENSITIVE_PATHS:
        try:
            resp = requests.get(base_url + path, timeout=5, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0 BugWol/1.0"})
            if resp.status_code in (200, 403):
                found.append({"path": path, "status": resp.status_code, "size": len(resp.content)})
        except Exception:
            pass
    return found


def check_open_redirect(base_url: str) -> bool:
    for param in ["redirect", "url", "next", "return", "goto", "redir", "target"]:
        try:
            resp = requests.get(f"{base_url}/?{param}=https://evil.com", timeout=5, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0 BugWol/1.0"})
            if "evil.com" in resp.headers.get("Location", ""):
                return True
        except Exception:
            pass
    return False


def answer_bounty_question(text: str) -> str:
    text_lower = text.lower()
    for qa in BOUNTY_QA:
        if any(kw in text_lower for kw in qa["keywords"]):
            return qa["answer"]
    return None


def build_narrative_report(url: str, header_data: dict, ssl_data: dict, paths: list, open_redirect: bool) -> str:
    domain = get_domain(url)
    missing_headers = [h for h, present in header_data["headers"].items() if not present]
    total_score = 0
    critical_finds = []
    high_finds = []
    medium_finds = []
    low_finds = []

    # SSL
    if not ssl_data.get("valid"):
        medium_finds.append(("SSL sorunu", "$200–500", "Sertifika geçersiz veya hatalı yapılandırılmış."))
        total_score += 300

    # CORS
    if header_data.get("cors") == "wildcard":
        if header_data.get("cors_creds"):
            critical_finds.append(("CORS + Credentials", "$2000–10000", "Wildcard CORS + credentials=true — çok tehlikeli kombinasyon!"))
            total_score += 5000
        else:
            high_finds.append(("CORS Misconfiguration", "$500–3000", "Herhangi bir site bu API'ye istek atabilir."))
            total_score += 1500

    # Open redirect
    if open_redirect:
        medium_finds.append(("Open Redirect", "$100–500", "URL parametresi ile dış siteye yönlendirme mümkün."))
        total_score += 300

    # Hassas dosyalar
    for p in paths:
        path = p["path"]
        status = p["status"]
        if any(x in path for x in [".env", ".git", "backup", "dump"]):
            if status == 200:
                critical_finds.append((f"Hassas Dosya: {path}", "$1000–10000", "Kaynak kod veya gizli bilgiler açıkta!"))
                total_score += 5000
            else:
                medium_finds.append((f"Kısıtlı Yol: {path}", "$50–200", "Erişim engellendi ama varlığı doğrulandı."))
                total_score += 100
        elif any(x in path for x in ["admin", "phpmyadmin", "adminer"]):
            if status == 200:
                high_finds.append((f"Admin Panel: {path}", "$200–2000", "Admin paneli internete açık!"))
                total_score += 1000
            else:
                low_finds.append((f"Admin Varlığı: {path}", "$50–100", "Engellendi ama panel var."))
                total_score += 50
        elif any(x in path for x in ["swagger", "graphql", "api-docs", "openapi"]):
            medium_finds.append((f"API Dokümantasyonu: {path}", "$100–500", "API endpoint listesi herkese açık."))
            total_score += 200
        elif status == 200:
            low_finds.append((f"{path}", "$50–200", f"HTTP {status} ile erişilebilir."))
            total_score += 100

    # Header bulgular
    header_info = {
        "Content-Security-Policy": ("CSP Eksik", "$200–2000", "XSS saldırıları için zemin hazır."),
        "Strict-Transport-Security": ("HSTS Eksik", "$100–500", "SSL stripping saldırısına açık."),
        "X-Frame-Options": ("Clickjacking Riski", "$50–500", "Site bir iframe içine yerleştirilebilir."),
        "X-Content-Type-Options": ("MIME Sniffing", "$50–200", "Tarayıcı dosya türünü yanlış yorumlayabilir."),
        "Referrer-Policy": ("Referrer Sızıyor", "$0–100", "Kullanıcı hareketleri dışarı sızıyor."),
        "Permissions-Policy": ("İzin Politikası Yok", "$0–100", "Kamera/mikrofon kontrolü tanımlı değil."),
    }
    for h in missing_headers:
        if h in header_info:
            name, bounty, desc = header_info[h]
            info = SECURITY_HEADERS[h]
            if info["severity"] == "High":
                high_finds.append((name, bounty, desc))
                total_score += 500
            elif info["severity"] == "Medium":
                medium_finds.append((name, bounty, desc))
                total_score += 200
            else:
                low_finds.append((name, bounty, desc))
                total_score += 50

    # Teknoloji bilgisi
    tech_str = ", ".join(header_data.get("tech", [])) if header_data.get("tech") else "tespit edilemedi"

    lines = []

    # Giriş
    lines.append(f"🔍 *{domain}* için keşif raporum hazır, dinle:\n")

    if header_data.get("server") or header_data.get("powered_by"):
        server = header_data.get("server", "")
        powered = header_data.get("powered_by", "")
        lines.append(f"Öncelikle sunucu bize biraz fazla bilgi vermiş gibi 😏")
        if server:
            lines.append(f"Sunucu kendini *{server}* olarak tanıtıyor — bu versiyon bilgisi saldırganlar için ipucu olabilir.")
        if powered:
            lines.append(f"Üstelik *X-Powered-By: {powered}* başlığı da var, teknoloji ifşası bu.")
        lines.append("")

    lines.append(f"Kullandığı teknolojiler: *{tech_str}*")
    if "WordPress" in header_data.get("tech", []):
        lines.append("WordPress gördüğümde gözlerim parlıyor — plugin açıkları, xmlrpc, kullanıcı enumeration gibi bir sürü yol açılıyor. wpscan'i çalıştırmanı öneririm.")
    lines.append("")

    # SSL
    lines.append("*SSL durumuna baktım:*")
    if ssl_data.get("valid"):
        lines.append(f"Sertifika geçerli, {ssl_data.get('issuer', '?')} tarafından verilmiş. Bu cephede sorun yok.")
    else:
        lines.append(f"Bir sorun var: {ssl_data.get('error', 'SSL hatası')}. Bu orta seviye bir bulgu, raporlanabilir.")
    lines.append("")

    # Bulgular
    if critical_finds:
        lines.append("🚨 *KRİTİK BULGULAR — Bunları hemen raporla:*")
        for name, bounty, desc in critical_finds:
            lines.append(f"• *{name}* ({bounty})\n  {desc}")
        lines.append("")

    if high_finds:
        lines.append("🔴 *YÜKSEK SEVİYE BULGULAR:*")
        for name, bounty, desc in high_finds:
            lines.append(f"• *{name}* ({bounty})\n  {desc}")
        lines.append("")

    if medium_finds:
        lines.append("🟡 *ORTA SEVİYE BULGULAR:*")
        for name, bounty, desc in medium_finds:
            lines.append(f"• *{name}* ({bounty})\n  {desc}")
        lines.append("")

    if low_finds:
        lines.append("🔵 *DÜŞÜK / BİLGİ SEVİYESİ:*")
        for name, bounty, desc in low_finds:
            lines.append(f"• *{name}* ({bounty})\n  {desc}")
        lines.append("")

    # Öneri
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("*Sıradaki adımlar için önerilerim:*\n")

    suggestions = []
    if "WordPress" in header_data.get("tech", []):
        suggestions.append("🛠 wpscan çalıştır: `wpscan --url " + url + " --enumerate p,u`")
    if any(".env" in p["path"] or ".git" in p["path"] for p in paths):
        suggestions.append("📁 git-dumper ile kaynak kodu çekmeyi dene: `git-dumper " + url + "/.git ./output`")
    if header_data.get("cors") == "wildcard":
        suggestions.append("🌐 CORS'u test et: farklı bir originden fetch() isteği at ve credentials ile dene")
    if "Content-Security-Policy" in missing_headers:
        suggestions.append("🧪 XSS payload dene: basit bir <script>alert(1)</script> ile başla, CSP yok")
    if any("swagger" in p["path"] or "api" in p["path"] or "graphql" in p["path"] for p in paths):
        suggestions.append("📡 API endpoint'lerini manuel olarak test et, auth bypass var mı bak")
    suggestions.append("🔎 Subdomainleri tara: `subfinder -d " + domain + "`")
    suggestions.append("📋 Wayback Machine'den eski endpoint'leri çek: `gau " + domain + "`")

    for s in suggestions:
        lines.append(s)

    lines.append("")

    # Tahmini ödül özeti
    if total_score > 3000:
        verdict = "🔥 Bu site çok umut verici! Dikkatlice incelemeye devam et."
        est = f"${total_score // 2}–${total_score * 2} arası"
    elif total_score > 500:
        verdict = "👍 Raporlanabilir bulgular var, değer görür."
        est = f"${total_score // 2}–${total_score} arası"
    else:
        verdict = "😐 Büyük açık görünmüyor ama subdomain ve manuel testle devam et."
        est = "$0–200 arası (şimdilik)"

    lines.append(f"*Genel değerlendirmem:* {verdict}")
    lines.append(f"*Tahmini ödül potansiyeli:* {est}")
    lines.append("")
    lines.append("💬 _Bir bulgu hakkında soru sorabilirsin — 'CORS ne eder?', 'nasıl rapor yazarım?' gibi._")
    lines.append("⚠️ _Sadece izinli bug bounty programlarında kullan._")

    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👋 *BugWol'a hoş geldin!*\n\n"
        "Bug bounty için hedef analiz asistanınım. Sana şunları yapabilirim:\n\n"
        "🔍 *Site analizi:* URL'yi yaz, tarayayım\n"
        "💬 *Soru-cevap:* Bir bulgu hakkında soru sor\n\n"
        "*Örnekler:*\n"
        "`hedef.com` — siteyi tara\n"
        "`CORS ne kadar eder?` — bounty değeri sor\n"
        "`nasıl rapor yazarım?` — raporlama rehberi\n"
        "`open redirect önemli mi?` — önemi ne?\n\n"
        "⚠️ _Sadece izin verilen hedeflerde kullan!_"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Kullanım: `/scan https://hedef.com`", parse_mode="Markdown")
        return
    url = normalize_url(" ".join(context.args))
    await do_scan(update, url)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # Bounty sorusu mu?
    answer = answer_bounty_question(text)
    if answer:
        await update.message.reply_text(answer, parse_mode="Markdown")
        return

    # URL gibi görünüyor mu?
    if re.match(r"^(https?://)?[\w\-]+(\.[\w\-]+)+(/\S*)?$", text):
        url = normalize_url(text)
        await do_scan(update, url)
    else:
        await update.message.reply_text(
            "Bir URL yaz ya da bounty hakkında soru sor.\n"
            "Örnek: `example.com` veya `CORS ne kadar eder?`",
            parse_mode="Markdown"
        )


async def do_scan(update: Update, url: str):
    domain = get_domain(url)
    wait_msg = await update.message.reply_text(
        f"⏳ *{domain}* taranıyor...\n"
        "_Güvenlik başlıkları, hassas dosyalar, CORS, SSL — hepsine bakıyorum. 20-30 sn sürebilir._",
        parse_mode="Markdown"
    )

    try:
        loop = asyncio.get_event_loop()
        header_data, ssl_data, paths, open_redirect = await asyncio.gather(
            loop.run_in_executor(None, check_headers, url),
            loop.run_in_executor(None, check_ssl, domain),
            loop.run_in_executor(None, check_sensitive_paths, url),
            loop.run_in_executor(None, check_open_redirect, url),
        )

        report = build_narrative_report(url, header_data, ssl_data, paths, open_redirect)
        await wait_msg.delete()

        if len(report) > 4000:
            for i in range(0, len(report), 4000):
                await update.message.reply_text(report[i:i+4000], parse_mode="Markdown")
        else:
            await update.message.reply_text(report, parse_mode="Markdown")

    except Exception as e:
        await wait_msg.edit_text(f"Bir hata oldu: {e}")


def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("BugWol bot calisiyor...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
