"""Technology fingerprint to vulnerability hypothesis catalog."""


TECH_VULN_DB = {
    "wordpress": (["sql_injection", "file_upload", "xss_stored", "authentication_bypass", "idor"],
                  "WordPress core + plugin/theme CVE'leri (wpscan DB)",
                  "Asıl risk plugin/theme'ler; sürüm + plugin/user enum şart (wp-json/wp/v2/users).",
                  "wordpress plugin sql injection rce arbitrary file upload CVE"),
    "drupal": (["sql_injection", "rce", "authentication_bypass"],
               "Drupalgeddon (CVE-2014-3704, SA-CORE-2018-002/004)",
               "Sürümü çek; Drupalgeddon2 (CVE-2018-7600) form API RCE.",
               "drupal drupalgeddon CVE-2018-7600 rce"),
    "joomla": (["sql_injection", "rce", "lfi"], "Joomla com_* extension CVE'leri",
               "3. parti component'ler en zayıf halka.", "joomla component sql injection rce CVE"),
    "apache": (["path_traversal", "rce", "info_disclosure"],
               "CVE-2021-41773/42013 (path traversal→RCE), mod_cgi",
               "Apache 2.4.49/2.4.50 path traversal + cgi → RCE; sürüm banner'ı kontrol et.",
               "apache 2.4.49 CVE-2021-41773 path traversal rce"),
    "nginx": (["path_traversal", "info_disclosure", "ssrf"],
              "alias misconfig (off-by-slash), merge_slashes",
              "location/alias off-by-slash → kaynak sızıntısı; proxy_pass SSRF.",
              "nginx alias traversal off-by-slash misconfiguration"),
    "tomcat": (["deserialization", "rce", "path_traversal"],
               "Ghostcat (CVE-2020-1938 AJP), manager upload",
               "AJP 8009 açıksa Ghostcat dosya okuma/include; /manager zayıf cred.",
               "apache tomcat ghostcat CVE-2020-1938 ajp manager rce"),
    "jboss": (["deserialization", "rce"], "JBoss/JMX-console deserialization",
              "invoker/JMXInvokerServlet → Java deserialization RCE.",
              "jboss jmx invoker deserialization rce"),
    "struts": (["rce", "ssti"], "Apache Struts OGNL (CVE-2017-5638, S2-*)",
               "Content-Type OGNL enjeksiyonu → RCE (S2-045/057).",
               "apache struts ognl CVE-2017-5638 S2-045 rce"),
    "spring": (["ssti", "rce", "info_disclosure"],
               "Spring4Shell (CVE-2022-22965), actuator exposure",
               "Actuator /env,/heapdump sızıntısı; Spring4Shell sınıf binding RCE.",
               "spring4shell CVE-2022-22965 actuator env heapdump"),
    "laravel": (["rce", "info_disclosure", "deserialization"],
                "CVE-2021-3129 (debug Ignition RCE), APP_KEY deserialization",
                "APP_DEBUG=true + Ignition → RCE; sızan APP_KEY → cookie deserialization.",
                "laravel ignition CVE-2021-3129 debug rce app_key"),
    "django": (["ssti", "info_disclosure", "open_redirect"],
               "DEBUG=True bilgi sızıntısı, SSTI (özel)",
               "DEBUG sayfası SECRET_KEY/ortam sızdırır; admin path enum.",
               "django debug=true information disclosure secret_key"),
    "flask": (["ssti", "deserialization"], "Jinja2 SSTI, pickle session",
              "{{7*7}} SSTI; SECRET_KEY sızarsa session forge.",
              "flask jinja2 ssti server side template injection"),
    "jinja": (["ssti"], "Jinja2 SSTI", "{{7*7}}/{{config}} → SSTI→RCE.",
              "jinja2 ssti rce payload"),
    "express": (["ssti", "deserialization", "mass_assignment", "ssrf"],
                "Node prototype pollution, pug/handlebars SSTI",
                "Prototype pollution + gadget → RCE; SSTI engine'e bağlı.",
                "nodejs express prototype pollution ssti rce"),
    "node": (["deserialization", "ssti", "mass_assignment", "ssrf"],
             "node-serialize RCE, prototype pollution",
             "node-serialize/funcster gadget; __proto__ pollution.",
             "nodejs deserialization prototype pollution rce"),
    "php": (["lfi", "rce", "file_upload", "sql_injection"],
            "LFI→RCE (wrapper/log poisoning), type juggling",
            "php://filter, data://, log poisoning; '==' type juggling auth bypass.",
            "php lfi rce log poisoning php filter wrapper"),
    "asp": (["deserialization", "path_traversal", "xxe"],
            "ViewState deserialization, padding oracle (MS10-070)",
            "Sızan machineKey → ViewState RCE; .NET deserialization.",
            "asp.net viewstate deserialization machinekey rce"),
    "iis": (["path_traversal", "info_disclosure"], "IIS short-name (~), tilde enum",
            "8.3 short-name enum; WebDAV.", "iis tilde short name enumeration webdav"),
    "graphql": (["idor", "bola", "info_disclosure", "sql_injection", "business_logic"],
                "GraphQL introspection, batching, nested DoS",
                "Introspection açık mı? alias batching brute; her resolver'da BOLA dene.",
                "graphql introspection idor batching authorization bypass"),
    "jwt": (["jwt_attack", "authentication_bypass", "bfla"],
            "alg=none, weak HMAC secret, kid injection",
            "alg none/HS256-RS256 confusion; zayıf secret crack; kid path traversal.",
            "jwt alg none hs256 rs256 confusion kid injection"),
    "oauth": (["open_redirect", "authentication_bypass", "account_takeover"],
              "redirect_uri laxity, state CSRF, token leak",
              "redirect_uri açık → token sızdırma; state yoksa CSRF; code reuse.",
              "oauth redirect_uri bypass token leak account takeover"),
    "saml": (["xxe", "authentication_bypass", "xml_signature_wrapping"],
             "XML signature wrapping, XXE, comment injection",
             "XSW ile assertion sahteciliği; XXE; canonicalization comment.",
             "saml xml signature wrapping xxe authentication bypass"),
    "api": (["bola", "bfla", "mass_assignment", "idor", "business_logic", "info_disclosure"],
            "OWASP API Top 10 (BOLA/BFLA/mass-assignment)",
            "Her object id'de BOLA; admin fonksiyonlarında BFLA; gizli alan mass-assignment.",
            "owasp api top 10 BOLA BFLA mass assignment"),
    "rest": (["bola", "bfla", "mass_assignment", "idor"], "OWASP API Top 10",
             "Method tampering (GET→PUT/DELETE); id manipülasyonu.",
             "rest api BOLA mass assignment method tampering"),
    "s3": (["info_disclosure", "broken_access_control"], "Public bucket, ACL misconfig",
           "Liste/okuma/yazma ACL; bucket takeover.", "aws s3 bucket public acl misconfiguration"),
    "aws": (["ssrf", "info_disclosure", "broken_access_control"],
            "SSRF→IMDS (169.254.169.254), IAM over-perm",
            "SSRF varsa IMDSv1 role kimlik bilgisi; metadata.", "aws ssrf imds iam credential metadata"),
    "elasticsearch": (["info_disclosure", "rce"], "Unauth 9200, CVE-2015-1427 Groovy RCE",
                      "9200 unauth ise tüm index; eski sürüm Groovy/MVEL RCE.",
                      "elasticsearch unauthenticated 9200 rce CVE-2015-1427"),
    "redis": (["rce", "info_disclosure"], "Unauth 6379 → RCE (cron/SSH key)",
              "Unauth Redis → webroot/SSH key yazma.", "redis unauthenticated rce config set dir"),
    "mongodb": (["info_disclosure", "authentication_bypass"], "Unauth 27017, NoSQL injection",
                "Unauth DB; $ne/$gt NoSQL auth bypass.", "mongodb unauthenticated nosql injection auth bypass"),
    "jenkins": (["rce", "info_disclosure"], "Script console RCE, CVE-2018-1000861",
                "/script Groovy RCE; anon read.", "jenkins script console groovy rce CVE-2018-1000861"),
    "git": (["info_disclosure"], ".git exposure → kaynak/secret",
            "/.git/ açıksa dump + secret/credential.", "exposed .git directory source code disclosure"),
    "login": (["authentication_bypass", "sql_injection", "business_logic", "bfla"],
              "Auth bypass, SQLi, rate-limit yok",
              "' OR 1=1; OTP/parola brute; response manipülasyonu.",
              "login authentication bypass sql injection rate limit"),
    "upload": (["file_upload", "path_traversal", "xxe"], "Unrestricted file upload",
               "Uzantı/content-type/magic byte bypass → webshell.",
               "unrestricted file upload bypass webshell"),
    "payment": (["price_manipulation", "business_logic", "race_condition", "idor"],
                "Fiyat/tutar tampering, race double-spend",
                "İstemci-taraflı fiyat; negatif miktar; race ile çift kullanım.",
                "payment price manipulation race condition business logic"),
    "checkout": (["price_manipulation", "business_logic", "workflow_bypass", "race_condition"],
                 "Sepet/checkout iş akışı bypass",
                 "Adım atlama; kupon stacking; negatif adet.",
                 "checkout workflow bypass coupon stacking negative quantity"),
}


# Taksonomi-dışı davranışsal / taşıyıcı sinyalleri (sınıf-adından bağımsız hipotez üretimi)
BEHAVIORAL_SIGNAL_RULES = [
    {
        "id": "opaque_carrier_differential",
        "vuln_class": "token_differential",
        "keywords": ("cookie", "token", "stay-logged-in", "remember", "session", "cipher", "encrypted", "notification"),
        "hypothesis": "Opak/şifreli taşıyıcıda (cookie/header/param) bit-flip, blok kesme (splice) veya padding farkı davranışsal oracle üretir.",
        "validate_with": "mcp__validator__validate_token_differential",
        "trigger_skill": "/exploit-validation",
        "rag_query": "padding oracle cbc bit flip block splice encrypted cookie token",
        "confidence": 0.72,
    },
    {
        "id": "appflow_encrypt_decrypt_roundtrip",
        "vuln_class": "token_roundtrip",
        "keywords": ("notification", "remember", "stay-logged-in", "comment", "profile", "settings", "preference"),
        "hypothesis": "Bir uçta girilen verinin şifrelenip başka bir uçta/cookie'de çözülerek yansıması (encrypt→decrypt round-trip oracle).",
        "validate_with": "mcp__validator__validate_token_roundtrip",
        "trigger_skill": "/exploit-validation",
        "rag_query": "encryption oracle decrypt oracle chosen plaintext cookie roundtrip",
        "confidence": 0.68,
    },
    {
        "id": "two_step_stored_flow",
        "vuln_class": "second_order",
        "keywords": ("comment", "post", "review", "message", "profile", "webhook", "import", "guestbook"),
        "hypothesis": "Yazma (POST/PUT) uçlarından girilen yükün okuma (GET) uçlarında ikinci derece (second-order/stored) tetiklenmesi.",
        "validate_with": "mcp__validator__validate_second_order",
        "trigger_skill": "/web-exploit",
        "rag_query": "second order injection stored xss stored ssti sqli two step",
        "confidence": 0.66,
    },
    {
        "id": "cross_state_mutation_csrf",
        "vuln_class": "csrf",
        "keywords": ("settings", "email", "password", "change", "transfer", "update", "delete", "form"),
        "hypothesis": "Durum değiştiren POST/PUT işleminin anti-CSRF token olmadan veya sahte token ile kabul edilmesi.",
        "validate_with": "mcp__validator__validate_csrf",
        "trigger_skill": "/web-exploit",
        "rag_query": "csrf cross site request forgery token bypass state mutation",
        "confidence": 0.62,
    },
]


def derive_behavioral_hypotheses(blob: str = "", surface_records: list | None = None) -> list[dict]:
    """Teknoloji taksonomisi eşleşmese bile yüzey ve taşıyıcı yapısından davranışsal hipotez üretir."""
    text = (blob or "").lower()
    records = list(surface_records or [])
    has_post = False
    has_get = False
    has_cookie_carrier = False
    for rec in records:
        if not isinstance(rec, dict):
            continue
        method = str(rec.get("method") or rec.get("state") or "GET").upper()
        url = str(rec.get("url") or rec.get("url_or_port") or "").lower()
        text += " " + url
        if method in ("POST", "PUT", "PATCH"):
            has_post = True
        elif method == "GET":
            has_get = True
        for p in rec.get("params") or []:
            if isinstance(p, dict):
                pname = str(p.get("name") or "").lower()
                ploc = str(p.get("in") or "").lower()
                psample = str(p.get("sample") or "")
                text += f" {pname} {ploc} "
                if ploc == "cookie" or len(psample) >= 24:
                    has_cookie_carrier = True

    out = []
    for rule in BEHAVIORAL_SIGNAL_RULES:
        matched_kw = [kw for kw in rule["keywords"] if kw in text]
        structural_hit = (
            (rule["id"] == "opaque_carrier_differential" and has_cookie_carrier)
            or (rule["id"] in ("appflow_encrypt_decrypt_roundtrip", "two_step_stored_flow") and has_post and has_get)
            or (rule["id"] == "cross_state_mutation_csrf" and has_post)
        )
        if matched_kw or structural_hit:
            sources = matched_kw[:3] if matched_kw else ["surface_topology"]
            out.append({
                "vuln_class": rule["vuln_class"],
                "confidence": rule["confidence"],
                "predicted_from": [f"behavioral:{s}" for s in sources],
                "cve_families": [f"invariant:{rule['id']}"],
                "hypothesis": rule["hypothesis"],
                "validate_with": rule["validate_with"],
                "trigger_skill": rule["trigger_skill"],
                "rag_query": rule["rag_query"],
            })

    if not out:
        out.append({
            "vuln_class": "behavioral_differential",
            "confidence": 0.55,
            "predicted_from": ["behavioral:baseline_vs_probe"],
            "cve_families": ["invariant:differential_observation"],
            "hypothesis": "Bilinen teknoloji/sınıf imzası yok; baseline ve mutasyonlu probe gözlemleri arasında durum/uzunluk/şema farkı (differential oracle) ara.",
            "validate_with": "mcp__validator__validate_finding",
            "trigger_skill": "/exploit-validation",
            "rag_query": "differential analysis business logic state invariant bypass",
        })
    return out

