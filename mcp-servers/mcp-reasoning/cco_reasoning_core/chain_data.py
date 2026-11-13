"""Static candidate catalog; CHAIN_RULES never prove data flow or severity.

Feasibility and potential impact rank hypotheses only. Runnable chains require
typed evidence relations and a deterministic terminal-effect oracle (P8).
"""


CAPABILITY_IMPACT = {
    "remote_code_execution": 1.0, "webshell": 0.95, "cloud_account_takeover": 1.0,
    "iam_credentials": 0.9, "data_breach": 0.9, "account_takeover": 0.9,
    "admin_access": 0.85, "internal_network_access": 0.8, "credential_dump": 0.8,
    "session_hijack": 0.7, "oauth_token_theft": 0.7, "cloud_metadata_access": 0.6,
    "authentication_bypass": 0.6, "log_poisoning": 0.5, "ssrf": 0.5,
}

CHAIN_RULES = {
    "ssrf": [("cloud_metadata_access", 0.7, "169.254.169.254 IMDS sorgusu"),
             ("internal_network_access", 0.5, "iç ağ port taraması / pivot")],
    "cloud_metadata_access": [("iam_credentials", 0.8, "IMDS role kimlik bilgisi sızıntısı")],
    "iam_credentials": [("cloud_account_takeover", 0.7, "AWS/GCP API ile kaynak ele geçirme"),
                        ("data_breach", 0.7, "S3/bucket / storage okuma")],
    "lfi": [("log_poisoning", 0.6, "access.log'a PHP payload enjeksiyonu"),
            ("credential_dump", 0.6, "config/.env/secrets okuma")],
    "log_poisoning": [("remote_code_execution", 0.7, "poisoned log include → kod yürütme")],
    "path_traversal": [("credential_dump", 0.55, "hassas dosya okuma")],
    "rfi": [("remote_code_execution", 0.8, "uzak shell include")],
    "file_upload": [("webshell", 0.7, "yürütülebilir dosya yükleme")],
    "webshell": [("remote_code_execution", 0.95, "yüklenen shell çağrısı")],
    "sql_injection": [("credential_dump", 0.8, "users tablosu / hash dump"),
                      ("authentication_bypass", 0.5, "' OR 1=1 login bypass")],
    "sql_injection_blind": [("credential_dump", 0.6, "boolean/time-based veri çıkarımı")],
    "credential_dump": [("admin_access", 0.7, "kırılan hash ile admin login")],
    "authentication_bypass": [("admin_access", 0.7, "yetkili panel erişimi")],
    "default_credentials": [("admin_access", 0.85, "varsayılan admin login")],
    "weak_credentials": [("admin_access", 0.7, "zayıf parola brute/guess")],
    "admin_access": [("remote_code_execution", 0.6, "admin paneli → dosya/komut yürütme"),
                     ("data_breach", 0.7, "tüm veriye erişim")],
    "idor": [("account_takeover", 0.6, "başka kullanıcı kaynağı → ATO"),
             ("data_breach", 0.6, "yetkisiz veri okuma")],
    "open_redirect": [("oauth_token_theft", 0.5, "OAuth redirect_uri ile token sızdırma")],
    "oauth_token_theft": [("account_takeover", 0.8, "çalınan token ile hesap ele geçirme")],
    "xss_stored": [("session_hijack", 0.7, "kalıcı cookie/oturum çalma")],
    "xss_reflected": [("session_hijack", 0.5, "kurban cookie çalma")],
    "xss_dom": [("session_hijack", 0.5, "DOM tabanlı oturum çalma")],
    "session_hijack": [("account_takeover", 0.8, "çalınan oturumla ATO")],
    "jwt_attack": [("authentication_bypass", 0.6, "alg=none / zayıf imza → kimlik sahteciliği")],
    "ssti": [("remote_code_execution", 0.8, "template engine RCE")],
    "command_injection": [("remote_code_execution", 0.95, "doğrudan komut yürütme")],
    "rce": [("remote_code_execution", 0.99, "doğrudan kod yürütme")],
    "xxe": [("ssrf", 0.6, "XXE → iç istek (SSRF pivot)"),
            ("credential_dump", 0.6, "dosya okuma via XXE")],
    "deserialization": [("remote_code_execution", 0.7, "gadget chain RCE")],
    "subdomain_takeover": [("account_takeover", 0.6, "cookie/oauth domain trust kötüye kullanımı")],
    "cors_misconfiguration": [("data_breach", 0.5, "kimlikli cross-origin veri okuma")],
}

CAPABILITY_TOOL = {
    "cloud_metadata_access": "mcp__kali-tools__interactsh_start (OOB) / curl IMDS",
    "iam_credentials": "aws/gcloud CLI ile çalınan token doğrulama",
    "cloud_account_takeover": "bulut API enumeration",
    "log_poisoning": "manuel curl (User-Agent/log injection)",
    "webshell": "mcp__kali-tools__generate_exploit_poc",
    "credential_dump": "mcp__kali-tools__sqlmap_test_structured --dump",
    "admin_access": "mcp__kali-tools__hydra_brute / manuel login",
    "session_hijack": "mcp__browser__browser_cookie_audit",
    "oauth_token_theft": "manuel OAuth akış analizi",
    "account_takeover": "manuel doğrulama (giriş)",
    "remote_code_execution": "mcp__kali-tools__generate_exploit_poc",
    "data_breach": "manuel veri erişim kanıtı",
    "internal_network_access": "mcp__kali-tools__nmap_scan_structured (pivot)",
    "ssrf": "mcp__validator__validate_ssrf_oob",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
}
