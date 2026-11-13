# İskele Kapsama Matrisi (yaşayan belge)

Her satır bir zafiyet sınıfı; 3 bacak: TESPİT (payload/tetik) / İCRA (alet) /
DOĞRULAMA (oracle). Durumlar: **KANITLI** (canlı ateş + kanıt) · **KABLOLU**
(tetikleyici var, ateş yok) · **ÖLÜ** (alet var, tetik yok, hiç çağrılmadı) ·
**YOK** (alet yok).

Kural: her kampanya başında bu dosyaya bakılır; yeni ateş/ekleme sonrası
güncellenir. Kaynak: audit.db (distinct tool), lab kanıtları, kod okuma.

## Web enjeksiyon

| Sınıf | Tespit | İcra | Doğrulama | Kanıt | Durum |
|---|---|---|---|---|---|
| SQLi (error/union/blind) | validator payloadları | el-curl + sqlmap (manuel) | validate_sqli 0.82 | lab1-t2..t4, lab2 | KANITLI |
| XSS reflected | arjun + evolve zinciri | evolve_payload (%253C) | browser exec + validator | lab1-t4 (Alert:1) | KANITLI |
| XSS stored | harvest + manuel | browser_dom_xss_probe | exec json/png | lab2-t1 (KALI_2X7) | KANITLI |
| SSRF in-band | el-curl | curl_request | 200+creds diff | lab1-t1/t2/t4 | KANITLI |
| SSRF OOB | interactsh_start | validate_ssrf_oob | poll+confirm_oob | lab1-t4 (7 cb), lab2-t1 (6 cb) | KANITLI |
| XXE | payload bilgisi | el-curl | validate_xxe (AUTO_VALIDATE'e baglandi) | lab2-t1 F8 OOB ile kapandı | KABLOLU |
| SSTI Jinja | {{7*7}} | el-curl | validate_ssti 0.97 | lab2-t1 | KANITLI |
| SSTI diğer motorlar | validator şablonları (Twig/FM/Velocity/Smarty/ERB/Razor) | validate_ssti | aritmetik + Jinja/Twig ayırt etme (Faz D) | yerel fixture (jinja/twig) | KABLOLU |
| CMDi | payload bilgisi | el-curl | validate_command_injection (ölü) | yok | KABLOLU |
| NoSQLi | nosqli_mongo_test | alet (1 ateş) | auth-bypass diff | lab2-mixed (CRITICAL) | KANITLI |
| SSTI/CMDi blind-OOB | interactsh zinciri | validate + poll | confirm_oob | lab2-t1 XXE | KANITLI |

## Erişim kontrolü + kimlik

| Sınıf | Tespit | İcra | Doğrulama | Kanıt | Durum |
|---|---|---|---|---|---|
| BOLA/IDOR (tek obje) | harvest + idor_id_candidates | test_access_matrix (14 ateş) | analyze_authz_result | lab1-t2.. | KANITLI |
| IDOR (çok-ID süpürme) | idor_id_candidates | api_idor_matrix (ölü) | analyze_authz_result | yok (tetikleyici eklendi) | KABLOLU |
| BFLA | el-curl + matrix | test_access_matrix | analyze_authz_result | lab1 tüm turlar | KANITLI |
| Tenant confusion | header matrisi | test_access_matrix | byte-identical oracle | lab1 tüm turlar | KANITLI |
| JWT alg-none | jwt_attack_alg_none | alet | 401/2xx diff | lab turları (negatif) | KANITLI |
| JWT RS→HS | jwt_rs_to_hs_confusion (5 varyant) | alet + tüm uçlara | 2xx+veri | lab1-mixed (CRITICAL) | KANITLI |
| JWT kid/jku/x5u/brute | jwt_attack_kid/jku üretici + jwt_kid_jku_verify (Faz B) + loop kancası | alet gönderir | baseline/aday diferansiyel | yerel savunmasız sunucu kabulü (kid + jku) | KABLOLU |
| OAuth redirect | oauth_discovery_checklist | el-curl | redirect diff | lab1 (PARKED, lab kusuru) | KABLOLU |
| OAuth code/PKCE/state | bilgi | YOK (browser akışı) | YOK | yok | YOK |
| Session/refresh replay | el-curl | curl_request | çift-kullanım diff | lab2-t1 F10 (bonus) | KANITLI |
| Mass assignment | generate_abuse_cases | el-curl | rol diff | lab2-t1 F2 | KANITLI |

## Modern web / API

| Sınıf | Tespit | İcra | Doğrulama | Kanıt | Durum |
|---|---|---|---|---|---|
| GraphQL intro | graphql_introspect | alet (1 ateş) | şema diff | lab2-t1 | KANITLI |
| GraphQL depth/mutation | suggestion_scan (loop yuzey kancasi) + operasyon planı (graphql_ops) | el-curl | veri diff | lab2 (leak: lab kusuru) | KABLOLU |
| Prototype pollution (query) | prototype_pollution_scan | alet | echo heuristik | negatifler | KANITLI |
| PP (JSON-body) | post_json fazı (eklendi) | alet (ateş yok) | default/read diff | yok | KABLOLU |
| Race/double-spend | race_condition_test | barrier burst (4 ateş) | sayaç diff | lab2-t1 F5 (25/25) | KANITLI |
| WS handshake (CSWSH) | websocket_handshake_test | alet | 101+secret diff | lab2-t1 F9 | KANITLI |
| WS auth-matrix | websocket_authz_matrix (Faz 4) | alet (yerel test) | kimlik hash diff | yerel echo testi | KABLOLU |
| gRPC reflection | grpc_reflection_probe (Faz 4) | alet | servis listesi | yok (canlı yok) | KABLOLU |
| Smuggling probe | http_smuggling_probe (loop yuzey kancasi) | alet | timing diff | yok | KABLOLU |
| CORS matrix | cors_advanced_scan (stub-kanıtlı) | alet | 9 senaryo | stub (canlı: grant bekliyor) | KABLOLU |
| Cache poisoning | el-curl | curl_request | x-cache diff | lab2-t1 F7 | KANITLI |
| Open redirect | oauth_redirect_bypass (ölü?) | varyant listesi | redirect diff | lab1 OAuth (PARKED) | KABLOLU |
| Deserialization (Java/PHP/pickle) | serileştirilmiş sample tetikleyicisi (normalize+fuzz+router) | validate_deserialization (üçlü farksal; .NET kapsam dışı) | geçerli/bozuk/taşıyıcısız diff | yerel testler; canlı lab kabulü lab erişimi bekliyor | KABLOLU |
| Cookie taşıyıcı (TrackingId örüntüsü) | discover Set-Cookie kaydı + canary (location=cookie) | validate_sqli carrier='cookie' (baz gerçek cookie değerinden) | boolean/error/time diferansiyeli | yerel uygulama CONFIRMED; canlı lab instance süresi doldu | KABLOLU |
| Header/path taşıyıcıları | kayıt (normalize) + canary (header/path) | validate_* carrier='header'/'path' | boolean diferansiyel | yerel uygulama CONFIRMED (ikisi de) | KABLOLU |
| Blind OOB (genel) | validate_blind_oob şablonları (sqli/xss/cmdi/xxe) | confirm_oob_callback (token korelasyonu) | callback host tam eşleşme | yerel roundtrip CONFIRMED/UNCONFIRMED ayrımı | KABLOLU |
| CSRF | validate_csrf (token alanı tespiti) | token'sız + sahte token POST | 2xx + success_marker diferansiyeli | yerel zayıf/güçlü uygulama ayrımı | KABLOLU |
| File upload | bilgi | el-curl | validate_file_upload (validator) | yok (canlı yok) | KABLOLU |
| SSTI dışı template | bilgi | YOK | YOK | yok | YOK |

## Zincirleme + kapanış

| İşlev | Alet | Kanıt | Durum |
|---|---|---|---|
| Varyant fanout | hunt_variants + auto_fanout (7 ateş) | lab2-t1 p4c_* | KANITLI |
| Kill-chain | compose_attack_chains + kill_chain_report (2 ateş) | lab2-t1 SSTI→RCE | KANITLI |
| Exploit merdiveni | exploit_confirmed (artifact→evidence pack→replay→fanout→kapılı deepen) | yerel CONFIRMED üzerinde replay 200 kanıtı | KABLOLU |
| Stored / ikinci derece | validate_second_order (yaz->oku canary) | yerel guestbook CONFIRMED; çalıştırma browser probe notu | KABLOLU |
| Padding oracle (sifreli token) | crypto_token cekirdegi (yapi+iyi-yapililik) + loop kancasi | validate_token_differential (kontrollu kume: flip/truncate/malformed/absent; decode-hatasi disi) | lab vakasi UNCONFIRMED regresyonu + sentetik CONFIRMED | KABLOLU |
| Uygulama-akisi sifreleme oracle'i | jenerik sifrele-coz donus-turu probu | validate_token_roundtrip (kanarya A/B + Set-Cookie + yansima) + forge_cbc_token (yerel IV-dovme) + splice_cbc_token (blok-hizali onek kesme) | sentetik CONFIRMED/UNCONFIRMED ayrimi | KABLOLU |
| XXE + upload canary | fuzz SAFE_LIVE'a xxe/file_upload eklendi (XML gövde + multipart) | light oracle (passwd imzası / yansıma) -> validate_xxe / validate_file_upload | KABLOLU |
| RAG PoC zenginleştirme | enrich_with_rag (ölü) | yok | ÖLÜ |
| Critic review | critic_review (1 ateş + 401 ölü sağlayıcı) | storm yedeği | KABLOLU (sağlayıcı borç) |
| Headed otonom | agent-browse (401, ölü) | yok | YOK (sağlayıcı borç) |
| Oturumlu tarayıcı etkileşimi | browser_session_* (10 alet: CDP attach, goto/click/fill/press/snapshot/text/crawl/requests/close) | login akışı + crawl boyunca XHR toplama (POST gövde, maskeli) → parse_xhr ingest | yerel uygulama (login→panel→fetch→envanter) | KABLOLU |
| Proxy kayıt (mitm) | mitmdump 8080: mitm_rapyd + mitm_scope (kapsam hostları, gövde 2000kr, maskeli) | session context + kullanıcı Chrome'u (start-user-chrome.sh) proxy'den geçer | expedia.com canlı akış logu (07:28) | KABLOLU |
| Katana crawl | katana_crawl (kali-tools; depth≤5, rl=50, kimlik header desteği) | alet | yerel site (link keşfi) | KABLOLU |
| JS rota madenciliği | compose_js_routes (3 ateş) | lab turları | KANITLI |
| Param keşfi | arjun_param_discover (3 ateş) + api_param_discover (ölü) | lab1-t4 | KANITLI |
| OOB dinleyici | interactsh_start/poll (5+ ateş) | lab1-t4, lab2-t1 | KANITLI |

## Alan dışı (uyuyan rezerv — normal)

AD (12), container/k8s (12), CTF/HTB (11), LLM-security (6), osint derinleri,
telemetry (9), wpscan/nikto/zap tekil sarmalayıcılar. Politika-yasaklılar
(nuclei/masscan/hydra) ölü kalmalı.

## Borç defteri (öncelikli)

1. ~~JWT kid/jku~~ — Faz B ile KABLOLU (verify + loop kancası; canlı hedef kanıtı Faz A'da).
2. Session manager — alet YOK (prompt kuralı var). Tetik: portal/Keycloak turu.
3. Transport impersonate — YOK. Tetik: WAF bloğu (ShieldSquare/Radware).
4. Rollback motoru — YOK (yasaklarla idare). Tetik: PUT/PATCH/DELETE ihtiyacı.
5. Critic + agent-browse sağlayıcı 401 — infra borç. Tetik: anahtar yenileme.
6. Smuggling/file-upload baglandi (loop kancasi / validate_file_upload). Deserialization Faz 1 ile KABLOLU (canlı lab kabulü kaldı). Kimlik tedarik: identity_provision.py (Faz 3, human_needed görünür). Deepen adımları policy grant + zincir önkoşul kapılı (Faz 2).
