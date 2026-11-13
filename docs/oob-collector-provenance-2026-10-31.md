# OOB kolektör kanıtının kaynağı — 31 Ekim 2026

Bu özellik, operatörün yönettiği bir kolektörden gelen **imzalı olay
metadata'sını** yerel SSRF denemesiyle ilişkilendirir. Kolektörün kendi
altyapısı bu repoda kurulmaz ve bu geliştirme sırasında bir callback servisine
veya hedefe bağlanılmadı. İmza, olayı yapılandırılmış kolektörün imzaladığını
gösterir; callback'in hedef uygulama tarafından üretildiğini tek başına
göstermez. Sonuç bu nedenle daima `INCONCLUSIVE` kalır.

## Önkoşullar

- Hedef ve callback hostu aktif program kapsamına girmeli, ilgili araç için
  geçerli grant bulunmalıdır. Mevcut SSRF yolu yalnız gözlenen tek bir query
  parametresinde salt okunur GET dener; 401/429, giriş yönlendirmesi veya taşıma
  hatası challenge üretmez. Bağımsız validator çağrısında son istek URL'si ve
  header'ları scope, policy ve grant kapısından geçer; Hunter içindeki çağrı üst koşunun mevcut
  istek ve bütçe kapısını devralır. Redirect takip edilmez.
- Operatör, kendi kolektörünün Ed25519 **açık** anahtarını MCP sunucusunu
  başlatan güvenilir ortamda `CCO_OOB_COLLECTORS_JSON` ile tanımlar. Özel
  imzalama anahtarı kolektörde kalır; MCP argümanı veya repo içeriği yapılmaz.
  Örnek biçim: `{"lab-collector":"<base64url-32-baytlik-acik-anahtar>"}`.
- Bir anahtarı güvenilir saymak, onun sahibi olan kolektöre güvenmek demektir.
  Kolektör yalnız doğruladığı gerçek DNS/HTTP kaydını imzalamalı; ajanın verdiği
  serbest metni veya rastgele JSON'u doğrulamadan imzalamamalıdır.

## Gönderim ve olay sözleşmesi

`validator_validate_ssrf_oob` başarılı ve tek bir GET gönderimini gözlediğinde,
geçici challenge'ı yerel kanıt anahtarıyla imzalar. Yanıttaki
`evidence.collector_binding` aşağıdaki alanları içerir:

```json
{
  "nonce": "<tekil-challenge>",
  "host": "<nonce.kolektor-hostu>",
  "target_binding": "<64-hex>",
  "probe_binding": "<64-hex>",
  "param": "<query-parametresi>",
  "run_id": "<kosu-kimligi>",
  "scope_revision": "<scope-surumu>",
  "policy_hash": "<policy-surumu>",
  "sent_at": 0,
  "expires_at": 0
}
```

Binding değerleri her challenge için yeni, saklanmayan rastgele bir anahtarla
üretilen HMAC-SHA256 değerleridir; ham hedef/istek sorgu değerleri buraya
kopyalanmaz. Bunlar yerel imzalı challenge'a bağlı opak değerlerdir; dış
kolektörün tek başına HTTP gönderimini yeniden üretmesini sağlamaz. Yeni
challenge dosyasında hedef URL'si mevcut credential kasasının anahtarıyla
şifrelenir; geçmiş düz metin kayıtlar otomatik silinmez veya dönüştürülmez.
Anahtar okunamazsa kayıt kullanılamaz; okuma sırasında otomatik yeni anahtar
oluşturulmaz. Kasa anahtarının yedeği ve erişim sınırı operatöre aittir.
`collector_binding` boşsa istek ayrıntıları
doğrulanamadığından kolektör olayı bu akışta kabul edilmez.

Kolektör, gerçekten gördüğü olayın nonce ve hostunu, operatörün güvenilir
eşleştirmesiyle yukarıdaki binding'e bağlar. Ardından aşağıdaki alanlardan
oluşan nesneyi imzalar; örnekteki binding alanları challenge çıktısından aynen
alınmalıdır:

```json
{
  "schema": "cco-oob-collector-event/1",
  "collector_id": "lab-collector",
  "event_id": "<kolektorde-tekil-olay-kimligi>",
  "nonce": "<tekil-challenge>",
  "host": "<nonce.kolektor-hostu>",
  "target_binding": "<64-hex>",
  "probe_binding": "<64-hex>",
  "param": "<query-parametresi>",
  "run_id": "<kosu-kimligi>",
  "scope_revision": "<scope-surumu>",
  "policy_hash": "<policy-surumu>",
  "protocol": "dns",
  "observed_at": 0,
  "signature": "<base64url-64-baytlik-imza>"
}
```

`event_id` kişisel veri içermeyen, kolektörde üretilmiş tekil bir etikettir.
`protocol`, `dns` veya `http`; `observed_at`, UTC Unix saniyesidir. İmza,
`signature` alanı çıkarılmış nesnenin UTF-8 `json.dumps(..., sort_keys=True,
separators=(",", ":"), ensure_ascii=False)` çıktısı üzerine atılır. Bilinmeyen
veya yinelenmiş JSON alanları, yanlış anahtar, farklı hedef/istek/koşu/kapsam,
süre dışı olay ve tekrar kullanılan olay ya da challenge reddedilir.

`validator_confirm_oob_callback(token=..., collector_event_json=...)` olayı
çevrimdışı doğrular. Geçerli olayda `collector_authenticated: true` döner;
`correlated: false` ve `INCONCLUSIVE` korunur. Aynı olayın kabulü kalıcı yerel
replay kaydında tek kullanımlıktır. Doğrulanan olayın imzalı metadatası ve
kolektörün açık anahtarı, ham hedef URL'si eklenmeden yerel dosyaya kaydedilir;
dosyaya ayrıca yerel kanıt anahtarıyla imzalı bir receipt bağlanır. Dönen yol
ve SHA-256 değeri bu dosyanın bütünlüğünü incelemek içindir. Dosya veya receipt
üretilemezse olay kabul edilmez. Scope/policy, olay ile doğrulama arasında
değişmişse kabul edilmez. Eski imzasız challenge'lar serbest metin hipotezi
olarak kalır, imzalı kolektör kanıtına yükseltilmez.
`CCO_SCOPE_REVISION` veya `CCO_POLICY_HASH` ortam değişkenleri otomatik dosya
hash'i yerine kullanılıyorsa, bunların değişikliklerle güncellenmesi operatörün
sorumluluğundadır; sabit bırakılmış eski bir override değişikliği göstermez.

Kaynak atfı, bağımsız kolektör entegrasyonu, gerçek ağ üzerinde saat/yeniden
oynatma sınamaları ve bu verinin raporlanabilir bir kanıta dönüşüm kuralı
henüz tamamlanmadı. Genel blind OOB yürütmesi kapalıdır.

OOB, policy ve kasa yolunu kapsayan 56 hedefli çevrimdışı test, sentetik imzalar
ve sahte taşıyıcılarla geçti. Sonrasında browser ve validator egress dahil ilgili
74 testlik grup da geçti; gruplar örtüşür. Kurulu pakette şifreli challenge'ın
açılması ve sentetik imzalı olayın receipt ile kaydedilmesi de ayrıca kontrol
edildi. Gerçek DNS/HTTP callback veya bağımsız kolektör denenmedi.
