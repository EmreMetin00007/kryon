# İmzalı defter ve ortak doğrulama — ikinci dilim

Bu dilim [incelemedeki](project-review-2026-10-29.md) R03 ve R04'ü kapatır.
İlk dilimde kapanan R01/R02 kontrolleri korunur. Canlı hedeflerde işlem
yapılmaz; testler geçici depolar ve gömülü laboratuvar kullanır.

## R03: tek yazma işlemi, tutarlı okuma

[Deneme defterinde](../scripts/attempt_ledger.py) okuma, mevcut zinciri
doğrulama, sıra numarası ayırma, imzalama ve commit aynı süreçler arası
`flock` kilidinin içindedir. Ayrı lock dosyası, ledger dosyası atomic replace
ile değiştiğinde de aynı kilit inode'unu korur. Lock ve ledger symlink'leri
reddedilir.

Yeni içerik aynı dosya sisteminde geçici dosyaya yazılır; dosya fsync edilir,
`os.replace` ile devreye alınır ve dizin fsync edilir. Commit öncesindeki
yazma hatası önceki defteri korur. Okuyucuya yarım JSON satırı gösterilmez.
Okuma, varsa lock dosyasını salt okunur açar; doğrulama için yazma yetkisi
gerekmez. Eski veya dışa aktarılmış kilitsiz snapshot'lar da okunabilir.

Yeni kayıtlar aynı kanonik ledger yoluna bağlanır. Başka koşuya kopyalanan
kayıtlar, yeni yolun kanıtı olarak kabul edilmez. Koşu dizinini taşımak
otomatik güven geçişi sağlamaz; orijinal yol ve kanıtlar arşivde korunmalıdır.

## R04: özel anahtar host'ta, doğrulama açık anahtarla

[Ortak güven modülü](../scripts/evidence_trust.py) yeni deneme kayıtlarını,
validator artifact'lerini ve kapanış payload'larını Ed25519 ile imzalar.
Kayıt, artifact, kapanış ve eski kayıt geçiş kanıtları ayrı imza amaçları
kullanır; bir amaç için üretilen imza diğerinde kullanılamaz.

Host'ta `CCO_HOME/evidence_signing.key` 0600 izinleriyle oluşturulur. Anahtar
başlatma kilitlidir; mevcut anahtar sessizce yenilenmez. Anahtar kaybolmuşsa
kurulu açık anahtar kaydı değiştirilerek devam edilmez. Doğrulama işlemi
eksik bir anahtarı veya çalışma dizinini kendiliğinden oluşturmaz.

OpenCode [sandbox katmanı](../.opencode/plugins/security-gate.js), yalnızca
açık anahtar içeren `public-trust` dizinini `/tmp/cco-trust` yoluna salt
okunur mount eder. Doğrulayıcı bu mount'u `/proc/self/mountinfo` üzerinden
tanır. Komut `CCO_HOME`'u değiştirse veya `CCO_BASH_SANDBOXED` işaretini
kaldırsa bile mount güven kökü olarak kalır. Çalışma dizinine yeni bir
anahtar koymak doğrulama yetkisi yaratmaz.

Özel state home maskelenir. Sadece redakte edilmiş `validations` dizini,
salt okunur olarak doğrulama için geri bağlanır. İki eski HMAC anahtar ortam
değişkeni child ortamından çıkarılır. Böylece vault, grant/audit DB'si veya
özel imza anahtarı sandbox'a açılmaz.

MCP sunucuları ve plugin aynı host `CCO_HOME`'unu kullanmalıdır. Repo
varsayılanı `.cco` buna uygundur. Özel bir state home kullanılıyorsa MCP
konfigürasyonundaki değer de eşleşmelidir; farklı bir otoritenin anahtarı
otomatik olarak güvenilir sayılmaz. Child için göreli state home mutlak
yola çevrilir; çalışma dizininin değişmesi başka anahtar seçtirmez.

## Host checkpoint ve kapanış

Yeni yerel MCP aracı:

```text
kali-tools_ledger_checkpoint(
  workdir="<run>",
  seal=false,
  spec_file="specs.json"
)
```

`seal=false`, bütünlüğü doğrulanmış eski HMAC kayıtları için geçiş kanıtını
hazırlar. `seal=true`, aynı işlemden sonra ilk dilimdeki bütün kapanış
kontrollerini host'ta çalıştırır. Spec dosyası koşu içinde olmalı ve hedefi
koşuyla eşleşmelidir. Eksik veya geçersiz validator kanıtı kapanışı engeller.
Başarı, `check_exit=0` ve `sealed=true` ile bildirilir.

Sandbox içinde imza üretilemez. Yerel `brain.py check --closure` bu durumda
host checkpoint aracını göstererek durur. Sonucun doğrulanması sandbox'ta
çalışmaya devam eder:

```bash
python3 scripts/brain.py attempts coverage --workdir <run> --vector <vector>
python3 scripts/brain.py handoff --workdir <run> --vector <vector>
python3 scripts/brain.py closure verify --workdir <run>
```

Araç `CCO_WORKDIR` dışındaki koşuları ve koşu dışındaki spec yollarını
reddeder. Ham payload imzalayan bir MCP aracı sunulmaz. TaskSpec'in son
işçi görevine aracı eklerken `tool_justification` olarak host kanıt custody
ve kapanış gerekçesi yazılır; çekirdek dışı araç kaydı kontrolü korunur.

## HMAC kayıtlarının geçişi

Eski kayıtlar ve artifact dosyaları yeniden yazılmaz. Host, HMAC imzasını
gerçek eski anahtarla doğruladıktan sonra içerik ve kanonik yol için ayrı
bir Ed25519 receipt üretir. Özgün validation ID ve içerik hash'i korunur.
Receipt olmadan sandbox eski HMAC kayıtlarını güvenilir saymaz; bozuk veya
başka otoritenin imzaladığı receipt ile özel anahtara geri dönüş yapılmaz.

Yeni Ed25519 kayıtlarından sonra tekrar HMAC kaydı eklemek reddedilir.
Bu yüzden mevcut MCP süreçleri yeni kodla yeniden başlatılmalı; ardından
eski koşu için checkpoint ve gerekirse yeni kapanış istenmelidir. Bu çalışma
mevcut canlı süreçleri yeniden başlatmaz veya gerçek koşuları otomatik
taşımaz. Eski kapanışlar yeni host checkpoint üzerinden yeniden üretilir.

Geçiş kanıtı, mevcut tarihsel içeriğin host tarafından doğrulandığını
gösterir. İmza tek başına bir HTTP sondasının gerçekten çalıştığı iddiası
değildir; yürütme kanıtı ve validator oracle kontrolleri ayrı kalır.

## Doğrulama

[Yeni regresyonlar](../tests/test_ledger_integrity.py) dört ayrı süreçle
eşzamanlı 32 kayıt, eşzamanlı okuma, başarısız commit, symlink lock,
başka koşuya replay, farklı CCO_HOME, sahte receipt, imza amacı karışması
ve anahtar kaybı durumlarını kapsar.

[Gerçek bubblewrap testleri](../tests/test_ledger_sandbox.py), host/MCP
üretimi yeni ve eski kanıtların sandbox'ta doğrulandığını; özel anahtarın
gizli, açık anahtarın değiştirilemez kaldığını; environment değişikliğiyle
imzalama yetkisinin geri gelmediğini sınar. Mevcut P0 regresyonları da
yeniden çalıştırılır.

Bu dilimin çıktıları `/tmp/cco-ledger-fix-20261029/` altındadır. İlk yeniden
üretimde 11 testin 9'u başarısızdı. Salt okunur lock ve göreli state home
için iki ek kırmızı test de düzeltmelerden önce yeniden üretildi.

| Son kontrol | Sonuç |
|---|---|
| Tam pytest, collection öncesinden izole CCO_HOME | **1.121 geçti; 0 hata, 0 başarısız, 0 atlanan** |
| Yeni bütünlük ve sandbox regresyonları | **23 geçti**, tam paket içinde |
| Gömülü loopback lab | **48/48** |
| Negatif kontrol | **6/6 UNCONFIRMED**, yanlış pozitif yok |
| Sentetik worker kontrolü | **16/16**, 2 eski claim kurtarıldı |
| Ruff / JS sözdizimi / bağımlılık kilidi / repo düzeni | Geçti |
| CI mypy / genişletilmiş imza-defter mypy | 2 / 4 kaynak dosyada hata yok |
| OpenCode debug config | Geçti; 16 MCP sunucusu yapılandırılmış |
| Governance | 0 high / 31 medium; önceki medium kayıtlar ayrıca incelenmeli |

- `full-final.xml`, `full-final.log`: son kaynak sürümünün tam test paketi.
- `sandbox.xml`, `sandbox.log`: gerçek bubblewrap dahil 56 testlik ara kontrol.
- `compatibility.xml`: collector doğrulaması ve fresh-process başlangıç kontrolü.
- `red.xml`, `read-only-red.log`: düzeltme öncesi yeniden üretimler.
- `quality-final.json`, `lab.log`, `negative.log`, `soak.log`: son kalite kontrolleri.
- `mypy-ci.log`, `mypy-final.log`, `opencode-config.json`: tip ve config kontrolleri.
- `completion.json`: sonuç özeti ve kaynak dosyalarının SHA256 parmak izleri.

İlk tam koşuda 1.120 test geçti; bir collector testi eski HMAC adını
beklediği için başarısızdı. Beklenti Ed25519 olarak güncellendi ve kaydın
gerçek `artifact_is_valid` doğrulaması eklendi. Çok süreçli testler `spawn`
ile yeni Python süreçleri kullanır. Son tam koşu bu sürümle geçti.

Test ortamı Python 3.13.14'tür; CI'ın Python 3.12 koşusu burada ayrıca
çalıştırılmadı. OpenCode config kontrolü model sağlayıcısına gerçek bir
istek veya canlı hedef kampanyası doğrulaması değildir. Negatif kontrol
bataryasının R09'da kayıtlı hata kabul sorunu bu dilimde değiştirilmedi.

UUID/opaque aday havuzu, bulgu tekilleştirmesi, paketleme ve diğer açık
maddeler bu dilimde kapatılmış sayılmaz.
