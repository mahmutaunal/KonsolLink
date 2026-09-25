# KonsolLink — mevcut durum ve 1.0 yol haritası

Tarih: 20 Eylül 2026. Bu belge kaynak ağacının tamamı incelenerek hazırlanmıştır. Aşamalar önerilen işlerdir; tamamlanmış implementation veya fiziksel doğrulama anlamına gelmez.

**P0 güncellemesi:** Kod ve yerel macOS doğrulaması tamamlandı. Aşağıdaki mevcut durum tablosu ilk incelemenin tarihsel kaydıdır; P0 ile giderilen sorunlar ve başarılı kontroller [P0 sonuç raporunda](P0_BUILD_FOUNDATION.md) listelenmiştir. GitHub CI çalıştırma kanıtı henüz yoktur; bu klasörde Git remote bulunmuyor. P0 kaydıdır; güncel adım aşağıdaki M0-B teslimatıdır.

**M0-A güncellemesi:** [Salt okunur preflight](M0_PREFLIGHT.md) uygulandı ve yerel Mac'te çalıştırıldı. [ADR-004](ADR-004-MACOS-M0.md) mevcut PF/divert varsayımını düzeltiyor. Tanılama teslimatı tamamlandı; M0-B canlı gateway için PF anchor sahipliği, yetki ayrımı ve UDP stratejisi kapıları açık. M0'nun bütünü ve fiziksel test paketi henüz tamamlanmadı.

**M0-B1 güncellemesi:** [Kalıcı journal ve recovery altyapısı](M0_HELPER_JOURNAL.md) uygulandı. Singleton/dosya güvenliği ve 33 subprocess sonlandırma senaryosu yerelde doğrulandı. Henüz authenticated IPC, root servis kurulumu, watchdog veya canlı PF/sysctl backend bağlantısı yok; M0-B tamamlandı sayılmaz.

**M0-B güncellemesi:** [Gateway/helper uygulaması](M0_IMPLEMENTATION.md), UI/CLI
ile authenticated IPC, launchd developer kurulumu, lease/watchdog, boot-aware
recovery ve cihaz testi paketi tamamlandı. [İlk fiziksel Xbox denemesinde](M0_TEST_RESULTS.md)
internet, oyun/indirme ve cleanup geçti; Mac SNAT altında NAT `Açık → Sıkı`
geriledi. SNAT kabul edilmedi ve güncel aday router'ın NAT/UPnP sahibi kaldığı
route-only moda çevrildi. Tekrar testinde internet, Xbox ağı ve oyun/indirme
geçti, NAT `Açık → Açık` kaldı ve hata sonrası otomatik recovery temizlendi.
**M0 kabul edildi; sıradaki aşama M1'dir.** UDP bypass çözümü M1/M2 kapısıdır.

## Mevcut durum

Proje `0.1.0-source` seviyesinde. Rust core + Tauri + ayrı helper mimarisi korunabilir. Ürünün asıl ağ işlevleri henüz uygulanmamıştır.

| Alan | Kaynakta bulunan | Eksik / sorun |
| --- | --- | --- |
| Core | Konsol modeli, durum enum'u, domain eşleştirme, iki unit test | Gerçek orkestrasyon, hata/iptal/recovery geçişleri; aktifken konsol değişimi koruması |
| Platform | `NetworkBackend` trait ve `DryRunBackend` | macOS/Windows/Linux gerçek backend'leri; gerçek sağlık kontrolü |
| Helper | CLI dry-run akışı | Yetkili servis, authenticated IPC, kalıcı journal, watchdog, rollback; hatalar `expect` ile sonlanıyor |
| Desktop | Tauri tray ve HTML ekran | Keşif, helper bağlantısı, gerçek ON/OFF ve doğrulanmış durum göstergeleri |
| Discord | Rust içinde statik profil ve ayrı TOML | TOML yükleme yok; iki kopya ayrışabilir. DNS, TTL, flow tracking ve voice endpoint takibi yok |
| Dağıtım | Rust CI ve kaynak dosyası kontrolü | Desktop CI, paketleme, imza, SBOM, dependency audit, installer testleri |

Bu klasörde `.git` yok; commit/geçmiş/remote durumu doğrulanamadı. İlk incelemede dependency lockfile'ları da yoktu; doğrulama sırasında Cargo kök `Cargo.lock` dosyasını üretti.

### Çalıştırılan kontroller

- `python3 scripts/verify_source.py`: geçti; yalnızca kaynak yapısını kontrol eder.
- `cargo fmt --check`: başarısız, mevcut biçimlendirme farkları var.
- `cargo test --workspace --offline` ve `cargo clippy --workspace --all-targets --offline -- -D warnings`: Xcode lisansı kabul edilmediğinden linker aşamasında durdu. Testler geçti denemez.
- Tauri manifest'i ile `cargo metadata`: paket üst workspace'e ait olduğunu düşünüyor fakat member/exclude olarak tanımlanmamış; başarısız.
- Frontend/Tauri uygulama build'i ve fiziksel ağ testleri yapılmadı.
- Yerel işletim sistemi `sw_vers` çıktısı: macOS 27.0, build 26A428. Bu tek makine desteklenen sürüm matrisi yerine geçmez.

## Önce karara bağlanacak sınırlar

1. **İlk cihaz PS5.** PS4/PS5 ortak cihaz abstraction'ı korunabilir; PS4'e yerleşik Discord Voice desteği vaat edilemez. Release checklist'teki PS4 voice beklentisi düzeltilmeli. [Discord resmi açıklaması](https://support.discord.com/hc/en-us/articles/4419534960919-Discord-and-PlayStation-Network-Connection-FAQ).
2. **macOS PF/divert varsayımı doğrulanmış değil.** Upstream macOS dokümanı ciddi mekanizma sınırlamaları ve Internet Sharing uyumsuzluğu bildiriyor. `dvtws` hazır çözüm kabul edilmemeli; seçilecek yöntem hedef OS üzerinde doğrulanmalı. [zapret macOS/BSD dokümanı](https://github.com/bol-van/zapret/blob/master/docs/bsd.en.md).
3. **Direct trafik de Mac üzerinden geçebilir.** Konsolun default gateway'i Mac olduğunda oyun trafiği kernel forwarding yolunda kalır ama ek Wi-Fi aktarımı oluşur. Bu nedenle <= %1 / <1 ms hedefleri mevcut topolojide henüz kanıtlanmış değildir. Başarısız ölçüm ürün/topoloji kararını yeniden açar.
4. **OFF ile eski topolojiye dönüş aynı şey değildir.** Konsolda gateway elle Mac'e ayarlanmışsa host kurallarını temizlemek konsol ayarını router'a döndürmez. Kontrollü OFF, helper crash ve Mac'in tamamen kapanması için ayrı bağlantı davranışları ve compatibility mode yönergeleri tanımlanmalı.
5. **Discord IP'si tek başına yeterli kanıt değildir.** Paylaşılan adreslerde başka servis akışları olabilir. Belirsiz akış bypass'a alınmamalı; bu nedenle oluşabilecek Discord erişim eksikliği açık raporlanmalı.

## Aşamalar ve bitiş koşulları

### P0 — Derlenebilir ve ölçülebilir temel

İşler: Tauri workspace üyeliğini düzelt; `tauri::Manager` import gereksinimi dahil desktop derleme sorunlarını gider; formatı düzelt; Rust/frontend lockfile ve toolchain politikasını belirle; desktop build'ini CI'a ekle. TOML'i tek servis profili kaynağı yap. UI'da ölçülmeden gösterilen “Doğrudan” gibi durumları gerçek sağlık verisine bağla. Xcode lisansını proje sahibi inceleyip kabul etmeli.

Bitiş: fmt, clippy, core/helper testleri, TypeScript ve Tauri build temiz; dry-run açıkça dry-run olarak gösterilir. CI'ın çalıştığı ayrıca doğrulanır.

### M0-A — macOS uygulanabilirlik ve ağ sözleşmesi

İşler: Salt okunur preflight ile OS, arayüz, subnet, rota, IPv6, PF ve mevcut paylaşım durumunu çıkar. Mac Wi-Fi + PS5 Ethernet + Zyxel topolojisinde aynı arayüzden forwarding, dönüş yolu, gerekirse NAT ve ICMP redirect davranışını incele. NAT'ın PSN/oyun bağlantılarına etkisini test planına al. TCP interception ve UDP voice için uygulanabilir mekanizmaları ayrı değerlendir; sadece kontrol trafiğine bypass uygulanmasının voice için yeterli olup olmadığını ölçülecek hipotez olarak kaydet.

Çıktı: Desteklenen OS/topoloji matrisi ve yeni ADR. Uygun seçici yöntem yoksa gereksinimleri sessizce gevşetmeden bu aşamada teknik engeli raporla; tüm trafiği userspace'e taşıyarak geçme.

Bitiş: Seçilen konsola sınırlı gateway ve seçici interception tasarımı, rollback ve performans ölçüm yöntemi somutlaştırılmıştır. Bu kapı geçilmeden engine entegrasyonuna başlanmaz.

### M0-B — Güvenli helper ve gerçek gateway

İşler: Yapılandırılmış, sürümlü ve istemci kimliği doğrulanan yerel IPC; singleton; input doğrulama; timeout/iptal; root sahipli kalıcı işlem günlüğü; her değişiklikten önce kayıt; idempotent geri alma. macOS helper kurulumu için SMAppService/launchd yaklaşımını hedef sürümlerde doğrula. PF anchor/table/state sahipliğini ayır; mevcut kullanıcı ve başka uygulama kurallarını koru. Global forwarding ayarındaki eşzamanlı değişiklikleri körlemesine geri yazma. Crash sonrası supervisor ve başlangıç recovery'si ekle. [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

İlk gerçek backend yalnızca seçilen konsol için gateway'i açar; henüz Discord bypass başarısı iddia etmez. IPv6 desteklenmiyorsa sessiz kaçış yerine açık destek durumu gösterilir.

Bitiş: Otomatik fault injection ile her mutasyon noktasındaki hata ve tekrar recovery testleri geçer; host üzerindeki değişikliklerin geri alındığı doğrulanır.

**Fiziksel test sonucu:** Kullanıcıya üretilmiş build/komut, tespit edilmiş gerçek ağ değerleriyle konsol ayarları, eski ayarlara dönüş adımları ve payload içermeyen diagnostics çıktısı verildi. İlk SNAT sonucu reddedildi; [route-only tekrar testi](M0_TEST_RESULTS.md) Xbox ağı/internet, oyun/indirme, Açık NAT ve güvenli recovery kriterlerini geçti.

### M1 — Discord sınıflandırması

Bağımlılık: M0 fiziksel testinin geçmesi.

**M1-A güncellemesi:** [Fail-closed sınıflandırıcı çekirdeği](M1_CLASSIFIER.md)
uygulandı. Seçili konsola bağlı DNS transaction/istemci-port eşleşmesi,
CNAME/en kısa TTL hedef kümesi, eşleşen görünür SNI, kontrol akışına bağlı UDP
adayı, ters 5-tuple takibi ve yalnız sayısal diagnostics fixture testleriyle
doğrulandı. Canlı adaptör ve helper entegrasyonu sonraki M1 alt adımlarındadır.

**M1-B güncellemesi:** [macOS salt okunur gözlem adaptörü](M1_OBSERVER.md)
uygulandı. Konsol IPv4'üne kernel seviyesinde sınırlı, promiscuous olmayan BPF
kaynağı; bounded Ethernet/IPv4/UDP/TCP, DNS ve görünür ClientHello SNI parser'ı;
capture received/drop sayaçları ve bozuk/kesilmiş wire fixture testleri eklendi.
Helper yaşam döngüsü bağlantısı ve fiziksel observation testi M1-C'yi bekler.

**M1-C güncellemesi:** [Helper/IPC/UI entegrasyonu ve fiziksel test paketi](M1_INTEGRATION.md)
hazırdır. Observer gateway lease'iyle açılıp kapanır; capture hatasında journal
rollback ile güvenli OFF olur. Protokol yalnız aggregate sayaçlar döndürür ve
teknik bilgisi olmayan kullanıcı için çift tıklanabilir test sihirbazı vardır.
**M1 fiziksel Xbox gözlem sonucunu bekliyor.**

**M1-D güncellemesi:** [Shadow qualification ve M2 seçim kapısı](M1_SHADOW_GATE.md)
uygulandı. Capture drop, yetersiz bağımsız örnek veya herhangi bir yanlış
pozitif/negatif proof üretimini engeller. Proof olsa bile yalnız Discord TCP
kontrol adayı M2 proxy adayıdır; UDP medya direct kalır. Fiziksel test, kullanıcı
tercihiyle daha olgun birleşik pakete ertelendi. [ADR-005](ADR-005-MACOS-INTERCEPTION.md)
macOS motor kararını ve supply-chain kapılarını kaydeder.

İşler: Konsola bağlı DNS observation, TTL/CNAME/A/AAAA takibi, süreli destination set ve connection tracking; görünür olduğu yerde TLS hostname doğrulaması. Şifreli DNS, ECH, önbellekteki adresler, paylaşılan IP ve endpoint değişimi açık senaryolardır. TLS çözme veya credential toplama yapılmaz. DNS'in görülemediği akış için port aralığına dayalı fallback yoktur. UDP voice sınıflandırması port aralığıyla değil gözlenen Discord kanıtıyla ilişkilendirilir. Sınıflandırma verileri kısa ömürlü tutulur; browsing history loglanmaz.

Bitiş: Önce interception olmadan gözlem modu; sentetik fixture'lar ve bağımsız etiketlenmiş cihaz akışlarıyla yanlış pozitif/negatif ölçümü. Sadece classifier'ın kendi etiketleriyle doğruluk kanıtlanmaz. Engine'e girecek non-Discord akış sayısı sıfır olmalı.

### M2 — macOS + konsol Discord uçtan uca

İşler: M0'da seçilen engine/adapter için upstream commit, hash, lisans ve dağıtım incelemesi; notices güncellemesi; helper kontrollü süreç yaşam döngüsü. Yalnızca konsol + doğrulanmış Discord flow kapsamına interception. TCP kontrol ve çift yönlü UDP ses ayrı test edilir; çalışan direct UDP gereksiz yere engine'e alınmaz. Engine ölümü durumunda interception kaldırma ve güvenli bağlantı politikası uygulanır.

**M2-A güncellemesi:** Legacy zapret `tpws` v72.13 tam commit, resmi arşiv ve
MIT lisans hash'leriyle sabitlendi. Hazır upstream binary kullanılmadan macOS
27/Apple Silicon üzerinde iki özdeş kaynak derlemesi alındı; universal mimari,
sistem kitaplıkları ve dry-run davranışı doğrulandı. Binary projeye eklenmedi ve
dağıtım için onaylanmadı. Ayrıntılar
[M2 engine nitelendirme kaydındadır](M2_ENGINE_QUALIFICATION.md). Sıradaki adım
sahte engine ile helper process yaşam döngüsü ve crash cleanup'tır.

**M2-B güncellemesi:** Helper journal şeması geriye uyumlu engine kaydıyla
genişletildi. Yalnız sabit engine enum/hash/loopback port kabul ediliyor; süreç
PID + doğum kimliğiyle izleniyor. Askıda spawn → kalıcı kimlik → resume → health
sırası ile watchdog rollback'ı sahte engine üzerinde doğrulandı. Stop hatası
kanıtı koruyor ve recovery retry ediyor; engine forwarding/PF geri alınmadan
önce duruyor. Gerçek binary hâlâ başlatılmıyor. Ayrıntılar
[M2-B yaşam döngüsü kaydındadır](M2_ENGINE_LIFECYCLE.md). Sıradaki adım macOS
sabit-path/hash process adapter'ıdır.

**M2-C güncellemesi:** macOS adapter sabit root-owned engine yolu, descriptor
üzerinden SHA-256, kontrol pipe'ında bekleyen child-wrapper, PID + process doğum
kimliği, image-path health ve kimlik kontrollü TERM/KILL cleanup ile uygulandı.
Path veya argüman IPC'den alınmıyor; TCP-only loopback argümanları bundled
Discord profiliyle üretiliyor. Gerçek artifact kurulmadığı ve PF redirect bağlı
olmadığı için ürün akışı engine başlatmıyor. Ayrıntılar
[M2-C process adapter kaydındadır](M2_MACOS_PROCESS_ADAPTER.md). Sıradaki adım
root-owned geliştirici artifact kurulum/kaldırma ve kısa gerçek-process fixture
testidir.

**M2-D güncellemesi:** Mevcut M0 installer'a ayrı `install-with-engine` modu
eklendi. Kaynak/hedef hash, root sahipliği, sabit mode/link/path, version ve
üretim argümanlarıyla dry-run geçmeden launchd açılmıyor; hata ve uninstall
yalnız sabit dosyaları temizliyor, recovery journal'ını koruyor. Aynı kaynak
artifact loopback SOCKS fixture'da gerçek listener ve SIGTERM kapanışıyla geçti.
Root kurulum yapılmadı, PF/ağ ayarı değişmedi. Ayrıntılar
[M2-D paketleme kaydındadır](M2_ENGINE_PACKAGING.md). Sıradaki adım qualified
Discord TCP destination setine sınırlı journal-backed PF `rdr`dır.

**M2-E güncellemesi:** M1 shadow proof + DNS/SNI ile doğrulanmış kısa ömürlü
IPv4 hedefler, en fazla 64 ayrı `/32` PF kuralına çevriliyor. Kapsam yalnız
seçili konsol ve TCP/443; redirect sabit loopback engine portudur. Journal şema
3, interception'ı engine'den önce kaldırır; expiry, engine veya kernel kural
sağlık hatası tam rollback yapar. Root PF ve fiziksel konsol aktivasyonu henüz
yapılmadı. Ayrıntılar [M2-E kaydındadır](M2_TCP_INTERCEPTION.md). Sıradaki adım
observer TTL yenilemesi, engine ve redirect yaşam döngüsünü dormant runtime
controller'da birleştirmektir.

**M2-F güncellemesi:** BPF observer artık opaque shadow proof ile qualified hedef
snapshot'ı verebiliyor. Dormant runtime controller capture sağlığı, monotonic TTL,
engine ve PF health'i birlikte reconcile ediyor. Aynı hedefte yalnız journal
expiry yenileniyor; hedef değişiminde aynı anchor atomik güncelleniyor; kanıt
kaybında redirect + engine kapanıp gateway gözlem modunda kalıyor. Engine/PF
arızası tam rollback yapıyor. IPC/UI aktivasyonu ve root PF deneyi yapılmadı.
Ayrıntılar [M2-F kaydındadır](M2_RUNTIME_CONTROLLER.md).

**M2-G uygulama adayı:** Version 3 IPC, kullanıcı etiketli iki normal trafik ve
bir Discord kontrol örneğini doğrudan shadow qualification kapısına bağlar.
Başarılı proof sonrası runtime, canlı TTL hedefleri için engine ve kesin `/32`
PF kurallarını otomatik açar; kanıt/capture/engine/PF kaybı fail-safe kapanır.
PF başlangıç durumu journal'a alınır ve yalnız KonsolLink'in açtığı PF kapanışta
geri kapatılır.
Tauri arayüzü teknik sayaç istemeden bu akışı yönlendirir. Resmi sabitlenmiş
kaynaktan üretilen motor ve tek dosyalık Xbox kabul sihirbazı hazırdır.
[M2 kabul testi](M2_ACCEPTANCE_TEST.md) kanal katılımı, çift yönlü ses, yeniden
bağlanma, oyun + ses, indirme + ses, NAT ve cleanup sonucunu kaydeder. Kod ve
paket kontrolleri tamamlandı; fiziksel sonuç gelmeden M2 kabul edilmiş sayılmaz.

**M2-H mimari düzeltmesi:** Son Xbox testi aynı-subnet route-only ve manuel
qualification yaklaşımını reddetti. Çalışan Windows referansındaki temel bileşen
olan ayrı `172.24.0.0/16` sanal ağ + go-pcap2socks geçidi macOS'a taşındı. UDP ve
varsayılan trafik doğrudan host socketlerinden çıkar. macOS'ta PS5'e verilecek
gerçek Discord DNS cevabındaki IP/TTL özel IPC ile helper'a iletilir ve PF
kurulumu onaylanmadan cevap konsola bırakılmaz. Yalnız bu Discord TCP/443
hedefleri journal-backed gateway-UID PF route + redirect ile
root transparent tpws'e girer ve DPI değişikliği sabit Discord host listesine
uygulanır. Kernel forwarding, NAT, VPN ve manuel “Güvenli tanıma” kaldırıldı.
İki motor tek journal süreç grubunda hash/config doğrulaması ve health rollback
ile yönetilir; REST ve WebSocket readiness onaylanmış kesin IP'lere sabitlenir
ve ikisi geçmeden açık duruma gelmez. Patched
upstream ve KonsolLink otomatik testleri geçti; fiziksel Xbox başarısı henüz
yeniden ölçülmedi. Ayrıntılar [M2 fiziksel bulgu raporundadır](M2_PHYSICAL_FINDINGS.md).

Bitiş: Desteklenen gerçek konsolda kanal katılımı, mikrofon uplink, ses downlink,
yeniden bağlanma, oyun + voice ve indirme + voice fiziksel olarak geçer. Wi-Fi,
sleep/wake ve router restart davranışı izleyen dayanıklılık matrisi içinde
doğrulanır. Sadece TCP başarısı milestone'u tamamlamaz.

### M3 — Performans ve macOS kullanılabilir alpha

**M3 uygulaması tamamlandı:** Token korumalı yerel Xbox tarayıcı benchmark'ı,
dokuz örnekli baseline/etkin karşılaştırması, tam payload bütünlük kontrolü ve
fail-closed eşik değerlendiricisi eklendi. Eşikler throughput kaybı en fazla %1
ve median ek gecikme 1 ms altında olacak şekilde kodlandı; motor CPU/RSS değeri
ayrıca raporlanıyor. Gateway policy tek hash'li JSON kaynağına taşındı ve
UDP/TCP direct çıkışı, macOS Discord TCP/443 transparent interception'ı ve
capture-off kapsamı kaynak doğrulamasına bağlandı.
Tam test+build çalıştıran macOS alpha paketleyicisi app, helper, motorlar,
lisanslar, upstream patch ve SHA-256 manifestli taşınabilir ZIP üretiyor.
Uyku/lease, topoloji kaybı, child ölümü ve userspace modunun forwarding/NAT'e
dokunmaması otomatik test kapsamındadır. Ayrıntılar
[M3 performans ve alpha kaydındadır](M3_PERFORMANCE_ALPHA.md). Fiziksel eşikler
uygulanmıştır fakat ertelenen tek nihai cihaz koşusu olmadan geçmiş sayılmaz.

İşler: Aynı koşullarda iki ölçüm: doğrudan router baseline ve birleşik yerel
gateway/bypass etkin. Güncel güvenlik modeli gateway'i bypass motorundan ayrı
çalıştırmadığı için kullanıcıya yapay bir üçüncü mod sunulmaz. Tekrarlı ölçüm,
referans donanım, örnek sayısı ve dağılım raporlanır; kontrollü LAN aktarımı
konsolun kendi hız göstergesinin yerini alır.

Bitiş: Doğrudan baseline'a karşı non-Discord throughput farkı <= %1 ve median ek
yerel latency <1 ms; non-Discord DPI değişikliği = 0. Userspace geçitten geçen
doğrudan akışlar ayrıca sayılır; CPU/RAM ve uzun oturum sonuçları kaydedilir.
Wi-Fi topolojisi hedefi geçemiyorsa destek iddiası verilmez.

UX: Keşif sinyalleri kullanıcı seçimiyle doğrulanır; güvenilmez zero-config yerine açıklamalı compatibility mode. UI yalnızca helper healthcheck sonrası AÇIK gösterir. İmzalı/notarized macOS paketi, temiz makine install/uninstall, güncelleme ve recovery testleri alpha çıkış koşuludur.

### M4 — Windows, ardından Linux

**M4 uygulaması tamamlandı:** Ortak kapalı deployment contract, Windows
LocalSystem SCM supervisor + kill-on-close Job Object, sabit Discord hostlistli
GoodbyeDPI/WinDivert, Npcap önkoşulu, hash/ACL kontrollü PowerShell kurucu ve
paketleyici eklendi. Linux'ta aynı tpws + userspace gateway modelini çalıştıran
hash/sahiplik kontrollü supervisor, hardened systemd unit, tek-servis polkit
yetkisi, kurucu ve paketleyici eklendi. Tauri iki platformda yalnız sabit hizmeti
start/stop/query eder. Native hedef CI işleri patched gateway'i kaynaktan derler,
servis/policy testlerini çalıştırır ve iki paketi üretir. Kernel forwarding, NAT,
firewall ve VPN hiçbir hedefin runtime yolunda yoktur. Ayrıntılar
[M4 kaydındadır](M4_CROSS_PLATFORM.md). Native VM + fiziksel konsol sonucu M5'in
birleşik kabul matrisine bırakılmıştır.

### M5 — 1.0 release qualification

**M5 geliştirmesi tamamlandı:** Birinci taraf sürümler 1.0.0'a taşındı;
CycloneDX SBOM, eksiksiz lisans envanteri, RustSec/npm denetimi, karşılık gelen
GPL kaynak paketi, kapalı checksum manifestleri ve provenance attestations
eklendi. macOS PKG imzalama/notarization, Windows Authenticode NSIS/runtime ve
Linux DEB/runtime işleri tek release workflow'unda fail-closed çalışır. Tek
birleşik son kabul aracı baseline/etkin performansla Discord/oyun/video/NAT/
reconnect/OFF kontrollerini kaydeder. Stable yayın, gerçek PS5/Xbox, host OS,
Türkiye ISS ve IP modu kanıt matrisi `passed` olmadan veya imza sırları eksikken
çalışmaz. Ayrıntılar [M5 kaydındadır](M5_RELEASE.md).

## Öncelik ve sorumluluk

Sıra: **P0 → M0-A → M0-B → ilk fiziksel test → M1 → M2 → M3 → M4 → M5**.

Geliştirme tarafı kod, otomatik test, diagnostics, paket ve adım adım cihaz testini hazırlar. Proje sahibi Xcode lisansı/dağıtım hesapları ve fiziksel PS5/Xbox/ağ testlerini sağlar. İlk cihaz testinden önce uzun vadeli teslim tarihi güvenilir değildir; M0 ve M2 sonuçlarından sonra takvim yeniden tahmin edilir. En yakın somut teslimat güvenli macOS gateway ve geri alma test paketidir.
