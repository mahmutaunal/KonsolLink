# macOS oturum güvenilirliği düzeltmesi

8 Ekim 2026

## Uygulanan davranış

- Heartbeat komutu ve 15 saniyelik oturum süresi kaldırıldı. IPC sürümü 4 oldu;
  uygulama ile helper birlikte güncellenmelidir.
- Oturumun sahibi native uygulamanın açık Unix socket bağlantısıdır. Pencere
  arka planda kalınca oturum kapanmaz. Pencereyi kapatma düğmesi gizler;
  menü çubuğundaki Çıkış süreci sonlandırır ve helper temizleme yapar.
- Durum sorguları yalnızca görünür arayüz için, 5 saniyede bir yapılır. Arayüz
  tekrar görünür olduğunda güncel durum okunur. Bunlar oturum canlılığı şartı
  değildir. Kilitlenmiş bir arayüzün açık socket'i sağlıklı ağ motorunu durdurmaz.
- Helper etkin oturumda scoped IOKit idle-system-sleep assertion tutar.
  Ekran uyuyabilir. Stop, başlangıç hatası veya süreç çıkışı bildirimi bırakır.
  Kapak kapatılması, elle uyku ve fiziksel ağ kesintisi geçersiz kılınmaz.
- Süreli ağ sağlık kontrolleri ana servis döngüsünden ayrıldı. Bekleyen Discord
  probe'u sırasında IPC, DNS politika ACK'leri ve motor gözetimi devam eder.
  DNS politikası değişmişse eski probe sonucu kullanılmaz. Aynı oturum için
  eşzamanlı readiness probe'ları başlatılmaz. Stop eski görev sonuçlarını atar.
- Ağ motorunun stderr'i sürekli tüketilir; bellekte yalnızca son 8 KiB kalır.
  Motor hatasında gösterilen ayrıntı da sınırlıdır.
- Temizleme bağımsız adımlarda devam eder, başarısız adımlar journal'da kalır.
  Motor durmamışsa forwarding geri alınmaz. Yeni başlangıç önce kalan journal'ı
  temizler; başarısız temizlemeyi başarılı oturum olarak göstermez. Servis hata
  nedeniyle çıkarsa mevcut launchd gözetimi yeniden açıp journal'ı kurtarır.
- Son operasyonel hata özel journal dizinindeki sınırlı last-failure.json
  kaydında tutulur; root yetkisiyle helper journal-status komutundan okunabilir.
  Paket içeriği ve DNS geçmişi kaydedilmez.

## Doğrulama

- cargo test --workspace --locked: 99 test geçti, atlanan test yok.
- cargo clippy --workspace --all-targets --locked -- -D warnings: geçti.
- cargo fmt --all --check ve git diff --check: geçti.
- npm --prefix apps/desktop run build: geçti.
- scripts/verify_gateway_policy.py: geçti.
- Yeni testler: yoğun stderr tüketimi ve tampon sınırı, saat/arayüz heartbeat'i
  olmadan socket sahipliği, bağımsız temizlemenin hata sonrası devamı, kalıcı
  sınırlı hata kaydı, bekleyen probe'un bloklamaması ve eski DNS politika
  sonucunun kullanılmaması.
- Fiziksel konsol/ağ uzun süreli testi yapılmadı; kullanıcı tarafından yapılacak.
- verify_release_source.py çalıştırılamadı: bu çalışma ağacında
  .github/workflows/release.yml bulunmuyor. Bu, yerel derleme ve testleri
  engellemedi; CI yayın sözleşmesi kontrolü doğrulanmış sayılmamalıdır.

## Yerel paket

Paketler target/release-packages/macos-lifecycle dizininde hazırlanır. Önceki
macos dizinindeki paketler korunur. Paket Apple Silicon içindir ve yerel imzasız
RC olarak hazırlanır; Developer ID / Apple notarization uygulanmaz. Kurulu
uygulama ve sistem ayarları bu çalışma sırasında değiştirilmez.
