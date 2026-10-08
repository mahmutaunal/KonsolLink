# Windows hizmet güvenilirliği

Mevcut Windows SCM hizmeti, Job Object, GoodbyeDPI ve go-pcap2socks yönlendirmesi korunur. GUI heartbeat'i veya güç/uyku ayarı eklenmez.

## Sağlık ve toparlanma

- İlk kontrol başlangıçtan sonra, sonraki kontroller tamamlandıktan 45 saniye sonra yapılır. Aynı anda yalnızca bir kontrol çalışır; 10 saniyelik süre sınırı ve stop iptali vardır. SCM komutları ve motor çıkış gözetimi bloklanmaz.
- Gateway kontrol noktası yalnızca 127.0.0.1 üzerinde rastgele bir portta açılır. Her çalıştırmada üretilen token ile doğrulanır; hizmet yanıt şeması, boyutu ve beklenen gateway PID'sini kontrol eder. Token dosyaya veya loga yazılmaz.
- Yakalama kanalının kapanması, seçilen arayüzün durumu/MAC/IPv4 adresleri ve gateway'in mevcut proxy çıkışı üzerinden TLS doğrulamalı Discord API/internet erişimi kontrol edilir. Geçici IPv6 adres değişimleri IPv4 oturumunu etkilemez.
- İnternet/Discord erişim hataları arayüzde uyarı olarak gösterilir, yeniden başlatma tetiklemez. Yerel motor kontrolünün art arda üç kez başarısız olması hizmeti hata koduyla kapatır. Motorun çıkması anında aynı kapanma yolunu kullanır.
- Job Object kapatılır ve çocuk süreçlerin çıkışı beklenir. SCM kurtarma ayarı kontrollü hata çıkışlarını kapsar: 3 ve 10 saniye sonra iki yeniden başlatma, sonra durma; hata sayacı 24 saat sonra sıfırlanır. Kullanıcının Durdur komutu başarılı kapanma bildirir ve yeniden başlatma tetiklemez.
- Arayüz çalışıyor bilgisine ek olarak güncel hizmet PID'sine bağlı sağlık kaydını okur. Eski/eksik kayıt sağlıklı olarak gösterilmez. Uyarı sırasında Durdur düğmesi kullanılabilir.

Bu kontroller konsoldan geçen her paketi veya Npcap'in açık kalıp hiç ilerlemeyen tüm olası kilitlenmelerini kanıtlamaz. Trafik yokluğu arıza sayılmaz. Konsolun gerçek trafiği ve uzun süreli kararlılık fiziksel testle doğrulanmalıdır.

## Tanılama

- Her motorun stdout/stderr'i sürekli tüketilir; RAM'de son 8 KiB tutulur.
- Kurulum dizinindeki `diagnostics/status.json` atomik olarak güncellenir; olay kayıtları `events.jsonl` ve `events.jsonl.1` dosyalarında en fazla 64 KiB olacak şekilde döndürülür. Başlangıç, hata, toparlanma ve durma sonuçları tutulur.
- Normal trafik/cihaz katılım mesajları diske aktarılmaz. Motor çıktısından yalnızca hata satırları sınırlı olarak alınır; IPv4/MAC adresleri gizlenir. Paket yakalama açılmaz. Hizmet hataları ayrıca Windows Application Event Log'daki KonsolLink kaynağına gönderilir.
- Dizin kurulumun mevcut SYSTEM/Administrators yazma, Users okuma ACL'sini devralır. Yeni ağ izinleri veya sürücü kurulumu yapılmaz.

## GitHub Actions

Mevcut `.github/workflows/windows-installer.yml` kullanılır. Sabit gateway commit'ine mevcut ortak yama, ardından Windows sağlık yaması uygulanır. Gateway testleri Windows runner üzerinde çalışır; paketleme adımı hizmet testlerini çalıştırır. Gateway sürüm komutu ve `health_schema: 1` manifest alanı eski motorun yeni hizmetle paketlenmesini engeller. NSIS `.exe` mevcut artifact adında üretilir. Mevcut manuel workflow tetikleme biçimi korunur.

## Yerel doğrulama

- Servisin taşınabilir manifest, sağlık politikası, yanıt kimliği/boyutu, iptal, yoğun stdout/stderr, eşzamanlı tampon sınırı, log rotasyonu ve adres gizleme testleri macOS üzerinde race detector ile çalıştırıldı.
- Windows hizmeti ve yamalı gateway x64 hedefi için derlendi; Windows gateway testleri derleme kontrolünden geçti.
- Windows arayüzünün hizmet/sağlık modülü x64 hedefi için bağımsız olarak type-check edildi. Tam Windows Tauri/NSIS derlemesi GitHub Actions'a bırakıldı.
- Fiziksel konsol testi ve gerçek Windows SCM/Npcap çalıştırma testi yerelde yapılmadı. Actions çalıştırılmadı, commit/push yapılmadı.
