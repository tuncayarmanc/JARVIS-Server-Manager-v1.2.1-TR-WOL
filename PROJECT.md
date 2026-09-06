# J.A.R.V.I.S. Server Manager — v1.2.1 Proje Planı

## Amaç

J.A.R.V.I.S. Server Manager'ı güvenli, Türkçe ve masaüstünden sunucu güç yönetimi yapabilen bir yönetim uygulamasına dönüştürmek.

## v1.2.1 kapsamında

- Tam Türkçe kullanıcı arayüzü ve Türkçe durum/uyarı metinleri.
- Wake-on-LAN ile kapalı Ubuntu sunucusunu açma.
- SSH üzerinden güvenli kapanış ile açık sunucuyu kapatma.
- Sunucunun SSH portuna salt-okunur TCP erişilebilirlik kontrolü.
- Açılış sonrası otomatik erişilebilirlik bekleme ve SSH bağlantısı.
- Güç ayarları: MAC, broadcast adresi ve UDP portu.
- Native SSH giriş sınırları için host/port/kullanıcı/anahtar doğrulaması.
- Güvenlik skorunun harici dinleyici risklerini puana yansıtması.

## Sonraki güvenlik işleri

1. Dosya yöneticisinde symlink sınırının gerçek filesystem seviyesinde doğrulanması.
2. `start_log_stream`, `start_monitor_stream` ve diğer native SSH yollarının ortak bir doğrulama katmanına alınması.
3. Listener/UFW analizinin serbest metin regex yerine daha deterministik/structured çıktıya geçirilmesi.
4. Remediation backup retention ve güvenli temizlik politikası.
5. Canlı Ubuntu sunucusunda helper sürümü, UFW, Fail2Ban, SSH politikası ve 9090 listener'ının salt-okunur doğrulanması.
6. Rust/Cargo audit ortamının CI'da etkinleştirilmesi.

## Güç düğmesi davranışı

- Sunucu çevrimdışı: Wake-on-LAN magic packet gönderilir.
- Sunucu çevrimiçi: `sudo -n systemctl poweroff` gönderilir.
- Açılış: TCP portu erişilebilir olana kadar sınırlı süre beklenir; ardından SSH bağlantısı başlatılır.
- MAC adresi yerel ayarlarda tutulur ve ağ üzerinden özel anahtar aktarılmaz.

## Güvenlik notu

Wake-on-LAN yalnızca açma içindir. Kapatma, mevcut SSH oturumundaki yetkili sudo komutuyla gerçekleştirilir. Canlı sunucuya otomatik değişiklik bu paket tarafından yapılmaz; önce salt-okunur doğrulama yapılmalıdır.
