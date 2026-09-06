# J.A.R.V.I.S. Server Manager 1.2.0 — Türkçe + Wake-on-LAN

Bu sürüm geliştirme/inceleme amacıyla hazırlanmış temiz kaynak paketidir. `src-tauri/target` ve `node_modules` dahil değildir.

## Güç düğmesi

Gösterge panelindeki tek güç düğmesi sunucunun durumuna göre davranır:

- Çevrimdışıysa: UDP Wake-on-LAN magic packet gönderir.
- Çevrimiçiyse: SSH üzerinden `sudo -n systemctl poweroff` gönderir.
- Açılıştan sonra SSH portu salt-okunur TCP bağlantı denemesiyle izlenir ve hazır olduğunda SSH oturumu başlatılır.

BIOS'ta Wake-on-LAN'ın etkin olması gereklidir. MAC, yayın adresi ve UDP portu Ayarlar ekranından değiştirilebilir. Varsayılan yapılandırma bu sunucunun yerel ağ adreslemesine göre `192.168.1.255:9` ve daha önce gözlenen MAC için `9C:A2:F4:E1:FD:46` değerini kullanır; donanım MAC'ini doğrulamanız önerilir.

## Kurulum

1. PowerShell'i proje klasöründe açın.
2. `npm install` çalıştırın.
3. `npm run build` ile ön yüzü derleyin.
4. `npm run tauri build` ile MSI/NSIS paketleri üretin.

Rust/Tauri build ortamı mevcut sistemde doğrulanamadığı için bu pakette yalnızca kaynak ve statik yapı doğrulaması yapılmıştır.
