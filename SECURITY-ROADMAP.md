# Güvenlik Yol Haritası

## Öncelik 1 — Native SSH sınırı

Tauri renderer'dan gelen host/port/kullanıcı/anahtar değerleri native tarafta doğrulanmalı. Etkileşimli terminal için gerekli PTY korunurken bağlantı parametreleri tek bir doğrulama fonksiyonundan geçmeli.

## Öncelik 2 — Dosya sandbox'ı

`/home/<user>` metinsel kontrolü tek başına yeterli değil. Symlink ve mevcut path component'leri ayrıca doğrulanmalı. Özellikle okuma/yazma/yükleme hedeflerinin gerçek canonical path'i kullanıcı kökünün içinde kalmalı.

## Öncelik 3 — Security Score

Harici dinleyiciler ve risk sınıfları puana yansıtılmalı. `100/100` sonucu, MEDIUM/HIGH bulgu varken üretilememeli.

## Öncelik 4 — Ağ analizi

UFW ve listener parse işlemleri mümkün olduğunca yapılandırılmış çıktıya taşınmalı; port eşleşmeleri tam sayısal eşleşme ile yapılmalı.

## Öncelik 5 — Canlı sunucu doğrulaması

SSH üzerinden salt-okunur kontroller:

- `sshd -T`
- `ufw status verbose`
- `fail2ban-client status`
- `ss -lntup`
- systemd socket/service eşleşmeleri
- `/usr/local/sbin/jarvis-remediation --check`
- 9090 kaynağı

## Öncelik 6 — Dağıtım

Değişiklikler doğrulanıp yerel build tamamlandıktan sonra yeni installer oluşturulmalı. Canlı sunucudaki helper ancak ayrı bir kontrollü kurulum adımıyla güncellenmeli.
