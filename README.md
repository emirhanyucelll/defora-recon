# Defora Recon
Web sitelerini analiz etmek, kullanılan teknolojileri tespit etmek ve olası güvenlik açıklarını/sızıntıları bulmak için hazırladığım bir araç.

---

## 🇹🇷 Türkçe Açıklama

### 🚀 Hızlı Başlangıç (Kullanıcılar İçin)
Eklentiyi hemen kullanmaya başlamak için:
1. Bu projeyi bilgisayarınıza indirin.
2. Chrome tarayıcınızda `chrome://extensions/` adresine gidin.
3. Sağ üstteki **Geliştirici Modu**'nu açın.
4. **Paketlenmemiş öğe yükle** butonuna basarak bu klasörü seçin.
*Hepsi bu kadar! Eklenti, güncel zafiyet verilerini otomatik olarak benim sunucumdan çekecektir.*

### 🛠️ Neler Yapıyor?
- **Web Odaklı Analiz:** Sadece web teknolojilerini (kütüphane, sunucu, veritabanı vb.) tarar. Windows veya Android gibi gereksiz verilerle sizi yormaz.
- **Anlık Tespit:** Sayfa yüklendiği an (0.5 saniyenin altında) teknolojileri ve CVE zafiyetlerini listeler.
- **Sızıntı Avcısı:** Kaynak kodda unutulan gizli yorumları, API anahtarlarını ve veritabanı bağlantılarını bulur.
- **Dinamik Keşif:** URL ve sayfa yapısına bakarak sızdırılmış olabilecek yedek dosyalarını (`.zip`, `.sql`, `.bak` vb.) otomatik arar.
- **Saldırı Yüzeyi:** Sitenin dış bağlantılarını ve alt alan adlarını ayıklayarak bir harita çıkarır.

### 👨‍💻 Geliştiriciler İçin (Kendi Veritabanını Kurmak İsteyenler)
Eğer zafiyet veritabanını kendi sunucunuzda barındırmak isterseniz:
1. PHP dosyalarını ve `shards/` klasörünü web sunucunuza yükleyin.
2. `background.js` içindeki `BASE_URL` kısmını kendi adresinizle değiştirin.
3. `daily_sync.php` dosyasını bir Cronjob'a bağlayarak verilerin güncel kalmasını sağlayın.

---

## 🇺🇸 English Description

### 🚀 Quick Start (For Users)
To use the extension immediately:
1. Download this project to your computer.
2. Go to `chrome://extensions/` in your Chrome browser.
3. Enable **Developer Mode** in the top right.
4. Click **Load unpacked** and select this folder.
*That's it! The extension will automatically fetch the latest vulnerability data from my database.*

### 🛠️ Features
- **Web-Focused:** Targets only web stack vulnerabilities, filtering out OS or hardware noise.
- **Fast Scanning:** Detects technologies and CVE matches in less than 0.5s.
- **Secret Scraper:** Finds hidden developer comments, API keys, and DB credentials in the source code.
- **Dynamic Probing:** Automatically guesses and checks for exposed backup files (`.zip`, `.sql`, `.bak`).
- **Attack Surface:** Lists all external endpoints and subdomains.

### 👨‍💻 For Developers (Self-Hosting)
If you want to host the vulnerability data on your own server:
1. Upload the PHP files and `shards/` folder to your server.
2. Update the `BASE_URL` in `background.js` to point to your URL.
3. Schedule `daily_sync.php` via Cronjob to keep the data fresh.
