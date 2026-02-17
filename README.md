# Defora Recon
Web sitelerini analiz etmek, kullanılan teknolojileri tespit etmek ve olası güvenlik açıklarını/sızıntıları bulmak için hazırladığım bir araç.

---

## 🇹🇷 Türkçe Açıklama

### 🚀 Nasıl Kullanılır?
Eklentiyi hemen kullanmaya başlamak için:
1. Bu projeyi bilgisayarınıza indirin.
2. Chrome tarayıcınızda `chrome://extensions/` adresine gidin.
3. Sağ üstteki **Geliştirici Modu**'nu açın.
4. **Paketlenmemiş öğe yükle** butonuna basarak indirdiğiniz klasörü seçin.
*Eklenti, güncel zafiyet verilerini otomatik olarak benim hazırladığım ve her gün güncellenen veritabanından çekecektir.*

### 🛠️ Neler Yapıyor?
- **Web Odaklı Analiz:** Sadece web teknolojilerini (kütüphane, sunucu, veritabanı vb.) tarar. Windows veya Android gibi bu araçla alakası olmayan verileri ayıklayarak sistemi temiz tutuyorum.
- **Anlık Tespit:** Sayfa yüklendiği an teknolojileri ve CVE zafiyetlerini yarım saniyenin altında bir sürede listeler.
- **Sızıntı Avcısı:** Kaynak kodda unutulan gizli yorumları, API anahtarlarını ve veritabanı bağlantılarını bulur.
- **Dinamik Keşif:** URL ve sayfa yapısına bakarak sızdırılmış olabilecek yedek dosyalarını (`.zip`, `.sql`, `.bak` vb.) otomatik olarak arar.
- **Saldırı Yüzeyi:** Sitenin dış bağlantılarını ve alt alan adlarını ayıklayarak bir harita çıkarır.
- **Otomatik Güncelleme:** Arka planda çalışan sistemim sayesinde zafiyet veritabanını her gün NIST ve OSV üzerinden güncel tutuyorum.

---

## 🇺🇸 English Description

### 🚀 How to Use?
To use the extension immediately:
1. Download this project to your computer.
2. Go to `chrome://extensions/` in your Chrome browser.
3. Enable **Developer Mode** in the top right.
4. Click **Load unpacked** and select the folder you just downloaded.
*The extension will automatically fetch the latest vulnerability data from my database, which I keep updated daily.*

### 🛠️ Features
- **Web-Focused:** I filter the data to target only web stack vulnerabilities, removing unnecessary OS or hardware noise.
- **Fast Scanning:** Detects technologies and CVE matches in less than 0.5s.
- **Secret Scraper:** Finds hidden developer comments, API keys, and DB credentials in the source code.
- **Dynamic Probing:** Automatically identifies and checks for potentially exposed backup files (`.zip`, `.sql`, `.bak`).
- **Attack Surface:** Lists all external endpoints and subdomains found on the page.
- **Always Fresh:** My backend system keeps the vulnerability data synchronized daily with NIST and OSV sources.