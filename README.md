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
- **Otomatik Tam Tarama (Full Scan):** Tek tıkla tüm siteyi gezen bir "Örümcek" motoru ekledim. Bu motor `robots.txt` dosyalarını analiz eder, gizli yolları bulur ve bulduğu tüm subdomainleri otomatik olarak yoklar.
- **Sızıntı Avcısı:** Kaynak kodda unutulan gizli yorumları, API anahtarlarını, veritabanı bağlantılarını ve sızdırılmış dosyaları bulur.
- **Dış Kaynak Analizi:** Sitenin konuştuğu tüm dış servisleri ve alt alan adlarını ayıklayarak bir harita çıkarır.
- **Akıllı Raporlama:** Tarama bittiğinde tüm bulguları profesyonel, aydınlık temalı bir rapor olarak otomatik indirir.

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
- **Intelligence Spider (Full Scan):** A built-in crawler that explores the entire site, parses `robots.txt` for hidden paths, and automatically probes discovered subdomains for leaks.
- **Secret Scraper:** Finds hidden developer comments, API keys, and DB credentials in the source code.
- **External Resource Mapping:** Lists all external endpoints and subdomains found on the page.
- **Auto-Reporting:** Automatically generates and downloads a professional light-themed audit report after the scan completes.