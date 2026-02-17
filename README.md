# Defora Recon
Web sitelerini analiz etmek, kullanılan teknolojileri tespit etmek ve olası güvenlik açıklarını/sızıntıları bulmak için geliştirdiğim bir araç.

---

## 🇹🇷 Türkçe Açıklama

### Neler Yapıyor?
- **Web Odaklı Filtreleme:** NIST veritabanındaki zafiyetleri tararken sadece web sitelerini ilgilendiren (kütüphane, sunucu, veritabanı vb.) verileri alır. Windows, Android veya donanım gibi web dışı içerikleri ayıklayarak veritabanını sade ve amaca yönelik tutar.
- **Hızlı Tarama:** Sayfa yüklendiği an kullanılan teknolojileri ve bunlarla eşleşen bilinen zafiyetleri (CVE) yarım saniyenin altında bir sürede gösterir.
- **Hassas Veri Taraması:** Kaynak kod içindeki geliştirici yorumlarını, API anahtarlarını (AWS, Azure, Firebase, JWT), veritabanı bağlantılarını ve sızdırılmış olabilecek dosya isimlerini tespit eder.
- **Bağlantı Keşfi:** Sayfadaki tüm dış bağlantıları ve alt alan adlarını (subdomain) listeleyerek sitenin genel haritasını çıkarır.
- **Aktif Dosya Kontrolü:** Arka planda `.env`, `.git/config`, `backup.zip`, `sql` yedekleri gibi 30'dan fazla kritik noktayı otomatik olarak kontrol eder.
- **Güncel Veri:** GitHub Actions ve NIST API 2.0 entegrasyonu sayesinde zafiyet listesini her gün otomatik olarak günceller.

### Kurulum
1. `shards/` klasörünü ve PHP dosyalarını web sunucunuza aktarın.
2. Eklentiyi Chrome'da "Geliştirici Modu" üzerinden "Paketlenmemiş öğe yükle" diyerek seçin.
3. Güncellemelerin daha hızlı çalışması için GitHub Secrets kısmına `NVD_API_KEY` ekleyebilirsiniz.

---

## 🇺🇸 English Description

### Features
- **Web-Focused Filtering:** Filters NIST vulnerability data to include only web-related entries (libraries, servers, databases, etc.). It excludes non-web data like OS or hardware to keep the database lean and relevant.
- **Fast Scanning:** Detects technologies and matched vulnerabilities (CVE) in less than 0.5 seconds upon page load.
- **Secret & Sensitive Data Scraping:** Identifies developer comments, API keys (AWS, Azure, Firebase, JWT), database connection strings, and potentially exposed filenames in the source code.
- **Endpoint Discovery:** Lists all external links and subdomains to map out the site's structure.
- **Active File Probing:** Automatically checks for over 30 critical exposure points such as `.env`, `.git/config`, `backup.zip`, and `sql` dumps.
- **Automated Updates:** Uses GitHub Actions and NVD API 2.0 to keep the vulnerability database updated daily.

### Installation
1. Upload the `shards/` folder and PHP scripts to your web server.
2. Load the extension in Chrome via "Developer Mode" -> "Load unpacked".
3. Optionally, add `NVD_API_KEY` to GitHub Secrets to speed up daily synchronization.

---

### Veri Kaynakları / Data Sources
- NIST NVD API 2.0
- OSV (Open Source Vulnerabilities)