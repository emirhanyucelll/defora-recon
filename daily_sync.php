<?php
// DEFORA RECON - SMART DAILY SYNC (WEB FOCUSED)
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config.php';
@ini_set('memory_limit', '2048M');
@set_time_limit(0); 

$shards_dir = __DIR__ . DIRECTORY_SEPARATOR . 'shards';
$timestamp_file = __DIR__ . DIRECTORY_SEPARATOR . 'last_sync.txt';

// Dizin Kontrolü
if (!file_exists($shards_dir)) { mkdir($shards_dir, 0777, true); }

// Anlık çıktı (Browser/CLI)
if (php_sapi_name() !== 'cli') {
    @ini_set('output_buffering', 'off'); @ini_set('zlib.output_compression', false);
    while (ob_get_level()) ob_end_flush(); ob_implicit_flush(true);
    echo "<pre style='background:#111; color:#0f0; padding:20px; font-family:monospace;'>";
}

echo "DEFORA RECON: AKILLI WEB TARAMASI BAŞLATILIYOR...\n";

// Tarih Ayarları
$last_run = file_exists($timestamp_file) ? intval(file_get_contents($timestamp_file)) : (time() - 86400);
$current_run = time();
echo "Son Senkronizasyon: " . date("Y-m-d H:i:s", $last_run) . "\n";
echo "--------------------------------------------------\n";

// --- YARDIMCI FONKSİYONLAR ---

function updateShards($data, $dir) {
    if (empty($data)) return;
    foreach ($data as $name => $vulns) {
        $prefix = substr($name, 0, 2);
        if (strlen($prefix) < 2) $prefix .= '_';
        $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
        $shardPath = $dir . DIRECTORY_SEPARATOR . "shard_$prefix.json";
        
        $current = file_exists($shardPath) ? json_decode(file_get_contents($shardPath), true) : [];
        if ($current === null) $current = [];

        if (!isset($current[$name])) $current[$name] = [];

        foreach ($vulns as $newV) {
            $exists = false;
            foreach ($current[$name] as $idx => $oldV) {
                if ($oldV['id'] === $newV['id']) { $current[$name][$idx] = $newV; $exists = true; break; }
            }
            if (!$exists) {
                $current[$name][] = $newV;
            }
        }
        file_put_contents($shardPath, json_encode($current));
    }
}

// Genişletilmiş Web İzleme Listesi (OSV İçin)
function getWebWatchlist() {
    return [
        // Frontend & JS
        'react', 'vue', 'angular', 'svelte', 'jquery', 'bootstrap', 'next.js', 'nuxt', 'gatsby',
        'ember-source', 'backbone.js', 'lodash', 'moment', 'axios', 'express', 'socket.io',
        'chart.js', 'three', 'd3', 'underscore', 'handlebars', 'mustache', 'alpinejs',
        // PHP Ecosystem
        'laravel/framework', 'symfony/symfony', 'codeigniter/framework', 'cakephp/cakephp',
        'slim/slim', 'yiisoft/yii2', 'guzzlehttp/guzzle', 'monolog/monolog', 'phpunit/phpunit',
        'composer/composer', 'twig/twig', 'doctrine/orm', 'nesbot/carbon',
        // CMS & E-Commerce
        'wordpress', 'joomla', 'drupal', 'magento/product-community-edition', 'shopify',
        'opencart', 'prestashop', 'moodle', 'typo3', 'ghost', 'strapi',
        // Python Web
        'django', 'flask', 'fastapi', 'tornado', 'pyramid', 'requests', 'sqlalchemy',
        // Java Web
        'spring-framework', 'struts', 'hibernate-orm', 'jackson-databind', 'log4j', 'tomcat', 'jetty',
        // Server & DB (OSV bazen bunları da paket olarak görür)
        'nginx', 'apache', 'mysql', 'postgresql', 'redis', 'mongodb'
    ];
}

// --- 1. NIST API 2.0 (AKILLI WEB FİLTRESİ) ---
echo "[*] NIST API 2.0 (Sadece Web/App)... ";

$startDate = date("Y-m-d\TH:i:s.000", $last_run);
$endDate = date("Y-m-d\TH:i:s.000", $current_run);
// NVD API Anahtarı Kontrolü (GitHub Secrets veya Config'den al)
$nvd_api_key = getenv('NVD_API_KEY') ?: (defined('NVD_API_KEY') ? NVD_API_KEY : null);

// API URL (Zaman aralıklı sorgu)
$nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=" . urlencode($startDate) . "&lastModEndDate=" . urlencode($endDate);

$headers = [
    'User-Agent: DeforaRecon-Sync/2.1',
    'Accept: application/json'
];

if ($nvd_api_key) {
    $headers[] = "apiKey: $nvd_api_key";
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $nvd_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 60);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($http_code === 200 && !empty($response)) {
    $data = json_decode($response, true);
    $batch = [];
    $count = 0;
    
    // Masaüstü/Donanım Kara Listesi (Regex)
    $desktop_blacklist = '/(firmware|driver|bios|uefi|kernel|android|ios|windows|macos|linux_desktop|usb|bluetooth|wifi|gpu|nvidia|amd|intel|adobe_acrobat|photoshop|reader|player|client|vpn)/i';
    
    if (isset($data['vulnerabilities'])) {
        foreach ($data['vulnerabilities'] as $item) {
            $cve = $item['cve'];
            $cve_id = $cve['id'];
            if (($cve['vulnStatus'] ?? '') === 'Rejected') continue;

            if (isset($cve['configurations'])) {
                foreach ($cve['configurations'] as $config) {
                    foreach ($config['nodes'] as $node) {
                        foreach ($node['cpeMatch'] ?? [] as $match) {
                            if (!$match['vulnerable']) continue;
                            
                            // CPE Analizi: cpe:2.3:PART:VENDOR:PRODUCT:...
                            $p = explode(':', $match['criteria']);
                            
                            // 1. FİLTRE: Sadece Uygulama (a) kategorisi. İşletim Sistemi (o) ve Donanım (h) atılır.
                            if (!isset($p[2]) || ($p[2] !== 'a')) continue;
                            
                            // 2. FİLTRE: Ürün Adı Kontrolü (Web mi?)
                            $prod = strtolower($p[4] ?? '');
                            if (empty($prod)) continue;

                            // Eğer ürün adı kara listedeyse at
                            if (preg_match($desktop_blacklist, $prod)) continue;

                            // Eğer ürün adı web teknolojisi çağrıştırmıyorsa ve çok genel bir isimse şüpheyle yaklaşılabilir
                            // Ancak şimdilik whitelist yerine blacklist ile gidiyoruz, böylece bilinmeyen yeni web kütüphanelerini kaçırmayız.

                            $rule = ['exact' => $p[5] ?? '*'];
                            if (isset($match['versionStartIncluding'])) $rule['sInc'] = $match['versionStartIncluding'];
                            if (isset($match['versionEndExcluding']))   $rule['eExc'] = $match['versionEndExcluding'];
                            
                            $batch[$prod][] = ['id' => $cve_id, 'sev' => 'HIGH', 'r' => [$rule], 'src' => 'NVD'];
                            $count++;
                        }
                    }
                }
            }
        }
    }
    updateShards($batch, $shards_dir);
    echo "TAMAM (Filtre sonrası $count kayıt).\n";
} else {
    echo "HATA: NIST Bağlantısı başarısız ($http_code).\n";
}

// --- 2. OSV API (GENİŞLETİLMİŞ LİSTE) ---
echo "[*] OSV API (Top 100+ Web Tech)... ";
$watchlist = getWebWatchlist();
$batch = [];
$osv_hits = 0;

// Performans için curl_multi kullanmıyoruz (basitlik adına), ancak timeout kısa tutuyoruz.
foreach ($watchlist as $tech) {
    // İsmi temizle (vendor/product -> product)
    $cleanName = (strpos($tech, '/') !== false) ? explode('/', $tech)[1] : $tech;

    $ch = curl_init("https://api.osv.dev/v1/query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    // OSV'ye sormak için "ecosystem" belirtmeden isme göre soruyoruz (daha geniş kapsam)
    // Ancak ecosystem belirtmezsek bazen saçma sonuçlar gelebilir, o yüzden genel deniyoruz.
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["package" => ["name" => $tech]]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3); // Hızlı geç
    
    $resp = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code === 200) {
        $json = json_decode($resp, true);
        if (isset($json['vulns'])) {
            foreach ($json['vulns'] as $v) {
                // OSV 'modified' tarihini kontrol et
                $vMod = isset($v['modified']) ? strtotime($v['modified']) : 0;
                if ($vMod > $last_run) {
                    // ID FORMATLAMA: CVE Öncelikli, GHSA Destekli
                    $cve_id = null;
                    if (isset($v['aliases'])) {
                        foreach ($v['aliases'] as $alias) {
                            if (strpos($alias, 'CVE-') === 0) { $cve_id = $alias; break; }
                        }
                    }
                    
                    // Görünüm: CVE-2024-1234 (GHSA-xxxx) veya sadece GHSA-xxxx
                    $displayId = $cve_id ? $cve_id : $v['id'];

                    $rules = [];
                    if (isset($v['affected'])) {
                        foreach ($v['affected'] as $aff) {
                            if (strtolower($aff['package']['name'] ?? '') !== strtolower($tech)) continue;
                            foreach ($aff['ranges'] ?? [] as $range) {
                                if (($range['type'] ?? '') === "SEMVER") {
                                    $r = [];
                                    foreach ($range['events'] as $evt) {
                                        if (isset($evt['introduced'])) $r['sInc'] = $evt['introduced'];
                                        if (isset($evt['fixed'])) $r['eExc'] = $evt['fixed'];
                                    }
                                    if(!empty($r)) $rules[] = $r;
                                }
                            }
                        }
                    }
                    if(!empty($rules)) {
                        $batch[$tech][] = ['id' => $displayId, 'sev' => 'HIGH', 'r' => $rules, 'src' => "OSV-API"];
                        $osv_count++;
                    }
                }
            }
        }
    }
}
updateShards($batch, $shards_dir);
echo "TAMAM ($osv_hits yeni kayıt).\n";

// --- BİTİŞ ---
file_put_contents($timestamp_file, $current_run);
echo "--------------------------------------------------\n";
echo "BASARI: Tüm veritabanları güncellendi.\n";
if (php_sapi_name() !== 'cli') echo "</pre>";
?>