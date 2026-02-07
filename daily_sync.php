<?php
// DEFORA RECON - SURGICAL SYNC (Time-Based & API)
require_once 'config.php';
@ini_set('memory_limit', '1024M');
@set_time_limit(600); // 10 Dakika limit

// Anlık çıktı
@ini_set('output_buffering', 'off'); @ini_set('zlib.output_compression', false);
while (ob_get_level()) ob_end_flush(); ob_implicit_flush(true);

$shards_dir = __DIR__ . DIRECTORY_SEPARATOR . 'shards';
$raw_dir = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'raw';
$timestamp_file = __DIR__ . DIRECTORY_SEPARATOR . 'last_sync.txt';

// MOD SEÇİMİ: Normal (Hızlı) vs Deep (Tam Tarama)
$mode = isset($argv[1]) ? $argv[1] : (isset($_GET['mode']) ? $_GET['mode'] : 'normal');
$deep_scan = ($mode === 'deep');

// Son çalışma zamanını al
if ($deep_scan) {
    $last_run = 0; // Zamanı sıfırla, her şeyi al
    echo "MOD: DEEP SCAN (TÜM GEÇMİŞ TARANIYOR - BU UZUN SÜREBİLİR)\n";
} else {
    $last_run = file_exists($timestamp_file) ? intval(file_get_contents($timestamp_file)) : (time() - 86400);
    echo "MOD: NORMAL SCAN (SADECE YENİLER)\n";
}

$current_run = time();

echo "<pre style='background:#000; color:#0f0; padding:20px; font-family:monospace;'>";
echo "DEFORA RECON: GÜNCELLEME OPERASYONU\n";
echo "Son Güncelleme Referansı: " . date("Y-m-d H:i:s", $last_run) . "\n";
echo "--------------------------------------------------\n";

// Genişletilmiş Takip Listesi (OSV API için)
$watchlist = [
    'bootstrap', 'jquery', 'react', 'vue', 'angular', 'svelte', 'ember', 'meteor',
    'lodash', 'moment', 'axios', 'socket.io', 'd3', 'chart.js', 'three',
    'express', 'django', 'flask', 'rails', 'laravel', 'symfony', 'spring',
    'apache', 'nginx', 'tomcat', 'iis',
    'mysql', 'postgresql', 'redis', 'mongodb',
    'wordpress', 'drupal', 'joomla', 'magento', 'shopify',
    'fastapi', 'hibernate', 'struts', 'log4j', 'jackson'
];

function updateShards($data, $dir) {
    foreach ($data as $name => $vulns) {
        $prefix = substr($name, 0, 2);
        if (strlen($prefix) < 2) $prefix .= '_';
        $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
        $shardPath = $dir . DIRECTORY_SEPARATOR . "shard_$prefix.json";
        
        $current = file_exists($shardPath) ? json_decode(file_get_contents($shardPath), true) : [];
        foreach ($vulns as $newV) {
            $exists = false;
            if (isset($current[$name])) {
                foreach ($current[$name] as $idx => $oldV) {
                    if ($oldV['id'] === $newV['id']) { $current[$name][$idx] = $newV; $exists = true; break; }
                }
            }
            if (!$exists) {
                $current[$name][] = $newV;
                echo "    [+] Yeni Zafiyet: $name ({$newV['id']})\n";
            }
        }
        file_put_contents($shardPath, json_encode($current));
    }
}

// 1. NIST MODIFIED (Time-Based Filter)
echo "[*] NIST Modified Feed Kontrol Ediliyor... ";
$url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
$gz_file = "$raw_dir/nvd-modified.json.gz";

$ch = curl_init($url); $fp = fopen($gz_file, 'wb');
curl_setopt($ch, CURLOPT_FILE, $fp); 
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_USERAGENT, 'DeforaRecon/1.0');
curl_exec($ch); curl_close($ch); fclose($fp);

$content = '';
if (file_exists($gz_file)) {
    $gz = gzopen($gz_file, 'rb');
    if ($gz) {
        while (!gzeof($gz)) { $content .= gzread($gz, 4096); }
        gzclose($gz);
    }
}

if (!empty($content)) {
    $data = json_decode($content, true);
    unset($content);
    $batch = [];
    $processed = 0;
    $skipped = 0;
    
    if (isset($data['CVE_Items'])) {
        foreach ($data['CVE_Items'] as $item) {
            // ZAMAN FİLTRESİ: Eğer zafiyet son güncellemeden eskiyse atla
            $modDate = strtotime($item['lastModifiedDate']);
            if ($modDate < $last_run) {
                $skipped++;
                continue;
            }

            $processed++;
            $cve_id = $item['cve']['CVE_data_meta']['ID'];
            $desc = $item['cve']['description']['description_data'][0]['value'] ?? '';
            $hasCPE = false;

            // CPE Analizi
            if (isset($item['configurations']['nodes'])) {
                foreach ($item['configurations']['nodes'] as $node) {
                    foreach ($node['cpe_match'] ?? [] as $m) {
                        $p = explode(':', $m['cpe23Uri']);
                        if (isset($p[4])) {
                            $prod = strtolower($p[4]);
                            $rule = ['exact' => $p[5] ?? '*'];
                            if (isset($m['versionStartIncluding'])) $rule['sInc'] = $m['versionStartIncluding'];
                            if (isset($m['versionEndExcluding']))   $rule['eExc'] = $m['versionEndExcluding'];
                            $batch[$prod][] = ['id' => $cve_id, 'sev' => 'HIGH', 'r' => [$rule], 'src' => 'NVD'];
                            $hasCPE = true;
                        }
                    }
                }
            }

            // Hunter Mode (CPE Yoksa)
            if (!$hasCPE && !empty($desc)) {
                foreach ($watchlist as $tech) {
                    if (stripos($desc, $tech) !== false) {
                        $rule = ['exact' => '*'];
                        if (preg_match('/(?:before|prior to|up to|earlier than|versions?)\s+([0-9.]+)/i', $desc, $m)) {
                            $rule = ['eExc' => $m[1]];
                        }
                        $batch[$tech][] = ['id' => $cve_id, 'sev' => 'HIGH', 'r' => [$rule], 'src' => 'NVD-MINER'];
                    }
                }
            }
        }
    }
    updateShards($batch, $shards_dir);
    echo "TAMAM ($processed işlendi, $skipped atlandı - Güncel).\n";
} else {
    echo "HATA (Dosya açılamadı).\n";
}

// 2. OSV API (Watchlist Scan - Zip Yok, Hız Var)
echo "[*] OSV API Taraması (Kritik Teknolojiler)... ";
$batch = [];
$api_hits = 0;
foreach ($watchlist as $tech) {
    $ecosystems = ['npm', 'PyPI', 'Maven', 'Packagist', 'RubyGems'];
    
    foreach($ecosystems as $eco) {
        $ch = curl_init("https://api.osv.dev/v1/query");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["package" => ["name" => $tech, "ecosystem" => $eco]]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        $resp = curl_exec($ch);
        curl_close($ch);
        
        $json = json_decode($resp, true);
        if (isset($json['vulns'])) {
            foreach ($json['vulns'] as $v) {
                // Zaman Filtresi (API'de modified varsa)
                if (isset($v['modified']) && strtotime($v['modified']) > $last_run) {
                    $rules = [];
                    if (isset($v['affected'])) {
                        foreach ($v['affected'] as $aff) {
                            foreach ($aff['ranges'] ?? [] as $range) {
                                if ($range['type'] === "SEMVER") {
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
                        $batch[$tech][] = ['id' => $v['id'], 'sev' => 'HIGH', 'r' => $rules, 'src' => "OSV-API"];
                        $api_hits++;
                    }
                }
            }
        }
    }
    echo "."; flush();
}
echo "\nOSV Taraması Tamamlandı ($api_hits yeni kayıt).\n";
updateShards($batch, $shards_dir);

// Zaman damgasını güncelle
file_put_contents($timestamp_file, $current_run);

echo "--------------------------------------------------\n";
echo "BAŞARI: SİSTEM " . date("H:i:s", $current_run) . " İTİBARİYLE SENKRONİZE.\n";
echo "</pre>";
?>
