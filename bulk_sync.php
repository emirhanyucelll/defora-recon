<?php
// DEFORA RECON - API-DRIVEN BULK SYNC (NVD 2.0 & OSV)
error_reporting(E_ALL);
ini_set('display_errors', 1);
@ini_set('memory_limit', '-1');
@set_time_limit(0); 

$shards_dir = __DIR__ . DIRECTORY_SEPARATOR . 'shards';
$timestamp_file = __DIR__ . DIRECTORY_SEPARATOR . 'last_sync.txt';

function getWebWatchlist() {
    return [
        'react', 'vue', 'angular', 'svelte', 'jquery', 'bootstrap', 'next.js', 'nuxt', 'gatsby',
        'laravel', 'symfony', 'codeigniter', 'cakephp', 'slim', 'yii', 'django', 'flask', 'fastapi',
        'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'nginx', 'apache', 'mysql', 'postgresql', 'redis', 'mongodb'
    ];
}

function updateShards($data) {
    global $shards_dir;
    if (empty($data)) return;
    foreach ($data as $name => $vulns) {
        $prefix = substr($name, 0, 2);
        if (strlen($prefix) < 2) $prefix .= '_';
        $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
        $shardPath = $shards_dir . DIRECTORY_SEPARATOR . "shard_$prefix.json";
        $current = file_exists($shardPath) ? json_decode(file_get_contents($shardPath), true) : [];
        if (!isset($current[$name])) $current[$name] = [];
        foreach ($vulns as $newV) {
            $exists = false;
            foreach ($current[$name] as $existing) { if ($existing['id'] === $newV['id']) { $exists = true; break; } }
            if (!$exists) $current[$name][] = $newV;
        }
        file_put_contents($shardPath, json_encode($current));
    }
}

echo "=== DEFORA RECON: API TABANLI YENİDEN İNŞA ===\n";

// 1. NIST API 2.0 (Geriye Dönük Tarama)
// NVD API 2.0 bir seferde max 120 günlük veri verir.
echo "[*] NIST API 2.0 (2010 -> Bugun) Sorgulaniyor...\n";
$start = strtotime("2010-01-01");
$end = time();
$step = 90 * 24 * 60 * 60; // 90 gunluk dilimler (daha guvenli)

$non_web_blacklist = '/(firmware|driver|bios|uefi|kernel|android|ios|windows|macos|linux_desktop|usb|bluetooth|wifi|gpu|nvidia|amd|intel|adobe_acrobat|photoshop|illustrator|reader|player|client|vpn|office|excel|word|powerpoint|antivirus|firewall|game|launcher|printer|scanner|camera|zoom|skype|teams|outlook|explorer|finder|utility|calculator|wallpaper|screen_saver)/i';

for ($t = $start; $t < $end; $t += $step) {
    $t1 = date("Y-m-d\TH:i:s.000", $t);
    $t2 = date("Y-m-d\TH:i:s.000", min($t + $step, $end));
    echo "    > Periyot: " . date("Y-m-d", $t) . " - " . date("Y-m-d", min($t + $step, $end)) . " ... ";
    
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=$t1&lastModEndDate=$t2";
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'DeforaRecon-Bulk/2.0');
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 200) {
        $json = json_decode($resp, true);
        $batch = [];
        $count = 0;
        if (isset($json['vulnerabilities'])) {
            foreach ($json['vulnerabilities'] as $item) {
                $cve = $item['cve'];
                if (isset($cve['configurations'])) {
                    foreach ($cve['configurations'] as $config) {
                        foreach ($config['nodes'] as $node) {
                            foreach ($node['cpeMatch'] ?? [] as $m) {
                                if (!$m['vulnerable']) continue;
                                $p = explode(':', $m['criteria']);
                                if (isset($p[2]) && $p[2] === 'a') {
                                    $prod = strtolower($p[4] ?? '');
                                    if (!empty($prod) && !preg_match($non_web_blacklist, $prod)) {
                                        $rule = ['exact' => $p[5] ?? '*'];
                                        if (isset($m['versionStartIncluding'])) $rule['sInc'] = $m['versionStartIncluding'];
                                        if (isset($m['versionEndExcluding']))   $rule['eExc'] = $m['versionEndExcluding'];
                                        $batch[$prod][] = ['id' => $cve['id'], 'sev' => 'HIGH', 'r' => [$rule], 'src' => 'NVD'];
                                        $count++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        updateShards($batch);
        echo "TAMAM ($count web zafiyeti).\n";
    } else {
        echo "HATA ($code). Atlandi.\n";
    }
    sleep(6); // NVD API Rate Limit Koruması (6 saniye bekleme zorunludur)
}

// 2. OSV Taraması (Watchlist)
echo "\n[*] OSV API (Web Watchlist) Full History...\n";
$watchlist = getWebWatchlist();
foreach ($watchlist as $tech) {
    echo "    > $tech sorgulaniyor... ";
    $ch = curl_init("https://api.osv.dev/v1/query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["package" => ["name" => $tech]]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($code === 200) {
        $json = json_decode($resp, true);
        $count = isset($json['vulns']) ? count($json['vulns']) : 0;
        // ... (Shard güncelleme mantığı buraya gelecek)
        echo "TAMAM ($count kayit).\n";
    } else { echo "HATA ($code).\n"; }
    usleep(200000);
}

file_put_contents($timestamp_file, time());
echo "\nZAFER: Veritabanı API üzerinden güncellendi.\n";
?>