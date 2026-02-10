<?php
// DEFORA RECON - SURGICAL SYNC (Time-Based & API)
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config.php';
@ini_set('memory_limit', '2048M');
@set_time_limit(0); 

$shards_dir = __DIR__ . DIRECTORY_SEPARATOR . 'shards';
$raw_dir = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'raw';
$timestamp_file = __DIR__ . DIRECTORY_SEPARATOR . 'last_sync.txt';

// Dizin Kontrolü
if (!file_exists($shards_dir)) { mkdir($shards_dir, 0777, true); }
if (!file_exists($raw_dir)) { mkdir($raw_dir, 0777, true); }

// Anlık çıktı
if (php_sapi_name() !== 'cli') {
    @ini_set('output_buffering', 'off'); @ini_set('zlib.output_compression', false);
    while (ob_get_level()) ob_end_flush(); ob_implicit_flush(true);
    echo "<pre style='background:#000; color:#0f0; padding:20px; font-family:monospace;'>";
}

echo "DEFORA RECON: GÜNCELLEME OPERASYONU\n";

// MOD SEÇİMİ
$mode = isset($argv[1]) ? $argv[1] : (isset($_GET['mode']) ? $_GET['mode'] : 'normal');
$deep_scan = ($mode === 'deep');

if ($deep_scan) {
    $last_run = 0;
    echo "MOD: DEEP SCAN\n";
} else {
    $last_run = file_exists($timestamp_file) ? intval(file_get_contents($timestamp_file)) : (time() - 86400);
    echo "MOD: NORMAL SCAN\n";
}

$current_run = time();
echo "Referans Zaman: " . date("Y-m-d H:i:s", $last_run) . "\n";
echo "--------------------------------------------------\n";

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
    if (empty($data)) return;
    foreach ($data as $name => $vulns) {
        $prefix = substr($name, 0, 2);
        if (strlen($prefix) < 2) $prefix .= '_';
        $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
        $shardPath = $dir . DIRECTORY_SEPARATOR . "shard_$prefix.json";
        
        $current = file_exists($shardPath) ? json_decode(file_get_contents($shardPath), true) : [];
        if ($current === null) $current = [];

        foreach ($vulns as $newV) {
            $exists = false;
            if (isset($current[$name])) {
                foreach ($current[$name] as $idx => $oldV) {
                    if ($oldV['id'] === $newV['id']) { $current[$name][$idx] = $newV; $exists = true; break; }
                }
            }
            if (!$exists) {
                $current[$name][] = $newV;
                echo "    [+] Yeni: $name ({$newV['id']})\n";
            }
        }
        file_put_contents($shardPath, json_encode($current));
    }
}

// 1. NIST MODIFIED
echo "[*] NIST Modified Kontrol Ediliyor... ";
$url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
$gz_file = "$raw_dir/nvd-modified.json.gz";

$ch = curl_init($url); $fp = @fopen($gz_file, 'wb');
if (!$fp) { die("HATA: $gz_file yazilamadi!\n"); }

curl_setopt($ch, CURLOPT_FILE, $fp); 
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_USERAGENT, 'DeforaRecon/1.0');
curl_exec($ch); curl_close($ch); fclose($fp);

if (!file_exists($gz_file) || filesize($gz_file) == 0) {
    echo "HATA: NIST Dosyasi indirilemedi.\n";
} else {
    $content = '';
    $gz = gzopen($gz_file, 'rb');
    if ($gz) {
        while (!gzeof($gz)) { $content .= gzread($gz, 8192); }
        gzclose($gz);
    }

    if (!empty($content)) {
        $data = json_decode($content, true);
        unset($content);
        $batch = [];
        if (isset($data['CVE_Items'])) {
            foreach ($data['CVE_Items'] as $item) {
                $modDate = strtotime($item['lastModifiedDate']);
                if ($modDate < $last_run) continue;

                $cve_id = $item['cve']['CVE_data_meta']['ID'];
                $desc = $item['cve']['description']['description_data'][0]['value'] ?? '';
                
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
                            }
                        }
                    }
                }
            }
        }
        updateShards($batch, $shards_dir);
        echo "TAMAM.\n";
    }
}

// 2. OSV API
echo "[*] OSV API Taramasi... ";
$batch = [];
foreach ($watchlist as $tech) {
    $ecosystems = ['npm', 'PyPI', 'Packagist'];
    foreach($ecosystems as $eco) {
        $ch = curl_init("https://api.osv.dev/v1/query");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["package" => ["name" => $tech, "ecosystem" => $eco]]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        $resp = curl_exec($ch); curl_close($ch);
        
        $json = json_decode($resp, true);
        if (isset($json['vulns'])) {
            foreach ($json['vulns'] as $v) {
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
                    if(!empty($rules)) $batch[$tech][] = ['id' => $v['id'], 'sev' => 'HIGH', 'r' => $rules, 'src' => "OSV-API"];
                }
            }
        }
    }
}
updateShards($batch, $shards_dir);
echo "TAMAM.\n";

// Bitis
file_put_contents($timestamp_file, $current_run);
echo "--------------------------------------------------\n";
echo "BASARI: SİSTEM SENKRONİZE.\n";
if (php_sapi_name() !== 'cli') echo "</pre>";
?>
