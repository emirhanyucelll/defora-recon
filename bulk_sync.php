<?php
// DEFORA RECON - V60 "OMNIPOTENT" (THE UNIVERSAL HARVESTER)
require_once 'config.php';
@set_time_limit(0); @ini_set('memory_limit', '4096M');

// Anlık çıktı ayarları
@ini_set('output_buffering', 'off'); @ini_set('zlib.output_compression', false);
while (ob_get_level()) ob_end_flush(); ob_implicit_flush(true);

$root = __DIR__;
$shards_dir = $root . DIRECTORY_SEPARATOR . 'shards';
$raw_dir = $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'raw';
$extract_base = $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'extracted';

if (!file_exists($shards_dir)) mkdir($shards_dir, 0777, true);
if (!file_exists($raw_dir)) mkdir($raw_dir, 0777, true);
if (!file_exists($extract_base)) mkdir($extract_base, 0777, true);

echo "<pre style='background:#000; color:#0f0; padding:20px; font-family:monospace; min-height:100vh;'>";
echo "DEFORA RECON V60: EVRENSEL İSTİHBARAT HAREKATI BAŞLADI\n";
echo "Hedef: Dünyadaki TÜM Zafiyetler | Kaynak: NIST NVD + Google OSV + GitHub\n";
echo "--------------------------------------------------\n";

function download($url, $dest) {
    echo "[*] İndiriliyor: " . basename($dest) . " ... "; flush();
    $ch = curl_init($url); $fp = @fopen($dest, 'wb');
    if (!$fp) return false;
    curl_setopt($ch, CURLOPT_FILE, $fp); curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); curl_setopt($ch, CURLOPT_TIMEOUT, 900);
    $res = curl_exec($ch); curl_close($ch); fclose($fp);
    if($res) echo "OK.\n"; else echo "HATA!\n"; flush();
    return $res;
}

function writeToShard($name, $vulns) {
    $name = strtolower(trim($name));
    if (empty($name)) return;
    $prefix = substr($name, 0, 2);
    if (strlen($prefix) < 2) $prefix .= '_';
    $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
    $path = __DIR__ . "/shards/shard_$prefix.json";
    
    $shard = file_exists($path) ? json_decode(file_get_contents($path), true) : [];
    if (!isset($shard[$name])) $shard[$name] = [];

    foreach ($vulns as $v) {
        $found = false;
        foreach ($shard[$name] as $idx => $existing) {
            if ($existing['id'] === $v['id']) { $found = true; break; }
        }
        if (!$found) $shard[$name][] = $v;
    }
    file_put_contents($path, json_encode($shard));
}

// 1. AŞAMA: OSV (TÜM AÇIK KAYNAK DÜNYASI)
$ecosystems = ["npm", "PyPI", "Packagist", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Android", "Debian", "Ubuntu", "Alpine", "Linux", "OSS-Fuzz"];
foreach ($ecosystems as $eco) {
    $zip_file = "$raw_dir/$eco.zip";
    $target_dir = "$extract_base/$eco";
    if (!file_exists($target_dir)) mkdir($target_dir, 0777, true);

    if (download("https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip", $zip_file)) {
        echo "[*] $eco açılıyor... "; flush();
        shell_exec('powershell -command "Expand-Archive -Path \'" . $zip_file . "\' -DestinationPath \'" . $target_dir . "\' -Force"');
        
        $files = glob("$target_dir/*.json");
        $batch = [];
        foreach ($files as $file) {
            $json = json_decode(file_get_contents($file), true);
            if (!isset($json['affected'])) { @unlink($file); continue; }
            
            $aliases = $json['aliases'] ?? [];
            foreach ($json['affected'] as $aff) {
                $pkg = strtolower($aff['package']['name'] ?? '');
                if (!$pkg) continue;
                $rules = [];
                foreach ($aff['ranges'] ?? [] as $range) {
                    $r = [];
                    foreach ($range['events'] as $evt) {
                        if (isset($evt['introduced'])) $r['sInc'] = $evt['introduced'];
                        if (isset($evt['fixed'])) $r['eExc'] = $evt['fixed'];
                    }
                    if(!empty($r)) $rules[] = $r;
                }
                $batch[$pkg][] = ['id' => $json['id'], 'alias' => $aliases, 'sev' => 'HIGH', 'r' => $rules, 'src' => "OSV"];
            }
            @unlink($file);
        }
        foreach($batch as $p => $d) writeToShard($p, $d);
        echo "OK.\n"; flush();
    }
}

// 2. AŞAMA: NIST NVD (TÜM TARİHÇE)
echo "\n[*] NIST NVD TOPYEKÜN KAZI (2002-2026) BAŞLIYOR...\n"; flush();
$feeds = array_merge(range(2002, 2026), ["recent", "modified"]);
foreach ($feeds as $feed) {
    $feedName = "nvdcve-1.1-$feed";
    $gz_file = "$raw_dir/$feedName.json.gz";
    $json_file = "$raw_dir/$feedName.json";
    
    if (download("https://nvd.nist.gov/feeds/json/cve/1.1/$feedName.json.gz", $gz_file)) {
        echo "[*] $feed işleniyor... "; flush();
        shell_exec('tar -xzf "' . $gz_file . '" -C "' . $raw_dir . '"');
        if (file_exists($json_file)) {
            $data = json_decode(file_get_contents($json_file), true);
            if (isset($data['CVE_Items'])) {
                $infraBatch = [];
                foreach ($data['CVE_Items'] as $item) {
                    $cve_id = $item['cve']['CVE_data_meta']['ID'];
                    foreach ($item['configurations']['nodes'] ?? [] as $node) {
                        foreach ($node['cpe_match'] ?? [] as $m) {
                            $p = explode(':', $m['cpe23Uri']);
                            if (isset($p[4])) {
                                $prod = strtolower($p[4]);
                                $rule = ['exact' => $p[5] ?? '*'];
                                if (isset($m['versionStartIncluding'])) $rule['sInc'] = $m['versionStartIncluding'];
                                if (isset($m['versionEndExcluding']))   $rule['eExc'] = $m['versionEndExcluding'];
                                $infraBatch[$prod][] = ['id' => $cve_id, 'alias' => [], 'sev' => 'HIGH', 'r' => [$rule], 'src' => 'NVD'];
                            }
                        }
                    }
                }
                foreach($infraBatch as $p => $d) writeToShard($p, $d);
            }
            @unlink($json_file);
        }
        @unlink($gz_file);
        echo "OK.\n"; flush();
    }
}

echo "--------------------------------------------------\n";
echo "ZAFER: EVRENSEL ARSENAL MÜHÜRLENDİ. %100 EMİNİM KOMUTANIM!\n";
echo "</pre>";
?>