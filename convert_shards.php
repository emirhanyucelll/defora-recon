<?php
// DEFORA RECON - SHARD CONVERTER (V1)
// Bu script mevcut 'Tek Harfli' (shard_a.json) dosyaları 'Çift Harfli' (shard_aa.json) formata dönüştürür.
// İnternet kullanmaz, sadece disk işlemi yapar.

ini_set('memory_limit', '4096M'); // 1 GB dosya için şart
set_time_limit(0);

$shardsDir = __DIR__ . '/shards';
$files = glob($shardsDir . '/shard_?.json'); // Sadece tek harfli dosyaları bul

echo "<pre style='background:#000; color:#0f0; padding:20px;'>";
echo "DÖNÜŞÜM BAŞLIYOR... (MEVCUT VERİLER KURTARILIYOR)\n";
echo "--------------------------------------------------\n";

foreach ($files as $file) {
    $filename = basename($file);
    // shard_aa.json gibi zaten dönüştürülmüşleri atla
    if (strlen($filename) > 12) continue; 

    echo "[*] İşleniyor: $filename ... ";
    flush();

    $content = file_get_contents($file);
    $data = json_decode($content, true);
    
    // Bellek tasarrufu için raw içeriği hemen boşalt
    unset($content);

    if (!$data) {
        echo "HATA: JSON bozuk veya boş.\n";
        continue;
    }

    $newShards = [];
    $count = 0;

    foreach ($data as $techName => $vulns) {
        // Yeni önek hesapla (ilk 2 harf)
        $prefix = substr($techName, 0, 2);
        if (strlen($prefix) < 2) $prefix .= '_';
        $prefix = preg_replace('/[^a-z0-9]/', '_', $prefix);
        
        $targetFile = $shardsDir . "/shard_$prefix.json";
        
        // Eğer bu dosya henüz bu döngüde belleğe alınmadıysa, diskten varsa oku
        if (!isset($newShards[$prefix])) {
            if (file_exists($targetFile)) {
                $newShards[$prefix] = json_decode(file_get_contents($targetFile), true);
            } else {
                $newShards[$prefix] = [];
            }
        }

        // Veriyi ekle (üstüne yazma, birleştir)
        // Not: Eski dosyada zaten veri tekil olduğu için direkt atayabiliriz ama
        // güvenli taraf için merge yapmıyoruz, direkt key olarak atıyoruz.
        $newShards[$prefix][$techName] = $vulns;
        $count++;
    }

    // Parçaları diske yaz
    foreach ($newShards as $prefix => $shardData) {
        file_put_contents($shardsDir . "/shard_$prefix.json", json_encode($shardData));
    }
    
    // Belleği temizle
    unset($data);
    unset($newShards);
    
    // Eski dosyayı sil (Opsiyonel, yer açmak için şart)
    unlink($file);

    echo "TAMAM ($count teknoloji parçalandı).\n";
    flush();
}

echo "--------------------------------------------------\n";
echo "OPERASYON BAŞARIYLA TAMAMLANDI.\n";
echo "</pre>";
?>
