<?php
// DEFORA RECON - HARDENED CONFIG
if (!function_exists('loadReconEnv')) {
    function loadReconEnv($path) {
        if (!file_exists($path)) return;
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0 || strpos($line, '=') === false) continue;
            list($name, $value) = explode('=', $line, 2);
            if (!defined(trim($name))) {
                define(trim($name), trim($value));
            }
        }
    }
}
loadReconEnv(__DIR__ . '/.env');
?>