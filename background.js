// DEFORA RECON - THE BRAIN (V60 - OMNIPOTENT)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

async function getShard(name) {
    let prefix = name.substring(0, 2).toLowerCase();
    if (prefix.length < 2) prefix += '_';
    prefix = prefix.replace(/[^a-z0-9]/g, '_');
    if (SHARD_CACHE[prefix]) return SHARD_CACHE[prefix];
    try {
        const res = await fetch(`${BASE_URL}shard_${prefix}.json`);
        if (res.ok) { SHARD_CACHE[prefix] = await res.json(); return SHARD_CACHE[prefix]; }
    } catch (e) {}
    return null;
}

function parseV(v) { return v.toString().replace(/[^0-9.]/g, '').split('.').map(Number); }
function compare(v1, v2) {
    const a = parseV(v1); const b = parseV(v2);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        if ((a[i] || 0) > (b[i] || 0)) return 1;
        if ((a[i] || 0) < (b[i] || 0)) return -1;
    }
    return 0;
}

function isVulnerable(detected, rules) {
    if (!detected || ["0.0.0", "Unknown", "Detected"].includes(detected)) return false;
    for (let r of rules) {
        if (r.exact && compare(detected, r.exact) === 0) return true;
        let inside = true; let hasLogic = false;
        if (r.sInc) { hasLogic = true; if (compare(detected, r.sInc) < 0) inside = false; }
        if (r.eExc) { hasLogic = true; if (compare(detected, r.eExc) >= 0) inside = false; }
        if (hasLogic && inside) return true;
    }
    return false;
}

const detectedHeaders = {}; 
const securityReports = {}; 
const networkEndpoints = {}; // Canlı ağ trafiği takibi

// --- CANLI AĞ CASUSU (Hidden API & Endpoint Discovery) ---
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.tabId < 0) return;
        try {
            const url = new URL(details.url);
            if (!networkEndpoints[details.tabId]) networkEndpoints[details.tabId] = new Set();
            networkEndpoints[details.tabId].add(url.hostname);
        } catch(e) {}
    },
    { urls: ["<all_urls>"] }
);

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.type !== 'main_frame') return;
        const tabId = details.tabId;
        const headers = details.responseHeaders;
        if (!detectedHeaders[tabId]) detectedHeaders[tabId] = [];
        const security = [];
        const headerNames = headers.map(h => h.name.toLowerCase());
        
        if (!headerNames.includes('strict-transport-security')) security.push({ risk: 'MEDIUM', name: 'HSTS Eksik', desc: 'HTTPS zorlanmiyor.' });
        if (!headerNames.includes('content-security-policy')) security.push({ risk: 'MEDIUM', name: 'CSP Eksik', desc: 'XSS riski yuksek.' });
        if (!headerNames.includes('x-frame-options')) security.push({ risk: 'HIGH', name: 'Clickjacking', desc: 'Site frame icine alinabilir.' });

        headers.forEach(h => {
            const name = h.name.toLowerCase();
            const val = h.value;
            const parts = val.split(/[\/\s]/);
            const techName = parts[0];
            const techVer = parts[1] || 'Unknown';

            if (name === 'server') detectedHeaders[tabId].push({ name: techName, version: techVer, source: 'Header: Server' });
            if (name === 'x-powered-by') detectedHeaders[tabId].push({ name: techName, version: techVer, source: 'Header: X-Powered-By' });
            if (name === 'x-generator') detectedHeaders[tabId].push({ name: techName, version: techVer, source: 'Header: Generator' });
            
            if (name === 'set-cookie') {
                const c = val.split('=')[0].trim();
                if (c === 'JSESSIONID') detectedHeaders[tabId].push({ name: 'Java', version: 'Unknown', source: 'Cookie: Java' });
                if (c === 'PHPSESSID') detectedHeaders[tabId].push({ name: 'PHP', version: 'Unknown', source: 'Cookie: PHP' });
                if (c === 'csrftoken') detectedHeaders[tabId].push({ name: 'Django', version: 'Unknown', source: 'Cookie: Django' });
                if (c.includes('laravel_session')) detectedHeaders[tabId].push({ name: 'Laravel', version: 'Unknown', source: 'Cookie: Laravel' });
            }
        });
        securityReports[tabId] = security;
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

const detectedHeaders = {}; 
const securityReports = {}; 
const networkEndpoints = {}; 
let fullScanData = { active: false, queue: [], visited: new Set(), results: { secrets: [], tech: [], endpoints: [], matches: [] }, tabId: null };

// --- FULL SCAN MOTORU (BEAST MODE V2) ---
async function startFullScan(tabId, startUrl) {
    const url = new URL(startUrl);
    const domain = url.hostname;
    const baseDomain = domain.split('.').slice(-2).join('.');
    
    fullScanData = {
        active: true,
        queue: [startUrl],
        visited: new Set(),
        discoveredSubdomains: new Set([domain]),
        results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] },
        tabId: tabId,
        baseDomain: baseDomain
    };

    // 1. ADIM: Gizli Yollari Bul (Robots.txt)
    try {
        const robots = await fetch(url.origin + "/robots.txt").then(r => r.text());
        const disallowed = robots.match(/Disallow: \s*(\/[^\s#]+)/g);
        if (disallowed) {
            disallowed.forEach(p => {
                const path = p.replace('Disallow:', '').trim();
                if (path.length > 1) fullScanData.queue.push(url.origin + path);
            });
        }
    } catch(e) {}
    
    processNextInQueue();
}

async function processNextInQueue() {
    if (!fullScanData.active || fullScanData.queue.length === 0 || fullScanData.visited.size > 150) { // Max 150 sayfa
        fullScanData.active = false;
        chrome.runtime.sendMessage({ action: "FULL_SCAN_COMPLETE", data: fullScanData.results });
        return;
    }

    const nextUrl = fullScanData.queue.shift();
    if (fullScanData.visited.has(nextUrl)) return processNextInQueue();
    
    // Alt Alan Adi (Subdomain) Kesfi ve Otomatik Probe
    try {
        const u = new URL(nextUrl);
        if (!fullScanData.discoveredSubdomains.has(u.hostname)) {
            fullScanData.discoveredSubdomains.add(u.hostname);
            // Yeni subdomain bulundu! Kritik dosyalari hemen yokla
            const miniTargets = ['/.env', '/.git/config', '/backup.zip', '/.npmrc'];
            miniTargets.forEach(t => fullScanData.queue.unshift(u.origin + t));
        }
    } catch(e) {}

    fullScanData.visited.add(nextUrl);
    chrome.tabs.update(fullScanData.tabId, { url: nextUrl });
    chrome.runtime.sendMessage({ action: "FULL_SCAN_PROGRESS", current: fullScanData.visited.size, total: fullScanData.queue.length + fullScanData.visited.size });
}

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    if (request.action === "START_FULL_SCAN") {
        startFullScan(request.tabId, request.url);
    }

    if (request.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech, endpoints, candidates, links } = request.data;
        
        // Full Scan Aktifse Verileri Birleştir
        if (fullScanData.active && fullScanData.tabId === tabId) {
            if (links) {
                links.forEach(l => {
                    try {
                        const u = new URL(l);
                        if (u.hostname.endsWith(fullScanData.baseDomain) && !fullScanData.visited.has(l)) {
                            if (!fullScanData.queue.includes(l)) fullScanData.queue.push(l);
                        }
                    } catch(e) {}
                });
            }

            fullScanData.results.secrets.push(...secrets);
            fullScanData.results.tech.push(...tech);
            fullScanData.results.endpoints.push(...endpoints);
            // Bir sonraki sayfaya geç
            setTimeout(processNextInQueue, 2000); // 2 saniye bekleme (WAF koruması)
        }

        if (networkEndpoints[tabId]) {
            endpoints = Array.from(new Set([...endpoints, ...Array.from(networkEndpoints[tabId])]));
        }

        const matches = []; const seen = new Set();
        if (detectedHeaders[tabId]) tech = [...tech, ...detectedHeaders[tabId]];
        const security = securityReports[tabId] || [];

        try {
            const url = new URL(sender.tab.url);
            const domain = url.hostname;
            if (!globalThis.scannedDomains) globalThis.scannedDomains = new Set();
            if (!globalThis.scannedDomains.has(domain)) {
                globalThis.scannedDomains.add(domain);
                
                (async () => {
                    // --- SOFT 404 (YALANCI SUNUCU) KONTROLÜ ---
                    const honeyPot = await fetch(url.origin + "/defora_recon_honey_pot_" + Math.random(), { method: 'HEAD' });
                    if (honeyPot.status === 200) {
                        console.log("Sunucu Yalancı 200 dönüyor. Aktif tarama iptal.");
                        return; 
                    }

                    const targets = [
                        { path: '/.env', check: 'APP_KEY=' },
                        { path: '/.env.production', check: 'APP_KEY=' },
                        { path: '/.git/config', check: '[core]' },
                        { path: '/config.php.bak', check: '<?php' },
                        { path: '/backup.zip', check: '' },
                        { path: '/dump.sql', check: '' },
                        { path: '/phpinfo.php', check: 'System' }
                    ];

                    // Dinamik "x" Adaylarını Ekle
                    const exts = ['.zip', '.sql', '.bak', '.tar.gz'];
                    if (candidates) {
                        candidates.forEach(c => {
                            exts.forEach(ext => {
                                targets.push({ path: `/${c}${ext}`, check: '' });
                            });
                        });
                    }

                    for (const t of targets) {
                        try {
                            // Stealth: 400ms - 1200ms arası rastgele bekle
                            await new Promise(r => setTimeout(r, 400 + Math.random() * 800));
                            const resp = await fetch(url.origin + t.path, { method: 'HEAD', cache: 'no-store' });
                            if (resp.status === 200) {
                                const size = resp.headers.get('content-length');
                                if (size === null || parseInt(size) > 100) { 
                                    chrome.storage.local.get([`results_${tabId}`], (curr) => {
                                        let res = curr[`results_${tabId}`] || { secrets: [] };
                                        if(!res.secrets) res.secrets = [];
                                        const already = res.secrets.find(s => s.value === t.path + " bulundu!");
                                        if (!already) {
                                            res.secrets.push({ 
                                                type: "KRİTİK DOSYA", 
                                                value: t.path + " bulundu!", 
                                                source: "Active Scan",
                                                url: url.origin + t.path // Tam URL eklendi
                                            });
                                            chrome.action.setBadgeText({ text: "!", tabId: tabId });
                                            chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tabId });
                                            chrome.storage.local.set({ [`results_${tabId}`]: res });
                                        }
                                    });
                                }
                            }
                        } catch(err) { }
                    }
                })();
            }
        } catch(e) {}

        // TEKNOLOJİ EŞ ANLAMLI İSİMLERİ (NIST/CVE Eşleşmesi İçin)
        const techAliases = {
            'angular': ['angularjs', 'angular.js'],
            'react': ['reactjs', 'react_native'],
            'vue.js': ['vue', 'vuejs'],
            'jquery': ['jquery.js'],
            'bootstrap': ['bootstrap_framework'],
            'nodejs': ['node.js'],
            'wordpress': ['word_press'],
            'drupal': ['drupal_cms'],
            'magento': ['magento_commerce'],
            'nginx': ['nginx_server'],
            'apache': ['http_server']
        };

        // PARALEL TARAMA (TURBO MODE)
        const scanPromises = tech.flatMap(t => {
            let baseName = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '');
            if (!baseName) return [];
            
            // Kontrol edilecek tüm isimleri belirle (Orijinal + Aliaslar)
            const searchNames = [baseName, ...(techAliases[baseName] || [])];
            
            return searchNames.map(async (fullName) => {
                if (seen.has(fullName)) return null;
                seen.add(fullName);
                
                const shard = await getShard(fullName);
                if (shard && shard[fullName]) {
                    const v = t.version || "Unknown";
                    const found = shard[fullName].filter(item => isVulnerable(v, item.r));
                    if (found.length > 0) return { tech: t.name, version: v, exploits: found, source: t.source };
                }
                return null;
            });
        });

        const results = await Promise.all(scanPromises);
        results.filter(r => r !== null).forEach(r => matches.push(r));

        chrome.storage.local.set({ [`results_${tabId}`]: { secrets, matches, tech, security, endpoints, time: Date.now() } });
        const high = security.some(s => s.risk === 'HIGH');
        if (secrets.length > 0 || matches.length > 0 || high) {
            chrome.action.setBadgeText({ text: "!", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tabId });
        }
    }
});