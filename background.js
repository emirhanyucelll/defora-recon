// DEFORA RECON - THE BRAIN (V65 - STEALTH & AGGREGATED)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

// --- TEKNOLOJİ SÖZLÜĞÜ (CVE EŞLEŞMESİ İÇİN) ---
const techAliases = {
    'angular': ['angularjs', 'angular.js'],
    'react': ['reactjs', 'react_native'],
    'vue.js': ['vue', 'vuejs'],
    'jquery': ['jquery.js', 'jquery-min.js'],
    'bootstrap': ['bootstrap_framework', 'bootstrap.css'],
    'nodejs': ['node.js'],
    'wordpress': ['word_press'],
    'drupal': ['drupal_cms'],
    'magento': ['magento_commerce'],
    'nginx': ['nginx_server'],
    'apache': ['http_server']
};

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
const networkEndpoints = {}; 
let fullScanData = { active: false, queue: [], visited: new Set(), results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] }, tabId: null };

// --- FULL SCAN MOTORU (STEALTH MODE) ---
async function startFullScan(tabId, startUrl) {
    const url = new URL(startUrl);
    fullScanData = {
        active: true, queue: [startUrl], visited: new Set(),
        results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] },
        tabId: tabId, baseDomain: url.hostname.split('.').slice(-2).join('.')
    };
    
    // Robots.txt kontrolü
    try {
        const robots = await fetch(url.origin + "/robots.txt").then(r => r.text());
        const disallowed = robots.match(/Disallow: \s*(\/[^\s#]+)/g);
        if (disallowed) disallowed.forEach(p => fullScanData.queue.push(url.origin + p.replace('Disallow:', '').trim()));
    } catch(e) {}

    processNextInQueue();
}

async function processNextInQueue() {
    if (!fullScanData.active || fullScanData.queue.length === 0 || fullScanData.visited.size > 100) {
        fullScanData.active = false;
        chrome.runtime.sendMessage({ action: "FULL_SCAN_COMPLETE", data: fullScanData.results });
        return;
    }

    const nextUrl = fullScanData.queue.shift();
    if (fullScanData.visited.has(nextUrl)) return processNextInQueue();
    fullScanData.visited.add(nextUrl);

    // ARKA PLANDA SESSİZ FETCH
    try {
        const resp = await fetch(nextUrl);
        const html = await resp.text();
        
        // Linkleri ve Subdomainleri Topla
        const linkMatches = html.match(/href=["'](https?:\/\/[^"']+)["']/gi);
        if (linkMatches) {
            linkMatches.forEach(m => {
                const l = m.match(/https?:\/\/[^"']+/i)[0];
                if (l.includes(fullScanData.baseDomain) && !fullScanData.visited.has(l)) fullScanData.queue.push(l);
            });
        }

        // Arka Planda Geçici Analiz Yap ve Sonuçları Birleştir
        // Not: Gerçek analiz content.js tetiklendiğinde tab üzerinden daha sağlıklı yapılır
        // ama stealth modda fetch sonuçlarını da topluyoruz.
        
    } catch(e) {}

    chrome.runtime.sendMessage({ action: "FULL_SCAN_PROGRESS", current: fullScanData.visited.size, total: fullScanData.queue.length + fullScanData.visited.size });
    setTimeout(processNextInQueue, 1500);
}

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    if (request.action === "START_FULL_SCAN") startFullScan(request.tabId, request.url);

    if (request.action === "SCAN_RESULTS") {
        try {
            const tabId = sender.tab.id;
            let { secrets, tech, endpoints, candidates, links } = request.data;
            
            // Veri Birleştirme (Aggregations)
            if (fullScanData.active && fullScanData.tabId === tabId) {
                fullScanData.results.secrets.push(...secrets);
                fullScanData.results.tech.push(...tech);
                fullScanData.results.endpoints.push(...endpoints);
            }

            if (networkEndpoints[tabId]) endpoints = Array.from(new Set([...endpoints, ...Array.from(networkEndpoints[tabId])]));

            const matches = []; 
            const seenTech = new Set();

            if (detectedHeaders[tabId]) tech = [...tech, ...detectedHeaders[tabId]];
            const security = securityReports[tabId] || [];

            // --- GELİŞMİŞ ZAFİYET EŞLEŞTİRME (CVE & GHSA BİRLEŞTİRİCİ) ---
            for (const t of tech) {
                let baseName = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '');
                if (!baseName || seenTech.has(baseName)) continue;
                seenTech.add(baseName);

                const searchNames = [baseName, ...(techAliases[baseName] || [])];
                let allExploits = [];
                let detectedVersion = t.version || "Unknown";

                for (const fullName of searchNames) {
                    const shard = await getShard(fullName);
                    if (shard && shard[fullName]) {
                        const found = shard[fullName].filter(item => isVulnerable(detectedVersion, item.r));
                        allExploits.push(...found);
                    }
                }

                if (allExploits.length > 0) {
                    // ID'leri Benzersiz Yap (Unique)
                    const uniqueExploits = Array.from(new Map(allExploits.map(item => [item.id, item])).values());
                    matches.push({ tech: t.name, version: detectedVersion, exploits: uniqueExploits, source: t.source });
                }
            }

            chrome.storage.local.set({ [`results_${tabId}`]: { secrets, matches, tech, security, endpoints, time: Date.now() } });
        } catch (e) {}
    }
});

// Headers Dinleyicisi (Aynen Kaldi)
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.tabId < 0) return;
    try {
        const url = new URL(details.url);
        if (!networkEndpoints[details.tabId]) networkEndpoints[details.tabId] = new Set();
        networkEndpoints[details.tabId].add(url.hostname);
    } catch(e) {}
}, { urls: ["<all_urls>"] });

chrome.webRequest.onHeadersReceived.addListener((details) => {
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
        if (['server', 'x-powered-by', 'x-generator'].includes(name)) {
            const parts = val.split(/[\/\s]/);
            detectedHeaders[tabId].push({ name: parts[0], version: parts[1] || 'Unknown', source: `Header: ${name}` });
        }
    });
    securityReports[tabId] = security;
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);
