// DEFORA RECON - THE BRAIN (V67 - ULTIMATE STEALTH & BACKGROUND ENGINE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

const techAliases = {
    'angular': ['angularjs', 'angular.js'],
    'react': ['reactjs', 'react_native'],
    'vue.js': ['vue', 'vuejs'],
    'jquery': ['jquery.js', 'jquery-min.js'],
    'bootstrap': ['bootstrap_framework'],
    'nodejs': ['node.js'],
    'wordpress': ['word_press'],
    'drupal': ['drupal_cms'],
    'nginx': ['nginx_server'],
    'apache': ['http_server']
};

const patterns = {
    "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "ID: UUID (Potansiyel Sızıntı)": /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi,
    "Dosya: Hassas": /[a-z0-9_\-\.]+\.(?:env|conf|bak|sql|ini|log|yaml|sh|old|zip|tar\.gz)/gi
};

// --- YARDIMCI FONKSIYONLAR ---
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

function isVulnerable(detected, rules) {
    if (!detected || ["0.0.0", "Unknown", "Detected"].includes(detected)) return false;
    const parseV = (v) => v.toString().replace(/[^0-9.]/g, '').split('.').map(Number);
    const compare = (v1, v2) => {
        const a = parseV(v1); const b = parseV(v2);
        for (let i = 0; i < Math.max(a.length, b.length); i++) {
            if ((a[i] || 0) > (b[i] || 0)) return 1;
            if ((a[i] || 0) < (b[i] || 0)) return -1;
        }
        return 0;
    };
    for (let r of rules) {
        if (r.exact && compare(detected, r.exact) === 0) return true;
        let inside = true; let hasLogic = false;
        if (r.sInc) { hasLogic = true; if (compare(detected, r.sInc) < 0) inside = false; }
        if (r.eExc) { hasLogic = true; if (compare(detected, r.eExc) >= 0) inside = false; }
        if (hasLogic && inside) return true;
    }
    return false;
}

let fullScanData = { active: false, queue: [], visited: new Set(), results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] }, domain: "" };

// --- TRUE BACKGROUND SCAN ENGINE ---
async function startFullScan(tabId, startUrl) {
    const url = new URL(startUrl);
    fullScanData = {
        active: true, queue: [startUrl], visited: new Set(),
        results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] },
        domain: url.hostname, baseDomain: url.hostname.split('.').slice(-2).join('.')
    };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    processNextInQueue();
}

async function processNextInQueue() {
    if (!fullScanData.active || fullScanData.queue.length === 0 || fullScanData.visited.size > 50) {
        finishFullScan();
        return;
    }

    const nextUrl = fullScanData.queue.shift();
    if (fullScanData.visited.has(nextUrl)) return processNextInQueue();
    fullScanData.visited.add(nextUrl);

    // Update Progress
    const progress = Math.round((fullScanData.visited.size / (fullScanData.queue.length + fullScanData.visited.size)) * 100);
    chrome.storage.local.set({ scanProgress: progress });

    try {
        // GERCEK ARKA PLAN TARAMASI (Sekmeye dokunmadan)
        const resp = await fetch(nextUrl);
        const html = await resp.text();
        
        // 1. Sızıntı Analizi (Regex)
        for (let [type, regex] of Object.entries(patterns)) {
            const matches = html.matchAll(regex);
            for (const m of matches) {
                fullScanData.results.secrets.push({ type, value: m[0], url: nextUrl });
            }
        }

        // 2. Link Madenciliği
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if (links) {
            links.forEach(m => {
                let l = m.match(/["']([^"']+)["']/)[1];
                if (l.startsWith('/')) l = new URL(nextUrl).origin + l;
                if (l.includes(fullScanData.baseDomain) && !fullScanData.visited.has(l)) fullScanData.queue.push(l);
            });
        }
    } catch(e) {}

    setTimeout(processNextInQueue, 1000);
}

function finishFullScan() {
    fullScanData.active = false;
    chrome.storage.local.set({ fullScanActive: false });
    generateAndDownloadReport();
}

async function generateAndDownloadReport() {
    const d = fullScanData.results;
    const domain = fullScanData.domain;
    
    // Verileri Unique yap
    const uniqueSecrets = Array.from(new Set(d.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    
    const secretHTML = uniqueSecrets.map(s => `
        <div class="card">
            <div style="display:flex; justify-content:space-between;">
                <span class="badge warn">${s.type}</span>
                <small style="color:#888;">📍 ${new URL(s.url).pathname}</small>
            </div>
            <div class="code-snippet">${s.value}</div>
        </div>`).join('');

    const reportHTML = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>Defora Audit - ${domain}</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #f9fafb; color: #1f2937; padding: 50px; }
        .wrapper { max-width: 900px; margin: auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
        .header { border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #1e3a8a; }
        .card { background: #f8fafc; border: 1px solid #e5e7eb; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
        .badge { font-size: 10px; font-weight: bold; padding: 4px 8px; border-radius: 4px; text-transform: uppercase; }
        .warn { background: #fef3c7; color: #92400e; }
        .code-snippet { font-family: monospace; background: #111827; color: #10b981; padding: 10px; border-radius: 6px; margin-top: 8px; word-break: break-all; }
    </style></head>
    <body><div class="wrapper"><div class="header"><h1>Defora Recon Audit</h1><p>Hedef: ${domain}</p></div>
    <h2>Sızıntı Bulguları</h2>${secretHTML || 'Bulunamadı'}</div></body></html>`;

    const blob = "data:text/html;base64," + btoa(unescape(encodeURIComponent(reportHTML)));
    chrome.downloads.download({
        url: blob,
        filename: `DEFORA_AUDIT_${domain.replace(/\./g, '_')}.html`
    });
}

// Mesaj Dinleyicisi (Teknoloji Temizleme Dahil)
chrome.runtime.onMessage.addListener(async (request, sender) => {
    if (request.action === "START_FULL_SCAN") startFullScan(request.tabId, request.url);
    if (request.action === "SCAN_RESULTS") {
        try {
            const tabId = sender.tab.id;
            let { secrets, tech, endpoints } = request.data;
            
            // ISIM VE VERSION TEMIZLEME
            tech = tech.map(t => {
                let clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                return { ...t, name: clean };
            });

            const matches = []; const seenTech = new Set();
            for (const t of tech) {
                if (!t.name || seenTech.has(t.name)) continue;
                seenTech.add(t.name);
                const searchNames = [t.name, ...(techAliases[t.name] || [])];
                let allExploits = [];
                for (const fullName of searchNames) {
                    const shard = await getShard(fullName);
                    if (shard && shard[fullName]) {
                        const found = shard[fullName].filter(item => isVulnerable(t.version, item.r));
                        allExploits.push(...found);
                    }
                }
                if (allExploits.length > 0) {
                    const unique = Array.from(new Map(allExploits.map(item => [item.id, item])).values());
                    matches.push({ tech: t.name, version: t.version, exploits: unique });
                }
            }
            chrome.storage.local.set({ [`results_${tabId}`]: { secrets, matches, tech, endpoints, time: Date.now() } });
        } catch(e) {}
    }
});
