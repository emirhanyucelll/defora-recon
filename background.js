// DEFORA RECON - THE BRAIN (V73 - SILENT SPIDER & PRO REPORT)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

const techAliases = {
    'angular': ['angularjs', 'angular.js'],
    'react': ['reactjs'],
    'vue.js': ['vue', 'vuejs'],
    'jquery': ['jquery.js'],
    'bootstrap': ['bootstrap_framework']
};

const patterns = {
    "Cloud: AWS": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi
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

// --- SILENT FULL SCAN ENGINE ---
let scanStatus = { active: false, queue: [], visited: new Set(), results: { secrets: [], matches: [] }, domain: "" };

async function startFullScan(tabId, startUrl) {
    const url = new URL(startUrl);
    scanStatus = {
        active: true, queue: [startUrl], visited: new Set(),
        results: { secrets: [], matches: [] },
        domain: url.hostname, baseDomain: url.hostname.split('.').slice(-2).join('.')
    };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    runSilentSpider();
}

async function runSilentSpider() {
    if (!scanStatus.active || scanStatus.queue.length === 0 || scanStatus.visited.size > 100) {
        finishScan(); return;
    }

    const currentUrl = scanStatus.queue.shift();
    if (scanStatus.visited.has(currentUrl)) return runSilentSpider();
    scanStatus.visited.add(currentUrl);

    // Progress Update
    const progress = Math.round((scanStatus.visited.size / (scanStatus.queue.length + scanStatus.visited.size)) * 100);
    chrome.storage.local.set({ scanProgress: progress });

    try {
        const resp = await fetch(currentUrl);
        const html = await resp.text();

        // 1. Sızıntı Analizi
        for (let [type, regex] of Object.entries(patterns)) {
            const matches = html.matchAll(regex);
            for (const m of matches) {
                scanStatus.results.secrets.push({ type, value: m[0], url: currentUrl });
            }
        }

        // 2. Link Toplama (Kuyruğa ekle)
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if (links) {
            links.forEach(m => {
                let l = m.match(/["']([^"']+)["']/)[1];
                if (l.startsWith('/')) l = new URL(currentUrl).origin + l;
                if (l.includes(scanStatus.baseDomain) && !scanStatus.visited.has(l)) scanStatus.queue.push(l);
            });
        }
    } catch(e) {}

    setTimeout(runSilentSpider, 500); // 0.5 saniye bekle (Hızlı tarama)
}

function finishScan() {
    scanStatus.active = false;
    chrome.storage.local.set({ fullScanActive: false });
    chrome.runtime.sendMessage({ action: "FULL_SCAN_COMPLETE", data: scanStatus.results });
}

chrome.runtime.onMessage.addListener(async (request, sender) => {
    if (request.action === "START_FULL_SCAN") startFullScan(sender.tab.id, request.url);
    if (request.action === "SCAN_RESULTS") {
        try {
            const tabId = sender.tab.id;
            let { secrets, tech, endpoints } = request.data;
            
            // Teknoloji ve Zafiyet Analizi (Single Page - Turbo)
            const matches = []; const seenTech = new Set();
            tech = tech.map(t => {
                let clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                return { ...t, name: clean };
            });

            for (const t of tech) {
                if (seenTech.has(t.name)) continue;
                seenTech.add(t.name);
                const searchNames = [t.name, ...(techAliases[t.name] || [])];
                for (const name of searchNames) {
                    const shard = await getShard(name);
                    if (shard && shard[name]) {
                        const found = shard[name].filter(item => isVulnerable(t.version, item.r));
                        if(found.length > 0) matches.push({ tech: t.name, version: t.version, exploits: found });
                    }
                }
            }

            const currentRes = { secrets, matches, tech, endpoints, time: Date.now() };
            chrome.storage.local.set({ [`results_${tabId}`]: currentRes });
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: currentRes });
        } catch(e) {}
    }
});