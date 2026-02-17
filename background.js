// DEFORA RECON - THE BRAIN (V85 - BEAST MODE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
const SHARD_CACHE = new Map();
const MASTER_DATA = new Map(); // RAM Üzerinde Ölümsüz Veri
let CRAWLER = { active: false, queue: [], visited: new Set(), secrets: [], domain: "" };

const techAliases = {
    'angular': ['angularjs', 'angular.js'], 'react': ['reactjs'], 'vue.js': ['vue', 'vuejs'],
    'jquery': ['jquery.js'], 'bootstrap': ['bootstrap_framework']
};

const patterns = {
    "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi
};

// --- HIZLI ANALIZ MOTORU ---
async function getShard(name) {
    let p = name.substring(0, 2).toLowerCase(); if (p.length < 2) p += '_';
    p = p.replace(/[^a-z0-9]/g, '_');
    if (SHARD_CACHE.has(p)) return SHARD_CACHE.get(p);
    try { 
        const res = await fetch(`${BASE_URL}shard_${p}.json`);
        if (res.ok) { const j = await res.json(); SHARD_CACHE.set(p, j); return j; }
    } catch (e) {}
    return null;
}

function isVulnerable(v, rules) {
    if (!v || v === "Unknown") return false;
    const parse = (x) => String(x).replace(/[^0-9.]/g, '').split('.').map(Number);
    const comp = (a, b) => {
        const a1 = parse(a), b1 = parse(b);
        for(let i=0; i<Math.max(a1.length, b1.length); i++) {
            if((a1[i]||0) > (b1[i]||0)) return 1; if((a1[i]||0) < (b1[i]||0)) return -1;
        } return 0;
    };
    for(let r of rules) {
        if(r.exact && comp(v, r.exact) === 0) return true;
        let inside = true, has = false;
        if(r.sInc) { has=true; if(comp(v, r.sInc) < 0) inside=false; }
        if(r.eExc) { has=true; if(comp(v, r.eExc) >= 0) inside=false; }
        if(has && inside) return true;
    } return false;
}

// --- TRUE BACKGROUND SPIDER ---
async function startFullScan(tabId, url) {
    const u = new URL(url);
    CRAWLER = { active: true, tabId, domain: u.hostname, baseDomain: u.hostname.split('.').slice(-2).join('.'), queue: [url], visited: new Set(), secrets: [] };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    runSpider();
}

async function runSpider() {
    if(!CRAWLER.active || CRAWLER.queue.length === 0 || CRAWLER.visited.size >= 40) return finishScan();
    const target = CRAWLER.queue.shift();
    if(CRAWLER.visited.has(target)) return runSpider();
    CRAWLER.visited.add(target);
    chrome.storage.local.set({ scanProgress: Math.round((CRAWLER.visited.size / 40) * 100) });

    try {
        const resp = await fetch(target);
        const html = await resp.text();
        for(let [type, reg] of Object.entries(patterns)) {
            const matches = html.matchAll(reg);
            for(const m of matches) CRAWLER.secrets.push({ type, value: m[0], url: target });
        }
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if(links) links.forEach(m => {
            let l = m.match(/["']([^"']+)["']/)[1];
            if(l.startsWith('/')) l = new URL(target).origin + l;
            if(l.includes(CRAWLER.baseDomain) && !CRAWLER.visited.has(l)) CRAWLER.queue.push(l);
        });
    } catch(e) {}
    setTimeout(runSpider, 600);
}

function finishScan() {
    CRAWLER.active = false;
    chrome.storage.local.set({ fullScanActive: false, scanProgress: 100 });
    const unique = Array.from(new Set(CRAWLER.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    
    const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit</title><style>body{font-family:sans-serif;background:#fff;padding:50px;color:#111}.card{background:#f8fafc;padding:20px;border-radius:12px;border:1px solid #eee;margin-bottom:15px}code{background:#000;color:#0f0;padding:10px;display:block;border-radius:6px;word-break:break-all}</style></head><body><h1>Defora Recon Audit</h1><p>Target: ${CRAWLER.domain}</p><h2>Data Leaks</h2>${unique.map(s=>`<div class="card"><b>${s.type}</b><code>${s.value}</code><small>📍 ${new URL(s.url).pathname}</small></div>`).join('')}</body></html>`;
    
    const blob = "data:text/html;base64," + btoa(unescape(encodeURIComponent(reportHTML)));
    chrome.downloads.download({ url: blob, filename: `RECON_${CRAWLER.domain.replace(/\./g, '_')}.html` });
}

// --- MESSAGE ENGINE ---
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if(req.action === "START_FULL_SCAN") startFullScan(sender.tab.id, req.url);
    if(req.action === "GET_LIVE_DATA") { sendResponse(MASTER_DATA.get(req.tabId) || null); return true; }
    if(req.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech, endpoints } = req.data;
        
        (async () => {
            const matches = []; const seen = new Set();
            const scanTask = (tech || []).map(async t => {
                const clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                if(!clean || seen.has(clean)) return; seen.add(clean);
                const aliases = [clean, ...(techAliases[clean]||[])];
                for(const a of aliases) {
                    const shard = await getShard(a);
                    if(shard && shard[a]) {
                        const f = shard[a].filter(i => isVulnerable(t.version, i.r));
                        if(f.length) matches.push({ tech: clean.toUpperCase(), version: t.version, exploits: f });
                    }
                }
            });
            await Promise.all(scanTask);
            const final = { secrets, tech, matches, endpoints, security: MASTER_DATA.get(tabId)?.security || [], time: Date.now() };
            MASTER_DATA.set(tabId, final);
            chrome.storage.local.set({ [`results_${tabId}`]: final });
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: final });
        })();
    }
});

// --- LIVE NETWORK SENSOR ---
chrome.webRequest.onHeadersReceived.addListener((d) => {
    if(d.type !== 'main_frame') return;
    const security = []; const h = d.responseHeaders.map(x => x.name.toLowerCase());
    if(!h.includes('strict-transport-security')) security.push({ name: 'HSTS Eksik', risk: 'MEDIUM', desc: 'Güvenli bağlantı zorunlu değil.' });
    if(!h.includes('x-frame-options')) security.push({ name: 'Clickjacking', risk: 'HIGH', desc: 'Site bir frame içine gömülebilir.' });
    if(!MASTER_DATA.has(d.tabId)) MASTER_DATA.set(d.tabId, { security: [] });
    MASTER_DATA.get(d.tabId).security = security;
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);
