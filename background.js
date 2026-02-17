// DEFORA RECON - THE BRAIN (V90 - REBORN & STABLE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

const patterns = {
    "Cloud: AWS": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi
};

// --- YARDIMCI FONKSİYONLAR ---
async function getShard(name) {
    let p = name.substring(0, 2).toLowerCase(); if (p.length < 2) p += '_';
    p = p.replace(/[^a-z0-9]/g, '_');
    if (SHARD_CACHE[p]) return SHARD_CACHE[p];
    try { const res = await fetch(`${BASE_URL}shard_${p}.json`); if (res.ok) { SHARD_CACHE[p] = await res.json(); return SHARD_CACHE[p]; } } catch (e) {}
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

// --- FULL SCAN ---
let spider = { active: false, queue: [], visited: new Set(), secrets: [], domain: "", tabId: null };

async function startFullScan(tabId, url) {
    const u = new URL(url);
    spider = { active: true, tabId, domain: u.hostname, queue: [url], visited: new Set(), secrets: [] };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    runSpider();
}

async function runSpider() {
    if(!spider.active || spider.queue.length === 0 || spider.visited.size >= 30) {
        finishSpider(); return;
    }
    const current = spider.queue.shift();
    if(spider.visited.has(current)) return runSpider();
    spider.visited.add(current);
    chrome.storage.local.set({ scanProgress: Math.round((spider.visited.size / 30) * 100) });

    try {
        const resp = await fetch(current);
        const html = await resp.text();
        // Sızıntıları Ayıkla
        for(let [type, reg] of Object.entries(patterns)) {
            const matches = html.matchAll(reg);
            for(const m of matches) spider.secrets.push({ type, value: m[0], url: current });
        }
        // Linkleri Topla
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if(links) links.forEach(m => {
            let l = m.match(/["']([^"']+)["']/)[1];
            if(l.startsWith('/')) l = new URL(current).origin + l;
            if(l.includes(spider.domain) && !spider.visited.has(l)) spider.queue.push(l);
        });
    } catch(e) {}
    setTimeout(runSpider, 800);
}

function finishSpider() {
    spider.active = false;
    chrome.storage.local.set({ fullScanActive: false });
    const unique = Array.from(new Set(spider.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    
    const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit</title><style>body{font-family:sans-serif;background:#fff;padding:50px;} .card{background:#f8fafc;padding:15px;border-radius:10px;border:1px solid #eee;margin-bottom:10px;} code{background:#000;color:#0f0;padding:8px;display:block;border-radius:6px;word-break:break-all;}</style></head>
    <body><h1>Defora Audit: ${spider.domain}</h1>${unique.map(s=>`<div class="card"><b>${s.type}</b><code>${s.value}</code><small>Yol: ${new URL(s.url).pathname}</small></div>`).join('')}</body></html>`;
    
    const blob = "data:text/html;base64," + btoa(unescape(encodeURIComponent(reportHTML)));
    chrome.downloads.download({ url: blob, filename: `RECON_${spider.domain.replace(/\./g, '_')}.html` });
}

// --- MESSAGE LISTENERS ---
chrome.runtime.onMessage.addListener(async (req, sender) => {
    if (req.action === "START_FULL_SCAN") startFullScan(sender.tab.id, req.url);
    if (req.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech, endpoints } = req.data;
        
        const matches = []; const seen = new Set();
        for(const t of (tech || [])) {
            const clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
            if(!clean || seen.has(clean)) continue; seen.add(clean);
            const shard = await getShard(clean);
            if(shard && shard[clean]) {
                const f = shard[clean].filter(i => isVulnerable(t.version, i.r));
                if(f.length) matches.push({ tech: clean.toUpperCase(), version: t.version, exploits: f });
            }
        }
        chrome.storage.local.set({ [`results_${tabId}`]: { secrets, tech, matches, endpoints, time: Date.now() } });
        chrome.runtime.sendMessage({ action: "UPDATE_UI" });
    }
});