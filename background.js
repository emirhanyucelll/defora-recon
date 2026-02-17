// DEFORA RECON - THE BRAIN (V81 - REPAIRED & STABLE ENGINE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};
let TAB_RESULTS = {}; // Bellekteki canli veriler
let SCAN_JOB = { active: false, queue: [], visited: new Set(), secrets: [], domain: "", tabId: null };

const patterns = {
    "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "ID: UUID": /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi
};

// --- YARDIMCI FONKSIYONLAR ---
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

// --- FULL SCAN MOTORU (SIRALI VE SAGLAM) ---
async function startFullScan(tabId, url) {
    const u = new URL(url);
    SCAN_JOB = {
        active: true, tabId: tabId, domain: u.hostname,
        baseDomain: u.hostname.split('.').slice(-2).join('.'),
        queue: [url], visited: new Set(), secrets: []
    };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    runSpider();
}

async function runSpider() {
    if (!SCAN_JOB.active || SCAN_JOB.queue.length === 0 || SCAN_JOB.visited.size >= 40) {
        return finishScan();
    }

    const current = SCAN_JOB.queue.shift();
    if (SCAN_JOB.visited.has(current)) return runSpider();
    SCAN_JOB.visited.add(current);

    // Progress update
    const prog = Math.round((SCAN_JOB.visited.size / 40) * 100);
    chrome.storage.local.set({ scanProgress: prog });

    try {
        const resp = await fetch(current);
        const html = await resp.text();

        // Sızıntı Analizi
        for (let [type, reg] of Object.entries(patterns)) {
            const matches = html.matchAll(reg);
            for (const m of matches) SCAN_JOB.secrets.push({ type, value: m[0], url: current });
        }

        // Link Toplama
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if (links) links.forEach(m => {
            let l = m.match(/["']([^"']+)["']/)[1];
            if (l.startsWith('/')) l = new URL(current).origin + l;
            if (l.includes(SCAN_JOB.baseDomain) && !SCAN_JOB.visited.has(l)) SCAN_JOB.queue.push(l);
        });
    } catch (e) {}

    setTimeout(runSpider, 800);
}

function finishScan() {
    SCAN_JOB.active = false;
    chrome.storage.local.set({ fullScanActive: false, scanProgress: 100 });
    
    const unique = Array.from(new Set(SCAN_JOB.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    
    const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit Report</title>
    <style>body{font-family:sans-serif; background:#f8fafc; padding:50px;} .box{background:#fff; padding:40px; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.05); max-width:850px; margin:auto;} h1{color:#1e3a8a; border-bottom:2px solid #eee; padding-bottom:10px;} .item{background:#f1f5f9; padding:15px; border-radius:10px; margin-bottom:10px;} code{background:#111; color:#10b981; padding:8px; display:block; border-radius:6px; word-break:break-all; margin-top:5px; font-family:monospace;}</style></head>
    <body><div class="box"><h1>Audit: ${SCAN_JOB.domain}</h1>
    <h2>🔍 Sızıntılar</h2>${unique.map(s => `<div class="item"><b>${s.type}</b><code>${s.value}</code><small>Yol: ${new URL(s.url).pathname}</small></div>`).join('') || 'Temiz.'}
    </div></body></html>`;

    const blob = "data:text/html;base64," + btoa(unescape(encodeURIComponent(reportHTML)));
    chrome.downloads.download({ url: blob, filename: `AUDIT_${SCAN_JOB.domain.replace(/\./g, '_')}.html` });
}

// --- MESAJ DINLEYICI ---
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "START_FULL_SCAN") startFullScan(sender.tab.id, req.url);
    if (req.action === "GET_LIVE_DATA") {
        sendResponse(TAB_RESULTS[req.tabId] || null);
        return true;
    }
    if (req.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech, endpoints } = req.data;
        
        (async () => {
            const matches = []; const seen = new Set();
            for (const t of (tech || [])) {
                let clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                if (!clean || seen.has(clean)) continue; seen.add(clean);
                const shard = await getShard(clean);
                if (shard && shard[clean]) {
                    const f = shard[clean].filter(i => isVulnerable(t.version, i.r));
                    if (f.length) matches.push({ tech: clean.toUpperCase(), version: t.version, exploits: f });
                }
            }
            const data = { secrets, tech, matches, endpoints, time: Date.now() };
            TAB_RESULTS[tabId] = data;
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: data });
        })();
    }
});
