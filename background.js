// DEFORA RECON - THE BRAIN (V76 - ENTERPRISE STABLE & TRUE STEALTH)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};
let TAB_DATA = {}; 
let FULL_SCAN_STATE = { active: false, queue: [], visited: new Set(), results: null, progress: 0, tabId: null, domain: "" };

const techAliases = {
    'angular': ['angularjs', 'angular.js'], 'react': ['reactjs'], 'vue.js': ['vue', 'vuejs'],
    'jquery': ['jquery.js'], 'bootstrap': ['bootstrap_framework'], 'nginx': ['nginx_server'], 'apache': ['http_server']
};

const patterns = {
    "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google API": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi,
    "Dosya: Hassas": /[a-z0-9_\-\.]+\.(?:env|conf|bak|sql|ini|log|yaml|sh|old|zip|tar\.gz)/gi
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
    if (!v || ["0.0.0", "Unknown"].includes(v)) return false;
    const parse = (x) => x.toString().replace(/[^0-9.]/g, '').split('.').map(Number);
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

// --- FULL SCAN ENGINE (FETCH BASED - WON'T STOP ON NAVIGATE) ---
async function startFullScan(tabId, url) {
    const u = new URL(url);
    FULL_SCAN_STATE = {
        active: true, tabId: tabId, domain: u.hostname,
        baseDomain: u.hostname.split('.').slice(-2).join('.'),
        queue: [url], visited: new Set(),
        results: { secrets: [], matches: [], tech: [], security: [], endpoints: new Set() }
    };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    runSpider();
}

async function runSpider() {
    if(!FULL_SCAN_STATE.active || FULL_SCAN_STATE.queue.length === 0 || FULL_SCAN_STATE.visited.size >= 40) {
        return finishScan();
    }
    const target = FULL_SCAN_STATE.queue.shift();
    if(FULL_SCAN_STATE.visited.has(target)) return runSpider();
    FULL_SCAN_STATE.visited.add(target);

    FULL_SCAN_STATE.progress = Math.round((FULL_SCAN_STATE.visited.size / 40) * 100);
    chrome.storage.local.set({ scanProgress: FULL_SCAN_STATE.progress });

    try {
        const resp = await fetch(target);
        const html = await resp.text();
        
        // Sızıntı Analizi
        for(let [type, reg] of Object.entries(patterns)) {
            const matches = html.matchAll(reg);
            for(const m of matches) FULL_SCAN_STATE.results.secrets.push({ type, value: m[0], url: target });
        }

        // Link Toplama
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if(links) links.forEach(m => {
            let l = m.match(/["']([^"']+)["']/)[1];
            if(l.startsWith('/')) l = new URL(target).origin + l;
            if(l.includes(FULL_SCAN_STATE.baseDomain) && !FULL_SCAN_STATE.visited.has(l)) FULL_SCAN_STATE.queue.push(l);
        });
    } catch(e) {}
    setTimeout(runSpider, 800);
}

function finishScan() {
    FULL_SCAN_STATE.active = false;
    chrome.storage.local.set({ fullScanActive: false, scanProgress: 100 });
    const d = FULL_SCAN_STATE.results;
    d.secrets = Array.from(new Set(d.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    chrome.storage.local.set({ [`results_${FULL_SCAN_STATE.tabId}`]: d });
    chrome.runtime.sendMessage({ action: "FULL_SCAN_COMPLETE", data: d });
}

// --- MESSAGE LISTENERS ---
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if(req.action === "START_FULL_SCAN") startFullScan(sender.tab.id, req.url);
    if(req.action === "GET_LIVE_DATA") {
        chrome.storage.local.get(`results_${req.tabId}`, (res) => {
            sendResponse(res[`results_${req.tabId}`] || null);
        });
        return true; 
    }
    if(req.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech, endpoints } = req.data;
        (async () => {
            const matches = []; const seen = new Set();
            for(const t of (tech||[])) {
                const name = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                if(!name || seen.has(name)) continue; seen.add(name);
                const aliases = [name, ...(techAliases[name]||[])];
                for(const a of aliases) {
                    const shard = await getShard(a);
                    if(shard && shard[a]) {
                        const f = shard[a].filter(i => isVulnerable(t.version, i.r));
                        if(f.length) matches.push({ tech: t.name, version: t.version, exploits: f });
                    }
                }
            }
            const finalData = { secrets, tech, matches, endpoints, security: TAB_DATA[tabId]?.security || [], time: Date.now() };
            chrome.storage.local.set({ [`results_${tabId}`]: finalData });
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: finalData });
            if(matches.length || secrets.length) {
                chrome.action.setBadgeText({ text: "!", tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
            }
        })();
    }
});

chrome.webRequest.onHeadersReceived.addListener((d) => {
    if(d.type !== 'main_frame') return;
    const security = []; const h = d.responseHeaders.map(x => x.name.toLowerCase());
    if(!h.includes('strict-transport-security')) security.push({ name: 'HSTS Eksik', risk: 'MEDIUM', desc: 'Güvensiz baglanti riski.' });
    if(!h.includes('x-frame-options')) security.push({ name: 'Clickjacking', risk: 'HIGH', desc: 'Site frame icine alinabilir.' });
    TAB_DATA[d.tabId] = { security: security };
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);