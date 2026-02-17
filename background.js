// DEFORA RECON - THE BRAIN (V102 - MULTI-STAGE ENGINE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
const SHARD_CACHE = new Map();
const techAliases = { 'angular': ['angularjs', 'angular.js'], 'react': ['reactjs'], 'vue.js': ['vue', 'vuejs'], 'jquery': ['jquery.js'], 'bootstrap': ['bootstrap_framework'] };
const patterns = { "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g, "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g, "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g, "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g, "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g, "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi };

async function getShard(name) {
    let p = name.substring(0, 2).toLowerCase(); if (p.length < 2) p += '_'; p = p.replace(/[^a-z0-9]/g, '_');
    if (SHARD_CACHE.has(p)) return SHARD_CACHE.get(p);
    try { const res = await fetch(`${BASE_URL}shard_${p}.json`); if (res.ok) { const j = await res.json(); SHARD_CACHE.set(p, j); return j; } } catch (e) {}
    return null;
}

function isVulnerable(v, rules) {
    if (!v || v === "Unknown") return false;
    const parse = (x) => String(x).replace(/[^0-9.]/g, '').split('.').map(Number);
    const comp = (a, b) => {
        const a1 = parse(a), b1 = parse(b);
        for(let i=0; i<Math.max(a1.length, b1.length); i++) { if((a1[i]||0) > (b1[i]||0)) return 1; if((a1[i]||0) < (b1[i]||0)) return -1; } return 0;
    };
    for(let r of rules) { if(r.exact && comp(v, r.exact) === 0) return true; let inside = true, has = false; if(r.sInc) { has=true; if(comp(v, r.sInc) < 0) inside=false; } if(r.eExc) { has=true; if(comp(v, r.eExc) >= 0) inside=false; } if(has && inside) return true; } return false;
}

// --- MESSAGE ENGINE ---
chrome.runtime.onMessage.addListener((req, sender) => {
    if(req.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        const { secrets, tech, endpoints } = req.data;
        
        // 1. ASAMA: Ham veriyi aninda kaydet ve Popup'i uyar (Sifir Gecikme)
        chrome.storage.local.get(`results_${tabId}`, (res) => {
            const current = res[`results_${tabId}`] || { security: [] };
            const fastData = { secrets, tech, endpoints, matches: [], security: current.security, time: Date.now(), scanning: true };
            chrome.storage.local.set({ [`results_${tabId}`]: fastData });
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: fastData });

            // 2. ASAMA: Arka planda agir zafiyet taramasini baslat
            (async () => {
                const matches = []; const seen = new Set();
                for(const t of (tech || [])) {
                    const clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                    if(!clean || seen.has(clean)) continue; seen.add(clean);
                    const aliases = [clean, ...(techAliases[clean]||[])];
                    for(const a of aliases) {
                        const shard = await getShard(a);
                        if(shard && shard[a]) {
                            const f = shard[a].filter(i => isVulnerable(t.version, i.r));
                            if(f.length) matches.push({ tech: clean.toUpperCase(), version: t.version, exploits: f });
                        }
                    }
                }
                // 3. ASAMA: Zafiyetler bitince veriyi guncelle
                const finalData = { ...fastData, matches, scanning: false };
                chrome.storage.local.set({ [`results_${tabId}`]: finalData });
                chrome.runtime.sendMessage({ action: "UPDATE_UI", data: finalData });
                
                if(matches.length || secrets.length) {
                    chrome.action.setBadgeText({ text: "!", tabId });
                    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
                }
            })();
        });
    }
});

// --- PERSISTENT SECURITY HEADERS ---
chrome.webRequest.onHeadersReceived.addListener((d) => {
    if(d.type !== 'main_frame') return;
    const security = []; const h = d.responseHeaders.map(x => x.name.toLowerCase());
    if(!h.includes('strict-transport-security')) security.push({ name: 'HSTS Eksik', risk: 'MEDIUM', desc: 'HTTPS zorlanmıyor.' });
    if(!h.includes('x-frame-options')) security.push({ name: 'Clickjacking', risk: 'HIGH', desc: 'Site frame içine alınabilir.' });
    
    chrome.storage.local.get(`results_${d.tabId}`, (res) => {
        const current = res[`results_${d.tabId}`] || { tech: [], secrets: [], endpoints: [], matches: [] };
        current.security = security;
        chrome.storage.local.set({ [`results_${d.tabId}`]: current });
    });
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);
