// DEFORA RECON - THE BRAIN (V71 - STABLE & SYNCED)
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
    "ID: UUID": /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi,
    "Dosya: Hassas": /[a-z0-9_\-\.]+\.(?:env|conf|bak|sql|ini|log|yaml|sh|old|zip|tar\.gz)/gi
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

const securityReports = {}; 
const detectedHeaders = {};
const networkEndpoints = {}; 
let fullScanData = { active: false, queue: [], visited: new Set(), results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] }, tabId: null };

async function startFullScan(tabId, startUrl) {
    const url = new URL(startUrl);
    fullScanData = {
        active: true, queue: [startUrl], visited: new Set(),
        results: { secrets: [], tech: [], endpoints: [], matches: [], security: [] },
        tabId: tabId, domain: url.hostname, baseDomain: url.hostname.split('.').slice(-2).join('.')
    };
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    processNextInQueue();
}

async function processNextInQueue() {
    if (!fullScanData.active || fullScanData.queue.length === 0 || fullScanData.visited.size > 50) {
        finishFullScan(); return;
    }
    const nextUrl = fullScanData.queue.shift();
    if (fullScanData.visited.has(nextUrl)) return processNextInQueue();
    fullScanData.visited.add(nextUrl);
    chrome.storage.local.set({ scanProgress: Math.round((fullScanData.visited.size / 50) * 100) });
    chrome.tabs.update(fullScanData.tabId, { url: nextUrl });
    setTimeout(processNextInQueue, 2500); 
}

function finishFullScan() {
    fullScanData.active = false;
    chrome.storage.local.set({ fullScanActive: false });
    chrome.runtime.sendMessage({ action: "UPDATE_UI", data: fullScanData.results });
    chrome.runtime.sendMessage({ action: "FULL_SCAN_COMPLETE", data: fullScanData.results });
}

chrome.runtime.onMessage.addListener(async (request, sender) => {
    if (request.action === "START_FULL_SCAN") startFullScan(request.tabId, request.url);
    if (request.action === "SCAN_RESULTS") {
        try {
            const tabId = sender.tab.id;
            let { secrets, tech, endpoints } = request.data;
            if (detectedHeaders[tabId]) tech = [...tech, ...detectedHeaders[tabId]];
            
            tech = (tech || []).map(t => {
                if(!t.name) return t;
                let clean = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '').trim();
                return { ...t, name: clean };
            }).filter(t => t && t.name);

            const matches = []; const seenTech = new Set();
            for (const t of tech) {
                if (seenTech.has(t.name)) continue;
                seenTech.add(t.name);
                const searchNames = [t.name, ...(techAliases[t.name] || [])];
                let allExploits = [];
                for (const fullName of searchNames) {
                    const shard = await getShard(fullName);
                    if (shard && shard[fullName]) {
                        allExploits.push(...shard[fullName].filter(item => isVulnerable(t.version, item.r)));
                    }
                }
                if (allExploits.length > 0) {
                    const unique = Array.from(new Map(allExploits.map(item => [item.id, item])).values());
                    matches.push({ tech: t.name, version: t.version || "Unknown", exploits: unique });
                }
            }

            const res = { secrets: secrets || [], matches, tech, security: securityReports[tabId] || [], endpoints: endpoints || [], time: Date.now() };
            
            if (fullScanData.active && fullScanData.tabId === tabId) {
                fullScanData.results.secrets.push(...res.secrets);
                fullScanData.results.tech.push(...res.tech);
                fullScanData.results.endpoints.push(...res.endpoints);
                fullScanData.results.matches.push(...res.matches);
            }

            chrome.storage.local.set({ [`results_${tabId}`]: res });
            chrome.runtime.sendMessage({ action: "UPDATE_UI", data: res }); // POPUP'I UYAR!
        } catch(e) { console.error(e); }
    }
});

chrome.webRequest.onHeadersReceived.addListener((details) => {
    if (details.type !== 'main_frame') return;
    const tabId = details.tabId;
    const headers = details.responseHeaders;
    const security = [];
    const hNames = headers.map(h => h.name.toLowerCase());
    if (!hNames.includes('strict-transport-security')) security.push({ risk: 'MEDIUM', name: 'HSTS Eksik', desc: 'HTTPS zorlanmiyor.' });
    if (!hNames.includes('content-security-policy')) security.push({ risk: 'MEDIUM', name: 'CSP Eksik', desc: 'XSS riski yuksek.' });
    if (!hNames.includes('x-frame-options')) security.push({ risk: 'HIGH', name: 'Clickjacking', desc: 'Site frame icine alinabilir.' });
    
    headers.forEach(h => {
        const name = h.name.toLowerCase();
        if (['server', 'x-powered-by'].includes(name)) {
            const parts = h.value.split(/[\/\s]/);
            if(!detectedHeaders[tabId]) detectedHeaders[tabId] = [];
            detectedHeaders[tabId].push({ name: parts[0], version: parts[1] || 'Unknown', source: `Header` });
        }
    });
    securityReports[tabId] = security;
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);