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

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    if (request.action === "SCAN_RESULTS") {
        const tabId = sender.tab.id;
        let { secrets, tech } = request.data;
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
                    const targets = [
                        { path: '/.env', check: 'APP_KEY=' },
                        { path: '/.git/HEAD', check: 'ref: refs/' },
                        { path: '/.vscode/sftp.json', check: '"host":' }
                    ];
                    for (const t of targets) {
                        try {
                            await new Promise(r => setTimeout(r, 1000 + Math.random() * 2000));
                            const resp = await fetch(url.origin + t.path, { method: 'GET', cache: 'no-store' });
                            if (resp.status === 200) {
                                const text = await resp.text();
                                if (text.includes(t.check)) {
                                    chrome.storage.local.get([`results_${tabId}`], (curr) => {
                                        let res = curr[`results_${tabId}`] || { secrets: [] };
                                        if(!res.secrets) res.secrets = [];
                                        const already = res.secrets.find(s => s.value === t.path + " exposed!");
                                        if (!already) {
                                            res.secrets.push({ type: "CRITICAL FILE", value: t.path + " exposed!", source: "Active Scan" });
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

        for (const t of tech) {
            let fullName = t.name.toLowerCase().replace(/(\.min)?\.js$/, '').replace(/[-_.]?v?\d+(\.\d+)*.*/, '');
            if (!fullName || seen.has(fullName)) continue; seen.add(fullName);
            
            const shard = await getShard(fullName);
            if (shard && shard[fullName]) {
                const v = t.version || "Unknown";
                const found = shard[fullName].filter(item => isVulnerable(v, item.r));
                if (found.length > 0) matches.push({ tech: t.name, version: v, exploits: found, source: t.source });
            }
        }

        chrome.storage.local.set({ [`results_${tabId}`]: { secrets, matches, tech, security, time: Date.now() } });
        const high = security.some(s => s.risk === 'HIGH');
        if (secrets.length > 0 || matches.length > 0 || high) {
            chrome.action.setBadgeText({ text: "!", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tabId });
        }
    }
});