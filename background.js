// DEFORA RECON - THE BRAIN (V80 - PARALLEL BEAST ENGINE)
const BASE_URL = "https://emirhanyucelll.github.io/defora-recon/shards/";
let SHARD_CACHE = {};

const patterns = {
    "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
    "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
    "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
    "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
    "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
    "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi
};

async function getState() {
    const s = await chrome.storage.local.get('fullScanState');
    return s.fullScanState || { active: false, queue: [], visited: [], secrets: [], domain: "", baseDomain: "" };
}

async function saveState(state) {
    await chrome.storage.local.set({ fullScanState: state });
}

async function startFullScan(url) {
    const u = new URL(url);
    const state = {
        active: true, domain: u.hostname, baseDomain: u.hostname.split('.').slice(-2).join('.'),
        queue: [url], visited: [], secrets: []
    };
    await saveState(state);
    chrome.storage.local.set({ fullScanActive: true, scanProgress: 0 });
    
    // Paralel 5 Is Kolu Baslat
    for(let i=0; i<5; i++) runSpiderWorker();
}

async function runSpiderWorker() {
    let state = await getState();
    if (!state.active || state.queue.length === 0 || state.visited.length >= 50) {
        if (state.active && state.queue.length === 0) finishScan();
        return;
    }

    const current = state.queue.shift();
    if (!current || state.visited.includes(current)) {
        await saveState(state);
        return runSpiderWorker();
    }
    
    state.visited.push(current);
    await saveState(state);

    try {
        const resp = await fetch(current, { priority: 'high' });
        const html = await resp.text();

        // Hizli Regex Analizi
        for (let [type, reg] of Object.entries(patterns)) {
            const matches = html.matchAll(reg);
            for (const m of matches) state.secrets.push({ type, value: m[0], url: current });
        }

        // Link Madenciligi
        const links = html.match(/href=["'](\/[^"'>\s]+|https?:\/\/[^"'>\s]+)["']/gi);
        if (links) {
            links.forEach(m => {
                let l = m.match(/["']([^"']+)["']/)[1];
                if (l.startsWith('/')) l = new URL(current).origin + l;
                if (l.includes(state.baseDomain) && !state.visited.includes(l) && !state.queue.includes(l)) {
                    state.queue.push(l);
                }
            });
        }
        
        // Progress Update
        const prog = Math.min(100, Math.round((state.visited.length / 50) * 100));
        chrome.storage.local.set({ scanProgress: prog });

    } catch (e) {}

    await saveState(state);
    runSpiderWorker(); // Beklemeden bir sonrakine gec
}

async function finishScan() {
    let state = await getState();
    if (!state.active) return;
    state.active = false;
    await chrome.storage.local.set({ fullScanActive: false, scanProgress: 100 });
    
    const unique = Array.from(new Set(state.secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
    
    const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit - ${state.domain}</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #fdfdfd; padding: 50px; }
        .wrapper { max-width: 900px; margin: auto; background: #fff; padding: 40px; border-radius: 16px; box-shadow: 0 4px 30px rgba(0,0,0,0.05); }
        h1 { color: #1e3a8a; border-bottom: 2px solid #3b82f6; padding-bottom: 15px; margin-bottom: 30px; }
        .item { background: #f8fafc; border: 1px solid #edf2f7; padding: 15px; border-radius: 10px; margin-bottom: 10px; }
        code { background: #0f172a; color: #10b981; padding: 8px; display: block; border-radius: 6px; word-break: break-all; margin-top: 5px; font-family: monospace; }
    </style></head>
    <body><div class="wrapper"><h1>Audit Report: ${state.domain}</h1>
    <h2>🔍 Data Leaks</h2>${unique.map(s => `<div class="item"><b>${s.type}</b><code>${s.value}</code><small>📍 ${new URL(s.url).pathname}</small></div>`).join('') || 'Clear.'}
    </div></body></html>`;

    const blob = "data:text/html;base64," + btoa(unescape(encodeURIComponent(reportHTML)));
    chrome.downloads.download({ url: blob, filename: `AUDIT_${state.domain.replace(/\./g, '_')}.html` });
    await chrome.storage.local.remove('fullScanState');
}

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "START_FULL_SCAN") startFullScan(req.url);
    if (req.action === "GET_LIVE_DATA") {
        chrome.storage.local.get(`results_${req.tabId}`, (res) => { sendResponse(res[`results_${req.tabId}`] || null); });
        return true;
    }
});