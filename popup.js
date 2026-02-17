// DEFORA RECON - HUD CONTROL (V85 - LIGHTNING)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    // CANLI VERIYE BAGLAN
    function sync() {
        chrome.runtime.sendMessage({ action: "GET_LIVE_DATA", tabId: tab.id }, (data) => {
            if (data) render(data);
        });
    }
    sync();

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI" || msg.action === "FULL_SCAN_COMPLETE") render(msg.data);
    });

    function render(data) {
        if (!data) return;
        try {
            // Inventory
            const inv = document.getElementById('inventoryList');
            if(inv) inv.innerHTML = (data.tech || []).map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span>${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('');
            
            // Security
            const sec = document.getElementById('securityList');
            if(sec) {
                const sData = data.security || [];
                let score = 100;
                sec.innerHTML = sData.length ? sData.map(s => {
                    score -= (s.risk === 'HIGH' ? 20 : 10);
                    return `<div class="item-card" style="border-left:3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}"><strong>${s.name}</strong><br><small>${s.desc}</small></div>`;
                }).join('') : '<div class="empty-state">Analiz ediliyor...</div>';
                document.getElementById('securityScore').innerText = score + "/100";
            }

            // Secrets
            const sl = document.getElementById('secretList');
            if(sl) {
                document.getElementById('secretCount').innerText = (data.secrets || []).length;
                sl.innerHTML = (data.secrets || []).map(s => `<div class="item-card secret-card" style="border-left:3px solid var(--danger)"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('') || '<div class="empty-state">Temiz.</div>';
            }

            // Vulns
            const vl = document.getElementById('vulnList');
            if(vl) vl.innerHTML = (data.matches || []).map(m => `<div class="item-card"><div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('') || '<div class="empty-state">Zafiyet yok.</div>';
        } catch (e) {}
    }

    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", url: tab.url });
            fullScanBtn.innerText = "DENETLENİYOR...";
            document.getElementById('scanProgress').style.display = 'block';
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "GET_LIVE_DATA", tabId: tab.id }, (d) => {
                if (!d) { alert("Veri hazır değil!"); return; }
                const domain = new URL(tab.url).hostname;
                const score = document.getElementById('securityScore')?.innerText || "--";
                
                const reportHTML = `
                <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit - ${domain}</title>
                <style>
                    body { font-family: sans-serif; background: #f8fafc; padding: 50px; color: #1e293b; }
                    .box { max-width: 900px; margin: auto; background: #fff; padding: 40px; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
                    h1 { margin: 0; color: #2563eb; border-bottom: 2px solid #eee; padding-bottom: 10px; }
                    .item { background: #f1f5f9; padding: 15px; border-radius: 10px; margin-bottom: 15px; }
                    code { background: #111; color: #10b981; padding: 8px; display: block; border-radius: 6px; word-break: break-all; margin-top: 5px; font-family: monospace; }
                </style></head>
                <body><div class="box">
                    <h1>Defora Recon Audit</h1>
                    <p>Hedef: <b>${domain}</b> | Skor: <b>${score}</b></p>
                    <h2>🛡️ Zafiyetler</h2>
                    ${(d.matches||[]).map(m => `<div class="item"><b>${m.tech} ${m.version}</b><br>${m.exploits.map(ex => ex.id).join(', ')}</div>`).join('') || 'Temiz.'}
                    <h2>🔍 Sızıntılar</h2>
                    ${(d.secrets||[]).map(s => `<div class="item"><b>${s.type}</b><code>${s.value}</code></div>`).join('') || 'Temiz.'}
                </div></body></html>`;

                const blob = new Blob([reportHTML], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url;
                a.download = `RECON_${domain.replace(/\./g, '_')}.html`; a.click();
            });
        });
    }

    // Progress Check
    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive) {
            if(progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
            fullScanBtn.disabled = true;
        } else {
            fullScanBtn.innerText = "FULL SCAN";
            fullScanBtn.disabled = false;
            document.getElementById('scanProgress').style.display = 'none';
        }
    }, 1000);

    // Tab Switcher
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById(`tab-${btn.dataset.tab}`);
            if (target) target.classList.add('active');
        });
    });
});