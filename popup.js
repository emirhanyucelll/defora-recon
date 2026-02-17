// DEFORA RECON - HUD CONTROL (V73 - PRO REPORT & UI)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    async function loadData() {
        const result = await chrome.storage.local.get(`results_${tab.id}`);
        if (result[`results_${tab.id}`]) render(result[`results_${tab.id}`]);
    }

    loadData();

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI") render(msg.data);
        if (msg.action === "FULL_SCAN_COMPLETE") {
            alert("Full Site Audit Complete!");
            loadData();
        }
    });

    function render(data) {
        try {
            // Inventory
            const invList = document.getElementById('inventoryList');
            if(invList) invList.innerHTML = (data.tech || []).map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span>${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('');
            
            // Secrets
            const secList = document.getElementById('secretList');
            if(secList) secList.innerHTML = (data.secrets || []).map(s => `<div class="item-card" style="border-left:3px solid var(--danger);"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('');

            // Vulns
            const vulnList = document.getElementById('vulnList');
            if(vulnList) vulnList.innerHTML = (data.matches || []).map(m => `<div class="item-card"><div class="tech-title">${m.tech} ${m.version}</div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('');
        } catch(e) {}
    }

    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", url: tab.url });
            fullScanBtn.innerText = "AUDITING...";
            document.getElementById('scanProgress').style.display = 'block';
        });
    }

    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive && progressCount) progressCount.innerText = res.scanProgress + "%";
    }, 1000);

    // --- PRO AUDIT REPORT (MINIMALIST & SHIK) ---
    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            const res = await chrome.storage.local.get(`results_${tab.id}`);
            const d = res[`results_${tab.id}`];
            if (!d) return;
            const domain = new URL(tab.url).hostname;

            const reportHTML = `
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit - ${domain}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #111; padding: 60px; line-height: 1.6; }
                .container { max-width: 800px; margin: auto; }
                h1 { font-size: 32px; font-weight: 800; letter-spacing: -1px; margin-bottom: 10px; }
                .meta { color: #666; font-size: 14px; margin-bottom: 50px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
                h2 { font-size: 18px; font-weight: 700; margin-top: 40px; margin-bottom: 20px; color: #000; }
                .entry { margin-bottom: 25px; padding-bottom: 20px; border-bottom: 1px solid #f5f5f5; }
                .entry-title { font-weight: 700; font-size: 15px; margin-bottom: 5px; }
                .entry-val { font-family: "JetBrains Mono", monospace; font-size: 13px; color: #059669; background: #f0fdf4; padding: 10px; border-radius: 6px; word-break: break-all; }
                .cve-badge { display: inline-block; background: #fee2e2; color: #b91c1c; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 4px; margin-right: 5px; margin-top: 5px; }
                .footer { margin-top: 100px; font-size: 12px; color: #999; text-align: center; }
            </style></head>
            <body><div class="container">
                <h1>Audit Report</h1>
                <div class="meta">Target: <b>${domain}</b> &nbsp;|&nbsp; Date: ${new Date().toLocaleDateString()}</div>
                
                <h2>🛡️ Vulnerabilities</h2>
                ${(d.matches||[]).map(m => `<div class="entry"><div class="entry-title">${m.tech} ${m.version}</div>${m.exploits.map(ex => `<span class="cve-badge">${ex.id}</span>`).join('')}</div>`).join('') || 'None found.'}
                
                <h2>🔍 Leaked Data</h2>
                ${(d.secrets||[]).map(s => `<div class="entry"><div class="entry-title">${s.type}</div><div class="entry-val">${s.value}</div><small style="color:#999;">Found at: ${new URL(s.url).pathname}</small></div>`).join('') || 'None found.'}
                
                <div class="footer">Generated by Defora Recon Engine</div>
            </div></body></html>`;

            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url;
            a.download = `AUDIT_${domain.replace(/\./g, '_')}.html`; a.click();
        });
    }

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