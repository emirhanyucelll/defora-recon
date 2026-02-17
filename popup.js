// DEFORA RECON - HUD CONTROL (V70 - FINAL STABLE)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    async function updateDisplay() {
        const result = await chrome.storage.local.get(`results_${tab.id}`);
        const data = result[`results_${tab.id}`];
        if (data) render(data);
    }

    updateDisplay();

    function render(data) {
        try {
            // --- ENVANTER ---
            const invList = document.getElementById('inventoryList');
            if (invList) {
                invList.innerHTML = "";
                const techs = data.tech || [];
                document.getElementById('inventoryCount').innerText = techs.length;
                techs.forEach(t => {
                    const div = document.createElement('div');
                    div.className = "item-card";
                    div.innerHTML = `<div style="display:flex; justify-content:space-between;">
                        <span class="tech-name-highlight">${t.name}</span>
                        <span class="tech-version-pill">${t.version || '...'}</span>
                    </div>`;
                    invList.appendChild(div);
                });
            }

            // --- GÜVENLİK ---
            const secList = document.getElementById('securityList');
            if (secList) {
                secList.innerHTML = "";
                const secs = data.security || [];
                let score = 100;
                secs.forEach(s => {
                    if(s.risk === 'HIGH') score -= 20; else score -= 10;
                    const div = document.createElement('div');
                    div.className = "item-card";
                    div.style.borderLeft = `3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}`;
                    div.innerHTML = `<strong>${s.name}</strong> <small>(${s.risk})</small><br><span style="font-size:0.7rem; color:#888;">${s.desc}</span>`;
                    secList.appendChild(div);
                });
                document.getElementById('securityScore').innerText = score + "/100";
            }

            // --- SIZINTILAR ---
            const secretList = document.getElementById('secretList');
            if (secretList) {
                secretList.innerHTML = "";
                const secrets = data.secrets || [];
                document.getElementById('secretCount').innerText = secrets.length;
                secrets.forEach(s => {
                    const div = document.createElement('div');
                    div.className = "item-card secret-card";
                    div.innerHTML = `<span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div>`;
                    secretList.appendChild(div);
                });
            }

            // --- ZAFİYETLER ---
            const vulnList = document.getElementById('vulnList');
            if (vulnList) {
                vulnList.innerHTML = "";
                const matches = data.matches || [];
                if (matches.length > 0) {
                    matches.forEach(m => {
                        const div = document.createElement('div');
                        div.className = "item-card";
                        const tags = m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ');
                        div.innerHTML = `<div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div>
                            <div class="cve-list">${tags}</div>`;
                        vulnList.appendChild(div);
                    });
                } else { vulnList.innerHTML = '<div class="empty-state">Kritik tehdit yok.</div>'; }
            }
        } catch(e) { console.error("UI Render Error:", e); }
    }

    // --- FULL SCAN ---
    fullScanBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "START_FULL_SCAN", tabId: tab.id, url: tab.url });
        fullScanBtn.innerText = "SCANNING...";
        document.getElementById('scanProgress').style.display = 'block';
    });

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "FULL_SCAN_COMPLETE") {
            fullScanBtn.innerText = "FULL SCAN";
            document.getElementById('scanProgress').style.display = 'none';
            render(msg.data);
        }
    });

    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive && progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
    }, 1000);

    // --- EXPORT ---
    exportBtn.addEventListener('click', async () => {
        const res = await chrome.storage.local.get(`results_${tab.id}`);
        const d = res[`results_${tab.id}`];
        if (!d) return;
        const domain = new URL(tab.url).hostname;
        
        const vulnHTML = (d.matches || []).map(m => `<div style="padding:15px; background:#f8fafc; border:1px solid #eee; border-radius:8px; margin-bottom:15px;">
            <strong>${m.tech} ${m.version}</strong><br><div style="margin-top:5px;">${m.exploits.map(ex => `<span style="background:#fee2e2; color:#dc2626; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:700; border:1px solid #fecaca; margin-right:4px;">${ex.id}</span>`).join('')}</div></div>`).join('');

        const secretHTML = (d.secrets || []).map(s => `<div style="padding:15px; background:#fff7ed; border:1px solid #fed7aa; border-radius:8px; margin-bottom:15px;">
            <div style="font-size:12px; font-weight:800; color:#9a3412; margin-bottom:5px;">${s.type}</div><code style="word-break:break-all; font-family:monospace; background:#111; color:#10b981; padding:8px; display:block; border-radius:4px;">${s.value}</code></div>`).join('');

        const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit - ${domain}</title>
        <style>body{font-family: sans-serif; background:#f3f4f6; color:#1f2937; padding:50px;} .box{background:#fff; padding:40px; border-radius:16px; max-width:900px; margin:auto; box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);}</style>
        </head><body><div class="box"><h1>Defora Recon Audit</h1><p>Hedef: <strong>${domain}</strong></p>
        <h2 style="color:#6b7280; font-size:14px; text-transform:uppercase; margin-top:40px; border-bottom:1px solid #eee; padding-bottom:10px;">Zafiyet Bulguları</h2>${vulnHTML || 'Temiz'}
        <h2 style="color:#6b7280; font-size:14px; text-transform:uppercase; margin-top:40px; border-bottom:1px solid #eee; padding-bottom:10px;">Sızıntı Analizi</h2>${secretHTML || 'Temiz'}
        <footer style="margin-top:50px; text-align:center; font-size:12px; color:#aaa;">Defora Recon Engine</footer>
        </div></body></html>`;

        const blob = new Blob([reportHTML], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url;
        a.download = `RECON_${domain.replace(/\./g, '_')}.html`; a.click();
    });

    // --- TABS ---
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });
});