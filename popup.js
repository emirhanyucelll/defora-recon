// DEFORA RECON - HUD CONTROL (V68 - REPAIRED & STABLE)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const scanProgress = document.getElementById('scanProgress');
    const progressCount = document.getElementById('progressCount');

    // Verileri Yükle ve Goster
    async function loadData() {
        const result = await chrome.storage.local.get(`results_${tab.id}`);
        const data = result[`results_${tab.id}`];
        if (data) render(data);
    }

    loadData();

    function render(data) {
        try {
            // --- ENVANTER ---
            const inventoryList = document.getElementById('inventoryList');
            if (inventoryList) {
                inventoryList.innerHTML = "";
                const allTech = data.tech || [];
                document.getElementById('inventoryCount').innerText = allTech.length;
                allTech.forEach(t => {
                    const div = document.createElement('div');
                    div.className = "item-card";
                    div.innerHTML = `<div style="display:flex; justify-content:space-between;">
                        <span class="tech-name-highlight">${t.name}</span>
                        <span class="tech-version-pill">${t.version || 'Detecting...'}</span>
                    </div>`;
                    inventoryList.appendChild(div);
                });
            }

            // --- SIZINTILAR ---
            const secretList = document.getElementById('secretList');
            if (secretList) {
                secretList.innerHTML = "";
                const allSecrets = data.secrets || [];
                document.getElementById('secretCount').innerText = allSecrets.length;
                allSecrets.forEach(s => {
                    const div = document.createElement('div');
                    div.className = "item-card secret-card";
                    let color = s.type.match(/(Kritik|Parola|Dosya)/) ? "var(--danger)" : "var(--accent)";
                    div.style.borderLeft = `3px solid ${color}`;
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                            <span class="secret-label" style="background:${color}22; color:${color}; border:1px solid ${color}44;">${s.type}</span>
                        </div>
                        <div class="secret-content" style="color:#eee; font-weight:bold; word-break:break-all;">${s.value}</div>
                    `;
                    secretList.appendChild(div);
                });
            }

            // --- ZAFİYETLER ---
            const vulnList = document.getElementById('vulnList');
            if (vulnList) {
                vulnList.innerHTML = "";
                if (data.matches && data.matches.length > 0) {
                    data.matches.forEach(m => {
                        const div = document.createElement('div');
                        div.className = "item-card";
                        const cveTags = m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ');
                        div.innerHTML = `
                            <div class="card-top">
                                <span class="tech-title">${m.tech} ${m.version}</span>
                                <span class="tech-count">${m.exploits.length} TEHDİT</span>
                            </div>
                            <div class="cve-list">${cveTags}</div>
                        `;
                        vulnList.appendChild(div);
                    });
                } else {
                    vulnList.innerHTML = '<div class="empty-state">Kritik tehdit bulunamadı.</div>';
                }
            }

            // --- DIS KAYNAKLAR ---
            const endpointList = document.getElementById('endpointList');
            if (endpointList) {
                endpointList.innerHTML = "";
                const endpoints = data.endpoints || [];
                endpoints.forEach(e => {
                    const div = document.createElement('div');
                    div.className = "item-card";
                    div.style.fontSize = "0.7rem";
                    div.innerHTML = `• ${e}`;
                    endpointList.appendChild(div);
                });
            }
        } catch (e) { console.error("Render Error:", e); }
    }

    // --- FULL SCAN ---
    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", tabId: tab.id, url: tab.url });
            fullScanBtn.innerText = "TARANIYOR...";
            fullScanBtn.disabled = true;
            if(scanProgress) scanProgress.style.display = 'block';
        });
    }

    // Progress Check
    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive) {
            if(progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
            if(scanProgress) scanProgress.style.display = 'block';
            fullScanBtn.disabled = true;
        } else {
            if(fullScanBtn.innerText === "TARANIYOR...") {
                fullScanBtn.innerText = "FULL SCAN";
                fullScanBtn.disabled = false;
                if(scanProgress) scanProgress.style.display = 'none';
                loadData(); // Biten tarama verilerini yukle
            }
        }
    }, 1000);

    // --- EXPORT REPORT (SHIK & AYDINLIK) ---
    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            const result = await chrome.storage.local.get(`results_${tab.id}`);
            const d = result[`results_${tab.id}`];
            if (!d) return;

            const domain = new URL(tab.url).hostname;
            const vulnHTML = (d.matches || []).map(m => `
                <div style="background:#f8fafc; border:1px solid #e2e8f0; padding:15px; border-radius:8px; margin-bottom:10px;">
                    <div style="font-weight:700; color:#1e293b;">${m.tech} <small style="color:#64748b;">${m.version}</small></div>
                    <div style="margin-top:8px;">${m.exploits.map(ex => `<span style="background:#fee2e2; color:#dc2626; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:700; border:1px solid #fecaca; margin-right:4px;">${ex.id}</span>`).join('')}</div>
                </div>`).join('');

            const secretHTML = (d.secrets || []).map(s => `
                <div style="background:#f8fafc; border:1px solid #e2e8f0; padding:15px; border-radius:8px; margin-bottom:10px;">
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:5px;">
                        <span style="font-weight:800; color:#1e293b;">${s.type}</span>
                        <span style="color:#3b82f6; font-family:monospace;">${s.url ? new URL(s.url).pathname : '/'}</span>
                    </div>
                    <div style="font-family:monospace; background:#111827; color:#10b981; padding:10px; border-radius:6px; font-size:13px; word-break:break-all;">${s.value}</div>
                </div>`).join('');

            const reportHTML = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>Audit - ${domain}</title>
            <style>
                body { font-family: sans-serif; background: #f3f4f6; color: #1f2937; padding: 40px; margin: 0; }
                .wrapper { max-width: 850px; margin: auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
                h1 { color: #1e3a8a; border-bottom: 2px solid #e5e7eb; padding-bottom: 15px; }
                h2 { font-size: 14px; text-transform: uppercase; color: #6b7280; margin-top: 30px; }
            </style></head>
            <body><div class="wrapper"><h1>Defora Recon Audit</h1><p>Hedef: ${domain}</p>
            <h2>🛡️ Zafiyetler</h2>${vulnHTML || 'Temiz'}
            <h2>🔍 Sızıntılar</h2>${secretHTML || 'Temiz'}
            </div></body></html>`;

            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `RECON_${domain.replace(/\./g, '_')}.html`;
            a.click();
        });
    }

    // --- TAB SWITCHER ---
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