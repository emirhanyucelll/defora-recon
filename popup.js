// DEFORA RECON - HUD CONTROL (V76 - PREMIUM & STABLE)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    // CANLI VERI SENKRONU
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
                }).join('') : '<div class="empty-state">Güvenli.</div>';
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

    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive && progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
        else if(fullScanBtn.innerText === "DENETLENİYOR...") {
            fullScanBtn.innerText = "FULL SCAN";
            document.getElementById('scanProgress').style.display = 'none';
        }
    }, 1000);

    // --- PREMIUM DONANIMLI RAPOR ---
    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            const res = await chrome.storage.local.get(`results_${tab.id}`);
            const d = res[`results_${tab.id}`];
            if (!d) return;
            const domain = new URL(tab.url).hostname;
            const score = document.getElementById('securityScore').innerText;

            const reportHTML = `
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit - ${domain}</title>
            <style>
                body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 40px; line-height: 1.6; }
                .report { max-width: 1000px; margin: auto; background: #fff; border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.1); overflow: hidden; border: 1px solid #e2e8f0; }
                .hero { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); color: white; padding: 60px; display: flex; justify-content: space-between; align-items: center; }
                .hero h1 { margin: 0; font-size: 36px; font-weight: 900; letter-spacing: -1.5px; }
                .score-card { background: #3b82f6; padding: 20px 40px; border-radius: 16px; text-align: center; box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.5); }
                .section { padding: 50px; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; }
                h2 { font-size: 13px; text-transform: uppercase; color: #64748b; letter-spacing: 2px; margin-bottom: 25px; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; display: flex; align-items: center; }
                .item { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 16px; margin-bottom: 20px; }
                .badge { font-size: 10px; font-weight: 800; padding: 5px 12px; border-radius: 6px; text-transform: uppercase; background: #fee2e2; color: #ef4444; margin-top: 10px; display: inline-block; }
                .code { font-family: 'JetBrains Mono', monospace; background: #0f172a; color: #34d399; padding: 15px; border-radius: 10px; font-size: 13px; margin-top: 12px; word-break: break-all; border: 1px solid #1e293b; }
                footer { background: #f8fafc; padding: 30px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
            </style></head>
            <body><div class="report">
                <div class="hero">
                    <div><h1>Defora Recon</h1><p style="opacity:0.6; font-size:18px;">Security Audit Report for <b>${domain}</b></p></div>
                    <div class="score-card"><div style="font-size:11px; opacity:0.8; font-weight:700;">OVERALL SCORE</div><div style="font-size:32px; font-weight:900;">${score}</div></div>
                </div>
                <div class="section">
                    <div class="grid">
                        <div>
                            <h2>🛡️ Vulnerabilities</h2>
                            ${(d.matches||[]).map(m => `<div class="item"><b>${m.tech} ${m.version}</b><br>${m.exploits.map(ex => `<span class="badge">${ex.id}</span>`).join('')}</div>`).join('') || 'Clear.'}
                        </div>
                        <div>
                            <h2>🔍 Data Leaks</h2>
                            ${(d.secrets||[]).map(s => `<div class="item"><b>${s.type}</b><div class="code">${s.value}</div><small style="color:#94a3b8;">📍 ${s.url ? new URL(s.url).pathname : '/'}</small></div>`).join('') || 'None.'}
                        </div>
                    </div>
                </div>
                <footer>Generated by Defora Recon Intelligence Engine • ${new Date().toLocaleString()}</footer>
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