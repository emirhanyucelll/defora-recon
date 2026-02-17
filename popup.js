// DEFORA RECON - HUD CONTROL (V102 - SMART UI)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const exportBtn = document.getElementById('exportReport');

    // VERİLERİ YÜKLE
    async function load() {
        const res = await chrome.storage.local.get(`results_${tab.id}`);
        const data = res[`results_${tab.id}`];
        if (data) render(data);
    }
    load();

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI") render(msg.data);
    });

    function render(data) {
        if (!data) return;
        try {
            // 1. ENVANTER
            const inv = document.getElementById('inventoryList');
            if(inv) inv.innerHTML = (data.tech || []).map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span>${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('') || '<div class="empty-state">Aranıyor...</div>';
            
            // 2. GUVENLIK
            const sec = document.getElementById('securityList');
            if(sec) {
                const sData = data.security || [];
                let score = 100;
                sec.innerHTML = sData.length ? sData.map(s => {
                    score -= (s.risk === 'HIGH' ? 20 : 10);
                    return `<div class="item-card" style="border-left:3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}"><strong>${s.name}</strong><br><small>${s.desc}</small></div>`;
                }).join('') : '<div class="empty-state">Sıkılaştırma Aktif.</div>';
                document.getElementById('securityScore').innerText = score + "/100";
            }

            // 3. SIZINTILAR
            const sl = document.getElementById('secretList');
            if(sl) {
                document.getElementById('secretCount').innerText = (data.secrets || []).length;
                sl.innerHTML = (data.secrets || []).map(s => `<div class="item-card secret-card" style="border-left:3px solid var(--danger)"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('') || '<div class="empty-state">Temiz.</div>';
            }

            // 4. ZAFIYETLER (LOADING STATE)
            const vl = document.getElementById('vulnList');
            if(vl) {
                if (data.scanning) {
                    vl.innerHTML = '<div class="empty-state">NIST Arsenal taranıyor...</div>';
                } else {
                    const matches = data.matches || [];
                    vl.innerHTML = matches.length ? matches.map(m => `<div class="item-card"><div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('') : '<div class="empty-state">Zafiyet yok.</div>';
                }
            }
        } catch (e) {}
    }

    // --- PREMIUM AUDIT REPORT ---
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
                body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f8fafc; color: #1e293b; padding: 50px; }
                .report { max-width: 1000px; margin: auto; background: #fff; border-radius: 20px; box-shadow: 0 20px 50px rgba(0,0,0,0.05); overflow: hidden; border: 1px solid #e2e8f0; }
                .hero { background: #1e293b; color: white; padding: 60px; display: flex; justify-content: space-between; align-items: center; }
                .score-badge { background: #3b82f6; padding: 15px 30px; border-radius: 12px; font-weight: 900; font-size: 24px; }
                .section { padding: 50px; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; }
                h2 { font-size: 13px; text-transform: uppercase; color: #64748b; letter-spacing: 2px; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; margin-bottom: 20px; }
                .item { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 12px; margin-bottom: 15px; }
                .code { font-family: monospace; background: #0f172a; color: #34d399; padding: 12px; border-radius: 8px; margin-top: 10px; word-break: break-all; }
            </style></head>
            <body><div class="report">
                <div class="hero"><h1>Defora Recon Audit</h1><div class="score-badge">${score}</div></div>
                <div class="section">
                    <p>Hedef: <b>${domain}</b> | Tarih: ${new Date().toLocaleString()}</p>
                    <div class="grid">
                        <div><h2>🛡️ Zafiyetler</h2>${(d.matches||[]).map(m=>`<div class="item"><b>${m.tech} ${m.version}</b><br>${m.exploits.map(ex=>`<span style="color:red;font-size:11px;margin-right:5px;">${ex.id}</span>`).join('')}</div>`).join('') || 'Temiz.'}</div>
                        <div><h2>🔍 Sızıntılar</h2>${(d.secrets||[]).map(s=>`<div class="item"><b>${s.type}</b><div class="code">${s.value}</div></div>`).join('') || 'Temiz.'}</div>
                    </div>
                </div>
            </div></body></html>`;

            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = `AUDIT_${domain.replace(/\./g, '_')}.html`; a.click();
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