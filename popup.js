// DEFORA RECON - TACTICAL HUD CONTROL (V61 - STABILIZED)
document.addEventListener('DOMContentLoaded', async () => {
    const secretList = document.getElementById('secretList');
    const vulnList = document.getElementById('vulnList');
    const riskBadge = document.getElementById('riskBadge');
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const result = await chrome.storage.local.get(`results_${tab.id}`);
    const data = result ? result[`results_${tab.id}`] : null;

    if (data) render(data);

    function render(data) {
        // --- ENVANTER ---
        const inventoryList = document.getElementById('inventoryList');
        inventoryList.innerHTML = "";
        const allTech = data.tech || [];
        document.getElementById('inventoryCount').innerText = allTech.length;
        if (allTech.length > 0) {
            allTech.forEach(t => {
                const div = document.createElement('div');
                div.className = "item-card";
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="tech-name-highlight">${t.name}</span>
                        <span class="tech-version-pill">${t.version}</span>
                    </div>
                `;
                inventoryList.appendChild(div);
            });
        } else {
             inventoryList.innerHTML = '<div class="empty-state">Teknoloji tespit edilemedi.</div>';
        }

        // --- GÜVENLİK ---
        const securityList = document.getElementById('securityList');
        securityList.innerHTML = "";
        const securityData = data.security || [];
        let score = 100;
        if (securityData.length > 0) {
            securityData.forEach(s => {
                if(s.risk === 'HIGH') score -= 20;
                if(s.risk === 'MEDIUM') score -= 10;
                if(s.risk === 'LOW') score -= 5;
                const div = document.createElement('div');
                div.className = "item-card";
                div.style.borderLeft = `3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : (s.risk === 'MEDIUM' ? 'var(--warning)' : 'var(--accent)')}`;
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:900; color:#fff; font-size:0.8rem;">${s.name}</span>
                        <span style="font-size:0.6rem; color:${s.risk === 'HIGH' ? 'var(--danger)' : (s.risk === 'MEDIUM' ? 'var(--warning)' : 'var(--accent)')}">${s.risk}</span>
                    </div>
                    <div style="font-size:0.7rem; color:var(--text-dim); margin-top:4px;">${s.desc}</div>
                `;
                securityList.appendChild(div);
            });
        }
        document.getElementById('securityScore').innerText = score + "/100";

        // --- SIZINTILAR & BULGULAR ---
        secretList.innerHTML = "";
        const allSecrets = data.secrets || [];
        document.getElementById('secretCount').innerText = allSecrets.length;
        
        if (allSecrets.length > 0) {
            allSecrets.forEach(s => {
                const div = document.createElement('div');
                div.className = "item-card secret-card";
                let color = "var(--accent)";
                if (s.type.includes("Kritik") || s.type.includes("Parola") || s.type.includes("Dosya")) color = "var(--danger)";
                if (s.type.includes("Yorum")) color = "var(--warning)";

                let path = "/";
                try { if(s.url) path = new URL(s.url).pathname; } catch(e) {}

                div.style.borderLeft = `3px solid ${color}`;
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                        <span class="secret-label" style="background:${color}22; color:${color}; border:1px solid ${color}44;">${s.type}</span>
                        <span style="font-size:0.55rem; color:var(--accent); opacity:0.9; font-weight:bold;">📍 ${path}</span>
                    </div>
                    <div class="secret-content" style="color:#eee; font-weight:bold; word-break: break-all;">${s.value}</div>
                `;
                secretList.appendChild(div);
            });
            riskBadge.innerText = "DANGER";
            riskBadge.className = "status-badge status-danger";
        } else {
            secretList.innerHTML = '<div class="empty-state">Hassas veri sızıntısı bulunamadı.</div>';
        }

        // --- ATTACK SURFACE (ENDPOINTS) ---
        const endpointList = document.getElementById('endpointList');
        if (endpointList) {
            endpointList.innerHTML = "";
            const endpoints = data.endpoints || [];
            if (endpoints.length > 0) {
                endpoints.forEach(e => {
                    const div = document.createElement('div');
                    div.className = "item-card";
                    div.style.fontSize = "0.75rem";
                    div.innerHTML = `<span style="color:var(--accent);">🔗</span> ${e}`;
                    endpointList.appendChild(div);
                });
            } else {
                endpointList.innerHTML = '<div class="empty-state">Dış bağlantı bulunamadı.</div>';
            }
        }

        // --- ZAFİYETLER ---
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
            riskBadge.innerText = "DANGER";
            riskBadge.className = "status-badge status-danger";
        } else {
            vulnList.innerHTML = '<div class="empty-state">Kritik tehdit tespit edilmedi.</div>';
        }
    }

    // --- REPORT EXPORTER ---
    const exportBtn = document.getElementById('exportReport');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            if (!data) return;
            const domain = new URL(tab.url).hostname;
            const score = document.getElementById('securityScore').innerText;
            
            const vulnHTML = (data.matches || []).map(m => `
                <div class="report-card">
                    <div class="report-card-title">${m.tech} <small>${m.version}</small></div>
                    <div class="tag-container">
                        ${m.exploits.map(ex => `<span class="badge badge-danger">${ex.id}</span>`).join('')}
                    </div>
                </div>
            `).join('');

            const secretHTML = (data.secrets || []).map(s => {
                let p = "/"; try { if(s.url) p = new URL(s.url).pathname; } catch(e) {}
                return `
                <div class="report-card">
                    <div style="display:flex; justify-content:space-between; align-items:start;">
                        <span class="badge badge-warning">${s.type}</span>
                        <span style="font-size:0.7rem; color:#888;">📍 ${p}</span>
                    </div>
                    <div style="font-family:monospace; background:#1a1a1a; color:#0f0; padding:8px; border-radius:4px; margin-top:8px; word-break:break-all; font-size:0.85rem; border:1px solid #333;">${s.value}</div>
                </div>`;
            }).join('');

            const endpointHTML = (data.endpoints || []).map(e => `<div class="endpoint-item">🔗 ${e}</div>`).join('');

            const reportHTML = `
            <!DOCTYPE html>
            <html lang="tr">
            <head>
                <meta charset="UTF-8">
                <title>Recon Report - ${domain}</title>
                <style>
                    :root { --bg: #0a0a0a; --card: #141414; --text: #e0e0e0; --accent: #2563eb; --danger: #ef4444; --warning: #f59e0b; }
                    body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; margin: 0; padding: 40px; }
                    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                    h1 { margin: 0; font-size: 1.5rem; letter-spacing: -0.5px; }
                    .score-box { text-align: right; }
                    .score-val { font-size: 2rem; font-weight: 900; color: var(--accent); }
                    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 25px; }
                    .section { margin-bottom: 40px; }
                    h2 { font-size: 1rem; text-transform: uppercase; color: #888; border-left: 3px solid var(--accent); padding-left: 10px; margin-bottom: 20px; }
                    .report-card { background: var(--card); border: 1px solid #222; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
                    .report-card-title { font-weight: 700; margin-bottom: 10px; }
                    .badge { font-size: 0.7rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }
                    .badge-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
                    .badge-warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
                    .tech-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
                    .tech-item { background: var(--card); border: 1px solid #222; padding: 10px; border-radius: 6px; font-size: 0.85rem; }
                    .endpoint-list { background: var(--card); border: 1px solid #222; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.8rem; display: grid; grid-template-columns: 1fr 1fr; gap: 5px; }
                    .endpoint-item { color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                    footer { margin-top: 60px; border-top: 1px solid #333; padding-top: 20px; text-align: center; color: #555; font-size: 0.8rem; }
                </style>
            </head>
            <body>
                <div class="header">
                    <div>
                        <h1>Defora Recon | Analiz Raporu</h1>
                        <div style="color:#666; font-size:0.9rem;">Hedef: <strong>${domain}</strong></div>
                    </div>
                    <div class="score-box">
                        <div style="font-size:0.7rem; color:#888;">GÜVENLİK PUANI</div>
                        <div class="score-val">${score}</div>
                        <div style="font-size:0.7rem; color:#555;">${new Date().toLocaleString()}</div>
                    </div>
                </div>
                <div class="grid">
                    <div class="section">
                        <h2>Zafiyet Taraması</h2>
                        ${vulnHTML || '<div class="report-card">✓ Zafiyet bulunamadı.</div>'}
                    </div>
                    <div class="section">
                        <h2>Veri Sızıntıları</h2>
                        ${secretHTML || '<div class="report-card">✓ Sızıntı bulunamadı.</div>'}
                    </div>
                </div>
                <div class="section">
                    <h2>Saldırı Yüzeyi</h2>
                    <div class="endpoint-list">${endpointHTML || 'Bağlantı bulunamadı.'}</div>
                </div>
                <footer>Defora Recon tarafından otomatik oluşturulmuştur.</footer>
            </body>
            </html>`;

            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `RECON_REPORT_${domain.replace(/\./g, '_')}.html`;
            a.click();
        });
    }

    // --- TAB SWITCHER ---
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });
});