// DEFORA RECON - TACTICAL HUD CONTROL (V60 - STABLE VERSION)
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
                // Kritiklik seviyesine göre renk belirle
                let color = "var(--accent)";
                if (s.type.includes("Kritik") || s.type.includes("Parola") || s.type.includes("Dosya")) color = "var(--danger)";
                if (s.type.includes("Yorum")) color = "var(--warning)";

                div.style.borderLeft = `3px solid ${color}`;
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                        <span class="secret-label" style="background:${color}22; color:${color}; border:1px solid ${color}44;">${s.type}</span>
                        ${s.url ? `<span style="font-size:0.55rem; color:var(--accent); opacity:0.7;">📍 ${new URL(s.url).pathname}</span>` : ''}
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
            
            // HTML yapısını önceden hazırla (Template Literal karmaşasını önlemek için)
            const vulnHTML = (data.matches || []).map(m => `
                <div class="item">
                    <div style="font-weight:bold; color:#111; margin-bottom:5px;">${m.tech} ${m.version}</div>
                    <div style="display:flex; gap:5px; flex-wrap:wrap;">
                        ${m.exploits.map(ex => `<span style="background:#fee2e2; color:#b91c1c; padding:2px 6px; border-radius:4px; font-size:0.8rem; font-weight:bold; border:1px solid #ef4444;">${ex.id}</span>`).join('')}
                    </div>
                    <div style="font-size:0.8rem; color:#666; margin-top:5px;">Kaynak: ${m.source}</div>
                </div>
            `).join('');

            const reportHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>RECON REPORT - ${domain}</title>
                <style>
                    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f7f6; color: #333; padding: 40px; line-height: 1.6; }
                    .report-header { border-bottom: 3px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
                    h1 { color: #111; margin: 0; font-size: 2rem; }
                    .section { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 25px; }
                    h2 { border-left: 5px solid #2563eb; padding-left: 15px; font-size: 1.4rem; color: #2563eb; margin-top: 0; }
                    .item { padding: 15px; border-bottom: 1px solid #eee; }
                    .item:last-child { border-bottom: none; }
                    .risk-HIGH { color: #ef4444; font-weight: bold; }
                    .risk-MEDIUM { color: #f59e0b; font-weight: bold; }
                    .label { font-size: 0.75rem; background: #e5e7eb; padding: 3px 8px; border-radius: 4px; font-weight: 600; text-transform: uppercase; }
                    code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; color: #e11d48; }
                    .tech-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }
                    .tech-item { background: #f8fafc; padding: 10px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 0.9rem; }
                </style>
            </head>
            <body>
                <div class="report-header">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h1>DEFORA RECON | İstihbarat Raporu</h1>
                        <div style="text-align:right">
                            <div style="font-weight:bold; font-size:1.2rem; color:#2563eb;">GÜVENLİK PUANI: ${document.getElementById('securityScore').innerText}</div>
                            <div style="font-size:0.8rem; color:#666;">${new Date().toLocaleString()}</div>
                        </div>
                    </div>
                    <p style="margin-top:15px; color:#444;">Hedef Alan Adı: <strong>${domain}</strong></p>
                </div>

                <div class="section">
                    <h2>1. Güvenlik Denetimi (Headers)</h2>
                    ${(data.security || []).map(s => `<div class="item"><span class="risk-${s.risk}">[${s.risk}]</span> <strong>${s.name}</strong>: ${s.desc}</div>`).join('') || '<p style="color:#10b981; padding:15px;">✓ Kritik yapılandırma hatası tespit edilmedi.</p>'}
                </div>

                <div class="section">
                    <h2>2. Bilinen Zafiyetler (CVE)</h2>
                    ${vulnHTML || '<p style="color:#10b981; padding:15px;">✓ Bilinen bir zafiyetli kütüphane tespit edilmedi.</p>'}
                </div>

                <div class="section">
                    <h2>3. Kritik Veri Sızıntıları</h2>
                    ${(data.secrets || []).map(s => `
                        <div class="item">
                            <span class="label">${s.type}</span> <code>${s.value}</code>
                            <div style="font-size:0.75rem; color:#888; margin-top:5px;">Konum: ${s.source}</div>
                        </div>
                    `).join('') || '<p style="color:#10b981; padding:15px;">✓ Herhangi bir API anahtarı veya parola sızıntısı bulunamadı.</p>'}
                </div>

                <div class="section">
                    <h2>4. Teknoloji Envanteri</h2>
                    <div class="tech-grid">
                        ${(data.tech || []).map(t => `
                            <div class="tech-item">
                                <strong>${t.name}</strong><br>
                                <span style="color:#64748b; font-size:0.8rem;">Sürüm: ${t.version}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <footer style="margin-top:50px; text-align:center; font-size:0.8rem; color:#94a3b8; border-top:1px solid #e2e8f0; padding-top:20px;">
                    Bu rapor <strong>Defora Recon Engine</strong> tarafından üretilmiştir. Gizli belgedir.
                </footer>
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

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });
});