// DEFORA RECON - HUD CONTROL (V63 - PROFESSIONAL LIGHT THEME)
document.addEventListener('DOMContentLoaded', async () => {
    const secretList = document.getElementById('secretList');
    const vulnList = document.getElementById('vulnList');
    const riskBadge = document.getElementById('riskBadge');
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const result = await chrome.storage.local.get(`results_${tab.id}`);
    const data = result ? result[`results_${tab.id}`] : null;

    if (data) {
        try { render(data); } catch (e) { console.error("Render hatasi:", e); }
    }

    function render(data) {
        // --- ENVANTER ---
        const inventoryList = document.getElementById('inventoryList');
        if (inventoryList) {
            inventoryList.innerHTML = "";
            const allTech = data.tech || [];
            const invCount = document.getElementById('inventoryCount');
            if(invCount) invCount.innerText = allTech.length;
            
            allTech.forEach(t => {
                const div = document.createElement('div');
                div.className = "item-card";
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="tech-name-highlight">${t.name}</span>
                        <span class="tech-version-pill">${t.version || 'Unknown'}</span>
                    </div>
                `;
                inventoryList.appendChild(div);
            });
        }

        // --- GÜVENLİK ---
        const securityList = document.getElementById('securityList');
        if (securityList) {
            securityList.innerHTML = "";
            const securityData = data.security || [];
            let score = 100;
            securityData.forEach(s => {
                if(s.risk === 'HIGH') score -= 20;
                else if(s.risk === 'MEDIUM') score -= 10;
                const div = document.createElement('div');
                div.className = "item-card";
                div.style.borderLeft = `3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}`;
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:900; color:#fff; font-size:0.8rem;">${s.name}</span>
                        <span style="font-size:0.6rem; color:${s.risk === 'HIGH' ? 'var(--danger)' : (s.risk === 'MEDIUM' ? 'var(--warning)' : 'var(--accent)')}">${s.risk}</span>
                    </div>
                    <div style="font-size:0.7rem; color:var(--text-dim); margin-top:4px;">${s.desc}</div>
                `;
                securityList.appendChild(div);
            });
            if(document.getElementById('securityScore')) document.getElementById('securityScore').innerText = score + "/100";
        }

        // --- SIZINTILAR (YOL KALDIRILDI) ---
        if (secretList) {
            secretList.innerHTML = "";
            const allSecrets = data.secrets || [];
            if(document.getElementById('secretCount')) document.getElementById('secretCount').innerText = allSecrets.length;
            
            allSecrets.forEach(s => {
                const div = document.createElement('div');
                div.className = "item-card secret-card";
                let color = "var(--accent)";
                if (s.type.includes("Kritik") || s.type.includes("Parola") || s.type.includes("Dosya")) color = "var(--danger)";
                
                div.style.borderLeft = `3px solid ${color}`;
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                        <span class="secret-label" style="background:${color}22; color:${color}; border:1px solid ${color}44;">${s.type}</span>
                    </div>
                    <div class="secret-content" style="color:#eee; font-weight:bold; word-break: break-all;">${s.value}</div>
                `;
                secretList.appendChild(div);
            });
        }

        // --- DIŞ KAYNAKLAR (ESKİ YÜZEY) ---
        const endpointList = document.getElementById('endpointList');
        if (endpointList) {
            endpointList.innerHTML = "";
            const endpoints = data.endpoints || [];
            endpoints.forEach(e => {
                const div = document.createElement('div');
                div.className = "item-card";
                div.style.fontSize = "0.75rem";
                div.innerHTML = `<span style="color:var(--accent); margin-right:5px;">•</span> ${e}`;
                endpointList.appendChild(div);
            });
        }

        // --- ZAFİYETLER ---
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
            }
        }
    }

    // --- REPORT EXPORTER (PROFESSIONAL LIGHT THEME) ---
    const exportBtn = document.getElementById('exportReport');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            if (!data) return;
            const domain = new URL(tab.url).hostname;
            const score = document.getElementById('securityScore')?.innerText || "--";
            
            const vulnHTML = (data.matches || []).map(m => `
                <div class="report-section-item">
                    <div class="item-header"><strong>${m.tech}</strong> <span class="text-muted">${m.version}</span></div>
                    <div class="tag-row">${m.exploits.map(ex => `<span class="tag-danger">${ex.id}</span>`).join('')}</div>
                </div>`).join('');

            const secretHTML = (data.secrets || []).map(s => {
                let p = "/"; try { if(s.url) p = new URL(s.url).pathname; } catch(e) {}
                return `
                <div class="report-section-item">
                    <div class="item-header">
                        <span class="type-label">${s.type}</span>
                        <span class="path-label">Konum: ${p}</span>
                    </div>
                    <div class="code-box">${s.value}</div>
                </div>`;
            }).join('');

            const endpointHTML = (data.endpoints || []).map(e => `<div class="endpoint-link">${e}</div>`).join('');

            const reportHTML = `
            <!DOCTYPE html>
            <html lang="tr">
            <head>
                <meta charset="UTF-8">
                <title>Recon Analiz - ${domain}</title>
                <style>
                    body { font-family: 'Segoe UI', Arial, sans-serif; color: #333; background: #f9fafb; margin: 0; padding: 50px; line-height: 1.6; }
                    .report-container { max-width: 900px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #eee; }
                    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #3b82f6; padding-bottom: 25px; margin-bottom: 40px; }
                    h1 { margin: 0; color: #1e3a8a; font-size: 24px; font-weight: 800; }
                    .score-circle { width: 80px; height: 80px; border-radius: 50%; background: #eff6ff; border: 4px solid #3b82f6; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
                    .score-circle .val { font-size: 20px; font-weight: 900; color: #3b82f6; line-height: 1; }
                    .score-circle .lbl { font-size: 9px; font-weight: 700; color: #60a5fa; }
                    h2 { font-size: 14px; text-transform: uppercase; color: #64748b; letter-spacing: 1px; margin-bottom: 20px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; }
                    .report-section-item { margin-bottom: 20px; padding: 15px; background: #f8fafc; border-radius: 8px; border: 1px solid #edf2f7; }
                    .item-header { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 14px; }
                    .type-label { font-weight: 800; color: #1e293b; }
                    .path-label { color: #3b82f6; font-family: monospace; font-size: 12px; }
                    .code-box { font-family: 'Consolas', monospace; background: #1e293b; color: #34d399; padding: 12px; border-radius: 6px; font-size: 13px; word-break: break-all; }
                    .tag-danger { background: #fee2e2; color: #b91c1c; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; margin-right: 5px; border: 1px solid #fecaca; }
                    .tag-row { margin-top: 8px; }
                    .endpoint-link { font-family: monospace; color: #64748b; font-size: 12px; margin-bottom: 4px; }
                    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
                    .text-muted { color: #94a3b8; font-weight: 400; }
                    footer { margin-top: 50px; text-align: center; font-size: 12px; color: #cbd5e1; border-top: 1px solid #f1f5f9; padding-top: 20px; }
                </style>
            </head>
            <body>
                <div class="report-container">
                    <div class="header">
                        <div>
                            <h1>Defora Recon | Analiz Raporu</h1>
                            <div style="color:#64748b; margin-top:5px;">Hedef: <strong>${domain}</strong></div>
                        </div>
                        <div class="score-circle">
                            <div class="lbl">GÜVENLİK</div>
                            <div class="val">${score.split('/')[0]}</div>
                            <div class="lbl">PUANI</div>
                        </div>
                    </div>

                    <div class="grid-2">
                        <div>
                            <h2>Zafiyet Bulguları</h2>
                            ${vulnHTML || '<div class="report-section-item" style="color:#10b981;">Bilinen zafiyet tespit edilmedi.</div>'}
                        </div>
                        <div>
                            <h2>Veri Sızıntıları</h2>
                            ${secretHTML || '<div class="report-section-item" style="color:#10b981;">Hassas veri bulunamadı.</div>'}
                        </div>
                    </div>

                    <div style="margin-top: 30px;">
                        <h2>Dış Kaynaklar</h2>
                        <div class="report-section-item">
                            <div style="display:grid; grid-template-columns: 1fr 1fr;">${endpointHTML || 'Bağlantı yok.'}</div>
                        </div>
                    </div>

                    <footer>Bu rapor Defora Recon tarafından ${new Date().toLocaleString()} tarihinde oluşturulmuştur.</footer>
                </div>
            </body>
            </html>`;

            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `RECON_ANALYSIS_${domain.replace(/\./g, '_')}.html`;
            a.click();
        });
    }

    // --- FULL SCAN HANDLER ---
    const fullScanBtn = document.getElementById('fullScan');
    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", tabId: tab.id, url: tab.url });
            fullScanBtn.innerText = "TARANIYOR...";
            fullScanBtn.disabled = true;
            document.getElementById('scanProgress').style.display = 'block';
        });
    }

    chrome.runtime.onMessage.addListener((msg) => {
        if (request.action === "FULL_SCAN_PROGRESS") {
            document.getElementById('progressCount').innerText = `${msg.current}/${msg.total}`;
        }
        if (request.action === "FULL_SCAN_COMPLETE") {
            fullScanBtn.innerText = "SCAN COMPLETE";
            // Sonuçları storage'a yaz
            chrome.storage.local.set({ [`results_${tab.id}`]: msg.data }, () => {
                render(msg.data);
                // OTOMATİK RAPOR İNDİRME
                exportBtn.click();
                setTimeout(() => { 
                    document.getElementById('scanProgress').style.display = 'none';
                    fullScanBtn.innerText = "FULL SCAN";
                    fullScanBtn.disabled = false;
                }, 2000);
            });
        }
    });

    // --- TAB SWITCHER ---
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            if (!tabId) return;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const targetPane = document.getElementById(`tab-${tabId}`);
            if (targetPane) targetPane.classList.add('active');
        });
    });
});