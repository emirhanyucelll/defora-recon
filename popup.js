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
                <title>Recon Audit - ${domain}</title>
                <style>
                    body { font-family: 'Inter', -apple-system, sans-serif; background: #f3f4f6; color: #1f2937; margin: 0; padding: 40px; }
                    .report-wrapper { max-width: 950px; margin: auto; background: white; border-radius: 16px; box-shadow: 0 4px 30px rgba(0,0,0,0.05); padding: 50px; }
                    .header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid #e5e7eb; padding-bottom: 30px; margin-bottom: 40px; }
                    h1 { margin: 0; color: #111827; font-size: 28px; font-weight: 800; }
                    .score-pill { background: #eff6ff; color: #2563eb; padding: 10px 20px; border-radius: 99px; font-weight: 900; font-size: 18px; border: 1px solid #dbeafe; }
                    h2 { font-size: 12px; text-transform: uppercase; color: #6b7280; letter-spacing: 1.5px; margin: 40px 0 20px 0; display: flex; align-items: center; }
                    h2::after { content: ""; flex: 1; height: 1px; background: #e5e7eb; margin-left: 15px; }
                    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
                    .card { background: #f9fafb; border: 1px solid #f3f4f6; padding: 20px; border-radius: 12px; margin-bottom: 15px; transition: 0.2s; }
                    .card:hover { border-color: #d1d5db; }
                    .card-title { font-weight: 700; color: #111827; margin-bottom: 8px; font-size: 15px; }
                    .badge { font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; margin-right: 5px; }
                    .badge-danger { background: #fee2e2; color: #dc2626; }
                    .badge-warn { background: #fef3c7; color: #d97706; }
                    .code-snippet { font-family: 'JetBrains Mono', monospace; background: #111827; color: #10b981; padding: 12px; border-radius: 8px; font-size: 13px; margin-top: 10px; word-break: break-all; }
                    .footer-text { margin-top: 60px; text-align: center; color: #9ca3af; font-size: 13px; border-top: 1px solid #f3f4f6; padding-top: 30px; }
                </style>
            </head>
            <body>
                <div class="report-wrapper">
                    <div class="header">
                        <div>
                            <h1>Defora Recon Audit</h1>
                            <div style="color:#6b7280; margin-top:8px;">Hedef Alan Adı: <strong>${domain}</strong></div>
                        </div>
                        <div class="score-pill">GÜVENLİK SKORU: ${score}</div>
                    </div>

                    <div class="grid">
                        <div>
                            <h2>🛡️ Zafiyet Bulguları</h2>
                            ${vulnHTML || '<div class="card" style="color:#059669;">Bilinen zafiyet tespit edilmedi.</div>'}
                        </div>
                        <div>
                            <h2>🔍 Veri Sızıntıları</h2>
                            ${secretHTML || '<div class="card" style="color:#059669;">Hassas veri sızıntısı bulunamadı.</div>'}
                        </div>
                    </div>

                    <h2>🌐 Saldırı Yüzeyi & Dış Kaynaklar</h2>
                    <div class="card" style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; font-family:monospace; font-size:12px; color:#4b5563;">
                        ${endpointHTML || 'Dış bağlantı yok.'}
                    </div>

                    <div class="footer-text">
                        Bu denetim raporu Defora Recon Engine tarafından ${new Date().toLocaleString()} tarihinde üretilmiştir.
                    </div>
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

    // --- INITIAL SCAN STATE ---
    chrome.storage.local.get(['fullScanActive', 'scanProgress', 'scanStatus'], (res) => {
        if (res.fullScanActive) {
            fullScanBtn.innerText = "TARANIYOR...";
            fullScanBtn.disabled = true;
            document.getElementById('scanProgress').style.display = 'block';
            document.getElementById('progressCount').innerText = res.scanProgress + "%";
        }
    });

    // --- FULL SCAN HANDLER ---
    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", tabId: tab.id, url: tab.url });
            fullScanBtn.innerText = "TARANIYOR...";
            fullScanBtn.disabled = true;
            document.getElementById('scanProgress').style.display = 'block';
            document.getElementById('progressCount').innerText = "0%";
        });
    }

    // Periyodik Progress Kontrolü
    setInterval(() => {
        chrome.storage.local.get(['fullScanActive', 'scanProgress'], (res) => {
            if (res.fullScanActive) {
                document.getElementById('progressCount').innerText = res.scanProgress + "%";
            } else if (fullScanBtn.innerText === "TARANIYOR...") {
                fullScanBtn.innerText = "FULL SCAN";
                fullScanBtn.disabled = false;
                document.getElementById('scanProgress').style.display = 'none';
            }
        });
    }, 1000);

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