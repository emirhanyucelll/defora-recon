// DEFORA RECON - HUD CONTROL (V71 - LIVE UPDATES & STABLE)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    // VERİLERİ YÜKLE
    async function loadAndRender() {
        const result = await chrome.storage.local.get(`results_${tab.id}`);
        const data = result[`results_${tab.id}`];
        if (data) render(data);
    }

    loadAndRender();

    // ARKA PLANDAN GELEN CANLI GÜNCELLEMELERİ DİNLE
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI" || msg.action === "FULL_SCAN_COMPLETE") {
            render(msg.data);
        }
    });

    function render(data) {
        if (!data) return;
        try {
            // 1. ENVANTER
            const invList = document.getElementById('inventoryList');
            if (invList) {
                const techs = data.tech || [];
                document.getElementById('inventoryCount').innerText = techs.length;
                invList.innerHTML = techs.length ? techs.map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span class="tech-name-highlight">${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('') : '<div class="empty-state">Bulunamadı.</div>';
            }

            // 2. GÜVENLİK
            const secList = document.getElementById('securityList');
            if (secList) {
                const secs = data.security || [];
                let score = 100;
                secList.innerHTML = secs.length ? secs.map(s => {
                    if(s.risk === 'HIGH') score -= 20; else score -= 10;
                    return `<div class="item-card" style="border-left:3px solid ${s.risk === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}"><strong>${s.name}</strong><br><small>${s.desc}</small></div>`;
                }).join('') : '<div class="empty-state">Analiz ediliyor...</div>';
                document.getElementById('securityScore').innerText = score + "/100";
            }

            // 3. SIZINTILAR
            const secretList = document.getElementById('secretList');
            if (secretList) {
                const secrets = data.secrets || [];
                document.getElementById('secretCount').innerText = secrets.length;
                secretList.innerHTML = secrets.length ? secrets.map(s => `<div class="item-card secret-card" style="border-left:3px solid var(--danger)"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('') : '<div class="empty-state">Temiz.</div>';
            }

            // 4. ZAFİYETLER
            const vulnList = document.getElementById('vulnList');
            if (vulnList) {
                const matches = data.matches || [];
                vulnList.innerHTML = matches.length ? matches.map(m => `<div class="item-card"><div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('') : '<div class="empty-state">Tehdit yok.</div>';
            }

            // 5. YÜZEY
            const epList = document.getElementById('endpointList');
            if (epList) {
                const eps = data.endpoints || [];
                epList.innerHTML = eps.length ? eps.map(e => `<div class="item-card" style="font-size:0.7rem;">• ${e}</div>`).join('') : '<div class="empty-state">Bekleniyor...</div>';
            }
        } catch (e) { console.error("UI Render Error:", e); }
    }

    // BUTONLAR
    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", tabId: tab.id, url: tab.url });
            fullScanBtn.innerText = "TARANIYOR...";
            document.getElementById('scanProgress').style.display = 'block';
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            const res = await chrome.storage.local.get(`results_${tab.id}`);
            const d = res[`results_${tab.id}`];
            if (!d) return;
            const domain = new URL(tab.url).hostname;
            const reportHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Audit</title><style>body{font-family:sans-serif; background:#f3f4f6; padding:50px;} .box{background:#fff; padding:40px; border-radius:16px; max-width:900px; margin:auto; box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);}</style></head><body><div class="box"><h1>Defora Recon Audit</h1><p>Hedef: ${domain}</p><h2>Zafiyetler</h2>${(d.matches||[]).map(m=>`<div><b>${m.tech}</b>: ${m.exploits.map(ex=>ex.id).join(', ')}</div>`).join('')}<h2>Sızıntılar</h2>${(d.secrets||[]).map(s=>`<div>${s.type}: ${s.value}</div>`).join('')}</div></body></html>`;
            const blob = new Blob([reportHTML], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = `RECON_${domain}.html`; a.click();
        });
    }

    // SEKME GECISLERI
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById(`tab-${btn.dataset.tab}`);
            if (target) target.classList.add('active');
        });
    });

    // PROGRESS CHECK
    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive && progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
    }, 1000);
});