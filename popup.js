// DEFORA RECON - HUD CONTROL (V81 - STABLE & FAST)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');

    // CANLI VERI AL (Background'dan doğrudan)
    function sync() {
        chrome.runtime.sendMessage({ action: "GET_LIVE_DATA", tabId: tab.id }, (data) => {
            if (data) render(data);
        });
    }
    sync();

    // CANLI GÜNCELLEME DINLE
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI" || msg.action === "FULL_SCAN_COMPLETE") {
            sync();
        }
    });

    function render(data) {
        if (!data) return;
        try {
            // Inventory
            const inv = document.getElementById('inventoryList');
            if(inv) inv.innerHTML = (data.tech || []).map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span>${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('') || '<div class="empty-state">Yok.</div>';
            
            // Secrets
            const sl = document.getElementById('secretList');
            if(sl) sl.innerHTML = (data.secrets || []).map(s => `<div class="item-card secret-card" style="border-left:3px solid var(--danger)"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('') || '<div class="empty-state">Temiz.</div>';

            // Vulns
            const vl = document.getElementById('vulnList');
            if(vl) vl.innerHTML = (data.matches || []).map(m => `<div class="item-card"><div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('') || '<div class="empty-state">Yok.</div>';
        } catch (e) { console.error(e); }
    }

    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", url: tab.url });
            fullScanBtn.innerText = "DENETLENİYOR...";
            document.getElementById('scanProgress').style.display = 'block';
        });
    }

    // Progress Check
    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive) {
            if(progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
            fullScanBtn.disabled = true;
        } else {
            fullScanBtn.innerText = "FULL SCAN";
            fullScanBtn.disabled = false;
            document.getElementById('scanProgress').style.display = 'none';
        }
    }, 1000);

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