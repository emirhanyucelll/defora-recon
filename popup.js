// DEFORA RECON - HUD CONTROL (V78 - STABLE PROGRESS)
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    const fullScanBtn = document.getElementById('fullScan');
    const exportBtn = document.getElementById('exportReport');
    const progressCount = document.getElementById('progressCount');
    const scanProgress = document.getElementById('scanProgress');

    function sync() {
        chrome.runtime.sendMessage({ action: "GET_LIVE_DATA", tabId: tab.id }, (data) => {
            if (data) render(data);
        });
    }
    sync();

    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "UPDATE_UI" || msg.action === "FULL_SCAN_COMPLETE") sync();
    });

    function render(data) {
        try {
            document.getElementById('inventoryList').innerHTML = (data.tech || []).map(t => `<div class="item-card"><div style="display:flex; justify-content:space-between;"><span>${t.name}</span><span class="tech-version-pill">${t.version || '...'}</span></div></div>`).join('');
            document.getElementById('secretList').innerHTML = (data.secrets || []).map(s => `<div class="item-card secret-card" style="border-left:3px solid var(--danger)"><span class="secret-label">${s.type}</span><div class="secret-content">${s.value}</div></div>`).join('') || '<div class="empty-state">Temiz.</div>';
            document.getElementById('vulnList').innerHTML = (data.matches || []).map(m => `<div class="item-card"><div class="card-top"><span class="tech-title">${m.tech} ${m.version}</span></div><div class="cve-list">${m.exploits.map(ex => `<span class="cve-tag">${ex.id}</span>`).join(' ')}</div></div>`).join('') || '<div class="empty-state">Zafiyet yok.</div>';
        } catch (e) {}
    }

    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: "START_FULL_SCAN", url: tab.url });
            fullScanBtn.innerText = "DENETLENİYOR...";
            scanProgress.style.display = 'block';
        });
    }

    // Progress Check (Her saniye)
    setInterval(async () => {
        const res = await chrome.storage.local.get(['fullScanActive', 'scanProgress']);
        if (res.fullScanActive) {
            if(progressCount) progressCount.innerText = (res.scanProgress || 0) + "%";
            fullScanBtn.innerText = "DENETLENİYOR...";
            scanProgress.style.display = 'block';
        } else {
            fullScanBtn.innerText = "FULL SCAN";
            scanProgress.style.display = 'none';
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