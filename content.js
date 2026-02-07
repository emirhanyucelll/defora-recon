// DEFORA RECON - AGGRESSIVE SCRAPER (V60 - NOISE CANCELLATION)
(function() {
    const probe = document.createElement('script');
    probe.src = chrome.runtime.getURL('probe.js');
    (document.head || document.documentElement).appendChild(probe);
    probe.onload = () => probe.remove();

    const patterns = {
        "Cloud: AWS": /AKIA[0-9A-Z]{16}/g,
        "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
        "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
        "Token: Slack": /xox[bapr]-[0-9a-zA-Z-]{15,80}/g,
        "Token: Stripe": /sk_live_[0-9a-zA-Z]{24}/g,
        "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-z0-9.-]+/gi,
        "Kritik: Key": /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
        // Tırnak Zorunlu Regexler (CSS gürültüsünü engellemek için)
        "Kritik: Kimlik": /(?:[a-zA-Z0-9_]*(?:user(?:name)?|uname|login|account)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{4,})["']/gi,
        "Kritik: Parola": /(?:[a-zA-Z0-9_]*(?:pass(?:word|wd)?|pwd|secret|key|cred)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{5,})["']/gi,
        "Kritik: Yetki": /(?:[a-zA-Z0-9_]*(?:auth(?:entication|orization)?|token|sid|session|access)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{5,})["']/gi
    };

    async function scrape() {
        const secrets = [];
        const tech = [];
        
        let html = "";
        try {
            const res = await fetch(window.location.href);
            html = await res.text();
        } catch (e) {
            html = document.documentElement.outerHTML;
        }
        const lines = html.split('\n');

        // Regex Scan
        for (let [type, regex] of Object.entries(patterns)) {
            const matches = html.matchAll(regex);
            for (const m of matches) {
                // Regex grubuna göre değeri al (Grup 1 varsa onu al, yoksa tamamını)
                const matchedValue = (m[1] || m[0]).trim();
                const lowerVal = matchedValue.toLowerCase();

                // --- GÜRÜLTÜ FİLTRESİ ---
                
                // 1. CSS Terimleri (Kesinlikle Reddet)
                if (["hover", "active", "focus", "visited", "before", "after", "checked", "disabled", "enabled", "first-child", "last-child"].includes(lowerVal)) continue;
                if (lowerVal.match(/^(?:\d+(?:px|em|rem|vw|vh|%)|auto|none|inherit|initial|unset|transparent|rgba?(\(|\))|hsla?(\(|\))|#)/)) continue;
                
                // 2. CSS Property İsimleri
                if (["width", "height", "margin", "padding", "border", "background", "color", "font", "display", "position", "top", "left", "right", "bottom", "z-index", "content", "cursor", "pointer"].includes(lowerVal)) continue;

                // 3. Yazılım Terimleri
                if (["return", "true", "false", "null", "undefined", "function", "class", "const", "var", "let", "import", "export", "typeof", "instanceof", "void"].includes(lowerVal)) continue;

                // 4. Uzunluk ve Karakter Kontrolü
                if (matchedValue.length < 5 || matchedValue.length > 150) continue;
                
                let line = "Unknown";
                for (let i = 0; i < lines.length; i++) {
                    if (lines[i].includes(m[0].substring(0, 20))) { line = i + 1; break; }
                }
                secrets.push({ type, value: matchedValue, source: `Line: ${line}` });
            }
        }

        // DOM Tech
        const gen = document.querySelector('meta[name="generator"]');
        if (gen) tech.push({ name: gen.content.split(' ')[0], version: gen.content.split(' ')[1] || 'Unknown', source: "Meta" });

        if (html.includes('wp-content')) tech.push({ name: 'WordPress', version: 'Unknown', source: "HTML" });
        if (html.includes('drupal.js')) tech.push({ name: 'Drupal', version: 'Unknown', source: "HTML" });

        // Memory Data (from probe.js)
        const pData = document.documentElement.getAttribute('defora-recon-data');
        if (pData) {
            try { JSON.parse(pData).forEach(d => tech.push(d)); } catch(e) {}
        }

        // Script Tags
        document.querySelectorAll('script[src]').forEach(s => {
            const url = s.src.split('?')[0];
            const name = url.split('/').pop();
            if (name) tech.push({ name, version: url.match(/(\d+\.\d+(\.\d+)?)/)?.[0] || "Unknown", source: "Script" });
        });

        // Unique & Send
        const unique = Array.from(new Set(secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
        chrome.runtime.sendMessage({ action: "SCAN_RESULTS", data: { secrets: unique, tech } });
    }

    setTimeout(scrape, 1500);
})();
