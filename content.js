// DEFORA RECON - AGGRESSIVE SCRAPER (V60 - NOISE CANCELLATION)
(function() {
    const probe = document.createElement('script');
    probe.src = chrome.runtime.getURL('probe.js');
    (document.head || document.documentElement).appendChild(probe);
    probe.onload = () => probe.remove();

    const patterns = {
        "Cloud: AWS": /AKIA[0-9A-Z]{16}/g,
        "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
        "Cloud: Azure": /"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]{40,100}"/gi,
        "Cloud: Firebase": /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,
        "Storage: S3 Bucket": /[a-z0-9.-]+\.s3\.amazonaws\.com/gi,
        "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
        "Token: Slack": /xox[bapr]-[0-9a-zA-Z-]{15,80}/g,
        "Token: Stripe": /sk_live_[0-9a-zA-Z]{24}/g,
        "Token: Twilio": /AC[a-z0-9]{32}/gi,
        "Token: Mailgun": /key-[a-z0-9]{32}/gi,
        "Token: JWT": /eyJ[a-zA-Z0-9._-]{50,500}/g,
        "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-z0-9.-]+/gi,
        "IP: Dahili": /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
        "Kritik: Key": /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
        "Dosya: Hassas": /[a-z0-9_\-\.]+\.(?:env|conf|bak|sql|ini|log|yaml|toml|sh|dist|old|temp|tmp|backup|swp|git|svn|bz2|gz|tar|rar|zip|7z)/gi,
        "Kritik: Kimlik": /(?:[a-zA-Z0-9_]*(?:user(?:name)?|uname|login|account)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{4,})["']/gi,
        "Kritik: Parola": /(?:[a-zA-Z0-9_]*(?:pass(?:word|wd)?|pwd|secret|key|cred)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{5,})["']/gi,
        "Kritik: Yetki": /(?:[a-zA-Z0-9_]*(?:auth(?:entication|orization)?|token|sid|session|access)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{5,})["']/gi
    };

    async function scrape() {
        const secrets = [];
        const tech = [];
        
        // Fetch yerine doğrudan DOM'u al (Sıfır gecikme)
        const html = document.documentElement.outerHTML;
        const lines = html.split('\n');

        // Regex Scan (Optimize edilmiş döngü)
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

        // 5. HTML Yorum Kazıma (Gizli Notlar)
        const comments = [];
        const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT, null, false);
        let curNode;
        while (curNode = iterator.nextNode()) {
            const val = curNode.nodeValue;
            if (val.match(/(todo|fixme|pass|user|api|key|secret|dev|test|admin)/i)) {
                comments.push(val.trim());
            }
        }
        if (comments.length > 0) {
            comments.forEach(c => secrets.push({ type: "Yorum: Not", value: c.substring(0, 100), source: "HTML Comment" }));
        }

        // 6. Endpoint & Saldırı Yüzeyi Keşfi
        const endpoints = new Set();
        document.querySelectorAll('a, script, img, link').forEach(el => {
            const url = el.href || el.src;
            if (url && url.startsWith('http')) {
                try {
                    const u = new URL(url);
                    if (u.hostname !== window.location.hostname) endpoints.add(u.hostname); // Subdomain/External
                } catch(e) {}
            }
            // Hassas Dosya Kontrolü
            if (url && url.match(/\.(zip|bak|sql|config|php~|old|pdf|xls|xlsx|doc|docx)$/i)) {
                secrets.push({ type: "Hassas Dosya", value: url.split('/').pop(), source: "Link Discovery" });
            }
        });

        // 7. Dinamik İsim Avcısı (x.zip için "x" bulma)
        const candidateNames = new Set();
        // URL'den klasör isimlerini al
        window.location.pathname.split('/').filter(p => p.length > 2 && !p.includes('.')).forEach(p => candidateNames.add(p));
        // Sayfadaki önemli ID ve Class isimlerini al (Örn: backup-zone -> backup)
        document.querySelectorAll('[id], [class]').forEach(el => {
            const str = (el.id + " " + el.className).toLowerCase();
            const matches = str.match(/([a-z0-9\-]{4,20})/g);
            if (matches) matches.forEach(m => {
                if (m.includes('backup') || m.includes('data') || m.includes('sql') || m.includes('db')) candidateNames.add(m);
            });
        });

        // Unique & Send
        const unique = Array.from(new Set(secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
        chrome.runtime.sendMessage({ 
            action: "SCAN_RESULTS", 
            data: { 
                secrets: unique, 
                tech, 
                endpoints: Array.from(endpoints),
                candidates: Array.from(candidateNames) // "x" adayları
            } 
        });
    }

    setTimeout(scrape, 100);
})();
