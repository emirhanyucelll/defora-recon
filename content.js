// DEFORA RECON - BEAST MODE SCRAPER (V67 - STABILIZED)
(function() {
    const probe = document.createElement('script');
    probe.src = chrome.runtime.getURL('probe.js');
    (document.head || document.documentElement).appendChild(probe);
    probe.onload = () => probe.remove();

    const patterns = {
        "Cloud: AWS Key": /AKIA[0-9A-Z]{16}/g,
        "Cloud: Google": /AIza[0-9A-Za-z\-_]{20,50}/g,
        "Cloud: Azure": /"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]{40,100}"/gi,
        "Cloud: Firebase": /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,
        "Storage: S3 Bucket": /[a-z0-9.-]+\.s3\.amazonaws\.com/gi,
        "Token: GitHub": /ghp_[a-zA-Z0-9]{30,50}/g,
        "Token: Slack": /xox[bapr]-[0-9a-zA-Z-]{15,80}/g,
        "Token: Stripe": /sk_live_[0-9a-zA-Z]{24}/g,
        "Token: Twilio SID": /\bAC[0-9a-fA-F]{32}\b/g,
        "Token: Mailgun": /key-[a-z0-9]{32}/gi,
        "Token: SendGrid": /SG\.[a-zA-Z0-9_\-\. ]{64}/g,
        "Token: Heroku": /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
        "Token: Shopify": /shppa_[a-fA-F0-9]{32}/g,
        "Token: Sentry DSN": /https:\/\/[a-f0-9]+(:[a-f0-9]+)?@sentry\.io\/[0-9]+/g,
        "Token: JWT": /\beyJ[a-zA-Z0-9._-]{50,500}\b/g,
        "Bağlantı: DB Link": /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-z0-9._-]+\:[a-z0-9._-]+\@[a-z0-9.-]+/gi,
        "IP: Dahili": /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
        "Kritik: Private Key": /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
        "Dosya: Hassas": /[a-z0-9_\-\. ]+\.(?:env|conf|bak|sql|ini|log|yaml|toml|sh|dist|old|temp|tmp|backup|swp|git|svn|bz2|gz|tar|rar|zip|7z)/gi,
        "Kritik: Kimlik": /(?:[a-zA-Z0-9_]*(?:user(?:name)?|uname|login|account)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{3,})["']/gi,
        "Kritik: Parola": /(?:[a-zA-Z0-9_]*(?:pass(?:word|wd)?|pwd|secret|key|cred)[a-zA-Z0-9_]*)[ \t]*[:=][ \t]*["']([^"'\s,;<>(){}]{3,})["']/gi
    };

    async function scrape() {
        const secrets = [];
        const tech = [];
        const html = document.documentElement.outerHTML;
        const currentUrl = window.location.href;

        // 1. Element Bazlı Derin Tarama
        const allElements = document.querySelectorAll('script, meta, link, a, [id], [class]');
        allElements.forEach(el => {
            const content = el.tagName === 'META' ? el.content : (el.innerText || el.href || el.src || "");
            const tagName = el.tagName;

            for (let [type, regex] of Object.entries(patterns)) {
                const matches = content.matchAll(regex);
                for (const m of matches) {
                    const val = (m[1] || m[0]).trim();
                    if (val.length < 4) continue;
                    if (val.startsWith('#') && (val.length === 4 || val.length === 7)) continue;
                    if (["true", "false", "null", "undefined", "auto", "none", "inherit"].includes(val.toLowerCase())) continue;

                    secrets.push({ type, value: val, url: currentUrl });
                }
            }
        });

        // 2. HTML Yorumları
        const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT, null, false);
        let curNode;
        while (curNode = iterator.nextNode()) {
            const val = curNode.nodeValue;
            if (val.match(/(todo|fixme|pass|user|api|key|secret|dev|test|admin|login)/i)) {
                secrets.push({ type: "Yorum: Not", value: val.trim().substring(0, 100), url: currentUrl });
            }
        }

        // 3. Teknoloji Tespiti
        const gen = document.querySelector('meta[name="generator"]');
        if (gen) tech.push({ name: gen.content.split(' ')[0], version: gen.content.split(' ')[1] || 'Unknown', source: "Meta" });
        if (html.includes('wp-content')) tech.push({ name: 'WordPress', version: 'Unknown', source: "HTML" });
        const pData = document.documentElement.getAttribute('defora-recon-data');
        if (pData) { try { JSON.parse(pData).forEach(d => tech.push(d)); } catch(e) {} }
        document.querySelectorAll('script[src]').forEach(s => {
            const url = s.src.split('?')[0];
            const name = url.split('/').pop();
            if (name) tech.push({ name, version: url.match(/(\d+\.\d+(\.\d+)?)/)?.[0] || "Unknown", source: "Script" });
        });

        // 4. Endpoint & Aday İsimler
        const endpoints = new Set();
        const candidates = new Set();
        const foundLinks = [];

        window.location.pathname.split('/').filter(p => p.length > 2 && !p.includes('.')).forEach(p => {
            endpoints.add(p);
            candidates.add(p);
        });

        document.querySelectorAll('a, script, img, link').forEach(el => {
            const url = el.href || el.src;
            if (url && url.startsWith('http')) {
                try {
                    const u = new URL(url);
                    if (u.hostname !== window.location.hostname) endpoints.add(u.hostname);
                    foundLinks.push(url);
                } catch(e) {}
            }
        });

        // 5. Gizli Yol Madenciliği
        const paths = html.match(/["'](\/[a-z0-9_\-\.\/]{2,50})["']/gi);
        if (paths) {
            paths.forEach(p => {
                const cleanPath = p.replace(/["']/g, '');
                if (cleanPath.includes('.') && !cleanPath.match(/\.(js|css|png|jpg|svg|woff)/i)) {
                    foundLinks.push(window.location.origin + cleanPath);
                }
            });
        }

        // Unique & Send
        const unique = Array.from(new Set(secrets.map(s => JSON.stringify(s)))).map(s => JSON.parse(s));
        chrome.runtime.sendMessage({
            action: "SCAN_RESULTS",
            data: {
                secrets: unique,
                tech,
                endpoints: Array.from(endpoints),
                candidates: Array.from(candidates), // BURASI DÜZELTİLDİ
                links: foundLinks
            }
        });
    }

    setTimeout(scrape, 100);
})();