(function() {
    // GHOST PROBE V6: OMNISCIENT & FILTERED
    const detected = [];
    const seen = new Set();

    const libraryMap = {
        "React": () => window.React?.version,
        "Vue": () => window.Vue?.version,
        "Angular": () => window.angular?.version?.full,
        "Svelte": () => window.__svelte?.version || (document.querySelector('.svelte-') ? 'Detected' : null),
        "jQuery": () => window.jQuery?.fn?.jquery,
        "Lodash": () => window._?.VERSION,
        "Moment": () => window.moment?.version,
        "Bootstrap": () => window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION,
        "Ember": () => window.Ember?.VERSION,
        "Backbone": () => window.Backbone?.VERSION,
        "D3": () => window.d3?.version,
        "Three.js": () => window.THREE?.REVISION,
        "Chart.js": () => window.Chart?.version,
        "Axios": () => window.axios?.VERSION,
        "Socket.io": () => window.io?.version,
        "Handlebars": () => window.Handlebars?.VERSION,
        "Mustache": () => window.Mustache?.version,
        "Underscore": () => window._?.VERSION,
        "RequireJS": () => window.requirejs?.version,
        "Modernizr": () => window.Modernizr?._version,
        "Aurelia": () => window.au?.framework?.version,
        "Meteor": () => window.Meteor?.release,
        "Polymer": () => window.Polymer?.version,
        "Mithril": () => window.m?.version,
        "Alpine": () => window.Alpine?.version,
        "Knockout": () => window.ko?.version,
        "Highcharts": () => window.Highcharts?.version,
        "Foundation": () => window.Foundation?.version,
        "Materialize": () => window.Materialize?.version,
        "UIkit": () => window.UIkit?.version,
        "Zepto": () => window.Zepto?.fn?.zepto,
        "Shopify": () => window.Shopify ? 'Detected' : null,
        "WordPress": () => window.wp ? 'Detected' : null,
        "Drupal": () => window.Drupal ? 'Detected' : null,
        "Joomla": () => window.Joomla ? 'Detected' : null,
        "Magento": () => window.Mage ? 'Detected' : null
    };

    // 1. Bilinen Kütüphaneler
    for (let [name, check] of Object.entries(libraryMap)) {
        try {
            const v = check();
            if (v) {
                detected.push({ name, version: String(v), source: "Memory" });
                seen.add(name.toLowerCase());
            }
        } catch(e) {}
    }

    // 2. Dinamik Universal Scanner (Gürültü Filtreli)
    const versionKeys = ['version', 'VERSION', 'v', 'ver', 'release'];
    const blacklist = ['window', 'document', 'location', 'navigator', 'history', 'screen', 'performance', 'console', 'chrome', 'external', 'parent', 'top', 'self', 'frames', 'styleMedia', 'localStorage', 'sessionStorage', 'indexedDB', 'webkitStorageInfo', 'crypto', 'visualViewport', 'speechSynthesis', 'toolbar', 'statusbar', 'menubar', 'personalbar', 'scrollbars', 'name', 'status', 'length', 'closed', 'opener', 'frameElement', 'customElements', 'clientInformation', 'event', 'offscreenBuffering', 'defaultStatus', 'defaultstatus', 'devicePixelRatio', 'screenLeft', 'screenTop', 'outerHeight', 'outerWidth', 'innerheight', 'innerWidth', 'screenX', 'screenY', 'pageXOffset', 'pageYOffset', 'scrollX', 'scrollY', 'caches', 'cookieStore', 'ondevicemotion', 'ondeviceorientation', 'ondeviceorientationabsolute', 'credentialless', 'trustedTypes', 'scheduler', 'cookieStore'];

    for (const key of Object.getOwnPropertyNames(window)) {
        if (blacklist.includes(key) || key.startsWith('on') || key.startsWith('webkit') || !isNaN(parseInt(key))) continue;
        if (seen.has(key.toLowerCase())) continue;

        try {
            const obj = window[key];
            if (obj && typeof obj === 'object' && obj !== null) {
                for (const vKey of versionKeys) {
                    if (vKey in obj) {
                        const val = obj[vKey];
                        if (val && (typeof val === 'string' || typeof val === 'number')) {
                            const verStr = String(val);
                            // Sıkı Filtre: 15 karakterden kısa olmalı, sayı içermeli, karmaşık semboller (+, /, =) içermemeli
                            if (verStr.length < 15 && verStr.match(/\d/) && !verStr.match(/[+\/=]/)) {
                                detected.push({ name: key, version: verStr, source: "Memory" });
                                seen.add(key.toLowerCase());
                                break; 
                            }
                        }
                    }
                }
            }
        } catch(e) {}
    }

    document.documentElement.setAttribute('defora-recon-data', JSON.stringify(detected));
})();