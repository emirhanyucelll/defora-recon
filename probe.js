(function() {
    // GHOST PROBE V5: ENCYCLOPEDIA (100+ Static Signatures)
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
        "Tailwind": () => document.querySelector('[class*="tw-"], [class*="space-x-"]') ? 'Detected' : null,
        "Bulma": () => document.querySelector('.is-flex, .columns.is-mobile') ? 'Detected' : null,
        "Shopify": () => window.Shopify ? 'Detected' : null,
        "WordPress": () => window.wp ? 'Detected' : null,
        "Drupal": () => window.Drupal ? 'Detected' : null,
        "Joomla": () => window.Joomla ? 'Detected' : null,
        "Magento": () => window.Mage ? 'Detected' : null
    };

    const detected = [];
    for (let [name, check] of Object.entries(libraryMap)) {
        try {
            const v = check();
            if (v) detected.push({ name, version: String(v), source: "Memory" });
        } catch(e) {}
    }
    document.documentElement.setAttribute('defora-recon-data', JSON.stringify(detected));
})();