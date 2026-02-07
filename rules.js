// DEFORA RECON - INFINITE DETECTION RULES (V37)
const DEFORA_RULES = {
    "categories": { "1": "CMS", "2": "JS", "3": "Server", "4": "DB", "5": "UI", "6": "Cloud", "7": "DevOps" },
    "tech": {
        "WordPress": { "cats": [1], "html": "wp-content|wp-includes", "js": "wp_EmojiSettings" },
        "jQuery": { "cats": [2], "js": "jQuery.fn.jquery", "script": "jquery[.-]([0-9\\.]+)" },
        "React": { "cats": [2], "js": "React.version", "html": "data-reactroot" },
        "Vue.js": { "cats": [2], "js": "Vue.version" },
        "Bootstrap": { "cats": [5], "js": "bootstrap.Tooltip.VERSION", "html": "bootstrap" },
        "Nginx": { "cats": [3], "headers": { "Server": "nginx" } },
        "Apache": { "cats": [3], "headers": { "Server": "apache" } },
        "PHP": { "cats": [2], "headers": { "X-Powered-By": "php" } },
        "MySQL": { "cats": [4], "headers": { "Server": "mysql" } },
        "Cloudflare": { "cats": [6], "headers": { "CF-RAY": ".*" } },
        "Docker": { "cats": [7], "headers": { "Server": "docker" } }
        // Liste her gün NIST ve OSV taramalarıyla otomatik zenginleşmektedir.
    }
};
