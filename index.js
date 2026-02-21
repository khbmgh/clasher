const fs = require('fs');
const fetch = require('node-fetch');
const net = require('net');

// =====================================================
// ۱. تنظیمات و منابع (SUBS)
// =====================================================
const FETCH_TIMEOUT = 15000;
const PING_TIMEOUT = 2500;
const MAX_PER_PROTOCOL = 500;

const SUBS = [...new Set(`
https://raw.githubusercontent.com/liketolivefree/kobabi/main/prov_clash.yaml
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Movaghat
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Reality
https://raw.githubusercontent.com/xtoolkit/TVC/main/subscriptions/meta/mix
https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/meta/mix
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/10ium-HiN-VPN.txt
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/10ium-config-fetcher.txt
https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml
https://raw.githubusercontent.com/anaer/Sub/main/proxies.yaml
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/nodes.meta.yml
https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml
https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml
https://raw.githubusercontent.com/liketolivefree/kobabi/main/prov_clash.yaml
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Movaghat
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Reality
https://raw.githubusercontent.com/xtoolkit/TVC/main/subscriptions/meta/mix
https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/meta/mix
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/10ium-HiN-VPN.txt
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/10ium-config-fetcher.txt
https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml
https://raw.githubusercontent.com/anaer/Sub/main/proxies.yaml
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/nodes.meta.yml
https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml
https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml
https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt
https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/clash-meta-wg.yml
https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml
https://raw.githubusercontent.com/lagzian/TVC/main/lite/subscriptions/meta/mix
https://sub.xeton.dev/sub?&url=https://raw.githubusercontent.com/10ium/base64-encoder/main/encoded/arshiacomplus_v2rayExtractor_vmess.txt&target=clash&config=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2FSleepyHeeead%2Fsubconverter-config%40master%2Fremote-config%2Funiversal%2Furltest.ini&emoji=false&append_type=true&append_info=true&scv=true&udp=true&list=true&sort=false&fdn=true&insert=false
https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt
https://raw.githubusercontent.com/xtoolkit/TVC/main/subscriptions/meta/mix
https://raw.githubusercontent.com/DarknessShade/WoW/refs/heads/main/clash-wg.yml
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/hamedvpns-Ali-Anv1-HP71.txt
https://raw.githubusercontent.com/10ium/ClashFactory/main/providers/10ium-configs-collector-ws.txt
https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/free-mihomo-sub/WARP%20%2B%20Ainita_%5BMulti-Profile%5D_%5BFull%5D.yaml
https://raw.githubusercontent.com/liketolivefree/kobabi/main/prov_clash.yaml
https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/mixed.txt
https://raw.githubusercontent.com/10ium/V2ray-Config/main/All_Configs_Sub.txt
https://raw.githubusercontent.com/maimengmeng/mysub/refs/heads/main/valid_content_all.txt
https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/base64/reality
https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/base64/xhttp
https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/splitted/mixed
https://raw.githubusercontent.com/hamedp-71/N_sub_cheker/refs/heads/patch-1/final.txt
https://raw.githubusercontent.com/MrBihal/Channel-Hddify/refs/heads/main/MeLi-Shekan
https://raw.githubusercontent.com/MrBihal/Channel-Hddify/refs/heads/main/Meli
https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/clash.yaml
https://raw.githubusercontent.com/peweza/PUBLICSUB/refs/heads/main/PewezaVPNPubSUB
https://raw.githubusercontent.com/frank-vpl/servers/refs/heads/main/irbox
https://v2.alicivil.workers.dev/?list=mix&count=500&shuffle=false&unique=false
https://raw.githubusercontent.com/parvinxs/Fssociety/refs/heads/main/Fssociety.sub
https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin
`.split("\n").map(s => s.trim()).filter(Boolean))];

// =====================================================
// ۲. سیستم تست پینگ هوشمند (TCP Ping)
// =====================================================
function checkTCP(host, port) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const timer = setTimeout(() => {
            socket.destroy();
            resolve(false);
        }, PING_TIMEOUT);

        socket.connect(port, host, () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(true);
        });

        socket.on('error', () => {
            clearTimeout(timer);
            resolve(false);
        });
    });
}

// =====================================================
// ۳. موتور اصلی (Main Engine)
// =====================================================
async function main() {
    let allProxies = [];
    console.log("🚀 Starting Aggregator for Moslem (1200 Line Logic)...");

    for (const sub of SUBS) {
        try {
            console.log(`📡 Fetching: ${sub}`);
            const response = await fetch(sub, { timeout: FETCH_TIMEOUT });
            if (!response.ok) continue;

            const raw = await response.text();
            const decoded = decodeSub(raw);
            const parsed = detectAndParse(decoded);

            for (let p of parsed) {
                p = sanitizeObj(p);
                
                // اصلاح تایپ پروتکل
                if (p.type) {
                    p.type = p.type.toLowerCase();
                    if (p.type === "shadowsocks") p.type = "ss";
                    if (p.type === "socks") p.type = "socks5";
                    if (p.type === "wireguard") p.type = "wg";
                }

                p = normalizeProxy(p);
                p = fixProxyArrayFields(p);

                // فیلتر سخت‌گیرانه برای جلوگیری از Missing Key
                if (valid(p)) {
                    const isAlive = await checkTCP(p.server, p.port);
                    if (isAlive) {
                        p.name = p.name || "Unnamed";
                        allProxies.push(p);
                    }
                }
            }
        } catch (e) {
            console.error(`❌ Error with ${sub}: ${e.message}`);
        }
    }

    const uniqueProxies = dedupe(allProxies);
    console.log(`✅ Alive & Unique: ${uniqueProxies.length}`);
    generateFiles(uniqueProxies);
}

// =====================================================
// ۴. بخش تشخیص و پارس کردن فرمت‌ها (Detect & Parse)
// =====================================================
function detectAndParse(text) {
    const trimmed = text.trim();
    if (trimmed.startsWith('[')) {
        try { const arr = JSON.parse(trimmed); if (Array.isArray(arr)) return parseJsonProxyArray(arr); } catch {}
    }
    if (trimmed.startsWith('{') || trimmed.includes('"proxies"') || trimmed.includes('"outbounds"')) {
        let jsonData = null; try { jsonData = JSON.parse(trimmed) } catch {}
        if (!jsonData) {
            const m = trimmed.match(/"proxies"\s*:\s*(\[[\s\S]*?\])(?:\s*[,}]|$)/);
            if (m) try { jsonData = { proxies: JSON.parse(m[1]) } } catch {}
        }
        if (jsonData) {
            if (Array.isArray(jsonData.proxies)) return parseJsonProxyArray(jsonData.proxies);
            if (Array.isArray(jsonData.outbounds)) return parseXrayOutbounds(jsonData.outbounds);
        }
    }
    if (/^\s*proxies:/m.test(text) || /^\s*-\s*name:/m.test(text) || /^\s*-\s*\{/m.test(text)) {
        return extractYamlConfigs(text);
    }
    const lines = text.split("\n").map(l => l.trim()).filter(Boolean);
    const result = [];
    for (const line of lines) {
        const p = parseProxy(line);
        if (p) result.push(p);
    }
    return result;
}

function parseJsonProxyArray(arr) {
    const result = [];
    for (const item of arr) {
        if (!item || typeof item !== 'object') continue;
        if (item.type || item.protocol) result.push(item);
    }
    return result;
}

function parseXrayOutbounds(outbounds) {
    const result = [];
    for (const ob of outbounds) {
        if (!ob || typeof ob !== 'object') continue;
        try {
            const protocol = (ob.protocol || "").toLowerCase();
            if (protocol === "wireguard") {
                const settings = ob.settings || {};
                const peer = (settings.peers || [])[0];
                if (!peer) continue;
                let server = "", port = 0;
                if (peer.endpoint) {
                    const parts = peer.endpoint.split(":");
                    server = parts[0]; port = parseInt(parts[1]);
                }
                result.push({
                    name: ob.tag || "wg", type: "wireguard", server, port,
                    "private-key": settings.secretKey, "public-key": peer.publicKey, udp: true
                });
            }
        } catch {}
    }
    return result;
}

// =====================================================
// ۵. پارسرهای اختصاصی پروتکل‌ها (Protocol Parsers)
// =====================================================
function parseProxy(line) {
    try {
        const l = line.toLowerCase();
        if (l.startsWith("vless://")) return parseVless(line);
        if (l.startsWith("vmess://")) return parseVmess(line);
        if (l.startsWith("trojan://")) return parseTrojan(line);
        if (l.startsWith("ss://")) return parseSS(line);
        if (l.startsWith("hy2://") || l.startsWith("hysteria2://")) return parseHysteria2(line);
        if (l.startsWith("wg://") || l.startsWith("wireguard://")) return parseWireguard(line);
        if (l.startsWith("anytls://")) return parseAnyTls(line);
        if (l.startsWith("http://") || l.startsWith("https://")) return parseHttp(line);
        if (l.startsWith("socks://") || l.startsWith("socks5://")) return parseSocks(line);
        if (l.startsWith("ssh://")) return parseSSH(line);
    } catch {}
    return null;
}

function parseVless(link) {
    const url = new URL(link.replace(/^vless:\/\//i, "http://"));
    const proxy = { 
        name: safeDecode(url.hash.substring(1) || url.hostname), 
        type: "vless", server: url.hostname, port: parseInt(url.port), 
        uuid: url.username, udp: true, network: url.searchParams.get("type") || "tcp",
        tls: ["tls", "reality"].includes(url.searchParams.get("security"))
    };
    if (url.searchParams.get("sni")) proxy.servername = url.searchParams.get("sni");
    if (url.searchParams.get("pbk")) proxy["reality-opts"] = { "public-key": url.searchParams.get("pbk") };
    if (url.searchParams.get("sid")) proxy["reality-opts"] = { ...proxy["reality-opts"], "short-id": url.searchParams.get("sid") };
    if (proxy.network === "ws") proxy["ws-opts"] = { path: url.searchParams.get("path") || "/", headers: { Host: url.searchParams.get("host") || "" } };
    if (proxy.network === "grpc") proxy["grpc-opts"] = { "grpc-service-name": url.searchParams.get("serviceName") || "" };
    return proxy;
}

function parseVmess(link) {
    try {
        const j = JSON.parse(Buffer.from(link.replace(/^vmess:\/\//i, ""), 'base64').toString('utf-8'));
        const proxy = {
            name: safeDecode(j.ps), type: "vmess", server: j.add, port: parseInt(j.port),
            uuid: j.id, alterId: parseInt(j.aid) || 0, cipher: "auto", udp: true,
            tls: j.tls === "tls", network: j.net || "tcp"
        };
        if (j.tls === "tls" && j.sni) proxy.servername = j.sni;
        if (j.net === "ws") proxy["ws-opts"] = { path: j.path || "/", headers: { Host: j.host || "" } };
        return proxy;
    } catch { return null; }
}

function parseHysteria2(link) {
    const url = new URL(link.replace(/^(hy2|hysteria2):\/\//i, "http://"));
    const proxy = {
        name: safeDecode(url.hash.substring(1)), type: "hysteria2", 
        server: url.hostname, port: parseInt(url.port), 
        password: safeDecode(url.username), udp: true
    };
    if (url.searchParams.get("sni")) proxy.sni = url.searchParams.get("sni");
    if (url.searchParams.get("obfs") === "salamander") {
        proxy.obfs = "salamander";
        proxy["obfs-password"] = url.searchParams.get("obfs-password");
    }
    return proxy;
}

function parseTrojan(link) {
    const url = new URL(link.replace(/^trojan:\/\//i, "http://"));
    return {
        name: safeDecode(url.hash.substring(1)), type: "trojan", server: url.hostname,
        port: parseInt(url.port), password: url.username, udp: true, tls: true,
        sni: url.searchParams.get("sni") || ""
    };
}

function parseSS(link) {
    try {
        const raw = link.replace(/^ss:\/\//i, "");
        const parts = raw.split("#");
        const main = parts[0];
        const tag = parts[1] ? safeDecode(parts[1]) : "";
        let decoded = "";
        if (main.includes("@")) {
            const auth = main.split("@")[0];
            const server = main.split("@")[1];
            decoded = Buffer.from(auth, 'base64').toString('utf-8') + "@" + server;
        } else {
            decoded = Buffer.from(main, 'base64').toString('utf-8');
        }
        const [auth, serverPort] = decoded.split("@");
        const [method, password] = auth.split(":");
        const [server, port] = serverPort.split(":");
        return { name: tag || server, type: "ss", server, port: parseInt(port), cipher: method, password, udp: true };
    } catch { return null; }
}

function parseWireguard(link) {
    const url = new URL(link.replace(/^(wg|wireguard):\/\//i, "http://"));
    return {
        name: safeDecode(url.hash.substring(1)), type: "wireguard", server: url.hostname,
        port: parseInt(url.port), "private-key": url.username, "public-key": url.searchParams.get("public-key"),
        ip: url.searchParams.get("ip") || "10.0.0.1", udp: true
    };
}

function parseAnyTls(link) {
    const url = new URL(link.replace(/^anytls:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "anytls", server: url.hostname, port: parseInt(url.port), password: url.username, tls: true };
}

function parseHttp(link) {
    const url = new URL(link);
    return { name: safeDecode(url.hash.substring(1)), type: "http", server: url.hostname, port: parseInt(url.port), tls: link.startsWith("https"), username: url.username, password: url.password };
}

function parseSocks(link) {
    const url = new URL(link.replace(/^socks5?:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "socks5", server: url.hostname, port: parseInt(url.port), username: url.username, password: url.password };
}

function parseSSH(link) {
    const url = new URL(link.replace(/^ssh:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "ssh", server: url.hostname, port: parseInt(url.port), username: url.username, password: url.password };
}

// =====================================================
// ۶. بخش پارسر YAML (The YAML Engine)
// =====================================================
function extractYamlConfigs(text) {
    const proxies = []; let current = null;
    for (let line of text.split("\n")) {
        const inlineJson = line.match(/^\s*-\s*\{(.*)\}\s*$/);
        if (inlineJson) {
            try { const p = JSON.parse("{" + inlineJson[1] + "}"); if (p.type && p.server) proxies.push(p); } catch {}
            continue;
        }
        if (line.includes("- name:")) {
            if (current) proxies.push(current);
            current = {};
        }
        const kv = line.match(/^\s+([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
        if (current && kv) {
            let val = kv[2].trim().replace(/^["']|["']$/g, '');
            if (val === 'true') val = true; else if (val === 'false') val = false;
            else if (/^\d+$/.test(val)) val = parseInt(val);
            current[kv[1]] = val;
        }
    }
    if (current) proxies.push(current);
    return proxies;
}

// =====================================================
// ۷. توابع اعتبارسنجی و تمیزکاری (Sanitize & Valid)
// =====================================================
function decodeSub(text) { if (text.includes("://")) return text; try { return Buffer.from(text.trim(), 'base64').toString('utf-8'); } catch { return text; } }
function safeDecode(str) { try { return decodeURIComponent(str) } catch { return str || "" } }

function sanitizeObj(obj) {
    if (typeof obj === 'string') return obj.replace(/[\x00-\x1F\x7F-\x9F]/g, "").trim();
    if (Array.isArray(obj)) return obj.map(sanitizeObj);
    if (obj !== null && typeof obj === 'object') {
        const res = {}; for (const key in obj) res[key] = sanitizeObj(obj[key]); return res;
    }
    return obj;
}

function normalizeProxy(p) {
    if (p.port) p.port = parseInt(p.port);
    if (p.ip) p.ip = p.ip.split("/")[0];
    return p;
}

function fixProxyArrayFields(p) {
    if (p.alpn && typeof p.alpn === 'string') p.alpn = p.alpn.split(",");
    return p;
}

function valid(p) {
    if (!p.server || !p.port || !p.type) return false;
    const blocked = ["127.0.0.1", "localhost", "github.com", "google.com"];
    if (blocked.some(s => p.server.toLowerCase().includes(s))) return false;
    
    // حل مشکل Missing Password / UUID
    switch (p.type) {
        case "vless": case "vmess": case "tuic": return !!p.uuid;
        case "ss": case "trojan": case "hysteria2": case "anytls": return !!p.password;
        case "wireguard": case "wg": return !!p["private-key"];
        default: return true;
    }
}

function dedupe(list) {
    const seen = new Set();
    return list.filter(p => {
        const key = `${p.type}-${p.server}-${p.port}-${p.uuid || p.password || p["private-key"]}`;
        if (seen.has(key)) return false; seen.add(key); return true;
    });
}

// =====================================================
// ۸. تولید خروجی (File Generation)
// =====================================================
function generateFiles(proxies) {
    const categories = {
        "all": () => true,
        "v2ray": (p) => ['vless', 'vmess', 'trojan'].includes(p.type),
        "hysteria2": (p) => p.type === 'hysteria2',
        "others": (p) => !['vless', 'vmess', 'trojan', 'hysteria2'].includes(p.type)
    };

    for (const [mode, filterFn] of Object.entries(categories)) {
        let filtered = proxies.filter(filterFn);
        const grouped = {};
        filtered.forEach(p => {
            if (!grouped[p.type]) grouped[p.type] = [];
            grouped[p.type].push(p);
        });

        const finalBatch = [];
        for (const type in grouped) {
            const shuffled = grouped[type].sort(() => 0.5 - Math.random());
            finalBatch.push(...shuffled.slice(0, MAX_PER_PROTOCOL));
        }

        const counts = {};
        const named = finalBatch.map(p => {
            counts[p.type] = (counts[p.type] || 0) + 1;
            p.name = `${p.type} ${counts[p.type]}`;
            return p;
        });

        fs.writeFileSync(`${mode}.yaml`, buildProvider(named));
        console.log(`📂 Saved: ${mode}.yaml`);
    }
}

function buildProvider(proxies) {
    let yaml = "proxies:\n";
    for (const p of proxies) {
        yaml += `  - name: "${p.name.replace(/"/g, '\\"')}"\n    type: ${p.type}\n    server: "${p.server}"\n    port: ${p.port}\n`;
        const skip = ["name", "type", "server", "port"];
        for (const key in p) {
            if (skip.includes(key)) continue;
            const val = p[key];
            if (val === null || val === undefined) continue;
            if (typeof val === 'object') yaml += `    ${key}: ${JSON.stringify(val)}\n`;
            else yaml += `    ${key}: ${typeof val === 'string' ? `"${val}"` : val}\n`;
        }
    }
    return yaml;
}

// استارت نهایی
main();
