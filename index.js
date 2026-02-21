const fs = require('fs');
const fetch = require('node-fetch');

// =====================================================
// تنظیمات و لیست ساب‌سکرایب‌ها
// =====================================================
const FETCH_TIMEOUT = 15000; 
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
`.split("\n").map(s => s.trim()).filter(Boolean))]

// =====================================================
// تابع اصلی اجرا
// =====================================================
async function main() {
    let allProxies = [];
    console.log("🚀 Starting Aggregation for Moslem...");

    for (const sub of SUBS) {
        try {
            console.log(`📡 Fetching: ${sub}`);
            const response = await fetch(sub, { timeout: FETCH_TIMEOUT });
            if (!response.ok) continue;

            const raw = await response.text();
            const decoded = decodeSub(raw);
            const parsed = detectAndParse(decoded);

            const cleaned = parsed.map(p => {
                p = sanitizeObj(p);
                p = normalizeProxy(p);
                p = fixProxyArrayFields(p);
                p.name = p.name || "Unnamed";
                return p;
            }).filter(p => valid(p) && p.type !== 'inline' && p.type !== 'hysteria2');

            allProxies.push(...cleaned);
        } catch (e) {
            console.error(`❌ Error fetching ${sub}: ${e.message}`);
        }
    }

    let proxies = dedupe(allProxies);
    console.log(`✅ Total unique proxies: ${proxies.length}`);

    generateFiles(proxies);
}

function generateFiles(proxies) {
    const modes = ["all", "v2ray", "others"];
    modes.forEach(mode => {
        let filtered = [...proxies];
        if (mode === 'v2ray') {
            filtered = filtered.filter(p => ['vless', 'vmess'].includes(p.type));
        } else if (mode === 'others') {
            filtered = filtered.filter(p => !['vless', 'vmess'].includes(p.type));
        }

        const grouped = {};
        filtered.forEach(p => {
            if (!grouped[p.type]) grouped[p.type] = [];
            grouped[p.type].push(p);
        });

        const randomized = [];
        for (const type in grouped) {
            const group = grouped[type];
            for (let i = group.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [group[i], group[j]] = [group[j], group[i]];
            }
            randomized.push(...group.slice(0, MAX_PER_PROTOCOL));
        }

        const protocolOrder = { "vless": 1, "anytls": 2, "trojan": 3, "ss": 4, "vmess": 5, "wg": 6, "tuic": 7, "http": 8, "socks": 9, "ssh": 10 };
        randomized.sort((a, b) => {
            const dt = t => (t === "wireguard" ? "wg" : t === "socks5" ? "socks" : t.toLowerCase());
            return (protocolOrder[dt(a.type)] || 99) - (protocolOrder[dt(b.type)] || 99);
        });

        const typeCounters = {};
        const finalProxies = randomized.map(p => {
            const dt = p.type === "wireguard" ? "wg" : p.type === "socks5" ? "socks" : p.type.toLowerCase();
            typeCounters[dt] = (typeCounters[dt] || 0) + 1;
            p.name = `${dt} ${typeCounters[dt]}`;
            return p;
        });

        const output = buildProvider(finalProxies);
        fs.writeFileSync(`${mode}.yaml`, output);
        console.log(`📂 File saved: ${mode}.yaml`);
    });
}

/* =====================================================
   بخش تشخیص فرمت و پارس کردن (DETECT & PARSE)
   ===================================================== */
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
            if (jsonData.type && jsonData.server) { const p = parseSingboxOutbound(jsonData); return p ? [p] : []; }
        }
    }
    if (/^\s*proxies:/m.test(text) || /^\s*-\s*name:/m.test(text) || /^\s*-\s*\{/m.test(text)) {
        return extractYamlConfigs(text);
    }
    const lines = text.split("\n").map(l => l.trim()).filter(Boolean);
    const result = [];
    for (const line of lines) { const p = parseProxy(line); if (p) result.push(p); }
    return result;
}

function parseJsonProxyArray(arr) {
    const result = [];
    for (const item of arr) {
        if (!item || typeof item !== 'object') continue;
        if (item.server_port !== undefined || item.private_key !== undefined || item.peer_public_key !== undefined) {
            const p = parseSingboxOutbound(item); if (p) result.push(p);
        } else if (item.type || item.protocol) { result.push(item); }
    }
    return result;
}

function parseSingboxOutbound(item) {
    try {
        const type = (item.type || "").toLowerCase();
        const typeMap = { "wireguard": "wireguard", "vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss", "socks": "socks5", "http": "http", "ssh": "ssh", "tuic": "tuic" };
        const clashType = typeMap[type]; if (!clashType) return null;
        if (clashType === "wireguard") {
            const proxy = { name: item.tag || item.name || "", type: "wireguard", server: item.server || "", port: parseInt(item.server_port || item.port) || 0, "private-key": item.private_key || item["private-key"] || "", "public-key": item.peer_public_key || item["public-key"] || "", udp: true };
            if (item.local_address) {
                const addrs = Array.isArray(item.local_address) ? item.local_address : [item.local_address];
                for (const addr of addrs) {
                    const clean = String(addr).split("/")[0].trim();
                    if (clean.includes(":")) { if (!proxy.ipv6) proxy.ipv6 = clean; } else { if (!proxy.ip) proxy.ip = clean; }
                }
            }
            if (item.ip) proxy.ip = String(item.ip).split("/")[0].trim();
            if (item.mtu) proxy.mtu = parseInt(item.mtu);
            if (item.reserved !== undefined) proxy.reserved = item.reserved;
            proxy["allowed-ips"] = ["0.0.0.0/0", "::/0"];
            return proxy;
        }
        const proxy = { name: item.tag || item.name || "", type: clashType, server: item.server || "", port: parseInt(item.server_port || item.port) || 0 };
        if (item.uuid) proxy.uuid = item.uuid;
        if (item.password) proxy.password = item.password;
        if (item.username) proxy.username = item.username;
        return proxy;
    } catch { return null }
}

function parseXrayOutbounds(outbounds) {
    const result = [];
    for (const ob of outbounds) {
        if (!ob || typeof ob !== 'object') continue;
        const protocol = (ob.protocol || "").toLowerCase();
        if (protocol !== "wireguard") continue;
        try {
            const settings = ob.settings || {};
            const peers = Array.isArray(settings.peers) ? settings.peers : [];
            if (peers.length === 0) continue;
            const peer = peers[0];
            let server = "", port = 0;
            if (peer.endpoint) {
                const lastColon = peer.endpoint.lastIndexOf(":");
                if (lastColon > 0) { server = peer.endpoint.substring(0, lastColon); port = parseInt(peer.endpoint.substring(lastColon + 1)) || 0; }
            }
            const proxy = { name: ob.tag || "", type: "wireguard", server, port, "private-key": settings.secretKey || settings["private-key"] || "", "public-key": peer.publicKey || peer["public-key"] || "", udp: true };
            if (Array.isArray(settings.address)) {
                for (const addr of settings.address) {
                    const clean = String(addr).split("/")[0].trim();
                    if (clean.includes(":")) { if (!proxy.ipv6) proxy.ipv6 = clean; } else { if (!proxy.ip) proxy.ip = clean; }
                }
            }
            if (Array.isArray(settings.reserved)) proxy.reserved = settings.reserved;
            if (settings.mtu) proxy.mtu = parseInt(settings.mtu);
            proxy["allowed-ips"] = ["0.0.0.0/0", "::/0"];
            result.push(proxy);
        } catch {}
    }
    return result;
}

/* =====================================================
   بخش نرمال‌سازی و سنیتایز (NORMALIZE & SANITIZE)
   ===================================================== */
function normalizeProxy(p) {
    if (p.ip && typeof p.ip === 'string') p.ip = p.ip.split("/")[0].trim();
    if (p.ipv6 && typeof p.ipv6 === 'string') p.ipv6 = p.ipv6.split("/")[0].trim();
    if (p.reserved !== undefined && !Array.isArray(p.reserved)) {
        if (typeof p.reserved === 'string' && p.reserved.trim() !== '') {
            const parts = p.reserved.split(",").map(Number);
            if (parts.length === 3 && parts.every(n => !isNaN(n))) { p.reserved = parts; } 
            else {
                try {
                    let b64 = p.reserved.trim().replace(/-/g, "+").replace(/_/g, "/");
                    const pad = b64.length % 4; if (pad === 2) b64 += "=="; else if (pad === 3) b64 += "=";
                    const bytes = [...Buffer.from(b64, 'base64')];
                    if (bytes.length === 3) p.reserved = bytes; else delete p.reserved;
                } catch { delete p.reserved; }
            }
        } else { delete p.reserved; }
    }
    if (p["dialer-proxy"] !== undefined && (p["dialer-proxy"] === "" || p["dialer-proxy"] === null)) delete p["dialer-proxy"];
    if (p.network !== undefined) {
        const validNetworks = ["tcp", "ws", "http", "h2", "grpc"];
        if (!validNetworks.includes(p.network)) { delete p.network; delete p["ws-opts"]; delete p["h2-opts"]; delete p["grpc-opts"]; delete p["http-opts"]; }
    }
    if (p["client-fingerprint"] !== undefined) {
        const validFp = ["chrome", "firefox", "safari", "iOS", "android", "edge", "360", "qq", "random"];
        if (!validFp.includes(p["client-fingerprint"])) delete p["client-fingerprint"];
    }
    if (p.type === "vmess" && p.cipher !== undefined) {
        const validCiphers = ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];
        if (!validCiphers.includes(p.cipher)) p.cipher = "auto";
    }
    return p;
}

function sanitizeObj(obj) {
    if (typeof obj === 'string') return obj.replace(/[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\uFFFD]/g, "").trim();
    if (Array.isArray(obj)) return obj.map(sanitizeObj);
    if (obj !== null && typeof obj === 'object') {
        const res = {}; for (const key in obj) res[key] = sanitizeObj(obj[key]); return res;
    }
    return obj;
}

/* =====================================================
   بخش پارسر YAML (YAML ENGINE)
   ===================================================== */
function extractYamlConfigs(text) {
    const proxies = []; let currentProxy = null; let currentNestedKey = null; let currentNestedIndent = 0;
    const knownListKeys = new Set(["allowed-ips", "dns", "alpn", "peers"]);
    for (const line of text.split(/\r?\n/)) {
        if (line.trim().startsWith('#')) continue;
        const listMatch = line.match(/^(\s*)-\s*(.*)$/);
        if (listMatch) {
            const indent = listMatch[1].length;
            if (currentProxy && currentNestedKey && indent > currentNestedIndent) {
                if (Array.isArray(currentProxy[currentNestedKey])) { currentProxy[currentNestedKey].push(parseYamlValue(listMatch[2].trim())); continue; }
            }
            if (currentProxy && currentProxy.type && currentProxy.server) proxies.push(currentProxy);
            currentProxy = {}; currentNestedKey = null; currentNestedIndent = 0;
            const remainder = listMatch[2].trim();
            if (remainder.startsWith('{')) {
                const parsed = parseInlineYaml(remainder); if (parsed) proxies.push(parsed); currentProxy = null;
            } else if (remainder) {
                const kv = remainder.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/); if (kv) currentProxy[kv[1]] = parseYamlValue(kv[2]);
            }
            continue;
        }
        if (currentProxy) {
            const indent = line.match(/^(\s*)/)[1].length;
            if (currentNestedKey && indent > currentNestedIndent) {
                const nestedListItem = line.match(/^\s+-\s+(.*)$/);
                if (nestedListItem) { if (!Array.isArray(currentProxy[currentNestedKey])) currentProxy[currentNestedKey] = []; currentProxy[currentNestedKey].push(parseYamlValue(nestedListItem[1])); continue; }
                const nestedKv = line.match(/^\s+([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
                if (nestedKv && nestedKv[2].trim() !== '') { if (Array.isArray(currentProxy[currentNestedKey])) currentProxy[currentNestedKey] = {}; currentProxy[currentNestedKey][nestedKv[1]] = parseYamlValue(nestedKv[2]); continue; }
            }
            const nestedKeyOnly = line.match(/^(\s+)([a-zA-Z0-9_-]+)\s*:\s*$/);
            if (nestedKeyOnly) { currentNestedKey = nestedKeyOnly[2]; currentNestedIndent = nestedKeyOnly[1].length; currentProxy[currentNestedKey] = knownListKeys.has(currentNestedKey) ? [] : {}; continue; }
            const kv = line.match(/^\s+([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
            if (kv && kv[2].trim() !== '') { currentNestedKey = null; currentNestedIndent = 0; currentProxy[kv[1]] = parseYamlValue(kv[2]); }
        }
    }
    if (currentProxy && currentProxy.type && currentProxy.server) proxies.push(currentProxy);
    return proxies;
}

function parseInlineYaml(str) {
    str = str.trim(); if (!str.startsWith('{') || !str.endsWith('}')) return null;
    str = str.slice(1, -1); const result = {};
    let currentKey = "", currentValue = "", inKey = true, depth = 0, inQuote = false, quoteChar = '';
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char === '"' || char === "'") { if (!inQuote) { inQuote = true; quoteChar = char } else if (quoteChar === char) inQuote = false }
        if (!inQuote) {
            if (char === '{' || char === '[') depth++; if (char === '}' || char === ']') depth--;
            if (char === ':' && inKey && depth === 0) { inKey = false; continue }
            if (char === ',' && !inKey && depth === 0) {
                if (currentKey.trim()) result[currentKey.trim()] = parseYamlValue(currentValue.trim());
                currentKey = ""; currentValue = ""; inKey = true; continue;
            }
        }
        if (inKey) currentKey += char; else currentValue += char;
    }
    if (currentKey.trim()) result[currentKey.trim()] = parseYamlValue(currentValue.trim());
    return result;
}

function parseYamlValue(val) {
    if (typeof val !== 'string') return val;
    val = val.trim(); if (val === 'true') return true; if (val === 'false') return false;
    if (/^[0-9]+$/.test(val)) return Number(val);
    if (val.startsWith('{') && val.endsWith('}')) return parseInlineYaml(val);
    if (val.startsWith('[') && val.endsWith(']')) return val.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
    return val.replace(/^["']|["']$/g, '');
}

function fixProxyArrayFields(p) {
    if (p.type === "wireguard" || p.type === "wg") {
        if (p["allowed-ips"] !== undefined && !Array.isArray(p["allowed-ips"])) {
            if (typeof p["allowed-ips"] === 'string' && p["allowed-ips"].trim() !== '') p["allowed-ips"] = p["allowed-ips"].split(",").map(s => s.trim()).filter(Boolean); else delete p["allowed-ips"];
        }
        if (p.dns !== undefined && !Array.isArray(p.dns)) {
            if (typeof p.dns === 'string' && p.dns.trim() !== '') p.dns = p.dns.split(",").map(s => s.trim()).filter(Boolean); else delete p.dns;
        }
        if (p.reserved !== undefined && !Array.isArray(p.reserved)) delete p.reserved;
    }
    if (p.alpn !== undefined && !Array.isArray(p.alpn)) {
        if (typeof p.alpn === 'string' && p.alpn.trim() !== '') p.alpn = p.alpn.split(",").map(s => s.trim()).filter(Boolean); else delete p.alpn;
    }
    return p;
}

/* =====================================================
   بخش دیکودر و پارسر پروتکل‌ها (PROTOCOL PARSERS)
   ===================================================== */
function decodeSub(text) { 
    if (text.includes("://")) return text; 
    try { return Buffer.from(text.trim(), 'base64').toString('utf-8'); } catch { return text; }
}

function safeDecode(str) { try { return decodeURIComponent(str) } catch { return str } }

function parseProxy(line) {
    try {
        const l = line.toLowerCase();
        if (l.startsWith("vless://")) return parseVless(line);
        if (l.startsWith("vmess://")) return parseVmess(line);
        if (l.startsWith("trojan://")) return parseTrojan(line);
        if (l.startsWith("anytls://")) return parseAnyTls(line);
        if (l.startsWith("ss://")) return parseSS(line);
        if (l.startsWith("wg://") || l.startsWith("wireguard://")) return parseWireguard(line);
        if (l.startsWith("tuic://")) return parseTuic(line);
        if (l.startsWith("http://") || l.startsWith("https://")) return parseHttp(line);
        if (l.startsWith("socks://") || l.startsWith("socks5://")) return parseSocks(line);
        if (l.startsWith("ssh://")) return parseSSH(line);
    } catch {}
    return null;
}

function parseVless(link) {
    const url = new URL(link.replace(/^vless:\/\//i, "http://"));
    const security = url.searchParams.get("security") || "";
    const network = url.searchParams.get("type") || "tcp";
    const proxy = { name: safeDecode(url.hash.substring(1) || url.hostname), type: "vless", server: url.hostname, port: parseInt(url.port), uuid: url.username || "", udp: true, tls: ["tls", "reality"].includes(security), network };
    if (url.searchParams.get("sni")) proxy.servername = url.searchParams.get("sni");
    if (url.searchParams.get("fp")) proxy["client-fingerprint"] = url.searchParams.get("fp");
    if (url.searchParams.get("alpn")) proxy.alpn = url.searchParams.get("alpn").split(",");
    if (url.searchParams.get("flow")) proxy.flow = url.searchParams.get("flow");
    const insecure = url.searchParams.get("allowInsecure") || url.searchParams.get("insecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;
    if (security === "reality") {
        proxy["reality-opts"] = { "public-key": url.searchParams.get("pbk") || "" };
        if (url.searchParams.get("sid")) proxy["reality-opts"]["short-id"] = url.searchParams.get("sid");
    }
    if (network === "ws") {
        const path = url.searchParams.get("path"), host = url.searchParams.get("host");
        if (path || host) { proxy["ws-opts"] = {}; if (path) proxy["ws-opts"].path = path; if (host) proxy["ws-opts"].headers = { Host: host } }
    } else if (network === "grpc") {
        if (url.searchParams.get("serviceName")) proxy["grpc-opts"] = { "grpc-service-name": url.searchParams.get("serviceName") }
    } else if (network === "h2") {
        const path = url.searchParams.get("path"), host = url.searchParams.get("host");
        if (path || host) { proxy["h2-opts"] = {}; if (path) proxy["h2-opts"].path = path; if (host) proxy["h2-opts"].host = [host] }
    }
    return proxy;
}

function parseVmess(link) {
    try {
        const raw = link.replace(/^vmess:\/\//i, ""); 
        const j = JSON.parse(Buffer.from(raw, 'base64').toString('utf-8'));
        if (!j.add || !j.port || !j.id) return null;
        const proxy = { name: safeDecode(j.ps || j.add), type: "vmess", server: j.add, port: parseInt(j.port), uuid: j.id || "", alterId: parseInt(j.aid) || 0, cipher: "auto", udp: true };
        if (j.tls === "tls") {
            proxy.tls = true; if (j.sni) proxy.servername = j.sni;
            if (j.fp) proxy["client-fingerprint"] = j.fp;
            if (j.alpn) proxy.alpn = typeof j.alpn === 'string' ? j.alpn.split(",") : j.alpn;
        }
        const net = j.net || j.type;
        if (net && net !== "tcp") {
            proxy.network = net;
            if (net === "ws") {
                proxy["ws-opts"] = {}; if (j.path) proxy["ws-opts"].path = j.path;
                const host = j.host || j.add; if (host) proxy["ws-opts"].headers = { Host: host };
            } else if (net === "grpc") { proxy["grpc-opts"] = { "grpc-service-name": j.path || "" }; }
            else if (net === "h2") { proxy["h2-opts"] = {}; if (j.path) proxy["h2-opts"].path = j.path; if (j.host) proxy["h2-opts"].host = [j.host] }
        }
        return proxy;
    } catch { return null }
}

function parseTrojan(link) {
    const url = new URL(link.replace(/^trojan:\/\//i, "http://")), network = url.searchParams.get("type") || "tcp";
    const proxy = { name: safeDecode(url.hash.substring(1) || url.hostname), type: "trojan", server: url.hostname, port: parseInt(url.port), password: safeDecode(url.username) || "", udp: true, tls: true, network };
    const sni = url.searchParams.get("sni") || url.searchParams.get("peer"); if (sni) proxy.sni = sni;
    if (url.searchParams.get("fp")) proxy["client-fingerprint"] = url.searchParams.get("fp");
    if (url.searchParams.get("alpn")) proxy.alpn = url.searchParams.get("alpn").split(",");
    const insecure = url.searchParams.get("allowInsecure") || url.searchParams.get("insecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;
    if (url.searchParams.get("security") === "reality") {
        proxy["reality-opts"] = { "public-key": url.searchParams.get("pbk") || "" };
        if (url.searchParams.get("sid")) proxy["reality-opts"]["short-id"] = url.searchParams.get("sid");
    }
    if (network === "ws") {
        const path = url.searchParams.get("path"), host = url.searchParams.get("host");
        if (path || host) { proxy["ws-opts"] = {}; if (path) proxy["ws-opts"].path = path; if (host) proxy["ws-opts"].headers = { Host: host } }
    } else if (network === "grpc") {
        if (url.searchParams.get("serviceName")) proxy["grpc-opts"] = { "grpc-service-name": url.searchParams.get("serviceName") }
    }
    return proxy;
}

function parseAnyTls(link) {
    const url = new URL(link.replace(/^anytls:\/\//i, "http://"));
    const proxy = { name: safeDecode(url.hash.substring(1) || url.hostname), type: "anytls", server: url.hostname, port: parseInt(url.port) };
    const pass = safeDecode(url.username || url.password); if (pass) proxy.password = pass;
    if (url.searchParams.get("sni")) proxy.sni = url.searchParams.get("sni");
    if (url.searchParams.get("alpn")) proxy.alpn = url.searchParams.get("alpn").split(",");
    const fp = url.searchParams.get("fp") || url.searchParams.get("fingerprint"); if (fp) proxy["client-fingerprint"] = fp;
    const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;
    return proxy;
}

function parseSS(link) {
    const raw = link.replace(/^ss:\/\//i, ""), hashIdx = raw.indexOf('#');
    const base = hashIdx >= 0 ? raw.substring(0, hashIdx) : raw, tag = hashIdx >= 0 ? raw.substring(hashIdx + 1) : "";
    let method, password, server, port;
    if (base.includes("@")) {
        const atIdx = base.lastIndexOf("@"), authPart = base.substring(0, atIdx), serverPart = base.substring(atIdx + 1);
        const decoded = Buffer.from(authPart, 'base64').toString('utf-8'), colonIdx = decoded.indexOf(":");
        if (colonIdx < 0) return null; method = decoded.substring(0, colonIdx); password = decoded.substring(colonIdx + 1);
        const lastColon = serverPart.lastIndexOf(":"); if (lastColon < 0) return null; server = serverPart.substring(0, lastColon); port = serverPart.substring(lastColon + 1);
    } else {
        const decoded = Buffer.from(base, 'base64').toString('utf-8'), atIdx = decoded.lastIndexOf("@"); if (atIdx < 0) return null;
        const authPart = decoded.substring(0, atIdx), serverPart = decoded.substring(atIdx + 1), colonIdx = authPart.indexOf(":"); if (colonIdx < 0) return null;
        method = authPart.substring(0, colonIdx); password = authPart.substring(colonIdx + 1);
        const lastColon = serverPart.lastIndexOf(":"); if (lastColon < 0) return null; server = serverPart.substring(0, lastColon); port = serverPart.substring(lastColon + 1);
    }
    server = server.replace(/^\[|\]$/g, ""); if (!server || !port || !method || password === undefined) return null;
    return { name: safeDecode(tag || server), type: "ss", server, port: parseInt(port), cipher: method.toLowerCase(), password: password || "", udp: true };
}

function parseWireguard(link) {
    const url = new URL(link.replace(/^(wg|wireguard):\/\//i, "http://"));
    const rawIp = url.searchParams.get("ip") || url.searchParams.get("address") || "10.0.0.1";
    const ip = rawIp.split(",")[0].trim().split("/")[0];
    const proxy = { name: safeDecode(url.hash.substring(1) || url.hostname), type: "wireguard", server: url.hostname, port: parseInt(url.port) || 51820, ip, "private-key": safeDecode(url.username || url.searchParams.get("privateKey") || url.searchParams.get("private-key") || ""), "public-key": safeDecode(url.searchParams.get("public-key") || url.searchParams.get("peer_public_key") || url.searchParams.get("publicKey") || ""), udp: true };
    const allowedIps = url.searchParams.get("allowedIPs") || url.searchParams.get("allowed-ips") || url.searchParams.get("allowed_ips");
    if (allowedIps) proxy["allowed-ips"] = allowedIps.split(",").map(s => s.trim()).filter(Boolean);
    const reserved = url.searchParams.get("reserved"); if (reserved) { const parts = reserved.split(",").map(Number); if (parts.length === 3 && parts.every(n => !isNaN(n))) proxy.reserved = parts }
    if (url.searchParams.get("mtu")) proxy.mtu = parseInt(url.searchParams.get("mtu"));
    if (url.searchParams.get("dns")) proxy.dns = url.searchParams.get("dns").split(",").map(s => s.trim()).filter(Boolean);
    return proxy;
}

function parseTuic(link) {
    const url = new URL(link.replace(/^tuic:\/\//i, "http://"));
    const proxy = { name: safeDecode(url.hash.substring(1) || url.hostname), type: "tuic", server: url.hostname, port: parseInt(url.port), uuid: safeDecode(url.username) || "", password: safeDecode(url.password) || "", udp: true };
    if (url.searchParams.get("sni")) proxy.sni = url.searchParams.get("sni");
    if (url.searchParams.get("alpn")) proxy.alpn = url.searchParams.get("alpn").split(",");
    const congestion = url.searchParams.get("congestion_control") || url.searchParams.get("congestion-control"); if (congestion) proxy["congestion-controller"] = congestion;
    const udpRelay = url.searchParams.get("udp_relay_mode") || url.searchParams.get("udp-relay-mode"); if (udpRelay) proxy["udp-relay-mode"] = udpRelay;
    const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure"); if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;
    if (url.searchParams.get("fp")) proxy["client-fingerprint"] = url.searchParams.get("fp");
    return proxy;
}

function parseHttp(link) {
    const isHttps = link.toLowerCase().startsWith("https://"), url = new URL(link);
    return { name: safeDecode(url.hash.substring(1) || url.hostname), type: "http", server: url.hostname, port: parseInt(url.port) || (isHttps ? 443 : 80), tls: isHttps, username: safeDecode(url.username) || "", password: safeDecode(url.password) || "" }
}
function parseSocks(link) {
    const url = new URL(link.replace(/^(socks|socks5):\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1) || url.hostname), type: "socks5", server: url.hostname, port: parseInt(url.port) || 1080, username: safeDecode(url.username) || "", password: safeDecode(url.password) || "", udp: true }
}
function parseSSH(link) {
    const url = new URL(link.replace(/^ssh:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1) || url.hostname), type: "ssh", server: url.hostname, port: parseInt(url.port) || 22, username: safeDecode(url.username) || "", password: safeDecode(url.password) || "" }
}

/* =====================================================
   بخش اعتبارسنجی و تولید نهایی (VALIDATION & BUILDER)
   ===================================================== */
const VALID_SS_CIPHERS = new Set(["aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-ccm", "aes-192-ccm", "aes-256-ccm", "aes-128-gcm-siv", "aes-256-gcm-siv", "chacha20-ietf", "chacha20", "xchacha20", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "lea-128-gcm", "lea-192-gcm", "lea-256-gcm", "rabbit128-poly1305", "aegis-128l", "aegis-256", "aez-384", "deoxys-ii-256-128", "rc4-md5", "none"]);

function valid(p) {
    if (!p.server || typeof p.server !== 'string' || p.server.trim() === '') return false;
    if (!p.port || isNaN(p.port) || p.port < 1 || p.port > 65535) return false;
    const blockedServers = ["127.0.0.1", "0.0.0.0", "localhost", "::1", "t.me", "github.com", "raw.githubusercontent.com", "google.com"];
    if (blockedServers.some(s => p.server.toLowerCase().includes(s))) return false;
    const optsFields = ["ws-opts", "grpc-opts", "h2-opts", "reality-opts", "http-opts"];
    for (const f of optsFields) { if (p[f] !== undefined && (typeof p[f] !== 'object' || Array.isArray(p[f]))) return false }
    if (p.reserved !== undefined) {
        if (!Array.isArray(p.reserved) || p.reserved.length !== 3) return false;
        if (!p.reserved.every(n => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 255)) return false;
    }
    if (p["reality-opts"]) {
        const pbk = p["reality-opts"]["public-key"]; if (!pbk || typeof pbk !== 'string') return false;
        const cleanPbk = pbk.replace(/=/g, "").trim(); if (cleanPbk.length !== 43 || !/^[A-Za-z0-9\-_]+$/.test(cleanPbk)) return false;
    }
    switch (p.type) {
        case "vless": if (!p.uuid || typeof p.uuid !== 'string') return false; break;
        case "vmess": if (!p.uuid || typeof p.uuid !== 'string') return false; break;
        case "trojan": if (!p.password || typeof p.password !== 'string') return false; break;
        case "tuic": if (!p.uuid || !p.password) return false; break;
        case "ss": if (!p.cipher || !p.password || !VALID_SS_CIPHERS.has(p.cipher.toLowerCase())) return false; break;
        case "wireguard": if (!p["private-key"] || !p["public-key"]) return false; break;
    }
    return true;
}

function dedupe(list) {
    const m = new Map();
    for (const p of list) {
        const key = p.uuid || p.password || p["private-key"] || p.username || "";
        const fp = `${p.type}|${p.server}|${p.port}|${key}`;
        if (!m.has(fp)) m.set(fp, p);
    }
    return [...m.values()];
}

const ALLOWED_FIELDS = {
    common: new Set(["name", "type", "server", "port", "udp", "ip-version", "dialer-proxy"]),
    tls: new Set(["tls", "sni", "servername", "fingerprint", "alpn", "skip-cert-verify", "client-fingerprint", "reality-opts"]),
    transport: new Set(["network", "ws-opts", "h2-opts", "grpc-opts", "http-opts"]),
    vless: new Set(["uuid", "flow", "packet-encoding"]),
    vmess: new Set(["uuid", "alterId", "cipher", "packet-encoding"]),
    trojan: new Set(["password"]),
    ss: new Set(["cipher", "password", "plugin", "plugin-opts"]),
    wireguard: new Set(["ip", "ipv6", "private-key", "public-key", "allowed-ips", "reserved", "mtu", "dns", "amnezia-wg-option"]),
    tuic: new Set(["uuid", "password", "udp-relay-mode", "congestion-controller"]),
    ssh: new Set(["username", "password"]),
    http: new Set(["username", "password", "tls"]),
    socks5: new Set(["username", "password", "tls"]),
};

function buildProvider(proxies) {
    let yaml = "proxies:\n";
    for (const p of proxies) {
        yaml += `  - name: "${p.name.replace(/"/g, '\\"')}"\n    type: ${p.type}\n    server: "${p.server}"\n    port: ${p.port}\n`;
        const t = p.type === "wireguard" ? "wireguard" : p.type === "socks5" ? "socks5" : p.type;
        const allowed = new Set([...ALLOWED_FIELDS.common, ...ALLOWED_FIELDS.tls, ...ALLOWED_FIELDS.transport, ...(ALLOWED_FIELDS[t] || [])]);
        for (const key in p) {
            if (["name", "type", "server", "port"].includes(key)) continue;
            if (!allowed.has(key)) continue;
            const val = p[key]; if (val === null || val === undefined) continue;
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    yaml += `    ${key}:\n`; for (const item of val) yaml += `      - ${typeof item === 'string' ? `"${item}"` : item}\n`;
                } else { yaml += `    ${key}: ${JSON.stringify(val)}\n`; }
            } else { yaml += `    ${key}: ${typeof val === 'string' ? `"${val}"` : val}\n`; }
        }
    }
    return yaml;
}

// استارت
main();
