const fs = require('fs');
const fetch = require('node-fetch');
const net = require('net');

// =====================================================
// ۱. تنظیمات و لیست ساب‌سکرایب‌ها
// =====================================================
const FETCH_TIMEOUT = 15000; 
const PING_TIMEOUT = 2500;   // زمان تست پینگ برای هر پروکسی
const MAX_PER_PROTOCOL = 777;

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
// ۲. تابع تست پینگ (TCP Connection Check)
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
// ۳. موتور اصلی پردازش (Main Logic)
// =====================================================
async function main() {
    let allProxies = [];
    console.log("🚀 Starting Full 1200-Line Logic Aggregator...");

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
                
                // اصلاح تایپ پروتکل (Case Insensitive)
                if (p.type) {
                    p.type = p.type.toLowerCase();
                    if (p.type === "shadowsocks") p.type = "ss";
                    if (p.type === "socks") p.type = "socks5";
                    if (p.type === "wireguard") p.type = "wg";
                }

                p = normalizeProxy(p);
                p = fixProxyArrayFields(p);

                if (valid(p)) {
                    // اجرای تست پینگ قبل از تایید نهایی
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
    console.log(`✅ Alive & Unique Proxies: ${uniqueProxies.length}`);
    generateFiles(uniqueProxies);
}

// =====================================================
// ۴. بخش غول‌پیکر پارسرها (Detect & Parse Engine)
// =====================================================
function detectAndParse(text) {
    const trimmed = text.trim();
    // تشخیص JSON Array
    if (trimmed.startsWith('[')) {
        try { const arr = JSON.parse(trimmed); if (Array.isArray(arr)) return parseJsonProxyArray(arr); } catch {}
    }
    // تشخیص JSON Object (Clash/Xray/Sing-box)
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
    // تشخیص YAML
    if (/^\s*proxies:/m.test(text) || /^\s*-\s*name:/m.test(text) || /^\s*-\s*\{/m.test(text)) {
        return extractYamlConfigs(text);
    }
    // تشخیص URI (Link)
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
        if (item.server_port !== undefined || item.private_key !== undefined) {
            const p = parseSingboxOutbound(item); if (p) result.push(p);
        } else if (item.type || item.protocol) { result.push(item); }
    }
    return result;
}

function parseSingboxOutbound(item) {
    try {
        const type = (item.type || "").toLowerCase();
        const typeMap = { "wireguard": "wireguard", "vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss", "socks": "socks5", "http": "http", "ssh": "ssh", "tuic": "tuic", "hysteria2": "hysteria2" };
        const clashType = typeMap[type]; if (!clashType) return null;
        
        const proxy = { name: item.tag || item.name || "sb", type: clashType, server: item.server || "", port: parseInt(item.server_port || item.port) || 0 };
        
        if (clashType === "wireguard") {
            proxy["private-key"] = item.private_key || "";
            proxy["public-key"] = item.peer_public_key || "";
            if (item.local_address) proxy.ip = String(item.local_address[0]).split("/")[0];
            proxy.udp = true;
        }
        if (item.uuid) proxy.uuid = item.uuid;
        if (item.password) proxy.password = item.password;
        if (item.tls && item.tls.enabled) {
            proxy.tls = true;
            if (item.tls.server_name) proxy.servername = item.tls.server_name;
            if (item.tls.utls) proxy["client-fingerprint"] = item.tls.utls.fingerprint;
        }
        return proxy;
    } catch { return null }
}

function parseXrayOutbounds(outbounds) {
    const result = [];
    for (const ob of outbounds) {
        if (!ob || typeof ob !== 'object') continue;
        const protocol = (ob.protocol || "").toLowerCase();
        try {
            const settings = ob.settings || {};
            if (protocol === "wireguard") {
                const peer = (settings.peers || [])[0];
                if (!peer) continue;
                const [srv, prt] = (peer.endpoint || "").split(":");
                result.push({
                    name: ob.tag || "wg", type: "wireguard", server: srv, port: parseInt(prt),
                    "private-key": settings.secretKey, "public-key": peer.publicKey, udp: true
                });
            }
        } catch {}
    }
    return result;
}

// =====================================================
// ۵. پارسرهای اختصاصی پروتکل‌ها (URI Parsers)
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
        if (l.startsWith("tuic://")) return parseTuic(line);
        if (l.startsWith("anytls://")) return parseAnyTls(line);
        if (l.startsWith("http://") || l.startsWith("https://")) return parseHttp(line);
        if (l.startsWith("socks://") || l.startsWith("socks5://")) return parseSocks(line);
    } catch {}
    return null;
}

function parseVless(link) {
    const url = new URL(link.replace(/^vless:\/\//i, "http://"));
    const proxy = { 
        name: safeDecode(url.hash.substring(1)), type: "vless", server: url.hostname, port: parseInt(url.port), 
        uuid: url.username, udp: true, tls: ["tls", "reality"].includes(url.searchParams.get("security")),
        network: url.searchParams.get("type") || "tcp"
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
        name: safeDecode(url.hash.substring(1)), type: "hysteria2", server: url.hostname, 
        port: parseInt(url.port), password: safeDecode(url.username), udp: true
    };
    if (url.searchParams.get("sni")) proxy.sni = url.searchParams.get("sni");
    if (url.searchParams.get("obfs") === "salamander") {
        proxy.obfs = "salamander";
        proxy["obfs-password"] = url.searchParams.get("obfs-password");
    }
    return proxy;
}

function parseSS(link) {
    try {
        const parts = link.replace(/^ss:\/\//i, "").split("#");
        const main = parts[0];
        const tag = parts[1] ? safeDecode(parts[1]) : "";
        let decoded = "";
        if (main.includes("@")) {
            const [auth, srv] = main.split("@");
            decoded = Buffer.from(auth, 'base64').toString('utf-8') + "@" + srv;
        } else {
            decoded = Buffer.from(main, 'base64').toString('utf-8');
        }
        const [authPart, srvPart] = decoded.split("@");
        const [method, password] = authPart.split(":");
        const [server, port] = srvPart.split(":");
        return { name: tag || server, type: "ss", server, port: parseInt(port), cipher: method, password, udp: true };
    } catch { return null; }
}

// =====================================================
// ۶. موتور پارسر YAML (The 1200-Line Core Engine)
// =====================================================
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

// =====================================================
// ۷. توابع کمکی و تمیزکاری (Sanitize & Logic)
// =====================================================
function decodeSub(text) { if (text.includes("://")) return text; try { return Buffer.from(text.trim(), 'base64').toString('utf-8'); } catch { return text; } }
function safeDecode(str) { try { return decodeURIComponent(str) } catch { return str || "" } }

function sanitizeObj(obj) {
    if (typeof obj === 'string') return obj.replace(/[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\uFFFD]/g, "").trim();
    if (Array.isArray(obj)) return obj.map(sanitizeObj);
    if (obj !== null && typeof obj === 'object') {
        const res = {}; for (const key in obj) res[key] = sanitizeObj(obj[key]); return res;
    }
    return obj;
}

function normalizeProxy(p) {
    if (p.port) p.port = parseInt(p.port);
    if (p.ip && typeof p.ip === 'string') p.ip = p.ip.split("/")[0].trim();
    return p;
}

function fixProxyArrayFields(p) {
    if (p.alpn && typeof p.alpn === 'string') p.alpn = p.alpn.split(",");
    return p;
}

function valid(p) {
    if (!p.server || !p.port || !p.type) return false;
    const blocked = ["127.0.0.1", "localhost", "github.com", "google.com"];
    if (blocked.some(s => String(p.server).toLowerCase().includes(s))) return false;
    
    // حل قطعی ارور ۵۰۰ (Missing Password/UUID)
    switch (p.type) {
        case "vless": case "vmess": case "tuic": return !!p.uuid;
        case "ss": case "trojan": case "hysteria2": return !!p.password;
        case "wireguard": case "wg": return !!p["private-key"] && !!p["public-key"];
        default: return true;
    }
}

function dedupe(list) {
    const seen = new Set();
    return list.filter(p => {
        const key = `${p.type}-${p.server}-${p.port}-${p.uuid || p.password || p["private-key"] || p.username}`;
        if (seen.has(key)) return false; seen.add(key); return true;
    });
}

// =====================================================
// ۸. تولید فایل‌های خروجی (Output Generation)
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
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    yaml += `    ${key}:\n`; for (const item of val) yaml += `      - ${typeof item === 'string' ? `"${item}"` : item}\n`;
                } else { yaml += `    ${key}: ${JSON.stringify(val)}\n`; }
            } else { yaml += `    ${key}: ${typeof val === 'string' ? `"${val}"` : val}\n`; }
        }
    }
    return yaml;
}

// اجرای موتور
main();
