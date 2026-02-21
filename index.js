const fs = require('fs');
const fetch = require('node-fetch');

// =====================================================
// تنظیمات اصلی (Heavy Config)
// =====================================================
const FETCH_TIMEOUT = 15000;
const MAX_PER_PROTOCOL = 800;

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
// موتور اصلی
// =====================================================
async function main() {
    let allProxies = [];
    console.log("🚀 Starting Massive Aggregation for Moslem...");

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
                if (p.type) {
                    p.type = p.type.toLowerCase();
                    if (p.type === "shadowsocks") p.type = "ss";
                    if (p.type === "socks") p.type = "socks5";
                    if (p.type === "wireguard") p.type = "wg";
                }
                p = normalizeProxy(p);
                p = fixProxyArrayFields(p);
                p.name = p.name || "Unnamed";
                return p;
            }).filter(p => valid(p) && p.type !== 'inline' && p.type !== 'hysteria2');

            allProxies.push(...cleaned);
        } catch (e) {
            console.error(`❌ Error with ${sub}: ${e.message}`);
        }
    }

    const uniqueProxies = dedupe(allProxies);
    console.log(`✅ Total unique proxies: ${uniqueProxies.length}`);
    generateFiles(uniqueProxies);
}

// =====================================================
// بخش پارسر غول‌پیکر (The Logic Monster)
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
// پارسرهای URI (Vless, Vmess, SS, ...)
// =====================================================

function parseProxy(line) {
    try {
        const l = line.toLowerCase();
        if (l.startsWith("vless://")) return parseVless(line);
        if (l.startsWith("vmess://")) return parseVmess(line);
        if (l.startsWith("trojan://")) return parseTrojan(line);
        if (l.startsWith("ss://")) return parseSS(line);
        if (l.startsWith("wg://") || l.startsWith("wireguard://")) return parseWireguard(line);
        if (l.startsWith("tuic://")) return parseTuic(line);
        if (l.startsWith("anytls://")) return parseAnyTls(line);
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
            name: j.ps, type: "vmess", server: j.add, port: parseInt(j.port), uuid: j.id, 
            alterId: parseInt(j.aid) || 0, cipher: "auto", udp: true, tls: j.tls === "tls", network: j.net || "tcp"
        };
        if (j.net === "ws") proxy["ws-opts"] = { path: j.path || "/", headers: { Host: j.host || "" } };
        return proxy;
    } catch { return null; }
}

function parseTrojan(link) {
    const url = new URL(link.replace(/^trojan:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "trojan", server: url.hostname, port: parseInt(url.port), password: url.username, tls: true, udp: true };
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
        return { name: tag, type: "ss", server, port: parseInt(port), cipher: method, password, udp: true };
    } catch { return null; }
}

function parseWireguard(link) {
    const url = new URL(link.replace(/^(wg|wireguard):\/\//i, "http://"));
    return { 
        name: safeDecode(url.hash.substring(1)), type: "wireguard", server: url.hostname, port: parseInt(url.port) || 51820,
        ip: url.searchParams.get("ip") || "10.0.0.1", "private-key": url.username, "public-key": url.searchParams.get("public-key"), udp: true 
    };
}

function parseTuic(link) {
    const url = new URL(link.replace(/^tuic:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "tuic", server: url.hostname, port: parseInt(url.port), uuid: url.username, password: url.password, udp: true, tls: true };
}

function parseAnyTls(link) {
    const url = new URL(link.replace(/^anytls:\/\//i, "http://"));
    return { name: safeDecode(url.hash.substring(1)), type: "anytls", server: url.hostname, port: parseInt(url.port), password: url.username, tls: true };
}

// =====================================================
// موتور پارسر YAML (The 1200-Line Core)
// =====================================================

function extractYamlConfigs(text) {
    const proxies = []; let current = null; let currentNestedKey = null; let currentNestedIndent = 0;
    const knownListKeys = new Set(["allowed-ips", "dns", "alpn", "peers"]);
    for (const line of text.split(/\r?\n/)) {
        if (line.trim().startsWith('#')) continue;
        const listMatch = line.match(/^(\s*)-\s*(.*)$/);
        if (listMatch) {
            const indent = listMatch[1].length;
            if (current && currentNestedKey && indent > currentNestedIndent) {
                if (Array.isArray(current[currentNestedKey])) {
                    current[currentNestedKey].push(parseYamlValue(listMatch[2].trim())); continue;
                }
            }
            if (current && current.type && current.server) proxies.push(current);
            current = {}; currentNestedKey = null; currentNestedIndent = 0;
            const remainder = listMatch[2].trim();
            if (remainder.startsWith('{')) {
                const p = parseInlineYaml(remainder); if (p) proxies.push(p); current = null;
            } else if (remainder) {
                const kv = remainder.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
                if (kv) current[kv[1]] = parseYamlValue(kv[2]);
            }
            continue;
        }
        if (current) {
            const indent = line.match(/^(\s*)/)[1].length;
            if (currentNestedKey && indent > currentNestedIndent) {
                const nli = line.match(/^\s+-\s+(.*)$/);
                if (nli) { if (!Array.isArray(current[currentNestedKey])) current[currentNestedKey] = []; current[currentNestedKey].push(parseYamlValue(nli[1])); continue; }
                const nkv = line.match(/^\s+([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
                if (nkv && nkv[2].trim() !== '') { if (Array.isArray(current[currentNestedKey])) current[currentNestedKey] = {}; current[currentNestedKey][nkv[1]] = parseYamlValue(nkv[2]); continue; }
            }
            const nko = line.match(/^(\s+)([a-zA-Z0-9_-]+)\s*:\s*$/);
            if (nko) { currentNestedKey = nko[2]; currentNestedIndent = nko[1].length; current[currentNestedKey] = knownListKeys.has(currentNestedKey) ? [] : {}; continue; }
            const kv = line.match(/^\s+([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
            if (kv && kv[2].trim() !== '') { currentNestedKey = null; currentNestedIndent = 0; current[kv[1]] = parseYamlValue(kv[2]); }
        }
    }
    if (current && current.type && current.server) proxies.push(current);
    return proxies;
}

function parseInlineYaml(str) {
    str = str.trim(); if (!str.startsWith('{')) return null;
    try { 
        str = str.replace(/([a-zA-Z0-9_-]+)\s*:/g, '"$1":').replace(/'/g, '"');
        return JSON.parse(str);
    } catch { return null; }
}

function parseYamlValue(val) {
    if (typeof val !== 'string') return val;
    val = val.trim(); if (val === 'true') return true; if (val === 'false') return false;
    if (/^[0-9]+$/.test(val)) return Number(val);
    return val.replace(/^["']|["']$/g, '');
}

// =====================================================
// توابع اعتبارسنجی و تمیزکاری
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
function normalizeProxy(p) { if (p.port) p.port = parseInt(p.port); if (p.ip) p.ip = String(p.ip).split("/")[0]; return p; }
function fixProxyArrayFields(p) { if (p.alpn && typeof p.alpn === 'string') p.alpn = p.alpn.split(","); return p; }

function valid(p) {
    if (!p.server || !p.port || !p.type) return false;
    
    // *** حل قطعی ارور 500: چک کردن فیلدهای حیاتی ***
    const type = p.type.toLowerCase();
    if (['vless', 'vmess', 'tuic'].includes(type) && !p.uuid) return false;
    if (['ss', 'trojan', 'anytls'].includes(type) && !p.password) return false;
    if (['wireguard', 'wg'].includes(type) && (!p["private-key"] || !p["public-key"])) return false;
    
    const blocked = ["127.0.0.1", "localhost", "github.com", "google.com"];
    if (blocked.some(s => String(p.server).toLowerCase().includes(s))) return false;
    
    return true;
}

function dedupe(list) {
    const seen = new Set();
    return list.filter(p => {
        const key = `${p.type}-${p.server}-${p.port}-${p.uuid || p.password || p["private-key"]}`;
        if (seen.has(key)) return false; seen.add(key); return true;
    });
}

// =====================================================
// تولید خروجی
// =====================================================

function generateFiles(proxies) {
    const categories = {
        "all": () => true,
        "v2ray": (p) => ['vless', 'vmess', 'trojan'].includes(p.type),
        "others": (p) => !['vless', 'vmess', 'trojan'].includes(p.type)
    };

    for (const [mode, filterFn] of Object.entries(categories)) {
        let filtered = proxies.filter(filterFn);
        
        // Shuffle و گروه‌بندی
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
        console.log(`📂 Created: ${mode}.yaml`);
    }
}

function buildProvider(proxies) {
    let yaml = "proxies:\n";
    for (const p of proxies) {
        // فیلتر نهایی برای اطمینان از وجود پسورد
        if (['ss', 'trojan'].includes(p.type) && !p.password) continue;
        if (['vless', 'vmess'].includes(p.type) && !p.uuid) continue;

        yaml += `  - name: "${p.name.replace(/"/g, '\\"')}"\n    type: ${p.type}\n    server: "${p.server}"\n    port: ${p.port}\n`;
        const skip = ["name", "type", "server", "port"];
        for (const key in p) {
            if (skip.includes(key)) continue;
            const val = p[key]; if (val === null || val === undefined) continue;
            if (typeof val === 'object') yaml += `    ${key}: ${JSON.stringify(val)}\n`;
            else yaml += `    ${key}: ${typeof val === 'string' ? `"${val}"` : val}\n`;
        }
    }
    return yaml;
}

main();
