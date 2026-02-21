const fs = require('fs');
const fetch = require('node-fetch');

// =====================================================
// تنظیمات اختصاصی Hysteria2
// =====================================================
const FETCH_TIMEOUT = 10000;
const MAX_PROXIES = 1000;

const SUBS = [...new Set(`
https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt
https://raw.githubusercontent.com/hamedp-71/hy2/refs/heads/main/hp.txt
https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt
https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria
https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/hysteria2.txt
https://raw.githubusercontent.com/10ium/V2ray-Config/main/Splitted-By-Protocol/hysteria2.txt
https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/normal/hysteria
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
https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt
https://raw.githubusercontent.com/parvinxs/Fssociety/refs/heads/main/Fssociety.sub
https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt
https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2
https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin
`.split("\n").map(s => s.trim()).filter(Boolean))]

async function main() {
    let allProxies = [];
    console.log("🚀 Starting Hysteria2 Aggregation...");

    for (const sub of SUBS) {
        try {
            console.log(`📡 Fetching: ${sub}`);
            const response = await fetch(sub, { timeout: FETCH_TIMEOUT });
            if (!response.ok) continue;

            const text = await response.text();
            const decoded = decodeSub(text);
            let localProxies = [];

            // تشخیص فرمت (YAML یا URI)
            if (/^\s*proxies:/m.test(decoded) || /^\s*-\s*name:/m.test(decoded)) {
                localProxies = extractYamlConfigs(decoded);
            } else {
                const lines = decoded.split("\n").map(l => l.trim()).filter(Boolean);
                for (const line of lines) {
                    if (line.toLowerCase().startsWith("hy2://") || line.toLowerCase().startsWith("hysteria2://")) {
                        const p = parseHysteria2(line);
                        if (p) localProxies.push(p);
                    }
                }
            }

            // فیلتر و تمیزکاری
            const cleaned = localProxies.filter(p => p.type === "hysteria2").map(p => {
                p = sanitizeObj(p);
                p = fixProxyArrayFields(p);
                p.name = p.name || "Unnamed";
                return p;
            }).filter(p => valid(p));

            allProxies.push(...cleaned);
        } catch (e) {
            console.error(`❌ Error fetching ${sub}: ${e.message}`);
        }
    }

    // حذف تکراری‌ها
    let proxies = dedupe(allProxies);
    console.log(`✅ Total Hysteria2 proxies: ${proxies.length}`);

    // Shuffle
    for (let i = proxies.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [proxies[i], proxies[j]] = [proxies[j], proxies[i]];
    }

    // محدودسازی و نام‌گذاری
    const finalProxies = proxies.slice(0, MAX_PROXIES).map((p, i) => {
        p.name = `hy2 ${i + 1}`;
        return p;
    });

    // ذخیره فایل
    const output = buildProvider(finalProxies);
    fs.writeFileSync('hysteria2.yaml', output);
    console.log("📂 File generated: hysteria2.yaml");
}

/* =====================================================
   پارسرهای اختصاصی HY2 و ابزارهای کمکی
   ===================================================== */

function parseHysteria2(link) {
    try {
        const url = new URL(link.replace(/^(hy2|hysteria2):\/\//i, "http://"));
        const proxy = {
            name: safeDecode(url.hash.substring(1) || url.hostname),
            type: "hysteria2",
            server: url.hostname,
            port: parseInt(url.port),
            password: safeDecode(url.username) || "",
            udp: true
        };
        const sni = url.searchParams.get("sni") || url.searchParams.get("peer"); if (sni) proxy.sni = sni;
        const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure");
        if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;
        if (url.searchParams.get("alpn")) proxy.alpn = url.searchParams.get("alpn").split(",");
        const obfs = url.searchParams.get("obfs");
        if (obfs && obfs.toLowerCase() === "salamander") {
            proxy.obfs = "salamander";
            const obfsPass = url.searchParams.get("obfs-password") || url.searchParams.get("obfsPassword");
            if (obfsPass) proxy["obfs-password"] = obfsPass;
        }
        if (url.searchParams.get("up")) proxy.up = url.searchParams.get("up");
        if (url.searchParams.get("down")) proxy.down = url.searchParams.get("down");
        return proxy;
    } catch { return null; }
}

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

function decodeSub(text) { if (text.includes("://")) return text; try { return Buffer.from(text.trim(), 'base64').toString('utf-8'); } catch { return text; } }
function safeDecode(str) { try { return decodeURIComponent(str) } catch { return str } }
function sanitizeObj(obj) {
    if (typeof obj === 'string') return obj.replace(/[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\uFFFD]/g, "").trim();
    if (Array.isArray(obj)) return obj.map(sanitizeObj);
    if (obj !== null && typeof obj === 'object') {
        const res = {}; for (const key in obj) res[key] = sanitizeObj(obj[key]); return res;
    }
    return obj;
}
function fixProxyArrayFields(p) {
    if (p.alpn !== undefined && !Array.isArray(p.alpn)) {
        if (typeof p.alpn === 'string' && p.alpn.trim() !== '') p.alpn = p.alpn.split(",").map(s => s.trim()).filter(Boolean); else delete p.alpn;
    }
    return p;
}
function valid(p) {
    if (!p.server || !p.port || !p.password) return false;
    const blockedServers = ["127.0.0.1", "0.0.0.0", "localhost", "github.com", "google.com"];
    if (blockedServers.some(s => p.server.toLowerCase().includes(s))) return false;
    return true;
}
function dedupe(list) {
    const m = new Map();
    for (const p of list) { const key = `${p.server}|${p.port}|${p.password}`; if (!m.has(key)) m.set(key, p); }
    return [...m.values()];
}
function buildProvider(proxies) {
    let yaml = "proxies:\n";
    for (const p of proxies) {
        yaml += `  - name: "${p.name}"\n    type: ${p.type}\n    server: "${p.server}"\n    port: ${p.port}\n`;
        for (const key in p) {
            if (["name", "type", "server", "port"].includes(key)) continue;
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

main();
