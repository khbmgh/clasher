const fs    = require('fs');
const fetch = require('node-fetch');

// =====================================================
// ۱. تنظیمات
// =====================================================
const FETCH_TIMEOUT    = 15000;
const MAX_PER_PROTOCOL = 1000;

const SUBS = [...new Set(`
https://msk.vless-balancer.ru/sub/dXNlcl82Nzg4MzMxMjQ5LDE3Njk1MzUzMTkBqGm3A1STd#Subscription
https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin
https://msk.vless-balancer.ru/sub/dXNlcl82Nzg4MzMxMjQ5LDE3Njk1MzUzMTkBqGm3A1STd/#KIA_NET
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Clash_Reality
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Clash_Reality
https://gist.githubusercontent.com/senatorpersian/ddb0dc4ceed582630c24ef56197d297a/raw/cb3370e2be7a72cb640d96c7b137029dc05b3739/subscription.txt
https://gist.githubusercontent.com/senatorpersian/ddb0dc4ceed582630c24ef56197d297a/raw/7767ced7587c4f8d203de08b186606eb880f3814/subscription.txt
https://raw.githubusercontent.com/hamedp-71/hy2/refs/heads/main/hp.txt
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs2.txt
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs.txt
https://raw.githubusercontent.com/hamedp-71/For_All_Net/refs/heads/main/hp.txt
https://zood.link/Motasel_Ba_Hame_Chi
https://gist.githubusercontent.com/senatorpersian/85d7bd0e4b64444a655ced36bd3136d5/raw/a4806bb92498ff77ca77b8555b2027dce2d84d51/subscription.txt
https://gist.githubusercontent.com/senatorpersian/85d7bd0e4b64444a655ced36bd3136d5/raw/0974dfe62a75fb7704a292d05c3f5f36ae6e14bf/subscription.txt
https://gist.githubusercontent.com/senatorpersian/85d7bd0e4b64444a655ced36bd3136d5/raw/7b2ce1090b3832102e86d2d0b892644f1dfeec12/subscription.txt
https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/mixed_iran.txt
https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vless_iran.txt
https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vmess_iran.txt
https://proxyclouds.vercel.app/get
https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/4.txt
https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt
https://raw.githubusercontent.com/MrBihal/Channel-Hddify/refs/heads/main/MeLi-Shekan
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality
https://zaya.io/C-Meta
https://raw.githubusercontent.com/proco2024/channel/main/Telegram%3A%40config_proxy-14041130-026.txt
https://raw.githubusercontent.com/Ali-Anv1/C-Meta/refs/heads/main/C-Meta.txt
https://raw.githubusercontent.com/liketolivefree/kobabi/main/prov_clash.yaml
https://tester.mr-afzoni.workers.dev/sub/normal/3170323?app=xray#%F0%9F%92%A6%20BPB%20Normal
https://tester.mr-afzoni.workers.dev/sub/fragment/3170323?app=xray#%F0%9F%92%A6%20BPB%20Fragment
https://tester.mr-afzoni.workers.dev/sub/warp/3170323?app=xray#%F0%9F%92%A6%20BPB%20Warp
https://tester.mr-afzoni.workers.dev/sub/warp-pro/3170323?app=xray#%F0%9F%92%A6%20BPB%20Warp%20Pro
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Movaghat
https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Clash_Reality
https://raw.githubusercontent.com/xtoolkit/TVC/main/subscriptions/meta/mix
https://raw.githubusercontent.com/HenryPorternew/sub/refs/heads/main/raw.txt
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
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs.txt
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs2.txt
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt
https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs4.txt
https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt
https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt
https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt
`.split("\n").map(s => s.trim()).filter(Boolean))];

// =====================================================
// ۲. موتور اصلی
// =====================================================
async function main() {
    let allProxies = [];
    console.log(`🚀 Starting Full Aggregation at: ${new Date().toISOString()}`);
    console.log(`📋 Total sources: ${SUBS.length}`);

    const fetchPromises = SUBS.map(async (sub) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
        try {
            console.log(`📡 Fetching: ${sub}`);
            const res = await fetch(sub, { signal: controller.signal });
            clearTimeout(timer);
            if (!res.ok) { console.warn(`⚠️  Skip (${res.status}): ${sub}`); return []; }

            const raw     = await res.text();
            const decoded = decodeSub(raw);
            const parsed  = detectAndParse(decoded);

            const cleaned = [];
            for (let p of parsed) {
                p = sanitizeObj(p);

                if (p.type) {
                    p.type = p.type.toLowerCase();
                    if (p.type === "shadowsocks") p.type = "ss";
                    if (p.type === "socks")       p.type = "socks5";
                    // FIX: mihomo فقط "wireguard" قبول می‌کنه
                    if (p.type === "wg")           p.type = "wireguard";
                }

                p = normalizeProxy(p);
                p = fixProxyArrayFields(p);
                p.name = p.name || "Unnamed";

                if (valid(p) && p.type !== 'inline') cleaned.push(p);
            }
            return cleaned;
        } catch (e) {
            clearTimeout(timer);
            console.error(`❌ Error with ${sub}: ${e.message}`);
            return [];
        }
    });

    const results = await Promise.allSettled(fetchPromises);
    results.forEach(r => { if (r.status === "fulfilled") allProxies.push(...r.value); });

    const unique = dedupe(allProxies);
    console.log(`✅ Total unique proxies collected: ${unique.length}`);
    generateFiles(unique);
}

// =====================================================
// ۳. تشخیص فرمت و parse
// =====================================================
function detectAndParse(text) {
    const trimmed = text.trim();

    // JSON آرایه
    if (trimmed.startsWith('[')) {
        try {
            const arr = JSON.parse(trimmed);
            if (Array.isArray(arr)) return parseJsonProxyArray(arr);
        } catch (_) {}
    }

    // JSON object
    if (trimmed.startsWith('{') || trimmed.includes('"proxies"') || trimmed.includes('"outbounds"')) {
        let jsonData = null;
        try { jsonData = JSON.parse(trimmed); } catch (_) {}

        if (!jsonData) {
            const m = trimmed.match(/"proxies"\s*:\s*(\[[\s\S]*?\])(?:\s*[,}]|$)/);
            if (m) try { jsonData = { proxies: JSON.parse(m[1]) }; } catch (_) {}
        }

        if (jsonData) {
            if (Array.isArray(jsonData.proxies))   return parseJsonProxyArray(jsonData.proxies);
            if (Array.isArray(jsonData.outbounds)) return parseXrayOutbounds(jsonData.outbounds);
            if (jsonData.type && jsonData.server) {
                const p = parseSingboxOutbound(jsonData);
                return p ? [p] : [];
            }
        }

        const outM = trimmed.match(/"outbounds"\s*:\s*(\[[\s\S]*?\])(?:\s*[,}]|$)/);
        if (outM) {
            try {
                const outbounds = JSON.parse(outM[1]);
                if (Array.isArray(outbounds)) return parseXrayOutbounds(outbounds);
            } catch (_) {}
        }
    }

    // WireGuard standard config format
    if (/^\s*\[Interface\]/im.test(text)) {
        return parseWireguardConfig(text);
    }

    // YAML
    if (/^\s*proxies:/m.test(text) || /^\s*-\s*name:/m.test(text) || /^\s*-\s*\{/m.test(text)) {
        return extractYamlConfigs(text);
    }

    // URI lines
    const result = [];
    for (const line of text.split("\n")) {
        const p = parseProxy(line.trim());
        if (p) result.push(p);
    }
    return result;
}

// =====================================================
// ۴. JSON Proxy Array Parser
// =====================================================
function parseJsonProxyArray(arr) {
    const result = [];
    for (const item of arr) {
        if (!item || typeof item !== 'object') continue;
        if (
            item.server_port !== undefined ||
            item.private_key !== undefined ||
            item.peer_public_key !== undefined
        ) {
            const p = parseSingboxOutbound(item);
            if (p) result.push(p);
        } else if (item.type || item.protocol) {
            result.push(item);
        }
    }
    return result;
}

// =====================================================
// ۵. Singbox Outbound Parser
// =====================================================
function parseSingboxOutbound(item) {
    try {
        const type = (item.type || "").toLowerCase();
        const typeMap = {
            "wireguard":   "wireguard",
            "vless":       "vless",
            "vmess":       "vmess",
            "trojan":      "trojan",
            "shadowsocks": "ss",
            "hysteria2":   "hysteria2",
            "socks":       "socks5",
            "http":        "http",
            "ssh":         "ssh",
            "tuic":        "tuic",
        };
        const clashType = typeMap[type];
        if (!clashType) return null;

        if (clashType === "wireguard") {
            const proxy = {
                name:          item.tag || item.name || "",
                type:          "wireguard",
                server:        item.server || "",
                port:          parseInt(item.server_port || item.port) || 0,
                "private-key": item.private_key || item["private-key"] || "",
                "public-key":  item.peer_public_key || item["public-key"] || "",
                udp:           true,
            };
            if (item.local_address) {
                const addrs = Array.isArray(item.local_address) ? item.local_address : [item.local_address];
                for (const addr of addrs) {
                    const clean = String(addr).split("/")[0].trim();
                    if (clean.includes(":")) { if (!proxy.ipv6) proxy.ipv6 = clean; }
                    else                     { if (!proxy.ip)   proxy.ip   = clean; }
                }
            }
            if (item.ip)  proxy.ip  = String(item.ip).split("/")[0].trim();
            if (item.mtu) proxy.mtu = parseInt(item.mtu);
            if (item.reserved !== undefined) proxy.reserved = item.reserved;
            proxy["allowed-ips"] = ["0.0.0.0/0", "::/0"];
            return proxy;
        }

        if (clashType === "hysteria2") {
            const proxy = {
                name:     item.tag || item.name || "",
                type:     "hysteria2",
                server:   item.server || "",
                port:     parseInt(item.server_port || item.port) || 0,
                password: item.password || "",
                udp:      true,
            };
            if (item.tls) {
                if (item.tls.server_name) proxy.sni = item.tls.server_name;
                if (item.tls.insecure)    proxy["skip-cert-verify"] = true;
                if (item.tls.alpn)        proxy.alpn = Array.isArray(item.tls.alpn) ? item.tls.alpn : [item.tls.alpn];
                if (item.tls.certificate) proxy.ca   = item.tls.certificate;
            }
            if (item.obfs && item.obfs.type === "salamander") {
                proxy.obfs             = "salamander";
                proxy["obfs-password"] = item.obfs.password || "";
            }
            if (item.up_mbps)   proxy.up   = String(item.up_mbps);
            if (item.down_mbps) proxy.down = String(item.down_mbps);
            return proxy;
        }

        // FIX: TUIC — تفکیک v4 (token) از v5 (uuid+password)
        if (clashType === "tuic") {
            const proxy = {
                name:   item.tag || item.name || "",
                type:   "tuic",
                server: item.server || "",
                port:   parseInt(item.server_port || item.port) || 0,
                udp:    true,
            };
            // v4
            if (item.token) {
                proxy.token = item.token;
            }
            // v5
            if (item.uuid)     proxy.uuid     = item.uuid;
            if (item.password) proxy.password  = item.password;
            if (item.tls) {
                if (item.tls.server_name) proxy.sni = item.tls.server_name;
                if (item.tls.insecure)    proxy["skip-cert-verify"] = true;
                if (item.tls.alpn)        proxy.alpn = Array.isArray(item.tls.alpn) ? item.tls.alpn : [item.tls.alpn];
            }
            return proxy;
        }

        const proxy = {
            name:   item.tag || item.name || "",
            type:   clashType,
            server: item.server || "",
            port:   parseInt(item.server_port || item.port) || 0,
        };
        if (item.uuid)     proxy.uuid     = item.uuid;
        if (item.password) proxy.password = item.password;
        if (item.username) proxy.username = item.username;
        return proxy;
    } catch (_) { return null; }
}

// =====================================================
// ۶. Xray Outbounds Parser
// =====================================================
function parseXrayOutbounds(outbounds) {
    const result = [];
    for (const ob of outbounds) {
        if (!ob || typeof ob !== 'object') continue;
        const protocol = (ob.protocol || "").toLowerCase();
        if (protocol !== "wireguard") continue;
        try {
            const settings = ob.settings || {};
            const peers    = Array.isArray(settings.peers) ? settings.peers : [];
            if (peers.length === 0) continue;
            const peer = peers[0];

            let server = "", port = 0;
            if (peer.endpoint) {
                const lastColon = peer.endpoint.lastIndexOf(":");
                if (lastColon > 0) {
                    server = peer.endpoint.substring(0, lastColon);
                    port   = parseInt(peer.endpoint.substring(lastColon + 1)) || 0;
                }
            }

            const proxy = {
                name:          ob.tag || "",
                type:          "wireguard",
                server,
                port,
                "private-key": settings.secretKey || settings["private-key"] || "",
                "public-key":  peer.publicKey || peer["public-key"] || "",
                udp:           true,
            };
            if (Array.isArray(settings.address)) {
                for (const addr of settings.address) {
                    const clean = String(addr).split("/")[0].trim();
                    if (clean.includes(":")) { if (!proxy.ipv6) proxy.ipv6 = clean; }
                    else                     { if (!proxy.ip)   proxy.ip   = clean; }
                }
            }
            if (Array.isArray(settings.reserved)) proxy.reserved = settings.reserved;
            if (settings.mtu) proxy.mtu = parseInt(settings.mtu);
            proxy["allowed-ips"] = ["0.0.0.0/0", "::/0"];
            result.push(proxy);
        } catch (_) {}
    }
    return result;
}

// =====================================================
// ۷. YAML Parser — با پشتیبانی از ۳ سطح nested
// =====================================================
function extractYamlConfigs(text) {
    const proxies           = [];
    let current             = null;
    let nestedStack         = []; // [{key, indent, value}] — stack برای nested objects
    const knownListKeys     = new Set(["allowed-ips", "dns", "alpn", "peers", "h2-opts-host"]);

    function flushCurrent() {
        if (current && current.type && current.server) proxies.push(current);
    }

    for (const line of text.split(/\r?\n/)) {
        if (line.trim().startsWith('#')) continue;

        const listMatch = line.match(/^(\s*)-\s*(.*)$/);
        if (listMatch) {
            const indent    = listMatch[1].length;
            const remainder = listMatch[2].trim();

            // آیا این آیتم به یه لیست nested تعلق داره؟
            if (current && nestedStack.length > 0) {
                const top = nestedStack[nestedStack.length - 1];
                if (indent > top.indent && Array.isArray(top.value)) {
                    // این آیتم به لیست nested اضافه می‌شه
                    if (remainder.startsWith('{')) {
                        const inlineObj = parseInlineYaml(remainder);
                        if (inlineObj) top.value.push(inlineObj);
                    } else {
                        top.value.push(parseYamlValue(remainder));
                    }
                    continue;
                }
            }

            // شروع proxy جدید
            flushCurrent();
            current     = {};
            nestedStack = [];

            if (remainder.startsWith('{')) {
                const p = parseInlineYaml(remainder);
                if (p) proxies.push(p);
                current = null;
            } else if (remainder) {
                const kv = remainder.match(/^([a-zA-Z0-9_\-\.]+)\s*:\s*(.*)$/);
                if (kv) current[kv[1]] = parseYamlValue(kv[2]);
            }
            continue;
        }

        if (!current) continue;

        const indent     = line.match(/^(\s*)/)[1].length;
        const trimmedLine = line.trim();
        if (!trimmedLine) continue;

        // بررسی که آیا از یه nested block خارج شدیم
        while (nestedStack.length > 0 && indent <= nestedStack[nestedStack.length - 1].indent) {
            nestedStack.pop();
        }

        // لیست nested (- item داخل یه key)
        const nestedListItem = trimmedLine.match(/^-\s+(.*)$/);
        if (nestedListItem && nestedStack.length > 0) {
            const top = nestedStack[nestedStack.length - 1];
            if (!Array.isArray(top.value)) top.value = [];
            const itemVal = nestedListItem[1].trim();
            if (itemVal.startsWith('{')) {
                const inlineObj = parseInlineYaml(itemVal);
                if (inlineObj) top.value.push(inlineObj);
            } else {
                top.value.push(parseYamlValue(itemVal));
            }
            // sync back to current
            setNestedValue(current, nestedStack);
            continue;
        }

        // key: (بدون value — nested block)
        const nestedKeyOnly = line.match(/^(\s+)([a-zA-Z0-9_\-\.]+)\s*:\s*$/);
        if (nestedKeyOnly) {
            const key    = nestedKeyOnly[2];
            const isArr  = knownListKeys.has(key);
            const newVal = isArr ? [] : {};

            if (nestedStack.length === 0) {
                current[key] = newVal;
                nestedStack.push({ key, indent, value: newVal, parentObj: current });
            } else {
                const top = nestedStack[nestedStack.length - 1];
                if (typeof top.value === 'object' && !Array.isArray(top.value)) {
                    top.value[key] = newVal;
                    nestedStack.push({ key, indent, value: newVal, parentObj: top.value });
                }
            }
            continue;
        }

        // key: value (معمولی)
        const kv = line.match(/^(\s+)([a-zA-Z0-9_\-\.]+)\s*:\s*(.+)$/);
        if (kv) {
            const key = kv[2];
            const val = parseYamlValue(kv[3]);

            if (nestedStack.length > 0) {
                const top = nestedStack[nestedStack.length - 1];
                if (typeof top.value === 'object' && !Array.isArray(top.value)) {
                    top.value[key] = val;
                    // sync
                    setNestedValue(current, nestedStack);
                }
            } else {
                current[key] = val;
            }
        }
    }

    flushCurrent();
    return proxies;
}

// helper: sync nested value back to current (برای حالتی که value reference هست نیازی نیست ولی برای safety)
function setNestedValue(root, stack) {
    // چون همه object‌ها by reference هستن، نیازی به sync نیست
    // این function برای آینده reserved
}

function parseInlineYaml(str) {
    str = str.trim();
    if (!str.startsWith('{') || !str.endsWith('}')) return null;
    str = str.slice(1, -1);
    const result = {};
    let currentKey = "", currentValue = "", inKey = true, depth = 0, inQuote = false, quoteChar = '';
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char === '"' || char === "'") {
            if (!inQuote) { inQuote = true; quoteChar = char; }
            else if (quoteChar === char) inQuote = false;
        }
        if (!inQuote) {
            if (char === '{' || char === '[') depth++;
            if (char === '}' || char === ']') depth--;
            if (char === ':' && inKey && depth === 0) { inKey = false; continue; }
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
    val = val.trim();
    if (val === 'true')  return true;
    if (val === 'false') return false;
    if (/^[0-9]+$/.test(val)) return Number(val);
    if (val.startsWith('{') && val.endsWith('}')) return parseInlineYaml(val);
    if (val.startsWith('[') && val.endsWith(']'))
        return val.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
    return val.replace(/^["']|["']$/g, '');
}

// =====================================================
// ۸. URI Protocol Parsers
// =====================================================
function parseProxy(line) {
    try {
        const l = line.toLowerCase();
        if (l.startsWith("vless://"))                                return parseVless(line);
        if (l.startsWith("vmess://"))                                return parseVmess(line);
        if (l.startsWith("trojan://"))                               return parseTrojan(line);
        if (l.startsWith("anytls://"))                               return parseAnyTls(line);
        if (l.startsWith("ss://"))                                   return parseSS(line);
        if (l.startsWith("hy2://") || l.startsWith("hysteria2://"))  return parseHysteria2(line);
        if (l.startsWith("wg://") || l.startsWith("wireguard://"))   return parseWireguard(line);
        if (l.startsWith("tuic://"))                                 return parseTuic(line);
        if (l.startsWith("http://") || l.startsWith("https://"))    return parseHttp(line);
        if (l.startsWith("socks://") || l.startsWith("socks5://"))  return parseSocks(line);
        if (l.startsWith("ssh://"))                                  return parseSSH(line);
    } catch (_) {}
    return null;
}

function parseVless(link) {
    const url      = new URL(link.replace(/^vless:\/\//i, "http://"));
    const security = url.searchParams.get("security") || "";
    const network  = url.searchParams.get("type") || "tcp";

    const proxy = {
        name:    safeDecode(url.hash.substring(1) || url.hostname),
        type:    "vless",
        server:  url.hostname,
        port:    parseInt(url.port),
        uuid:    url.username || "",
        udp:     true,
        tls:     ["tls", "reality"].includes(security),
        network
    };

    const sni = url.searchParams.get("sni");
    if (sni) proxy.servername = sni;

    const fp = url.searchParams.get("fp");
    if (fp) proxy["client-fingerprint"] = fp;

    const alpn = url.searchParams.get("alpn");
    if (alpn) proxy.alpn = alpn.split(",");

    const flow = url.searchParams.get("flow");
    if (flow) proxy.flow = flow;

    const insecure = url.searchParams.get("allowInsecure") || url.searchParams.get("insecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;

    if (security === "reality") {
        proxy["reality-opts"] = { "public-key": url.searchParams.get("pbk") || "" };
        const sid = url.searchParams.get("sid");
        if (sid) proxy["reality-opts"]["short-id"] = sid;
    }

    // FIX: network=tcp نیازی به network field ندارد
    if (network === "tcp") {
        delete proxy.network;
    } else if (network === "ws") {
        const path = url.searchParams.get("path");
        const host = url.searchParams.get("host");
        if (path || host) {
            proxy["ws-opts"] = {};
            if (path) proxy["ws-opts"].path = safeDecode(path);
            if (host) proxy["ws-opts"].headers = { Host: host };
        }
    } else if (network === "grpc") {
        const serviceName = url.searchParams.get("serviceName");
        if (serviceName) proxy["grpc-opts"] = { "grpc-service-name": serviceName };
    } else if (network === "h2") {
        const path = url.searchParams.get("path");
        const host = url.searchParams.get("host");
        if (path || host) {
            proxy["h2-opts"] = {};
            if (path) proxy["h2-opts"].path = safeDecode(path);
            if (host) proxy["h2-opts"].host  = [host];
        }
    }

    return proxy;
}

function parseVmess(link) {
    try {
        const raw   = link.replace(/^vmess:\/\//i, "");
        const fixed = normalizeBase64(raw);
        if (!fixed) return null;
        const j = JSON.parse(fixed);
        if (!j.add || !j.port || !j.id) return null;

        const proxy = {
            name:    safeDecode(j.ps || j.add),
            type:    "vmess",
            server:  j.add,
            port:    parseInt(j.port),
            uuid:    j.id || "",
            alterId: parseInt(j.aid) || 0,
            cipher:  "auto",
            udp:     true
        };

        if (j.tls === "tls") {
            proxy.tls = true;
            if (j.sni) proxy.servername = j.sni;
            if (j.fp)  proxy["client-fingerprint"] = j.fp;
            if (j.alpn) proxy.alpn = typeof j.alpn === 'string' ? j.alpn.split(",") : j.alpn;
        }

        const net = j.net || j.type;
        // FIX: فقط اگه network غیر tcp باشه ست کن
        if (net && net !== "tcp") {
            proxy.network = net;
            if (net === "ws") {
                proxy["ws-opts"] = {};
                if (j.path) proxy["ws-opts"].path = j.path;
                const host = j.host || j.add;
                if (host) proxy["ws-opts"].headers = { Host: host };
            } else if (net === "grpc") {
                proxy["grpc-opts"] = { "grpc-service-name": j.path || "" };
            } else if (net === "h2") {
                proxy["h2-opts"] = {};
                if (j.path) proxy["h2-opts"].path = j.path;
                if (j.host) proxy["h2-opts"].host  = [j.host];
            }
        }

        return proxy;
    } catch (_) { return null; }
}

function parseTrojan(link) {
    const url     = new URL(link.replace(/^trojan:\/\//i, "http://"));
    const network = url.searchParams.get("type") || "tcp";

    const proxy = {
        name:     safeDecode(url.hash.substring(1) || url.hostname),
        type:     "trojan",
        server:   url.hostname,
        port:     parseInt(url.port),
        password: safeDecode(url.username) || "",
        udp:      true,
        tls:      true,
    };

    // FIX: trojan فقط ws/grpc پشتیبانی می‌کنه، tcp پیش‌فرضه و نباید نوشته بشه
    if (network === "ws" || network === "grpc") {
        proxy.network = network;
    }

    const sni = url.searchParams.get("sni") || url.searchParams.get("peer");
    if (sni) proxy.sni = sni;

    const fp = url.searchParams.get("fp");
    if (fp) proxy["client-fingerprint"] = fp;

    const alpn = url.searchParams.get("alpn");
    if (alpn) proxy.alpn = alpn.split(",");

    const insecure = url.searchParams.get("allowInsecure") || url.searchParams.get("insecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;

    const security = url.searchParams.get("security") || "";
    if (security === "reality") {
        proxy["reality-opts"] = { "public-key": url.searchParams.get("pbk") || "" };
        const sid = url.searchParams.get("sid");
        if (sid) proxy["reality-opts"]["short-id"] = sid;
    }

    if (network === "ws") {
        const path = url.searchParams.get("path");
        const host = url.searchParams.get("host");
        if (path || host) {
            proxy["ws-opts"] = {};
            if (path) proxy["ws-opts"].path = safeDecode(path);
            if (host) proxy["ws-opts"].headers = { Host: host };
        }
    } else if (network === "grpc") {
        const serviceName = url.searchParams.get("serviceName");
        if (serviceName) proxy["grpc-opts"] = { "grpc-service-name": serviceName };
    }

    return proxy;
}

function parseAnyTls(link) {
    const url = new URL(link.replace(/^anytls:\/\//i, "http://"));
    const proxy = {
        name:   safeDecode(url.hash.substring(1) || url.hostname),
        type:   "anytls",
        server: url.hostname,
        port:   parseInt(url.port),
        udp:    true,
    };

    // password معمولاً در username جای می‌گیره
    const pass = safeDecode(url.username) || safeDecode(url.password) || "";
    if (pass) proxy.password = pass;

    const sni = url.searchParams.get("sni");
    if (sni) proxy.sni = sni;

    const alpn = url.searchParams.get("alpn");
    if (alpn) proxy.alpn = alpn.split(",");

    const fp = url.searchParams.get("fp") || url.searchParams.get("fingerprint");
    if (fp) proxy["client-fingerprint"] = fp;

    const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;

    return proxy;
}

function parseSS(link) {
    const raw     = link.replace(/^ss:\/\//i, "");
    const hashIdx = raw.indexOf('#');
    const base    = hashIdx >= 0 ? raw.substring(0, hashIdx) : raw;
    const tag     = hashIdx >= 0 ? raw.substring(hashIdx + 1) : "";

    let method, password, server, port;

    if (base.includes("@")) {
        const atIdx      = base.lastIndexOf("@");
        const authPart   = base.substring(0, atIdx);
        const serverPart = base.substring(atIdx + 1);
        const decoded    = normalizeBase64(authPart) || authPart;
        const colonIdx   = decoded.indexOf(":");
        if (colonIdx < 0) return null;
        method   = decoded.substring(0, colonIdx);
        password = decoded.substring(colonIdx + 1);
        const lastColon = serverPart.lastIndexOf(":");
        if (lastColon < 0) return null;
        server = serverPart.substring(0, lastColon);
        port   = serverPart.substring(lastColon + 1);
    } else {
        const decoded = normalizeBase64(base);
        if (!decoded) return null;
        const atIdx = decoded.lastIndexOf("@");
        if (atIdx < 0) return null;
        const authPart   = decoded.substring(0, atIdx);
        const serverPart = decoded.substring(atIdx + 1);
        const colonIdx   = authPart.indexOf(":");
        if (colonIdx < 0) return null;
        method   = authPart.substring(0, colonIdx);
        password = authPart.substring(colonIdx + 1);
        const lastColon = serverPart.lastIndexOf(":");
        if (lastColon < 0) return null;
        server = serverPart.substring(0, lastColon);
        port   = serverPart.substring(lastColon + 1);
    }

    server = server.replace(/^\[|\]$/g, "");
    if (!server || !port || !method || password === undefined) return null;

    return {
        name:     safeDecode(tag || server),
        type:     "ss",
        server,
        port:     parseInt(port),
        cipher:   method.toLowerCase(),
        password: password || "",
        udp:      true
    };
}

function parseHysteria2(link) {
    const url = new URL(link.replace(/^(hy2|hysteria2):\/\//i, "http://"));

    const proxy = {
        name:     safeDecode(url.hash.substring(1) || url.hostname),
        type:     "hysteria2",
        server:   url.hostname,
        port:     parseInt(url.port),
        password: safeDecode(url.username) || "",
        udp:      true
    };

    const sni = url.searchParams.get("sni") || url.searchParams.get("peer");
    if (sni) proxy.sni = sni;

    const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;

    const alpn = url.searchParams.get("alpn");
    if (alpn) proxy.alpn = alpn.split(",");

    const obfs = url.searchParams.get("obfs");
    if (obfs && obfs.toLowerCase() === "salamander") {
        proxy.obfs = "salamander";
        const obfsPass = url.searchParams.get("obfs-password") || url.searchParams.get("obfsPassword");
        if (obfsPass) proxy["obfs-password"] = obfsPass;
    }

    const up   = url.searchParams.get("up");
    const down = url.searchParams.get("down");
    if (up)   proxy.up   = up;
    if (down) proxy.down = down;

    return proxy;
}

function parseWireguard(link) {
    const url = new URL(link.replace(/^(wg|wireguard):\/\//i, "http://"));

    const privateKey = safeDecode(
        url.username ||
        url.searchParams.get("privateKey") ||
        url.searchParams.get("private-key") || ""
    );

    const publicKey = safeDecode(
        url.searchParams.get("publickey") ||
        url.searchParams.get("public-key") ||
        url.searchParams.get("peer_public_key") ||
        url.searchParams.get("publicKey") || ""
    );

    const rawAddress = url.searchParams.get("address") || url.searchParams.get("ip") || "10.0.0.1";
    const addresses  = rawAddress.split(",").map(s => s.trim().split("/")[0]);
    let ip   = "";
    let ipv6 = "";
    for (const addr of addresses) {
        if (addr.includes(":")) { if (!ipv6) ipv6 = addr; }
        else                    { if (!ip)   ip   = addr; }
    }
    if (!ip) ip = "10.0.0.1";

    const proxy = {
        name:          safeDecode(url.hash.substring(1) || url.hostname),
        type:          "wireguard",
        server:        url.hostname,
        port:          parseInt(url.port) || 51820,
        ip,
        "private-key": privateKey,
        "public-key":  publicKey,
        udp:           true,
    };
    if (ipv6) proxy.ipv6 = ipv6;

    const allowedIps = url.searchParams.get("allowedIPs") ||
                       url.searchParams.get("allowed-ips") ||
                       url.searchParams.get("allowed_ips");
    if (allowedIps)
        proxy["allowed-ips"] = allowedIps.split(",").map(s => s.trim()).filter(Boolean);

    const reserved = url.searchParams.get("reserved");
    if (reserved) {
        const parts = reserved.split(",").map(Number);
        if (parts.length === 3 && parts.every(n => !isNaN(n) && n >= 0 && n <= 255))
            proxy.reserved = parts;
    }

    const mtu = url.searchParams.get("mtu");
    if (mtu) proxy.mtu = parseInt(mtu);

    const keepalive = url.searchParams.get("keepalive") ||
                      url.searchParams.get("persistentkeepalive") ||
                      url.searchParams.get("persistent-keepalive");
    if (keepalive) proxy["persistent-keepalive"] = parseInt(keepalive);

    const dns = url.searchParams.get("dns");
    if (dns) {
        proxy["remote-dns-resolve"] = true;
        proxy.dns = dns.split(",").map(s => s.trim()).filter(Boolean);
    }

    const awgFields = ["wnoise","wnoisecount","wnoisedelay","wpayloadsize",
                       "jc","jmin","jmax","h1","h2","h3","h4","s1","s2","i1","i2","i3","i4","i5","j1","j2","j3","itime"];
    const awgOpt = {};
    for (const f of awgFields) {
        const v = url.searchParams.get(f);
        if (v !== null) {
            const num = Number(v);
            awgOpt[f] = isNaN(num) ? v : num;
        }
    }
    if (Object.keys(awgOpt).length > 0) proxy["amnezia-wg-option"] = awgOpt;

    return proxy;
}

// FIX: parseWireguardConfig — چند [Peer] section به درستی split می‌شه
function parseWireguardConfig(text) {
    const proxies  = [];
    let sections   = { interface: null, peer: null };
    let current    = null;

    function tryBuild() {
        if (sections.interface && sections.peer) {
            const p = buildWgFromSections(sections.interface, sections.peer);
            if (p) proxies.push(p);
        }
    }

    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || line.startsWith(';')) continue;

        const secMatch = line.match(/^\[(\w+)\]$/);
        if (secMatch) {
            const secName = secMatch[1].toLowerCase();
            // FIX: وقتی section جدید [Peer] می‌بینیم، peer قبلی رو build کن
            if (secName === 'peer' && sections.peer && Object.keys(sections.peer).length > 0) {
                tryBuild();
                sections.peer = {};
            } else if (secName === 'peer') {
                sections.peer = {};
            } else if (secName === 'interface') {
                sections.interface = {};
            }
            current = secName;
            continue;
        }

        if (current && sections[current] !== null) {
            const kv = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
            if (kv) {
                sections[current][kv[1].trim()] = kv[2].trim();
            }
        }
    }

    // آخرین peer
    tryBuild();

    return proxies;
}

function buildWgFromSections(iface, peer) {
    const endpoint = peer.Endpoint || peer.endpoint || "";
    let server = "", port = 0;
    if (endpoint) {
        const ipv6Match = endpoint.match(/^\[([^\]]+)\]:(\d+)$/);
        if (ipv6Match) {
            server = ipv6Match[1];
            port   = parseInt(ipv6Match[2]);
        } else {
            const lastColon = endpoint.lastIndexOf(":");
            if (lastColon > 0) {
                server = endpoint.substring(0, lastColon);
                port   = parseInt(endpoint.substring(lastColon + 1));
            }
        }
    }
    if (!server || !port) return null;

    const privKey = iface.PrivateKey || iface.privatekey || "";
    const pubKey  = peer.PublicKey   || peer.publickey   || "";
    if (!privKey || !pubKey) return null;

    const rawAddr   = iface.Address || iface.address || "";
    const addresses = rawAddr.split(",").map(s => s.trim().split("/")[0]);
    let ip   = "";
    let ipv6 = "";
    for (const addr of addresses) {
        if (addr.includes(":")) { if (!ipv6) ipv6 = addr; }
        else                    { if (!ip)   ip   = addr; }
    }
    if (!ip) ip = "10.0.0.1";

    const proxy = {
        name:          "",
        type:          "wireguard",
        server,
        port,
        ip,
        "private-key": privKey,
        "public-key":  pubKey,
        udp:           true,
    };
    if (ipv6) proxy.ipv6 = ipv6;

    const allowed = peer.AllowedIPs || peer.allowedips || "0.0.0.0/0";
    proxy["allowed-ips"] = allowed.split(",").map(s => s.trim()).filter(Boolean);

    const mtu = iface.MTU || iface.mtu;
    if (mtu) proxy.mtu = parseInt(mtu);

    const ka = peer.PersistentKeepalive || peer.persistentkeepalive;
    if (ka) proxy["persistent-keepalive"] = parseInt(ka);

    const psk = peer.PresharedKey || peer.presharedkey;
    if (psk) proxy["pre-shared-key"] = psk;

    const dns = iface.DNS || iface.dns;
    if (dns) {
        proxy["remote-dns-resolve"] = true;
        proxy.dns = dns.split(",").map(s => s.trim()).filter(Boolean);
    }

    const awgMap = {
        Jc:"jc", Jmin:"jmin", Jmax:"jmax", H1:"h1", H2:"h2", H3:"h3", H4:"h4",
        S1:"s1", S2:"s2", I1:"i1", I2:"i2", I3:"i3", I4:"i4", I5:"i5",
        J1:"j1", J2:"j2", J3:"j3", Itime:"itime"
    };
    const awgOpt = {};
    for (const [ifaceKey, outKey] of Object.entries(awgMap)) {
        const v = iface[ifaceKey];
        if (v !== undefined && v !== "") {
            const num = Number(v);
            awgOpt[outKey] = isNaN(num) ? v : num;
        }
    }
    if (Object.keys(awgOpt).length > 0) proxy["amnezia-wg-option"] = awgOpt;

    return proxy;
}

// FIX: parseTuic — uuid+password از uri (v5)؛ token برای v4
function parseTuic(link) {
    const url = new URL(link.replace(/^tuic:\/\//i, "http://"));

    const proxy = {
        name:   safeDecode(url.hash.substring(1) || url.hostname),
        type:   "tuic",
        server: url.hostname,
        port:   parseInt(url.port),
        uuid:   safeDecode(url.username) || "",
        password: safeDecode(url.password) || "",
        udp:    true
    };

    const sni = url.searchParams.get("sni");
    if (sni) proxy.sni = sni;

    const alpn = url.searchParams.get("alpn");
    if (alpn) proxy.alpn = alpn.split(",");

    const congestion = url.searchParams.get("congestion_control") || url.searchParams.get("congestion-control");
    if (congestion) proxy["congestion-controller"] = congestion;

    const udpRelay = url.searchParams.get("udp_relay_mode") || url.searchParams.get("udp-relay-mode");
    if (udpRelay) proxy["udp-relay-mode"] = udpRelay;

    const insecure = url.searchParams.get("insecure") || url.searchParams.get("allowInsecure");
    if (insecure === "1" || insecure === "true") proxy["skip-cert-verify"] = true;

    const fp = url.searchParams.get("fp");
    if (fp) proxy["client-fingerprint"] = fp;

    return proxy;
}

function parseHttp(link) {
    const isHttps = link.toLowerCase().startsWith("https://");
    const url     = new URL(link);
    const p = {
        name:   safeDecode(url.hash.substring(1) || url.hostname),
        type:   "http",
        server: url.hostname,
        port:   parseInt(url.port) || (isHttps ? 443 : 80),
    };
    if (isHttps) p.tls = true;
    const u = safeDecode(url.username); if (u) p.username = u;
    const w = safeDecode(url.password); if (w) p.password = w;
    return p;
}

function parseSocks(link) {
    const url = new URL(link.replace(/^(socks|socks5):\/\//i, "http://"));
    const p = {
        name:   safeDecode(url.hash.substring(1) || url.hostname),
        type:   "socks5",
        server: url.hostname,
        port:   parseInt(url.port) || 1080,
        udp:    true,
    };
    const u = safeDecode(url.username); if (u) p.username = u;
    const w = safeDecode(url.password); if (w) p.password = w;
    return p;
}

function parseSSH(link) {
    const url = new URL(link.replace(/^ssh:\/\//i, "http://"));
    const p = {
        name:   safeDecode(url.hash.substring(1) || url.hostname),
        type:   "ssh",
        server: url.hostname,
        port:   parseInt(url.port) || 22,
    };
    const u = safeDecode(url.username); if (u) p.username = u;
    const w = safeDecode(url.password); if (w) p.password = w;
    return p;
}

// =====================================================
// ۹. Normalize & Fix
// =====================================================
function normalizeProxy(p) {
    if (p.port) p.port = parseInt(p.port);

    if (p.ip   && typeof p.ip   === 'string') p.ip   = p.ip.split("/")[0].trim();
    if (p.ipv6 && typeof p.ipv6 === 'string') p.ipv6 = p.ipv6.split("/")[0].trim();

    // FIX: username/password خالی رو حذف کن — mihomo اگه username ببینه باید non-empty باشه
    if (p.username !== undefined && (p.username === "" || p.username === null)) delete p.username;
    if (p.password !== undefined && (p.password === "" || p.password === null)) {
        // password خالی رو فقط برای پروتکل‌هایی که واقعاً نیازش ندارن حذف کن
        // (trojan, hysteria2, anytls, tuic در valid() چک می‌شن)
        if (!["trojan","hysteria2","anytls","tuic","ss"].includes(p.type)) {
            delete p.password;
        }
    }

    // نرمال‌سازی reserved
    if (p.reserved !== undefined && !Array.isArray(p.reserved)) {
        if (typeof p.reserved === 'string' && p.reserved.trim() !== '') {
            const parts = p.reserved.split(",").map(Number);
            if (parts.length === 3 && parts.every(n => !isNaN(n))) {
                p.reserved = parts;
            } else {
                try {
                    let b64 = p.reserved.trim().replace(/-/g, "+").replace(/_/g, "/");
                    const pad = b64.length % 4;
                    if (pad === 2) b64 += "==";
                    else if (pad === 3) b64 += "=";
                    const bytes = Buffer.from(b64, 'base64');
                    if (bytes.length === 3) p.reserved = [...bytes];
                    else delete p.reserved;
                } catch (_) { delete p.reserved; }
            }
        } else { delete p.reserved; }
    }

    if (p["dialer-proxy"] !== undefined &&
        (p["dialer-proxy"] === "" || p["dialer-proxy"] === null)) {
        delete p["dialer-proxy"];
    }

    // FIX: network validation — فقط مقادیر معتبر
    if (p.network !== undefined) {
        const validNetworks = ["ws", "http", "h2", "grpc"];
        // FIX: اگه tcp باشه، network رو حذف کن (tcp پیش‌فرضه، نوشتنش مشکل ایجاد نمی‌کنه ولی تمیزتره)
        if (p.network === "tcp") {
            delete p.network;
            // اما opts رو نگه دار اگه مرتبط باشن (برای tcp معمولاً نیستن)
        } else if (!validNetworks.includes(p.network)) {
            delete p.network;
            delete p["ws-opts"];
            delete p["h2-opts"];
            delete p["grpc-opts"];
            delete p["http-opts"];
        }
    }

    // اعتبارسنجی client-fingerprint
    if (p["client-fingerprint"] !== undefined) {
        const validFp = ["chrome", "firefox", "safari", "iOS", "android", "edge", "360", "qq", "random"];
        if (!validFp.includes(p["client-fingerprint"])) delete p["client-fingerprint"];
    }

    // اعتبارسنجی cipher برای vmess
    if (p.type === "vmess" && p.cipher !== undefined) {
        const validCiphers = ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];
        if (!validCiphers.includes(p.cipher)) p.cipher = "auto";
    }

    // اعتبارسنجی obfs برای hysteria2
    if (p.type === "hysteria2" && p.obfs !== undefined) {
        if (p.obfs !== "salamander") delete p.obfs;
    }

    return p;
}

function fixProxyArrayFields(p) {
    if (p.type === "wireguard" || p.type === "wg") {
        if (p["allowed-ips"] !== undefined && !Array.isArray(p["allowed-ips"])) {
            if (typeof p["allowed-ips"] === 'string' && p["allowed-ips"].trim() !== '') {
                p["allowed-ips"] = p["allowed-ips"].split(",").map(s => s.trim()).filter(Boolean);
            } else { delete p["allowed-ips"]; }
        }
        if (p.dns !== undefined && !Array.isArray(p.dns)) {
            if (typeof p.dns === 'string' && p.dns.trim() !== '') {
                p.dns = p.dns.split(",").map(s => s.trim()).filter(Boolean);
            } else { delete p.dns; }
        }
        if (p.reserved !== undefined && !Array.isArray(p.reserved)) delete p.reserved;
    }

    if (p.alpn !== undefined && !Array.isArray(p.alpn)) {
        if (typeof p.alpn === 'string' && p.alpn.trim() !== '') {
            p.alpn = p.alpn.split(",").map(s => s.trim()).filter(Boolean);
        } else { delete p.alpn; }
    }

    return p;
}

// =====================================================
// ۱۰. Validation
// =====================================================
const VALID_SS_CIPHERS = new Set([
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20-ietf", "chacha20", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
    "rabbit128-poly1305", "aegis-128l", "aegis-256",
    "aez-384", "deoxys-ii-256-128",
    "rc4-md5", "none"
]);

function valid(p) {
    if (!p.server || typeof p.server !== 'string' || p.server.trim() === '') return false;
    if (!p.port   || isNaN(p.port) || p.port < 1 || p.port > 65535)          return false;

    const blockedServers = [
        "127.0.0.1", "0.0.0.0", "localhost", "::1",
        "t.me", "github.com", "raw.githubusercontent.com", "google.com"
    ];
    if (blockedServers.some(s => p.server.toLowerCase().includes(s))) return false;

    // opts فیلدها باید object باشن
    const optsFields = ["ws-opts", "grpc-opts", "h2-opts", "reality-opts", "http-opts"];
    for (const f of optsFields) {
        if (p[f] !== undefined && (typeof p[f] !== 'object' || Array.isArray(p[f]))) return false;
    }

    // array فیلدها باید array باشن
    const arrayFields = ["allowed-ips", "dns", "alpn", "reserved"];
    for (const f of arrayFields) {
        if (p[f] !== undefined && !Array.isArray(p[f])) return false;
    }

    // اعتبارسنجی reserved
    if (p.reserved !== undefined) {
        if (!Array.isArray(p.reserved) || p.reserved.length !== 3) return false;
        if (!p.reserved.every(n => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 255)) return false;
    }

    // اعتبارسنجی reality-opts
    if (p["reality-opts"]) {
        const pbk = p["reality-opts"]["public-key"];
        if (!pbk || typeof pbk !== 'string') return false;
        const cleanPbk = pbk.replace(/=/g, "").trim();
        if (cleanPbk.length !== 43 || !/^[A-Za-z0-9\-_]+$/.test(cleanPbk)) return false;
        const sid = p["reality-opts"]["short-id"];
        if (sid !== undefined && sid !== "") {
            if (typeof sid !== 'string' || !/^[0-9a-fA-F]*$/.test(sid) ||
                sid.length % 2 !== 0 || sid.length > 16) return false;
        }
    }

    switch (p.type) {
        case "vless":
            if (!p.uuid || typeof p.uuid !== 'string' || p.uuid.trim() === '') return false;
            if (!/^[0-9a-f-]{32,36}$/i.test(p.uuid.replace(/-/g, "").padEnd(32))) return false;
            break;
        case "vmess":
            if (!p.uuid || typeof p.uuid !== 'string' || p.uuid.trim() === '') return false;
            if (p.alterId === undefined || isNaN(p.alterId)) return false;
            break;
        case "trojan":
            if (!p.password || typeof p.password !== 'string' || p.password.trim() === '') return false;
            break;
        case "hysteria2":
            if (!p.password || typeof p.password !== 'string' || p.password.trim() === '') return false;
            if (p.obfs && p.obfs !== "salamander") return false;
            break;
        // FIX: TUIC v4 (token) و v5 (uuid+password) هر دو معتبرند
        case "tuic": {
            const hasV4 = p.token && typeof p.token === 'string' && p.token.trim() !== '';
            const hasV5 = p.uuid  && typeof p.uuid  === 'string' && p.uuid.trim()  !== '' &&
                          p.password && typeof p.password === 'string' && p.password.trim() !== '';
            if (!hasV4 && !hasV5) return false;
            break;
        }
        case "wireguard":
            if (!p["private-key"] || p["private-key"].trim() === '') return false;
            if (!p["public-key"]  || p["public-key"].trim()  === '') return false;
            break;
        case "ss": {
            if (!p.cipher || !p.password) return false;
            const cipher = p.cipher.toLowerCase();
            if (!VALID_SS_CIPHERS.has(cipher)) return false;
            if (cipher.startsWith("2022-")) {
                try {
                    const keys      = p.password.split(":");
                    const fixedKeys = [];
                    for (const k of keys) {
                        let cleanK = k.trim().replace(/-/g, "+").replace(/_/g, "/");
                        const pad  = cleanK.length % 4;
                        if (pad === 1) return false;
                        if (pad === 2) cleanK += "==";
                        if (pad === 3) cleanK += "=";
                        if (!/^[A-Za-z0-9+/]+=*$/.test(cleanK)) return false;
                        Buffer.from(cleanK, 'base64');
                        fixedKeys.push(cleanK);
                    }
                    p.password = fixedKeys.join(":");
                } catch (_) { return false; }
            }
            break;
        }
        case "anytls":
            if (!p.password || p.password.trim() === '') return false;
            break;
        case "ssh":
        case "http":
        case "socks5":
            break;
    }

    return true;
}

// =====================================================
// ۱۱. Dedupe — بر اساس fingerprint واقعی سرور
// =====================================================
function dedupe(list) {
    const m = new Map();
    for (const p of list) {
        // FIX: TUIC هم token (v4) هم uuid (v5) رو چک کن
        const key = p.token || p.uuid || p.password || p["auth-str"] || p["private-key"] || p.psk || p.username || "";
        const fp  = `${p.type}|${p.server}|${p.port}|${key}`;
        if (!m.has(fp)) m.set(fp, p);
    }
    return [...m.values()];
}

// =====================================================
// ۱۲. تولید فایل‌های خروجی
// =====================================================
function normalizeTypeName(t) {
    if (!t) return "unknown";
    const s = t.toLowerCase();
    if (s === "hysteria2") return "hy2";
    if (s === "wireguard") return "wg";
    if (s === "socks5")    return "socks";
    return s;
}

function generateFiles(proxies) {
    const protocolOrder = {
        "hy2": 1, "vless": 2, "anytls": 3, "trojan": 4, "ss": 5,
        "vmess": 6, "wg": 7, "tuic": 8, "http": 9, "socks": 10, "ssh": 11
    };

    const categories = {
        "all":    () => true,
        "v2ray":  (p) => ['vless', 'vmess'].includes(p.type),
        "others": (p) => !['vless', 'vmess'].includes(p.type)
    };

    for (const [mode, filterFn] of Object.entries(categories)) {
        let filtered = proxies.filter(filterFn);

        // گروه‌بندی بر اساس پروتکل
        const grouped = {};
        for (const p of filtered) {
            if (!grouped[p.type]) grouped[p.type] = [];
            grouped[p.type].push(p);
        }

        // Fisher-Yates shuffle هر گروه + برش به MAX_PER_PROTOCOL
        const randomized = [];
        for (const type in grouped) {
            const group = grouped[type];
            for (let i = group.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [group[i], group[j]] = [group[j], group[i]];
            }
            randomized.push(...group.slice(0, MAX_PER_PROTOCOL));
        }

        // مرتب‌سازی بر اساس اولویت پروتکل
        randomized.sort((a, b) =>
            (protocolOrder[normalizeTypeName(a.type)] || 99) -
            (protocolOrder[normalizeTypeName(b.type)] || 99)
        );

        // نام‌گذاری ترتیبی
        const typeCounters = {};
        const finalProxies = randomized.map(p => {
            const dt = normalizeTypeName(p.type);
            typeCounters[dt] = (typeCounters[dt] || 0) + 1;
            return { ...p, name: `${dt} ${typeCounters[dt]}` };
        });

        const header = `# Last Update: ${new Date().toISOString()}\n# Proxy Aggregator — mode: ${mode}\n`;
        const content = header + buildProvider(finalProxies);
        fs.writeFileSync(`${mode}.yaml`, content, 'utf-8');
        console.log(`📂 Created: ${mode}.yaml — ${finalProxies.length} proxies`);
    }
}

// =====================================================
// ۱۳. YAML Builder — کاملاً بر اساس مستندات رسمی mihomo
// =====================================================

const PROTO_FIELDS = {
    _common:    ["udp", "ip-version", "tfo", "mptcp", "interface-name", "routing-mark", "dialer-proxy"],
    _tls:       ["tls", "sni", "servername", "fingerprint", "alpn", "skip-cert-verify",
                 "client-fingerprint", "reality-opts", "ech-opts"],
    // FIX: transport فقط برای vless/vmess — trojan فقط network+ws-opts+grpc-opts
    _transport: ["network", "ws-opts", "h2-opts", "grpc-opts", "http-opts"],

    vless:     ["uuid", "flow", "packet-encoding", "encryption"],
    vmess:     ["uuid", "alterId", "cipher", "packet-encoding", "global-padding", "authenticated-length"],
    // FIX: trojan فقط ws/grpc دارد — h2-opts و http-opts حذف شدن
    trojan:    ["password", "ss-opts", "network", "ws-opts", "grpc-opts"],
    anytls:    ["password", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"],
    ss:        ["cipher", "password", "udp-over-tcp", "udp-over-tcp-version", "plugin", "plugin-opts"],
    wireguard: ["ip", "ipv6", "private-key", "public-key", "allowed-ips",
                "pre-shared-key", "reserved", "persistent-keepalive", "mtu",
                "remote-dns-resolve", "dns", "peers", "amnezia-wg-option"],
    hysteria2: ["password", "obfs", "obfs-password", "up", "down",
                "ports", "hop-interval", "fast-open",
                "sni", "skip-cert-verify", "fingerprint", "alpn", "ca", "ca-str"],
    // FIX: TUIC — هر دو token (v4) و uuid+password (v5)
    tuic:      ["token", "uuid", "password", "ip", "heartbeat-interval",
                "disable-sni", "reduce-rtt", "request-timeout",
                "udp-relay-mode", "congestion-controller",
                "max-udp-relay-packet-size", "fast-open", "max-open-streams",
                "sni", "alpn", "skip-cert-verify", "fingerprint"],
    ssh:       ["username", "password", "private-key", "private-key-passphrase",
                "host-key", "host-key-algorithms"],
    http:      ["username", "password", "tls", "sni", "skip-cert-verify", "headers"],
    socks5:    ["username", "password", "tls", "skip-cert-verify"],
};

const NESTED_OBJ_FIELDS = new Set([
    "ws-opts", "h2-opts", "grpc-opts", "http-opts",
    "reality-opts", "ech-opts", "ss-opts", "plugin-opts",
    "amnezia-wg-option", "smux",
]);

// ── FIX: peers باید به صورت array of objects نوشته بشه
const ARRAY_OF_OBJ_FIELDS = new Set(["peers"]);

function yamlStr(val) {
    return '"' + String(val)
        .replace(/\\/g,  "\\\\")
        .replace(/"/g,   '\\"')
        .replace(/\n/g,  "\\n")
        .replace(/\r/g,  "\\r")
        .replace(/\t/g,  "\\t")
        .replace(/\x00/g,"") + '"';
}

function yamlValue(val) {
    if (val === null || val === undefined) return null;
    if (typeof val === 'boolean') return String(val);
    if (typeof val === 'number')  return String(val);
    if (typeof val === 'string')  return yamlStr(val);
    return null;
}

// FIX: writeNestedObj — از recursion استفاده می‌کنه برای هر عمقی
function writeNestedObj(obj, indent) {
    let out = "";
    const pad = " ".repeat(indent);
    for (const k in obj) {
        const v = obj[k];
        if (v === null || v === undefined) continue;
        if (Array.isArray(v)) {
            if (v.length === 0) continue;
            // آیا آرایه‌ای از objectهاست؟
            if (typeof v[0] === 'object' && v[0] !== null) {
                out += `${pad}${k}:\n`;
                for (const item of v) {
                    const keys = Object.keys(item);
                    if (keys.length === 0) continue;
                    // اولین key با - شروع می‌شه
                    const firstKey = keys[0];
                    const firstVal = yamlValue(item[firstKey]);
                    if (firstVal !== null) {
                        out += `${pad}  - ${firstKey}: ${firstVal}\n`;
                    } else {
                        out += `${pad}  -\n`;
                    }
                    for (let i = 1; i < keys.length; i++) {
                        const kk = keys[i];
                        const vv = item[kk];
                        if (vv === null || vv === undefined) continue;
                        if (Array.isArray(vv)) {
                            out += `${pad}    ${kk}:\n`;
                            for (const ai of vv) {
                                const sv = yamlValue(ai);
                                if (sv !== null) out += `${pad}      - ${sv}\n`;
                            }
                        } else {
                            const sv = yamlValue(vv);
                            if (sv !== null) out += `${pad}    ${kk}: ${sv}\n`;
                        }
                    }
                }
            } else {
                out += `${pad}${k}:\n`;
                for (const item of v) {
                    const sv = yamlValue(item);
                    if (sv !== null) out += `${pad}  - ${sv}\n`;
                }
            }
        } else if (typeof v === 'object') {
            out += `${pad}${k}:\n`;
            out += writeNestedObj(v, indent + 2);
        } else {
            const sv = yamlValue(v);
            if (sv !== null) out += `${pad}${k}: ${sv}\n`;
        }
    }
    return out;
}

function buildProvider(proxies) {
    let yaml = "proxies:\n";

    for (const p of proxies) {
        const protoKey = p.type;
        const protoSpecific = PROTO_FIELDS[protoKey] || [];

        // FIX: تفکیک دقیق پروتکل‌هایی که TLS/Transport دارن
        const hasTls = !["wireguard", "hysteria2", "tuic", "ssh", "socks5", "http"].includes(p.type);
        // FIX: transport فقط برای vless و vmess — trojan فیلدهای transport رو در proto_specific داره
        const hasTransport = ["vless", "vmess"].includes(p.type);

        const allowedSet = new Set([
            ...PROTO_FIELDS._common,
            ...(hasTls       ? PROTO_FIELDS._tls       : []),
            ...(hasTransport ? PROTO_FIELDS._transport  : []),
            ...protoSpecific,
        ]);

        yaml += `  - name: ${yamlStr(p.name)}\n`;
        yaml += `    type: ${p.type}\n`;
        yaml += `    server: ${yamlStr(p.server)}\n`;
        yaml += `    port: ${p.port}\n`;

        for (const key of allowedSet) {
            if (["name", "type", "server", "port"].includes(key)) continue;
            const val = p[key];
            if (val === null || val === undefined || val === "") continue;

            // FIX: boolean false هم باید نوشته بشه (مثلاً skip-cert-verify: false)
            // اما false رو فقط وقتی معنی‌دار باشه بنویس
            if (val === false) {
                // فقط فیلدهایی که false بودنشون معنی داره
                const writeFalse = ["tls", "udp", "skip-cert-verify", "tfo", "mptcp",
                                    "global-padding", "authenticated-length", "disable-sni",
                                    "reduce-rtt", "fast-open", "remote-dns-resolve",
                                    "udp-over-tcp"];
                if (writeFalse.includes(key)) {
                    yaml += `    ${key}: false\n`;
                }
                continue;
            }

            // array
            if (Array.isArray(val)) {
                if (val.length === 0) continue;
                // FIX: peers — array of objects
                if (ARRAY_OF_OBJ_FIELDS.has(key) && typeof val[0] === 'object') {
                    yaml += `    ${key}:\n`;
                    for (const item of val) {
                        const keys = Object.keys(item);
                        if (keys.length === 0) continue;
                        let first = true;
                        for (const k of keys) {
                            const v = item[k];
                            if (v === null || v === undefined) continue;
                            if (Array.isArray(v)) {
                                if (first) { yaml += `      -\n`; first = false; }
                                yaml += `        ${k}:\n`;
                                for (const ai of v) {
                                    const sv = yamlValue(ai);
                                    if (sv !== null) yaml += `          - ${sv}\n`;
                                }
                            } else {
                                const sv = yamlValue(v);
                                if (sv !== null) {
                                    if (first) { yaml += `      - ${k}: ${sv}\n`; first = false; }
                                    else        { yaml += `        ${k}: ${sv}\n`; }
                                }
                            }
                        }
                    }
                    continue;
                }
                yaml += `    ${key}:\n`;
                for (const item of val) {
                    const sv = yamlValue(item);
                    if (sv !== null) yaml += `      - ${sv}\n`;
                }
                continue;
            }

            // nested object
            if (typeof val === 'object' && NESTED_OBJ_FIELDS.has(key)) {
                yaml += `    ${key}:\n`;
                yaml += writeNestedObj(val, 6);
                continue;
            }

            // simple value
            const sv = yamlValue(val);
            if (sv !== null) yaml += `    ${key}: ${sv}\n`;
        }
    }

    return yaml;
}

// =====================================================
// ۱۴. Helper Functions
// =====================================================
function normalizeBase64(v) {
    if (!v) return null;
    v = v.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
    const pad = v.length % 4;
    if (pad === 1) return null;
    if (pad === 2) v += "==";
    if (pad === 3) v += "=";
    try { return Buffer.from(v, 'base64').toString('utf-8'); }
    catch (_) { return null; }
}

function decodeSub(text) {
    return text.includes("://") ? text : (normalizeBase64(text.trim()) || text);
}

function safeDecode(str) {
    if (!str) return "";
    try { return decodeURIComponent(str); } catch (_) { return str; }
}

function sanitizeObj(obj) {
    if (typeof obj === 'string')
        return obj.replace(/[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\uFFFD]/g, "").trim();
    if (Array.isArray(obj)) return obj.map(sanitizeObj);
    if (obj !== null && typeof obj === 'object') {
        const res = {};
        for (const key in obj) res[key] = sanitizeObj(obj[key]);
        return res;
    }
    return obj;
}

// =====================================================
// Start
// =====================================================
main();
