const fs = require('fs');

// =====================================================
// convert.js — تبدیل all.yaml به فرمت‌های V2Ray و Sing-Box
// ورودی: all.yaml (خروجی aggregator)
// خروجی:
//   v2ray_links.txt     — لینک‌های URI (vless:// vmess:// ...)
//   v2ray_base64.txt    — همان لینک‌ها به صورت base64
//   singbox.json        — فایل کامل sing-box
// =====================================================

// ── ۱. خواندن و parse ساده YAML proxies ──────────────────
function parseProxiesYaml(text) {
    const proxies = [];
    let current = null;
    let currentNestedKey = null;
    let currentNestedIndent = 0;
    const knownListKeys = new Set(["allowed-ips", "dns", "alpn", "peers", "reserved", "host"]);

    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine;
        if (line.trim().startsWith('#')) continue;

        // شروع آیتم جدید با "  - name:"
        const listMatch = line.match(/^(\s*)-\s+name:\s*(.*)$/);
        if (listMatch) {
            if (current) proxies.push(current);
            current = { name: stripQuotes(listMatch[2].trim()) };
            currentNestedKey = null;
            currentNestedIndent = 0;
            continue;
        }

        if (!current) continue;

        // آیتم آرایه
        const arrItem = line.match(/^(\s+)-\s+(.*)$/);
        if (arrItem && currentNestedKey) {
            const indent = arrItem[1].length;
            if (indent > currentNestedIndent) {
                if (!Array.isArray(current[currentNestedKey])) current[currentNestedKey] = [];
                current[currentNestedKey].push(parseYamlScalar(arrItem[2].trim()));
                continue;
            }
        }

        // key: value
        const kv = line.match(/^(\s+)([a-zA-Z0-9_\-]+):\s*(.*)$/);
        if (!kv) continue;
        const indent = kv[1].length;
        const key = kv[2];
        const valStr = kv[3].trim();

        if (valStr === '') {
            // nested object یا array شروع می‌شه
            currentNestedKey = key;
            currentNestedIndent = indent;
            if (knownListKeys.has(key)) current[key] = [];
            else current[key] = {};
        } else if (currentNestedKey && indent > currentNestedIndent && typeof current[currentNestedKey] === 'object' && !Array.isArray(current[currentNestedKey])) {
            current[currentNestedKey][key] = parseYamlScalar(valStr);
        } else {
            currentNestedKey = null;
            current[key] = parseYamlScalar(valStr);
        }
    }
    if (current) proxies.push(current);
    return proxies;
}

function parseYamlScalar(v) {
    if (!v || v === '') return v;
    v = stripQuotes(v);
    if (v === 'true') return true;
    if (v === 'false') return false;
    if (/^-?\d+$/.test(v)) return Number(v);
    return v;
}

function stripQuotes(s) {
    if (!s) return s;
    s = s.trim();
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))
        return s.slice(1, -1);
    return s;
}

// ── ۲. تبدیل به URI لینک ─────────────────────────────────
function proxyToUri(p) {
    try {
        switch (p.type) {
            case 'vless':     return vlessToUri(p);
            case 'vmess':     return vmessToUri(p);
            case 'trojan':    return trojanToUri(p);
            case 'ss':        return ssToUri(p);
            case 'hysteria2': return hy2ToUri(p);
            case 'tuic':      return tuicToUri(p);
            case 'wireguard': return wgToUri(p);
            case 'socks5':    return socksToUri(p);
            case 'http':      return httpToUri(p);
            case 'ssh':       return sshToUri(p);
            default: return null;
        }
    } catch (_) { return null; }
}

function enc(s) { return encodeURIComponent(s || ''); }

function vlessToUri(p) {
    const params = new URLSearchParams();
    params.set('type', p.network || 'tcp');
    if (p.tls) params.set('security', p['reality-opts'] ? 'reality' : 'tls');
    if (p.servername || p.sni) params.set('sni', p.servername || p.sni);
    if (p['client-fingerprint']) params.set('fp', p['client-fingerprint']);
    if (p.alpn) params.set('alpn', [].concat(p.alpn).join(','));
    if (p.flow) params.set('flow', p.flow);
    if (p['skip-cert-verify']) params.set('allowInsecure', '1');
    if (p['reality-opts']) {
        params.set('pbk', p['reality-opts']['public-key'] || '');
        if (p['reality-opts']['short-id']) params.set('sid', p['reality-opts']['short-id']);
    }
    if (p['ws-opts']) {
        if (p['ws-opts'].path) params.set('path', p['ws-opts'].path);
        if (p['ws-opts'].headers?.Host) params.set('host', p['ws-opts'].headers.Host);
    }
    if (p['grpc-opts']?.['grpc-service-name']) params.set('serviceName', p['grpc-opts']['grpc-service-name']);
    if (p['h2-opts']) {
        if (p['h2-opts'].path) params.set('path', p['h2-opts'].path);
        if (p['h2-opts'].host) params.set('host', [].concat(p['h2-opts'].host)[0]);
    }
    return `vless://${enc(p.uuid)}@${p.server}:${p.port}?${params.toString()}#${enc(p.name)}`;
}

function vmessToUri(p) {
    const obj = {
        v: "2", ps: p.name, add: p.server, port: String(p.port),
        id: p.uuid, aid: String(p.alterId || 0),
        net: p.network || 'tcp', type: 'none',
        tls: p.tls ? 'tls' : '',
    };
    if (p.servername || p.sni) obj.sni = p.servername || p.sni;
    if (p['client-fingerprint']) obj.fp = p['client-fingerprint'];
    if (p.alpn) obj.alpn = [].concat(p.alpn).join(',');
    if (p['ws-opts']) {
        obj.path = p['ws-opts'].path || '';
        obj.host = p['ws-opts'].headers?.Host || '';
    }
    if (p['grpc-opts']) obj.path = p['grpc-opts']['grpc-service-name'] || '';
    if (p['h2-opts']) {
        obj.path = p['h2-opts'].path || '';
        obj.host = [].concat(p['h2-opts'].host || [])[0] || '';
    }
    return 'vmess://' + Buffer.from(JSON.stringify(obj)).toString('base64');
}

function trojanToUri(p) {
    const params = new URLSearchParams();
    if (p.network && p.network !== 'tcp') params.set('type', p.network);
    if (p.sni) params.set('sni', p.sni);
    if (p['client-fingerprint']) params.set('fp', p['client-fingerprint']);
    if (p.alpn) params.set('alpn', [].concat(p.alpn).join(','));
    if (p['skip-cert-verify']) params.set('allowInsecure', '1');
    if (p['ws-opts']) {
        if (p['ws-opts'].path) params.set('path', p['ws-opts'].path);
        if (p['ws-opts'].headers?.Host) params.set('host', p['ws-opts'].headers.Host);
    }
    if (p['grpc-opts']?.['grpc-service-name']) params.set('serviceName', p['grpc-opts']['grpc-service-name']);
    return `trojan://${enc(p.password)}@${p.server}:${p.port}?${params.toString()}#${enc(p.name)}`;
}

function ssToUri(p) {
    const auth = Buffer.from(`${p.cipher}:${p.password}`).toString('base64');
    return `ss://${auth}@${p.server}:${p.port}#${enc(p.name)}`;
}

function hy2ToUri(p) {
    const params = new URLSearchParams();
    if (p.sni) params.set('sni', p.sni);
    if (p['skip-cert-verify']) params.set('insecure', '1');
    if (p.alpn) params.set('alpn', [].concat(p.alpn).join(','));
    if (p.obfs) {
        params.set('obfs', p.obfs);
        if (p['obfs-password']) params.set('obfs-password', p['obfs-password']);
    }
    if (p.up) params.set('up', p.up);
    if (p.down) params.set('down', p.down);
    return `hy2://${enc(p.password)}@${p.server}:${p.port}?${params.toString()}#${enc(p.name)}`;
}

function tuicToUri(p) {
    const params = new URLSearchParams();
    if (p.sni) params.set('sni', p.sni);
    if (p.alpn) params.set('alpn', [].concat(p.alpn).join(','));
    if (p['congestion-controller']) params.set('congestion_control', p['congestion-controller']);
    if (p['udp-relay-mode']) params.set('udp_relay_mode', p['udp-relay-mode']);
    if (p['skip-cert-verify']) params.set('insecure', '1');
    return `tuic://${enc(p.uuid)}:${enc(p.password)}@${p.server}:${p.port}?${params.toString()}#${enc(p.name)}`;
}

function wgToUri(p) {
    const params = new URLSearchParams();
    params.set('publickey', p['public-key'] || '');
    if (p.ip) params.set('address', p.ip + (p.ipv6 ? `,${p.ipv6}` : ''));
    if (p['allowed-ips']) params.set('allowedIPs', [].concat(p['allowed-ips']).join(','));
    if (p.reserved) params.set('reserved', [].concat(p.reserved).join(','));
    if (p.mtu) params.set('mtu', p.mtu);
    return `wireguard://${enc(p['private-key'])}@${p.server}:${p.port}?${params.toString()}#${enc(p.name)}`;
}

function socksToUri(p) {
    const auth = (p.username || p.password) ? `${enc(p.username)}:${enc(p.password)}@` : '';
    return `socks5://${auth}${p.server}:${p.port}#${enc(p.name)}`;
}

function httpToUri(p) {
    const scheme = p.tls ? 'https' : 'http';
    const auth = (p.username || p.password) ? `${enc(p.username)}:${enc(p.password)}@` : '';
    return `${scheme}://${auth}${p.server}:${p.port}#${enc(p.name)}`;
}

function sshToUri(p) {
    const auth = p.username ? `${enc(p.username)}${p.password ? ':' + enc(p.password) : ''}@` : '';
    return `ssh://${auth}${p.server}:${p.port}#${enc(p.name)}`;
}

// ── ۳. تبدیل به Sing-Box outbound ────────────────────────
function proxyToSingbox(p) {
    try {
        switch (p.type) {
            case 'vless':     return vlessToSingbox(p);
            case 'vmess':     return vmessToSingbox(p);
            case 'trojan':    return trojanToSingbox(p);
            case 'ss':        return ssToSingbox(p);
            case 'hysteria2': return hy2ToSingbox(p);
            case 'tuic':      return tuicToSingbox(p);
            case 'wireguard': return wgToSingbox(p);
            case 'socks5':    return socksToSingbox(p);
            case 'http':      return httpToSingbox(p);
            case 'ssh':       return sshToSingbox(p);
            default: return null;
        }
    } catch (_) { return null; }
}

function buildTlsObj(p) {
    const tls = { enabled: true };
    if (p.servername || p.sni) tls.server_name = p.servername || p.sni;
    if (p['skip-cert-verify']) tls.insecure = true;
    if (p.alpn) tls.alpn = [].concat(p.alpn);
    if (p['client-fingerprint']) tls.utls = { enabled: true, fingerprint: p['client-fingerprint'] };
    if (p['reality-opts']) {
        tls.reality = {
            enabled: true,
            public_key: p['reality-opts']['public-key'],
            short_id: p['reality-opts']['short-id'] || '',
        };
    }
    return tls;
}

function buildTransport(p) {
    if (!p.network || p.network === 'tcp') return null;
    if (p.network === 'ws') {
        const t = { type: 'ws' };
        if (p['ws-opts']?.path) t.path = p['ws-opts'].path;
        if (p['ws-opts']?.headers) t.headers = p['ws-opts'].headers;
        return t;
    }
    if (p.network === 'grpc') {
        return { type: 'grpc', service_name: p['grpc-opts']?.['grpc-service-name'] || '' };
    }
    if (p.network === 'h2') {
        const t = { type: 'http' };
        if (p['h2-opts']?.path) t.path = p['h2-opts'].path;
        if (p['h2-opts']?.host) t.host = [].concat(p['h2-opts'].host);
        return t;
    }
    return null;
}

function vlessToSingbox(p) {
    const out = {
        tag: p.name, type: 'vless',
        server: p.server, server_port: p.port,
        uuid: p.uuid,
    };
    if (p.flow) out.flow = p.flow;
    if (p.tls) out.tls = buildTlsObj(p);
    const transport = buildTransport(p);
    if (transport) out.transport = transport;
    return out;
}

function vmessToSingbox(p) {
    const out = {
        tag: p.name, type: 'vmess',
        server: p.server, server_port: p.port,
        uuid: p.uuid, alter_id: p.alterId || 0,
        security: p.cipher || 'auto',
    };
    if (p.tls) out.tls = buildTlsObj(p);
    const transport = buildTransport(p);
    if (transport) out.transport = transport;
    return out;
}

function trojanToSingbox(p) {
    const out = {
        tag: p.name, type: 'trojan',
        server: p.server, server_port: p.port,
        password: p.password,
    };
    out.tls = buildTlsObj(p);
    const transport = buildTransport(p);
    if (transport) out.transport = transport;
    return out;
}

function ssToSingbox(p) {
    return {
        tag: p.name, type: 'shadowsocks',
        server: p.server, server_port: p.port,
        method: p.cipher, password: p.password,
    };
}

function hy2ToSingbox(p) {
    const out = {
        tag: p.name, type: 'hysteria2',
        server: p.server, server_port: p.port,
        password: p.password,
    };
    const tls = { enabled: true };
    if (p.sni) tls.server_name = p.sni;
    if (p['skip-cert-verify']) tls.insecure = true;
    if (p.alpn) tls.alpn = [].concat(p.alpn);
    out.tls = tls;
    if (p.obfs === 'salamander') out.obfs = { type: 'salamander', password: p['obfs-password'] || '' };
    if (p.up) out.up_mbps = parseInt(p.up) || undefined;
    if (p.down) out.down_mbps = parseInt(p.down) || undefined;
    return out;
}

function tuicToSingbox(p) {
    const out = {
        tag: p.name, type: 'tuic',
        server: p.server, server_port: p.port,
        uuid: p.uuid, password: p.password,
    };
    if (p['congestion-controller']) out.congestion_control = p['congestion-controller'];
    if (p['udp-relay-mode']) out.udp_relay_mode = p['udp-relay-mode'];
    const tls = { enabled: true };
    if (p.sni) tls.server_name = p.sni;
    if (p['skip-cert-verify']) tls.insecure = true;
    if (p.alpn) tls.alpn = [].concat(p.alpn);
    out.tls = tls;
    return out;
}

function wgToSingbox(p) {
    const local_address = [];
    if (p.ip) local_address.push(`${p.ip}/32`);
    if (p.ipv6) local_address.push(`${p.ipv6}/128`);
    const out = {
        tag: p.name, type: 'wireguard',
        server: p.server, server_port: p.port,
        local_address,
        private_key: p['private-key'],
        peer_public_key: p['public-key'],
    };
    if (p.reserved) out.reserved = [].concat(p.reserved);
    if (p.mtu) out.mtu = p.mtu;
    return out;
}

function socksToSingbox(p) {
    const out = {
        tag: p.name, type: 'socks',
        server: p.server, server_port: p.port, version: '5',
    };
    if (p.username) out.username = p.username;
    if (p.password) out.password = p.password;
    return out;
}

function httpToSingbox(p) {
    const out = {
        tag: p.name, type: 'http',
        server: p.server, server_port: p.port,
    };
    if (p.username) out.username = p.username;
    if (p.password) out.password = p.password;
    if (p.tls) out.tls = { enabled: true };
    return out;
}

function sshToSingbox(p) {
    const out = {
        tag: p.name, type: 'ssh',
        server: p.server, server_port: p.port,
    };
    if (p.username) out.user = p.username;
    if (p.password) out.password = p.password;
    return out;
}

// ── ۴. ساخت فایل کامل Sing-Box ───────────────────────────
function buildSingboxConfig(outbounds) {
    return {
        log: { level: "warn", timestamp: true },
        dns: {
            servers: [
                { tag: "google", address: "8.8.8.8" },
                { tag: "local", address: "local", detour: "direct" }
            ],
            rules: [{ outbound: "any", server: "local" }],
            final: "google"
        },
        inbounds: [
            {
                type: "tun",
                tag: "tun-in",
                address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                auto_route: true,
                strict_route: true,
                sniff: true
            },
            {
                type: "mixed",
                tag: "mixed-in",
                listen: "127.0.0.1",
                listen_port: 2080
            }
        ],
        outbounds: [
            { type: "selector", tag: "proxy", outbounds: ["auto", ...outbounds.map(o => o.tag)] },
            { type: "urltest", tag: "auto", outbounds: outbounds.map(o => o.tag), url: "https://www.gstatic.com/generate_204", interval: "5m" },
            { type: "direct", tag: "direct" },
            { type: "block", tag: "block" },
            { type: "dns", tag: "dns-out" },
            ...outbounds
        ],
        route: {
            rules: [
                { protocol: "dns", outbound: "dns-out" },
                { geoip: ["private"], outbound: "direct" }
            ],
            final: "proxy",
            auto_detect_interface: true
        }
    };
}

// ── ۵. main ───────────────────────────────────────────────
function main() {
    const inputFile = 'all.yaml';

    if (!fs.existsSync(inputFile)) {
        console.error(`❌ فایل ${inputFile} یافت نشد. ابتدا aggregator را اجرا کنید.`);
        process.exit(1);
    }

    console.log(`📖 Reading ${inputFile}...`);
    const raw = fs.readFileSync(inputFile, 'utf-8');
    const proxies = parseProxiesYaml(raw);
    console.log(`✅ Parsed ${proxies.length} proxies`);

    // ── V2Ray URIs
    const uris = proxies.map(p => proxyToUri(p)).filter(Boolean);
    console.log(`🔗 V2Ray URIs: ${uris.length}`);

    fs.writeFileSync('v2ray_links.txt', uris.join('\n'), 'utf-8');
    console.log('📂 Created: v2ray_links.txt');

    const base64 = Buffer.from(uris.join('\n')).toString('base64');
    fs.writeFileSync('v2ray_base64.txt', base64, 'utf-8');
    console.log('📂 Created: v2ray_base64.txt');

    // ── Sing-Box
    const outbounds = proxies.map(p => proxyToSingbox(p)).filter(Boolean);
    console.log(`📦 Sing-Box outbounds: ${outbounds.length}`);

    const singboxConfig = buildSingboxConfig(outbounds);
    fs.writeFileSync('singbox.json', JSON.stringify(singboxConfig, null, 2), 'utf-8');
    console.log('📂 Created: singbox.json');

    console.log('\n🎉 Done!');
    console.log(`   v2ray_links.txt  — ${uris.length} URI links`);
    console.log(`   v2ray_base64.txt — Base64 encoded`);
    console.log(`   singbox.json     — Full Sing-Box config with ${outbounds.length} outbounds`);
}

main();
