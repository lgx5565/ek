import { Crypto } from 'assets://js/lib/cat.js';

// ===== 🧪 诊断源: 在 OK影视真实运行时里自检, 结果渲染成影片列表 =====
var __ek_ext = {};
var ext = __ek_ext;
function parseJson(s) { return JSON.parse(s); }
function text(v) { return v == null ? '' : String(v); }
function req_(u, o) {
    o = o || {};
    var r = req(u, { headers: o.headers || {}, timeout: o.timeout || 12000,
                     method: o.method, data: o.data, postType: o.postType });
    if (r == null) return '';
    if (typeof r === 'string') return r;
    if (r.content != null) return r.content;
    if (r.body != null) return r.body;
    return String(r);
}
function post_(u, b, o) {
    o = o || {};
    var r = req(u, { headers: o.headers || {}, timeout: o.timeout || 12000, method: 'POST',
                     data: b == null ? '' : String(b), postType: 'raw' });
    if (r == null) return '';
    if (typeof r === 'string') return r;
    if (r.content != null) return r.content;
    if (r.body != null) return r.body;
    return String(r);
}

var RESULTS = [];
function rec(name, ok, detail) {
    RESULTS.push({ id: 'dbg' + RESULTS.length, name: (ok === true ? '✅ ' : ok === 'skip' ? '⏭ ' : '❌ ') + name,
                   pic: '', remarks: ok === true ? '通过' : (ok === 'skip' ? '跳过' : '失败'),
                   desc: String(detail || '').slice(0, 400), type: '', year: '' });
}

/* ---- 纯 JS RSA (与内置 shim 同源实现, selfTest 用于设备端验证) ---- */
var __rsaJS = (function () {
    function b64ToBuf(s) {
        s = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
        var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = [], bits = 0, acc = 0;
        for (var i = 0; i < s.length; i++) {
            var c = s.charAt(i);
            if (c === '=') break;
            acc = (acc << 6) | t.indexOf(c); bits += 6;
            if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xFF); }
        }
        return out;
    }
    function bufToHex(arr) { var s = ''; for (var i = 0; i < arr.length; i++) { s += (arr[i] < 16 ? '0' : '') + arr[i].toString(16); } return s; }
    function hexToBuf(s) { var out = []; s = String(s).replace(/[^0-9a-fA-F]/g, ''); for (var i = 0; i + 1 < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16)); return out; }
    function derFind(arr, start, end, tag) {
        var i = start;
        while (i + 1 < end) {
            var t = arr[i], j = i + 1, len;
            var b = arr[j]; j++;
            if (b < 0x80) len = b;
            else { var nb = b & 0x7F; len = 0; for (var x = 0; x < nb; x++) { len = len * 256 + arr[j]; j++; } }
            if (t === tag) return { body: arr.slice(j, j + len), next: j + len };
            i = j + len;
        }
        return null;
    }
    function pemBody(pem) {
        var lines = String(pem).split('\n'), rows = [];
        for (var i = 0; i < lines.length; i++) {
            var L = lines[i].replace(/\r/g, '');
            if (L.indexOf('-----') < 0 && L.length) rows.push(L.replace(/\s+/g, ''));
        }
        return b64ToBuf(rows.join(''));
    }
    function intsFromSeq(seq) {
        var out = [], pos = 0, guard = 0;
        while (pos + 1 < seq.length && guard++ < 32) {
            var t = seq[pos], j = pos + 1, len;
            var b = seq[j]; j++;
            if (b < 0x80) len = b;
            else { var nb = b & 0x7F; len = 0; for (var x = 0; x < nb; x++) { len = len * 256 + seq[j]; j++; } }
            if (t === 0x02) {
                var v = seq.slice(j, j + len);
                while (v.length && v[0] === 0) v.shift();
                var hex = bufToHex(v);
                out.push(hex === '' ? 0n : BigInt('0x' + hex));
            }
            pos = j + len;
        }
        return out;
    }
    function parsePrivateKey(pem) {
        var der = pemBody(pem);
        var top = derFind(der, 0, der.length, 0x30);
        var oct = derFind(top.body, 0, top.body.length, 0x04);
        var seq = derFind(oct.body, 0, oct.body.length, 0x30);
        var ints = intsFromSeq(seq.body);
        return { n: ints[1], e: ints[2] || 65537n, d: ints[3], k: (ints[1].toString(16).length + 1) >> 1 };
    }
    function modPow(b, e, m) {
        var r = 1n; b %= m;
        while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
        return r;
    }
    function bytesOf(big, k) {
        var hex = big.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        var arr = hexToBuf(hex);
        while (arr.length < k) arr.unshift(0);
        return arr.slice(-k);
    }
    function os2ip(arr) { return BigInt('0x' + (bufToHex(arr) || '0')); }
    function utf8Bytes(s) {
        var out = [];
        for (var i = 0; i < s.length; i++) {
            var c = s.charCodeAt(i);
            if (c < 0x80) out.push(c);
            else if (c < 0x800) { out.push(0xC0 | (c >> 6), 0x80 | (c & 63)); }
            else if (c < 0xD800 || c >= 0xE000) { out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
            else { i++; var cp = 0x10000 + (((c & 1023) << 10) | (s.charCodeAt(i) & 1023)); out.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63)); }
        }
        return out;
    }
    function utf8FromBytes(arr) {
        var s = '', i = 0;
        while (i < arr.length) {
            var b = arr[i];
            if (b < 0x80) { s += String.fromCharCode(b); i++; }
            else if (b < 0xE0) { s += String.fromCharCode(((b & 31) << 6) | (arr[i + 1] & 63)); i += 2; }
            else if (b < 0xF0) { s += String.fromCharCode(((b & 15) << 12) | ((arr[i + 1] & 63) << 6) | (arr[i + 2] & 63)); i += 3; }
            else { var cp = ((b & 7) << 18) | ((arr[i + 1] & 63) << 12) | ((arr[i + 2] & 63) << 6) | (arr[i + 3] & 63); cp -= 0x10000; s += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 1023)); i += 4; }
        }
        return s;
    }
    function selfTest(pemPriv, msg) {
        var key = parsePrivateKey(pemPriv), mb = utf8Bytes(msg), k = key.k;
        if (mb.length > k - 11) return null;
        var ps = [];
        while (ps.length < k - 3 - mb.length) ps.push(Math.floor(Math.random() * 255) + 1);
        var c = modPow(os2ip([0].concat([2], ps, [0], mb)), key.e, key.n);
        var m = bytesOf(modPow(os2ip(bytesOf(c, k)), key.d, key.n), k);
        if (!(m[0] === 0 && m[1] === 2)) return '填充校验失败';
        var idx = m.indexOf(0, 2);
        if (idx < 2) return '分隔符未找到';
        return utf8FromBytes(m.slice(idx + 1)) === msg;
    }
    return { selfTest: selfTest, parsePrivateKey: parsePrivateKey };
})();

/* ---- 瓜子协议常量 ---- */
var GZ_PUB = '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcLwnPcnXNNiVLYVvEqUuZqzLQ\n' +
    'N8iK4zYZ3XK8YGRVhzHZkwcEwJLTGZn1Gk4loCpInQRUu5/tGRhXaJUXTS28jPnB\n' +
    '5wIDAQAB\n' +
    '-----END PUBLIC KEY-----';
var GZ_PRIV_OBJ = { priv: '-----BEGIN PRIVATE KEY-----\n' +
    'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGAe6hKrWLi1zQmjTT1\n' +
    'ozbE4QdFeJGNxubxld6GrFGximxfMsMB6BpJhpcTouAqywAFppiKetUBBbXwYsYU\n' +
    '1wNr648XVmPmCMCy4rY8vdliFnbMUj086DU6Z+/oXBdWU3/b1G0DN3E9wULRSwcK\n' +
    'ZT3wj/cCI1vsCm3gj2R5SqkA9Y0CAwEAAQKBgAJH+4CxV0/zBVcLiBCHvSANm0l7\n' +
    'HetybTh/j2p0Y1sTXro4ALwAaCTUeqdBjWiLSo9lNwDHFyq8zX90+gNxa7c5EqcW\n' +
    'V9FmlVXr8VhfBzcZo1nXeNdXFT7tQ2yah/odtdcx+vRMSGJd1t/5k5bDd9wAvYdI\n' +
    'DblMAg+wiKKZ5KcdAkEA1cCakEN4NexkF5tHPRrR6XOY/XHfkqXxEhMqmNbB9U34\n' +
    'saTJnLWIHC8IXys6Qmzz30TtzCjuOqKRRy+FMM4TdwJBAJQZFPjsGC+RqcG5UvVM\n' +
    'iMPhnwe/bXEehShK86yJK/g/UiKrO87h3aEu5gcJqBygTq3BBBoH2md3pr/W+hUM\n' +
    'WBsCQQChfhTIrdDinKi6lRxrdBnn0Ohjg2cwuqK5zzU9p/N+S9x7Ck8wUI53DKm8\n' +
    'jUJE8WAG7WLj/oCOWEh+ic6NIwTdAkEAj0X8nhx6AXsgCYRql1klbqtVmL8+95KZ\n' +
    'K7PnLWG/IfjQUy3pPGoSaZ7fdquG8bq8oyf5+dzjE/oTXcByS+6XRQJAP/5ciy1b\n' +
    'L3NhUhsaOVy55MHXnPjdcTX0FaLi+ybXZIfIQ2P4rb19mVq1feMbCXhz+L1rG8oa\n' +
    't5lYKfpe8k83ZA==\n' +
    '-----END PRIVATE KEY-----' };
var GZ_OLD_KEY = 'aLFBMWpxBrIDAD1Si/KVvm41';
var GZ_SIGN_SUFFIX = '*&zvdvdvddbfikkkumtmdwqppp?|4Y!s!2br';
var GZ_HOST = 'https://apinew.uozvr.com';
var GZ_UA = 'okhttp/3.12.0';
var GZ_DEVICE_KEY = '';
var GZ_TOKEN = '';

function md5Upper(s) { return Crypto.MD5(s).toString().toUpperCase(); }

function runTests() {
    rec('运行时.BigInt', typeof BigInt !== 'undefined', 'typeof BigInt = ' + typeof BigInt + ' (柿子/师兄/粉猪/热播/瓜子 都依赖)');
    rec('运行时.Crypto(cat.js)', typeof Crypto !== 'undefined' && !!Crypto && !!Crypto.AES,
        'typeof Crypto = ' + typeof Crypto + ', AES = ' + (typeof Crypto !== 'undefined' && Crypto ? typeof Crypto.AES : '-'));
    rec('运行时.req', typeof req === 'function', 'typeof req = ' + typeof req);

    try {
        var out = Crypto.AES.encrypt('hello-test', Crypto.enc.Utf8.parse('0123456789abcdef'),
            { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse('abcdef0123456789') });
        var back = Crypto.AES.decrypt(out.toString(), Crypto.enc.Utf8.parse('0123456789abcdef'),
            { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse('abcdef0123456789') }).toString(Crypto.enc.Utf8);
        rec('Crypto.AES(CBC)', back === 'hello-test', '回文: ' + back);
    } catch (e) { rec('Crypto.AES(CBC)', false, e.message); }
}

function runRsAndGz() {
    /* RSA 自洽: 瓜子响应私钥自加密自解密 */
    try {
        var privPem = GZ_PRIV_OBJ && GZ_PRIV_OBJ.priv ? GZ_PRIV_OBJ.priv : '';
        var r = privPem ? __rsaJS.selfTest(privPem, 'round-trip-test') : '无私钥';
        rec('Crypto.RSA自洽(BigInt+DER)', r === true, 'typeof结果: ' + String(r));
    } catch (e) { rec('Crypto.RSA自洽(BigInt+DER)', false, e.message); }

    /* 瓜子完整认证 + 列表 (真实服务端) */
    try {
        GZ_DEVICE_KEY = '';
        var chars = '0123456789abcdef';
        for (var i = 0; i < 40; i++) GZ_DEVICE_KEY += chars.charAt(Math.floor(Math.random() * 16));
        var signIn = post_(GZ_HOST + '/App/Authentication/Device/signIn',
            'token=&token_id=&phone_type=1&app_id=1&time=' + Math.floor(Date.now() / 1000) +
            '&new_key=' + GZ_DEVICE_KEY + '&old_key=' + encodeURIComponent(GZ_OLD_KEY),
            { headers: { 'User-Agent': GZ_UA, 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' } });
        var env = parseJson(signIn);
        if (!env || env.code == null) {
            rec('瓜子.认证 signIn', false, '非法响应: ' + text(signIn).slice(0, 100));
        } else if (Number(env.code) !== 200) {
            rec('瓜子.认证 signIn', 'skip', 'code=' + env.code + ' ' + text(env.msg || env.message).slice(0, 60));
            var signUp = post_(GZ_HOST + '/App/Authentication/Device/signUp',
                'new_key=' + GZ_DEVICE_KEY + '&old_key=' + encodeURIComponent(GZ_OLD_KEY) + '&phone_type=1&code=',
                { headers: { 'User-Agent': GZ_UA, 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' } });
            var env2 = parseJson(signUp);
            if (!env2 || Number(env2.code) !== 200) {
                rec('瓜子.认证 signUp', false, 'code=' + (env2 ? env2.code : '?') + ' ' + text(env2 && (env2.msg || env2.message)).slice(0, 80));
            } else {
                rec('瓜子.认证 signUp', true, 'code=200');
            }
        } else {
            rec('瓜子.认证 signIn', true, 'code=200');
        }
    } catch (e) { rec('瓜子.认证', false, e.message); }
}

function probeBackend(name, url, method, body, headers) {
    try {
        var opt = { headers: headers || {}, timeout: 15000 };
        if (method === 'POST') { opt.method = 'POST'; opt.data = body || ''; opt.postType = 'raw'; }
        var r = req(url, opt);
        var code = (r == null || typeof r === 'string') ? '' : (r.code != null ? r.code : (r.status != null ? r.status : ''));
        var content = '';
        if (typeof r === 'string') content = r;
        else if (r) { if (r.content != null) content = String(r.content); else if (r.body != null) content = String(r.body); }
        var up = (code !== '' && code != null);
        rec('后端.' + name + ' 连通', up, 'HTTP ' + String(code) + ', ' + content.length + 'B | 预览: ' + content.replace(/\s+/g, ' ').slice(0, 70));
    } catch (e) { rec('后端.' + name + ' 连通', false, '异常: ' + e.message); }
}
function runBackendProbes() {
    var appv7h = { 'User-Agent': 'Dart/3.11 (dart:io)', 'Content-Type': 'text/plain' };
    probeBackend('柿子', 'http://198.16.32.131:12345/nxsz.php/v7/logs', 'POST', '', appv7h);
    probeBackend('师兄', 'http://app2.dsx.ac/ndsx.php/v7/logs', 'POST', '', appv7h);
    probeBackend('粉猪', 'http://198.16.60.3:6688/nfenzhu.php/v7/logs', 'POST', '', appv7h);
    probeBackend('热播', 'http://v.rbotv.cn/', 'POST', '', appv7h);
    probeBackend('闪电(对照)', 'https://u.yyxdmn.com/api/new_type/list_v2', 'POST', '{}', { 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json' });
}
function runNativeRsa() {
    if (typeof rsaX !== 'function') { rec('原生rsaX', 'skip', 'typeof rsaX = ' + typeof rsaX + ' (无原生桥, 源将走纯JS兜底)'); return; }
    try {
        var ct = rsaX('', true, true, 'native-check', false, GZ_PUB, true);
        var lenOk = (ct && String(ct).length >= 100);
        rec('原生rsaX.encrypt(JCE)', !!lenOk, '密文长度 ' + (ct ? String(ct).length : 0) + ' (1024位应≈172, 标准base64)');
    } catch (e) { rec('原生rsaX.encrypt(JCE)', false, e.message); }
}

function home(filter) {
    RESULTS = [];
    try { runTests(); } catch (e) { rec('测试执行', false, e.message); }
    try { runRsAndGz(); } catch (e) { rec('RSA/瓜子执行', false, e.message); }
    try { runNativeRsa(); } catch (e) { rec('原生rsaX执行', false, e.message); }
    try { runBackendProbes(); } catch (e) { rec('后端探测执行', false, e.message); }
    return JSON.stringify({ class: [{ type_id: 'r', type_name: '诊断结果(' + RESULTS.length + '项)' }] });
}
function category(tid, pg, filter, extend) {
    return JSON.stringify({ list: RESULTS.map(function (x) {
        return { vod_id: x.id, vod_name: x.name, vod_pic: x.pic, vod_remarks: x.remarks, vod_content: x.desc };
    }) });
}
function detail(id) {
    var hit = null;
    for (var i = 0; i < RESULTS.length; i++) if (RESULTS[i].id === id) hit = RESULTS[i];
    if (!hit) return JSON.stringify({ list: [] });
    return JSON.stringify({ list: [{ vod_id: id, vod_name: hit.name, vod_content: hit.desc,
        vod_play_from: 'diag', vod_play_url: '详情$diag://' + id }] });
}
function play(flag, id) {
    return JSON.stringify({ parse: 0, url: '', header: {} });
}
function search(wd) { return JSON.stringify({ list: [] }); }
function config() { return JSON.stringify({ kind: 'video', browseOnly: false, source: '诊断' }); }

export function __jsEvalReturn() {
    return { init: function(){}, home: home, homeVod: function(){ return JSON.stringify({list: []}); },
             category: category, detail: detail, search: search, play: play };
}
