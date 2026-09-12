import { Crypto } from 'assets://js/lib/cat.js';

// ===== 🧪 诊断源 v4: 在 OK影视真实运行时里自检 + 瓜子真实加密流程 =====
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
                     data: b == null ? '' : String(b), postType: o.postType || 'raw' });
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
                   desc: String(detail || '').slice(0, 500), type: '', year: '' });
}

/* ---- 纯 JS RSA (与内置 shim 同源) ---- */
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
    function parsePublicKey(pem) {
        var der = pemBody(pem);
        var spki = derFind(der, 0, der.length, 0x30);
        var bit = derFind(spki.body, 0, spki.body.length, 0x03);
        var inner = bit.body.slice(1);
        var seq = derFind(inner, 0, inner.length, 0x30);
        var ints = intsFromSeq(seq.body);
        return { n: ints[0], e: ints[1] || 65537n, k: (ints[0].toString(16).length + 1) >> 1 };
    }
    function encryptRaw(msgBytes, pub) {
        var k = pub.k;
        if (msgBytes.length > k - 11) throw new Error('明文过长');
        var ps = [];
        while (ps.length < k - 3 - msgBytes.length) ps.push(Math.floor(Math.random() * 255) + 1);
        var c = modPow(os2ip([0].concat([2], ps, [0], msgBytes)), pub.e, pub.n);
        return bytesOf(c, k);
    }
    function decryptRaw(ctBytes, priv) {
        var m = bytesOf(modPow(os2ip(ctBytes.slice(0, priv.k)), priv.d, priv.n), priv.k);
        if (!(m[0] === 0 && m[1] === 2)) throw new Error('填充校验失败');
        var idx = m.indexOf(0, 2);
        if (idx < 2) throw new Error('分隔符未找到');
        return m.slice(idx + 1);
    }
    function b64decode(s) {
        s = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
        var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var out = [], bits = 0, acc = 0;
        for (var i = 0; i < s.length; i++) {
            var c = s.charAt(i);
            if (c === '=') break;
            acc = (acc << 6) | t.indexOf(c); bits += 6;
            if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xFF); }
        }
        return out;
    }
    function decrypt(data, pemPriv, o) {
        o = o || {};
        var priv = parsePrivateKey(pemPriv);
        var bytes = (o.input === 'hex') ? hexToBuf(String(data)) : b64decode(String(data));
        var outBytes;
        if (bytes.length > priv.k) {
            outBytes = [];
            for (var i = 0; i < bytes.length; i += priv.k) outBytes = outBytes.concat(decryptRaw(bytes.slice(i, i + priv.k), priv));
        } else {
            outBytes = decryptRaw(bytes, priv);
        }
        var s = utf8FromBytes(outBytes);
        return o.output === 'hex' ? bufToHex(utf8Bytes(s)) : s;
    }
    function encryptPub(msg, pemPub, o) {
        o = o || {};
        var pub = parsePublicKey(pemPub), msgBytes = utf8Bytes(msg);
        var ct = encryptRaw(msgBytes, pub);
        if (o.output === 'hex') return bufToHex(ct);
        var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = '', i;
        for (i = 0; i < ct.length; i += 3) {
            var b0 = ct[i], b1 = i + 1 < ct.length ? ct[i + 1] : NaN, b2 = i + 2 < ct.length ? ct[i + 2] : NaN;
            out += t.charAt(b0 >> 2);
            out += t.charAt(((b0 & 3) << 4) | (isNaN(b1) ? 0 : b1 >> 4));
            out += isNaN(b1) ? '=' : t.charAt(((b1 & 15) << 2) | (isNaN(b2) ? 0 : b2 >> 6));
            out += isNaN(b2) ? '=' : t.charAt(b2 & 63);
        }
        return out;
    }
    return { selfTest: selfTest, parsePrivateKey: parsePrivateKey, encryptRaw: encryptRaw, decryptRaw: decryptRaw, encryptPub: encryptPub, decrypt: decrypt };
})();

/* ---- 瓜子协议 (与 guazi.js 完全一致) ---- */
var GZ_PUB =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUM5+/y8sPsWkd1/RQS64X259E\n' +
    'UwxFXFE5HlA65MqrxnPs0JqoSRojSDy5QhwvROlaD6TwRQHKMY2OAZ6SnQeUJsCh\n' +
    'TEFIR9qUkwrs3/MVUMxjsv6JS6Oe/juclyJGTgVmDhB55EafXsD0SQYVj/QXXsxR\n' +
    '6ewR5E2kL52yAAD4yQIDAQAB\n' +
    '-----END PUBLIC KEY-----';
var GZ_PRIV = ('-----BEGIN PRIVATE KEY-----\n' +
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
    '-----END PRIVATE KEY-----');
/* 私钥在下方 init 时从完整字符串重建(太长分段) */
var GZ_OLD_KEY = 'aLFBMWpxBrIDAD1Si/KVvm41';
var GZ_SIGN_SUFFIX = '*&zvdvdvddbfikkkumtmdwqppp?|4Y!s!2br';
var GZ_HOST = 'https://apinew.uozvr.com';
var GZ_UA = 'okhttp/3.12.0';
var GZ_DEVICE_KEY = '';
var GZ_TOKEN = '';

function md5Upper(s) { return Crypto.MD5(s).toString().toUpperCase(); }

/* 瓜子完整加密请求 (与源同流程) */
function gzPost(path, body, label) {
    var ts = String(Math.floor(Date.now() / 1000));
    var aesKey = '', aesIv = '';
    var chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
    for (var i = 0; i < 16; i++) {
        aesKey += chars.charAt(Math.floor(Math.random() * chars.length));
        aesIv += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    var enc = Crypto.AES.encrypt(JSON.stringify(body || {}), Crypto.enc.Utf8.parse(aesKey),
        { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse(aesIv) });
    var requestKey = Crypto.enc.Hex.stringify(enc.ciphertext).toUpperCase();
    var keys = text(__rsaJS.encryptPub(JSON.stringify({ iv: aesIv, key: aesKey }), GZ_PUB, { output: 'base64' }));
    if (!keys) throw new Error(label + ': RSA 加密失败(keys为空)');
    var signature = md5Upper('token_id=,token=' + GZ_TOKEN + ',phone_type=1,request_key=' + requestKey +
        ',app_id=1,time=' + ts + ',keys=' + keys + GZ_SIGN_SUFFIX);
    var form = 'token=' + GZ_TOKEN + '&token_id=&phone_type=1&request_key=' + encodeURIComponent(requestKey) +
        '&app_id=1&time=' + ts + '&keys=' + encodeURIComponent(keys) + '&signature=' + signature +
        '&phone_model=xiaomi-22081212c&ad_version=1';
    var raw = post_(GZ_HOST + path, form, {
        headers: { 'User-Agent': GZ_UA, 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                   'Ver': '3.0.4.8', 'Version': '2606029', 'api-ver': '3.0.4.8',
                   'PackageName': 'com.v54f07a912.t4ee50f184.dbb1e7669f20260721',
                   'code': 'GZ0313', 'deviceId': '864150060000001', 'lang': 'zh_cn', 'Referer': GZ_HOST }
    });
    var envelope = parseJson(raw);
    if (!envelope || typeof envelope !== 'object' || !envelope.data) {
        throw new Error(label + ': 非法响应 ' + text(raw).slice(0, 50));
    }
    if (envelope.code != null && Number(envelope.code) !== 200) {
        var err = new Error(label + ': 业务错误 ' + envelope.code + ' ' + text(envelope.msg || envelope.message).slice(0, 60));
        err.business = true; err.code = Number(envelope.code);
        throw err;
    }
    var section = envelope.data;
    if (section.response_key == null && (section.list instanceof Array || section.vodInfo)) {
        return section;
    }
    /* 响应解密: keys → RSA私钥(分块) → {iv,key} → AES解 response_key */
    var keyHex = __rsaJS.decrypt(text(section.keys), GZ_PRIV, { padding: 'PKCS1', input: 'base64', output: 'utf8' });
    var keyInfo = parseJson(keyHex);
    if (!keyInfo || !keyInfo.key || !keyInfo.iv) throw new Error(label + ': 响应key解析失败');
    var plain = Crypto.AES.decrypt(text(section.response_key), Crypto.enc.Utf8.parse(text(keyInfo.key)),
        { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse(text(keyInfo.iv)),
          input: 'hex', output: 'utf8' }).toString(Crypto.enc.Utf8);
    var decoded = parseJson(plain);
    if (!decoded || typeof decoded !== 'object') throw new Error(label + ': 响应JSON解析失败');
    return decoded;
}

function runTests() {
    rec('运行时.BigInt', typeof BigInt !== 'undefined', 'typeof BigInt = ' + typeof BigInt + ' (5个失败源都依赖)');
    rec('运行时.Crypto(cat.js)', typeof Crypto !== 'undefined' && !!Crypto && !!Crypto.AES,
        'typeof Crypto = ' + typeof Crypto);
    rec('运行时.req', typeof req === 'function', 'typeof req = ' + typeof req);
    try {
        var out = Crypto.AES.encrypt('hello-test', Crypto.enc.Utf8.parse('0123456789abcdef'),
            { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse('abcdef0123456789') });
        var back = Crypto.AES.decrypt(out.toString(), Crypto.enc.Utf8.parse('0123456789abcdef'),
            { mode: Crypto.mode.CBC, padding: Crypto.pad.Pkcs7, iv: Crypto.enc.Utf8.parse('abcdef0123456789') }).toString(Crypto.enc.Utf8);
        rec('Crypto.AES(CBC)', back === 'hello-test', '回文: ' + back);
    } catch (e) { rec('Crypto.AES(CBC)', false, e.message); }
    try {
        var r = __rsaJS.selfTest(GZ_PRIV, 'round-trip-test');
        rec('RSA纯JS自洽(私钥)', r === true, '结果: ' + String(r) + ' (验证 BigInt+DER+PKCS1 全链路)');
    } catch (e) { rec('RSA纯JS自洽(私钥)', false, e.message); }
}

function runGz() {
    /* 瓜子真实流程 */
    try {
        GZ_DEVICE_KEY = '';
        var chars = '0123456789abcdef';
        for (var i = 0; i < 40; i++) GZ_DEVICE_KEY += chars.charAt(Math.floor(Math.random() * 16));
        var t0 = Date.now();
        var signed = gzPost('/App/Authentication/Device/signIn', { new_key: GZ_DEVICE_KEY, old_key: GZ_OLD_KEY }, 'signIn');
        GZ_TOKEN = text(signed.token || signed.app_user_token || '');
        rec('瓜子.signIn(加密流程)', !!GZ_TOKEN, '耗时' + (Date.now() - t0) + 'ms, token: ' + GZ_TOKEN.slice(0, 25));
        if (!GZ_TOKEN) throw new Error('无token, 后续跳过');
    } catch (e) {
        rec('瓜子.signIn(加密流程)', false, e.message);
        var emsg = String(e.message);
        if (emsg.indexOf('注册') >= 0 || emsg.indexOf('已经存在') >= 0 || emsg.indexOf('用户不存在') >= 0) {
            try {
                var signed2 = gzPost('/App/Authentication/Device/signUp', { new_key: GZ_DEVICE_KEY, old_key: GZ_OLD_KEY, phone_type: 1, code: '' }, 'signUp');
                GZ_TOKEN = text(signed2.token || '');
                rec('瓜子.signUp', !!GZ_TOKEN, 'token: ' + GZ_TOKEN.slice(0, 25));
            } catch (e2) { rec('瓜子.signUp', false, e2.message); }
        }
    }
    try {
        var t1 = Date.now();
        var list = gzPost('/App/IndexList/indexList', { area: '0', sub: '5', year: '0', pageSize: '10', sort: 'd_id', page: '1', tid: '1' }, 'indexList');
        var arr = list.list || [];
        rec('瓜子.电影列表(加密流程)', arr.length > 0, arr.length + ' 条 / ' + (Date.now() - t1) + 'ms' + (arr.length ? ', 首条: ' + text(arr[0].vod_name || arr[0].name) : ''));
    } catch (e) { rec('瓜子.电影列表(加密流程)', false, e.message); }
    try {
        var s = gzPost('/App/Index/findMoreVod', { keywords: '爱', ns: '', nt: String(Math.floor(Date.now() / 1000)), order_val: '1', page: '1' }, 'search');
        var sarr = s.list || [];
        rec('瓜子.搜索(加密流程)', sarr.length > 0, sarr.length + ' 条');
    } catch (e) { rec('瓜子.搜索(加密流程)', false, e.message); }
}

function home(filter) {
    RESULTS = [];
    try { runTests(); } catch (e) { rec('测试执行', false, e.message); }
    try { runGz(); } catch (e) { rec('瓜子执行', false, e.message); }
    return JSON.stringify({ class: [{ type_id: 'r', type_name: '诊断v4(' + RESULTS.length + '项)' }] });
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
function play(flag, id) { return JSON.stringify({ parse: 0, url: '', header: {} }); }
function search(wd) { return JSON.stringify({ list: [] }); }
function config() { return JSON.stringify({ kind: 'video', browseOnly: false, source: '诊断' }); }

export function __jsEvalReturn() {
    return { init: function(){}, home: home, homeVod: function(){ return JSON.stringify({list: []}); },
             category: category, detail: detail, search: search, play: play };
}
