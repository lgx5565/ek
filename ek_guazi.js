import { Crypto } from 'assets://js/lib/cat.js';
// ===== 纯 JS RSA (PKCS1 v1.5, BigInt 实现, 供 quickjs/Node 通用) =====
// 支持 1024/2048 位密钥; 输入输出按 o.input/o.output: base64|hex|utf8
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
    function bufToB64(arr) {
        var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = '', i;
        for (i = 0; i < arr.length; i += 3) {
            var b0 = arr[i], b1 = i + 1 < arr.length ? arr[i + 1] : NaN, b2 = i + 2 < arr.length ? arr[i + 2] : NaN;
            out += t.charAt(b0 >> 2);
            out += t.charAt(((b0 & 3) << 4) | (isNaN(b1) ? 0 : b1 >> 4));
            out += isNaN(b1) ? '=' : t.charAt(((b1 & 15) << 2) | (isNaN(b2) ? 0 : b2 >> 6));
            out += isNaN(b2) ? '=' : t.charAt(b2 & 63);
        }
        return out;
    }
    function bufToHex(arr) { var s = ''; for (var i = 0; i < arr.length; i++) { s += (arr[i] < 16 ? '0' : '') + arr[i].toString(16); } return s; }
    function hexToBuf(s) { var out = []; s = String(s).replace(/[^0-9a-fA-F]/g, ''); for (var i = 0; i + 1 < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16)); return out; }
    /* 极简 DER: 在 buffer 里找指定 tag 的第一个 TLV, 返回 value 字节数组 */
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
        /* 收集 SEQUENCE 里的所有 INTEGER (跳过前导 0x00) */
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
    function parsePublicKey(pem) {
        var der = pemBody(pem);
        var spki = derFind(der, 0, der.length, 0x30);           // 外层 SEQUENCE
        var bit = derFind(spki.body, 0, spki.body.length, 0x03); // BIT STRING
        var inner = bit.body.slice(1);                           // 去掉 unused-bits
        var seq = derFind(inner, 0, inner.length, 0x30);
        var ints = intsFromSeq(seq.body);
        return { n: ints[0], e: ints[1] || 65537n, k: (ints[0].toString(16).length + 1) >> 1 };
    }
    function parsePrivateKey(pem) {
        var der = pemBody(pem);
        var top = derFind(der, 0, der.length, 0x30);             // PKCS#8 外层
        var oct = derFind(top.body, 0, top.body.length, 0x04);   // OCTET STRING (PKCS#1)
        var seq = derFind(oct.body, 0, oct.body.length, 0x30);
        var ints = intsFromSeq(seq.body);                        // [ver, n, e, d, p, q, ...]
        return { n: ints[1], e: ints[2] || 65537n, d: ints[3], k: (ints[1].toString(16).length + 1) >> 1 };
    }
    function modPow(b, e, m) {
        var r = 1n; b %= m;
        while (e > 0n) {
            if (e & 1n) r = (r * b) % m;
            b = (b * b) % m; e >>= 1n;
        }
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
    return {
        encrypt: function (plain, pem, o) {
            o = o || {};
            var key = parsePublicKey(pem), msg, i;
            if (o.input === 'hex') msg = hexToBuf(plain);
            else if (o.input === 'base64') msg = b64ToBuf(plain);
            else msg = [];
            var s = String(plain);
            var _ub = utf8Bytes(s);
            for (i = 0; i < _ub.length; i++) msg.push(_ub[i]);
            var k = key.k;
            if (msg.length > k - 11) throw new Error('RSA 明文过长');
            var ps = [];
            while (ps.length < k - 3 - msg.length) { var r = Math.floor(Math.random() * 255) + 1; ps.push(r); }
            var m = [0].concat([2], ps, [0], msg);
            var c = modPow(os2ip(m), key.e, key.n);
            var out = bytesOf(c, k);
            if (o.output === 'hex') return bufToHex(out);
            return bufToB64(out);
        },
        decrypt: function (data, pem, o) {
            o = o || {};
            var key = parsePrivateKey(pem), arr;
            if (o.input === 'hex') arr = hexToBuf(data);
            else arr = b64ToBuf(data);
            var k = key.k;
            var c = os2ip(arr.slice(0, k));
            var m = modPow(c, key.d, key.n);
            var out = bytesOf(m, k);
            /* PKCS1 type 2: 00 02 PS 00 msg */
            if (out[0] === 0 && out[1] === 2) {
                var idx = out.indexOf(0, 2);
                if (idx > 2) out = out.slice(idx + 1);
            } else if (out[0] === 0 && out[1] === 1) {
                var idx2 = out.indexOf(0xFF, 2), idx3 = out.indexOf(0, 2);
                if (idx3 > 2) out = out.slice(idx3 + 1);
            }
            var s = '';
            for (var i = 0; i < out.length; i++) s += String.fromCharCode(out[i]);
            return utf8FromBytes(out);
        }
    };
})();

// ===== ekan 桥 shim (drpy0 模块环境复刻易看Pro全局桥) =====
var __ek_ext = {};
var ext = __ek_ext;   /* 关键: 源里 typeof ext 检查在 eval 期即成立; init 时原地更新属性 */


function __ekOpts(o) {
    o = o || {};
    return { headers: o.headers || {}, timeout: o.timeout || 20000 };
}
// 兼容不同壳的 req 返回: {content|body}|string
function __ekUnwrap(r) {
    if (r == null) return '';
    if (typeof r === 'string') return r;
    if (r.content != null) return r.content;
    if (r.body != null) return r.body;
    try { return String(r); } catch (e) { return ''; }
}
function request(u, o) {
    return __ekUnwrap(req(u, __ekOpts(typeof o === 'string' ? JSON.parse(o) : o)));
}
function post(u, b, o) {
    var opt = __ekOpts(typeof o === 'string' ? JSON.parse(o) : o);
    opt.method = 'POST';
    opt.data = b == null ? '' : String(b);
    opt.postType = 'raw';
    return __ekUnwrap(req(u, opt));
}
function parseJson(s) { return JSON.parse(s); }
function encodeUri(v) { return encodeURIComponent(String(v)); }
function decodeUri(v) { return decodeURIComponent(String(v)); }
function base64Encode(v) { return Crypto.enc.Base64.stringify(Crypto.enc.Utf8.parse(String(v))); }
function base64Decode(v) { return Crypto.enc.Utf8.stringify(Crypto.enc.Base64.parse(String(v))); }
function md5(v) { return Crypto.MD5(String(v)).toString(); }
function sha1(v) { return Crypto.SHA1(String(v)).toString(); }
var __ekStore = {};
/* OK影视 quickjs 无全局 log(只有 console): 部分源在 catch 里直接调 log() → 设备端 ReferenceError */
var log = (typeof log === 'function') ? log : function (v) { try { console.log(String(v)); } catch (e) {} };
function getItem(k, d) { return (k in __ekStore) ? __ekStore[k] : (d == null ? '' : d); }
function setItem(k, v) { __ekStore[k] = String(v); }
var crypto = {
    hash: function (n, v, o) {
        o = o || {};
        var h = (n === 'SHA-1') ? Crypto.SHA1 : (n === 'SHA-256' ? Crypto.SHA256 : Crypto.MD5);
        var msg = (o.input === 'hex') ? Crypto.enc.Hex.parse(String(v)) : Crypto.enc.Utf8.parse(String(v));
        return h(msg).toString();
    },
    base64: {
        encode: function (v, o) { o = o || {}; var w = (o.input === 'hex') ? Crypto.enc.Hex.parse(String(v)) : Crypto.enc.Utf8.parse(String(v)); return Crypto.enc.Base64.stringify(w); },
        decode: function (v, o) { o = o || {}; var w = Crypto.enc.Base64.parse(String(v)); return (o.output === 'hex') ? Crypto.enc.Hex.stringify(w) : Crypto.enc.Utf8.stringify(w); }
    },
    aes: {
        decrypt: function (str, key, o) {
            o = o || {};
            var k = (o.keyFormat === 'hex') ? Crypto.enc.Hex.parse(String(key)) : Crypto.enc.Utf8.parse(String(key));
            var mode = (String(o.mode || 'CBC').toUpperCase() === 'ECB') ? Crypto.mode.ECB : Crypto.mode.CBC;
            var pad = (String(o.padding || 'PKCS7').toUpperCase() === 'NoPadding') ? Crypto.pad.NoPadding : Crypto.pad.Pkcs7;
            var opt = { mode: mode, padding: pad };
            if (o.iv) opt.iv = (o.ivFormat === 'hex') ? Crypto.enc.Hex.parse(String(o.iv)) : Crypto.enc.Utf8.parse(String(o.iv));
            var msg = (o.input === 'hex') ? Crypto.enc.Hex.parse(String(str)) : null;
            var out = msg ? Crypto.AES.decrypt({ ciphertext: msg }, k, opt) : Crypto.AES.decrypt(String(str), k, opt);
            return out.toString(Crypto.enc.Utf8);
        },
        encrypt: function (str, key, o) {
            o = o || {};
            var k = (o.keyFormat === 'hex') ? Crypto.enc.Hex.parse(String(key)) : Crypto.enc.Utf8.parse(String(key));
            var mode = (String(o.mode || 'CBC').toUpperCase() === 'ECB') ? Crypto.mode.ECB : Crypto.mode.CBC;
            var pad = (String(o.padding || 'PKCS7').toUpperCase() === 'NoPadding') ? Crypto.pad.NoPadding : Crypto.pad.Pkcs7;
            var opt = { mode: mode, padding: pad };
            if (o.iv) opt.iv = (o.ivFormat === 'hex') ? Crypto.enc.Hex.parse(String(o.iv)) : Crypto.enc.Utf8.parse(String(o.iv));
            var out = Crypto.AES.encrypt(String(str), k, opt);
            if (o.output === 'hex') return Crypto.enc.Hex.stringify(out.ciphertext);
            return out.toString();
        }
    },
    rsa: {
        encrypt: function (plain, pem, o) {
            return __rsaJS.encrypt(plain, pem, o || {});
        },
        decrypt: function (data, pem, o) {
            return __rsaJS.decrypt(data, pem, o || {});
        }
    }
};
// ===== shim 结束 =====
/*
 * 瓜子秒播 - Lanerc QuickJS 数据源
 *
 * 协议依据：WexAiGuaZi.java + hy5528/tvbox py/guazi.py
 * 重要：上游按 Android 客户端校验请求头，API User-Agent 必须保持 okhttp/3.12.0。
 *
 * 该站有推荐列表，故意不声明 homeSections()；Lanerc 首页回退
 * 到 search('', 1)。
 */

var SOURCE_NAME = '瓜子';
var TIMEOUT = 45000;
var API_UA = 'okhttp/3.12.0';
var MEDIA_UA = 'Lavf/57.83.100';
var DEFAULT_PLAY_REFERER = 'http://WJiZxLXA2.com/';
var DEVICE_OLD_KEY = 'aLFBMWpxBrIDAD1Si/KVvm41';
var SIGN_SUFFIX = '*&zvdvdvddbfikkkumtmdwqppp?|4Y!s!2br';
var RESOLUTION_ORDER = ['3840', '2160', '1080', '720', '480', '360', '240'];

/* 当前 WexAiGuaZi 与公开实现交集中的 API host。apinew 放在第一位，因为
 * 2026-09-01 实测可完成 search -> detail -> play。可在 ext.hosts 覆盖。 */
var DEFAULT_HOSTS = [
    'https://apinew.uozvr.com',
    'https://sdapi.e2wu4ht.com',
    'https://api.w32z7vtd.com',
    'https://api.6a7nnf7.com',
    'https://api.umygrx3.com',
    'https://api.rmedphk.com'
];

var RSA_REQUEST_PUBLIC =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUM5+/y8sPsWkd1/RQS64X259E\n' +
    'UwxFXFE5HlA65MqrxnPs0JqoSRojSDy5QhwvROlaD6TwRQHKMY2OAZ6SnQeUJsCh\n' +
    'TEFIR9qUkwrs3/MVUMxjsv6JS6Oe/juclyJGTgVmDhB55EafXsD0SQYVj/QXXsxR\n' +
    '6ewR5E2kL52yAAD4yQIDAQAB\n' +
    '-----END PUBLIC KEY-----';

/* 这是协议的响应解密 key（PKCS#8），不是请求加密 public key 的私钥。 */
var RSA_RESPONSE_PRIVATE =
    '-----BEGIN PRIVATE KEY-----\n' +
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
    '-----END PRIVATE KEY-----';

var _stateLoaded = false;
var _token = '';
var _tokenId = '';
var _deviceKey = '';
var _deviceId = '';
var _selectedHost = '';
var _playReferer = '';
var _authBusy = false;

function text(value) { return value == null ? '' : String(value); }
function trim(value) { return text(value).replace(/^\s+|\s+$/g, ''); }
function clean(value) {
    return trim(text(value).replace(/<[^>]+>/g, '').replace(/&nbsp;|&#160;/gi, ' ')
        .replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#0?39;|&#x27;/gi, "'")
        .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>'));
}
function parse(value) {
    if (value && typeof value === 'object') return value;
    try { if (typeof parseJson === 'function') return parseJson(text(value)); } catch (ignore1) {}
    try { return JSON.parse(text(value)); } catch (ignore2) { return null; }
}
function extObject() {
    try {
        if (typeof ext === 'undefined' || ext == null) return {};
        return typeof ext === 'object' ? ext : (parse(ext) || {});
    } catch (ignore) { return {}; }
}
function cfg(key, fallback) {
    var value = extObject()[key];
    return value == null || text(value) === '' ? fallback : value;
}
function getStored(key, fallback) {
    try { return text(getItem('guazi_' + key, fallback)); } catch (ignore) { return text(fallback); }
}
function setStored(key, value) {
    try { setItem('guazi_' + key, text(value)); } catch (ignore) {}
}
function responseText(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (value.body != null) return text(value.body);
    if (value.content != null) return text(value.content);
    try { return JSON.stringify(value); } catch (ignore) { return text(value); }
}
function postRaw(url, body, headers) {
    var options = JSON.stringify({ headers: headers || {}, timeout: Number(cfg('timeout', TIMEOUT)) || TIMEOUT });
    try { return responseText(post(text(url), text(body), options)); }
    catch (ignore) { return ''; }
}
function nowSeconds() { return String(Math.floor(Date.now() / 1000)); }
function randomHex(bytes) {
    try { return text(crypto.randomHex(bytes)).toUpperCase(); } catch (ignore1) {}
    var out = '';
    while (out.length < bytes * 2) out += Math.floor(Math.random() * 16).toString(16);
    return out.substring(0, bytes * 2).toUpperCase();
}
function randomAlpha(length) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var out = '';
    while (out.length < length) {
        var hex = randomHex(1);
        var n = parseInt(hex, 16);
        if (!isNaN(n)) out += alphabet.charAt(n % alphabet.length);
    }
    return out;
}
function md5Upper(value) {
    try { if (typeof md5 === 'function') return text(md5(text(value))).toUpperCase(); } catch (ignore1) {}
    try { return text(crypto.hash('MD5', text(value), { input: 'utf8', output: 'hex' })).toUpperCase(); } catch (ignore2) { return ''; }
}
function base64EncodeText(value) {
    try { if (typeof base64Encode === 'function') return text(base64Encode(text(value))); } catch (ignore1) {}
    try { return text(crypto.base64.encode(text(value))); } catch (ignore2) { return ''; }
}
function base64DecodeText(value) {
    try { if (typeof base64Decode === 'function') return text(base64Decode(text(value))); } catch (ignore1) {}
    try { return text(crypto.base64.decode(text(value), { output: 'utf8' })); } catch (ignore2) { return ''; }
}
function formEncode(values) {
    var parts = [];
    for (var key in values) {
        if (!Object.prototype.hasOwnProperty.call(values, key)) continue;
        parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(text(values[key])));
    }
    return parts.join('&');
}
function mediaType(url) {
    var value = text(url).toLowerCase();
    if (value.indexOf('.m3u8') >= 0) return 'm3u8';
    if (value.indexOf('.mp4') >= 0) return 'mp4';
    return 'auto';
}
function normalizeHost(value) {
    value = trim(value).replace(/\/+$/, '');
    if (!value) return '';
    if (!/^https?:\/\//i.test(value)) value = 'https://' + value;
    return value;
}
function uniqueStrings(values) {
    var out = [], seen = {};
    for (var i = 0; i < values.length; i++) {
        var value = normalizeHost(values[i]);
        if (!value || seen[value]) continue;
        seen[value] = true;
        out.push(value);
    }
    return out;
}
function hosts() {
    loadState();
    var values = [];
    if (_selectedHost) values.push(_selectedHost);
    var custom = cfg('hosts', null);
    if (custom instanceof Array) values = values.concat(custom);
    else if (custom) values = values.concat(text(custom).split(','));
    var single = cfg('host', '');
    if (single) values.push(single);
    values = values.concat(DEFAULT_HOSTS);
    return uniqueStrings(values);
}
function loadState() {
    if (_stateLoaded) return;
    _token = getStored('token', '');
    _tokenId = getStored('token_id', '');
    _deviceKey = getStored('device_key', '');
    _deviceId = getStored('device_id', '');
    _selectedHost = normalizeHost(getStored('host', ''));
    _playReferer = getStored('play_referer', '');
    if (!/^[0-9A-F]{40}$/i.test(_deviceKey)) {
        _deviceKey = randomHex(20);
        setStored('device_key', _deviceKey);
    }
    if (!/^\d{15,16}$/.test(_deviceId)) {
        _deviceId = String(864150060000000 + Math.floor(Math.random() * 10000));
        setStored('device_id', _deviceId);
    }
    _stateLoaded = true;
}
function saveAuth(data) {
    data = data || {};
    _token = text(data.token || '');
    _tokenId = text(data.app_user_id || _tokenId || '');
    if (!_token) throw new Error('瓜子认证未返回 token');
    setStored('token', _token);
    setStored('token_id', _tokenId);
}
function clearAuth() {
    _token = '';
    _tokenId = '';
    setStored('token', '');
    setStored('token_id', '');
}
function rsaDecryptResponseKeys(value) {
    value = trim(value);
    if (!value) return '';
    try {
        return text(crypto.rsa.decrypt(value, RSA_RESPONSE_PRIVATE, {
            padding: 'PKCS1', input: 'base64', output: 'utf8'
        }));
    } catch (firstError) {
        /* Java 实现按 128 字节分块。绝大多数响应只有一块，但保留
         * 多块兼容，避免 keys 变长时直接失败。 */
        var hex = '';
        try { hex = text(crypto.base64.decode(value, { output: 'hex' })); } catch (ignore) {}
        if (!hex || hex.length % 256 !== 0) throw firstError;
        var plain = '';
        for (var i = 0; i < hex.length; i += 256) {
            plain += text(crypto.rsa.decrypt(hex.substring(i, i + 256), RSA_RESPONSE_PRIVATE, {
                padding: 'PKCS1', input: 'hex', output: 'utf8'
            }));
        }
        return plain;
    }
}
function apiHeaders(host) {
    return {
        'User-Agent': API_UA,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Ver': text(cfg('ver', '3.0.4.8')),
        'Version': text(cfg('version', '2606029')),
        'api-ver': text(cfg('apiVer', '3.0.4.8')),
        'PackageName': text(cfg('packageName', 'com.v54f07a912.t4ee50f184.dbb1e7669f20260721')),
        'code': text(cfg('code', 'GZ0313')),
        'deviceId': _deviceId,
        'lang': 'zh_cn',
        'Cache-Control': 'no-cache',
        'Referer': host
    };
}
function sendEncrypted(host, path, payload) {
    loadState();
    var aesKey = randomAlpha(16);
    var aesIv = randomAlpha(16);
    var jsonPayload = JSON.stringify(payload || {});
    var requestKey = text(crypto.aes.encrypt(jsonPayload, aesKey, {
        mode: 'CBC', padding: 'PKCS5', keyFormat: 'utf8', iv: aesIv,
        ivFormat: 'utf8', input: 'utf8', output: 'hex'
    })).toUpperCase();
    var keys = text(crypto.rsa.encrypt(JSON.stringify({ iv: aesIv, key: aesKey }), RSA_REQUEST_PUBLIC, {
        padding: 'PKCS1', input: 'utf8', output: 'base64'
    }));
    var timestamp = nowSeconds();
    /* 当前 WexAiGuaZi 外层 token_id 固定留空；详情需要的 token_id 位于
     * AES payload 内。不要将这两个字段混为一处。 */
    var signatureBase = 'token_id=,token=' + _token + ',phone_type=1,request_key=' + requestKey +
        ',app_id=1,time=' + timestamp + ',keys=' + keys + SIGN_SUFFIX;
    var body = {
        token: _token,
        token_id: '',
        phone_type: '1',
        request_key: requestKey,
        app_id: '1',
        time: timestamp,
        keys: keys,
        signature: md5Upper(signatureBase),
        phone_model: text(cfg('phoneModel', 'xiaomi-22081212c')),
        ad_version: '1'
    };
    var raw = postRaw(host + path, formEncode(body), apiHeaders(host));
    var envelope = parse(raw);
    if (!envelope || typeof envelope !== 'object' || !envelope.data) {
        return { ok: false, network: true, error: '非法响应' };
    }
    if (envelope.code != null && Number(envelope.code) !== 200) {
        return { ok: false, business: true, code: Number(envelope.code), error: text(envelope.msg || envelope.message) };
    }
    var section = envelope.data;
    if (section.response_key == null && (section.list instanceof Array || section.vodInfo)) {
        return { ok: true, data: section };
    }
    try {
        var keyInfo = parse(rsaDecryptResponseKeys(section.keys));
        if (!keyInfo || !keyInfo.key || !keyInfo.iv) throw new Error('响应 key 解密失败');
        var plain = crypto.aes.decrypt(text(section.response_key), text(keyInfo.key), {
            mode: 'CBC', padding: 'PKCS5', keyFormat: 'utf8', iv: text(keyInfo.iv),
            ivFormat: 'utf8', input: 'hex', output: 'utf8'
        });
        var decoded = parse(plain);
        if (!decoded || typeof decoded !== 'object') throw new Error('响应 JSON 解析失败');
        return { ok: true, data: decoded };
    } catch (error) {
        return { ok: false, network: true, error: text(error && error.message || error) };
    }
}
function rawRequest(path, payload) {
    var list = hosts();
    var last = null;
    for (var i = 0; i < list.length; i++) {
        var result = sendEncrypted(list[i], path, payload);
        if (result.ok) {
            _selectedHost = list[i];
            setStored('host', _selectedHost);
            return result.data;
        }
        last = result;
        /* 连到真正 API 后的业务错误不是 host 失效；不再对其他 CDN
         * 重放同一个注册/播放请求。 */
        if (result.business) throw new Error('瓜子业务错误 ' + result.code + ': ' + result.error);
    }
    throw new Error('瓜子 API 不可用: ' + text(last && last.error));
}
function ensureAuth() {
    loadState();
    if (_token) return;
    if (_authBusy) throw new Error('瓜子认证重入');
    _authBusy = true;
    try {
        var signInPayload = { new_key: _deviceKey, old_key: DEVICE_OLD_KEY };
        try {
            saveAuth(rawRequest('/App/Authentication/Device/signIn', signInPayload));
        } catch (ignoreSignIn) {
            saveAuth(rawRequest('/App/Authentication/Device/signUp', {
                new_key: _deviceKey, old_key: DEVICE_OLD_KEY, phone_type: 1, code: ''
            }));
        }
    } finally { _authBusy = false; }
}
function currentPayload(payload) {
    var out = {}, source = payload || {};
    for (var key in source) if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
    /* detail payload 同时内嵌 token/token_id。如果首次请求发现 token 过期并
     * 重新登录，重放前必须把新值回填，不能继续加密旧 token。 */
    if (Object.prototype.hasOwnProperty.call(out, 'token')) out.token = _token;
    if (Object.prototype.hasOwnProperty.call(out, 'token_id')) out.token_id = _tokenId;
    return out;
}
function apiCall(path, payload, noRetry) {
    ensureAuth();
    try { return rawRequest(path, currentPayload(payload)); }
    catch (firstError) {
        if (noRetry) throw firstError;
        clearAuth();
        ensureAuth();
        return rawRequest(path, currentPayload(payload));
    }
}

function mapCard(value) {
    value = value || {};
    var id = text(value.vod_id || value.id);
    var name = clean(value.vod_name || value.name || value.title);
    if (!id || !name) return null;
    var continu = Number(value.vod_continu || 0) || 0;
    var total = Number(value.d_total || 0) || 0;
    var remarks = clean(value.vod_remarks || value.vod_scroe || '');
    if (continu > 0) remarks = total > 0 && continu === total ? '全' + total + '集' : '更新至' + continu + '集';
    else if (!remarks) remarks = text(value.vod_year || '');
    return {
        id: id,
        name: name,
        pic: text(value.vod_pic || value.pic),
        type: clean(value.vod_class || value.type_name || ''),
        year: text(value.vod_year || ''),
        remarks: remarks,
        desc: clean(value.vod_use_content || value.vod_content || '')
    };
}
function mapCards(values) {
    var out = [], seen = {}, list = values instanceof Array ? values : [];
    for (var i = 0; i < list.length; i++) {
        var card = mapCard(list[i]);
        if (!card || seen[card.id]) continue;
        seen[card.id] = true;
        out.push(card);
    }
    return out;
}
function filterSet(category) {
    var subtype = {
        '1': [['全部', ''], ['动作片', '5'], ['悬疑片', '29'], ['喜剧片', '6'], ['爱情片', '7'], ['科幻片', '8'], ['恐怖片', '9'], ['剧情片', '10'], ['战争片', '11'], ['动画片', '36'], ['纪录片', '20'], ['灾难片', '38'], ['犯罪片', '61']],
        '2': [['全部', ''], ['国产剧', '12'], ['香港剧', '13'], ['台湾剧', '14'], ['欧美剧', '15'], ['日本剧', '16'], ['韩国剧', '17'], ['海外剧', '18'], ['泰国剧', '19'], ['新加坡剧', '69']],
        '3': [['全部', ''], ['中国动漫', '30'], ['日本动漫', '31'], ['欧美动漫', '33']],
        '4': [['全部', ''], ['大陆综艺', '22'], ['港台综艺', '23'], ['日韩综艺', '24'], ['欧美综艺', '25']]
    }[text(category)] || [['全部', '']];
    function values(rows) {
        var out = [];
        for (var i = 0; i < rows.length; i++) out.push({ n: rows[i][0], v: rows[i][1] });
        return out;
    }
    var years = [['全部', ''], ['2026', '2026'], ['2025', '2025'], ['2024', '2024'], ['2023', '2023'], ['2022', '2022'], ['2021', '2021'], ['2020', '2020'], ['2019', '2019'], ['2018', '2018'], ['更早', '2004']];
    return [
        { key: 'sub', name: '类型', value: values(subtype) },
        { key: 'area', name: '地区', value: values([['全部', ''], ['大陆', '大陆'], ['香港', '香港'], ['台湾', '台湾'], ['美国', '美国'], ['韩国', '韩国'], ['日本', '日本'], ['泰国', '泰国'], ['其他', '其他']]) },
        { key: 'year', name: '年份', value: values(years) },
        { key: 'sort', name: '排序', value: values([['最新', 'd_id'], ['最热', 'd_hits'], ['推荐', 'd_score']]) }
    ];
}
function defaultSubtype(category) {
    var defaults = { '1': '5', '2': '12', '3': '30', '4': '22' };
    return defaults[text(category)] || '';
}
function categoryList(category, page, filters) {
    filters = filters || {};
    var body = {
        area: text(filters.area || '0'),
        sub: Object.prototype.hasOwnProperty.call(filters, 'sub') ? text(filters.sub) : defaultSubtype(category),
        year: text(filters.year || '0'),
        pageSize: '30',
        sort: text(filters.sort || 'd_id'),
        page: String(Math.max(1, Number(page) || 1)),
        tid: text(category)
    };
    return mapCards((apiCall('/App/IndexList/indexList', body).list || []));
}
function recommendation() {
    return mapCards((apiCall('/App/IndexList/indexList', {
        area: '0', sub: '', year: '0', pageSize: '30', sort: 'd_hits', page: '1', tid: '0'
    }).list || []));
}
function searchList(keyword, page) {
    return mapCards((apiCall('/App/Index/findMoreVod', {
        keywords: text(keyword), ns: '', nt: nowSeconds(), order_val: '1',
        page: String(Math.max(1, Number(page) || 1))
    }).list || []));
}
function encodePlayMeta(value) {
    return 'gz1:' + base64EncodeText(JSON.stringify(value || {}));
}
function decodePlayMeta(value) {
    value = text(value);
    if (value.indexOf('gz1:') === 0) return parse(base64DecodeText(value.substring(4))) || {};
    return { p: value, r: [] };
}
function parseParam(value) {
    var out = {}, pairs = text(value).split('&');
    for (var i = 0; i < pairs.length; i++) {
        var at = pairs[i].indexOf('=');
        if (at <= 0) continue;
        var key = pairs[i].substring(0, at);
        var val = pairs[i].substring(at + 1);
        try { key = decodeURIComponent(key); } catch (ignore1) {}
        try { val = decodeURIComponent(val); } catch (ignore2) {}
        out[key] = val;
    }
    return out;
}
function bestResolution(values) {
    var list = values instanceof Array ? values : [];
    var best = '', score = -1;
    for (var i = 0; i < list.length; i++) {
        var n = Number(text(list[i]).replace(/\D+/g, '')) || 0;
        if (n > score) { score = n; best = text(list[i]); }
    }
    return best || '1080';
}
function loadPlayReferer() {
    if (_playReferer) return _playReferer;
    _playReferer = text(cfg('playReferer', DEFAULT_PLAY_REFERER));
    try {
        var value = trim(apiCall('/App/UserInfo/getUserInfo', {}, true).playRef);
        if (/^https?:\/\//i.test(value)) _playReferer = value;
    } catch (ignore) {}
    setStored('play_referer', _playReferer);
    return _playReferer;
}

function config() {
    return JSON.stringify({ kind: 'video', browseOnly: false, source: SOURCE_NAME });
}
function categories() {
    try {
        var rows = [
            ['', '推荐'], ['1', '电影'], ['2', '电视剧'], ['3', '动漫'], ['4', '综艺'],
            ['64', '短剧'], ['72', '音乐'], ['74', 'AI漫剧'], ['73', '电影解说'],
            ['71', '体育解说'], ['70', '电竞解说']
        ];
        var out = [];
        for (var i = 0; i < rows.length; i++) {
            var item = { key: rows[i][0], title: rows[i][1] };
            if (rows[i][0]) item.filters = filterSet(rows[i][0]);
            out.push(item);
        }
        return JSON.stringify(out);
    } catch (ignore) { return JSON.stringify([{ key: '', title: '推荐' }]); }
}
function search(keyword, page) {
    try {
        keyword = trim(keyword);
        page = Math.max(1, Number(page) || 1);
        if (!keyword) return JSON.stringify(page === 1 ? recommendation() : []);
        return JSON.stringify(searchList(keyword, page));
    } catch (ignore) { return '[]'; }
}
function searchFiltered(category, filtersJson, page) {
    var items;
    try { items = categoryList(text(category), page, parse(filtersJson) || {}); } catch (ignore) { items = []; }
    if (!Array.isArray(items)) items = [];
    if (!items.length && (Number(page) || 1) === 1) return JSON.stringify([{ id: 'ekoff_hint', name: '⚠️ 后端未响应或限流，请稍后重试', pic: '', remarks: '后端状态', desc: '首页分类能显示但列表为空，通常是后端 API 被限流或临时故障，过段时间刷新即可。' }]);
    return JSON.stringify(items);
}
function detail(id) {
    id = text(id).split('/')[0];
    try {
        ensureAuth();
        var infoData = apiCall('/App/IndexPlay/playInfo', {
            token_id: _tokenId, vod_id: id, mobile_time: nowSeconds(), token: _token
        });
        var vod = infoData.vodInfo || {};
        var sourceData = apiCall('/App/Resource/Vurl/show', { vurl_cloud_id: '2', vod_d_id: id });
        var list = sourceData.list instanceof Array ? sourceData.list : [];
        var episodes = [];
        for (var i = 0; i < list.length; i++) {
            var item = list[i] || {}, playMap = item.play || {};
            var resolutions = [], firstParam = '';
            for (var r = 0; r < RESOLUTION_ORDER.length; r++) {
                var resolution = RESOLUTION_ORDER[r], candidate = playMap[resolution] || {};
                if (text(candidate.show_type) === '2' || !candidate.param) continue;
                resolutions.push(resolution);
                if (!firstParam) firstParam = text(candidate.param);
            }
            /* 某些后端返回新的清晰度 key；按数值降序补入。 */
            var extras = [];
            for (var key in playMap) {
                if (!Object.prototype.hasOwnProperty.call(playMap, key) || RESOLUTION_ORDER.indexOf(key) >= 0) continue;
                var extra = playMap[key] || {};
                if (text(extra.show_type) !== '2' && extra.param) extras.push(key);
            }
            extras.sort(function (a, b) { return (Number(text(b).replace(/\D+/g, '')) || 0) - (Number(text(a).replace(/\D+/g, '')) || 0); });
            for (var e = 0; e < extras.length; e++) {
                resolutions.push(extras[e]);
                if (!firstParam) firstParam = text((playMap[extras[e]] || {}).param);
            }
            if (!firstParam) continue;
            episodes.push({
                name: clean(item.title || ('第' + (i + 1) + '集')),
                route: '瓜子',
                url: encodePlayMeta({ p: firstParam, r: resolutions })
            });
        }
        return JSON.stringify({
            id: id,
            name: clean(vod.vod_name || ''),
            pic: text(vod.vod_pic || ''),
            type: clean(vod.vod_class || vod.vod_area || ''),
            year: text(vod.vod_year || ''),
            area: clean(vod.vod_area || ''),
            actor: clean(vod.vod_actor || ''),
            director: clean(vod.vod_director || ''),
            desc: clean(vod.vod_use_content || vod.vod_content || ''),
            episodes: episodes
        });
    } catch (ignore) {
        return JSON.stringify({ id: id, name: '', pic: '', desc: '', episodes: [] });
    }
}
function play(flag) {
    try {
        var meta = decodePlayMeta(flag);
        var params = parseParam(meta.p);
        if (params.vod_d_id) {
            params.vod_id = params.vod_d_id;
            delete params.vod_d_id;
        }
        params._client_ts = String(Date.now()) + randomHex(4);
        params.mobile_time = nowSeconds();
        params.rand = String(Math.floor(Math.random() * 2147483647));
        if (!params.resolution) params.resolution = bestResolution(meta.r);
        params.type = 'play';
        var data = apiCall('/App/Resource/VurlDetail/showOne', params);
        var url = trim(data.url);
        if (!/^https?:\/\//i.test(url)) return JSON.stringify({ url: '', type: 'auto' });
        var referer = loadPlayReferer();
        var headers = { 'User-Agent': MEDIA_UA, 'Referer': referer };
        return JSON.stringify({
            url: url,
            type: mediaType(url),
            headers: headers,
            userAgent: MEDIA_UA,
            referer: referer
        });
    } catch (ignore) { return JSON.stringify({ url: '', type: 'auto' }); }
}
// ===== drpy 适配层: 易看源 -> drpy0(TVBox/FongMi) 约定 =====
// 注意: drpy 函数一律用 drpy_ 前缀, 避免覆盖易看源的同名函数(hoisting 后者会赢)
function __ekCards(a) {
    a = (typeof a === 'string') ? JSON.parse(a || '[]') : (a || []);
    if (!Array.isArray(a)) a = [];
    return a.map(function (x) {
        var pic = String(x.pic || '');
        // 豆瓣图床防盗链: 418 裸请求, 必须带 douban Referer (jar 版蜘蛛同款后缀格式)
        if (pic.indexOf('doubanio.com') >= 0 && pic.indexOf('@') < 0) {
            pic += '@Referer=https://www.douban.com/@User-Agent=Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';
        }
        return { vod_id: String(x.id || ''), vod_name: String(x.name || ''), vod_pic: pic,
                 vod_remarks: String(x.remarks || ''), vod_year: String(x.year || ''),
                 vod_class: String(x.type || ''), vod_content: String(x.desc || '') };
    });
}
/* 设备端错误可视化: 出错时把错误文本变成一条"影片", 用户截图即可看到真实原因 */
function __ekErr(scope, e) {
    var msg = (e && e.message) ? e.message : String(e);
    var line = (e && e.stack) ? (String(e.stack).split('\n')[1] || '').trim().slice(0, 120) : '';
    return [{ id: 'ekdbg_' + scope, name: '⚠️ ' + scope + ': ' + msg.slice(0, 80),
              pic: '', remarks: line, desc: String(e.stack || e).slice(0, 400), type: '', year: '' }];
}
function __ekExtApply(cfg) {
    try {
        if (cfg && cfg.ext) {
            var o = (typeof cfg.ext === 'string') ? JSON.parse(cfg.ext) : cfg.ext;
            if (o && typeof o === 'object') for (var k in o) __ek_ext[k] = o[k];
        }
    } catch (e) {}
}
function drpy_init(cfg) { __ekExtApply(cfg); }
function drpy_home(filter) {
    var classes = [], filters = {};
    try {
        var cats = JSON.parse(categories());
        cats.forEach(function (c) {
            if (c.key === '' || c.key == null) return;
            classes.push({ type_id: String(c.key), type_name: String(c.title || c.key) });
            if (c.filters && c.filters.length) filters[String(c.key)] = c.filters;
        });
    } catch (e) {
        var em = (e && e.message) ? e.message : String(e);
        classes.push({ type_id: 'ekdbg_home', type_name: '⚠️ 加载错误: ' + em.slice(0, 70) });
    }
    return JSON.stringify({ class: classes, filters: filters });
}
function drpy_homeVod() {
    try {
        if (typeof homeSections === 'function') {
            var secs = JSON.parse(homeSections());
            var cards = [];
            (Array.isArray(secs) ? secs : []).forEach(function (s) { (s.cards || s.list || []).forEach(function (c) { cards.push(c); }); });
            return JSON.stringify({ list: __ekCards(JSON.stringify(cards)) });
        }
    } catch (e) {}
    return JSON.stringify({ list: [] });
}
function drpy_category(tid, pg, filter, extend) {
    pg = Math.max(1, parseInt(pg, 10) || 1);
    if (tid === 'ekoff') return JSON.stringify({ page: 1, pagecount: 1, list: [{ id: 'ekoff', name: '⚠️ 该源后端暂不可达（服务器停机或限流），请稍后重试。', pic: '', remarks: '后端状态', desc: 'AppV7 系源的后端为 VPS，不稳定属常态；过一会儿刷新本源，或先改用其他源。' }] });
    try {
        var f = {};
        try { f = (typeof extend === 'string' && extend) ? JSON.parse(extend) : (extend || {}); } catch (e) {}
        if (typeof searchFiltered === 'function' && tid) return JSON.stringify({ page: pg, pagecount: 9999, list: __ekCards(searchFiltered(String(tid), JSON.stringify(f), pg)) });
        if (typeof search === 'function') return JSON.stringify({ page: pg, pagecount: 9999, list: __ekCards(search('', pg)) });
    } catch (e) {
        var em = (e && e.message) ? e.message : String(e);
        return JSON.stringify({ page: 1, pagecount: 1, list: __ekCards(JSON.stringify([
            { id: 'ekdbg_cat', name: '⚠️ ' + em.slice(0, 70), pic: '', remarks: '加载错误', desc: String(e.stack || e).slice(0, 300) }])) });
    }
    return JSON.stringify({ page: pg, pagecount: 9999, list: [] });
}
function drpy_detail(id) {
    try {
        var d = JSON.parse(detail(String(id)));
        var groups = {}, order = [];
        (d.episodes || []).forEach(function (e) {
            var rt = String(e.route || 'source');
            if (!groups[rt]) { groups[rt] = []; order.push(rt); }
            groups[rt].push(String(e.name || '') + '$' + String(e.url || ''));
        });
        var v = { vod_id: String(d.id || id), vod_name: String(d.name || ''), vod_pic: String(d.pic || ''),
                  vod_content: String(d.desc || ''), vod_year: String(d.year || ''), vod_area: String(d.area || ''),
                  vod_actor: String(d.actor || ''), vod_director: String(d.director || ''), vod_class: String(d.type || ''),
                  vod_play_from: order.join('$$$'), vod_play_url: order.map(function (k) { return groups[k].join('#'); }).join('$$$') };
        return JSON.stringify({ list: [v] });
    } catch (e) { return JSON.stringify({ list: [] }); }
}
function drpy_search(wd, quick, pg) {
    pg = Math.max(1, parseInt(pg, 10) || 1);
    try {
        if (typeof search === 'function') return JSON.stringify({ list: __ekCards(search(String(wd || ''), pg)) });
    } catch (e) {}
    return JSON.stringify({ list: [] });
}
function drpy_play(flag, id, flags) {
    try {
        var r = JSON.parse(play(String(id)));
        var u = String(r.url || '');
        if (!u) return JSON.stringify({ parse: 0, url: '' });
        var out = { parse: 0, url: u };
        var hd = r.headers || r.header;
        if (hd && typeof hd === 'string') { try { hd = JSON.parse(hd); } catch (e) { hd = undefined; } }
        if (hd && typeof hd === 'object' && Object.keys(hd).length) out.header = hd;
        return JSON.stringify(out);
    } catch (e) { return JSON.stringify({ parse: 0, url: '' }); }
}
export function __jsEvalReturn() {
    return { init: drpy_init, home: drpy_home, homeVod: drpy_homeVod, category: drpy_category,
             detail: drpy_detail, search: drpy_search, play: drpy_play };
}
// ===== 适配层结束 =====
