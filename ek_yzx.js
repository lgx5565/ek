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
 * 云帧享（com.baiyunvideo.app）JS 源 —— 海阔小程序移植（全频道）
 * 明文 JSON 列表/搜索 + AES-256-GCM 详情解密 + vuk 签名取流（已用 Node 端到端验证 2026-07-10）
 * version: 1.0.0
 *
 * 全频道：动漫 / 剧集 / 电影 / 综艺 / 少儿 / 纪录片；搜索不过滤 typeName。
 *
 * 机制：
 *   - 引导：GET https://ss.trgfd.cn/cache/index/com.baiyunvideo.app.json
 *           → app.textURL(接口host) / qudao[0].banben(播放要的 version)；有稳定默认值，失败/轮换才回源刷新。
 *   - 分类：GET host/cache/zhaopian/{频道}/{剧情}/{地区}/{年份}/{排序}/{page}.json → 明文数组（每页 21，剧情段恒填「全部」）
 *   - 搜索：GET host/vc/api/search/{kw}/{page}.json → 明文数组（含全部频道；仅第 1 页有数据）
 *   - 详情：GET host/cache/videos/{floor(id/1000)}/{id}.json?version={ver}&baoming=com.baiyunvideo.app&channel=fenxiang
 *           → base64(iv12+cipher+tag16)，AES-256-GCM 解密（必须带上面 query，否则服务端返回旧 key 密文、新 key 解不开）
 *           key=qvn1u7FCfu8uaolp980i8uVHVS8Dxih7（utf8 32B）→ {videoName,...,playUrlList:[{name,ji}]}
 *   - 取流：GET host/vc/api/video/playurl?sid={id}&ji={ji}&jiIndex={i}&t=0&y=0&isjiid=1&androidId={16}&version={ver}&baoming=com.baiyunvideo.app&channel=fenxiang
 *           header vuk=md5(id+key) → data.url（多为带签名 mp4 直链）
 */

var CHANNELS = ['动漫', '剧集', '电影', '综艺', '少儿', '纪录片'];
var PKG = 'com.baiyunvideo.app';
var KEY = 'qvn1u7FCfu8uaolp980i8uVHVS8Dxih7'; // AES-256 key（utf8 32 字节；2026-07 由 Zz4O… 轮换而来，详情解密 + 取流 vuk 签名共用）
var BOOT = 'https://ss.trgfd.cn/cache/index/' + PKG + '.json';
var HOST_DEFAULT = 'https://js.trgfd.cn';
var VER_DEFAULT = '2.5.0';
var UA_OK = (typeof UA !== 'undefined' && UA.okhttp) ? UA.okhttp : 'okhttp/3.12.0';
var TIMEOUT = 15000;

var FILTERS = [
    { key: 'area', name: '地区', value: [{ n: '全部', v: '' }, { n: '日本', v: '日本' }, { n: '大陆', v: '大陆' }, { n: '美国', v: '美国' }, { n: '其他', v: '其他' }] },
    { key: 'year', name: '年份', value: [{ n: '全部', v: '' }, { n: '2026', v: '2026' }, { n: '2025', v: '2025' }, { n: '2024', v: '2024' }, { n: '2023', v: '2023' }, { n: '2022', v: '2022' }, { n: '2021', v: '2021' }, { n: '2020', v: '2020' }, { n: '2019', v: '2019' }, { n: '2018', v: '2018' }, { n: '2017', v: '2017' }, { n: '2016', v: '2016' }, { n: '更早', v: '更早' }] },
    { key: 'sort', name: '排序', value: [{ n: '最新', v: '最新' }, { n: '最热', v: '最热' }, { n: '评分', v: '评分' }] }
];

// host / version 优先级：内存缓存 → 持久缓存(getItem) → 硬编码默认（当前有效）；请求失败时才回引导接口刷新并持久化。
var _host = '', _ver = '', _loaded = false;
function loadCfg() {
    if (_loaded) return;
    _loaded = true;
    try { _host = getItem('yzx1_host', '') || ''; } catch (e) {}
    try { _ver = getItem('yzx1_ver', '') || ''; } catch (e) {}
}
function freshCfg() {
    try {
        var j = parseJson(request(BOOT, JSON.stringify({ headers: { 'User-Agent': UA_OK }, timeout: TIMEOUT }))) || {};
        if (j.app && j.app.textURL) { _host = String(j.app.textURL).replace(/\/+$/, ''); try { setItem('yzx1_host', _host); } catch (e) {} }
        if (j.qudao && j.qudao[0] && j.qudao[0].banben) { _ver = String(j.qudao[0].banben); try { setItem('yzx1_ver', _ver); } catch (e2) {} }
    } catch (e) { log('[yzx1] freshCfg err ' + e); }
}
function getHost() { loadCfg(); return (_host || HOST_DEFAULT).replace(/\/+$/, ''); }
function getVer() { loadCfg(); return _ver || VER_DEFAULT; }

function trim(s) { return s == null ? '' : String(s).replace(/^\s+|\s+$/g, ''); }
function clean(s) { if (!s) return ''; return trim(String(s).replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/[\u3000]+/g, ' ')); }
function guessType(u) { var l = (u || '').toLowerCase(); if (l.indexOf('.m3u8') >= 0) return 'm3u8'; if (l.indexOf('.mp4') >= 0) return 'mp4'; return 'auto'; }
function nonce(n) { var c = 'abcdefghijklmnopqrstuvwxyz0123456789', r = ''; for (var i = 0; i < n; i++) r += c.charAt(Math.floor(Math.random() * c.length)); return r; }
function isChannel(k) {
    for (var i = 0; i < CHANNELS.length; i++) if (CHANNELS[i] === k) return true;
    return false;
}

function reqJson(url) {
    try { return parseJson(request(url, JSON.stringify({ headers: { 'User-Agent': UA_OK }, timeout: TIMEOUT }))); }
    catch (e) { log('[yzx1] req err ' + e); return null; }
}

function gcmDec(b64) {
    try {
        var hex = crypto.base64.decode(b64, { output: 'hex' }) || '';
        if (hex.length < 24) return '';
        var ivHex = hex.substring(0, 24);
        var bodyHex = hex.substring(24);
        return crypto.aes.decrypt(bodyHex, KEY, {
            mode: 'GCM', padding: 'NoPadding', keyFormat: 'utf8',
            iv: ivHex, ivFormat: 'hex', input: 'hex', output: 'utf8', tagLen: 128
        }) || '';
    } catch (e) { log('[yzx1] gcm err ' + e); return ''; }
}

function mapList(arr, defaultType) {
    var out = [];
    if (!arr || !arr.length) return out;
    for (var i = 0; i < arr.length; i++) {
        var v = arr[i] || {};
        if (v.videoId == null) continue;
        out.push({
            id: String(v.videoId),
            name: trim(v.videoName),
            pic: v.fengmiantu || v.dahengtu || '',
            type: trim(v.typeName) || defaultType || '',
            year: v.year ? String(v.year) : '',
            remarks: trim(v.serialDesc || v.newchapter || v.remarks || ''),
            desc: clean(v.blurb || v.shortBlurb || '')
        });
    }
    return out;
}

// ───────────────────────── 契约入口 ─────────────────────────

function categories() {
    var arr = [{ key: '', title: '推荐' }];
    for (var i = 0; i < CHANNELS.length; i++) {
        arr.push({ key: CHANNELS[i], title: CHANNELS[i], filters: FILTERS });
    }
    return JSON.stringify(arr);
}

function listPage(channel, area, year, sort, page) {
    var ch = channel || CHANNELS[0];
    // 少儿频道路径比其它频道多两段（海阔实测：只按排序取、地区/年份段全填「全部」），否则 404
    var mid = (ch === '少儿')
        ? encodeUri('全部') + '/' + encodeUri('全部') + '/' + encodeUri('全部') + '/' + encodeUri('全部') + '/' + encodeUri('全部')
        : encodeUri('全部') + '/' + encodeUri(area || '全部') + '/' + encodeUri(year || '全部');
    var url = getHost() + '/cache/zhaopian/' + encodeUri(ch) + '/' + mid + '/' + encodeUri(sort || '最新') + '/' + (page || 1) + '.json';
    return mapList(reqJson(url), channel);
}

function homeSections() {
    var out = [];
    var secs = [
        { t: '最新动漫', ch: '动漫', s: '最新' },
        { t: '热播剧集', ch: '剧集', s: '最热' },
        { t: '热门电影', ch: '电影', s: '最热' },
        { t: '综艺精选', ch: '综艺', s: '最新' },
        { t: '少儿动画', ch: '少儿', s: '最新' },
        { t: '纪录片', ch: '纪录片', s: '评分' }
    ];
    for (var i = 0; i < secs.length; i++) {
        var lst = listPage(secs[i].ch, '全部', '全部', secs[i].s, 1);
        if (lst.length) out.push({ title: secs[i].t, key: secs[i].ch, items: lst.slice(0, 12) });
    }
    return JSON.stringify(out);
}

function search(keyword, page) {
    page = page || 1;
    var key = trim(keyword);
    if (!key) return JSON.stringify(listPage(CHANNELS[0], '全部', '全部', '最新', page));
    if (isChannel(key)) return JSON.stringify(listPage(key, '全部', '全部', '最新', page));
    if (page > 1) return '[]';
    var arr = reqJson(getHost() + '/vc/api/search/' + encodeUri(key) + '/' + page + '.json') || [];
    return JSON.stringify(mapList(arr));
}

function searchFiltered(category, filtersJson, page) {
    var f = parseJson(filtersJson) || {};
    var ch = isChannel(category) ? category : CHANNELS[0];
    return JSON.stringify(listPage(ch, f.area || '全部', f.year || '全部', f.sort || '最新', page || 1));
}

function detail(id) {
    var out = { id: id, name: '', pic: '', desc: '', type: '', year: '', remarks: '', episodes: [] };
    var dir = Math.floor((parseInt(id, 10) || 0) / 1000);
    // 详情接口必须带鉴权 query，否则服务端返回旧 key 密文（新 key 解不开）；getVer 可能被 freshCfg 刷新，故每次现取
    function detUrl() { return getHost() + '/cache/videos/' + dir + '/' + id + '.json?version=' + getVer() + '&baoming=' + PKG + '&channel=fenxiang'; }
    var raw = '';
    try { raw = request(detUrl(), JSON.stringify({ headers: { 'User-Agent': UA_OK }, timeout: TIMEOUT })) || ''; } catch (e) {}
    if (raw && raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
    var plain = gcmDec(trim(raw));
    if (!plain) { freshCfg(); try { raw = request(detUrl(), JSON.stringify({ headers: { 'User-Agent': UA_OK }, timeout: TIMEOUT })) || ''; } catch (e2) {} if (raw && raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1); plain = gcmDec(trim(raw)); }
    var v = parseJson(plain);
    if (!v) return JSON.stringify(out);

    out.name = trim(v.videoName);
    out.pic = v.fengmiantu || v.dahengtu || '';
    out.year = v.year ? String(v.year) : '';
    out.type = trim(v.typeName || v.class) || '';
    out.remarks = trim(v.remarks || v.serialDesc || '');
    var extra = [];
    if (v.class) extra.push('类型：' + trim(v.class));
    if (v.region) extra.push('地区：' + trim(v.region));
    if (v.actor) extra.push('主演：' + trim(v.actor));
    out.desc = (extra.length ? extra.join('  ') + '\n' : '') + clean(v.blurb || v.shortBlurb || '');

    var eps = v.playUrlList || [];
    for (var i = 0; i < eps.length; i++) {
        var e = eps[i] || {};
        if (e.ji == null) continue;
        out.episodes.push({ name: trim(e.name) || ('第' + (i + 1) + '集'), url: id + '$' + e.ji + '$' + i });
    }
    return JSON.stringify(out);
}

function fetchPlay(id, ji, idx) {
    var url = getHost() + '/vc/api/video/playurl?sid=' + id + '&ji=' + ji + '&jiIndex=' + idx +
        '&t=0&y=0&isjiid=1&androidId=' + nonce(16) + '&version=' + getVer() + '&baoming=' + PKG + '&channel=fenxiang';
    try {
        return parseJson(request(url, JSON.stringify({ headers: { 'User-Agent': UA_OK, 'vuk': md5(id + KEY) }, timeout: TIMEOUT })));
    } catch (e) { log('[yzx1] play err ' + e); return null; }
}

function play(flag) {
    var res = { url: '', type: 'auto', referer: '' };
    var seg = String(flag || '').split('$');
    if (seg.length < 3) return JSON.stringify(res);
    var id = seg[0], ji = seg[1], idx = seg[2];
    var r = fetchPlay(id, ji, idx);
    var u = r && r.data && r.data.url;
    if (!u) { freshCfg(); r = fetchPlay(id, ji, idx); u = r && r.data && r.data.url; }
    if (u) { res.url = u; res.type = guessType(u); }
    return JSON.stringify(res);
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
