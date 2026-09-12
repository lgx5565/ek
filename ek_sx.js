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
/* 师兄 - 大师兄 AppV7 Lanerc source.
 * AppV7 AES 与播放解析 RSA 均由本文件本地完成，不依赖远程解密服务。 */
var SOURCE_TITLE = '师兄';
var APP_API = 'http://app2.dsx.ac/ndsx.php/v7/logs';
var APPV7_SEPARATOR = '^~!@#[-';
var APPV7_RESPONSE_MAGIC = 'eGRkYXBwc2VjcmV0a2V5'; /* base64("xddappsecretkey") */
var APPV7_KEY_HEX_FALLBACK = '21295b04b4d671c664faf7a8078f5b0d';
var APPV7_PARSE_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\n' +
'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO9omsi+ys7fmBH3\n' +
'w1d0DfvRAQlj0wLB1BI3Xsb9WSiu4lEc1Me+XubnzTxaQPCBbnuZURerRrO981n9\n' +
'GhsQkDcWmtW+X1mpCllOWt8bbnWwKPsHqemRFxncDWE/d0nA9yrZn6nLVy/J7DJ3\n' +
'cVJlIs9bNLArqEiR8KVrAf1PNSLXAgMBAAECgYBGPn3z2q8s5cP7uaOSHFYiBZ/1\n' +
'PlniXDa6JY7ked9YJX/35qqz9LJps6evRpf5OTDOiRyXAkUbZedqBu5K9KArSGVy\n' +
'xp/Vym4b0siEVeM8qq9Gbf74lHPH+L+X/NmXemydwZHR1lU9PiLJVMsh8o6aAazk\n' +
'B8ijZcsNMyYZUSH36QJBAPvHq511Uz45lx5BtVSZClcUnqPRFSmNnRdjATikDzFT\n' +
'ObemnGJU3eL/7VIPWtjEj9LvGP/WyX6gyo1zKc8BRtUCQQDza9oFnSmMHPkvrll/\n' +
'zMxcy3FeOTW0hctBhdIMbBmjJJyhlfTmBOvxwm8I91F05ydkSZ1yLuLhAjLxbjqs\n' +
'2fD7AkB/KOHQvW+UTqu22ULGfiCNyFkyrSc9/EqphBQa0ijmJX1R9nCm7Ou/eLgY\n' +
'KK8eKW/l/WGn3IeZT4XdGJu185QdAkBthqmivQRktuSoP5qlllCdsCxiaPtxLoI2\n' +
'CTBpxnoCngab7g0zMiO3s/Sh5CYSo69lwHnHVrFe7M5fM2nTPHzhAkEAiJETUvYF\n' +
'wCVKNGTYMzUg7v3QblqYXB+IhzcU37sHZOn6a46V5eJDadavIvuEmoxJHWTybi+1\n' +
'ZkN7LeUUg4ylCw==\n-----END PRIVATE KEY-----';
var TIMEOUT = 30000;
var _avConfig = {
    key:'AppV7Dsx', name:'大师兄', home_url:'https://dsxys.com/',
    host:'http://app2.dsx.ac/ndsx.php', version:'4.0.0', version_number:'4000',
    pk_id:'com.qdsj.zxt.hzjc', build_time:'1786613938967',
    sign_md5:'56a4bb80bd67422e9c5b48f003d445c8', apk_length:'59954699',
    parse_key:'DSX', platform:'android', platform_version:'TP1A.220624.014',
    user_agent:'Dart/3.11 (dart:io)'
};
var _avNav = null;
var _avHome = null;

function t(v) { return v == null ? '' : String(v); }
function trim(v) { return t(v).replace(/^\s+|\s+$/g, ''); }
function entities(v) { var s=t(v); for(var i=0;i<4;i++){var n=s.replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'");if(n===s)break;s=n;}return s; }
function clean(v) { return trim(entities(t(v).replace(/<br\s*\/?\s*>/gi, '\n').replace(/<[^>]+>/g, ''))); }
function pic(v) { return trim(entities(v)); }
function json(v) { if (v && typeof v === 'object') return v; try { if (typeof parseJson === 'function') return parseJson(t(v)); } catch (e1) {} try { return JSON.parse(t(v)); } catch (e2) { return null; } }
function body(v) { if (v == null) return ''; if (typeof v === 'string') return v; if (v.body != null) return t(v.body); if (v.content != null) return t(v.content); try { return JSON.stringify(v); } catch (e) { return t(v); } }
function getRaw(url, headers) { try { return body(request(url, JSON.stringify({headers:headers || {}, timeout:TIMEOUT}))); } catch (e) { return ''; } }
function postRaw(url, value, headers) {
    var options = JSON.stringify({headers:headers || {}, timeout:TIMEOUT});
    try { return body(post(url, t(value), options)); } catch (e) { return ''; }
}
function enc(v) { try { if (typeof encodeUri === 'function') return t(encodeUri(t(v))); } catch (e1) {} try { return encodeURIComponent(t(v)); } catch (e2) { return t(v); } }
function b64e(v) { try { if (typeof base64Encode === 'function') return t(base64Encode(t(v))); } catch (e1) {} try { return t(crypto.base64.encode(t(v), {input:'utf8'})); } catch (e2) { return ''; } }
function b64d(v) { try { if (typeof base64Decode === 'function') return t(base64Decode(t(v))); } catch (e1) {} try { return t(crypto.base64.decode(t(v), {output:'utf8'})); } catch (e2) { return ''; } }
function mediaType(u) { u=t(u).toLowerCase(); if (u.indexOf('.m3u8')>=0) return 'm3u8'; if (u.indexOf('.mp4')>=0) return 'mp4'; if (u.indexOf('.flv')>=0) return 'flv'; return 'auto'; }

function md5Hex(v) {
    try { if (typeof md5 === 'function') return t(md5(t(v))).toLowerCase(); } catch (e1) {}
    try { return t(crypto.hash('MD5', t(v), {input:'utf8', output:'hex'})).toLowerCase(); } catch (e2) { return ''; }
}
function randomHex(bytes) {
    try { return t(crypto.randomHex(bytes)).toLowerCase(); } catch (e1) {}
    try { return t(crypto.randomBytes(bytes)).toLowerCase(); } catch (e2) {}
    var out=''; while(out.length<bytes*2)out+=Math.floor(Math.random()*16).toString(16); return out.substring(0,bytes*2);
}
function appKeyHex() {
    var cfg=appConfig(), key=md5Hex(t(cfg.build_time)+APPV7_SEPARATOR+t(cfg.pk_id));
    return /^[0-9a-f]{32}$/.test(key)?key:APPV7_KEY_HEX_FALLBACK;
}
function appEncrypt(raw) {
    try {
        var iv=randomHex(16), cipher=t(crypto.aes.encrypt(t(raw),appKeyHex(),{
            mode:'CBC',padding:'PKCS5',keyFormat:'hex',iv:iv,ivFormat:'hex',input:'utf8',output:'hex'
        }));
        if(!/^[0-9a-f]+$/i.test(cipher)||cipher.length%32!==0)return '';
        return t(crypto.base64.encode(iv+cipher,{input:'hex'})).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    } catch(e){return '';}
}
function responseDelta(i){if(i%2===0)return 11;if(i%3===0)return 4;if(i%5===0)return 2;return 3;}
function appDecrypt(raw) {
    try {
        raw=trim(raw).replace(/\s+/g,'');
        var at=raw.lastIndexOf(APPV7_RESPONSE_MAGIC);if(at<0)return '';
        var pass=Number(t(crypto.base64.decode(raw.substring(at+APPV7_RESPONSE_MAGIC.length),{output:'utf8'})));
        var prefix=raw.substring(0,at);if(!(pass>0)||pass>prefix.length)return '';
        var secret=t(crypto.base64.decode(prefix.substring(0,pass),{output:'utf8'})), values=[],re=/0x(\d+?)(?=0x|$)/g,m;
        while((m=re.exec(secret))!==null)values.push(Number(m[1]));
        if(!values.length)return '';values.reverse();
        var hidden='';for(var i=0;i<values.length;i++){var n=(values[i]-responseDelta(i))&255;hidden+=(n<16?'0':'')+n.toString(16);}
        var tail=t(crypto.base64.decode(prefix.substring(pass),{output:'hex'})), wire=hidden+tail;
        if(wire.length<64||(wire.length-32)%32!==0)return '';
        return t(crypto.aes.decrypt(wire.substring(32),appKeyHex(),{
            mode:'CBC',padding:'PKCS5',keyFormat:'hex',iv:wire.substring(0,32),ivFormat:'hex',input:'hex',output:'utf8'
        }));
    } catch(e){return '';}
}
function parseDecrypt(raw) {
    try {
        var value=trim(raw).replace(/\s+/g,''), hex=t(crypto.base64.decode(value,{output:'hex'}));
        if(!hex||hex.length%256!==0)return '';
        var plain='';
        for(var i=0;i<hex.length;i+=256){
            var block=t(crypto.base64.encode(hex.substring(i,i+256),{input:'hex'}));
            var part=t(crypto.rsa.decrypt(block,APPV7_PARSE_PRIVATE_KEY,{padding:'PKCS1',input:'base64',output:'utf8'}));
            if(!part)return '';plain+=part;
        }
        return plain;
    } catch(e){return '';}
}
function appConfig() { return _avConfig; }
function appCall(method, data) {
    var cfg = appConfig();
    var raw = JSON.stringify({method:method, data:data || {token:''}, csrf:Date.now()});
    var encrypted = appEncrypt(raw);
    if (!encrypted) throw new Error('AppV7 encrypt empty');
    var headers = {
        'User-Agent': cfg.user_agent || 'Dart/3.11 (dart:io)', 'version':cfg.version || '',
        /* Do not set Accept-Encoding manually: Lanerc/OkHttp only transparently gunzips when it owns that header. */
        'version-number':cfg.version_number || '',
        'content-type':'text/plain', 'pk-id':cfg.pk_id || '', 'build-time':cfg.build_time || '',
        'platform':cfg.platform || 'android', 'platform-version':cfg.platform_version || 'TP1A.220624.014'
    };
    var response = postRaw(APP_API, encrypted, headers);
    var direct = json(response);
    if (direct && typeof direct === 'object') return direct;
    return json(appDecrypt(response)) || {};
}
function list(v) { if (Array.isArray(v)) return v; return v && Array.isArray(v.data) ? v.data : []; }
function navTypeName(id){var a=list(nav()),key=t(id);for(var i=0;i<a.length;i++){if(t((a[i]||{}).type_id)===key)return clean((a[i]||{}).type_name);}return '';}
function card(v) { v=v||{}; return {id:t(v.vod_id||v.id),name:clean(v.vod_name||v.name||v.title),pic:pic(v.vod_pic||v.pic||v.image),type:clean(v.type_name||v.vod_class||navTypeName(v.type_id)),year:t(v.vod_year||v.year),remarks:clean(v.vod_remarks||v.vod_state||v.remarks),desc:clean(v.vod_blurb||v.vod_content||v.desc)}; }
function cards(root) { var a=list(root), out=[]; for (var i=0;i<a.length;i++) { var c=card(a[i]); if(c.id&&c.name) out.push(c); } return out; }
function filters(name, title, raw) { var values=[{n:'全部',v:''}], seen={}, parts=t(raw).split(','); for(var i=0;i<parts.length;i++){var x=trim(parts[i]);if(x&&x!=='全部'&&!seen[x]){seen[x]=1;values.push({n:x,v:x});}} return values.length>1?{key:name,name:title,value:values}:null; }
function orderFilter(){return {key:'order',name:'排序',value:[{n:'全部',v:''},{n:'最新',v:'最新'},{n:'最热',v:'最热'},{n:'好评',v:'好评'}]};}
function nav() { if(!_avNav)_avNav=appCall('nav',{token:''}); return _avNav; }
function home(){if(!_avHome)_avHome=appCall('index_recommend',{token:''});return _avHome;}
function defaultTid() { var a=list(nav()); for(var i=0;i<a.length;i++){var id=(a[i]||{}).type_id;if(id!=null&&trim(id)!=='')return t(id);} return '1'; }
function isTid(v){var a=list(nav()),key=t(v);for(var i=0;i<a.length;i++)if(t((a[i]||{}).type_id)===key)return true;return false;}
function config() { return JSON.stringify({kind:'video',browseOnly:false,source:SOURCE_TITLE}); }
function categories() {
    try { var out=[{key:'',title:'推荐'}], a=list(nav()); for(var i=0;i<a.length;i++){var x=a[i]||{};if(t(x.type_id)==='58'||clean(x.type_name)==='直播')continue; var e=json(x.type_extend)||x.type_extend||{}, fs=[]; var f;
        f=filters('class','类型',e['class']);if(f)fs.push(f); f=filters('area','地区',e.area);if(f)fs.push(f); f=filters('lang','语言',e.lang);if(f)fs.push(f); f=filters('year','年份',e.year);if(f)fs.push(f); fs.push(orderFilter());
        var item={key:t(x.type_id),title:clean(x.type_name)};if(fs.length)item.filters=fs;out.push(item);} return JSON.stringify(out);
    } catch(e){return JSON.stringify([{key:'',title:'推荐'}]);}
}
function filterValue(v){v=trim(v);return v==='全部'?'':v;}
function videoList(tid,page,filtersObj){ filtersObj=filtersObj||{}; var order=filterValue(filtersObj.order);if(order==='评分')order='好评';return cards(appCall('video_list',{token:'',pg:Math.max(1,Number(page)||1),tid:Number(tid)||Number(defaultTid()),'class':filterValue(filtersObj['class']),area:filterValue(filtersObj.area),lang:filterValue(filtersObj.lang),year:filterValue(filtersObj.year),order:order})); }
function recommendationList(id){return cards(appCall('index_recommend_video_list',{token:'',recommend_id:Number(id)||0}));}
function recommendationKey(id){return '__dsx_recommend__:'+t(id);}
function uniqueCards(a){var out=[],seen={};for(var i=0;i<a.length;i++){var c=a[i]||{},k=t(c.id)+'|'+t(c.name)+'|'+t(c.pic);if(c.id&&c.name&&!seen[k]){seen[k]=1;out.push(c);}}return out;}
function homeSectionArray(){var root=home(),data=(root&&root.data)||{},sections=[],rows=Array.isArray(data.videos)?data.videos:[];for(var i=0;i<rows.length;i++){var x=rows[i]||{},title=clean(x.name),items=cards(x.vlist||x.videos||x.data||[]);if(!items.length)continue;if(title==='大师兄亲自推荐')items=items.slice(0,5);var displayTitle=title==='大师兄亲自推荐'?'推荐':title;var key='';if(Number(x.more_req_type)===2&&x.id!=null)key=recommendationKey(x.id);else if(x.type_id!=null&&t(x.type_id)!=='0')key=t(x.type_id);else if(x.id!=null)key=recommendationKey(x.id);sections.push({title:displayTitle||('推荐'+(i+1)),key:key,items:items});}var banners=cards(data.banners||[]);if(banners.length)sections.push({title:'精选推荐',key:'__hero__',items:banners});return sections;}
function homeSections(){try{return JSON.stringify(homeSectionArray());}catch(e){return '[]';}}
function homeCards(){var ss=homeSectionArray(),all=[];for(var i=0;i<ss.length;i++)for(var j=0;j<(ss[i].items||[]).length;j++)all.push(ss[i].items[j]);return uniqueCards(all);}
function search(keyword,page) { try { var q=trim(keyword),pg=Math.max(1,Number(page)||1),rp='__dsx_recommend__:';if(!q){if(pg>1)return '[]';var h=homeCards();return JSON.stringify(h);}if(q.indexOf(rp)===0)return JSON.stringify(recommendationList(q.substring(rp.length)));if(isTid(q))return JSON.stringify(videoList(q,pg,{}));return JSON.stringify(cards(appCall('search',{token:'',pg:pg,text:q}))); } catch(e){return '[]';} }
function searchFiltered(category,filtersJson,page){ try{return JSON.stringify(videoList(category,page,json(filtersJson)||{}));}catch(e){return '[]';} }
function pack(v){var x=b64e(JSON.stringify(v));return x?'av7:'+x:'av7u:'+enc(JSON.stringify(v));}
function unpack(v){v=t(v);try{if(v.indexOf('av7:')===0)return json(b64d(v.substring(4)))||{};if(v.indexOf('av7u:')===0)return json(decodeURIComponent(v.substring(5)))||{};}catch(e){}return{url:v};}
function detail(id) {
    var key=t(id); try { var cfg=appConfig(), result=appCall('video_detail',{token:'',id:Number(key)||0,sign_md5:cfg.sign_md5||'',apk_path:'/data/app/'+(cfg.pk_id||'')+'/base.apk',apk_length:Number(cfg.apk_length)||0});
        var data=result.data||{}, vod=data.vod_info||{}, lines=vod.vod_url_with_player||[], eps=[];
        for(var i=0;i<lines.length;i++){var line=lines[i]||{}, route=clean(line.name)||('线路'+(i+1)), groups=t(line.url).split('#');for(var j=0;j<groups.length;j++){var p=groups[j].indexOf('$'), n=p>=0?clean(groups[j].substring(0,p)):('第'+(j+1)+'集'),u=p>=0?groups[j].substring(p+1):groups[j];if(trim(u))eps.push({name:n,route:route,url:pack({code:t(line.code),url:trim(u),parse:t(line.parse_api),extra:t(line.extra_parse_api)})});}}
        return JSON.stringify({id:t(vod.vod_id||key),name:clean(vod.vod_name),pic:t(vod.vod_pic),desc:clean(vod.vod_content),type:clean(vod.type_name||vod.vod_class),year:t(vod.vod_year),area:clean(vod.vod_area),actor:clean(vod.vod_actor),director:clean(vod.vod_director),remarks:clean(vod.vod_remarks),episodes:eps});
    } catch(e){return JSON.stringify({id:key,name:'',pic:'',desc:'',episodes:[]});}
}
function parsedUrl(raw){var s=trim(raw),o=json(s),u='';if(o){u=t(o.url||(o.data&&o.data.url)||(typeof o.data==='string'?o.data:''));}else u=s;u=trim(u);/* Signed absolute URLs must keep their original percent-encoding. Only decode when the whole value is URL-encoded. */if(/^https?:\/\//i.test(u))return /^https?:\/\/[^\/?#]+\/?$/i.test(u)?'':u;if(u.indexOf('%')>=0){try{var decoded=decodeURIComponent(u.replace(/\+/g,'%2B'));if(/^https?:\/\//i.test(decoded))return decoded;}catch(e){}}return '';}
function parseBy(prefix,url){if(!prefix)return'';var raw=getRaw(prefix+url,{'User-Agent':appConfig().user_agent||'Dart/3.11 (dart:io)'}),found=parsedUrl(raw);if(found)return found;return parsedUrl(parseDecrypt(raw));}
function isLikelyMedia(url){return /(?:\.m3u8|\.mp4|\.flv|\.m4s|\.mpd)(?:$|[?#])/i.test(t(url))||/^data:application\/vnd\.apple\.mpegurl;base64,/i.test(t(url));}
function play(flag) { try { var p=unpack(flag), url=t(p.url); if(!p.parse&&!p.extra&&isLikelyMedia(url))return JSON.stringify({url:url,type:mediaType(url)});
        try{var secret=appCall('secret_parse_api_url',{token:'',url:url,player_code:t(p.code)}).data;if(secret)url=t(secret);}catch(ignore){}
        if(!p.parse&&!p.extra&&isLikelyMedia(url))return JSON.stringify({url:url,type:mediaType(url)});
        var finalUrl=parseBy(t(p.parse),url)||parseBy(t(p.extra),url);if(!finalUrl)return JSON.stringify({url:'',type:'auto'});
        return JSON.stringify({url:finalUrl,type:mediaType(finalUrl)});
    } catch(e){return JSON.stringify({url:'',type:'auto'});}
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
