// ============================================================================
// MiraPlay(catpaw) → OK影视/FongMi QuickJS 源  移植桥  shim v1
// 逆向自 /var/minis/shared/miraplay_v35_src22/src/*.js（22 源）
// ----------------------------------------------------------------------------
// 这批猫源的共同特征：
//   1) 契约: export default function createSpider(name, config) → api({get,post}) 路由, 返回**对象**
//   2) HTTP: 自带 _fh() → fetch(url,{...}) 优先, 退化到 __CAT_JS_UTIL["node:https"]
//   3) 加密: __CAT_JS_UTIL["crypto-js"] 的 CryptoJS(AES/MD5/SHA/mode/pad) + require("crypto")
//      (RSA publicEncrypt / X25519 generateKeyPairSync+diffieHellman / ECDH createECDH)
//   4) 压缩: require("zlib") 的 gunzipSync/inflateSync/inflateRawSync/brotliDecompressSync
//   5) 个别源用 Mc(mini_crypto) + mc_* 协议层（两个BT / 星影4K —— 本就是从 OK 包移植过去的）
//
// OK影视 宿主实际提供（已核实 FongMi/TV 源码 Global.java + Connect.java + http.js）：
//   req(url, opts)  **同步**（http.js 里 req = http(url, {async:false})）
//     opts: {method, headers, body, data, postType(json|form|form-data), buffer(0字符/1字节数组/2b64/3bytes),
//            charset, timeout, redirect, async:false}
//     返回 {code, headers, content}   ← code 是**数字**; 失败 {code:'', content:'', headers:{}}
//   md5X / aesX / desX / rsaX（Java 端, 无 GCM、无 SHA 系列）
//   setTimeout / clearTimeout / console / getPort / getProxy / js2Proxy / joinUrl / s2t / t2s / local.*
//   import { Crypto, cheerio, dayjs, ... } from 'assets://js/lib/cat.js'
//   ★ QuickJS **无** fetch / Buffer / URL / AbortController / atob / btoa / TextEncoder / Intl.BigInt 有
//
// 因此本 shim 的职责 = 在源文件顶部把上述「猫源依赖」全部补齐，让源体一个字节都不用改。
// 拼装顺序：  shim_head.js  +  源体(_fh 等原样)  +  adapter_tail.js
// ============================================================================
'use strict';

// ---- 0. 取壳自带 CryptoJS（cat.js 导出完整 CryptoJS；default 模式下需自己 import）----
// ⚠️ 若壳的 cat.js 不可用，退回内置纯 JS 实现（见 §6 的 __okCryptoJS 兜底）
var __OK_CATJS = null;
try {
  __OK_CATJS = (typeof globalThis !== 'undefined' && globalThis.Crypto) ? { Crypto: globalThis.Crypto } : null;
} catch (e) { __OK_CATJS = null; }

// ---- 1. Uint8Array/字节助手（QuickJS 有 Uint8Array，无 Buffer）----
function __okIsBytes(v) {
  return v && typeof v === 'object' && (v instanceof Uint8Array || v instanceof ArrayBuffer ||
    (typeof v.length === 'number' && typeof v !== 'string'));
}
function __okToArr(v) {
  if (v == null) return [];
  if (typeof v === 'string') { var a = [], i; for (i = 0; i < v.length; i++) a.push(v.charCodeAt(i) & 0xFF); return a; }
  if (v instanceof ArrayBuffer) return Array.prototype.slice.call(new Uint8Array(v));
  // ★ E-030: __OkBuffer 的索引 getter 只覆盖 0..255 —— 大于 256B 的缓冲区走 v[j] 会从 256 起全部取到 undefined→0
  //   （GCM 密文 >256B 被清零 → tag 校验失败）。必须直接读内部数组 _a。
  if (v._a && typeof v._a.length === 'number' && v.__isOkBuf) return v._a.slice();
  var out = [], j; for (j = 0; j < v.length; j++) out.push(v[j] & 0xFF); return out;
}
function __okUtf8Bytes(s) {
  s = String(s); var out = [], i, c;
  for (i = 0; i < s.length; i++) {
    c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xC0 | (c >> 6), 0x80 | (c & 63)); }
    else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.length) {
      var c2 = s.charCodeAt(i + 1);
      if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
        var cp = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00); i++;
        out.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      } else out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    } else { out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
  }
  return out;
}
function __okUtf8FromBytes(arr) {
  // ★ 分块 String.fromCharCode.apply（逐字符 += 是 O(n²)，QuickJS 上 169KB 要 6 秒）
  var s = '', i, chunk = [];
  function dec(u) {
    if (u < 0x80) return String.fromCharCode(u);
    if (u < 0x800) return String.fromCharCode(0xC0 | (u >> 6), 0x80 | (u & 63));
    return String.fromCharCode(0xE0 | (u >> 12), 0x80 | ((u >> 6) & 63), 0x80 | (u & 63));
  }
  for (i = 0; i < arr.length;) {
    var b = arr[i];
    if (b < 0x80) { chunk.push(b); i++; }
    else if (b >= 0xC0 && b < 0xE0 && i + 1 < arr.length) { chunk.push(((b & 31) << 6) | (arr[i + 1] & 63)); i += 2; }
    else if (b >= 0xE0 && b < 0xF0 && i + 2 < arr.length) { chunk.push(((b & 15) << 12) | ((arr[i + 1] & 63) << 6) | (arr[i + 2] & 63)); i += 3; }
    else if (b >= 0xF0 && i + 3 < arr.length) {
      var cp = ((b & 7) << 18) | ((arr[i + 1] & 63) << 12) | ((arr[i + 2] & 63) << 6) | (arr[i + 3] & 63);
      cp -= 0x10000; chunk.push(0xD800 + (cp >> 10), 0xDC00 + (cp & 1023)); i += 4;
    } else { chunk.push(b); i++; }
    if (chunk.length > 4096) { s += String.fromCharCode.apply(null, chunk); chunk = []; }
  }
  if (chunk.length) s += String.fromCharCode.apply(null, chunk);
  return s;
}
var __OK_B64T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function __okB64(bytes) {
  var out = '', i, n;
  for (i = 0; i + 2 < bytes.length; i += 3) {
    n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += __OK_B64T.charAt((n >> 18) & 63) + __OK_B64T.charAt((n >> 12) & 63) + __OK_B64T.charAt((n >> 6) & 63) + __OK_B64T.charAt(n & 63);
  }
  var rem = bytes.length - i;
  if (rem === 1) { n = bytes[i] << 16; out += __OK_B64T.charAt((n >> 18) & 63) + __OK_B64T.charAt((n >> 12) & 63) + '=='; }
  else if (rem === 2) { n = (bytes[i] << 16) | (bytes[i + 1] << 8); out += __OK_B64T.charAt((n >> 18) & 63) + __OK_B64T.charAt((n >> 12) & 63) + __OK_B64T.charAt((n >> 6) & 63) + '='; }
  return out;
}
function __okUnb64(s) {
  s = String(s || '').replace(/[-_]/g, function (m) { return m === '-' ? '+' : '/'; }).replace(/[^A-Za-z0-9+/=]/g, '');
  var out = [], buf = 0, bits = 0, i, c, v;
  for (i = 0; i < s.length; i++) {
    c = s.charAt(i); if (c === '=') break;
    v = __OK_B64T.indexOf(c); if (v < 0) continue;
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xFF); }
  }
  return out;
}

// ---- 2. Buffer 替身（源体大量使用 Buffer.from/alloc/concat/isBuffer/toString）----
function __OkBuffer(data, enc) {
  if (!(this instanceof __OkBuffer)) return new __OkBuffer(data, enc);
  var arr;
  if (data == null) arr = [];
  else if (typeof data === 'string') arr = (enc === 'base64' || enc === 'base64url') ? __okUnb64(data) : (enc === 'hex' ? __okHexToArr(data) : (enc === 'binary' || enc === 'latin1') ? __okLatinToArr(data) : __okUtf8Bytes(data));
  else if (data instanceof __OkBuffer) arr = data._a.slice();
  else arr = __okToArr(data);
  this._a = arr;
  this.length = arr.length;
}
__OkBuffer.from = function (d, e) { return new __OkBuffer(d, e); };
__OkBuffer.alloc = function (n, fill) { var a = [], i; for (i = 0; i < n; i++) a.push(fill == null ? 0 : (fill & 0xFF)); return new __OkBuffer(a); };
__OkBuffer.concat = function (list) { var out = [], i, j; for (i = 0; i < list.length; i++) { var a = list[i]._a || __okToArr(list[i]); for (j = 0; j < a.length; j++) out.push(a[j] & 0xFF); } return new __OkBuffer(out); };
__OkBuffer.isBuffer = function (v) { return v instanceof __OkBuffer; };
__OkBuffer.byteLength = function (s, e) { return (e === 'base64') ? __okUnb64(s).length : __okUtf8Bytes(s).length; };
__OkBuffer.prototype.toString = function (enc) {
  var a = this._a;
  if (enc === 'base64') return __okB64(a);
  if (enc === 'base64url') return __okB64(a).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (enc === 'hex') { var s = '', i; for (i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16); return s; }
  if (enc === 'binary' || enc === 'latin1') { var b = '', j; for (j = 0; j < a.length; j++) b += String.fromCharCode(a[j]); return b; }
  return __okUtf8FromBytes(a);
};
__OkBuffer.prototype.slice = function (s, e) { return new __OkBuffer(this._a.slice(s, e)); };
__OkBuffer.prototype.subarray = function (s, e) { return new __OkBuffer(this._a.slice(s, e)); };
__OkBuffer.prototype.toStringUTF16 = function () { return __okUtf8FromBytes(this._a); };
// 索引读写 + readUInt16BE / writeUInt16BE（4K影视 用）
Object.defineProperty(__OkBuffer.prototype, '__isOkBuf', { value: true });
(function () {
  var i;
  for (i = 0; i < 256; i++) {
    (function (idx) {
      Object.defineProperty(__OkBuffer.prototype, idx, {
        get: function () { return this._a[idx]; },
        set: function (v) { this._a[idx] = v & 0xFF; },
        configurable: true
      });
    })(i);
  }
})();
__OkBuffer.prototype.readUInt16BE = function (off) { return ((this._a[off] & 0xFF) << 8) | (this._a[off + 1] & 0xFF); };
__OkBuffer.prototype.writeUInt16BE = function (v, off) { this._a[off] = (v >> 8) & 0xFF; this._a[off + 1] = v & 0xFF; };
__OkBuffer.prototype.copy = function (target, tOff) { var i; for (i = 0; i < this._a.length; i++) target._a[tOff + i] = this._a[i]; return this._a.length; };
__OkBuffer.prototype.toJSON = function () { return { type: 'Buffer', data: this._a }; };
function __okHexToArr(s) { var out = [], i; s = String(s).replace(/[^0-9a-fA-F]/g, ''); for (i = 0; i + 1 < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16)); return out; }
function __okLatinToArr(s) { var a = [], i; s = String(s); for (i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xFF); return a; }
// 让 new Uint8Array(buffer) 拿到字节
__OkBuffer.prototype.valueOf = function () { return this._a; };
// 挂到全局（源体里裸 Buffer 必须能解析）
var Buffer = __OkBuffer;
try { globalThis.Buffer = __OkBuffer; } catch (e) { }

// atob / btoa（纯 JS）
function atob(s) { return __OK_B64T ? __okUtf8FromBytes(__okUnb64(String(s))) : ''; }
function btoa(s) { return __okB64(__okUtf8Bytes(String(s))); }
try { globalThis.atob = atob; globalThis.btoa = btoa; } catch (e) { }

// TextEncoder / TextDecoder
function TextEncoder() { }
TextEncoder.prototype.encode = function (s) { return new Uint8Array(__okUtf8Bytes(String(s))); };
function TextDecoder() { }
TextDecoder.prototype.decode = function (b) { return __okUtf8FromBytes(__okToArr(b)); };
try { globalThis.TextEncoder = TextEncoder; globalThis.TextDecoder = TextDecoder; } catch (e) { }


// ---- mini-crypto 纯 JS (来自 ok-video-source, 36/36 KAT; IIFE 防与源体撞名) ----
var __OK_MC = (function () {
function utf8Bytes(str) {
    str = String(str);
    var out = [], i = 0, c;
    while (i < str.length) {
      c = str.charCodeAt(i++);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) { out.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F)); }
      else if (c >= 0xD800 && c < 0xDC00 && i < str.length) {
        var c2 = str.charCodeAt(i++);
        c = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00);
        out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 0x3F), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
      } else { out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F)); }
    }
    return out;
  }
  function MC_toHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += ("0" + bytes[i].toString(16)).slice(-2);
    return s;
  }
  function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) | 0; }

  // ---------- MD5 (RFC 1321, 寄存器结构对齐 CryptoJS 4.x 实测) ----------
  var KMD5 = [], SMD5 = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  (function () {
    for (var i = 0; i < 64; i++) KMD5[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
  })();
  function MC_md5Bytes(msg) {
    var m = msg.slice(), L = m.length, j;
    m.push(0x80);
    while ((m.length % 64) !== 56) m.push(0);
    var bitLen = L * 8;
    m.push(bitLen % 0x100000000, (bitLen / 0x100000000) | 0, 0, 0, 0, 0, 0, 0);
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (var off = 0; off < m.length; off += 64) {
      var x = [];
      for (j = 0; j < 16; j++) x[j] = m[off + j * 4] | (m[off + j * 4 + 1] << 8) | (m[off + j * 4 + 2] << 16) | (m[off + j * 4 + 3] << 24);
      var a = a0, b = b0, c = c0, d = d0, g, A, B, C, D, F, idx, s, T;
      for (g = 0; g < 64; g++) {
        // 目标寄存器按 a,d,c,b 循环, F 参数为后续三个寄存器 (与 CryptoJS 宏序列一致)
        if ((g & 3) === 0) { A = a; B = b; C = c; D = d; }
        else if ((g & 3) === 1) { A = d; B = a; C = b; D = c; }
        else if ((g & 3) === 2) { A = c; B = d; C = a; D = b; }
        else { A = b; B = c; C = d; D = a; }
        if (g < 16) F = (B & C) | (~B & D);
        else if (g < 32) F = (B & D) | (C & ~D);
        else if (g < 48) F = B ^ C ^ D;
        else F = C ^ (B | ~D);
        idx = g < 16 ? g % 16 : g < 32 ? (5 * g + 1) % 16 : g < 48 ? (3 * g + 5) % 16 : (7 * g) % 16;
        s = SMD5[Math.floor(g / 16) * 4 + (g % 4)];
        T = rotl32((A + F + KMD5[g] + x[idx]) | 0, s) + B;
        if ((g & 3) === 0) a = T; else if ((g & 3) === 1) d = T; else if ((g & 3) === 2) c = T; else b = T;
      }
      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }
    var out = [];
    [a0, b0, c0, d0].forEach(function (w) { for (var s2 = 0; s2 < 4; s2++) out.push((w >>> (s2 * 8)) & 0xFF); });
    return out;
  }

  // ---------- SHA-1 (FIPS 180-1) ----------
  function MC_sha1Bytes(msg) {
    var m = msg.slice(), L = m.length;
    m.push(0x80);
    while ((m.length % 64) !== 56) m.push(0);
    var bitLen = L * 8;
    for (var i = 7; i >= 0; i--) m.push(((bitLen / Math.pow(256, i)) & 0xFF) || 0);
    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    var w = new Array(80);
    for (var off = 0; off < m.length; off += 64) {
      for (var t = 0; t < 16; t++) w[t] = m[off + t * 4] << 24 | m[off + t * 4 + 1] << 16 | m[off + t * 4 + 2] << 8 | m[off + t * 4 + 3];
      for (t = 16; t < 80; t++) w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (t = 0; t < 80; t++) {
        var f, k;
        if (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        var T = (rotl32(a, 5) + f + e + k + (w[t] | 0)) | 0;
        e = d; d = c; c = rotl32(b, 30); b = a; a = T;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    var out = [];
    [h0, h1, h2, h3, h4].forEach(function (w2) { for (var s = 0; s < 4; s++) out.push((w2 >>> (24 - s * 8)) & 0xFF); });
    return out;
  }

  // ---------- SHA-256 (FIPS 180-4) ----------
  var K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  function MC_sha256Bytes(msg) {
    var m = msg.slice(), L = m.length;
    m.push(0x80);
    while ((m.length % 64) !== 56) m.push(0);
    var bitLen = L * 8;
    for (var i = 7; i >= 0; i--) m.push(((bitLen / Math.pow(256, i)) & 0xFF) || 0);
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64);
    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) | 0; }
    for (var off = 0; off < m.length; off += 64) {
      for (var t = 0; t < 16; t++) w[t] = m[off + t * 4] << 24 | m[off + t * 4 + 1] << 16 | m[off + t * 4 + 2] << 8 | m[off + t * 4 + 3];
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], gg = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & gg);
        var T1 = (hh + S1 + ch + K256[t] + (w[t] | 0)) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var T2 = (S0 + maj) | 0;
        hh = gg; gg = f; f = e; e = (d + T1) | 0; d = c; c = b; b = a; a = (T1 + T2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + gg) | 0; h[7] = (h[7] + hh) | 0;
    }
    var out = [];
    for (var s2 = 0; s2 < 8; s2++) out.push((h[s2] >>> 24) & 0xFF, (h[s2] >>> 16) & 0xFF, (h[s2] >>> 8) & 0xFF, h[s2] & 0xFF);
    return out;
  }

  function MC_hmacSha256Bytes(key, msg) {
    var kb = key.length > 64 ? MC_sha256Bytes(key) : key.slice();
    var iKey = [], oKey = [];
    for (var i = 0; i < 64; i++) { iKey.push((kb[i] | 0) ^ 0x36); oKey.push((kb[i] | 0) ^ 0x5c); }
    return MC_sha256Bytes(oKey.concat(MC_sha256Bytes(iKey.concat(msg))));
  }

  
return {
  md5: function (m) { return MC_toHex(MC_md5Bytes(m)); },
  sha1: function (m) { return MC_toHex(MC_sha1Bytes(m)); },
  sha256: function (m) { return MC_toHex(MC_sha256Bytes(m)); },
  hmac256: function (k, m) { return MC_toHex(MC_hmacSha256Bytes(k, m)); }
};
})();
function __OK_MC_MD5(m) { return __OK_MC.md5(m); }
function __OK_MC_SHA1(m) { return __OK_MC.sha1(m); }
function __OK_MC_SHA256(m) { return __OK_MC.sha256(m); }
function __OK_MC_HMAC256(k, m) { return __OK_MC.hmac256(k, m); }


// 提取自历史 OK 源 /tmp/pkg_4kapp.js (tweetnacl 提取, RFC7748 KAT 通过, 见技能 ok-video-source)
// API: X25519.pub(priv32) → 32B array | X25519.shared(priv32, peerPub32) → 32B array (字节序=RFC7748 小端, 与 Go/Node 互操作)
// KAT: RFC 7748 §6.1 官方向量 + 200 随机对 vs Node crypto.diffieHellman (双向)
var X25519 = (function () {
  var gf = function(init) {
    var i, r = new Float64Array(16);
    if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };
  var _9 = new Uint8Array(32); _9[0] = 9;
  var _121665 = gf([0xdb41, 1]);

  function car25519(o) {
    var c, i;
    for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i+1)*(i<15?1:0)] += c - 1 + 37 * (c-1) * (i===15?1:0);
      o[i] -= (c * 65536);
    }
  }
  function sel25519(p, q, b) {
    var t, c = ~(b-1);
    for (var i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }
  function pack25519(o, n) {
    var i, j, b;
    var m = gf(), t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
        m[i-1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
      b = (m[15]>>16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1-b);
    }
    for (i = 0; i < 16; i++) { o[2*i] = t[i] & 0xff; o[2*i+1] = t[i]>>8; }
  }
  function unpack25519(o, n) {
    for (var i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
    o[15] &= 0x7fff;
  }
  function A(o, a, b) { for (var i = 0; i < 16; i++) o[i] = (a[i] + b[i])|0; }
  function Z(o, a, b) { for (var i = 0; i < 16; i++) o[i] = (a[i] - b[i])|0; }
  function M(o, a, b) {
    var i, j, t = new Float64Array(31);
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i+j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i+16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
  }
  function S(o, a) { M(o, a, a); }
  function inv25519(o, i) {
    var c = gf(), a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
      S(c, c);
      if (a !== 2 && a !== 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }
  function scalarmult(q, n, p) {
    var z = new Uint8Array(32);
    var x = new Float64Array(80), r, i;
    var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
    for (i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31]&127)|64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; i++) { b[i]=x[i]; d[i]=a[i]=c[i]=0; }
    a[0]=d[0]=1;
    for (i=254; i>=0; --i) {
      r = (z[i>>>3]>>>(i&7))&1;
      sel25519(a,b,r); sel25519(c,d,r);
      A(e,a,c); Z(a,a,c); A(c,b,d); Z(b,b,d);
      S(d,e); S(f,a); M(a,c,a); M(c,b,e);
      A(e,a,c); Z(a,a,c); S(b,a); Z(c,d,f);
      M(a,c,_121665); A(a,a,d); M(c,c,a);
      M(a,d,f); M(d,b,x); S(b,e);
      sel25519(a,b,r); sel25519(c,d,r);
    }
    for (i = 0; i < 16; i++) { x[i+16]=a[i]; x[i+32]=c[i]; x[i+48]=b[i]; x[i+64]=d[i]; }
    var x32 = x.subarray(32), x16 = x.subarray(16);
    inv25519(x32, x32);
    M(x16, x16, x32);
    pack25519(q, x16);
    return 0;
  }
  function toArr(buf) { var a = new Array(buf.length); for (var i=0;i<buf.length;i++) a[i] = buf[i]; return a; }
  return {
    // priv: 32 字节数组(小端标量). 返回 32 字节数组
    pub: function (priv32) {
      var q = new Uint8Array(32);
      scalarmult(q, toArr(priv32), _9);
      return toArr(q);
    },
    shared: function (priv32, peerPub32) {
      var q = new Uint8Array(32);
      scalarmult(q, toArr(priv32), toArr(peerPub32));
      return toArr(q);
    },
    rand32: function () { var a = new Array(32); for (var i=0;i<32;i++) a[i] = Math.floor(Math.random()*256); return a; }
  };
})();


function __ek_b64ToBuf(s) {
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
function __ek_bufToB64(arr) {
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
function __ek_bufToHex(arr) { var s = ''; for (var i = 0; i < arr.length; i++) { s += (arr[i] < 16 ? '0' : '') + arr[i].toString(16); } return s; }
function __ek_hexToBuf(s) { var out = []; s = String(s).replace(/[^0-9a-fA-F]/g, ''); for (var i = 0; i + 1 < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16)); return out; }
function __ek_utf8FromBytes(arr) {
    var s = '', i = 0;
    while (i < arr.length) {
        var b = arr[i];
        if (b < 0x80) { s += String.fromCharCode(b); i++; }
        else if (b < 0xE0) { s += String.fromCharCode(((b & 31) << 6) | (arr[i + 1] & 63)); i += 2; }
        else if (b < 0xF0) { s += String.fromCharCode(((b & 15) << 12) | ((arr[i + 1] & 63) << 6) | ((arr[i + 2] & 63))); i += 3; }
        else { var cp = ((b & 7) << 18) | ((arr[i + 1] & 63) << 12) | ((arr[i + 2] & 63) << 6) | ((arr[i + 3] & 63)); cp -= 0x10000; s += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 1023)); i += 4; }
    }
    return s;
}
function __ek_utf8Bytes(s) {
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
var __gcm = (function () {
    /* SBOX: 直接移植 crypto-js 的 GF(2^8) 增量遍历 (久经考验):
       sx = xi ^ xi<<1 ^ xi<<2 ^ xi<<3 ^ xi<<4; sbox[x] = fold4(sx) ^ 0x63
       (fold4 = 高 4 位折回异或; 注意不是"循环左移"也不是域倍乘) */
    var SBOX = (function () {
        var d = new Array(256), i;
        for (i = 0; i < 256; i++) d[i] = (i << 1) ^ ((i & 0x80) ? 0x11B : 0);
        var s = new Array(256), x = 0, xi = 0;
        for (i = 0; i < 256; i++) {
            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
            s[x] = ((sx >>> 8) ^ (sx & 0xFF)) ^ 0x63;
            if (!x) { x = xi = 1; }
            else {
                var x2 = d[x], x4 = d[x2], x8 = d[x4];
                x = x2 ^ d[d[d[x8 ^ x2]]];
                xi ^= d[d[xi]];
            }
        }
        return s;
    })();
    function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x11B : 0)) & 0xFF; }
    function gmul(a, b) { var x = 0; for (var i = 0; i < 8; i++) { if (b & 1) x ^= a; a = xtime(a); b >>>= 1; } return x; }
    function keyExpand(keyB) {
        var Nk = keyB.length / 4, Nr = Nk + 6, W = [], i; // Nk = 32位字数 (16B→4, 32B→8)
        for (i = 0; i < Nk; i++) W.push([keyB[i * 4], keyB[i * 4 + 1], keyB[i * 4 + 2], keyB[i * 4 + 3]]);
        var rcon = 1;
        for (i = Nk; i < 4 * (Nr + 1); i++) {
            var T = W[i - 1].slice();
            if (i % Nk === 0) {
                var u = T[0];
                T = [SBOX[T[1]] ^ rcon, SBOX[T[2]], SBOX[T[3]], SBOX[u]];
                rcon = xtime(rcon);
            } else if (Nk > 6 && i % Nk === 4) {
                T = [SBOX[T[0]], SBOX[T[1]], SBOX[T[2]], SBOX[T[3]]];
            }
            W.push([W[i - Nk][0] ^ T[0], W[i - Nk][1] ^ T[1], W[i - Nk][2] ^ T[2], W[i - Nk][3] ^ T[3]]);
        }
        return { W: W, Nr: Nr };
    }
    function blockEnc(b, K) { // 只需求 AES 加密方向的单块 (GCTR/GHASH 都只用 E)
        var s = b.slice(), i, r, c, Nk = K.W.length / (K.Nr + 1), Nr = K.Nr;
        // AddRoundKey: FIPS-197 state[r][c] ^= W[round*Nk+c][r]; 输入字节 i: row=i&3, col=i>>2
        for (i = 0; i < 16; i++) s[i] ^= K.W[i >> 2][i & 3];
        for (r = 1; r <= Nr; r++) {
            for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
            // ShiftRows: 第 r 行循环左移 r 字节 → new[c] = old[(c+r) mod 4]
            var t;
            t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            var a = s[2], b2 = s[6], c2 = s[10], d2 = s[14]; s[2] = c2; s[6] = d2; s[10] = a; s[14] = b2;
            t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
            if (r < Nr) {
                for (c = 0; c < 4; c++) {
                    var x0 = s[4 * c], x1 = s[4 * c + 1], x2 = s[4 * c + 2], x3 = s[4 * c + 3];
                    s[4 * c] = gmul(x0, 2) ^ gmul(x1, 3) ^ x2 ^ x3;
                    s[4 * c + 1] = x0 ^ gmul(x1, 2) ^ gmul(x2, 3) ^ x3;
                    s[4 * c + 2] = x0 ^ x1 ^ gmul(x2, 2) ^ gmul(x3, 3);
                    s[4 * c + 3] = gmul(x0, 3) ^ x1 ^ x2 ^ gmul(x3, 2);
                }
            }
            for (i = 0; i < 16; i++) s[i] ^= K.W[r * Nk + (i >> 2)][i & 3];
        }
        return s;
    }
    function gctrXor(K, iv12, data, startCtr) {
        var out = new Array(data.length), i, j;
        for (i = 0; i < data.length; i += 16) {
            var ctr = startCtr + (i / 16);
            var cb = iv12.concat([((ctr >>> 24) & 255), ((ctr >>> 16) & 255), ((ctr >>> 8) & 255), (ctr & 255)]);
            var ks = blockEnc(cb, K);
            for (j = 0; j < 16 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
        }
        return out;
    }
    /* GCM GF(2^128) 乘法 (反射约定, 与 OpenSSL/pycryptodome 实测一致):
       α = 右移 1 位 (bit0(字节i-1) → bit7(字节i)), 原 LSB=1 时顶字节 ^0xE1
       T[k] = H·α^k; gmult(X) = XOR 各置位 bit(自 MSB 起第 p 位) 的 T[p] */
    function xtimeR(B) {
        var out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], i, v;
        for (i = 0; i < 16; i++) {
            v = B[i] >> 1;
            if (i > 0) v |= ((B[i - 1] & 1) << 7);
            out[i] = v;
        }
        if (B[15] & 1) out[0] ^= 0xE1;
        return out;
    }
    function makeHtab(H) {
        var T = [H.slice()], k;
        for (k = 1; k < 128; k++) T.push(xtimeR(T[k - 1]));
        return T;
    }
    function gmultTab(X, T) {
        var Z = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], i, j, p, u;
        for (i = 0; i < 16; i++) {
            var b = X[i];
            for (j = 0; j < 8; j++) {
                if (b & (0x80 >> j)) {
                    p = 8 * i + j;
                    for (u = 0; u < 16; u++) Z[u] ^= T[p][u];
                }
            }
        }
        return Z;
    }
    /* 通用 GHASH (支持 aad + 任意 iv 长度; 长度块: 高 64 位 = aadBits, 低 64 位 = dataBits,
       均为位长(字节×8), 各 < 2^32。NIST SP800-38D §6 / OpenSSL 实测一致) */
    function ghashBlocks(T, aadB, dataB, aadBits, dataBits) {
        var Y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], i, j, len;
        len = aadB.length;
        for (i = 0; i < len; i += 16) {
            var block = [];
            for (j = 0; j < 16; j++) block.push(i + j < len ? aadB[i + j] : 0);
            for (j = 0; j < 16; j++) Y[j] ^= block[j];
            Y = gmultTab(Y, T);
        }
        len = dataB.length;
        for (i = 0; i < len; i += 16) {
            var block2 = [];
            for (j = 0; j < 16; j++) block2.push(i + j < len ? dataB[i + j] : 0);
            for (j = 0; j < 16; j++) Y[j] ^= block2[j];
            Y = gmultTab(Y, T);
        }
        if (aadBits > 0xFFFFFFFF || dataBits > 0xFFFFFFFF) throw new Error('GCM 长度超过 2^32 位');
        var L = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        /* 128 位长度字段 (big-endian): 前 64 位 = aad*8 (常用范围放字节 4-7), 后 64 位 = data*8 (字节 12-15) */
        L[4] = (aadBits >>> 24) & 255; L[5] = (aadBits >>> 16) & 255; L[6] = (aadBits >>> 8) & 255; L[7] = aadBits & 255;
        L[12] = (dataBits >>> 24) & 255; L[13] = (dataBits >>> 16) & 255; L[14] = (dataBits >>> 8) & 255; L[15] = dataBits & 255;
        for (j = 0; j < 16; j++) Y[j] ^= L[j];
        Y = gmultTab(Y, T);
        return Y;
    }
    function prep(input, key, o) {
        var keyB = (o.keyFormat === 'hex') ? __ek_hexToBuf(String(key)) : __ek_utf8Bytes(String(key));
        if (keyB.length !== 16 && keyB.length !== 32) throw new Error('GCM 密钥长度必须是 16/32 字节');
        var ivB = o.iv ? ((o.ivFormat === 'hex') ? __ek_hexToBuf(String(o.iv)) : __ek_utf8Bytes(String(o.iv))) : [];
        var dataB;
        if (o.input === 'hex') dataB = __ek_hexToBuf(String(input));
        else if (o.input === 'base64') dataB = __ek_b64ToBuf(String(input));
        else dataB = __ek_utf8Bytes(String(input));
        var aadB = [];
        if (o.aad) aadB = ((o.aadFormat === 'hex') ? __ek_hexToBuf(String(o.aad)) : ((o.aadFormat === 'base64') ? __ek_b64ToBuf(String(o.aad)) : __ek_utf8Bytes(String(o.aad))));
        return { keyB: keyB, ivB: ivB, dataB: dataB, aadB: aadB };
    }
    function gcmCore(keyB, ivB, pt, encrypt, aadB) {
        aadB = aadB || [];
        var K = keyExpand(keyB), iv12, dataCtr, tagCtr, i;
        var H = blockEnc([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], K);
        var T = makeHtab(H);
        /* 计数约定 (NIST SP800-38D 的 GCTR1/GCTR2, 与 OpenSSL 实测一致):
           12B IV: J0 = iv||0^31||1, 数据首块 E(J0+1), tag 块 E(J0)
           其他: J0 = GHASH_H(IV 零填充 || [0^64 || iv位长]), 数据从 J0+1 起计数 */
        if (ivB.length === 12) { iv12 = ivB; dataCtr = 2; tagCtr = 1; }
        else {
            var J0 = ghashBlocks(T, ivB, [], 0, ivB.length * 8);
            iv12 = J0.slice(0, 12);
            var baseCtr = ((J0[12] << 24 | J0[13] << 16 | J0[14] << 8 | J0[15]) >>> 0);
            dataCtr = (baseCtr + 1) >>> 0; tagCtr = baseCtr;
        }
        var ct, out;
        if (encrypt) {
            ct = gctrXor(K, iv12, pt, dataCtr);
            out = ct;
        } else {
            ct = pt;
            out = gctrXor(K, iv12, pt, dataCtr);
        }
        /* GHASH 输入 = aad 块 + 密文块 + 长度块 (GHASH 永远作用于密文, 不是 ct^pt!) */
        var S = ghashBlocks(T, aadB, ct, aadB.length * 8, ct.length * 8);
        var t0 = gctrXor(K, iv12, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], tagCtr);
        var tagCalc = [];
        for (i = 0; i < 16; i++) tagCalc.push(t0[i] ^ S[i]);
        return { out: out, tag: tagCalc };
    }
    return {
        /* input = cipher||tag (末尾 tagLen/8 字节为 tag); 返回明文, output: utf8(默认)|hex|base64 */
        decrypt: function (input, key, o) {
            o = o || {};
            var p = prep(input, key, o);
            var tagLen = (o.tagLen || 128) >> 3;
            if (p.dataB.length < tagLen) throw new Error('GCM 数据过短');
            var tag = p.dataB.slice(p.dataB.length - tagLen);
            var ct = p.dataB.slice(0, p.dataB.length - tagLen);
            var r = gcmCore(p.keyB, p.ivB, ct, false, p.aadB);
            for (var i = 0; i < tagLen; i++) { if (tag[i] !== r.tag[i]) throw new Error('GCM tag 校验失败'); }
            var outB = r.out;
            if (o.output === 'hex') return __ek_bufToHex(outB);
            if (o.output === 'base64') return __ek_bufToB64(outB);
            return __ek_utf8FromBytes(outB);
        },
        /* input = 明文; 返回 cipher||(截断 tag), output: hex(默认)|base64|utf8 */
        encrypt: function (input, key, o) {
            o = o || {};
            var p = prep(input, key, o);
            var tagLen = (o.tagLen || 128) >> 3;
            var r = gcmCore(p.keyB, p.ivB, p.dataB, true, p.aadB);
            var all = r.out.concat(r.tag.slice(0, tagLen));
            if (o.output === 'base64') return __ek_bufToB64(all);
            if (o.output === 'utf8') return __ek_utf8FromBytes(all);
            return __ek_bufToHex(all);
        }
    };
})();

var __rsaJS = (function () {
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
        return __ek_b64ToBuf(rows.join(''));
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
                var hex = __ek_bufToHex(v);
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
        var inner = bit.body.slice(1);                             // 去掉 unused-bits
        var seq = derFind(inner, 0, inner.length, 0x30);
        var ints = intsFromSeq(seq.body);
        return { n: ints[0], e: ints[1] || 65537n, k: (ints[0].toString(16).length + 1) >> 1 };
    }
    function parsePrivateKey(pem) {
        var der = pemBody(pem);
        var top = derFind(der, 0, der.length, 0x30);              // PKCS#8 外层
        var oct = derFind(top.body, 0, top.body.length, 0x04);    // OCTET STRING (PKCS#1)
        var seq = derFind(oct.body, 0, oct.body.length, 0x30);
        var ints = intsFromSeq(seq.body);                          // [ver, n, e, d, p, q, ...]
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
        var arr = __ek_hexToBuf(hex);
        while (arr.length < k) arr.unshift(0);
        return arr.slice(-k);
    }
    function os2ip(arr) { return BigInt('0x' + (__ek_bufToHex(arr) || '0')); }
    return {
        encrypt: function (plain, pem, o) {
            o = o || {};
            var key = parsePublicKey(pem), msg = [], i;
            if (o.input === 'hex') msg = __ek_hexToBuf(plain);
            else if (o.input === 'base64') msg = __ek_b64ToBuf(plain);
            else msg = __ek_utf8Bytes(String(plain));
            var k = key.k, chunk = k - 11;
            var out = [];
            for (i = 0; i < msg.length; i += chunk) {
                /* 明文按 k-11 分块, 每块独立 PKCS1 v1.5 加密 (瓜子/ AppV7 的多块密钥传输) */
                var piece = msg.slice(i, i + chunk);
                var ps = [];
                while (ps.length < k - 3 - piece.length) { var r = Math.floor(Math.random() * 255) + 1; ps.push(r); }
                var m = [0].concat([2], ps, [0], piece);
                out = out.concat(bytesOf(modPow(os2ip(m), key.e, key.n), k));
            }
            if (o.output === 'hex') return __ek_bufToHex(out);
            return __ek_bufToB64(out);
        },
        decrypt: function (data, pem, o) {
            o = o || {};
            var key = parsePrivateKey(pem), arr;
            if (o.input === 'hex') arr = __ek_hexToBuf(data);
            else arr = __ek_b64ToBuf(data);
            var k = key.k, out = [];
            for (var i = 0; i + k <= arr.length; i += k) {
                /* 密文按 k 字节分块, 逐块解 + 逐块 unpad, 明文拼接 */
                var m = bytesOf(modPow(os2ip(arr.slice(i, i + k)), key.d, key.n), k);
                if (m[0] === 0 && (m[1] === 2 || m[1] === 1)) {
                    var idx = m.indexOf(0, 2);
                    if (idx > 2) m = m.slice(idx + 1);
                }
                out = out.concat(m);
            }
            if (o.output === 'hex') return __ek_bufToHex(out);
            if (o.output === 'base64') return __ek_bufToB64(out);
            return __ek_utf8FromBytes(out);
        }
    };
})();

// ============================================================================
// shim/p256ecdh.js — 纯 JS secp256r1/prime256v1 ECDH（咕噜 握手用）
// 无 BigInt / 无 Buffer 依赖：256 位数用 16 个 16-bit limb（小端）表示。
// 模约减：2^256 ≡ T (mod p), T = 2^256 - p → 迭代折叠高位（每轮砍 ~31 bit）。
// 点运算：Jacobian 坐标（dbl-2001-b / add-2007-bl, a=-3）。
// KAT：与 Node crypto.createECDH('prime256v1') 对拍（test/p256_kat.mjs）。
// ============================================================================
var __OK_P256 = (function () {
  'use strict';
  var N = 16;                                   // limb 数（16×16bit = 256bit）

  function limbs(n) { var a = [], i; for (i = 0; i < n; i++) a.push(0); return a; }

  // ---- 大端字节(32B) ↔ limb ----
  function fromBE(b) {                          // b: 字节数组(大端, 任意长 ≤32)
    var a = limbs(N), i, j;
    for (i = 0; i < 32; i++) {
      j = 31 - i;
      if (j < b.length) a[i >> 1] |= (b[j] & 0xFF) << ((i & 1) * 8);
    }
    return a;
  }
  function toBE(a) {                            // → 32 字节大端
    var o = [], i;
    for (i = 31; i >= 0; i--) o.push((a[i >> 1] >> ((i & 1) * 8)) & 0xFF);
    return o;
  }

  // ---- 常量 ----
  function hexLimbs(h) {                        // 大端 hex → limb 小端
    var s = '', i; for (i = 0; i < 64 - h.length; i++) s += '0';
    s += h;
    var a = [], k;
    for (k = 60; k >= 0; k -= 4) a.push(parseInt(s.substr(k, 4), 16));
    return a;
  }
  var P  = hexLimbs('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
  var B  = hexLimbs('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
  var GX = hexLimbs('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
  var GY = hexLimbs('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
  var ONE = limbs(N); ONE[0] = 1;
  // T = 2^256 - p = 2^224 - 2^192 - 2^96 + 1
  var TH = '00000000fffffffeffffffffffffffffffffffff000000000000000000000001';
  var T = hexLimbs(TH);

  // ---- 基础运算（数组长度可变, 高位在尾部） ----
  function trim(a) { var r = a.slice(); while (r.length > 1 && r[r.length - 1] === 0) r.pop(); return r; }
  function cmp(a, b) {
    a = trim(a); b = trim(b);
    if (a.length !== b.length) return a.length < b.length ? -1 : 1;
    var i;
    for (i = a.length - 1; i >= 0; i--) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
    return 0;
  }
  function add(a, b) {
    var n = Math.max(a.length, b.length), r = limbs(n + 1), i, c = 0, v;
    for (i = 0; i < n; i++) {
      v = c + (a[i] || 0) + (b[i] || 0);
      r[i] = v & 0xFFFF; c = v >> 16;
    }
    r[n] = c;
    return trim(r);
  }
  function sub(a, b) {                          // 要求 a >= b
    var r = a.slice(), i, borrow = 0, v;
    for (i = 0; i < r.length; i++) {
      v = r[i] - borrow - (b[i] || 0);
      if (v < 0) { v += 0x10000; borrow = 1; } else borrow = 0;
      r[i] = v;
    }
    if (borrow) throw new Error('P256 sub underflow');
    return trim(r);
  }
  function mul(a, b) {
    var r = limbs(a.length + b.length), i, j, v, c;
    for (i = 0; i < a.length; i++) {
      if (!a[i]) continue;
      c = 0;
      for (j = 0; j < b.length; j++) {
        v = r[i + j] + a[i] * b[j] + c;
        r[i + j] = v & 0xFFFF;
        c = Math.floor(v / 0x10000);
      }
      var k = i + b.length;
      while (c) { v = r[k] + c; r[k] = v & 0xFFFF; c = Math.floor(v / 0x10000); k++; }
    }
    return trim(r);
  }

  // ---- mod p：迭代折叠（2^256 ≡ T） ----
  function modP(c) {
    c = c.slice();
    while (c.length > N) {
      var lo = c.slice(0, N), hi = c.slice(N);
      c = add(lo, mul(hi, T));                  // c ≡ lo + hi*T (mod p)
    }
    while (cmp(c, P) >= 0) c = sub(c, P);
    var r = limbs(N), i;
    for (i = 0; i < c.length; i++) r[i] = c[i];
    return r;
  }
  function fadd(a, b) { return modP(add(a, b)); }
  function fsub(a, b) { return cmp(a, b) >= 0 ? modP(sub(a, b)) : modP(sub(add(a, P), b)); }
  function fmul(a, b) { return modP(mul(a, b)); }
  function fsq(a) { return fmul(a, a); }
  function isZero(a) { for (var i = 0; i < a.length; i++) if (a[i]) return false; return true; }

  // ---- 逆元: a^(p-2) ----
  function inv(a) {
    var e = P.slice();                          // p-2：p 是奇数, 低 2 bit=11 → p-2 低 limb 减 2
    e[0] = (e[0] - 2) & 0xFFFF;                 // p ≡ ...ff → 不借位
    var r = ONE.slice(), b = a.slice(), i, bit, w;
    for (i = 0; i < N; i++) {
      w = e[i];
      for (bit = 0; bit < 16; bit++) {
        if ((w >> bit) & 1) r = fmul(r, b);
        b = fsq(b);
      }
    }
    return r;
  }

  // ---- Jacobian 点 ----
  // dbl-2001-b (a=-3): delta=Z^2 gamma=Y^2 beta=X*gamma alpha=3(X-delta)(X+delta)
  function pdbl(pt) {
    if (isZero(pt[2])) return pt;
    var X = pt[0], Y = pt[1], Z = pt[2];
    var delta = fsq(Z), gamma = fsq(Y), beta = fmul(X, gamma);
    var t1 = fsub(X, delta), t2 = fadd(X, delta);
    var alpha = fmul(t1, t2); alpha = fadd(alpha, fadd(alpha, alpha));   // 3*t1*t2
    var g2 = fsq(gamma), g4 = fadd(g2, g2), g8 = fadd(g4, g4);      // g8 = 4*gamma^2
    var b2 = fadd(beta, beta), b4 = fadd(b2, b2), b8 = fadd(b4, b4); // b8 = 8*beta
    var X3 = fsub(fsq(alpha), b8);                                   // alpha^2 - 8*beta
    var Z3 = fsub(fsub(fsq(fadd(Y, Z)), gamma), delta);              // (Y+Z)^2 - gamma - delta
    var Y3 = fsub(fmul(alpha, fsub(b4, X3)), fadd(g8, g8));         // alpha*(4beta - X3) - 8*gamma^2
    return [X3, Y3, Z3];
  }
  // add-2007-bl
  function padd(p1, p2) {
    if (isZero(p1[2])) return p2;
    if (isZero(p2[2])) return p1;
    var Z1 = p1[2], Z2 = p2[2];
    var z1z1 = fsq(Z1), z2z2 = fsq(Z2);
    var U1 = fmul(p1[0], z2z2), U2 = fmul(p2[0], z1z1);
    var S1 = fmul(fmul(p1[1], Z2), z2z2), S2 = fmul(fmul(p2[1], Z1), z1z1);
    var H = fsub(U2, U1), R = fsub(S2, S1);
    if (isZero(H)) {
      if (isZero(R)) return pdbl(p1);
      return [ONE, ONE, limbs(N)];              // 无穷远点 (z=0)
    }
    var HH = fsq(H), HHH = fmul(H, HH);
    var V = fmul(U1, HH);
    var X3 = fsub(fsq(R), fadd(HHH, fadd(V, V)));
    var Y3 = fsub(fmul(R, fsub(V, X3)), fmul(S1, HHH));
    var Z3 = fmul(fmul(Z1, Z2), H);
    return [X3, Y3, Z3];
  }
  function toAffine(pt) {
    if (isZero(pt[2])) return null;
    var zi = inv(pt[2]), zi2 = fsq(zi), zi3 = fmul(zi2, zi);
    return [fmul(pt[0], zi2), fmul(pt[1], zi3)];
  }
  function mulG(k) {                            // k: limb
    var r = [ONE, ONE, limbs(N)], i, bit, w;
    for (i = N - 1; i >= 0; i--) {
      w = k[i];
      for (bit = 15; bit >= 0; bit--) {
        r = pdbl(r);
        if ((w >> bit) & 1) r = padd(r, [GX, GY, ONE]);
      }
    }
    return r;
  }
  // ---- p ≡ 3 (mod 4): sqrt(w) = w^((p+1)/4) mod p，用于 33B 压缩公钥解压缩 ----
  // (p+1)/4 为精确常数（node 验证 4·((p+1)/4)-1 == p）
  var P1Q4 = hexLimbs('3fffffffc0000000400000000000000000000000400000000000000000000000');
  function sqrtModP(w) {
    if (isZero(w)) return w;
    // r = w^P1Q4 mod p —— 经典 left-to-right（MSB→LSB）平方乘。
    // P-256 的 p ≡ 3 (mod 4)，故 QR 的平方根 = w^((p+1)/4) mod p。
    var r = ONE.slice(), i, bit;
    for (i = N - 1; i >= 0; i--) {
      for (bit = 15; bit >= 0; bit--) {
        r = fsq(r);
        if ((P1Q4[i] >> bit) & 1) r = fmul(r, w);
      }
    }
    return r;
  }
  // y² = x³ - 3x + B；奇偶不符则取 p-y
  function decompressY(px, odd) {
    var w = fsub(fadd(fmul(fsq(px), px), B), fadd(px, fadd(px, px))); // x³ + B - 3x
    var y = sqrtModP(w);
    if (cmp(fsq(y), w) !== 0) return null;                       // 非平方剩余 → 无效点
    if ((y[0] & 1) !== odd) y = fsub(P, y);      // 奇偶不符取 p-y（数值严格比较, 旧版 ===!() 恒假）
    return y;
  }

  function mulPoint(k, px, py) {
    var r = [ONE, ONE, limbs(N)], Q = [px, py, ONE], i, bit, w;
    for (i = N - 1; i >= 0; i--) {
      w = k[i];
      for (bit = 15; bit >= 0; bit--) {
        r = pdbl(r);
        if ((w >> bit) & 1) r = padd(r, Q);
      }
    }
    return r;
  }
  function onCurve(x, y) {
    // y^2 = x^3 - 3x + b
    var lhs = fsq(y);
    var x3 = fmul(fsq(x), x);
    var rhs = fsub(fadd(x3, B), fadd(x, fadd(x, x)));
    return cmp(lhs, rhs) === 0;
  }

  // ---- 随机 ----
  function rand32(randFn) {
    var b = [], i;
    for (i = 0; i < 32; i++) b.push(randFn() & 0xFF);
    return b;
  }

  return {
    fromBE: fromBE, toBE: toBE, onCurve: onCurve, limbs: limbs,
    genKeyPair: function (randFn) {
      var d, pub, tries = 0;
      do {
        d = fromBE(rand32(randFn));
        tries++;
      } while (isZero(d) && tries < 8);
      var pt = toAffine(mulG(d));
      if (!pt) throw new Error('P256 keygen failed');
      pub = [0x04].concat(toBE(pt[0]), toBE(pt[1]));
      return { priv: toBE(d), pub: pub };
    },
    shared: function (privBE, peerBE) {
      // peerBE: 04||X||Y (65B) 或 X||Y (64B) 或 02/03||X (33B 压缩)
      if (!peerBE || peerBE.length < 33) throw new Error('bad peer key');
      var x, y;
      if (peerBE.length === 33 && (peerBE[0] === 2 || peerBE[0] === 3)) {
        x = fromBE(peerBE.slice(1, 33));
        y = decompressY(x, peerBE[0] & 1);
        if (y == null) throw new Error('compressed key: y not recoverable');
      } else {
        var off = peerBE.length === 65 ? 1 : 0;
        x = fromBE(peerBE.slice(off, off + 32));
        y = fromBE(peerBE.slice(off + 32, off + 64));
      }
      if (cmp(x, P) >= 0 || cmp(y, P) >= 0 || !onCurve(x, y)) throw new Error('peer point not on curve');
      var d = fromBE(privBE);
      if (isZero(d)) throw new Error('zero private key');
      var pt = toAffine(mulPoint(d, x, y));
      if (!pt) throw new Error('ECDH result infinity');
      return toBE(pt[0]);
    },
    pubFromPriv: function (privBE) {
      var d = fromBE(privBE);
      if (isZero(d)) throw new Error('zero private key');
      var pt = toAffine(mulG(d));
      if (!pt) throw new Error('P256 keygen failed');
      return [0x04].concat(toBE(pt[0]), toBE(pt[1]));
    }
  };
})();


var __OK_PAKO = (function(){ var module={exports:{}}; var exports=module.exports; (function(module,exports){
/*! pako 2.1.0 https://github.com/nodeca/pako @license (MIT AND Zlib) */
!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t="undefined"!=typeof globalThis?globalThis:t||self).pako={})}(this,(function(t){"use strict";function e(t){let e=t.length;for(;--e>=0;)t[e]=0}const a=256,i=286,n=30,s=15,r=new Uint8Array([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]),o=new Uint8Array([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]),l=new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,3,7]),h=new Uint8Array([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),d=new Array(576);e(d);const _=new Array(60);e(_);const f=new Array(512);e(f);const c=new Array(256);e(c);const u=new Array(29);e(u);const w=new Array(n);function m(t,e,a,i,n){this.static_tree=t,this.extra_bits=e,this.extra_base=a,this.elems=i,this.max_length=n,this.has_stree=t&&t.length}let b,g,p;function k(t,e){this.dyn_tree=t,this.max_code=0,this.stat_desc=e}e(w);const v=t=>t<256?f[t]:f[256+(t>>>7)],y=(t,e)=>{t.pending_buf[t.pending++]=255&e,t.pending_buf[t.pending++]=e>>>8&255},x=(t,e,a)=>{t.bi_valid>16-a?(t.bi_buf|=e<<t.bi_valid&65535,y(t,t.bi_buf),t.bi_buf=e>>16-t.bi_valid,t.bi_valid+=a-16):(t.bi_buf|=e<<t.bi_valid&65535,t.bi_valid+=a)},z=(t,e,a)=>{x(t,a[2*e],a[2*e+1])},A=(t,e)=>{let a=0;do{a|=1&t,t>>>=1,a<<=1}while(--e>0);return a>>>1},E=(t,e,a)=>{const i=new Array(16);let n,r,o=0;for(n=1;n<=s;n++)o=o+a[n-1]<<1,i[n]=o;for(r=0;r<=e;r++){let e=t[2*r+1];0!==e&&(t[2*r]=A(i[e]++,e))}},R=t=>{let e;for(e=0;e<i;e++)t.dyn_ltree[2*e]=0;for(e=0;e<n;e++)t.dyn_dtree[2*e]=0;for(e=0;e<19;e++)t.bl_tree[2*e]=0;t.dyn_ltree[512]=1,t.opt_len=t.static_len=0,t.sym_next=t.matches=0},Z=t=>{t.bi_valid>8?y(t,t.bi_buf):t.bi_valid>0&&(t.pending_buf[t.pending++]=t.bi_buf),t.bi_buf=0,t.bi_valid=0},U=(t,e,a,i)=>{const n=2*e,s=2*a;return t[n]<t[s]||t[n]===t[s]&&i[e]<=i[a]},S=(t,e,a)=>{const i=t.heap[a];let n=a<<1;for(;n<=t.heap_len&&(n<t.heap_len&&U(e,t.heap[n+1],t.heap[n],t.depth)&&n++,!U(e,i,t.heap[n],t.depth));)t.heap[a]=t.heap[n],a=n,n<<=1;t.heap[a]=i},D=(t,e,i)=>{let n,s,l,h,d=0;if(0!==t.sym_next)do{n=255&t.pending_buf[t.sym_buf+d++],n+=(255&t.pending_buf[t.sym_buf+d++])<<8,s=t.pending_buf[t.sym_buf+d++],0===n?z(t,s,e):(l=c[s],z(t,l+a+1,e),h=r[l],0!==h&&(s-=u[l],x(t,s,h)),n--,l=v(n),z(t,l,i),h=o[l],0!==h&&(n-=w[l],x(t,n,h)))}while(d<t.sym_next);z(t,256,e)},T=(t,e)=>{const a=e.dyn_tree,i=e.stat_desc.static_tree,n=e.stat_desc.has_stree,r=e.stat_desc.elems;let o,l,h,d=-1;for(t.heap_len=0,t.heap_max=573,o=0;o<r;o++)0!==a[2*o]?(t.heap[++t.heap_len]=d=o,t.depth[o]=0):a[2*o+1]=0;for(;t.heap_len<2;)h=t.heap[++t.heap_len]=d<2?++d:0,a[2*h]=1,t.depth[h]=0,t.opt_len--,n&&(t.static_len-=i[2*h+1]);for(e.max_code=d,o=t.heap_len>>1;o>=1;o--)S(t,a,o);h=r;do{o=t.heap[1],t.heap[1]=t.heap[t.heap_len--],S(t,a,1),l=t.heap[1],t.heap[--t.heap_max]=o,t.heap[--t.heap_max]=l,a[2*h]=a[2*o]+a[2*l],t.depth[h]=(t.depth[o]>=t.depth[l]?t.depth[o]:t.depth[l])+1,a[2*o+1]=a[2*l+1]=h,t.heap[1]=h++,S(t,a,1)}while(t.heap_len>=2);t.heap[--t.heap_max]=t.heap[1],((t,e)=>{const a=e.dyn_tree,i=e.max_code,n=e.stat_desc.static_tree,r=e.stat_desc.has_stree,o=e.stat_desc.extra_bits,l=e.stat_desc.extra_base,h=e.stat_desc.max_length;let d,_,f,c,u,w,m=0;for(c=0;c<=s;c++)t.bl_count[c]=0;for(a[2*t.heap[t.heap_max]+1]=0,d=t.heap_max+1;d<573;d++)_=t.heap[d],c=a[2*a[2*_+1]+1]+1,c>h&&(c=h,m++),a[2*_+1]=c,_>i||(t.bl_count[c]++,u=0,_>=l&&(u=o[_-l]),w=a[2*_],t.opt_len+=w*(c+u),r&&(t.static_len+=w*(n[2*_+1]+u)));if(0!==m){do{for(c=h-1;0===t.bl_count[c];)c--;t.bl_count[c]--,t.bl_count[c+1]+=2,t.bl_count[h]--,m-=2}while(m>0);for(c=h;0!==c;c--)for(_=t.bl_count[c];0!==_;)f=t.heap[--d],f>i||(a[2*f+1]!==c&&(t.opt_len+=(c-a[2*f+1])*a[2*f],a[2*f+1]=c),_--)}})(t,e),E(a,d,t.bl_count)},O=(t,e,a)=>{let i,n,s=-1,r=e[1],o=0,l=7,h=4;for(0===r&&(l=138,h=3),e[2*(a+1)+1]=65535,i=0;i<=a;i++)n=r,r=e[2*(i+1)+1],++o<l&&n===r||(o<h?t.bl_tree[2*n]+=o:0!==n?(n!==s&&t.bl_tree[2*n]++,t.bl_tree[32]++):o<=10?t.bl_tree[34]++:t.bl_tree[36]++,o=0,s=n,0===r?(l=138,h=3):n===r?(l=6,h=3):(l=7,h=4))},I=(t,e,a)=>{let i,n,s=-1,r=e[1],o=0,l=7,h=4;for(0===r&&(l=138,h=3),i=0;i<=a;i++)if(n=r,r=e[2*(i+1)+1],!(++o<l&&n===r)){if(o<h)do{z(t,n,t.bl_tree)}while(0!=--o);else 0!==n?(n!==s&&(z(t,n,t.bl_tree),o--),z(t,16,t.bl_tree),x(t,o-3,2)):o<=10?(z(t,17,t.bl_tree),x(t,o-3,3)):(z(t,18,t.bl_tree),x(t,o-11,7));o=0,s=n,0===r?(l=138,h=3):n===r?(l=6,h=3):(l=7,h=4)}};let F=!1;const L=(t,e,a,i)=>{x(t,0+(i?1:0),3),Z(t),y(t,a),y(t,~a),a&&t.pending_buf.set(t.window.subarray(e,e+a),t.pending),t.pending+=a};var N=(t,e,i,n)=>{let s,r,o=0;t.level>0?(2===t.strm.data_type&&(t.strm.data_type=(t=>{let e,i=4093624447;for(e=0;e<=31;e++,i>>>=1)if(1&i&&0!==t.dyn_ltree[2*e])return 0;if(0!==t.dyn_ltree[18]||0!==t.dyn_ltree[20]||0!==t.dyn_ltree[26])return 1;for(e=32;e<a;e++)if(0!==t.dyn_ltree[2*e])return 1;return 0})(t)),T(t,t.l_desc),T(t,t.d_desc),o=(t=>{let e;for(O(t,t.dyn_ltree,t.l_desc.max_code),O(t,t.dyn_dtree,t.d_desc.max_code),T(t,t.bl_desc),e=18;e>=3&&0===t.bl_tree[2*h[e]+1];e--);return t.opt_len+=3*(e+1)+5+5+4,e})(t),s=t.opt_len+3+7>>>3,r=t.static_len+3+7>>>3,r<=s&&(s=r)):s=r=i+5,i+4<=s&&-1!==e?L(t,e,i,n):4===t.strategy||r===s?(x(t,2+(n?1:0),3),D(t,d,_)):(x(t,4+(n?1:0),3),((t,e,a,i)=>{let n;for(x(t,e-257,5),x(t,a-1,5),x(t,i-4,4),n=0;n<i;n++)x(t,t.bl_tree[2*h[n]+1],3);I(t,t.dyn_ltree,e-1),I(t,t.dyn_dtree,a-1)})(t,t.l_desc.max_code+1,t.d_desc.max_code+1,o+1),D(t,t.dyn_ltree,t.dyn_dtree)),R(t),n&&Z(t)},B={_tr_init:t=>{F||((()=>{let t,e,a,h,k;const v=new Array(16);for(a=0,h=0;h<28;h++)for(u[h]=a,t=0;t<1<<r[h];t++)c[a++]=h;for(c[a-1]=h,k=0,h=0;h<16;h++)for(w[h]=k,t=0;t<1<<o[h];t++)f[k++]=h;for(k>>=7;h<n;h++)for(w[h]=k<<7,t=0;t<1<<o[h]-7;t++)f[256+k++]=h;for(e=0;e<=s;e++)v[e]=0;for(t=0;t<=143;)d[2*t+1]=8,t++,v[8]++;for(;t<=255;)d[2*t+1]=9,t++,v[9]++;for(;t<=279;)d[2*t+1]=7,t++,v[7]++;for(;t<=287;)d[2*t+1]=8,t++,v[8]++;for(E(d,287,v),t=0;t<n;t++)_[2*t+1]=5,_[2*t]=A(t,5);b=new m(d,r,257,i,s),g=new m(_,o,0,n,s),p=new m(new Array(0),l,0,19,7)})(),F=!0),t.l_desc=new k(t.dyn_ltree,b),t.d_desc=new k(t.dyn_dtree,g),t.bl_desc=new k(t.bl_tree,p),t.bi_buf=0,t.bi_valid=0,R(t)},_tr_stored_block:L,_tr_flush_block:N,_tr_tally:(t,e,i)=>(t.pending_buf[t.sym_buf+t.sym_next++]=e,t.pending_buf[t.sym_buf+t.sym_next++]=e>>8,t.pending_buf[t.sym_buf+t.sym_next++]=i,0===e?t.dyn_ltree[2*i]++:(t.matches++,e--,t.dyn_ltree[2*(c[i]+a+1)]++,t.dyn_dtree[2*v(e)]++),t.sym_next===t.sym_end),_tr_align:t=>{x(t,2,3),z(t,256,d),(t=>{16===t.bi_valid?(y(t,t.bi_buf),t.bi_buf=0,t.bi_valid=0):t.bi_valid>=8&&(t.pending_buf[t.pending++]=255&t.bi_buf,t.bi_buf>>=8,t.bi_valid-=8)})(t)}};var C=(t,e,a,i)=>{let n=65535&t|0,s=t>>>16&65535|0,r=0;for(;0!==a;){r=a>2e3?2e3:a,a-=r;do{n=n+e[i++]|0,s=s+n|0}while(--r);n%=65521,s%=65521}return n|s<<16|0};const M=new Uint32Array((()=>{let t,e=[];for(var a=0;a<256;a++){t=a;for(var i=0;i<8;i++)t=1&t?3988292384^t>>>1:t>>>1;e[a]=t}return e})());var H=(t,e,a,i)=>{const n=M,s=i+a;t^=-1;for(let a=i;a<s;a++)t=t>>>8^n[255&(t^e[a])];return-1^t},j={2:"need dictionary",1:"stream end",0:"","-1":"file error","-2":"stream error","-3":"data error","-4":"insufficient memory","-5":"buffer error","-6":"incompatible version"},K={Z_NO_FLUSH:0,Z_PARTIAL_FLUSH:1,Z_SYNC_FLUSH:2,Z_FULL_FLUSH:3,Z_FINISH:4,Z_BLOCK:5,Z_TREES:6,Z_OK:0,Z_STREAM_END:1,Z_NEED_DICT:2,Z_ERRNO:-1,Z_STREAM_ERROR:-2,Z_DATA_ERROR:-3,Z_MEM_ERROR:-4,Z_BUF_ERROR:-5,Z_NO_COMPRESSION:0,Z_BEST_SPEED:1,Z_BEST_COMPRESSION:9,Z_DEFAULT_COMPRESSION:-1,Z_FILTERED:1,Z_HUFFMAN_ONLY:2,Z_RLE:3,Z_FIXED:4,Z_DEFAULT_STRATEGY:0,Z_BINARY:0,Z_TEXT:1,Z_UNKNOWN:2,Z_DEFLATED:8};const{_tr_init:P,_tr_stored_block:Y,_tr_flush_block:G,_tr_tally:X,_tr_align:W}=B,{Z_NO_FLUSH:q,Z_PARTIAL_FLUSH:J,Z_FULL_FLUSH:Q,Z_FINISH:V,Z_BLOCK:$,Z_OK:tt,Z_STREAM_END:et,Z_STREAM_ERROR:at,Z_DATA_ERROR:it,Z_BUF_ERROR:nt,Z_DEFAULT_COMPRESSION:st,Z_FILTERED:rt,Z_HUFFMAN_ONLY:ot,Z_RLE:lt,Z_FIXED:ht,Z_DEFAULT_STRATEGY:dt,Z_UNKNOWN:_t,Z_DEFLATED:ft}=K,ct=258,ut=262,wt=42,mt=113,bt=666,gt=(t,e)=>(t.msg=j[e],e),pt=t=>2*t-(t>4?9:0),kt=t=>{let e=t.length;for(;--e>=0;)t[e]=0},vt=t=>{let e,a,i,n=t.w_size;e=t.hash_size,i=e;do{a=t.head[--i],t.head[i]=a>=n?a-n:0}while(--e);e=n,i=e;do{a=t.prev[--i],t.prev[i]=a>=n?a-n:0}while(--e)};let yt=(t,e,a)=>(e<<t.hash_shift^a)&t.hash_mask;const xt=t=>{const e=t.state;let a=e.pending;a>t.avail_out&&(a=t.avail_out),0!==a&&(t.output.set(e.pending_buf.subarray(e.pending_out,e.pending_out+a),t.next_out),t.next_out+=a,e.pending_out+=a,t.total_out+=a,t.avail_out-=a,e.pending-=a,0===e.pending&&(e.pending_out=0))},zt=(t,e)=>{G(t,t.block_start>=0?t.block_start:-1,t.strstart-t.block_start,e),t.block_start=t.strstart,xt(t.strm)},At=(t,e)=>{t.pending_buf[t.pending++]=e},Et=(t,e)=>{t.pending_buf[t.pending++]=e>>>8&255,t.pending_buf[t.pending++]=255&e},Rt=(t,e,a,i)=>{let n=t.avail_in;return n>i&&(n=i),0===n?0:(t.avail_in-=n,e.set(t.input.subarray(t.next_in,t.next_in+n),a),1===t.state.wrap?t.adler=C(t.adler,e,n,a):2===t.state.wrap&&(t.adler=H(t.adler,e,n,a)),t.next_in+=n,t.total_in+=n,n)},Zt=(t,e)=>{let a,i,n=t.max_chain_length,s=t.strstart,r=t.prev_length,o=t.nice_match;const l=t.strstart>t.w_size-ut?t.strstart-(t.w_size-ut):0,h=t.window,d=t.w_mask,_=t.prev,f=t.strstart+ct;let c=h[s+r-1],u=h[s+r];t.prev_length>=t.good_match&&(n>>=2),o>t.lookahead&&(o=t.lookahead);do{if(a=e,h[a+r]===u&&h[a+r-1]===c&&h[a]===h[s]&&h[++a]===h[s+1]){s+=2,a++;do{}while(h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&h[++s]===h[++a]&&s<f);if(i=ct-(f-s),s=f-ct,i>r){if(t.match_start=e,r=i,i>=o)break;c=h[s+r-1],u=h[s+r]}}}while((e=_[e&d])>l&&0!=--n);return r<=t.lookahead?r:t.lookahead},Ut=t=>{const e=t.w_size;let a,i,n;do{if(i=t.window_size-t.lookahead-t.strstart,t.strstart>=e+(e-ut)&&(t.window.set(t.window.subarray(e,e+e-i),0),t.match_start-=e,t.strstart-=e,t.block_start-=e,t.insert>t.strstart&&(t.insert=t.strstart),vt(t),i+=e),0===t.strm.avail_in)break;if(a=Rt(t.strm,t.window,t.strstart+t.lookahead,i),t.lookahead+=a,t.lookahead+t.insert>=3)for(n=t.strstart-t.insert,t.ins_h=t.window[n],t.ins_h=yt(t,t.ins_h,t.window[n+1]);t.insert&&(t.ins_h=yt(t,t.ins_h,t.window[n+3-1]),t.prev[n&t.w_mask]=t.head[t.ins_h],t.head[t.ins_h]=n,n++,t.insert--,!(t.lookahead+t.insert<3)););}while(t.lookahead<ut&&0!==t.strm.avail_in)},St=(t,e)=>{let a,i,n,s=t.pending_buf_size-5>t.w_size?t.w_size:t.pending_buf_size-5,r=0,o=t.strm.avail_in;do{if(a=65535,n=t.bi_valid+42>>3,t.strm.avail_out<n)break;if(n=t.strm.avail_out-n,i=t.strstart-t.block_start,a>i+t.strm.avail_in&&(a=i+t.strm.avail_in),a>n&&(a=n),a<s&&(0===a&&e!==V||e===q||a!==i+t.strm.avail_in))break;r=e===V&&a===i+t.strm.avail_in?1:0,Y(t,0,0,r),t.pending_buf[t.pending-4]=a,t.pending_buf[t.pending-3]=a>>8,t.pending_buf[t.pending-2]=~a,t.pending_buf[t.pending-1]=~a>>8,xt(t.strm),i&&(i>a&&(i=a),t.strm.output.set(t.window.subarray(t.block_start,t.block_start+i),t.strm.next_out),t.strm.next_out+=i,t.strm.avail_out-=i,t.strm.total_out+=i,t.block_start+=i,a-=i),a&&(Rt(t.strm,t.strm.output,t.strm.next_out,a),t.strm.next_out+=a,t.strm.avail_out-=a,t.strm.total_out+=a)}while(0===r);return o-=t.strm.avail_in,o&&(o>=t.w_size?(t.matches=2,t.window.set(t.strm.input.subarray(t.strm.next_in-t.w_size,t.strm.next_in),0),t.strstart=t.w_size,t.insert=t.strstart):(t.window_size-t.strstart<=o&&(t.strstart-=t.w_size,t.window.set(t.window.subarray(t.w_size,t.w_size+t.strstart),0),t.matches<2&&t.matches++,t.insert>t.strstart&&(t.insert=t.strstart)),t.window.set(t.strm.input.subarray(t.strm.next_in-o,t.strm.next_in),t.strstart),t.strstart+=o,t.insert+=o>t.w_size-t.insert?t.w_size-t.insert:o),t.block_start=t.strstart),t.high_water<t.strstart&&(t.high_water=t.strstart),r?4:e!==q&&e!==V&&0===t.strm.avail_in&&t.strstart===t.block_start?2:(n=t.window_size-t.strstart,t.strm.avail_in>n&&t.block_start>=t.w_size&&(t.block_start-=t.w_size,t.strstart-=t.w_size,t.window.set(t.window.subarray(t.w_size,t.w_size+t.strstart),0),t.matches<2&&t.matches++,n+=t.w_size,t.insert>t.strstart&&(t.insert=t.strstart)),n>t.strm.avail_in&&(n=t.strm.avail_in),n&&(Rt(t.strm,t.window,t.strstart,n),t.strstart+=n,t.insert+=n>t.w_size-t.insert?t.w_size-t.insert:n),t.high_water<t.strstart&&(t.high_water=t.strstart),n=t.bi_valid+42>>3,n=t.pending_buf_size-n>65535?65535:t.pending_buf_size-n,s=n>t.w_size?t.w_size:n,i=t.strstart-t.block_start,(i>=s||(i||e===V)&&e!==q&&0===t.strm.avail_in&&i<=n)&&(a=i>n?n:i,r=e===V&&0===t.strm.avail_in&&a===i?1:0,Y(t,t.block_start,a,r),t.block_start+=a,xt(t.strm)),r?3:1)},Dt=(t,e)=>{let a,i;for(;;){if(t.lookahead<ut){if(Ut(t),t.lookahead<ut&&e===q)return 1;if(0===t.lookahead)break}if(a=0,t.lookahead>=3&&(t.ins_h=yt(t,t.ins_h,t.window[t.strstart+3-1]),a=t.prev[t.strstart&t.w_mask]=t.head[t.ins_h],t.head[t.ins_h]=t.strstart),0!==a&&t.strstart-a<=t.w_size-ut&&(t.match_length=Zt(t,a)),t.match_length>=3)if(i=X(t,t.strstart-t.match_start,t.match_length-3),t.lookahead-=t.match_length,t.match_length<=t.max_lazy_match&&t.lookahead>=3){t.match_length--;do{t.strstart++,t.ins_h=yt(t,t.ins_h,t.window[t.strstart+3-1]),a=t.prev[t.strstart&t.w_mask]=t.head[t.ins_h],t.head[t.ins_h]=t.strstart}while(0!=--t.match_length);t.strstart++}else t.strstart+=t.match_length,t.match_length=0,t.ins_h=t.window[t.strstart],t.ins_h=yt(t,t.ins_h,t.window[t.strstart+1]);else i=X(t,0,t.window[t.strstart]),t.lookahead--,t.strstart++;if(i&&(zt(t,!1),0===t.strm.avail_out))return 1}return t.insert=t.strstart<2?t.strstart:2,e===V?(zt(t,!0),0===t.strm.avail_out?3:4):t.sym_next&&(zt(t,!1),0===t.strm.avail_out)?1:2},Tt=(t,e)=>{let a,i,n;for(;;){if(t.lookahead<ut){if(Ut(t),t.lookahead<ut&&e===q)return 1;if(0===t.lookahead)break}if(a=0,t.lookahead>=3&&(t.ins_h=yt(t,t.ins_h,t.window[t.strstart+3-1]),a=t.prev[t.strstart&t.w_mask]=t.head[t.ins_h],t.head[t.ins_h]=t.strstart),t.prev_length=t.match_length,t.prev_match=t.match_start,t.match_length=2,0!==a&&t.prev_length<t.max_lazy_match&&t.strstart-a<=t.w_size-ut&&(t.match_length=Zt(t,a),t.match_length<=5&&(t.strategy===rt||3===t.match_length&&t.strstart-t.match_start>4096)&&(t.match_length=2)),t.prev_length>=3&&t.match_length<=t.prev_length){n=t.strstart+t.lookahead-3,i=X(t,t.strstart-1-t.prev_match,t.prev_length-3),t.lookahead-=t.prev_length-1,t.prev_length-=2;do{++t.strstart<=n&&(t.ins_h=yt(t,t.ins_h,t.window[t.strstart+3-1]),a=t.prev[t.strstart&t.w_mask]=t.head[t.ins_h],t.head[t.ins_h]=t.strstart)}while(0!=--t.prev_length);if(t.match_available=0,t.match_length=2,t.strstart++,i&&(zt(t,!1),0===t.strm.avail_out))return 1}else if(t.match_available){if(i=X(t,0,t.window[t.strstart-1]),i&&zt(t,!1),t.strstart++,t.lookahead--,0===t.strm.avail_out)return 1}else t.match_available=1,t.strstart++,t.lookahead--}return t.match_available&&(i=X(t,0,t.window[t.strstart-1]),t.match_available=0),t.insert=t.strstart<2?t.strstart:2,e===V?(zt(t,!0),0===t.strm.avail_out?3:4):t.sym_next&&(zt(t,!1),0===t.strm.avail_out)?1:2};function Ot(t,e,a,i,n){this.good_length=t,this.max_lazy=e,this.nice_length=a,this.max_chain=i,this.func=n}const It=[new Ot(0,0,0,0,St),new Ot(4,4,8,4,Dt),new Ot(4,5,16,8,Dt),new Ot(4,6,32,32,Dt),new Ot(4,4,16,16,Tt),new Ot(8,16,32,32,Tt),new Ot(8,16,128,128,Tt),new Ot(8,32,128,256,Tt),new Ot(32,128,258,1024,Tt),new Ot(32,258,258,4096,Tt)];function Ft(){this.strm=null,this.status=0,this.pending_buf=null,this.pending_buf_size=0,this.pending_out=0,this.pending=0,this.wrap=0,this.gzhead=null,this.gzindex=0,this.method=ft,this.last_flush=-1,this.w_size=0,this.w_bits=0,this.w_mask=0,this.window=null,this.window_size=0,this.prev=null,this.head=null,this.ins_h=0,this.hash_size=0,this.hash_bits=0,this.hash_mask=0,this.hash_shift=0,this.block_start=0,this.match_length=0,this.prev_match=0,this.match_available=0,this.strstart=0,this.match_start=0,this.lookahead=0,this.prev_length=0,this.max_chain_length=0,this.max_lazy_match=0,this.level=0,this.strategy=0,this.good_match=0,this.nice_match=0,this.dyn_ltree=new Uint16Array(1146),this.dyn_dtree=new Uint16Array(122),this.bl_tree=new Uint16Array(78),kt(this.dyn_ltree),kt(this.dyn_dtree),kt(this.bl_tree),this.l_desc=null,this.d_desc=null,this.bl_desc=null,this.bl_count=new Uint16Array(16),this.heap=new Uint16Array(573),kt(this.heap),this.heap_len=0,this.heap_max=0,this.depth=new Uint16Array(573),kt(this.depth),this.sym_buf=0,this.lit_bufsize=0,this.sym_next=0,this.sym_end=0,this.opt_len=0,this.static_len=0,this.matches=0,this.insert=0,this.bi_buf=0,this.bi_valid=0}const Lt=t=>{if(!t)return 1;const e=t.state;return!e||e.strm!==t||e.status!==wt&&57!==e.status&&69!==e.status&&73!==e.status&&91!==e.status&&103!==e.status&&e.status!==mt&&e.status!==bt?1:0},Nt=t=>{if(Lt(t))return gt(t,at);t.total_in=t.total_out=0,t.data_type=_t;const e=t.state;return e.pending=0,e.pending_out=0,e.wrap<0&&(e.wrap=-e.wrap),e.status=2===e.wrap?57:e.wrap?wt:mt,t.adler=2===e.wrap?0:1,e.last_flush=-2,P(e),tt},Bt=t=>{const e=Nt(t);var a;return e===tt&&((a=t.state).window_size=2*a.w_size,kt(a.head),a.max_lazy_match=It[a.level].max_lazy,a.good_match=It[a.level].good_length,a.nice_match=It[a.level].nice_length,a.max_chain_length=It[a.level].max_chain,a.strstart=0,a.block_start=0,a.lookahead=0,a.insert=0,a.match_length=a.prev_length=2,a.match_available=0,a.ins_h=0),e},Ct=(t,e,a,i,n,s)=>{if(!t)return at;let r=1;if(e===st&&(e=6),i<0?(r=0,i=-i):i>15&&(r=2,i-=16),n<1||n>9||a!==ft||i<8||i>15||e<0||e>9||s<0||s>ht||8===i&&1!==r)return gt(t,at);8===i&&(i=9);const o=new Ft;return t.state=o,o.strm=t,o.status=wt,o.wrap=r,o.gzhead=null,o.w_bits=i,o.w_size=1<<o.w_bits,o.w_mask=o.w_size-1,o.hash_bits=n+7,o.hash_size=1<<o.hash_bits,o.hash_mask=o.hash_size-1,o.hash_shift=~~((o.hash_bits+3-1)/3),o.window=new Uint8Array(2*o.w_size),o.head=new Uint16Array(o.hash_size),o.prev=new Uint16Array(o.w_size),o.lit_bufsize=1<<n+6,o.pending_buf_size=4*o.lit_bufsize,o.pending_buf=new Uint8Array(o.pending_buf_size),o.sym_buf=o.lit_bufsize,o.sym_end=3*(o.lit_bufsize-1),o.level=e,o.strategy=s,o.method=a,Bt(t)};var Mt={deflateInit:(t,e)=>Ct(t,e,ft,15,8,dt),deflateInit2:Ct,deflateReset:Bt,deflateResetKeep:Nt,deflateSetHeader:(t,e)=>Lt(t)||2!==t.state.wrap?at:(t.state.gzhead=e,tt),deflate:(t,e)=>{if(Lt(t)||e>$||e<0)return t?gt(t,at):at;const a=t.state;if(!t.output||0!==t.avail_in&&!t.input||a.status===bt&&e!==V)return gt(t,0===t.avail_out?nt:at);const i=a.last_flush;if(a.last_flush=e,0!==a.pending){if(xt(t),0===t.avail_out)return a.last_flush=-1,tt}else if(0===t.avail_in&&pt(e)<=pt(i)&&e!==V)return gt(t,nt);if(a.status===bt&&0!==t.avail_in)return gt(t,nt);if(a.status===wt&&0===a.wrap&&(a.status=mt),a.status===wt){let e=ft+(a.w_bits-8<<4)<<8,i=-1;if(i=a.strategy>=ot||a.level<2?0:a.level<6?1:6===a.level?2:3,e|=i<<6,0!==a.strstart&&(e|=32),e+=31-e%31,Et(a,e),0!==a.strstart&&(Et(a,t.adler>>>16),Et(a,65535&t.adler)),t.adler=1,a.status=mt,xt(t),0!==a.pending)return a.last_flush=-1,tt}if(57===a.status)if(t.adler=0,At(a,31),At(a,139),At(a,8),a.gzhead)At(a,(a.gzhead.text?1:0)+(a.gzhead.hcrc?2:0)+(a.gzhead.extra?4:0)+(a.gzhead.name?8:0)+(a.gzhead.comment?16:0)),At(a,255&a.gzhead.time),At(a,a.gzhead.time>>8&255),At(a,a.gzhead.time>>16&255),At(a,a.gzhead.time>>24&255),At(a,9===a.level?2:a.strategy>=ot||a.level<2?4:0),At(a,255&a.gzhead.os),a.gzhead.extra&&a.gzhead.extra.length&&(At(a,255&a.gzhead.extra.length),At(a,a.gzhead.extra.length>>8&255)),a.gzhead.hcrc&&(t.adler=H(t.adler,a.pending_buf,a.pending,0)),a.gzindex=0,a.status=69;else if(At(a,0),At(a,0),At(a,0),At(a,0),At(a,0),At(a,9===a.level?2:a.strategy>=ot||a.level<2?4:0),At(a,3),a.status=mt,xt(t),0!==a.pending)return a.last_flush=-1,tt;if(69===a.status){if(a.gzhead.extra){let e=a.pending,i=(65535&a.gzhead.extra.length)-a.gzindex;for(;a.pending+i>a.pending_buf_size;){let n=a.pending_buf_size-a.pending;if(a.pending_buf.set(a.gzhead.extra.subarray(a.gzindex,a.gzindex+n),a.pending),a.pending=a.pending_buf_size,a.gzhead.hcrc&&a.pending>e&&(t.adler=H(t.adler,a.pending_buf,a.pending-e,e)),a.gzindex+=n,xt(t),0!==a.pending)return a.last_flush=-1,tt;e=0,i-=n}let n=new Uint8Array(a.gzhead.extra);a.pending_buf.set(n.subarray(a.gzindex,a.gzindex+i),a.pending),a.pending+=i,a.gzhead.hcrc&&a.pending>e&&(t.adler=H(t.adler,a.pending_buf,a.pending-e,e)),a.gzindex=0}a.status=73}if(73===a.status){if(a.gzhead.name){let e,i=a.pending;do{if(a.pending===a.pending_buf_size){if(a.gzhead.hcrc&&a.pending>i&&(t.adler=H(t.adler,a.pending_buf,a.pending-i,i)),xt(t),0!==a.pending)return a.last_flush=-1,tt;i=0}e=a.gzindex<a.gzhead.name.length?255&a.gzhead.name.charCodeAt(a.gzindex++):0,At(a,e)}while(0!==e);a.gzhead.hcrc&&a.pending>i&&(t.adler=H(t.adler,a.pending_buf,a.pending-i,i)),a.gzindex=0}a.status=91}if(91===a.status){if(a.gzhead.comment){let e,i=a.pending;do{if(a.pending===a.pending_buf_size){if(a.gzhead.hcrc&&a.pending>i&&(t.adler=H(t.adler,a.pending_buf,a.pending-i,i)),xt(t),0!==a.pending)return a.last_flush=-1,tt;i=0}e=a.gzindex<a.gzhead.comment.length?255&a.gzhead.comment.charCodeAt(a.gzindex++):0,At(a,e)}while(0!==e);a.gzhead.hcrc&&a.pending>i&&(t.adler=H(t.adler,a.pending_buf,a.pending-i,i))}a.status=103}if(103===a.status){if(a.gzhead.hcrc){if(a.pending+2>a.pending_buf_size&&(xt(t),0!==a.pending))return a.last_flush=-1,tt;At(a,255&t.adler),At(a,t.adler>>8&255),t.adler=0}if(a.status=mt,xt(t),0!==a.pending)return a.last_flush=-1,tt}if(0!==t.avail_in||0!==a.lookahead||e!==q&&a.status!==bt){let i=0===a.level?St(a,e):a.strategy===ot?((t,e)=>{let a;for(;;){if(0===t.lookahead&&(Ut(t),0===t.lookahead)){if(e===q)return 1;break}if(t.match_length=0,a=X(t,0,t.window[t.strstart]),t.lookahead--,t.strstart++,a&&(zt(t,!1),0===t.strm.avail_out))return 1}return t.insert=0,e===V?(zt(t,!0),0===t.strm.avail_out?3:4):t.sym_next&&(zt(t,!1),0===t.strm.avail_out)?1:2})(a,e):a.strategy===lt?((t,e)=>{let a,i,n,s;const r=t.window;for(;;){if(t.lookahead<=ct){if(Ut(t),t.lookahead<=ct&&e===q)return 1;if(0===t.lookahead)break}if(t.match_length=0,t.lookahead>=3&&t.strstart>0&&(n=t.strstart-1,i=r[n],i===r[++n]&&i===r[++n]&&i===r[++n])){s=t.strstart+ct;do{}while(i===r[++n]&&i===r[++n]&&i===r[++n]&&i===r[++n]&&i===r[++n]&&i===r[++n]&&i===r[++n]&&i===r[++n]&&n<s);t.match_length=ct-(s-n),t.match_length>t.lookahead&&(t.match_length=t.lookahead)}if(t.match_length>=3?(a=X(t,1,t.match_length-3),t.lookahead-=t.match_length,t.strstart+=t.match_length,t.match_length=0):(a=X(t,0,t.window[t.strstart]),t.lookahead--,t.strstart++),a&&(zt(t,!1),0===t.strm.avail_out))return 1}return t.insert=0,e===V?(zt(t,!0),0===t.strm.avail_out?3:4):t.sym_next&&(zt(t,!1),0===t.strm.avail_out)?1:2})(a,e):It[a.level].func(a,e);if(3!==i&&4!==i||(a.status=bt),1===i||3===i)return 0===t.avail_out&&(a.last_flush=-1),tt;if(2===i&&(e===J?W(a):e!==$&&(Y(a,0,0,!1),e===Q&&(kt(a.head),0===a.lookahead&&(a.strstart=0,a.block_start=0,a.insert=0))),xt(t),0===t.avail_out))return a.last_flush=-1,tt}return e!==V?tt:a.wrap<=0?et:(2===a.wrap?(At(a,255&t.adler),At(a,t.adler>>8&255),At(a,t.adler>>16&255),At(a,t.adler>>24&255),At(a,255&t.total_in),At(a,t.total_in>>8&255),At(a,t.total_in>>16&255),At(a,t.total_in>>24&255)):(Et(a,t.adler>>>16),Et(a,65535&t.adler)),xt(t),a.wrap>0&&(a.wrap=-a.wrap),0!==a.pending?tt:et)},deflateEnd:t=>{if(Lt(t))return at;const e=t.state.status;return t.state=null,e===mt?gt(t,it):tt},deflateSetDictionary:(t,e)=>{let a=e.length;if(Lt(t))return at;const i=t.state,n=i.wrap;if(2===n||1===n&&i.status!==wt||i.lookahead)return at;if(1===n&&(t.adler=C(t.adler,e,a,0)),i.wrap=0,a>=i.w_size){0===n&&(kt(i.head),i.strstart=0,i.block_start=0,i.insert=0);let t=new Uint8Array(i.w_size);t.set(e.subarray(a-i.w_size,a),0),e=t,a=i.w_size}const s=t.avail_in,r=t.next_in,o=t.input;for(t.avail_in=a,t.next_in=0,t.input=e,Ut(i);i.lookahead>=3;){let t=i.strstart,e=i.lookahead-2;do{i.ins_h=yt(i,i.ins_h,i.window[t+3-1]),i.prev[t&i.w_mask]=i.head[i.ins_h],i.head[i.ins_h]=t,t++}while(--e);i.strstart=t,i.lookahead=2,Ut(i)}return i.strstart+=i.lookahead,i.block_start=i.strstart,i.insert=i.lookahead,i.lookahead=0,i.match_length=i.prev_length=2,i.match_available=0,t.next_in=r,t.input=o,t.avail_in=s,i.wrap=n,tt},deflateInfo:"pako deflate (from Nodeca project)"};const Ht=(t,e)=>Object.prototype.hasOwnProperty.call(t,e);var jt=function(t){const e=Array.prototype.slice.call(arguments,1);for(;e.length;){const a=e.shift();if(a){if("object"!=typeof a)throw new TypeError(a+"must be non-object");for(const e in a)Ht(a,e)&&(t[e]=a[e])}}return t},Kt=t=>{let e=0;for(let a=0,i=t.length;a<i;a++)e+=t[a].length;const a=new Uint8Array(e);for(let e=0,i=0,n=t.length;e<n;e++){let n=t[e];a.set(n,i),i+=n.length}return a};let Pt=!0;try{String.fromCharCode.apply(null,new Uint8Array(1))}catch(t){Pt=!1}const Yt=new Uint8Array(256);for(let t=0;t<256;t++)Yt[t]=t>=252?6:t>=248?5:t>=240?4:t>=224?3:t>=192?2:1;Yt[254]=Yt[254]=1;var Gt=t=>{if("function"==typeof TextEncoder&&TextEncoder.prototype.encode)return(new TextEncoder).encode(t);let e,a,i,n,s,r=t.length,o=0;for(n=0;n<r;n++)a=t.charCodeAt(n),55296==(64512&a)&&n+1<r&&(i=t.charCodeAt(n+1),56320==(64512&i)&&(a=65536+(a-55296<<10)+(i-56320),n++)),o+=a<128?1:a<2048?2:a<65536?3:4;for(e=new Uint8Array(o),s=0,n=0;s<o;n++)a=t.charCodeAt(n),55296==(64512&a)&&n+1<r&&(i=t.charCodeAt(n+1),56320==(64512&i)&&(a=65536+(a-55296<<10)+(i-56320),n++)),a<128?e[s++]=a:a<2048?(e[s++]=192|a>>>6,e[s++]=128|63&a):a<65536?(e[s++]=224|a>>>12,e[s++]=128|a>>>6&63,e[s++]=128|63&a):(e[s++]=240|a>>>18,e[s++]=128|a>>>12&63,e[s++]=128|a>>>6&63,e[s++]=128|63&a);return e},Xt=(t,e)=>{const a=e||t.length;if("function"==typeof TextDecoder&&TextDecoder.prototype.decode)return(new TextDecoder).decode(t.subarray(0,e));let i,n;const s=new Array(2*a);for(n=0,i=0;i<a;){let e=t[i++];if(e<128){s[n++]=e;continue}let r=Yt[e];if(r>4)s[n++]=65533,i+=r-1;else{for(e&=2===r?31:3===r?15:7;r>1&&i<a;)e=e<<6|63&t[i++],r--;r>1?s[n++]=65533:e<65536?s[n++]=e:(e-=65536,s[n++]=55296|e>>10&1023,s[n++]=56320|1023&e)}}return((t,e)=>{if(e<65534&&t.subarray&&Pt)return String.fromCharCode.apply(null,t.length===e?t:t.subarray(0,e));let a="";for(let i=0;i<e;i++)a+=String.fromCharCode(t[i]);return a})(s,n)},Wt=(t,e)=>{(e=e||t.length)>t.length&&(e=t.length);let a=e-1;for(;a>=0&&128==(192&t[a]);)a--;return a<0||0===a?e:a+Yt[t[a]]>e?a:e};var qt=function(){this.input=null,this.next_in=0,this.avail_in=0,this.total_in=0,this.output=null,this.next_out=0,this.avail_out=0,this.total_out=0,this.msg="",this.state=null,this.data_type=2,this.adler=0};const Jt=Object.prototype.toString,{Z_NO_FLUSH:Qt,Z_SYNC_FLUSH:Vt,Z_FULL_FLUSH:$t,Z_FINISH:te,Z_OK:ee,Z_STREAM_END:ae,Z_DEFAULT_COMPRESSION:ie,Z_DEFAULT_STRATEGY:ne,Z_DEFLATED:se}=K;function re(t){this.options=jt({level:ie,method:se,chunkSize:16384,windowBits:15,memLevel:8,strategy:ne},t||{});let e=this.options;e.raw&&e.windowBits>0?e.windowBits=-e.windowBits:e.gzip&&e.windowBits>0&&e.windowBits<16&&(e.windowBits+=16),this.err=0,this.msg="",this.ended=!1,this.chunks=[],this.strm=new qt,this.strm.avail_out=0;let a=Mt.deflateInit2(this.strm,e.level,e.method,e.windowBits,e.memLevel,e.strategy);if(a!==ee)throw new Error(j[a]);if(e.header&&Mt.deflateSetHeader(this.strm,e.header),e.dictionary){let t;if(t="string"==typeof e.dictionary?Gt(e.dictionary):"[object ArrayBuffer]"===Jt.call(e.dictionary)?new Uint8Array(e.dictionary):e.dictionary,a=Mt.deflateSetDictionary(this.strm,t),a!==ee)throw new Error(j[a]);this._dict_set=!0}}function oe(t,e){const a=new re(e);if(a.push(t,!0),a.err)throw a.msg||j[a.err];return a.result}re.prototype.push=function(t,e){const a=this.strm,i=this.options.chunkSize;let n,s;if(this.ended)return!1;for(s=e===~~e?e:!0===e?te:Qt,"string"==typeof t?a.input=Gt(t):"[object ArrayBuffer]"===Jt.call(t)?a.input=new Uint8Array(t):a.input=t,a.next_in=0,a.avail_in=a.input.length;;)if(0===a.avail_out&&(a.output=new Uint8Array(i),a.next_out=0,a.avail_out=i),(s===Vt||s===$t)&&a.avail_out<=6)this.onData(a.output.subarray(0,a.next_out)),a.avail_out=0;else{if(n=Mt.deflate(a,s),n===ae)return a.next_out>0&&this.onData(a.output.subarray(0,a.next_out)),n=Mt.deflateEnd(this.strm),this.onEnd(n),this.ended=!0,n===ee;if(0!==a.avail_out){if(s>0&&a.next_out>0)this.onData(a.output.subarray(0,a.next_out)),a.avail_out=0;else if(0===a.avail_in)break}else this.onData(a.output)}return!0},re.prototype.onData=function(t){this.chunks.push(t)},re.prototype.onEnd=function(t){t===ee&&(this.result=Kt(this.chunks)),this.chunks=[],this.err=t,this.msg=this.strm.msg};var le={Deflate:re,deflate:oe,deflateRaw:function(t,e){return(e=e||{}).raw=!0,oe(t,e)},gzip:function(t,e){return(e=e||{}).gzip=!0,oe(t,e)},constants:K};const he=16209;var de=function(t,e){let a,i,n,s,r,o,l,h,d,_,f,c,u,w,m,b,g,p,k,v,y,x,z,A;const E=t.state;a=t.next_in,z=t.input,i=a+(t.avail_in-5),n=t.next_out,A=t.output,s=n-(e-t.avail_out),r=n+(t.avail_out-257),o=E.dmax,l=E.wsize,h=E.whave,d=E.wnext,_=E.window,f=E.hold,c=E.bits,u=E.lencode,w=E.distcode,m=(1<<E.lenbits)-1,b=(1<<E.distbits)-1;t:do{c<15&&(f+=z[a++]<<c,c+=8,f+=z[a++]<<c,c+=8),g=u[f&m];e:for(;;){if(p=g>>>24,f>>>=p,c-=p,p=g>>>16&255,0===p)A[n++]=65535&g;else{if(!(16&p)){if(0==(64&p)){g=u[(65535&g)+(f&(1<<p)-1)];continue e}if(32&p){E.mode=16191;break t}t.msg="invalid literal/length code",E.mode=he;break t}k=65535&g,p&=15,p&&(c<p&&(f+=z[a++]<<c,c+=8),k+=f&(1<<p)-1,f>>>=p,c-=p),c<15&&(f+=z[a++]<<c,c+=8,f+=z[a++]<<c,c+=8),g=w[f&b];a:for(;;){if(p=g>>>24,f>>>=p,c-=p,p=g>>>16&255,!(16&p)){if(0==(64&p)){g=w[(65535&g)+(f&(1<<p)-1)];continue a}t.msg="invalid distance code",E.mode=he;break t}if(v=65535&g,p&=15,c<p&&(f+=z[a++]<<c,c+=8,c<p&&(f+=z[a++]<<c,c+=8)),v+=f&(1<<p)-1,v>o){t.msg="invalid distance too far back",E.mode=he;break t}if(f>>>=p,c-=p,p=n-s,v>p){if(p=v-p,p>h&&E.sane){t.msg="invalid distance too far back",E.mode=he;break t}if(y=0,x=_,0===d){if(y+=l-p,p<k){k-=p;do{A[n++]=_[y++]}while(--p);y=n-v,x=A}}else if(d<p){if(y+=l+d-p,p-=d,p<k){k-=p;do{A[n++]=_[y++]}while(--p);if(y=0,d<k){p=d,k-=p;do{A[n++]=_[y++]}while(--p);y=n-v,x=A}}}else if(y+=d-p,p<k){k-=p;do{A[n++]=_[y++]}while(--p);y=n-v,x=A}for(;k>2;)A[n++]=x[y++],A[n++]=x[y++],A[n++]=x[y++],k-=3;k&&(A[n++]=x[y++],k>1&&(A[n++]=x[y++]))}else{y=n-v;do{A[n++]=A[y++],A[n++]=A[y++],A[n++]=A[y++],k-=3}while(k>2);k&&(A[n++]=A[y++],k>1&&(A[n++]=A[y++]))}break}}break}}while(a<i&&n<r);k=c>>3,a-=k,c-=k<<3,f&=(1<<c)-1,t.next_in=a,t.next_out=n,t.avail_in=a<i?i-a+5:5-(a-i),t.avail_out=n<r?r-n+257:257-(n-r),E.hold=f,E.bits=c};const _e=15,fe=new Uint16Array([3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,0,0]),ce=new Uint8Array([16,16,16,16,16,16,16,16,17,17,17,17,18,18,18,18,19,19,19,19,20,20,20,20,21,21,21,21,16,72,78]),ue=new Uint16Array([1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577,0,0]),we=new Uint8Array([16,16,16,16,17,17,18,18,19,19,20,20,21,21,22,22,23,23,24,24,25,25,26,26,27,27,28,28,29,29,64,64]);var me=(t,e,a,i,n,s,r,o)=>{const l=o.bits;let h,d,_,f,c,u,w=0,m=0,b=0,g=0,p=0,k=0,v=0,y=0,x=0,z=0,A=null;const E=new Uint16Array(16),R=new Uint16Array(16);let Z,U,S,D=null;for(w=0;w<=_e;w++)E[w]=0;for(m=0;m<i;m++)E[e[a+m]]++;for(p=l,g=_e;g>=1&&0===E[g];g--);if(p>g&&(p=g),0===g)return n[s++]=20971520,n[s++]=20971520,o.bits=1,0;for(b=1;b<g&&0===E[b];b++);for(p<b&&(p=b),y=1,w=1;w<=_e;w++)if(y<<=1,y-=E[w],y<0)return-1;if(y>0&&(0===t||1!==g))return-1;for(R[1]=0,w=1;w<_e;w++)R[w+1]=R[w]+E[w];for(m=0;m<i;m++)0!==e[a+m]&&(r[R[e[a+m]]++]=m);if(0===t?(A=D=r,u=20):1===t?(A=fe,D=ce,u=257):(A=ue,D=we,u=0),z=0,m=0,w=b,c=s,k=p,v=0,_=-1,x=1<<p,f=x-1,1===t&&x>852||2===t&&x>592)return 1;for(;;){Z=w-v,r[m]+1<u?(U=0,S=r[m]):r[m]>=u?(U=D[r[m]-u],S=A[r[m]-u]):(U=96,S=0),h=1<<w-v,d=1<<k,b=d;do{d-=h,n[c+(z>>v)+d]=Z<<24|U<<16|S|0}while(0!==d);for(h=1<<w-1;z&h;)h>>=1;if(0!==h?(z&=h-1,z+=h):z=0,m++,0==--E[w]){if(w===g)break;w=e[a+r[m]]}if(w>p&&(z&f)!==_){for(0===v&&(v=p),c+=b,k=w-v,y=1<<k;k+v<g&&(y-=E[k+v],!(y<=0));)k++,y<<=1;if(x+=1<<k,1===t&&x>852||2===t&&x>592)return 1;_=z&f,n[_]=p<<24|k<<16|c-s|0}}return 0!==z&&(n[c+z]=w-v<<24|64<<16|0),o.bits=p,0};const{Z_FINISH:be,Z_BLOCK:ge,Z_TREES:pe,Z_OK:ke,Z_STREAM_END:ve,Z_NEED_DICT:ye,Z_STREAM_ERROR:xe,Z_DATA_ERROR:ze,Z_MEM_ERROR:Ae,Z_BUF_ERROR:Ee,Z_DEFLATED:Re}=K,Ze=16180,Ue=16190,Se=16191,De=16192,Te=16194,Oe=16199,Ie=16200,Fe=16206,Le=16209,Ne=t=>(t>>>24&255)+(t>>>8&65280)+((65280&t)<<8)+((255&t)<<24);function Be(){this.strm=null,this.mode=0,this.last=!1,this.wrap=0,this.havedict=!1,this.flags=0,this.dmax=0,this.check=0,this.total=0,this.head=null,this.wbits=0,this.wsize=0,this.whave=0,this.wnext=0,this.window=null,this.hold=0,this.bits=0,this.length=0,this.offset=0,this.extra=0,this.lencode=null,this.distcode=null,this.lenbits=0,this.distbits=0,this.ncode=0,this.nlen=0,this.ndist=0,this.have=0,this.next=null,this.lens=new Uint16Array(320),this.work=new Uint16Array(288),this.lendyn=null,this.distdyn=null,this.sane=0,this.back=0,this.was=0}const Ce=t=>{if(!t)return 1;const e=t.state;return!e||e.strm!==t||e.mode<Ze||e.mode>16211?1:0},Me=t=>{if(Ce(t))return xe;const e=t.state;return t.total_in=t.total_out=e.total=0,t.msg="",e.wrap&&(t.adler=1&e.wrap),e.mode=Ze,e.last=0,e.havedict=0,e.flags=-1,e.dmax=32768,e.head=null,e.hold=0,e.bits=0,e.lencode=e.lendyn=new Int32Array(852),e.distcode=e.distdyn=new Int32Array(592),e.sane=1,e.back=-1,ke},He=t=>{if(Ce(t))return xe;const e=t.state;return e.wsize=0,e.whave=0,e.wnext=0,Me(t)},je=(t,e)=>{let a;if(Ce(t))return xe;const i=t.state;return e<0?(a=0,e=-e):(a=5+(e>>4),e<48&&(e&=15)),e&&(e<8||e>15)?xe:(null!==i.window&&i.wbits!==e&&(i.window=null),i.wrap=a,i.wbits=e,He(t))},Ke=(t,e)=>{if(!t)return xe;const a=new Be;t.state=a,a.strm=t,a.window=null,a.mode=Ze;const i=je(t,e);return i!==ke&&(t.state=null),i};let Pe,Ye,Ge=!0;const Xe=t=>{if(Ge){Pe=new Int32Array(512),Ye=new Int32Array(32);let e=0;for(;e<144;)t.lens[e++]=8;for(;e<256;)t.lens[e++]=9;for(;e<280;)t.lens[e++]=7;for(;e<288;)t.lens[e++]=8;for(me(1,t.lens,0,288,Pe,0,t.work,{bits:9}),e=0;e<32;)t.lens[e++]=5;me(2,t.lens,0,32,Ye,0,t.work,{bits:5}),Ge=!1}t.lencode=Pe,t.lenbits=9,t.distcode=Ye,t.distbits=5},We=(t,e,a,i)=>{let n;const s=t.state;return null===s.window&&(s.wsize=1<<s.wbits,s.wnext=0,s.whave=0,s.window=new Uint8Array(s.wsize)),i>=s.wsize?(s.window.set(e.subarray(a-s.wsize,a),0),s.wnext=0,s.whave=s.wsize):(n=s.wsize-s.wnext,n>i&&(n=i),s.window.set(e.subarray(a-i,a-i+n),s.wnext),(i-=n)?(s.window.set(e.subarray(a-i,a),0),s.wnext=i,s.whave=s.wsize):(s.wnext+=n,s.wnext===s.wsize&&(s.wnext=0),s.whave<s.wsize&&(s.whave+=n))),0};var qe={inflateReset:He,inflateReset2:je,inflateResetKeep:Me,inflateInit:t=>Ke(t,15),inflateInit2:Ke,inflate:(t,e)=>{let a,i,n,s,r,o,l,h,d,_,f,c,u,w,m,b,g,p,k,v,y,x,z=0;const A=new Uint8Array(4);let E,R;const Z=new Uint8Array([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]);if(Ce(t)||!t.output||!t.input&&0!==t.avail_in)return xe;a=t.state,a.mode===Se&&(a.mode=De),r=t.next_out,n=t.output,l=t.avail_out,s=t.next_in,i=t.input,o=t.avail_in,h=a.hold,d=a.bits,_=o,f=l,x=ke;t:for(;;)switch(a.mode){case Ze:if(0===a.wrap){a.mode=De;break}for(;d<16;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(2&a.wrap&&35615===h){0===a.wbits&&(a.wbits=15),a.check=0,A[0]=255&h,A[1]=h>>>8&255,a.check=H(a.check,A,2,0),h=0,d=0,a.mode=16181;break}if(a.head&&(a.head.done=!1),!(1&a.wrap)||(((255&h)<<8)+(h>>8))%31){t.msg="incorrect header check",a.mode=Le;break}if((15&h)!==Re){t.msg="unknown compression method",a.mode=Le;break}if(h>>>=4,d-=4,y=8+(15&h),0===a.wbits&&(a.wbits=y),y>15||y>a.wbits){t.msg="invalid window size",a.mode=Le;break}a.dmax=1<<a.wbits,a.flags=0,t.adler=a.check=1,a.mode=512&h?16189:Se,h=0,d=0;break;case 16181:for(;d<16;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(a.flags=h,(255&a.flags)!==Re){t.msg="unknown compression method",a.mode=Le;break}if(57344&a.flags){t.msg="unknown header flags set",a.mode=Le;break}a.head&&(a.head.text=h>>8&1),512&a.flags&&4&a.wrap&&(A[0]=255&h,A[1]=h>>>8&255,a.check=H(a.check,A,2,0)),h=0,d=0,a.mode=16182;case 16182:for(;d<32;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.head&&(a.head.time=h),512&a.flags&&4&a.wrap&&(A[0]=255&h,A[1]=h>>>8&255,A[2]=h>>>16&255,A[3]=h>>>24&255,a.check=H(a.check,A,4,0)),h=0,d=0,a.mode=16183;case 16183:for(;d<16;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.head&&(a.head.xflags=255&h,a.head.os=h>>8),512&a.flags&&4&a.wrap&&(A[0]=255&h,A[1]=h>>>8&255,a.check=H(a.check,A,2,0)),h=0,d=0,a.mode=16184;case 16184:if(1024&a.flags){for(;d<16;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.length=h,a.head&&(a.head.extra_len=h),512&a.flags&&4&a.wrap&&(A[0]=255&h,A[1]=h>>>8&255,a.check=H(a.check,A,2,0)),h=0,d=0}else a.head&&(a.head.extra=null);a.mode=16185;case 16185:if(1024&a.flags&&(c=a.length,c>o&&(c=o),c&&(a.head&&(y=a.head.extra_len-a.length,a.head.extra||(a.head.extra=new Uint8Array(a.head.extra_len)),a.head.extra.set(i.subarray(s,s+c),y)),512&a.flags&&4&a.wrap&&(a.check=H(a.check,i,c,s)),o-=c,s+=c,a.length-=c),a.length))break t;a.length=0,a.mode=16186;case 16186:if(2048&a.flags){if(0===o)break t;c=0;do{y=i[s+c++],a.head&&y&&a.length<65536&&(a.head.name+=String.fromCharCode(y))}while(y&&c<o);if(512&a.flags&&4&a.wrap&&(a.check=H(a.check,i,c,s)),o-=c,s+=c,y)break t}else a.head&&(a.head.name=null);a.length=0,a.mode=16187;case 16187:if(4096&a.flags){if(0===o)break t;c=0;do{y=i[s+c++],a.head&&y&&a.length<65536&&(a.head.comment+=String.fromCharCode(y))}while(y&&c<o);if(512&a.flags&&4&a.wrap&&(a.check=H(a.check,i,c,s)),o-=c,s+=c,y)break t}else a.head&&(a.head.comment=null);a.mode=16188;case 16188:if(512&a.flags){for(;d<16;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(4&a.wrap&&h!==(65535&a.check)){t.msg="header crc mismatch",a.mode=Le;break}h=0,d=0}a.head&&(a.head.hcrc=a.flags>>9&1,a.head.done=!0),t.adler=a.check=0,a.mode=Se;break;case 16189:for(;d<32;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}t.adler=a.check=Ne(h),h=0,d=0,a.mode=Ue;case Ue:if(0===a.havedict)return t.next_out=r,t.avail_out=l,t.next_in=s,t.avail_in=o,a.hold=h,a.bits=d,ye;t.adler=a.check=1,a.mode=Se;case Se:if(e===ge||e===pe)break t;case De:if(a.last){h>>>=7&d,d-=7&d,a.mode=Fe;break}for(;d<3;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}switch(a.last=1&h,h>>>=1,d-=1,3&h){case 0:a.mode=16193;break;case 1:if(Xe(a),a.mode=Oe,e===pe){h>>>=2,d-=2;break t}break;case 2:a.mode=16196;break;case 3:t.msg="invalid block type",a.mode=Le}h>>>=2,d-=2;break;case 16193:for(h>>>=7&d,d-=7&d;d<32;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if((65535&h)!=(h>>>16^65535)){t.msg="invalid stored block lengths",a.mode=Le;break}if(a.length=65535&h,h=0,d=0,a.mode=Te,e===pe)break t;case Te:a.mode=16195;case 16195:if(c=a.length,c){if(c>o&&(c=o),c>l&&(c=l),0===c)break t;n.set(i.subarray(s,s+c),r),o-=c,s+=c,l-=c,r+=c,a.length-=c;break}a.mode=Se;break;case 16196:for(;d<14;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(a.nlen=257+(31&h),h>>>=5,d-=5,a.ndist=1+(31&h),h>>>=5,d-=5,a.ncode=4+(15&h),h>>>=4,d-=4,a.nlen>286||a.ndist>30){t.msg="too many length or distance symbols",a.mode=Le;break}a.have=0,a.mode=16197;case 16197:for(;a.have<a.ncode;){for(;d<3;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.lens[Z[a.have++]]=7&h,h>>>=3,d-=3}for(;a.have<19;)a.lens[Z[a.have++]]=0;if(a.lencode=a.lendyn,a.lenbits=7,E={bits:a.lenbits},x=me(0,a.lens,0,19,a.lencode,0,a.work,E),a.lenbits=E.bits,x){t.msg="invalid code lengths set",a.mode=Le;break}a.have=0,a.mode=16198;case 16198:for(;a.have<a.nlen+a.ndist;){for(;z=a.lencode[h&(1<<a.lenbits)-1],m=z>>>24,b=z>>>16&255,g=65535&z,!(m<=d);){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(g<16)h>>>=m,d-=m,a.lens[a.have++]=g;else{if(16===g){for(R=m+2;d<R;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(h>>>=m,d-=m,0===a.have){t.msg="invalid bit length repeat",a.mode=Le;break}y=a.lens[a.have-1],c=3+(3&h),h>>>=2,d-=2}else if(17===g){for(R=m+3;d<R;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}h>>>=m,d-=m,y=0,c=3+(7&h),h>>>=3,d-=3}else{for(R=m+7;d<R;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}h>>>=m,d-=m,y=0,c=11+(127&h),h>>>=7,d-=7}if(a.have+c>a.nlen+a.ndist){t.msg="invalid bit length repeat",a.mode=Le;break}for(;c--;)a.lens[a.have++]=y}}if(a.mode===Le)break;if(0===a.lens[256]){t.msg="invalid code -- missing end-of-block",a.mode=Le;break}if(a.lenbits=9,E={bits:a.lenbits},x=me(1,a.lens,0,a.nlen,a.lencode,0,a.work,E),a.lenbits=E.bits,x){t.msg="invalid literal/lengths set",a.mode=Le;break}if(a.distbits=6,a.distcode=a.distdyn,E={bits:a.distbits},x=me(2,a.lens,a.nlen,a.ndist,a.distcode,0,a.work,E),a.distbits=E.bits,x){t.msg="invalid distances set",a.mode=Le;break}if(a.mode=Oe,e===pe)break t;case Oe:a.mode=Ie;case Ie:if(o>=6&&l>=258){t.next_out=r,t.avail_out=l,t.next_in=s,t.avail_in=o,a.hold=h,a.bits=d,de(t,f),r=t.next_out,n=t.output,l=t.avail_out,s=t.next_in,i=t.input,o=t.avail_in,h=a.hold,d=a.bits,a.mode===Se&&(a.back=-1);break}for(a.back=0;z=a.lencode[h&(1<<a.lenbits)-1],m=z>>>24,b=z>>>16&255,g=65535&z,!(m<=d);){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(b&&0==(240&b)){for(p=m,k=b,v=g;z=a.lencode[v+((h&(1<<p+k)-1)>>p)],m=z>>>24,b=z>>>16&255,g=65535&z,!(p+m<=d);){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}h>>>=p,d-=p,a.back+=p}if(h>>>=m,d-=m,a.back+=m,a.length=g,0===b){a.mode=16205;break}if(32&b){a.back=-1,a.mode=Se;break}if(64&b){t.msg="invalid literal/length code",a.mode=Le;break}a.extra=15&b,a.mode=16201;case 16201:if(a.extra){for(R=a.extra;d<R;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.length+=h&(1<<a.extra)-1,h>>>=a.extra,d-=a.extra,a.back+=a.extra}a.was=a.length,a.mode=16202;case 16202:for(;z=a.distcode[h&(1<<a.distbits)-1],m=z>>>24,b=z>>>16&255,g=65535&z,!(m<=d);){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(0==(240&b)){for(p=m,k=b,v=g;z=a.distcode[v+((h&(1<<p+k)-1)>>p)],m=z>>>24,b=z>>>16&255,g=65535&z,!(p+m<=d);){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}h>>>=p,d-=p,a.back+=p}if(h>>>=m,d-=m,a.back+=m,64&b){t.msg="invalid distance code",a.mode=Le;break}a.offset=g,a.extra=15&b,a.mode=16203;case 16203:if(a.extra){for(R=a.extra;d<R;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}a.offset+=h&(1<<a.extra)-1,h>>>=a.extra,d-=a.extra,a.back+=a.extra}if(a.offset>a.dmax){t.msg="invalid distance too far back",a.mode=Le;break}a.mode=16204;case 16204:if(0===l)break t;if(c=f-l,a.offset>c){if(c=a.offset-c,c>a.whave&&a.sane){t.msg="invalid distance too far back",a.mode=Le;break}c>a.wnext?(c-=a.wnext,u=a.wsize-c):u=a.wnext-c,c>a.length&&(c=a.length),w=a.window}else w=n,u=r-a.offset,c=a.length;c>l&&(c=l),l-=c,a.length-=c;do{n[r++]=w[u++]}while(--c);0===a.length&&(a.mode=Ie);break;case 16205:if(0===l)break t;n[r++]=a.length,l--,a.mode=Ie;break;case Fe:if(a.wrap){for(;d<32;){if(0===o)break t;o--,h|=i[s++]<<d,d+=8}if(f-=l,t.total_out+=f,a.total+=f,4&a.wrap&&f&&(t.adler=a.check=a.flags?H(a.check,n,f,r-f):C(a.check,n,f,r-f)),f=l,4&a.wrap&&(a.flags?h:Ne(h))!==a.check){t.msg="incorrect data check",a.mode=Le;break}h=0,d=0}a.mode=16207;case 16207:if(a.wrap&&a.flags){for(;d<32;){if(0===o)break t;o--,h+=i[s++]<<d,d+=8}if(4&a.wrap&&h!==(4294967295&a.total)){t.msg="incorrect length check",a.mode=Le;break}h=0,d=0}a.mode=16208;case 16208:x=ve;break t;case Le:x=ze;break t;case 16210:return Ae;default:return xe}return t.next_out=r,t.avail_out=l,t.next_in=s,t.avail_in=o,a.hold=h,a.bits=d,(a.wsize||f!==t.avail_out&&a.mode<Le&&(a.mode<Fe||e!==be))&&We(t,t.output,t.next_out,f-t.avail_out),_-=t.avail_in,f-=t.avail_out,t.total_in+=_,t.total_out+=f,a.total+=f,4&a.wrap&&f&&(t.adler=a.check=a.flags?H(a.check,n,f,t.next_out-f):C(a.check,n,f,t.next_out-f)),t.data_type=a.bits+(a.last?64:0)+(a.mode===Se?128:0)+(a.mode===Oe||a.mode===Te?256:0),(0===_&&0===f||e===be)&&x===ke&&(x=Ee),x},inflateEnd:t=>{if(Ce(t))return xe;let e=t.state;return e.window&&(e.window=null),t.state=null,ke},inflateGetHeader:(t,e)=>{if(Ce(t))return xe;const a=t.state;return 0==(2&a.wrap)?xe:(a.head=e,e.done=!1,ke)},inflateSetDictionary:(t,e)=>{const a=e.length;let i,n,s;return Ce(t)?xe:(i=t.state,0!==i.wrap&&i.mode!==Ue?xe:i.mode===Ue&&(n=1,n=C(n,e,a,0),n!==i.check)?ze:(s=We(t,e,a,a),s?(i.mode=16210,Ae):(i.havedict=1,ke)))},inflateInfo:"pako inflate (from Nodeca project)"};var Je=function(){this.text=0,this.time=0,this.xflags=0,this.os=0,this.extra=null,this.extra_len=0,this.name="",this.comment="",this.hcrc=0,this.done=!1};const Qe=Object.prototype.toString,{Z_NO_FLUSH:Ve,Z_FINISH:$e,Z_OK:ta,Z_STREAM_END:ea,Z_NEED_DICT:aa,Z_STREAM_ERROR:ia,Z_DATA_ERROR:na,Z_MEM_ERROR:sa}=K;function ra(t){this.options=jt({chunkSize:65536,windowBits:15,to:""},t||{});const e=this.options;e.raw&&e.windowBits>=0&&e.windowBits<16&&(e.windowBits=-e.windowBits,0===e.windowBits&&(e.windowBits=-15)),!(e.windowBits>=0&&e.windowBits<16)||t&&t.windowBits||(e.windowBits+=32),e.windowBits>15&&e.windowBits<48&&0==(15&e.windowBits)&&(e.windowBits|=15),this.err=0,this.msg="",this.ended=!1,this.chunks=[],this.strm=new qt,this.strm.avail_out=0;let a=qe.inflateInit2(this.strm,e.windowBits);if(a!==ta)throw new Error(j[a]);if(this.header=new Je,qe.inflateGetHeader(this.strm,this.header),e.dictionary&&("string"==typeof e.dictionary?e.dictionary=Gt(e.dictionary):"[object ArrayBuffer]"===Qe.call(e.dictionary)&&(e.dictionary=new Uint8Array(e.dictionary)),e.raw&&(a=qe.inflateSetDictionary(this.strm,e.dictionary),a!==ta)))throw new Error(j[a])}function oa(t,e){const a=new ra(e);if(a.push(t),a.err)throw a.msg||j[a.err];return a.result}ra.prototype.push=function(t,e){const a=this.strm,i=this.options.chunkSize,n=this.options.dictionary;let s,r,o;if(this.ended)return!1;for(r=e===~~e?e:!0===e?$e:Ve,"[object ArrayBuffer]"===Qe.call(t)?a.input=new Uint8Array(t):a.input=t,a.next_in=0,a.avail_in=a.input.length;;){for(0===a.avail_out&&(a.output=new Uint8Array(i),a.next_out=0,a.avail_out=i),s=qe.inflate(a,r),s===aa&&n&&(s=qe.inflateSetDictionary(a,n),s===ta?s=qe.inflate(a,r):s===na&&(s=aa));a.avail_in>0&&s===ea&&a.state.wrap>0&&0!==t[a.next_in];)qe.inflateReset(a),s=qe.inflate(a,r);switch(s){case ia:case na:case aa:case sa:return this.onEnd(s),this.ended=!0,!1}if(o=a.avail_out,a.next_out&&(0===a.avail_out||s===ea))if("string"===this.options.to){let t=Wt(a.output,a.next_out),e=a.next_out-t,n=Xt(a.output,t);a.next_out=e,a.avail_out=i-e,e&&a.output.set(a.output.subarray(t,t+e),0),this.onData(n)}else this.onData(a.output.length===a.next_out?a.output:a.output.subarray(0,a.next_out));if(s!==ta||0!==o){if(s===ea)return s=qe.inflateEnd(this.strm),this.onEnd(s),this.ended=!0,!0;if(0===a.avail_in)break}}return!0},ra.prototype.onData=function(t){this.chunks.push(t)},ra.prototype.onEnd=function(t){t===ta&&("string"===this.options.to?this.result=this.chunks.join(""):this.result=Kt(this.chunks)),this.chunks=[],this.err=t,this.msg=this.strm.msg};var la={Inflate:ra,inflate:oa,inflateRaw:function(t,e){return(e=e||{}).raw=!0,oa(t,e)},ungzip:oa,constants:K};const{Deflate:ha,deflate:da,deflateRaw:_a,gzip:fa}=le,{Inflate:ca,inflate:ua,inflateRaw:wa,ungzip:ma}=la;var ba=ha,ga=da,pa=_a,ka=fa,va=ca,ya=ua,xa=wa,za=ma,Aa=K,Ea={Deflate:ba,deflate:ga,deflateRaw:pa,gzip:ka,Inflate:va,inflate:ya,inflateRaw:xa,ungzip:za,constants:Aa};t.Deflate=ba,t.Inflate=va,t.constants=Aa,t.default=Ea,t.deflate=ga,t.deflateRaw=pa,t.gzip=ka,t.inflate=ya,t.inflateRaw=xa,t.ungzip=za,Object.defineProperty(t,"__esModule",{value:!0})}));

})(module,exports); return module.exports; })();
// ============================================================================
// shim/01_http.js — 把 OK 宿主的同步 req 包装成猫源期待的 fetch / __CAT_JS_UTIL
// ----------------------------------------------------------------------------
// OK 宿主（已核实 Connect.java + http.js + Req.java）：
//   req(url, opts) 同步; opts{ method, headers, body, data, postType, buffer, charset, timeout, redirect, async:false }
//   返回 { code(数字), headers(对象), content }
//   失败 → { code:'', headers:{}, content:'' }
//   buffer: 0=字符串(默认, 按 charset 解码) 1=有符号字节数组 2=base64 3=bytes
// ★ 不主动设 Accept-Encoding —— 让 OkHttp 自己加 gzip 并透明解压（手动设会导致解压丢失）
// ============================================================================

function __okHostReq() {
  try { if (typeof req === 'function') return req; } catch (e) { }
  try { if (typeof globalThis.req === 'function') return globalThis.req; } catch (e) { }
  return null;
}

// ---------- 统一底层请求：返回 {status, headers, bytes, text} ----------
function __okRaw(url, opt) {
  opt = opt || {};
  var H = __okHostReq();
  if (!H) throw new Error('no host req');
  var method = String(opt.method || 'GET').toUpperCase();
  var headers = {};
  var k;
  for (k in (opt.headers || {})) {
    var hv = opt.headers[k];
    if (hv !== undefined && hv !== null && hv !== '') headers[k] = String(hv);
  }
  var o = { method: method, headers: headers, timeout: opt.timeout || 20000, redirect: 1 };
  var body = (opt.body !== undefined) ? opt.body : opt.data;
  var wasBytes = false;
  if (body != null) {
    if (typeof body === 'string') o.body = body;
    else if (__okIsBytes(body)) { o.body = new __OkBuffer(body).toString('binary'); wasBytes = true; }
    else o.body = String(body);
  }
  // ★ E-020: 二进制 body 必须让壳按 latin1 编码，否则高位字节被 UTF-8 化 → 上游解密失败
  if (wasBytes) {
    var hasCT = false, ctKey = null;
    for (var hk in o.headers) if (String(hk).toLowerCase() === 'content-type') { hasCT = true; ctKey = hk; }
    if (!hasCT) { o.headers['Content-Type'] = 'application/octet-stream; charset=ISO-8859-1'; }
    else if (String(o.headers[ctKey]).indexOf('charset') < 0) { o.headers[ctKey] = String(o.headers[ctKey]) + '; charset=ISO-8859-1'; }
  }
  if (opt.binary) o.buffer = 2;              // 拿原始字节（base64），自己解
  else o.buffer = 0;
  var r;
  try { r = H(url, o); } catch (e) { throw e; }
  if (!r || r.code === '' || r.code === undefined || r.code === null) {
    throw new Error('request failed: ' + url);
  }
  var bytes;
  if (opt.binary) bytes = __okUnb64(String(r.content || ''));
  else bytes = __okUtf8Bytes(String(r.content == null ? '' : r.content));
  return {
    status: Number(r.code), headers: r.headers || {}, bytes: bytes,
    text: opt.binary ? __okUtf8FromBytes(bytes) : String(r.content == null ? '' : r.content)
  };
}

// ---------- fetch 兼容层 ----------
function __OkHeaders(h) {
  this._h = {};
  var self = this;
  for (var k in (h || {})) {
    var lk = String(k).toLowerCase();
    var v = h[k];
    self._h[lk] = Array.isArray(v) ? v.join(', ') : String(v == null ? '' : v);
  }
}
__OkHeaders.prototype.get = function (n) { var v = this._h[String(n).toLowerCase()]; return v === undefined ? null : v; };
__OkHeaders.prototype.has = function (n) { return this._h[String(n).toLowerCase()] !== undefined; };
__OkHeaders.prototype.forEach = function (cb) { for (var k in this._h) cb(this._h[k], k); };
__OkHeaders.prototype.entries = function () { return Object.keys(this._h).map(function (k) { return [k, this._h[k]]; }, this); };
__OkHeaders.prototype.all = function () { return this._h; };
__OkHeaders.prototype.keys = function () { return Object.keys(this._h); };

function __OkResponse(raw) {
  this.status = raw.status;
  this.ok = raw.status >= 200 && raw.status < 300;
  this.statusText = '';
  this.headers = new __OkHeaders(raw.headers);
  this._bytes = raw.bytes;
  this._text = raw.text;
  this.bodyUsed = false;
}
__OkResponse.prototype.text = function () {
  var self = this;
  return Promise.resolve().then(function () { self.bodyUsed = true; return self._text; });
};
__OkResponse.prototype.json = function () {
  var self = this;
  return Promise.resolve().then(function () { self.bodyUsed = true; var t = self._text; try { return JSON.parse(t); } catch (e) { return null; } });
};
__OkResponse.prototype.arrayBuffer = function () {
  var self = this;
  return Promise.resolve().then(function () {
    self.bodyUsed = true;
    var u = new Uint8Array(self._bytes.length), i;
    for (i = 0; i < self._bytes.length; i++) u[i] = self._bytes[i] & 0xFF;
    return u.buffer;
  });
};
__OkResponse.prototype.blob = function () { return this.arrayBuffer(); };
__OkResponse.prototype.clone = function () {
  return new __OkResponse({ status: this.status, headers: this.headers.all(), bytes: this._bytes, text: this._text });
};
// 让源里 `Buffer.from(r.data)` 这类也能工作（r.data 在 _fh 里是已解析对象）

function fetch(url, opts) {
  opts = opts || {};
  return new Promise(function (resolve, reject) {
    try {
      // ★ 一律走 binary（buffer:2）拿原始字节，避免壳按 UTF-8 解坏 protobuf/加密响应
      var raw = __okRaw(url, {
        method: opts.method || 'GET',
        headers: opts.headers || {},
        body: opts.body,
        timeout: opts.timeout || 20000,
        binary: true
      });
      resolve(new __OkResponse(raw));
    } catch (e) { reject(e); }
  });
}

// ---------- AbortController 替身（源里只用它做超时；这里超时由 req 自己管）----------
function AbortSignal() { this.aborted = false; this._cbs = []; }
AbortSignal.prototype.addEventListener = function (t, cb) { if (t === 'abort') this._cbs.push(cb); };
AbortSignal.prototype.removeEventListener = function () { };
function AbortController() { this.signal = new AbortSignal(); }
AbortController.prototype.abort = function () {
  if (this.signal.aborted) return;
  this.signal.aborted = true;
  for (var i = 0; i < this.signal._cbs.length; i++) { try { this.signal._cbs[i](); } catch (e) { } }
};

// ---------- URL 替身（源里只用 new URL(x) 取 host/protocol）----------
function __OkURL(u) {
  u = String(u || '');
  var m = u.match(/^([a-zA-Z][\w+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/);
  this.href = u;
  this.protocol = m ? (m[1] + ':') : '';
  this.host = m ? m[2] : '';
  this.hostname = m ? String(m[2]).replace(/:\d+$/, '') : '';
  this.port = (m && String(m[2]).indexOf(':') >= 0) ? String(m[2]).split(':').pop() : '';
  this.pathname = m ? (m[3] || '') : u;
  this.search = (m && m[4]) ? m[4] : '';
  this.hash = (m && m[5]) ? m[5] : '';
  this.origin = m ? (m[1] + '://' + m[2]) : '';
  this.toString = function () { return u; };
}
__OkURL.prototype.toString = function () { return this.href; };
function URLSearchParams(qs) {
  this._m = {};
  qs = String(qs || '').replace(/^\?/, '');
  if (qs) qs.split('&').forEach(function (kv) { var i = kv.indexOf('='); if (i < 0) i = kv.length; var k = kv.slice(0, i); try { this._m[decodeURIComponent(k)] = decodeURIComponent(kv.slice(i + 1)); } catch (e) { this._m[k] = kv.slice(i + 1); } }, this);
}
URLSearchParams.prototype.get = function (k) { return (k in this._m) ? this._m[k] : null; };
URLSearchParams.prototype.has = function (k) { return k in this._m; };
URLSearchParams.prototype.set = function (k, v) { this._m[k] = String(v); };
URLSearchParams.prototype.append = function (k, v) { this._m[k] = String(v); };
URLSearchParams.prototype.toString = function () {
  var out = [];
  for (var k in this._m) out.push(encodeURIComponent(k) + '=' + encodeURIComponent(this._m[k]));
  return out.join('&');
};

// ---------- require() 替身（源里 require("crypto"/"zlib"/"http"/"https"/"url"...)）----------
function __okRequire(name) {
  var n = String(name).replace(/^node:/, '');
  if (n === 'crypto') return __OK_NODE_CRYPTO;
  if (n === 'zlib') return __OK_ZLIB;
  if (n === 'https' || n === 'http') return __OK_HTTPMOD;
  if (n === 'url') return { URL: __OkURL };
  if (n === 'buffer') return { Buffer: __OkBuffer };
  if (n === 'querystring') return { stringify: function (o) { return new URLSearchParams(o).toString(); } };
  if (__OK_EXTRA_MODULES && __OK_EXTRA_MODULES[n]) return __OK_EXTRA_MODULES[n];
  throw new Error('require not available in OK shell: ' + name);
}

// ---------- __CAT_JS_UTIL 注入（猫源的核心依赖表）----------
function __okInstallUtil() {
  var U = (typeof globalThis !== 'undefined' && globalThis.__CAT_JS_UTIL) || {};
  U['crypto-js'] = __OK_CRYPTOJS;
  U['node:crypto'] = __OK_NODE_CRYPTO;
  U['crypto'] = __OK_NODE_CRYPTO;
  U['zlib'] = __OK_ZLIB;
  U['node:zlib'] = __OK_ZLIB;
  U['node:https'] = __OK_HTTPS;
  U['https'] = __OK_HTTPS;
  U['node:http'] = __OK_HTTPMOD;
  U['http'] = __OK_HTTPMOD;
  U['buffer'] = { Buffer: __OkBuffer };
  U['url'] = { URL: __OkURL };
  U['util/req.js'] = __OK_AXIOS;
  U['util/misc.js'] = { UA: 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36', IOS_UA: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1' };
  try { globalThis.__CAT_JS_UTIL = U; } catch (e) { }
  return U;
}

// ---------- 全局挂载 ----------
try {
  globalThis.fetch = fetch;
  globalThis.Headers = __OkHeaders;
  globalThis.Response = __OkResponse;
  globalThis.Request = function () { };
  globalThis.AbortController = AbortController;
  globalThis.AbortSignal = AbortSignal;
  globalThis.URL = __OkURL;
  globalThis.URLSearchParams = URLSearchParams;
  globalThis.require = __okRequire;
  globalThis.global = globalThis;
  globalThis.window = globalThis;
  globalThis.self = globalThis;
  globalThis.process = (typeof process !== 'undefined') ? process : { env: {}, version: 'v18', platform: 'android', nextTick: function (f) { setTimeout(f, 0); }, exit: function () { }, argv: [] };
  globalThis.setState = globalThis.setState || function () { };
} catch (e) { }
// __okInstallUtil 在 02_crypto.js 末尾调用（依赖 __OK_CRYPTOJS 等定义）

// ============================================================================
// shim/02_crypto.js — __OK_NODE_CRYPTO (require('crypto') 替身) + __OK_CRYPTOJS
// 依赖: 00_bytes.js (Buffer/atob/btoa/字节助手), x25519_raw.js (X25519)
// 复用: ek-to-ok __rsaJS (纯 JS RSA PKCS1, 137 项自检通过) + __gcm (AES-256-GCM)
// ============================================================================
// ★ 注: __rsaJS / __gcm / X25519 由构建脚本在前面拼接（各含独立 KAT）
//   本文件只做「Node crypto API 形状」的包装。

// ---------- mini-crypto 字节级助手（供 Node-crypto API 形状包装用）----------
// 来自 ok-video-source/scripts/mini_crypto.js (36/36 KAT)；这里直接内联字节接口
function Mc_Hex(bytes) { var s = "", i; for (i = 0; i < bytes.length; i++) s += ("0" + bytes[i].toString(16)).slice(-2); return s; }
function Mc_Md5(msg) { return __OK_MC_MD5(__okToArr(msg)); }
function Mc_Sha1(msg) { return __OK_MC_SHA1(__okToArr(msg)); }
function Mc_Sha256(msg) { return __OK_MC_SHA256(__okToArr(msg)); }
function Mc_HmacSha256(key, msg) { return __OK_MC_HMAC256(__okToArr(key), __okToArr(msg)); }
// __OK_MC_* 由构建脚本从 mini_crypto.js 提取注入（md5Bytes/sha1Bytes/sha256Bytes/hmacSha256Bytes 的别名）

// ---------- __OK_CRYPTOJS: 壳 cat.js 的 Crypto 或内置 crypto-js ----------
// 构建脚本会先尝试 import { Crypto } from 'assets://js/lib/cat.js' (首选, 完整实现)
// 失败则内联 vendor/crypto-js.js (UMD, 需要 module.exports 出口 —— 我们给它造一个)
var __OK_CRYPTOJS = (function () {
  try {
    if (typeof globalThis !== 'undefined' && globalThis.Crypto && globalThis.Crypto.AES) return globalThis.Crypto;
  } catch (e) { }
  // crypto-js UMD 注入: 造 module/exports 再执行 vendor 文本
  try {
    var __mod = { exports: null };
    (function (module, exports) { ;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		module.exports = exports = factory();
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define([], factory);
	}
	else {
		// Global (browser)
		root.CryptoJS = factory();
	}
}(this, function () {

	/*globals window, global, require*/

	/**
	 * CryptoJS core components.
	 */
	var CryptoJS = CryptoJS || (function (Math, undefined) {

	    var crypto;

	    // Native crypto from window (Browser)
	    if (typeof window !== 'undefined' && window.crypto) {
	        crypto = window.crypto;
	    }

	    // Native crypto in web worker (Browser)
	    if (typeof self !== 'undefined' && self.crypto) {
	        crypto = self.crypto;
	    }

	    // Native crypto from worker
	    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
	        crypto = globalThis.crypto;
	    }

	    // Native (experimental IE 11) crypto from window (Browser)
	    if (!crypto && typeof window !== 'undefined' && window.msCrypto) {
	        crypto = window.msCrypto;
	    }

	    // Native crypto from global (NodeJS)
	    if (!crypto && typeof global !== 'undefined' && global.crypto) {
	        crypto = global.crypto;
	    }

	    // Native crypto import via require (NodeJS)
	    if (!crypto && typeof require === 'function') {
	        try {
	            crypto = require('crypto');
	        } catch (err) {}
	    }

	    /*
	     * Cryptographically secure pseudorandom number generator
	     *
	     * As Math.random() is cryptographically not safe to use
	     */
	    var cryptoSecureRandomInt = function () {
	        if (crypto) {
	            // Use getRandomValues method (Browser)
	            if (typeof crypto.getRandomValues === 'function') {
	                try {
	                    return crypto.getRandomValues(new Uint32Array(1))[0];
	                } catch (err) {}
	            }

	            // Use randomBytes method (NodeJS)
	            if (typeof crypto.randomBytes === 'function') {
	                try {
	                    return crypto.randomBytes(4).readInt32LE();
	                } catch (err) {}
	            }
	        }

	        throw new Error('Native crypto module could not be used to get secure random number.');
	    };

	    /*
	     * Local polyfill of Object.create

	     */
	    var create = Object.create || (function () {
	        function F() {}

	        return function (obj) {
	            var subtype;

	            F.prototype = obj;

	            subtype = new F();

	            F.prototype = null;

	            return subtype;
	        };
	    }());

	    /**
	     * CryptoJS namespace.
	     */
	    var C = {};

	    /**
	     * Library namespace.
	     */
	    var C_lib = C.lib = {};

	    /**
	     * Base object for prototypal inheritance.
	     */
	    var Base = C_lib.Base = (function () {


	        return {
	            /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */
	            extend: function (overrides) {
	                // Spawn
	                var subtype = create(this);

	                // Augment
	                if (overrides) {
	                    subtype.mixIn(overrides);
	                }

	                // Create default initializer
	                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
	                    subtype.init = function () {
	                        subtype.$super.init.apply(this, arguments);
	                    };
	                }

	                // Initializer's prototype is the subtype object
	                subtype.init.prototype = subtype;

	                // Reference supertype
	                subtype.$super = this;

	                return subtype;
	            },

	            /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */
	            create: function () {
	                var instance = this.extend();
	                instance.init.apply(instance, arguments);

	                return instance;
	            },

	            /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */
	            init: function () {
	            },

	            /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */
	            mixIn: function (properties) {
	                for (var propertyName in properties) {
	                    if (properties.hasOwnProperty(propertyName)) {
	                        this[propertyName] = properties[propertyName];
	                    }
	                }

	                // IE won't copy toString using the loop above
	                if (properties.hasOwnProperty('toString')) {
	                    this.toString = properties.toString;
	                }
	            },

	            /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */
	            clone: function () {
	                return this.init.prototype.extend(this);
	            }
	        };
	    }());

	    /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var WordArray = C_lib.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 4;
	            }
	        },

	        /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */
	        toString: function (encoder) {
	            return (encoder || Hex).stringify(this);
	        },

	        /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */
	        concat: function (wordArray) {
	            // Shortcuts
	            var thisWords = this.words;
	            var thatWords = wordArray.words;
	            var thisSigBytes = this.sigBytes;
	            var thatSigBytes = wordArray.sigBytes;

	            // Clamp excess bits
	            this.clamp();

	            // Concat
	            if (thisSigBytes % 4) {
	                // Copy one byte at a time
	                for (var i = 0; i < thatSigBytes; i++) {
	                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
	                }
	            } else {
	                // Copy one word at a time
	                for (var j = 0; j < thatSigBytes; j += 4) {
	                    thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
	                }
	            }
	            this.sigBytes += thatSigBytes;

	            // Chainable
	            return this;
	        },

	        /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */
	        clamp: function () {
	            // Shortcuts
	            var words = this.words;
	            var sigBytes = this.sigBytes;

	            // Clamp
	            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
	            words.length = Math.ceil(sigBytes / 4);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone.words = this.words.slice(0);

	            return clone;
	        },

	        /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */
	        random: function (nBytes) {
	            var words = [];

	            for (var i = 0; i < nBytes; i += 4) {
	                words.push(cryptoSecureRandomInt());
	            }

	            return new WordArray.init(words, nBytes);
	        }
	    });

	    /**
	     * Encoder namespace.
	     */
	    var C_enc = C.enc = {};

	    /**
	     * Hex encoding strategy.
	     */
	    var Hex = C_enc.Hex = {
	        /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var hexChars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                hexChars.push((bite >>> 4).toString(16));
	                hexChars.push((bite & 0x0f).toString(16));
	            }

	            return hexChars.join('');
	        },

	        /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */
	        parse: function (hexStr) {
	            // Shortcut
	            var hexStrLength = hexStr.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < hexStrLength; i += 2) {
	                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
	            }

	            return new WordArray.init(words, hexStrLength / 2);
	        }
	    };

	    /**
	     * Latin1 encoding strategy.
	     */
	    var Latin1 = C_enc.Latin1 = {
	        /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var latin1Chars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                latin1Chars.push(String.fromCharCode(bite));
	            }

	            return latin1Chars.join('');
	        },

	        /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */
	        parse: function (latin1Str) {
	            // Shortcut
	            var latin1StrLength = latin1Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < latin1StrLength; i++) {
	                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
	            }

	            return new WordArray.init(words, latin1StrLength);
	        }
	    };

	    /**
	     * UTF-8 encoding strategy.
	     */
	    var Utf8 = C_enc.Utf8 = {
	        /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            try {
	                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
	            } catch (e) {
	                throw new Error('Malformed UTF-8 data');
	            }
	        },

	        /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */
	        parse: function (utf8Str) {
	            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	        }
	    };

	    /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
	        /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */
	        reset: function () {
	            // Initial values
	            this._data = new WordArray.init();
	            this._nDataBytes = 0;
	        },

	        /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */
	        _append: function (data) {
	            // Convert string to WordArray, else assume WordArray already
	            if (typeof data == 'string') {
	                data = Utf8.parse(data);
	            }

	            // Append
	            this._data.concat(data);
	            this._nDataBytes += data.sigBytes;
	        },

	        /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */
	        _process: function (doFlush) {
	            var processedWords;

	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var dataSigBytes = data.sigBytes;
	            var blockSize = this.blockSize;
	            var blockSizeBytes = blockSize * 4;

	            // Count blocks ready
	            var nBlocksReady = dataSigBytes / blockSizeBytes;
	            if (doFlush) {
	                // Round up to include partial blocks
	                nBlocksReady = Math.ceil(nBlocksReady);
	            } else {
	                // Round down to include only full blocks,
	                // less the number of blocks that must remain in the buffer
	                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
	            }

	            // Count words ready
	            var nWordsReady = nBlocksReady * blockSize;

	            // Count bytes ready
	            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

	            // Process blocks
	            if (nWordsReady) {
	                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
	                    // Perform concrete-algorithm logic
	                    this._doProcessBlock(dataWords, offset);
	                }

	                // Remove processed words
	                processedWords = dataWords.splice(0, nWordsReady);
	                data.sigBytes -= nBytesReady;
	            }

	            // Return processed words
	            return new WordArray.init(processedWords, nBytesReady);
	        },

	        /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone._data = this._data.clone();

	            return clone;
	        },

	        _minBufferSize: 0
	    });

	    /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */
	    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         */
	        cfg: Base.extend(),

	        /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */
	        init: function (cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-hasher logic
	            this._doReset();
	        },

	        /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            // Append
	            this._append(messageUpdate);

	            // Update the hash
	            this._process();

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Final message update
	            if (messageUpdate) {
	                this._append(messageUpdate);
	            }

	            // Perform concrete-hasher logic
	            var hash = this._doFinalize();

	            return hash;
	        },

	        blockSize: 512/32,

	        /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */
	        _createHelper: function (hasher) {
	            return function (message, cfg) {
	                return new hasher.init(cfg).finalize(message);
	            };
	        },

	        /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */
	        _createHmacHelper: function (hasher) {
	            return function (message, key) {
	                return new C_algo.HMAC.init(hasher, key).finalize(message);
	            };
	        }
	    });

	    /**
	     * Algorithm namespace.
	     */
	    var C_algo = C.algo = {};

	    return C;
	}(Math));


	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var X32WordArray = C_lib.WordArray;

	    /**
	     * x64 namespace.
	     */
	    var C_x64 = C.x64 = {};

	    /**
	     * A 64-bit word.
	     */
	    var X64Word = C_x64.Word = Base.extend({
	        /**
	         * Initializes a newly created 64-bit word.
	         *
	         * @param {number} high The high 32 bits.
	         * @param {number} low The low 32 bits.
	         *
	         * @example
	         *
	         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
	         */
	        init: function (high, low) {
	            this.high = high;
	            this.low = low;
	        }

	        /**
	         * Bitwise NOTs this word.
	         *
	         * @return {X64Word} A new x64-Word object after negating.
	         *
	         * @example
	         *
	         *     var negated = x64Word.not();
	         */
	        // not: function () {
	            // var high = ~this.high;
	            // var low = ~this.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ANDs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to AND with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ANDing.
	         *
	         * @example
	         *
	         *     var anded = x64Word.and(anotherX64Word);
	         */
	        // and: function (word) {
	            // var high = this.high & word.high;
	            // var low = this.low & word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to OR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ORing.
	         *
	         * @example
	         *
	         *     var ored = x64Word.or(anotherX64Word);
	         */
	        // or: function (word) {
	            // var high = this.high | word.high;
	            // var low = this.low | word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise XORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to XOR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after XORing.
	         *
	         * @example
	         *
	         *     var xored = x64Word.xor(anotherX64Word);
	         */
	        // xor: function (word) {
	            // var high = this.high ^ word.high;
	            // var low = this.low ^ word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the left.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftL(25);
	         */
	        // shiftL: function (n) {
	            // if (n < 32) {
	                // var high = (this.high << n) | (this.low >>> (32 - n));
	                // var low = this.low << n;
	            // } else {
	                // var high = this.low << (n - 32);
	                // var low = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the right.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftR(7);
	         */
	        // shiftR: function (n) {
	            // if (n < 32) {
	                // var low = (this.low >>> n) | (this.high << (32 - n));
	                // var high = this.high >>> n;
	            // } else {
	                // var low = this.high >>> (n - 32);
	                // var high = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Rotates this word n bits to the left.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotL(25);
	         */
	        // rotL: function (n) {
	            // return this.shiftL(n).or(this.shiftR(64 - n));
	        // },

	        /**
	         * Rotates this word n bits to the right.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotR(7);
	         */
	        // rotR: function (n) {
	            // return this.shiftR(n).or(this.shiftL(64 - n));
	        // },

	        /**
	         * Adds this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to add with this word.
	         *
	         * @return {X64Word} A new x64-Word object after adding.
	         *
	         * @example
	         *
	         *     var added = x64Word.add(anotherX64Word);
	         */
	        // add: function (word) {
	            // var low = (this.low + word.low) | 0;
	            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
	            // var high = (this.high + word.high + carry) | 0;

	            // return X64Word.create(high, low);
	        // }
	    });

	    /**
	     * An array of 64-bit words.
	     *
	     * @property {Array} words The array of CryptoJS.x64.Word objects.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var X64WordArray = C_x64.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create();
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ]);
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ], 10);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 8;
	            }
	        },

	        /**
	         * Converts this 64-bit word array to a 32-bit word array.
	         *
	         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
	         *
	         * @example
	         *
	         *     var x32WordArray = x64WordArray.toX32();
	         */
	        toX32: function () {
	            // Shortcuts
	            var x64Words = this.words;
	            var x64WordsLength = x64Words.length;

	            // Convert
	            var x32Words = [];
	            for (var i = 0; i < x64WordsLength; i++) {
	                var x64Word = x64Words[i];
	                x32Words.push(x64Word.high);
	                x32Words.push(x64Word.low);
	            }

	            return X32WordArray.create(x32Words, this.sigBytes);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {X64WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = x64WordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);

	            // Clone "words" array
	            var words = clone.words = this.words.slice(0);

	            // Clone each X64Word object
	            var wordsLength = words.length;
	            for (var i = 0; i < wordsLength; i++) {
	                words[i] = words[i].clone();
	            }

	            return clone;
	        }
	    });
	}());


	(function () {
	    // Check if typed arrays are supported
	    if (typeof ArrayBuffer != 'function') {
	        return;
	    }

	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;

	    // Reference original init
	    var superInit = WordArray.init;

	    // Augment WordArray.init to handle typed arrays
	    var subInit = WordArray.init = function (typedArray) {
	        // Convert buffers to uint8
	        if (typedArray instanceof ArrayBuffer) {
	            typedArray = new Uint8Array(typedArray);
	        }

	        // Convert other array views to uint8
	        if (
	            typedArray instanceof Int8Array ||
	            (typeof Uint8ClampedArray !== "undefined" && typedArray instanceof Uint8ClampedArray) ||
	            typedArray instanceof Int16Array ||
	            typedArray instanceof Uint16Array ||
	            typedArray instanceof Int32Array ||
	            typedArray instanceof Uint32Array ||
	            typedArray instanceof Float32Array ||
	            typedArray instanceof Float64Array
	        ) {
	            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
	        }

	        // Handle Uint8Array
	        if (typedArray instanceof Uint8Array) {
	            // Shortcut
	            var typedArrayByteLength = typedArray.byteLength;

	            // Extract bytes
	            var words = [];
	            for (var i = 0; i < typedArrayByteLength; i++) {
	                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
	            }

	            // Initialize this word array
	            superInit.call(this, words, typedArrayByteLength);
	        } else {
	            // Else call normal init
	            superInit.apply(this, arguments);
	        }
	    };

	    subInit.prototype = WordArray;
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * UTF-16 BE encoding strategy.
	     */
	    var Utf16BE = C_enc.Utf16 = C_enc.Utf16BE = {
	        /**
	         * Converts a word array to a UTF-16 BE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 BE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 BE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 BE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16.parse(utf16String);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    /**
	     * UTF-16 LE encoding strategy.
	     */
	    C_enc.Utf16LE = {
	        /**
	         * Converts a word array to a UTF-16 LE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 LE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 LE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 LE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    function swapEndian(word) {
	        return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
	    }
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64 encoding strategy.
	     */
	    var Base64 = C_enc.Base64 = {
	        /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */
	        parse: function (base64Str) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	      var words = [];
	      var nBytes = 0;
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              var bitsCombined = bits1 | bits2;
	              words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
	      return WordArray.create(words, nBytes);
	    }
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64url encoding strategy.
	     */
	    var Base64url = C_enc.Base64url = {
	        /**
	         * Converts a word array to a Base64url string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @param {boolean} urlSafe Whether to use url safe
	         *
	         * @return {string} The Base64url string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64url.stringify(wordArray);
	         */
	        stringify: function (wordArray, urlSafe=true) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = urlSafe ? this._safe_map : this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64url string to a word array.
	         *
	         * @param {string} base64Str The Base64url string.
	         *
	         * @param {boolean} urlSafe Whether to use url safe
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64url.parse(base64String);
	         */
	        parse: function (base64Str, urlSafe=true) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = urlSafe ? this._safe_map : this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                reverseMap = this._reverseMap = [];
	                for (var j = 0; j < map.length; j++) {
	                    reverseMap[map.charCodeAt(j)] = j;
	                }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
	        _safe_map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	        var words = [];
	        var nBytes = 0;
	        for (var i = 0; i < base64StrLength; i++) {
	            if (i % 4) {
	                var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	                var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	                var bitsCombined = bits1 | bits2;
	                words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
	                nBytes++;
	            }
	        }
	        return WordArray.create(words, nBytes);
	    }
	}());

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var T = [];

	    // Compute constants
	    (function () {
	        for (var i = 0; i < 64; i++) {
	            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
	        }
	    }());

	    /**
	     * MD5 hash algorithm.
	     */
	    var MD5 = C_algo.MD5 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }

	            // Shortcuts
	            var H = this._hash.words;

	            var M_offset_0  = M[offset + 0];
	            var M_offset_1  = M[offset + 1];
	            var M_offset_2  = M[offset + 2];
	            var M_offset_3  = M[offset + 3];
	            var M_offset_4  = M[offset + 4];
	            var M_offset_5  = M[offset + 5];
	            var M_offset_6  = M[offset + 6];
	            var M_offset_7  = M[offset + 7];
	            var M_offset_8  = M[offset + 8];
	            var M_offset_9  = M[offset + 9];
	            var M_offset_10 = M[offset + 10];
	            var M_offset_11 = M[offset + 11];
	            var M_offset_12 = M[offset + 12];
	            var M_offset_13 = M[offset + 13];
	            var M_offset_14 = M[offset + 14];
	            var M_offset_15 = M[offset + 15];

	            // Working varialbes
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];

	            // Computation
	            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
	            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
	            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
	            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
	            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
	            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
	            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
	            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
	            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
	            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
	            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
	            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
	            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
	            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
	            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
	            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

	            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
	            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
	            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
	            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
	            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
	            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
	            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
	            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
	            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
	            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
	            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
	            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
	            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
	            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
	            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
	            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

	            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
	            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
	            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
	            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
	            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
	            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
	            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
	            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
	            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
	            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
	            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
	            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
	            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
	            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
	            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
	            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

	            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
	            d = II(d, a, b, c, M_offset_7,  10, T[49]);
	            c = II(c, d, a, b, M_offset_14, 15, T[50]);
	            b = II(b, c, d, a, M_offset_5,  21, T[51]);
	            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
	            d = II(d, a, b, c, M_offset_3,  10, T[53]);
	            c = II(c, d, a, b, M_offset_10, 15, T[54]);
	            b = II(b, c, d, a, M_offset_1,  21, T[55]);
	            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
	            d = II(d, a, b, c, M_offset_15, 10, T[57]);
	            c = II(c, d, a, b, M_offset_6,  15, T[58]);
	            b = II(b, c, d, a, M_offset_13, 21, T[59]);
	            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
	            d = II(d, a, b, c, M_offset_11, 10, T[61]);
	            c = II(c, d, a, b, M_offset_2,  15, T[62]);
	            b = II(b, c, d, a, M_offset_9,  21, T[63]);

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

	            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
	            var nBitsTotalL = nBitsTotal;
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
	                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
	            );
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
	            );

	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                // Shortcut
	                var H_i = H[i];

	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    function FF(a, b, c, d, x, s, t) {
	        var n = a + ((b & c) | (~b & d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function GG(a, b, c, d, x, s, t) {
	        var n = a + ((b & d) | (c & ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function HH(a, b, c, d, x, s, t) {
	        var n = a + (b ^ c ^ d) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function II(a, b, c, d, x, s, t) {
	        var n = a + (c ^ (b | ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.MD5('message');
	     *     var hash = CryptoJS.MD5(wordArray);
	     */
	    C.MD5 = Hasher._createHelper(MD5);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacMD5(message, key);
	     */
	    C.HmacMD5 = Hasher._createHmacHelper(MD5);
	}(Math));


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-1 hash algorithm.
	     */
	    var SHA1 = C_algo.SHA1 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476,
	                0xc3d2e1f0
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];

	            // Computation
	            for (var i = 0; i < 80; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	                    W[i] = (n << 1) | (n >>> 31);
	                }

	                var t = ((a << 5) | (a >>> 27)) + e + W[i];
	                if (i < 20) {
	                    t += ((b & c) | (~b & d)) + 0x5a827999;
	                } else if (i < 40) {
	                    t += (b ^ c ^ d) + 0x6ed9eba1;
	                } else if (i < 60) {
	                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
	                } else /* if (i < 80) */ {
	                    t += (b ^ c ^ d) - 0x359d3e2a;
	                }

	                e = d;
	                d = c;
	                c = (b << 30) | (b >>> 2);
	                b = a;
	                a = t;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA1('message');
	     *     var hash = CryptoJS.SHA1(wordArray);
	     */
	    C.SHA1 = Hasher._createHelper(SHA1);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA1(message, key);
	     */
	    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
	}());


	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Initialization and round constants tables
	    var H = [];
	    var K = [];

	    // Compute constants
	    (function () {
	        function isPrime(n) {
	            var sqrtN = Math.sqrt(n);
	            for (var factor = 2; factor <= sqrtN; factor++) {
	                if (!(n % factor)) {
	                    return false;
	                }
	            }

	            return true;
	        }

	        function getFractionalBits(n) {
	            return ((n - (n | 0)) * 0x100000000) | 0;
	        }

	        var n = 2;
	        var nPrime = 0;
	        while (nPrime < 64) {
	            if (isPrime(n)) {
	                if (nPrime < 8) {
	                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
	                }
	                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

	                nPrime++;
	            }

	            n++;
	        }
	    }());

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-256 hash algorithm.
	     */
	    var SHA256 = C_algo.SHA256 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init(H.slice(0));
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];
	            var f = H[5];
	            var g = H[6];
	            var h = H[7];

	            // Computation
	            for (var i = 0; i < 64; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var gamma0x = W[i - 15];
	                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
	                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
	                                   (gamma0x >>> 3);

	                    var gamma1x = W[i - 2];
	                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
	                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
	                                   (gamma1x >>> 10);

	                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
	                }

	                var ch  = (e & f) ^ (~e & g);
	                var maj = (a & b) ^ (a & c) ^ (b & c);

	                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
	                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

	                var t1 = h + sigma1 + ch + K[i] + W[i];
	                var t2 = sigma0 + maj;

	                h = g;
	                g = f;
	                f = e;
	                e = (d + t1) | 0;
	                d = c;
	                c = b;
	                b = a;
	                a = (t1 + t2) | 0;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	            H[5] = (H[5] + f) | 0;
	            H[6] = (H[6] + g) | 0;
	            H[7] = (H[7] + h) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA256('message');
	     *     var hash = CryptoJS.SHA256(wordArray);
	     */
	    C.SHA256 = Hasher._createHelper(SHA256);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA256(message, key);
	     */
	    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
	}(Math));


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA256 = C_algo.SHA256;

	    /**
	     * SHA-224 hash algorithm.
	     */
	    var SHA224 = C_algo.SHA224 = SHA256.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA256._doFinalize.call(this);

	            hash.sigBytes -= 4;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA224('message');
	     *     var hash = CryptoJS.SHA224(wordArray);
	     */
	    C.SHA224 = SHA256._createHelper(SHA224);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA224(message, key);
	     */
	    C.HmacSHA224 = SHA256._createHmacHelper(SHA224);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;

	    function X64Word_create() {
	        return X64Word.create.apply(X64Word, arguments);
	    }

	    // Constants
	    var K = [
	        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
	        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
	        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
	        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
	        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
	        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
	        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
	        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
	        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
	        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
	        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
	        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
	        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
	        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
	        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
	        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
	        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
	        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
	        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
	        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
	        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
	        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
	        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
	        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
	        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
	        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
	        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
	        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
	        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
	        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
	        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
	        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
	        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
	        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
	        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
	        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
	        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
	        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
	        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
	        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
	    ];

	    // Reusable objects
	    var W = [];
	    (function () {
	        for (var i = 0; i < 80; i++) {
	            W[i] = X64Word_create();
	        }
	    }());

	    /**
	     * SHA-512 hash algorithm.
	     */
	    var SHA512 = C_algo.SHA512 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
	                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
	                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
	                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var H = this._hash.words;

	            var H0 = H[0];
	            var H1 = H[1];
	            var H2 = H[2];
	            var H3 = H[3];
	            var H4 = H[4];
	            var H5 = H[5];
	            var H6 = H[6];
	            var H7 = H[7];

	            var H0h = H0.high;
	            var H0l = H0.low;
	            var H1h = H1.high;
	            var H1l = H1.low;
	            var H2h = H2.high;
	            var H2l = H2.low;
	            var H3h = H3.high;
	            var H3l = H3.low;
	            var H4h = H4.high;
	            var H4l = H4.low;
	            var H5h = H5.high;
	            var H5l = H5.low;
	            var H6h = H6.high;
	            var H6l = H6.low;
	            var H7h = H7.high;
	            var H7l = H7.low;

	            // Working variables
	            var ah = H0h;
	            var al = H0l;
	            var bh = H1h;
	            var bl = H1l;
	            var ch = H2h;
	            var cl = H2l;
	            var dh = H3h;
	            var dl = H3l;
	            var eh = H4h;
	            var el = H4l;
	            var fh = H5h;
	            var fl = H5l;
	            var gh = H6h;
	            var gl = H6l;
	            var hh = H7h;
	            var hl = H7l;

	            // Rounds
	            for (var i = 0; i < 80; i++) {
	                var Wil;
	                var Wih;

	                // Shortcut
	                var Wi = W[i];

	                // Extend message
	                if (i < 16) {
	                    Wih = Wi.high = M[offset + i * 2]     | 0;
	                    Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
	                } else {
	                    // Gamma0
	                    var gamma0x  = W[i - 15];
	                    var gamma0xh = gamma0x.high;
	                    var gamma0xl = gamma0x.low;
	                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
	                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

	                    // Gamma1
	                    var gamma1x  = W[i - 2];
	                    var gamma1xh = gamma1x.high;
	                    var gamma1xl = gamma1x.low;
	                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
	                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

	                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
	                    var Wi7  = W[i - 7];
	                    var Wi7h = Wi7.high;
	                    var Wi7l = Wi7.low;

	                    var Wi16  = W[i - 16];
	                    var Wi16h = Wi16.high;
	                    var Wi16l = Wi16.low;

	                    Wil = gamma0l + Wi7l;
	                    Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
	                    Wil = Wil + gamma1l;
	                    Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
	                    Wil = Wil + Wi16l;
	                    Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

	                    Wi.high = Wih;
	                    Wi.low  = Wil;
	                }

	                var chh  = (eh & fh) ^ (~eh & gh);
	                var chl  = (el & fl) ^ (~el & gl);
	                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
	                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

	                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
	                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
	                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
	                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

	                // t1 = h + sigma1 + ch + K[i] + W[i]
	                var Ki  = K[i];
	                var Kih = Ki.high;
	                var Kil = Ki.low;

	                var t1l = hl + sigma1l;
	                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
	                var t1l = t1l + chl;
	                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
	                var t1l = t1l + Kil;
	                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
	                var t1l = t1l + Wil;
	                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

	                // t2 = sigma0 + maj
	                var t2l = sigma0l + majl;
	                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

	                // Update working variables
	                hh = gh;
	                hl = gl;
	                gh = fh;
	                gl = fl;
	                fh = eh;
	                fl = el;
	                el = (dl + t1l) | 0;
	                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
	                dh = ch;
	                dl = cl;
	                ch = bh;
	                cl = bl;
	                bh = ah;
	                bl = al;
	                al = (t1l + t2l) | 0;
	                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
	            }

	            // Intermediate hash value
	            H0l = H0.low  = (H0l + al);
	            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
	            H1l = H1.low  = (H1l + bl);
	            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
	            H2l = H2.low  = (H2l + cl);
	            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
	            H3l = H3.low  = (H3l + dl);
	            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
	            H4l = H4.low  = (H4l + el);
	            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
	            H5l = H5.low  = (H5l + fl);
	            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
	            H6l = H6.low  = (H6l + gl);
	            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
	            H7l = H7.low  = (H7l + hl);
	            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Convert hash to 32-bit word array before returning
	            var hash = this._hash.toX32();

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        },

	        blockSize: 1024/32
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA512('message');
	     *     var hash = CryptoJS.SHA512(wordArray);
	     */
	    C.SHA512 = Hasher._createHelper(SHA512);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA512(message, key);
	     */
	    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;
	    var SHA512 = C_algo.SHA512;

	    /**
	     * SHA-384 hash algorithm.
	     */
	    var SHA384 = C_algo.SHA384 = SHA512.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
	                new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
	                new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
	                new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA512._doFinalize.call(this);

	            hash.sigBytes -= 16;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA384('message');
	     *     var hash = CryptoJS.SHA384(wordArray);
	     */
	    C.SHA384 = SHA512._createHelper(SHA384);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA384(message, key);
	     */
	    C.HmacSHA384 = SHA512._createHmacHelper(SHA384);
	}());


	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var C_algo = C.algo;

	    // Constants tables
	    var RHO_OFFSETS = [];
	    var PI_INDEXES  = [];
	    var ROUND_CONSTANTS = [];

	    // Compute Constants
	    (function () {
	        // Compute rho offset constants
	        var x = 1, y = 0;
	        for (var t = 0; t < 24; t++) {
	            RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

	            var newX = y % 5;
	            var newY = (2 * x + 3 * y) % 5;
	            x = newX;
	            y = newY;
	        }

	        // Compute pi index constants
	        for (var x = 0; x < 5; x++) {
	            for (var y = 0; y < 5; y++) {
	                PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
	            }
	        }

	        // Compute round constants
	        var LFSR = 0x01;
	        for (var i = 0; i < 24; i++) {
	            var roundConstantMsw = 0;
	            var roundConstantLsw = 0;

	            for (var j = 0; j < 7; j++) {
	                if (LFSR & 0x01) {
	                    var bitPosition = (1 << j) - 1;
	                    if (bitPosition < 32) {
	                        roundConstantLsw ^= 1 << bitPosition;
	                    } else /* if (bitPosition >= 32) */ {
	                        roundConstantMsw ^= 1 << (bitPosition - 32);
	                    }
	                }

	                // Compute next LFSR
	                if (LFSR & 0x80) {
	                    // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
	                    LFSR = (LFSR << 1) ^ 0x71;
	                } else {
	                    LFSR <<= 1;
	                }
	            }

	            ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
	        }
	    }());

	    // Reusable objects for temporary values
	    var T = [];
	    (function () {
	        for (var i = 0; i < 25; i++) {
	            T[i] = X64Word.create();
	        }
	    }());

	    /**
	     * SHA-3 hash algorithm.
	     */
	    var SHA3 = C_algo.SHA3 = Hasher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} outputLength
	         *   The desired number of bits in the output hash.
	         *   Only values permitted are: 224, 256, 384, 512.
	         *   Default: 512
	         */
	        cfg: Hasher.cfg.extend({
	            outputLength: 512
	        }),

	        _doReset: function () {
	            var state = this._state = []
	            for (var i = 0; i < 25; i++) {
	                state[i] = new X64Word.init();
	            }

	            this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var state = this._state;
	            var nBlockSizeLanes = this.blockSize / 2;

	            // Absorb
	            for (var i = 0; i < nBlockSizeLanes; i++) {
	                // Shortcuts
	                var M2i  = M[offset + 2 * i];
	                var M2i1 = M[offset + 2 * i + 1];

	                // Swap endian
	                M2i = (
	                    (((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
	                    (((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
	                );
	                M2i1 = (
	                    (((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
	                    (((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
	                );

	                // Absorb message into state
	                var lane = state[i];
	                lane.high ^= M2i1;
	                lane.low  ^= M2i;
	            }

	            // Rounds
	            for (var round = 0; round < 24; round++) {
	                // Theta
	                for (var x = 0; x < 5; x++) {
	                    // Mix column lanes
	                    var tMsw = 0, tLsw = 0;
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        tMsw ^= lane.high;
	                        tLsw ^= lane.low;
	                    }

	                    // Temporary values
	                    var Tx = T[x];
	                    Tx.high = tMsw;
	                    Tx.low  = tLsw;
	                }
	                for (var x = 0; x < 5; x++) {
	                    // Shortcuts
	                    var Tx4 = T[(x + 4) % 5];
	                    var Tx1 = T[(x + 1) % 5];
	                    var Tx1Msw = Tx1.high;
	                    var Tx1Lsw = Tx1.low;

	                    // Mix surrounding columns
	                    var tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
	                    var tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        lane.high ^= tMsw;
	                        lane.low  ^= tLsw;
	                    }
	                }

	                // Rho Pi
	                for (var laneIndex = 1; laneIndex < 25; laneIndex++) {
	                    var tMsw;
	                    var tLsw;

	                    // Shortcuts
	                    var lane = state[laneIndex];
	                    var laneMsw = lane.high;
	                    var laneLsw = lane.low;
	                    var rhoOffset = RHO_OFFSETS[laneIndex];

	                    // Rotate lanes
	                    if (rhoOffset < 32) {
	                        tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
	                        tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
	                    } else /* if (rhoOffset >= 32) */ {
	                        tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
	                        tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
	                    }

	                    // Transpose lanes
	                    var TPiLane = T[PI_INDEXES[laneIndex]];
	                    TPiLane.high = tMsw;
	                    TPiLane.low  = tLsw;
	                }

	                // Rho pi at x = y = 0
	                var T0 = T[0];
	                var state0 = state[0];
	                T0.high = state0.high;
	                T0.low  = state0.low;

	                // Chi
	                for (var x = 0; x < 5; x++) {
	                    for (var y = 0; y < 5; y++) {
	                        // Shortcuts
	                        var laneIndex = x + 5 * y;
	                        var lane = state[laneIndex];
	                        var TLane = T[laneIndex];
	                        var Tx1Lane = T[((x + 1) % 5) + 5 * y];
	                        var Tx2Lane = T[((x + 2) % 5) + 5 * y];

	                        // Mix rows
	                        lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
	                        lane.low  = TLane.low  ^ (~Tx1Lane.low  & Tx2Lane.low);
	                    }
	                }

	                // Iota
	                var lane = state[0];
	                var roundConstant = ROUND_CONSTANTS[round];
	                lane.high ^= roundConstant.high;
	                lane.low  ^= roundConstant.low;
	            }
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;
	            var blockSizeBits = this.blockSize * 32;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
	            dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var state = this._state;
	            var outputLengthBytes = this.cfg.outputLength / 8;
	            var outputLengthLanes = outputLengthBytes / 8;

	            // Squeeze
	            var hashWords = [];
	            for (var i = 0; i < outputLengthLanes; i++) {
	                // Shortcuts
	                var lane = state[i];
	                var laneMsw = lane.high;
	                var laneLsw = lane.low;

	                // Swap endian
	                laneMsw = (
	                    (((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
	                    (((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
	                );
	                laneLsw = (
	                    (((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
	                    (((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
	                );

	                // Squeeze state to retrieve hash
	                hashWords.push(laneLsw);
	                hashWords.push(laneMsw);
	            }

	            // Return final computed hash
	            return new WordArray.init(hashWords, outputLengthBytes);
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);

	            var state = clone._state = this._state.slice(0);
	            for (var i = 0; i < 25; i++) {
	                state[i] = state[i].clone();
	            }

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA3('message');
	     *     var hash = CryptoJS.SHA3(wordArray);
	     */
	    C.SHA3 = Hasher._createHelper(SHA3);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA3(message, key);
	     */
	    C.HmacSHA3 = Hasher._createHmacHelper(SHA3);
	}(Math));


	/** @preserve
	(c) 2012 by Cédric Mesnil. All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var _zl = WordArray.create([
	        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
	    var _zr = WordArray.create([
	        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
	    var _sl = WordArray.create([
	         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
	    var _sr = WordArray.create([
	        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

	    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
	    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

	    /**
	     * RIPEMD160 hash algorithm.
	     */
	    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
	        _doReset: function () {
	            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
	        },

	        _doProcessBlock: function (M, offset) {

	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                // Swap
	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }
	            // Shortcut
	            var H  = this._hash.words;
	            var hl = _hl.words;
	            var hr = _hr.words;
	            var zl = _zl.words;
	            var zr = _zr.words;
	            var sl = _sl.words;
	            var sr = _sr.words;

	            // Working variables
	            var al, bl, cl, dl, el;
	            var ar, br, cr, dr, er;

	            ar = al = H[0];
	            br = bl = H[1];
	            cr = cl = H[2];
	            dr = dl = H[3];
	            er = el = H[4];
	            // Computation
	            var t;
	            for (var i = 0; i < 80; i += 1) {
	                t = (al +  M[offset+zl[i]])|0;
	                if (i<16){
		            t +=  f1(bl,cl,dl) + hl[0];
	                } else if (i<32) {
		            t +=  f2(bl,cl,dl) + hl[1];
	                } else if (i<48) {
		            t +=  f3(bl,cl,dl) + hl[2];
	                } else if (i<64) {
		            t +=  f4(bl,cl,dl) + hl[3];
	                } else {// if (i<80) {
		            t +=  f5(bl,cl,dl) + hl[4];
	                }
	                t = t|0;
	                t =  rotl(t,sl[i]);
	                t = (t+el)|0;
	                al = el;
	                el = dl;
	                dl = rotl(cl, 10);
	                cl = bl;
	                bl = t;

	                t = (ar + M[offset+zr[i]])|0;
	                if (i<16){
		            t +=  f5(br,cr,dr) + hr[0];
	                } else if (i<32) {
		            t +=  f4(br,cr,dr) + hr[1];
	                } else if (i<48) {
		            t +=  f3(br,cr,dr) + hr[2];
	                } else if (i<64) {
		            t +=  f2(br,cr,dr) + hr[3];
	                } else {// if (i<80) {
		            t +=  f1(br,cr,dr) + hr[4];
	                }
	                t = t|0;
	                t =  rotl(t,sr[i]) ;
	                t = (t+er)|0;
	                ar = er;
	                er = dr;
	                dr = rotl(cr, 10);
	                cr = br;
	                br = t;
	            }
	            // Intermediate hash value
	            t    = (H[1] + cl + dr)|0;
	            H[1] = (H[2] + dl + er)|0;
	            H[2] = (H[3] + el + ar)|0;
	            H[3] = (H[4] + al + br)|0;
	            H[4] = (H[0] + bl + cr)|0;
	            H[0] =  t;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	            );
	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 5; i++) {
	                // Shortcut
	                var H_i = H[i];

	                // Swap
	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });


	    function f1(x, y, z) {
	        return ((x) ^ (y) ^ (z));

	    }

	    function f2(x, y, z) {
	        return (((x)&(y)) | ((~x)&(z)));
	    }

	    function f3(x, y, z) {
	        return (((x) | (~(y))) ^ (z));
	    }

	    function f4(x, y, z) {
	        return (((x) & (z)) | ((y)&(~(z))));
	    }

	    function f5(x, y, z) {
	        return ((x) ^ ((y) |(~(z))));

	    }

	    function rotl(x,n) {
	        return (x<<n) | (x>>>(32-n));
	    }


	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.RIPEMD160('message');
	     *     var hash = CryptoJS.RIPEMD160(wordArray);
	     */
	    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
	     */
	    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);
	}(Math));


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var C_algo = C.algo;

	    /**
	     * HMAC algorithm.
	     */
	    var HMAC = C_algo.HMAC = Base.extend({
	        /**
	         * Initializes a newly created HMAC.
	         *
	         * @param {Hasher} hasher The hash algorithm to use.
	         * @param {WordArray|string} key The secret key.
	         *
	         * @example
	         *
	         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
	         */
	        init: function (hasher, key) {
	            // Init hasher
	            hasher = this._hasher = new hasher.init();

	            // Convert string to WordArray, else assume WordArray already
	            if (typeof key == 'string') {
	                key = Utf8.parse(key);
	            }

	            // Shortcuts
	            var hasherBlockSize = hasher.blockSize;
	            var hasherBlockSizeBytes = hasherBlockSize * 4;

	            // Allow arbitrary length keys
	            if (key.sigBytes > hasherBlockSizeBytes) {
	                key = hasher.finalize(key);
	            }

	            // Clamp excess bits
	            key.clamp();

	            // Clone key for inner and outer pads
	            var oKey = this._oKey = key.clone();
	            var iKey = this._iKey = key.clone();

	            // Shortcuts
	            var oKeyWords = oKey.words;
	            var iKeyWords = iKey.words;

	            // XOR keys with pad constants
	            for (var i = 0; i < hasherBlockSize; i++) {
	                oKeyWords[i] ^= 0x5c5c5c5c;
	                iKeyWords[i] ^= 0x36363636;
	            }
	            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this HMAC to its initial state.
	         *
	         * @example
	         *
	         *     hmacHasher.reset();
	         */
	        reset: function () {
	            // Shortcut
	            var hasher = this._hasher;

	            // Reset
	            hasher.reset();
	            hasher.update(this._iKey);
	        },

	        /**
	         * Updates this HMAC with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {HMAC} This HMAC instance.
	         *
	         * @example
	         *
	         *     hmacHasher.update('message');
	         *     hmacHasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            this._hasher.update(messageUpdate);

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the HMAC computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The HMAC.
	         *
	         * @example
	         *
	         *     var hmac = hmacHasher.finalize();
	         *     var hmac = hmacHasher.finalize('message');
	         *     var hmac = hmacHasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Shortcut
	            var hasher = this._hasher;

	            // Compute HMAC
	            var innerHash = hasher.finalize(messageUpdate);
	            hasher.reset();
	            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

	            return hmac;
	        }
	    });
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA1 = C_algo.SHA1;
	    var HMAC = C_algo.HMAC;

	    /**
	     * Password-Based Key Derivation Function 2 algorithm.
	     */
	    var PBKDF2 = C_algo.PBKDF2 = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hasher to use. Default: SHA1
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: SHA1,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.PBKDF2.create();
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Computes the Password-Based Key Derivation Function 2.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init HMAC
	            var hmac = HMAC.create(cfg.hasher, password);

	            // Initial values
	            var derivedKey = WordArray.create();
	            var blockIndex = WordArray.create([0x00000001]);

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var blockIndexWords = blockIndex.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                var block = hmac.update(salt).finalize(blockIndex);
	                hmac.reset();

	                // Shortcuts
	                var blockWords = block.words;
	                var blockWordsLength = blockWords.length;

	                // Iterations
	                var intermediate = block;
	                for (var i = 1; i < iterations; i++) {
	                    intermediate = hmac.finalize(intermediate);
	                    hmac.reset();

	                    // Shortcut
	                    var intermediateWords = intermediate.words;

	                    // XOR intermediate with block
	                    for (var j = 0; j < blockWordsLength; j++) {
	                        blockWords[j] ^= intermediateWords[j];
	                    }
	                }

	                derivedKey.concat(block);
	                blockIndexWords[0]++;
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Computes the Password-Based Key Derivation Function 2.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.PBKDF2(password, salt);
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.PBKDF2 = function (password, salt, cfg) {
	        return PBKDF2.create(cfg).compute(password, salt);
	    };
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var MD5 = C_algo.MD5;

	    /**
	     * This key derivation function is meant to conform with EVP_BytesToKey.
	     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
	     */
	    var EvpKDF = C_algo.EvpKDF = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: MD5,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.EvpKDF.create();
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Derives a key from a password.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            var block;

	            // Shortcut
	            var cfg = this.cfg;

	            // Init hasher
	            var hasher = cfg.hasher.create();

	            // Initial values
	            var derivedKey = WordArray.create();

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                if (block) {
	                    hasher.update(block);
	                }
	                block = hasher.update(password).finalize(salt);
	                hasher.reset();

	                // Iterations
	                for (var i = 1; i < iterations; i++) {
	                    block = hasher.finalize(block);
	                    hasher.reset();
	                }

	                derivedKey.concat(block);
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Derives a key from a password.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.EvpKDF(password, salt);
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.EvpKDF = function (password, salt, cfg) {
	        return EvpKDF.create(cfg).compute(password, salt);
	    };
	}());


	/**
	 * Cipher core components.
	 */
	CryptoJS.lib.Cipher || (function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var Base64 = C_enc.Base64;
	    var C_algo = C.algo;
	    var EvpKDF = C_algo.EvpKDF;

	    /**
	     * Abstract base cipher template.
	     *
	     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
	     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
	     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
	     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
	     */
	    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {WordArray} iv The IV to use for this operation.
	         */
	        cfg: Base.extend(),

	        /**
	         * Creates this cipher in encryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createEncryptor: function (key, cfg) {
	            return this.create(this._ENC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Creates this cipher in decryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createDecryptor: function (key, cfg) {
	            return this.create(this._DEC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Initializes a newly created cipher.
	         *
	         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	         */
	        init: function (xformMode, key, cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Store transform mode and key
	            this._xformMode = xformMode;
	            this._key = key;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this cipher to its initial state.
	         *
	         * @example
	         *
	         *     cipher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-cipher logic
	            this._doReset();
	        },

	        /**
	         * Adds data to be encrypted or decrypted.
	         *
	         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.process('data');
	         *     var encrypted = cipher.process(wordArray);
	         */
	        process: function (dataUpdate) {
	            // Append
	            this._append(dataUpdate);

	            // Process available blocks
	            return this._process();
	        },

	        /**
	         * Finalizes the encryption or decryption process.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after final processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.finalize();
	         *     var encrypted = cipher.finalize('data');
	         *     var encrypted = cipher.finalize(wordArray);
	         */
	        finalize: function (dataUpdate) {
	            // Final data update
	            if (dataUpdate) {
	                this._append(dataUpdate);
	            }

	            // Perform concrete-cipher logic
	            var finalProcessedData = this._doFinalize();

	            return finalProcessedData;
	        },

	        keySize: 128/32,

	        ivSize: 128/32,

	        _ENC_XFORM_MODE: 1,

	        _DEC_XFORM_MODE: 2,

	        /**
	         * Creates shortcut functions to a cipher's object interface.
	         *
	         * @param {Cipher} cipher The cipher to create a helper for.
	         *
	         * @return {Object} An object with encrypt and decrypt shortcut functions.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
	         */
	        _createHelper: (function () {
	            function selectCipherStrategy(key) {
	                if (typeof key == 'string') {
	                    return PasswordBasedCipher;
	                } else {
	                    return SerializableCipher;
	                }
	            }

	            return function (cipher) {
	                return {
	                    encrypt: function (message, key, cfg) {
	                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
	                    },

	                    decrypt: function (ciphertext, key, cfg) {
	                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
	                    }
	                };
	            };
	        }())
	    });

	    /**
	     * Abstract base stream cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
	     */
	    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
	        _doFinalize: function () {
	            // Process partial blocks
	            var finalProcessedBlocks = this._process(!!'flush');

	            return finalProcessedBlocks;
	        },

	        blockSize: 1
	    });

	    /**
	     * Mode namespace.
	     */
	    var C_mode = C.mode = {};

	    /**
	     * Abstract base block cipher mode template.
	     */
	    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
	        /**
	         * Creates this mode for encryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
	         */
	        createEncryptor: function (cipher, iv) {
	            return this.Encryptor.create(cipher, iv);
	        },

	        /**
	         * Creates this mode for decryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
	         */
	        createDecryptor: function (cipher, iv) {
	            return this.Decryptor.create(cipher, iv);
	        },

	        /**
	         * Initializes a newly created mode.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
	         */
	        init: function (cipher, iv) {
	            this._cipher = cipher;
	            this._iv = iv;
	        }
	    });

	    /**
	     * Cipher Block Chaining mode.
	     */
	    var CBC = C_mode.CBC = (function () {
	        /**
	         * Abstract base CBC mode.
	         */
	        var CBC = BlockCipherMode.extend();

	        /**
	         * CBC encryptor.
	         */
	        CBC.Encryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // XOR and encrypt
	                xorBlock.call(this, words, offset, blockSize);
	                cipher.encryptBlock(words, offset);

	                // Remember this block to use with next block
	                this._prevBlock = words.slice(offset, offset + blockSize);
	            }
	        });

	        /**
	         * CBC decryptor.
	         */
	        CBC.Decryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // Remember this block to use with next block
	                var thisBlock = words.slice(offset, offset + blockSize);

	                // Decrypt and XOR
	                cipher.decryptBlock(words, offset);
	                xorBlock.call(this, words, offset, blockSize);

	                // This block becomes the previous block
	                this._prevBlock = thisBlock;
	            }
	        });

	        function xorBlock(words, offset, blockSize) {
	            var block;

	            // Shortcut
	            var iv = this._iv;

	            // Choose mixing block
	            if (iv) {
	                block = iv;

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            } else {
	                block = this._prevBlock;
	            }

	            // XOR blocks
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= block[i];
	            }
	        }

	        return CBC;
	    }());

	    /**
	     * Padding namespace.
	     */
	    var C_pad = C.pad = {};

	    /**
	     * PKCS #5/7 padding strategy.
	     */
	    var Pkcs7 = C_pad.Pkcs7 = {
	        /**
	         * Pads data using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to pad.
	         * @param {number} blockSize The multiple that the data should be padded to.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
	         */
	        pad: function (data, blockSize) {
	            // Shortcut
	            var blockSizeBytes = blockSize * 4;

	            // Count padding bytes
	            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	            // Create padding word
	            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

	            // Create padding
	            var paddingWords = [];
	            for (var i = 0; i < nPaddingBytes; i += 4) {
	                paddingWords.push(paddingWord);
	            }
	            var padding = WordArray.create(paddingWords, nPaddingBytes);

	            // Add padding
	            data.concat(padding);
	        },

	        /**
	         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to unpad.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
	         */
	        unpad: function (data) {
	            // Get number of padding bytes from last byte
	            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	            // Remove padding
	            data.sigBytes -= nPaddingBytes;
	        }
	    };

	    /**
	     * Abstract base block cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
	     */
	    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Mode} mode The block mode to use. Default: CBC
	         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
	         */
	        cfg: Cipher.cfg.extend({
	            mode: CBC,
	            padding: Pkcs7
	        }),

	        reset: function () {
	            var modeCreator;

	            // Reset cipher
	            Cipher.reset.call(this);

	            // Shortcuts
	            var cfg = this.cfg;
	            var iv = cfg.iv;
	            var mode = cfg.mode;

	            // Reset block mode
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                modeCreator = mode.createEncryptor;
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                modeCreator = mode.createDecryptor;
	                // Keep at least one block in the buffer for unpadding
	                this._minBufferSize = 1;
	            }

	            if (this._mode && this._mode.__creator == modeCreator) {
	                this._mode.init(this, iv && iv.words);
	            } else {
	                this._mode = modeCreator.call(mode, this, iv && iv.words);
	                this._mode.__creator = modeCreator;
	            }
	        },

	        _doProcessBlock: function (words, offset) {
	            this._mode.processBlock(words, offset);
	        },

	        _doFinalize: function () {
	            var finalProcessedBlocks;

	            // Shortcut
	            var padding = this.cfg.padding;

	            // Finalize
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                // Pad data
	                padding.pad(this._data, this.blockSize);

	                // Process final blocks
	                finalProcessedBlocks = this._process(!!'flush');
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                // Process final blocks
	                finalProcessedBlocks = this._process(!!'flush');

	                // Unpad data
	                padding.unpad(finalProcessedBlocks);
	            }

	            return finalProcessedBlocks;
	        },

	        blockSize: 128/32
	    });

	    /**
	     * A collection of cipher parameters.
	     *
	     * @property {WordArray} ciphertext The raw ciphertext.
	     * @property {WordArray} key The key to this ciphertext.
	     * @property {WordArray} iv The IV used in the ciphering operation.
	     * @property {WordArray} salt The salt used with a key derivation function.
	     * @property {Cipher} algorithm The cipher algorithm.
	     * @property {Mode} mode The block mode used in the ciphering operation.
	     * @property {Padding} padding The padding scheme used in the ciphering operation.
	     * @property {number} blockSize The block size of the cipher.
	     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
	     */
	    var CipherParams = C_lib.CipherParams = Base.extend({
	        /**
	         * Initializes a newly created cipher params object.
	         *
	         * @param {Object} cipherParams An object with any of the possible cipher parameters.
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.lib.CipherParams.create({
	         *         ciphertext: ciphertextWordArray,
	         *         key: keyWordArray,
	         *         iv: ivWordArray,
	         *         salt: saltWordArray,
	         *         algorithm: CryptoJS.algo.AES,
	         *         mode: CryptoJS.mode.CBC,
	         *         padding: CryptoJS.pad.PKCS7,
	         *         blockSize: 4,
	         *         formatter: CryptoJS.format.OpenSSL
	         *     });
	         */
	        init: function (cipherParams) {
	            this.mixIn(cipherParams);
	        },

	        /**
	         * Converts this cipher params object to a string.
	         *
	         * @param {Format} formatter (Optional) The formatting strategy to use.
	         *
	         * @return {string} The stringified cipher params.
	         *
	         * @throws Error If neither the formatter nor the default formatter is set.
	         *
	         * @example
	         *
	         *     var string = cipherParams + '';
	         *     var string = cipherParams.toString();
	         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
	         */
	        toString: function (formatter) {
	            return (formatter || this.formatter).stringify(this);
	        }
	    });

	    /**
	     * Format namespace.
	     */
	    var C_format = C.format = {};

	    /**
	     * OpenSSL formatting strategy.
	     */
	    var OpenSSLFormatter = C_format.OpenSSL = {
	        /**
	         * Converts a cipher params object to an OpenSSL-compatible string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The OpenSSL-compatible string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            var wordArray;

	            // Shortcuts
	            var ciphertext = cipherParams.ciphertext;
	            var salt = cipherParams.salt;

	            // Format
	            if (salt) {
	                wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
	            } else {
	                wordArray = ciphertext;
	            }

	            return wordArray.toString(Base64);
	        },

	        /**
	         * Converts an OpenSSL-compatible string to a cipher params object.
	         *
	         * @param {string} openSSLStr The OpenSSL-compatible string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
	         */
	        parse: function (openSSLStr) {
	            var salt;

	            // Parse base64
	            var ciphertext = Base64.parse(openSSLStr);

	            // Shortcut
	            var ciphertextWords = ciphertext.words;

	            // Test for salt
	            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
	                // Extract salt
	                salt = WordArray.create(ciphertextWords.slice(2, 4));

	                // Remove salt from ciphertext
	                ciphertextWords.splice(0, 4);
	                ciphertext.sigBytes -= 16;
	            }

	            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
	        }
	    };

	    /**
	     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
	     */
	    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
	         */
	        cfg: Base.extend({
	            format: OpenSSLFormatter
	        }),

	        /**
	         * Encrypts a message.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Encrypt
	            var encryptor = cipher.createEncryptor(key, cfg);
	            var ciphertext = encryptor.finalize(message);

	            // Shortcut
	            var cipherCfg = encryptor.cfg;

	            // Create and return serializable cipher params
	            return CipherParams.create({
	                ciphertext: ciphertext,
	                key: key,
	                iv: cipherCfg.iv,
	                algorithm: cipher,
	                mode: cipherCfg.mode,
	                padding: cipherCfg.padding,
	                blockSize: cipher.blockSize,
	                formatter: cfg.format
	            });
	        },

	        /**
	         * Decrypts serialized ciphertext.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Decrypt
	            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

	            return plaintext;
	        },

	        /**
	         * Converts serialized ciphertext to CipherParams,
	         * else assumed CipherParams already and returns ciphertext unchanged.
	         *
	         * @param {CipherParams|string} ciphertext The ciphertext.
	         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	         *
	         * @return {CipherParams} The unserialized ciphertext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
	         */
	        _parse: function (ciphertext, format) {
	            if (typeof ciphertext == 'string') {
	                return format.parse(ciphertext, this);
	            } else {
	                return ciphertext;
	            }
	        }
	    });

	    /**
	     * Key derivation function namespace.
	     */
	    var C_kdf = C.kdf = {};

	    /**
	     * OpenSSL key derivation function.
	     */
	    var OpenSSLKdf = C_kdf.OpenSSL = {
	        /**
	         * Derives a key and IV from a password.
	         *
	         * @param {string} password The password to derive from.
	         * @param {number} keySize The size in words of the key to generate.
	         * @param {number} ivSize The size in words of the IV to generate.
	         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	         *
	         * @return {CipherParams} A cipher params object with the key, IV, and salt.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
	         */
	        execute: function (password, keySize, ivSize, salt) {
	            // Generate random salt
	            if (!salt) {
	                salt = WordArray.random(64/8);
	            }

	            // Derive key and IV
	            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

	            // Separate key and IV
	            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
	            key.sigBytes = keySize * 4;

	            // Return params
	            return CipherParams.create({ key: key, iv: iv, salt: salt });
	        }
	    };

	    /**
	     * A serializable cipher wrapper that derives the key from a password,
	     * and returns ciphertext as a serializable cipher params object.
	     */
	    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
	         */
	        cfg: SerializableCipher.cfg.extend({
	            kdf: OpenSSLKdf
	        }),

	        /**
	         * Encrypts a message using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Encrypt
	            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

	            // Mix in derived params
	            ciphertext.mixIn(derivedParams);

	            return ciphertext;
	        },

	        /**
	         * Decrypts serialized ciphertext using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Decrypt
	            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

	            return plaintext;
	        }
	    });
	}());


	/**
	 * Cipher Feedback block mode.
	 */
	CryptoJS.mode.CFB = (function () {
	    var CFB = CryptoJS.lib.BlockCipherMode.extend();

	    CFB.Encryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // Remember this block to use with next block
	            this._prevBlock = words.slice(offset, offset + blockSize);
	        }
	    });

	    CFB.Decryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            // Remember this block to use with next block
	            var thisBlock = words.slice(offset, offset + blockSize);

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // This block becomes the previous block
	            this._prevBlock = thisBlock;
	        }
	    });

	    function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
	        var keystream;

	        // Shortcut
	        var iv = this._iv;

	        // Generate keystream
	        if (iv) {
	            keystream = iv.slice(0);

	            // Remove IV for subsequent blocks
	            this._iv = undefined;
	        } else {
	            keystream = this._prevBlock;
	        }
	        cipher.encryptBlock(keystream, 0);

	        // Encrypt
	        for (var i = 0; i < blockSize; i++) {
	            words[offset + i] ^= keystream[i];
	        }
	    }

	    return CFB;
	}());


	/**
	 * Counter block mode.
	 */
	CryptoJS.mode.CTR = (function () {
	    var CTR = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = CTR.Encryptor = CTR.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Increment counter
	            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTR.Decryptor = Encryptor;

	    return CTR;
	}());


	/** @preserve
	 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
	 * derived from CryptoJS.mode.CTR
	 * Jan Hruby jhruby.web@gmail.com
	 */
	CryptoJS.mode.CTRGladman = (function () {
	    var CTRGladman = CryptoJS.lib.BlockCipherMode.extend();

		function incWord(word)
		{
			if (((word >> 24) & 0xff) === 0xff) { //overflow
			var b1 = (word >> 16)&0xff;
			var b2 = (word >> 8)&0xff;
			var b3 = word & 0xff;

			if (b1 === 0xff) // overflow b1
			{
			b1 = 0;
			if (b2 === 0xff)
			{
				b2 = 0;
				if (b3 === 0xff)
				{
					b3 = 0;
				}
				else
				{
					++b3;
				}
			}
			else
			{
				++b2;
			}
			}
			else
			{
			++b1;
			}

			word = 0;
			word += (b1 << 16);
			word += (b2 << 8);
			word += b3;
			}
			else
			{
			word += (0x01 << 24);
			}
			return word;
		}

		function incCounter(counter)
		{
			if ((counter[0] = incWord(counter[0])) === 0)
			{
				// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
				counter[1] = incWord(counter[1]);
			}
			return counter;
		}

	    var Encryptor = CTRGladman.Encryptor = CTRGladman.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }

				incCounter(counter);

				var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTRGladman.Decryptor = Encryptor;

	    return CTRGladman;
	}());




	/**
	 * Output Feedback block mode.
	 */
	CryptoJS.mode.OFB = (function () {
	    var OFB = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = OFB.Encryptor = OFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var keystream = this._keystream;

	            // Generate keystream
	            if (iv) {
	                keystream = this._keystream = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    OFB.Decryptor = Encryptor;

	    return OFB;
	}());


	/**
	 * Electronic Codebook block mode.
	 */
	CryptoJS.mode.ECB = (function () {
	    var ECB = CryptoJS.lib.BlockCipherMode.extend();

	    ECB.Encryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.encryptBlock(words, offset);
	        }
	    });

	    ECB.Decryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.decryptBlock(words, offset);
	        }
	    });

	    return ECB;
	}());


	/**
	 * ANSI X.923 padding strategy.
	 */
	CryptoJS.pad.AnsiX923 = {
	    pad: function (data, blockSize) {
	        // Shortcuts
	        var dataSigBytes = data.sigBytes;
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

	        // Compute last byte position
	        var lastBytePos = dataSigBytes + nPaddingBytes - 1;

	        // Pad
	        data.clamp();
	        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
	        data.sigBytes += nPaddingBytes;
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	/**
	 * ISO 10126 padding strategy.
	 */
	CryptoJS.pad.Iso10126 = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	        // Pad
	        data.concat(CryptoJS.lib.WordArray.random(nPaddingBytes - 1)).
	             concat(CryptoJS.lib.WordArray.create([nPaddingBytes << 24], 1));
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	/**
	 * ISO/IEC 9797-1 Padding Method 2.
	 */
	CryptoJS.pad.Iso97971 = {
	    pad: function (data, blockSize) {
	        // Add 0x80 byte
	        data.concat(CryptoJS.lib.WordArray.create([0x80000000], 1));

	        // Zero pad the rest
	        CryptoJS.pad.ZeroPadding.pad(data, blockSize);
	    },

	    unpad: function (data) {
	        // Remove zero padding
	        CryptoJS.pad.ZeroPadding.unpad(data);

	        // Remove one more byte -- the 0x80 byte
	        data.sigBytes--;
	    }
	};


	/**
	 * Zero padding strategy.
	 */
	CryptoJS.pad.ZeroPadding = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Pad
	        data.clamp();
	        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
	    },

	    unpad: function (data) {
	        // Shortcut
	        var dataWords = data.words;

	        // Unpad
	        var i = data.sigBytes - 1;
	        for (var i = data.sigBytes - 1; i >= 0; i--) {
	            if (((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
	                data.sigBytes = i + 1;
	                break;
	            }
	        }
	    }
	};


	/**
	 * A noop padding strategy.
	 */
	CryptoJS.pad.NoPadding = {
	    pad: function () {
	    },

	    unpad: function () {
	    }
	};


	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var CipherParams = C_lib.CipherParams;
	    var C_enc = C.enc;
	    var Hex = C_enc.Hex;
	    var C_format = C.format;

	    var HexFormatter = C_format.Hex = {
	        /**
	         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The hexadecimally encoded string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            return cipherParams.ciphertext.toString(Hex);
	        },

	        /**
	         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
	         *
	         * @param {string} input The hexadecimally encoded string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
	         */
	        parse: function (input) {
	            var ciphertext = Hex.parse(input);
	            return CipherParams.create({ ciphertext: ciphertext });
	        }
	    };
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Lookup tables
	    var SBOX = [];
	    var INV_SBOX = [];
	    var SUB_MIX_0 = [];
	    var SUB_MIX_1 = [];
	    var SUB_MIX_2 = [];
	    var SUB_MIX_3 = [];
	    var INV_SUB_MIX_0 = [];
	    var INV_SUB_MIX_1 = [];
	    var INV_SUB_MIX_2 = [];
	    var INV_SUB_MIX_3 = [];

	    // Compute lookup tables
	    (function () {
	        // Compute double table
	        var d = [];
	        for (var i = 0; i < 256; i++) {
	            if (i < 128) {
	                d[i] = i << 1;
	            } else {
	                d[i] = (i << 1) ^ 0x11b;
	            }
	        }

	        // Walk GF(2^8)
	        var x = 0;
	        var xi = 0;
	        for (var i = 0; i < 256; i++) {
	            // Compute sbox
	            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
	            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
	            SBOX[x] = sx;
	            INV_SBOX[sx] = x;

	            // Compute multiplication
	            var x2 = d[x];
	            var x4 = d[x2];
	            var x8 = d[x4];

	            // Compute sub bytes, mix columns tables
	            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
	            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
	            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
	            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
	            SUB_MIX_3[x] = t;

	            // Compute inv sub bytes, inv mix columns tables
	            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
	            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
	            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
	            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
	            INV_SUB_MIX_3[sx] = t;

	            // Compute next counter
	            if (!x) {
	                x = xi = 1;
	            } else {
	                x = x2 ^ d[d[d[x8 ^ x2]]];
	                xi ^= d[d[xi]];
	            }
	        }
	    }());

	    // Precomputed Rcon lookup
	    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	    /**
	     * AES block cipher algorithm.
	     */
	    var AES = C_algo.AES = BlockCipher.extend({
	        _doReset: function () {
	            var t;

	            // Skip reset of nRounds has been set before and key did not change
	            if (this._nRounds && this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            // Compute number of rounds
	            var nRounds = this._nRounds = keySize + 6;

	            // Compute number of key schedule rows
	            var ksRows = (nRounds + 1) * 4;

	            // Compute key schedule
	            var keySchedule = this._keySchedule = [];
	            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
	                if (ksRow < keySize) {
	                    keySchedule[ksRow] = keyWords[ksRow];
	                } else {
	                    t = keySchedule[ksRow - 1];

	                    if (!(ksRow % keySize)) {
	                        // Rot word
	                        t = (t << 8) | (t >>> 24);

	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

	                        // Mix Rcon
	                        t ^= RCON[(ksRow / keySize) | 0] << 24;
	                    } else if (keySize > 6 && ksRow % keySize == 4) {
	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
	                    }

	                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
	                }
	            }

	            // Compute inv key schedule
	            var invKeySchedule = this._invKeySchedule = [];
	            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
	                var ksRow = ksRows - invKsRow;

	                if (invKsRow % 4) {
	                    var t = keySchedule[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 4];
	                }

	                if (invKsRow < 4 || ksRow <= 4) {
	                    invKeySchedule[invKsRow] = t;
	                } else {
	                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
	                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
	                }
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	        },

	        decryptBlock: function (M, offset) {
	            // Swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;

	            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

	            // Inv swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;
	        },

	        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
	            // Shortcut
	            var nRounds = this._nRounds;

	            // Get input, add round key
	            var s0 = M[offset]     ^ keySchedule[0];
	            var s1 = M[offset + 1] ^ keySchedule[1];
	            var s2 = M[offset + 2] ^ keySchedule[2];
	            var s3 = M[offset + 3] ^ keySchedule[3];

	            // Key schedule row counter
	            var ksRow = 4;

	            // Rounds
	            for (var round = 1; round < nRounds; round++) {
	                // Shift rows, sub bytes, mix columns, add round key
	                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
	                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
	                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
	                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

	                // Update state
	                s0 = t0;
	                s1 = t1;
	                s2 = t2;
	                s3 = t3;
	            }

	            // Shift rows, sub bytes, add round key
	            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
	            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
	            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
	            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

	            // Set output
	            M[offset]     = t0;
	            M[offset + 1] = t1;
	            M[offset + 2] = t2;
	            M[offset + 3] = t3;
	        },

	        keySize: 256/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
	     */
	    C.AES = BlockCipher._createHelper(AES);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Permuted Choice 1 constants
	    var PC1 = [
	        57, 49, 41, 33, 25, 17, 9,  1,
	        58, 50, 42, 34, 26, 18, 10, 2,
	        59, 51, 43, 35, 27, 19, 11, 3,
	        60, 52, 44, 36, 63, 55, 47, 39,
	        31, 23, 15, 7,  62, 54, 46, 38,
	        30, 22, 14, 6,  61, 53, 45, 37,
	        29, 21, 13, 5,  28, 20, 12, 4
	    ];

	    // Permuted Choice 2 constants
	    var PC2 = [
	        14, 17, 11, 24, 1,  5,
	        3,  28, 15, 6,  21, 10,
	        23, 19, 12, 4,  26, 8,
	        16, 7,  27, 20, 13, 2,
	        41, 52, 31, 37, 47, 55,
	        30, 40, 51, 45, 33, 48,
	        44, 49, 39, 56, 34, 53,
	        46, 42, 50, 36, 29, 32
	    ];

	    // Cumulative bit shift constants
	    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

	    // SBOXes and round permutation constants
	    var SBOX_P = [
	        {
	            0x0: 0x808200,
	            0x10000000: 0x8000,
	            0x20000000: 0x808002,
	            0x30000000: 0x2,
	            0x40000000: 0x200,
	            0x50000000: 0x808202,
	            0x60000000: 0x800202,
	            0x70000000: 0x800000,
	            0x80000000: 0x202,
	            0x90000000: 0x800200,
	            0xa0000000: 0x8200,
	            0xb0000000: 0x808000,
	            0xc0000000: 0x8002,
	            0xd0000000: 0x800002,
	            0xe0000000: 0x0,
	            0xf0000000: 0x8202,
	            0x8000000: 0x0,
	            0x18000000: 0x808202,
	            0x28000000: 0x8202,
	            0x38000000: 0x8000,
	            0x48000000: 0x808200,
	            0x58000000: 0x200,
	            0x68000000: 0x808002,
	            0x78000000: 0x2,
	            0x88000000: 0x800200,
	            0x98000000: 0x8200,
	            0xa8000000: 0x808000,
	            0xb8000000: 0x800202,
	            0xc8000000: 0x800002,
	            0xd8000000: 0x8002,
	            0xe8000000: 0x202,
	            0xf8000000: 0x800000,
	            0x1: 0x8000,
	            0x10000001: 0x2,
	            0x20000001: 0x808200,
	            0x30000001: 0x800000,
	            0x40000001: 0x808002,
	            0x50000001: 0x8200,
	            0x60000001: 0x200,
	            0x70000001: 0x800202,
	            0x80000001: 0x808202,
	            0x90000001: 0x808000,
	            0xa0000001: 0x800002,
	            0xb0000001: 0x8202,
	            0xc0000001: 0x202,
	            0xd0000001: 0x800200,
	            0xe0000001: 0x8002,
	            0xf0000001: 0x0,
	            0x8000001: 0x808202,
	            0x18000001: 0x808000,
	            0x28000001: 0x800000,
	            0x38000001: 0x200,
	            0x48000001: 0x8000,
	            0x58000001: 0x800002,
	            0x68000001: 0x2,
	            0x78000001: 0x8202,
	            0x88000001: 0x8002,
	            0x98000001: 0x800202,
	            0xa8000001: 0x202,
	            0xb8000001: 0x808200,
	            0xc8000001: 0x800200,
	            0xd8000001: 0x0,
	            0xe8000001: 0x8200,
	            0xf8000001: 0x808002
	        },
	        {
	            0x0: 0x40084010,
	            0x1000000: 0x4000,
	            0x2000000: 0x80000,
	            0x3000000: 0x40080010,
	            0x4000000: 0x40000010,
	            0x5000000: 0x40084000,
	            0x6000000: 0x40004000,
	            0x7000000: 0x10,
	            0x8000000: 0x84000,
	            0x9000000: 0x40004010,
	            0xa000000: 0x40000000,
	            0xb000000: 0x84010,
	            0xc000000: 0x80010,
	            0xd000000: 0x0,
	            0xe000000: 0x4010,
	            0xf000000: 0x40080000,
	            0x800000: 0x40004000,
	            0x1800000: 0x84010,
	            0x2800000: 0x10,
	            0x3800000: 0x40004010,
	            0x4800000: 0x40084010,
	            0x5800000: 0x40000000,
	            0x6800000: 0x80000,
	            0x7800000: 0x40080010,
	            0x8800000: 0x80010,
	            0x9800000: 0x0,
	            0xa800000: 0x4000,
	            0xb800000: 0x40080000,
	            0xc800000: 0x40000010,
	            0xd800000: 0x84000,
	            0xe800000: 0x40084000,
	            0xf800000: 0x4010,
	            0x10000000: 0x0,
	            0x11000000: 0x40080010,
	            0x12000000: 0x40004010,
	            0x13000000: 0x40084000,
	            0x14000000: 0x40080000,
	            0x15000000: 0x10,
	            0x16000000: 0x84010,
	            0x17000000: 0x4000,
	            0x18000000: 0x4010,
	            0x19000000: 0x80000,
	            0x1a000000: 0x80010,
	            0x1b000000: 0x40000010,
	            0x1c000000: 0x84000,
	            0x1d000000: 0x40004000,
	            0x1e000000: 0x40000000,
	            0x1f000000: 0x40084010,
	            0x10800000: 0x84010,
	            0x11800000: 0x80000,
	            0x12800000: 0x40080000,
	            0x13800000: 0x4000,
	            0x14800000: 0x40004000,
	            0x15800000: 0x40084010,
	            0x16800000: 0x10,
	            0x17800000: 0x40000000,
	            0x18800000: 0x40084000,
	            0x19800000: 0x40000010,
	            0x1a800000: 0x40004010,
	            0x1b800000: 0x80010,
	            0x1c800000: 0x0,
	            0x1d800000: 0x4010,
	            0x1e800000: 0x40080010,
	            0x1f800000: 0x84000
	        },
	        {
	            0x0: 0x104,
	            0x100000: 0x0,
	            0x200000: 0x4000100,
	            0x300000: 0x10104,
	            0x400000: 0x10004,
	            0x500000: 0x4000004,
	            0x600000: 0x4010104,
	            0x700000: 0x4010000,
	            0x800000: 0x4000000,
	            0x900000: 0x4010100,
	            0xa00000: 0x10100,
	            0xb00000: 0x4010004,
	            0xc00000: 0x4000104,
	            0xd00000: 0x10000,
	            0xe00000: 0x4,
	            0xf00000: 0x100,
	            0x80000: 0x4010100,
	            0x180000: 0x4010004,
	            0x280000: 0x0,
	            0x380000: 0x4000100,
	            0x480000: 0x4000004,
	            0x580000: 0x10000,
	            0x680000: 0x10004,
	            0x780000: 0x104,
	            0x880000: 0x4,
	            0x980000: 0x100,
	            0xa80000: 0x4010000,
	            0xb80000: 0x10104,
	            0xc80000: 0x10100,
	            0xd80000: 0x4000104,
	            0xe80000: 0x4010104,
	            0xf80000: 0x4000000,
	            0x1000000: 0x4010100,
	            0x1100000: 0x10004,
	            0x1200000: 0x10000,
	            0x1300000: 0x4000100,
	            0x1400000: 0x100,
	            0x1500000: 0x4010104,
	            0x1600000: 0x4000004,
	            0x1700000: 0x0,
	            0x1800000: 0x4000104,
	            0x1900000: 0x4000000,
	            0x1a00000: 0x4,
	            0x1b00000: 0x10100,
	            0x1c00000: 0x4010000,
	            0x1d00000: 0x104,
	            0x1e00000: 0x10104,
	            0x1f00000: 0x4010004,
	            0x1080000: 0x4000000,
	            0x1180000: 0x104,
	            0x1280000: 0x4010100,
	            0x1380000: 0x0,
	            0x1480000: 0x10004,
	            0x1580000: 0x4000100,
	            0x1680000: 0x100,
	            0x1780000: 0x4010004,
	            0x1880000: 0x10000,
	            0x1980000: 0x4010104,
	            0x1a80000: 0x10104,
	            0x1b80000: 0x4000004,
	            0x1c80000: 0x4000104,
	            0x1d80000: 0x4010000,
	            0x1e80000: 0x4,
	            0x1f80000: 0x10100
	        },
	        {
	            0x0: 0x80401000,
	            0x10000: 0x80001040,
	            0x20000: 0x401040,
	            0x30000: 0x80400000,
	            0x40000: 0x0,
	            0x50000: 0x401000,
	            0x60000: 0x80000040,
	            0x70000: 0x400040,
	            0x80000: 0x80000000,
	            0x90000: 0x400000,
	            0xa0000: 0x40,
	            0xb0000: 0x80001000,
	            0xc0000: 0x80400040,
	            0xd0000: 0x1040,
	            0xe0000: 0x1000,
	            0xf0000: 0x80401040,
	            0x8000: 0x80001040,
	            0x18000: 0x40,
	            0x28000: 0x80400040,
	            0x38000: 0x80001000,
	            0x48000: 0x401000,
	            0x58000: 0x80401040,
	            0x68000: 0x0,
	            0x78000: 0x80400000,
	            0x88000: 0x1000,
	            0x98000: 0x80401000,
	            0xa8000: 0x400000,
	            0xb8000: 0x1040,
	            0xc8000: 0x80000000,
	            0xd8000: 0x400040,
	            0xe8000: 0x401040,
	            0xf8000: 0x80000040,
	            0x100000: 0x400040,
	            0x110000: 0x401000,
	            0x120000: 0x80000040,
	            0x130000: 0x0,
	            0x140000: 0x1040,
	            0x150000: 0x80400040,
	            0x160000: 0x80401000,
	            0x170000: 0x80001040,
	            0x180000: 0x80401040,
	            0x190000: 0x80000000,
	            0x1a0000: 0x80400000,
	            0x1b0000: 0x401040,
	            0x1c0000: 0x80001000,
	            0x1d0000: 0x400000,
	            0x1e0000: 0x40,
	            0x1f0000: 0x1000,
	            0x108000: 0x80400000,
	            0x118000: 0x80401040,
	            0x128000: 0x0,
	            0x138000: 0x401000,
	            0x148000: 0x400040,
	            0x158000: 0x80000000,
	            0x168000: 0x80001040,
	            0x178000: 0x40,
	            0x188000: 0x80000040,
	            0x198000: 0x1000,
	            0x1a8000: 0x80001000,
	            0x1b8000: 0x80400040,
	            0x1c8000: 0x1040,
	            0x1d8000: 0x80401000,
	            0x1e8000: 0x400000,
	            0x1f8000: 0x401040
	        },
	        {
	            0x0: 0x80,
	            0x1000: 0x1040000,
	            0x2000: 0x40000,
	            0x3000: 0x20000000,
	            0x4000: 0x20040080,
	            0x5000: 0x1000080,
	            0x6000: 0x21000080,
	            0x7000: 0x40080,
	            0x8000: 0x1000000,
	            0x9000: 0x20040000,
	            0xa000: 0x20000080,
	            0xb000: 0x21040080,
	            0xc000: 0x21040000,
	            0xd000: 0x0,
	            0xe000: 0x1040080,
	            0xf000: 0x21000000,
	            0x800: 0x1040080,
	            0x1800: 0x21000080,
	            0x2800: 0x80,
	            0x3800: 0x1040000,
	            0x4800: 0x40000,
	            0x5800: 0x20040080,
	            0x6800: 0x21040000,
	            0x7800: 0x20000000,
	            0x8800: 0x20040000,
	            0x9800: 0x0,
	            0xa800: 0x21040080,
	            0xb800: 0x1000080,
	            0xc800: 0x20000080,
	            0xd800: 0x21000000,
	            0xe800: 0x1000000,
	            0xf800: 0x40080,
	            0x10000: 0x40000,
	            0x11000: 0x80,
	            0x12000: 0x20000000,
	            0x13000: 0x21000080,
	            0x14000: 0x1000080,
	            0x15000: 0x21040000,
	            0x16000: 0x20040080,
	            0x17000: 0x1000000,
	            0x18000: 0x21040080,
	            0x19000: 0x21000000,
	            0x1a000: 0x1040000,
	            0x1b000: 0x20040000,
	            0x1c000: 0x40080,
	            0x1d000: 0x20000080,
	            0x1e000: 0x0,
	            0x1f000: 0x1040080,
	            0x10800: 0x21000080,
	            0x11800: 0x1000000,
	            0x12800: 0x1040000,
	            0x13800: 0x20040080,
	            0x14800: 0x20000000,
	            0x15800: 0x1040080,
	            0x16800: 0x80,
	            0x17800: 0x21040000,
	            0x18800: 0x40080,
	            0x19800: 0x21040080,
	            0x1a800: 0x0,
	            0x1b800: 0x21000000,
	            0x1c800: 0x1000080,
	            0x1d800: 0x40000,
	            0x1e800: 0x20040000,
	            0x1f800: 0x20000080
	        },
	        {
	            0x0: 0x10000008,
	            0x100: 0x2000,
	            0x200: 0x10200000,
	            0x300: 0x10202008,
	            0x400: 0x10002000,
	            0x500: 0x200000,
	            0x600: 0x200008,
	            0x700: 0x10000000,
	            0x800: 0x0,
	            0x900: 0x10002008,
	            0xa00: 0x202000,
	            0xb00: 0x8,
	            0xc00: 0x10200008,
	            0xd00: 0x202008,
	            0xe00: 0x2008,
	            0xf00: 0x10202000,
	            0x80: 0x10200000,
	            0x180: 0x10202008,
	            0x280: 0x8,
	            0x380: 0x200000,
	            0x480: 0x202008,
	            0x580: 0x10000008,
	            0x680: 0x10002000,
	            0x780: 0x2008,
	            0x880: 0x200008,
	            0x980: 0x2000,
	            0xa80: 0x10002008,
	            0xb80: 0x10200008,
	            0xc80: 0x0,
	            0xd80: 0x10202000,
	            0xe80: 0x202000,
	            0xf80: 0x10000000,
	            0x1000: 0x10002000,
	            0x1100: 0x10200008,
	            0x1200: 0x10202008,
	            0x1300: 0x2008,
	            0x1400: 0x200000,
	            0x1500: 0x10000000,
	            0x1600: 0x10000008,
	            0x1700: 0x202000,
	            0x1800: 0x202008,
	            0x1900: 0x0,
	            0x1a00: 0x8,
	            0x1b00: 0x10200000,
	            0x1c00: 0x2000,
	            0x1d00: 0x10002008,
	            0x1e00: 0x10202000,
	            0x1f00: 0x200008,
	            0x1080: 0x8,
	            0x1180: 0x202000,
	            0x1280: 0x200000,
	            0x1380: 0x10000008,
	            0x1480: 0x10002000,
	            0x1580: 0x2008,
	            0x1680: 0x10202008,
	            0x1780: 0x10200000,
	            0x1880: 0x10202000,
	            0x1980: 0x10200008,
	            0x1a80: 0x2000,
	            0x1b80: 0x202008,
	            0x1c80: 0x200008,
	            0x1d80: 0x0,
	            0x1e80: 0x10000000,
	            0x1f80: 0x10002008
	        },
	        {
	            0x0: 0x100000,
	            0x10: 0x2000401,
	            0x20: 0x400,
	            0x30: 0x100401,
	            0x40: 0x2100401,
	            0x50: 0x0,
	            0x60: 0x1,
	            0x70: 0x2100001,
	            0x80: 0x2000400,
	            0x90: 0x100001,
	            0xa0: 0x2000001,
	            0xb0: 0x2100400,
	            0xc0: 0x2100000,
	            0xd0: 0x401,
	            0xe0: 0x100400,
	            0xf0: 0x2000000,
	            0x8: 0x2100001,
	            0x18: 0x0,
	            0x28: 0x2000401,
	            0x38: 0x2100400,
	            0x48: 0x100000,
	            0x58: 0x2000001,
	            0x68: 0x2000000,
	            0x78: 0x401,
	            0x88: 0x100401,
	            0x98: 0x2000400,
	            0xa8: 0x2100000,
	            0xb8: 0x100001,
	            0xc8: 0x400,
	            0xd8: 0x2100401,
	            0xe8: 0x1,
	            0xf8: 0x100400,
	            0x100: 0x2000000,
	            0x110: 0x100000,
	            0x120: 0x2000401,
	            0x130: 0x2100001,
	            0x140: 0x100001,
	            0x150: 0x2000400,
	            0x160: 0x2100400,
	            0x170: 0x100401,
	            0x180: 0x401,
	            0x190: 0x2100401,
	            0x1a0: 0x100400,
	            0x1b0: 0x1,
	            0x1c0: 0x0,
	            0x1d0: 0x2100000,
	            0x1e0: 0x2000001,
	            0x1f0: 0x400,
	            0x108: 0x100400,
	            0x118: 0x2000401,
	            0x128: 0x2100001,
	            0x138: 0x1,
	            0x148: 0x2000000,
	            0x158: 0x100000,
	            0x168: 0x401,
	            0x178: 0x2100400,
	            0x188: 0x2000001,
	            0x198: 0x2100000,
	            0x1a8: 0x0,
	            0x1b8: 0x2100401,
	            0x1c8: 0x100401,
	            0x1d8: 0x400,
	            0x1e8: 0x2000400,
	            0x1f8: 0x100001
	        },
	        {
	            0x0: 0x8000820,
	            0x1: 0x20000,
	            0x2: 0x8000000,
	            0x3: 0x20,
	            0x4: 0x20020,
	            0x5: 0x8020820,
	            0x6: 0x8020800,
	            0x7: 0x800,
	            0x8: 0x8020000,
	            0x9: 0x8000800,
	            0xa: 0x20800,
	            0xb: 0x8020020,
	            0xc: 0x820,
	            0xd: 0x0,
	            0xe: 0x8000020,
	            0xf: 0x20820,
	            0x80000000: 0x800,
	            0x80000001: 0x8020820,
	            0x80000002: 0x8000820,
	            0x80000003: 0x8000000,
	            0x80000004: 0x8020000,
	            0x80000005: 0x20800,
	            0x80000006: 0x20820,
	            0x80000007: 0x20,
	            0x80000008: 0x8000020,
	            0x80000009: 0x820,
	            0x8000000a: 0x20020,
	            0x8000000b: 0x8020800,
	            0x8000000c: 0x0,
	            0x8000000d: 0x8020020,
	            0x8000000e: 0x8000800,
	            0x8000000f: 0x20000,
	            0x10: 0x20820,
	            0x11: 0x8020800,
	            0x12: 0x20,
	            0x13: 0x800,
	            0x14: 0x8000800,
	            0x15: 0x8000020,
	            0x16: 0x8020020,
	            0x17: 0x20000,
	            0x18: 0x0,
	            0x19: 0x20020,
	            0x1a: 0x8020000,
	            0x1b: 0x8000820,
	            0x1c: 0x8020820,
	            0x1d: 0x20800,
	            0x1e: 0x820,
	            0x1f: 0x8000000,
	            0x80000010: 0x20000,
	            0x80000011: 0x800,
	            0x80000012: 0x8020020,
	            0x80000013: 0x20820,
	            0x80000014: 0x20,
	            0x80000015: 0x8020000,
	            0x80000016: 0x8000000,
	            0x80000017: 0x8000820,
	            0x80000018: 0x8020820,
	            0x80000019: 0x8000020,
	            0x8000001a: 0x8000800,
	            0x8000001b: 0x0,
	            0x8000001c: 0x20800,
	            0x8000001d: 0x820,
	            0x8000001e: 0x20020,
	            0x8000001f: 0x8020800
	        }
	    ];

	    // Masks that select the SBOX input
	    var SBOX_MASK = [
	        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
	        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
	    ];

	    /**
	     * DES block cipher algorithm.
	     */
	    var DES = C_algo.DES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Select 56 bits according to PC1
	            var keyBits = [];
	            for (var i = 0; i < 56; i++) {
	                var keyBitPos = PC1[i] - 1;
	                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
	            }

	            // Assemble 16 subkeys
	            var subKeys = this._subKeys = [];
	            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
	                // Create subkey
	                var subKey = subKeys[nSubKey] = [];

	                // Shortcut
	                var bitShift = BIT_SHIFTS[nSubKey];

	                // Select 48 bits according to PC2
	                for (var i = 0; i < 24; i++) {
	                    // Select from the left 28 key bits
	                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

	                    // Select from the right 28 key bits
	                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
	                }

	                // Since each subkey is applied to an expanded 32-bit input,
	                // the subkey can be broken into 8 values scaled to 32-bits,
	                // which allows the key to be used without expansion
	                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
	                for (var i = 1; i < 7; i++) {
	                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
	                }
	                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
	            }

	            // Compute inverse subkeys
	            var invSubKeys = this._invSubKeys = [];
	            for (var i = 0; i < 16; i++) {
	                invSubKeys[i] = subKeys[15 - i];
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._subKeys);
	        },

	        decryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._invSubKeys);
	        },

	        _doCryptBlock: function (M, offset, subKeys) {
	            // Get input
	            this._lBlock = M[offset];
	            this._rBlock = M[offset + 1];

	            // Initial permutation
	            exchangeLR.call(this, 4,  0x0f0f0f0f);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeLR.call(this, 1,  0x55555555);

	            // Rounds
	            for (var round = 0; round < 16; round++) {
	                // Shortcuts
	                var subKey = subKeys[round];
	                var lBlock = this._lBlock;
	                var rBlock = this._rBlock;

	                // Feistel function
	                var f = 0;
	                for (var i = 0; i < 8; i++) {
	                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
	                }
	                this._lBlock = rBlock;
	                this._rBlock = lBlock ^ f;
	            }

	            // Undo swap from last round
	            var t = this._lBlock;
	            this._lBlock = this._rBlock;
	            this._rBlock = t;

	            // Final permutation
	            exchangeLR.call(this, 1,  0x55555555);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeLR.call(this, 4,  0x0f0f0f0f);

	            // Set output
	            M[offset] = this._lBlock;
	            M[offset + 1] = this._rBlock;
	        },

	        keySize: 64/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    // Swap bits across the left and right words
	    function exchangeLR(offset, mask) {
	        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
	        this._rBlock ^= t;
	        this._lBlock ^= t << offset;
	    }

	    function exchangeRL(offset, mask) {
	        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
	        this._lBlock ^= t;
	        this._rBlock ^= t << offset;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
	     */
	    C.DES = BlockCipher._createHelper(DES);

	    /**
	     * Triple-DES block cipher algorithm.
	     */
	    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            // Make sure the key length is valid (64, 128 or >= 192 bit)
	            if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
	                throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
	            }

	            // Extend the key according to the keying options defined in 3DES standard
	            var key1 = keyWords.slice(0, 2);
	            var key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
	            var key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

	            // Create DES instances
	            this._des1 = DES.createEncryptor(WordArray.create(key1));
	            this._des2 = DES.createEncryptor(WordArray.create(key2));
	            this._des3 = DES.createEncryptor(WordArray.create(key3));
	        },

	        encryptBlock: function (M, offset) {
	            this._des1.encryptBlock(M, offset);
	            this._des2.decryptBlock(M, offset);
	            this._des3.encryptBlock(M, offset);
	        },

	        decryptBlock: function (M, offset) {
	            this._des3.decryptBlock(M, offset);
	            this._des2.encryptBlock(M, offset);
	            this._des1.decryptBlock(M, offset);
	        },

	        keySize: 192/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
	     */
	    C.TripleDES = BlockCipher._createHelper(TripleDES);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    /**
	     * RC4 stream cipher algorithm.
	     */
	    var RC4 = C_algo.RC4 = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            var keySigBytes = key.sigBytes;

	            // Init sbox
	            var S = this._S = [];
	            for (var i = 0; i < 256; i++) {
	                S[i] = i;
	            }

	            // Key setup
	            for (var i = 0, j = 0; i < 256; i++) {
	                var keyByteIndex = i % keySigBytes;
	                var keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

	                j = (j + S[i] + keyByte) % 256;

	                // Swap
	                var t = S[i];
	                S[i] = S[j];
	                S[j] = t;
	            }

	            // Counters
	            this._i = this._j = 0;
	        },

	        _doProcessBlock: function (M, offset) {
	            M[offset] ^= generateKeystreamWord.call(this);
	        },

	        keySize: 256/32,

	        ivSize: 0
	    });

	    function generateKeystreamWord() {
	        // Shortcuts
	        var S = this._S;
	        var i = this._i;
	        var j = this._j;

	        // Generate keystream word
	        var keystreamWord = 0;
	        for (var n = 0; n < 4; n++) {
	            i = (i + 1) % 256;
	            j = (j + S[i]) % 256;

	            // Swap
	            var t = S[i];
	            S[i] = S[j];
	            S[j] = t;

	            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
	        }

	        // Update counters
	        this._i = i;
	        this._j = j;

	        return keystreamWord;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4 = StreamCipher._createHelper(RC4);

	    /**
	     * Modified RC4 stream cipher algorithm.
	     */
	    var RC4Drop = C_algo.RC4Drop = RC4.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} drop The number of keystream words to drop. Default 192
	         */
	        cfg: RC4.cfg.extend({
	            drop: 192
	        }),

	        _doReset: function () {
	            RC4._doReset.call(this);

	            // Drop
	            for (var i = this.cfg.drop; i > 0; i--) {
	                generateKeystreamWord.call(this);
	            }
	        }
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm
	     */
	    var Rabbit = C_algo.Rabbit = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
	                       (((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
	            }

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
	     */
	    C.Rabbit = StreamCipher._createHelper(Rabbit);
	}());


	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm.
	     *
	     * This is a legacy version that neglected to convert the key to little-endian.
	     * This error doesn't affect the cipher's security,
	     * but it does affect its compatibility with other implementations.
	     */
	    var RabbitLegacy = C_algo.RabbitLegacy = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
	     */
	    C.RabbitLegacy = StreamCipher._createHelper(RabbitLegacy);
	}());


	return CryptoJS;

}));; })(__mod, __mod.exports = {});
    if (__mod.exports && __mod.exports.AES) return __mod.exports;
  } catch (e) { }
  return null;
})();

// ---------- __OK_NODE_CRYPTO: require('crypto') 替身 ----------
// 覆盖 22 源用到的 API: randomBytes / createHash / createHmac / createCipheriv /
// createDecipheriv / generateKeyPairSync('x25519') / diffieHellman / createPublicKey /
// publicEncrypt(PKCS1) / createPrivateKey(JWK)
var __OK_NODE_CRYPTO = (function () {
  function randBytes(n) { var a = [], i; for (i = 0; i < n; i++) a.push(Math.floor(Math.random() * 256)); return new __OkBuffer(a); }
  function hashHex(algo, data) {
    var a = __okToArr(data);
    if (algo === 'sha256') return Mc_Hex(Mc_Sha256(a));
    if (algo === 'sha1') return Mc_Hex(Mc_Sha1(a));
    if (algo === 'md5') return Mc_Hex(Mc_Md5(a));
    throw new Error('unsupported hash: ' + algo);
  }
  function hmacHex(algo, key, data) {
    if (algo !== 'sha256') throw new Error('unsupported hmac: ' + algo);
    return Mc_Hex(Mc_HmacSha256(__okToArr(key), __okToArr(data)));
  }
  // ---- AES-CBC/ECB 原语（走 CryptoJS）----
  function aesRaw(algo, key, iv, data, enc) {
    var Crypto = __OK_CRYPTOJS;
    if (!Crypto) throw new Error('no CryptoJS');
    var kw = Crypto.enc.Utf8.parse ? null : null;
    var keyArr = __okToArr(key), ivArr = iv ? __okToArr(iv) : null;
    var keyHex = Mc_Hex(keyArr), ivHex = ivArr ? Mc_Hex(ivArr) : '';
    var dataB64 = __okB64(__okToArr(data));
    var mode = (algo.indexOf('ecb') >= 0) ? Crypto.mode.ECB : Crypto.mode.CBC;
    var opt = { mode: mode, padding: Crypto.pad.Pkcs7, format: Crypto.format.OpenSSL };
    if (ivArr) opt.iv = Crypto.enc.Hex.parse(ivHex);
    var kp = Crypto.enc.Hex.parse(keyHex);
    var cp = Crypto.enc.Base64.parse(dataB64);
    var out;
    if (enc) {
      out = Crypto.AES.encrypt(cp, kp, opt);
      // CipherParams → ciphertext bytes
      var ct = out.ciphertext;
      return new __OkBuffer(__okToArr(ct.words ? __OK_WA2Arr(ct) : ct));
    } else {
      var dec = Crypto.AES.decrypt({ ciphertext: cp }, kp, opt);
      return new __OkBuffer(__okToArr(__OK_WA2Arr(dec)));
    }
  }
  function __OK_WA2Arr(wa) {
    // CryptoJS WordArray → 字节数组
    if (wa && wa.words && typeof wa.sigBytes === 'number') {
      var out = [], w, i;
      for (i = 0; i < wa.sigBytes; i++) {
        w = wa.words[i >>> 2];
        out.push((w >>> (24 - (i % 4) * 8)) & 0xFF);
      }
      return out;
    }
    return __okToArr(wa);
  }
  function __OK_Arr2WA(arr) {
    var Crypto = __OK_CRYPTOJS, words = [], i;
    for (i = 0; i < arr.length; i++) words[i >>> 2] = (words[i >>> 2] || 0) | ((arr[i] & 0xFF) << (24 - (i % 4) * 8));
    return (Crypto.lib ? Crypto.lib.WordArray : { create: function (w, s) { return { words: w, sigBytes: s } } }).create(words, arr.length);
  }

  var C = {
    randomBytes: randBytes,
    createHash: function (algo) {
      var algoL = String(algo).toLowerCase(), chunks = [];
      return {
        update: function (d) { chunks = chunks.concat(__okToArr(d)); return this; },
        digest: function (enc) {
          var hexStr;
          if (algoL === 'sha256') hexStr = Mc_Sha256(chunks);
          else if (algoL === 'sha1') hexStr = Mc_Sha1(chunks);
          else if (algoL === 'md5') hexStr = Mc_Md5(chunks);
          else throw new Error('unsupported hash ' + algo);
          // Mc_* 返回 hex STRING → 还原成字节再按 enc 输出
          var bytes = [];
          for (var i = 0; i + 1 < hexStr.length; i += 2) bytes.push(parseInt(hexStr.substr(i, 2), 16));
          if (enc === 'base64') return __okB64(bytes);
          if (enc === 'base64url') return __okB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          return hexStr;
        }
      };
    },
    createHmac: function (algo, key) {
      var chunks = [];
      var kArr = (typeof key === 'string') ? __okUtf8Bytes(key) : __okToArr(key);
      return {
        update: function (d) { chunks = chunks.concat(__okToArr(d)); return this; },
        digest: function (enc) {
          // ★ __OK_MC_HMAC256 返回 hex STRING（64 字符）— 必须先还原成 32B 再编码
          var hexStr = Mc_HmacSha256(kArr, chunks);
          var bytes = [];
          for (var i = 0; i + 1 < hexStr.length; i += 2) bytes.push(parseInt(hexStr.substr(i, 2), 16));
          if (enc === 'base64') return __okB64(bytes);
          if (enc === 'base64url') return __okB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          return hexStr;
        }
      };
    },
    createCipheriv: function (algo, key, iv) {
      var a = String(algo).toLowerCase(), chunks = [];
      var isGcm = a.indexOf('gcm') >= 0;
      var gcmTag = null;
      return {
        update: function (d) { chunks = chunks.concat(__okToArr(d)); return new __OkBuffer([]); },
        final: function () {
          var dataB = chunks; chunks = [];
          if (isGcm) {
            var keyHex = Mc_Hex(__okToArr(key)), ivHex = Mc_Hex(__okToArr(iv));
            var r = __gcm.encrypt(__okB64(dataB), keyHex, { keyFormat: 'hex', ivFormat: 'hex', iv: ivHex, input: 'base64', output: 'base64' });
            var all = __okUnb64(r);
            gcmTag = new __OkBuffer(all.slice(all.length - 16));
            return new __OkBuffer(all.slice(0, all.length - 16));
          }
          return aesRaw(a, key, iv, dataB, true);
        },
        getAuthTag: function () { return gcmTag || new __OkBuffer([]); },
        setAAD: function () { return this; },
        setAutoPadding: function () { return this; }
      };
    },
    createDecipheriv: function (algo, key, iv) {
      var a = String(algo).toLowerCase();
      var isGcm = a.indexOf('gcm') >= 0;
      var ctx = { tag: null, aad: null, chunks: [] };
      return {
        update: function (d) { ctx.chunks = ctx.chunks.concat(__okToArr(d)); return new __OkBuffer([]); },
        final: function () {
          var dataB = ctx.chunks; ctx.chunks = [];
          if (isGcm) {
            var keyHex = Mc_Hex(__okToArr(key)), ivHex = Mc_Hex(__okToArr(iv));
            var all = dataB.concat(ctx.tag || []);
            var pt = __gcm.decrypt(__okB64(all), keyHex, { keyFormat: 'hex', ivFormat: 'hex', iv: ivHex, input: 'base64', output: 'base64' });
            return new __OkBuffer(__okUnb64(pt));
          }
          return aesRaw(a, key, iv, dataB, false);
        },
        setAuthTag: function (t) { ctx.tag = __okToArr(t); return this; },
        setAAD: function (a2) { ctx.aad = __okToArr(a2); return this; },
        setAutoPadding: function () { return this; }
      };
    },
    // ---- X25519 JWK 风格（4K影视 用）----
    generateKeyPairSync: function (type) {
      if (String(type) !== 'x25519') throw new Error('only x25519 supported, got ' + type);
      var priv = X25519.rand32();
      var pub = X25519.pub(priv);
      var privB64u = __okB64(priv).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      var pubB64u = __okB64(pub).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      return {
        privateKey: {
          __type: 'x25519priv', d: priv.slice(),
          export: function (o) {
            if (o && o.format === 'jwk') return { kty: 'OKP', crv: 'X25519', d: privB64u, x: pubB64u };
            return new __OkBuffer(priv);
          }
        },
        publicKey: {
          __type: 'x25519pub', x: pub.slice(),
          export: function (o) {
            if (o && o.format === 'jwk') return { kty: 'OKP', crv: 'X25519', x: pubB64u };
            return new __OkBuffer(pub);
          }
        }
      };
    },
    createPrivateKey: function (o) {
      var d;
      if (o && o.key && o.key.d) d = __okUnb64(o.key.d.replace(/-/g, '+').replace(/_/g, '/'));
      else if (o && o.key && o.key.kty) throw new Error('bad jwk');
      else throw new Error('createPrivateKey: unsupported');
      return { __type: 'x25519priv', d: d, export: function (f) { return f && f.format === 'jwk' ? { kty: 'OKP', crv: 'X25519', d: __okB64(d) } : new __OkBuffer(d); } };
    },
    createPublicKey: function (o) {
      // 两种形态: {key: jwk} 或 PEM 字符串
      var xArr;
      if (typeof o === 'string') return { __pem: o };
      if (o && o.key) {
        if (o.key.kty === 'OKP' && o.key.x) xArr = __okUnb64(String(o.key.x).replace(/-/g, '+').replace(/_/g, '/'));
        else if (typeof o.key === 'string') return { __pem: o.key };
        else throw new Error('createPublicKey: unsupported jwk');
      } else if (o && o.kty === 'OKP' && o.x) xArr = __okUnb64(String(o.x).replace(/-/g, '+').replace(/_/g, '/'));
      else throw new Error('createPublicKey: unsupported');
      return { __type: 'x25519pub', x: xArr };
    },
    diffieHellman: function (o) {
      if (!o || !o.privateKey || !o.publicKey) throw new Error('diffieHellman: bad args');
      var priv = o.privateKey.__type === 'x25519priv' ? o.privateKey.d : __okToArr(o.privateKey);
      var pub = o.publicKey.__type === 'x25519pub' ? o.publicKey.x : __okToArr(o.publicKey);
      return new __OkBuffer(X25519.shared(priv, pub));
    },
    constants: { RSA_PKCS1_PADDING: 1, RSA_PKCS1_OAEP_PADDING: 4, RSA_NO_PADDING: 3 }
  };
  // RSA publicEncrypt 走纯 JS __rsaJS
  C.publicEncrypt = function (o, data) {
    var pem = (typeof o.key === 'string') ? o.key : (o.key && o.key.__pem);
    if (!pem) throw new Error('publicEncrypt: need PEM');
    var padding = o.padding;
    var b64 = __rsaJS.encrypt(__okUtf8FromBytes(__okToArr(data)), pem, { padding: (padding === 1 ? 'PKCS1' : (padding === 3 ? 'NONE' : 'PKCS1')), output: 'base64' });
    return new __OkBuffer(__okUnb64(b64));
  };
  C.publicDecrypt = function (o, data) {
    var pem = (typeof o.key === 'string') ? o.key : (o.key && o.key.__pem);
    var out = __rsaJS.decrypt(__okUtf8FromBytes(__okToArr(data)), pem, { padding: 'PKCS1' });
    return new __OkBuffer(__okUtf8Bytes(out));
  };
  C.privateDecrypt = function (o, data) {
    var pem = (typeof o.key === 'string') ? o.key : (o.key && (o.key.__pem || o.key.PEM));
    if (!pem) throw new Error('privateDecrypt: need PEM private key');
    // data 是字节(Buffer/Uint8Array/latin1串) → 转 hex 走 __rsaJS 的 hex 输入(避免 latin1→b64 混淆)
    var hex = Mc_Hex(__okToArr(data));
    var out = __rsaJS.decrypt(hex, pem, { input: 'hex' });
    return new __OkBuffer(__okUtf8Bytes(out));
  };
  // ---- secp256r1/prime256v1 ECDH（纯 JS P256，KAT 已过）— Node crypto.createECDH 包装 ----
  // 供猫源里 __NC.createECDH("prime256v1") 的握手路径（如咕噜 GuluCrypto）在无 Node 环境走纯 JS。
  C.createECDH = function (curve) {
    var cn = String(curve == null ? '' : curve).replace(/[-_\s]/g, '').toLowerCase();
    if (cn !== 'prime256v1' && cn !== 'secp256r1' && cn !== 'p256')
      throw new Error('createECDH: only prime256v1 supported, got: ' + curve);
    if (typeof __OK_P256 === 'undefined')
      throw new Error('createECDH: __OK_P256 not loaded (shim/p256ecdh.js missing?)');
    var st = { priv: null, pub: null };
    var self = {
      generateKeys: function () {
        var b = [], i;
        for (i = 0; i < 32; i++) b.push(Math.floor(Math.random() * 256) & 0xFF);
        var idx = 0;
        var kp = __OK_P256.genKeyPair(function () { return b[idx++]; });
        st.priv = kp.priv; st.pub = kp.pub;
        return st.priv; // 普通字节数组（Node 版返回 Buffer，这里数组即可 slice.call）
      },
      setPrivateKey: function (k) {
        st.priv = __okToArr(k); st.pub = null;
        return self;
      },
      getPrivateKey: function () {
        if (!st.priv) throw new Error('ECDH: private key not set');
        return st.priv;
      },
      getPublicKey: function () {
        if (!st.pub) {
          if (!st.priv) throw new Error('ECDH: key not set (call generateKeys or setPrivateKey)');
          st.pub = __OK_P256.pubFromPriv(st.priv); // 04||X||Y (65B)
        }
        return st.pub;
      },
      computeSecret: function (peerPub) {
        if (!st.priv) throw new Error('ECDH: private key not set');
        return __OK_P256.shared(st.priv, __okToArr(peerPub)); // 32B shared x
      }
    };
    return self;
  };
  return C;
})();

// ---------- __gcmDecryptRaw 已并入 createDecipheriv GCM 路径 ----------

// ---------- __OK_ZLIB: pako 驱动的 zlib 替身 ----------
var __OK_ZLIB = (function () {
  var pako = (typeof __OK_PAKO !== 'undefined') ? __OK_PAKO : (typeof globalThis !== 'undefined' ? globalThis.pako : null);
  function toU8(arr) { var u = new Uint8Array(arr.length), i; for (i = 0; i < arr.length; i++) u[i] = arr[i] & 0xFF; return u; }
  function run(fn, data) {
    if (!pako || !pako[fn]) throw new Error('pako.' + fn + ' 不可用');
    var input = (data instanceof __OkBuffer) ? data._a : __okToArr(data);
    var out = pako[fn](toU8(input));
    var a = [], i; for (i = 0; i < out.length; i++) a.push(out[i]);
    return new __OkBuffer(a);
  }
  return {
    inflateSync: function (d) { return run('inflate', d); },
    inflateRawSync: function (d) { return run('inflateRaw', d); },
    gunzipSync: function (d) { return run('ungzip', d); },
    gzipSync: function (d) { return run('gzip', d); },
    deflateSync: function (d) { return run('deflate', d); },
    deflateRawSync: function (d) { return run('deflateRaw', d); },
    unzipSync: function (d) { return run('unzip', d); },
    brotliDecompressSync: function (d) {
      // 无 brotli → 抛错（源侧 catch 后按未压缩处理或跳过）
      throw new Error('brotli not available');
    }
  };
})();

// ---------- __OK_HTTPMOD: require('http'/'https') 替身 ----------
// ★ 区分 http/https 模块: __OK_HTTPMOD 标记 __proto='http'，https 模块包一层覆盖 protocol
function __okHexArr(a) { var s2 = '', i; for (i = 0; i < a.length; i++) s2 += ((a[i] < 16 ? '0' : '') + a[i].toString(16)); return s2; }
var __OK_HTTPMOD = {
  __proto_name: 'http',
  request: function (opts, cb) {
    // 支持 request(url, cb) 与 request(optsObj, cb) 两种形态
    if (typeof opts === 'string') opts = { url: opts };
    var proto = opts.protocol || (this.__proto_name === 'https' ? 'https:' : (opts.port === 443 ? 'https:' : 'http:'));
    if (this.__proto_name === 'https' && !opts.protocol) proto = 'https:';
    var portPart = (opts.port != null && String(opts.port) !== '') ? (':' + opts.port) : '';
    var u = opts.url || (proto + '//' + (opts.hostname || opts.host) + portPart + (opts.path || '/'));
    var headers = opts.headers || {};
    var method = opts.method || 'GET';
    var body = opts.body != null ? opts.body : null;
    var out = {
      setTimeout: function () { return out; },
      destroy: function () { return out; },
      on: function () { return out; },
      write: function (d) { if (body == null) body = d; return out; },
      end: function () {
        var bytes = __okIsBytes(body) ? __okToArr(body) : (body != null ? __okUtf8Bytes(String(body)) : null);
        var raw;
        try {
          if (bytes != null) {
            // ★ 二进制 body: latin1 串 + charset=ISO-8859-1（FongMi Req.body 按 CT charset 编码）
            var h2 = Object.assign({}, headers);
            var hasCT = false;
            for (var hk in h2) if (String(hk).toLowerCase() === 'content-type') hasCT = true;
            if (!hasCT) h2['Content-Type'] = 'application/x-protobuf';
            var hasCS = false;
            for (var hk2 in h2) if (String(hk2).toLowerCase() === 'charset') hasCS = true;
            // OK 壳 Connect.getRequestBody 用 headers.get(Content-Type) 的 MediaType →
            // charset 参数直接放 CT 里: application/x-protobuf; charset=ISO-8859-1
            if (!hasCS && hasCT) {
              for (var hk3 in h2) if (String(hk3).toLowerCase() === 'content-type' && String(h2[hk3]).indexOf('charset') < 0) h2[hk3] = h2[hk3] + '; charset=ISO-8859-1';
            }
            raw = __okRaw(u, { method: method, headers: h2, body: new __OkBuffer(bytes).toString('binary'), timeout: opts.timeout || 20000 });
          } else {
            raw = __okRaw(u, { method: method, headers: headers, timeout: opts.timeout || 20000 });
          }
        } catch (e) {
          var errObj = { message: String((e && e.message) || e) };
          try { if (opts.onerror || out._onerror) (out._onerror || opts.onerror)(errObj); } catch (e2) { }
          if (out._onerror) out._onerror(errObj);
          else throw e;
          return out;
        }
        var resObj = {
          statusCode: raw.status,
          headers: raw.headers,
          setEncoding: function () { return resObj; },
          on: function (ev, fn) {
            if (ev === 'data') { try { fn(new __OkBuffer(raw.bytes)); } catch (e) { } }
            else if (ev === 'end') { setTimeout(function () { try { fn(); } catch (e) { } }, 0); }
            return resObj;
          },
          resume: function () { return resObj; }
        };
        try { if (cb) cb(resObj); } catch (e) { }
        return out;
      }
    };
    return out;
  },
  get: function (u, cb) { return this.request(typeof u === 'string' ? { url: u } : u, cb); },
  STATUS_CODES: { 200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error' }
};

// ---------- __OK_AXIOS: util/req.js 替身（axios 风格 get/post）----------
var __OK_AXIOS = (function () {
  function toOpt(args, i) { return args[i] || {}; }
  async function get(url, opt) {
    opt = opt || {};
    var r = __okRaw(url, { method: 'GET', headers: opt.headers, timeout: opt.timeout, data: opt.data, body: opt.body });
    var t = r.text; var d; try { d = JSON.parse(t); } catch (e) { d = t; }
    return { data: d, status: r.status, headers: r.headers, request: { responseURL: url } };
  }
  async function post(url, body, opt) {
    opt = opt || {};
    var b = body;
    if (b != null && typeof b === 'object') { b = JSON.stringify(b); if (!opt.headers || (!opt.headers['Content-Type'] && !opt.headers['content-type'])) opt.headers = Object.assign({}, opt.headers, { 'Content-Type': 'application/json' }); }
    var r = __okRaw(url, { method: 'POST', headers: opt.headers, timeout: opt.timeout, body: b });
    var t = r.text; var d; try { d = JSON.parse(t); } catch (e) { d = t; }
    return { data: d, status: r.status, headers: r.headers, request: { responseURL: url } };
  }
  var AX = { get: get, post: post, request: function (o) { return (String((o && o.method) || 'get').toLowerCase() === 'post') ? post(o.url, o.data, o) : get(o.url, o); }, create: function () { return AX; } };
  AX.default = AX;
  return AX;
})();

// ---------- __OK_EXTRA_MODULES: require('crypto-js') 等 ----------
var __OK_EXTRA_MODULES = {
  'crypto-js': __OK_CRYPTOJS,
  'iconv-lite': null   // gbk/big5 源极少; 需要时再补
};

// ---------- https 模块派生（_fb 依赖 lib.request 区分 http/https）----------
var __OK_HTTPS = Object.create(__OK_HTTPMOD);
__OK_HTTPS.__proto_name = 'https';

// ---------- 安装 __CAT_JS_UTIL（必须在 __OK_CRYPTOJS 等全部就绪后调用）----------
try { __okInstallUtil(); } catch (e) { }

// ============================================================================
// shim/03_adapter.js — catpaw 对象契约 → FongMi JSON 字符串契约
// ----------------------------------------------------------------------------
// catpaw (MiraPlay):  createSpider(name,config).api({get,post}) 注册 /home /category
//   /detail /play /search /init 路由; 路由函数 (rq, rp) → 返回**对象**
//   rq 形状: {query:{}, body:{}, params:{}}; 响应对象如 {class,filters,list} / {list}
//   / {url, header, parse, message}
// FongMi (OK影视):  __JS_SPIDER__ = {init,home,homeVod,category,detail,search,play}
//   返回 **JSON 字符串**; category(tid, pg, filter, extend对象); play(flag, id, vipFlags)
// ----------------------------------------------------------------------------
// 做法: 构造一个 fake registrar 收集路由表 → 写 FongMi 方法，把入参打包成 rq
//   调路由函数 → 对象 → JSON.stringify 返回。
// 字段对齐:
//   home:      catpaw {class:[{type_id,type_name}], filters:{tid:[{key,name,init,value:[{n,v}]}]}, list}
//              → FongMi home(filter) 相同字段（FongMi filters 的键必须是 type_id 字符串）
//   category:  catpaw rq {id, page, filters} → FongMi (tid, pg, filter, extend)
//              extend 对象直接放 rq.filters（源里 q.filters 取）
//   detail:    rq {id} → detail(id)（壳只传一个 id 字符串）
//   search:    rq {wd, page} → search(wd, quick, pg)
//   play:      rq {id, flag} → play(flag, id, vipFlags)
//   vodItem:   catpaw {vod_id, vod_name, vod_pic, vod_remarks, ...} 与 FongMi 同构, 透传
//   play 响应: {url, header, parse, m3u8_url, message} — FongMi Result 兼容:
//              header(单数)✓ parse✓ msg→message 转换(失败时 FongMi 用 msg+code=0 显示)
// ============================================================================

function __okBuildAdapter(routes, meta) {
  function call(name, rq) {
    var fn = routes[name];
    if (!fn) return Promise.resolve(null);
    return Promise.resolve().then(function () { return fn(rq, { header: function () { return this; }, code: function () { return this; } }); });
  }
  function pack(q) { return { query: q, body: q, params: {} }; }
  function J(v) { return JSON.stringify(v == null ? {} : v); }
  function errObj(scope, e) {
    var m = String((e && e.message) || e);
    return { __ok_err: 1, __ok_scope: scope, __ok_msg: m.slice(0, 200) };
  }

  var api = {
    init: function (ext) {
      // FongMi init(ext): ext 为字符串/对象; catpaw /init 无参 → 把 ext 塞进 config
      try {
        globalThis.__OK_INIT_EXT__ = ext;
        return call('/init', pack({ ext: ext })).then(function () { return J({}); }, function () { return J({}); });
      } catch (e) { return J({}); }
    },
    home: function (filter) {
      return call('/home', pack({})).then(function (r) {
        if (!r) return J({ class: [] });
        return J({ class: r.class || [], filters: r.filters || {}, list: r.list || [] });
      }, function (e) { return J({ class: [], filters: {}, msg: 'home: ' + String((e && e.message) || e).slice(0, 100) }); });
    },
    homeVod: function () {
      // 修复: 多数源未注册 /homeVod 路由, 首页卡片实际来自 /home 的 list。
      // 优先 /homeVod(若源提供), 否则回退 /home.list, 再否则空。
      return call('/homeVod', pack({})).then(function (r) {
        if (r && r.list && r.list.length) return J({ list: r.list });
        if (r && r.vod_id) return J({ list: [r] });
        return call('/home', pack({})).then(function (h) {
          if (h && h.list && h.list.length) return J({ list: h.list });
          return J({ list: [] });
        }, function () { return J({ list: [] }); });
      }, function () {
        return call('/home', pack({})).then(function (h) {
          if (h && h.list && h.list.length) return J({ list: h.list });
          return J({ list: [] });
        }, function () { return J({ list: [] }); });
      });
    },
    category: function (tid, pg, filter, extend) {
      pg = parseInt(pg, 10) || 1;
      var q = { id: tid, page: pg, type_id: tid };
      // FongMi extend 是筛选键值对象（或字符串）
      var f = extend;
      if (typeof f === 'string') { try { f = JSON.parse(f); } catch (e) { f = {}; } }
      if (f && typeof f === 'object') q.filters = f;
      return call('/category', pack(q)).then(function (r) {
        if (!r) return J({ list: [], page: pg, pagecount: 0 });
        return J({ list: r.list || [], page: r.page || pg, pagecount: r.pagecount || 0, msg: r.msg });
      }, function (e) { return J({ list: [], page: pg, pagecount: 0, msg: 'category: ' + String((e && e.message) || e).slice(0, 100) }); });
    },
    detail: function (id) {
      return call('/detail', pack({ id: id })).then(function (r) {
        if (!r) return J({ list: [] });
        return J({ list: r.list || (r.vod_id ? [r] : []) });
      }, function (e) { return J({ list: [], msg: 'detail: ' + String((e && e.message) || e).slice(0, 100) }); });
    },
    search: function (wd, quick, pg) {
      pg = parseInt(pg, 10) || 1;
      var q = { wd: wd, key: wd, page: pg };
      return call('/search', pack(q)).then(function (r) {
        if (!r) return J({ list: [], page: pg });
        return J({ list: r.list || [], page: r.page || pg, pagecount: r.pagecount || 0 });
      }, function (e) { return J({ list: [], page: pg, msg: 'search: ' + String((e && e.message) || e).slice(0, 100) }); });
    },
    play: function (flag, id, vipFlags) {
      var q = { id: id, flag: flag, flags: vipFlags };
      return call('/play', pack(q)).then(function (r) {
        if (!r) return J({ parse: 0, url: '', msg: '无播放数据' });
        // catpaw play 响应: {url|m3u8_url, header, parse, message, action}
        var out = {};
        var u = r.url || r.m3u8_url || '';
        out.url = u;
        out.parse = (r.parse !== undefined) ? Number(r.parse) || 0 : 0;
        var hd = r.header || r.headers;
        if (hd && typeof hd === 'object' && Object.keys(hd).length) out.header = hd;
        if (r.action) out.action = r.action;
        // 失败信息: catpaw message → FongMi msg+code
        if (r.message && !u) { out.msg = String(r.message).slice(0, 150); out.code = 0; }
        else if (r.message && u) { out.msg = String(r.message).slice(0, 150); }
        return J(out);
      }, function (e) {
        return J({ parse: 0, url: '', code: 0, msg: 'play: ' + String((e && e.message) || e).slice(0, 120) });
      });
    },
    sniffer: function () { return false; },
    isVideo: function (url) { return /\.(m3u8|mp4|ts|flv|dash)(\?|$)/i.test(String(url || '')); },
    destroy: function () { }
  };
  return api;
}
var __okRoutes = null;    // 构建脚本注入: createSpider 收集的路由表
var __okMeta = null;

// ---- TVBox->MiraPlay 猫源移植通用头（自动生成，勿手改）v2 ----
// fetch-based AX shim（catpaw QuickJS sandbox 内置 fetch，不依赖坏掉的 util/req.js）

const __U = globalThis.__CAT_JS_UTIL || {};
const CJ  = __U["crypto-js"];
const CryptoJS = CJ && CJ.default ? CJ.default : (typeof globalThis.CryptoJS !== "undefined" ? globalThis.CryptoJS : CJ);
const zlib = (typeof require === "function") ? require("zlib") : (globalThis.__CAT_JS_UTIL && globalThis.__CAT_JS_UTIL["zlib"]);

// ---- AX shim：fetch 优先，Node https/http 兜底（reg 保证有 node:https）----
function _fh(url, opts) {
  const method  = (opts && opts.method)  || "GET";
  const headers = (opts && opts.headers) || {};
  const timeout = (opts && opts.timeout) || 20000;
  const body    = opts && opts.body;

  // 1) 宿主有全局 fetch → 用它（最快）
  if (typeof fetch === "function" && typeof AbortController === "function") {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    let fbody = body;
    if (body && typeof body !== "string") {
      // Buffer 来自另一个 realm 时 instanceof 不可靠 → 检查鸭子类型
      const isBufLike = body && typeof body.length === "number" && typeof body.copy === "function";
      const isU8 = body && typeof body.length === "number" && typeof body.set === "function" && typeof body.buffer === "object";
      if (isBufLike || isU8) { try { fbody = new Uint8Array(body); } catch (e) { fbody = body; } }
      else if (body instanceof Uint8Array || body instanceof ArrayBuffer) fbody = body;
      else fbody = JSON.stringify(body);
    }
    return fetch(url, { method, headers, body: fbody, signal: ctrl.signal, redirect: "follow" })
      .then(r => {
        clearTimeout(tid);
        if (opts && opts.validateStatus && !opts.validateStatus(r.status)) throw new Error("HTTP " + r.status);
        const ct = (r.headers && r.headers.get) ? r.headers.get("content-type") : "";
        if (opts && (opts.responseType === "arraybuffer" || opts.buffer)) {
          return r.arrayBuffer().then(ab => ({ data: ab, status: r.status, headers: {}, __ab: 1 }));
        }
        return r.text().then(t => { let d; try { d = JSON.parse(t); } catch (e) { d = t; } return { data: d, status: r.status, headers: {} }; });
      })
      .catch(e => { clearTimeout(tid); throw e; });
  }

  // 2) 兜底：Node https/http（__CAT_JS_UTIL 里保证可用）
  const https = __U["node:https"] || __U["https"];
  const http  = __U["node:http"]  || __U["http"];
  if (https || http) {
    return new Promise((resolve, reject) => {
      let u;
      try { u = new URL(url); } catch (e) { reject(e); return; }
      const lib = (u.protocol === "https:") ? https : http;
      if (!lib) { reject(new Error("no http lib for " + u.protocol)); return; }
      const h = {};
      Object.keys(headers).forEach(k => { h[k] = headers[k]; });
      const rq = lib.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname + u.search,
        method: method,
        headers: h
      }, (res) => {
        // 手动跟随 3xx 重定向（fetch 与某些 lib 行为不一致）
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers && res.headers.location && (opts._rd || 0) < 5) {
          const loc = res.headers.location;
          const nurl = loc.indexOf('http') === 0 ? loc : (u.protocol + '//' + u.host + (loc[0] === '/' ? '' : '/') + loc);
          res.resume();
          const o2 = Object.assign({}, opts, { _rd: (opts._rd || 0) + 1 });
          _fh(nurl, o2).then(resolve, reject);
          return;
        }
        const chunks = [];
        res.on("data", c => { chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(String(c))); });
        res.on("end", () => {
          const status = res.statusCode;
          if (opts && opts.validateStatus && !opts.validateStatus(status)) { reject(new Error("HTTP " + status)); return; }
          const buf = Buffer.concat(chunks);
          if (opts && (opts.responseType === "arraybuffer" || opts.buffer)) { resolve({ data: buf, text: "", status: status, headers: res.headers || {}, __bin: 1 }); return; }
          const data = buf.toString("utf8");
          let d; try { d = JSON.parse(data); } catch (e) { d = data; }
          resolve({ data: d, status: status, headers: res.headers || {} });
        });
      });
      rq.setTimeout(timeout, () => { rq.destroy(); reject(new Error("timeout")); });
      rq.on("error", e => reject(e));
      if (body) rq.write(typeof body === "string" ? body : (Buffer.isBuffer(body) ? body : JSON.stringify(body)));
      rq.end();
    });
  }

  // 3) 都没有 → 明确报错
  return Promise.reject(new Error("no HTTP client (fetch / node:https unavailable)"));
}


/* ===== v24 shared AX policy =====
 * 参考 9280 bundle：失败分类重试、同 host 熔断、显式在途请求复用。
 * 只对显式 _dedup:true 的 GET 做请求复用，避免签名/播放票据串用。
 */
function __mpWrapAX(ax) {
  if (!ax || ax.__mpV24) return ax;
  ax.__mpV24 = true;
  var down = {}, fails = {}, inflight = {};
  function hostOf(u) { try { return new URL(String(u)).host.toLowerCase(); } catch (e) { return String(u); } }
  function statusOf(r) {
    var n = r && (r.status !== undefined ? r.status : r.code);
    n = Number(n); return isFinite(n) ? n : 0;
  }
  function wait(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  function markFail(u) {
    var h = hostOf(u); fails[h] = (fails[h] || 0) + 1;
    if (fails[h] >= 3) down[h] = Date.now() + 60000;
  }
  function markOk(u) { var h = hostOf(u); fails[h] = 0; delete down[h]; }
  function retryableError(e) {
    var m = String((e && (e.code || e.message || e.name)) || e);
    return /timeout|abort|reset|socket|network|eai_again|enotfound|econn|fetch failed/i.test(m);
  }
  function wrap(name) {
    var orig = ax[name];
    if (typeof orig !== 'function' || orig.__mpV24) return;
    var fn = function () {
      var args = Array.prototype.slice.call(arguments);
      var opt = (name === 'post' || name === 'put' || name === 'patch') ? (args[2] || {}) : (args[1] || {});
      var url = String(args[0] || '');
      var h = hostOf(url);
      if (down[h] && Date.now() < down[h] && !opt._bypassCircuit) return Promise.reject(new Error('host circuit open: ' + h));
      var key = (name === 'get' || name === 'head') && opt._dedup ? name + '|' + url : '';
      if (key && inflight[key]) return inflight[key];
      var tries = opt._noRetry ? 1 : 2;
      function attempt(n) {
        return Promise.resolve().then(function () { return orig.apply(ax, args); }).then(function (r) {
          var st = statusOf(r);
          if (st >= 500 && st < 600) {
            markFail(url);
            if (n + 1 < tries) return wait(180 * (n + 1)).then(function () { return attempt(n + 1); });
          } else if (st >= 200 && st < 500) markOk(url);
          return r;
        }, function (e) {
          markFail(url);
          if (n + 1 < tries && retryableError(e)) return wait(180 * (n + 1)).then(function () { return attempt(n + 1); });
          throw e;
        });
      }
      var p = attempt(0);
      if (key) {
        inflight[key] = p;
        p.then(function () { if (inflight[key] === p) delete inflight[key]; }, function () { if (inflight[key] === p) delete inflight[key]; });
      }
      return p;
    };
    fn.__mpV24 = true;
    ax[name] = fn;
  }
  wrap('get'); wrap('post'); wrap('put'); wrap('delete'); wrap('head');
  return ax;
}
const AX = {
  get:    (url, opts)   => _fh(url, Object.assign({}, opts, { method: "GET" })),
  post:   (url, body, opts) => _fh(url, Object.assign({}, opts, { method: "POST",
    body: typeof body === "string" ? body : body })),
  put:    (url, body, opts) => _fh(url, Object.assign({}, opts, { method: "PUT", body })),
  delete: (url, opts)   => _fh(url, Object.assign({}, opts, { method: "DELETE" })),
  head:   (url, opts)   => _fh(url, Object.assign({}, opts, { method: "HEAD" })),
  create: () => AX
};
__mpWrapAX(AX);


// crypto help

// crypto helpers
const md5 = (s) => { try { return CryptoJS.MD5(String(s)).toString(); } catch(e){ return ""; } };
const sha256 = (s) => { try { return CryptoJS.SHA256(String(s)).toString(); } catch(e){ return ""; } };
const aesDecCbc = (b64, key, iv) => { try { return CryptoJS.AES.decrypt(b64, CryptoJS.enc.Utf8.parse(String(key)), { iv: CryptoJS.enc.Utf8.parse(String(iv)), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8); } catch (e) { return ""; } };
const aesEncCbcB64 = (s, key, iv) => { try { return CryptoJS.AES.encrypt(s, CryptoJS.enc.Utf8.parse(String(key)), { iv: CryptoJS.enc.Utf8.parse(String(iv)), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(); } catch (e) { return ""; } };
const aesCbcRaw = (data, key, iv) => { try { const d = CryptoJS.lib.CipherParams.create({ ciphertext: data }); return CryptoJS.AES.decrypt(d, CryptoJS.enc.Utf8.parse(String(key)), { iv: CryptoJS.enc.Utf8.parse(String(iv)), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8); } catch(e){ return ""; } };
const J = (p) => p.catch(e => ({ __err: String((e && e.message) || e) }));
const JC = (p) => p.catch(e => ({ __err: String((e && e.message) || e) }));
const ok = (o) => o && !o.__err;
const qof = (r) => Object.assign({}, (r && r.query) || {}, (r && r.body) || {});
const homeOut = (cls, filters, list) => ({ class: cls || [], filters: filters || {}, list: list || [] });
const catOut = (list, page, pagecount) => ({ list: list || [], page: page || 1, pagecount: pagecount || 0 });
const detailOut = (vod) => ({ list: [vod] });
const empty = (extra) => Object.assign({ class: [], filters: {}, list: [] }, extra || {});


// ===== protobuf 基础编解 =====
function pbVarint(n) {
  const out = [];
  n = Number(n);
  if (!isFinite(n) || n < 0) n = 0;
  while (true) {
    // 用除法+floor 避免 32 位位运算溢出
    const b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) out.push(b + 128); else { out.push(b); break; }
  }
  return out;
}
function pbTag(f, w) { return pbVarint((f << 3) | w); }
function pbStr(f, s) {
  let bytes;
  if (typeof s === "string") bytes = utf8Bytes(s);
  else bytes = Array.from(s || []);
  return pbTag(f, 2).concat(pbVarint(bytes.length), bytes);
}
function pbInt(f, n) { return pbTag(f, 0).concat(pbVarint(n)); }
function utf8Bytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c >= 0xd800 && c <= 0xdbff) { const c2 = s.charCodeAt(++i); const u = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00); out.push(0xf0 | (u >> 18), 0x80 | ((u >> 12) & 0x3f), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f)); }
    else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
  }
  return out;
}
function b64ToBytes(b64) {
  const bin = (typeof atob === "function") ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  const out = []; for (let i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i));
  return out;
}
function bytesToB64(bytes) {
  let bin = ""; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return (typeof btoa === "function") ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
}
function pbReadVarint(buf, i) {
  let r = 0, s = 0;
  while (i < buf.length) {
    const b = buf[i++];
    r += (b & 0x7f) * Math.pow(2, s);   // 乘法避免 32 位位移溢出
    if (!(b & 0x80)) break;
    s += 7;
  }
  return [r, i];
}
function pbFields(buf) {
  const o = {}; let i = 0;
  while (i < buf.length) {
    const [k, ni] = pbReadVarint(buf, i); i = ni;
    const f = k >> 3, w = k & 7;
    if (w === 0) { const [v, ni2] = pbReadVarint(buf, i); i = ni2; o[f] = v; }
    else if (w === 2) { const [ln, ni2] = pbReadVarint(buf, i); i = ni2; o[f] = buf.slice(i, i + ln); i += ln; }
    else if (w === 1) i += 8;
    else if (w === 5) i += 4;
    else break;
  }
  return o;
}
function pbRepeated(buf, field) {
  const out = []; let i = 0;
  while (i < buf.length) {
    const [k, ni] = pbReadVarint(buf, i); i = ni;
    const f = k >> 3, w = k & 7;
    if (w === 0) { const [v, ni2] = pbReadVarint(buf, i); i = ni2; if (f === field) out.push(v); }
    else if (w === 2) { const [ln, ni2] = pbReadVarint(buf, i); i = ni2; const seg = buf.slice(i, i + ln); i += ln; if (f === field) out.push(seg); }
    else if (w === 1) i += 8;
    else if (w === 5) i += 4;
    else break;
  }
  return out;
}
function bytesToUtf8(bytes) {
  try { return (typeof TextDecoder !== "undefined") ? new TextDecoder("utf-8").decode(new Uint8Array(bytes)) : Buffer.from(bytes).toString("utf8"); } catch (e) { return ""; }
}
// 构造 SecureRequest（g() 等价）
function secureBody(map2, dataKey) {
  const ts = Date.now();
  const f8 = randStr(8), f20 = randStr(20);
  const parts = [];
  for (const k of Object.keys(map2)) {
    const v = map2[k];
    if (v !== null && v !== undefined && String(v) !== "") parts.push(k + "=" + v);
  }
  const enc = ecbEncB64(parts.join("&") + ts, dataKey);
  const str3 = f8 + enc;
  const a1 = str3.slice(0, 20), a2 = str3.slice(20);
  let body = pbStr(1, a1).concat(pbStr(2, a2), pbStr(3, f20), pbInt(4, ts), pbStr(5, f8));
  return body;
}
function bytesToBuffer(bytes) {
  const arr = new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") return Buffer.from(arr);
  return arr.buffer;
}
function randStr(n) {
  const ch = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let s = ""; for (let i = 0; i < n - 1; i++) s += ch[Math.floor(Math.random() * ch.length)];
  return s + "=";
}


// proto 请求头（带 RSA 签名，走 publicKey 直签）
function protoHeaders() {
  const ts = Date.now(), f16 = randStr(16);
  const dev = deviceBlock();
  const sig = rsaEnc(String(ts) + f16 + dev.vApp, PUBKEY);
  const sig23 = ecbEncB64(String(ts) + f16, DATA_IV);
  dev.sig = sig; dev.random_str = f16; dev.timestamp = ts;
  dev.sig2 = sig23.slice(0, 8); dev.sig3 = sig23.slice(8);
  const pd = cbcEncHex(JSON.stringify(dev), CIPHER);
  return {
    "User-Agent": UA, "Accept": "application/x-protobuf", "Content-Type": "application/x-protobuf",
    publicParams: JSON.stringify({ paramsData: pd }),
  };
}
function rsaEnc(plain, pubB64) {
  const pem = "-----BEGIN PUBLIC KEY-----\n" + pubB64 + "\n-----END PUBLIC KEY-----";
  // 1) require('crypto')
  try {
    if (typeof require === "function") {
      const c = require("crypto");
      if (c && c.createPublicKey) {
        const k = c.createPublicKey(pem);
        return c.publicEncrypt({ key: k, padding: c.constants.RSA_PKCS1_PADDING }, Buffer.from(plain, "utf8")).toString("base64");
      }
    }
  } catch (e) {}
  // 2) node:crypto via __CAT_JS_UTIL
  try {
    const c = (__U && (__U["node:crypto"] || __U.crypto));
    if (c && c.createPublicKey) {
      const k = c.createPublicKey(pem);
      return c.publicEncrypt({ key: k, padding: c.constants.RSA_PKCS1_PADDING }, Buffer.from(plain, "utf8")).toString("base64");
    }
  } catch (e) {}
  return "";
}

// =====================================================================
// TVBox csp_AppDrama → MiraPlay 猫源移植：__NAME__
// 协议（实测修正版）：三重结构
//   1. 明文 JSON 头 publicParams：AES-128-CBC(deviceJSON, "ed5fdsgucxumegqa")
//      —— 无需 RSA 签名！这是能用的关键（签名那个 zone 流程走不通/可选）
//   2. 首页/分类：GET /api/ex/v3/security/tag/list 和 /drama/list
//      响应 data 是双重 AES-ECB 加密：AES_ECB(data, dataKey) → AES_ECB(result, dataIv)
//   3. 详情：/api/ex/v3/security/drama/list?vodId=ID&page=1&pagesize=1
//   4. 播放：/api/ex/v3/security/videoUsableUrl?vodPlayFrom=X&playUrl=Y
//      （服务端可能无解析配置 → 返回 parse:1 让播放器嗅探）
// =====================================================================
const CFG = {"host": "", "site": "https://dyttandroid04-1372779881.cos.ap-shanghai.myqcloud.com/app_dyttandroid.txt", "pkg": "com.dytiantang.one", "appName": "电影天堂", "version": "3.0.0.7", "decrypt": "0", "dataKey": "D2KREWRIBVNAUJJYEDL4VFHOY2Q0PQ==", "dataIv": "OC1A06E197EF10CF3F6058CA7A803B5E", "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCduNEnfxGaLuQRk5ABzXHhPV43zi00sCHjLo8BYc+Wi6xXm2b4v0i28Sq4WlNCKhseft9fz8kO/qLr6/022o1RcuOU7e4GFL3U9WnNODwRBYSYWd+K8nqpI/tAUDmZEBGRWqjrc7x6aMl3A+xpnWkLbPCLsuhbuuUE3tv09oeOpwIDAQAB"};
const KEY = "天堂";

const HOST = (CFG.host || CFG.url || "").replace(/\/+$/, "");
const PKG = CFG.pkg || "";
const APP_NAME = CFG.appName || "";
const VER = CFG.version || "1.0.0.4";
const DECRYPT = String(CFG.decrypt == null ? "0" : CFG.decrypt);
const CIPHER = "ed5fdsgucxumegqa";
const DATA_KEY = CFG.dataKey || "";
const PUBKEY = CFG.publicKey || "";
const DATA_IV = CFG.dataIv || "";
const UA = CFG.ua || "okhttp/3.12.1";

if (!HOST) { /* host 从 site 拉取，见 boot() */ }

let HOST_ = HOST;
let booting = null;

// AES-ECB 解密（CryptoJS，key 为 UTF-8 字符串字节）
function ecbDecB64(b64, key) {
  try {
    const w = CryptoJS.AES.decrypt({ ciphertext: CryptoJS.enc.Base64.parse(b64) },
      CryptoJS.enc.Utf8.parse(String(key)), { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
    return w.toString(CryptoJS.enc.Utf8);
  } catch (e) { return ""; }
}
// AES-ECB 加密 → base64
function ecbEncB64(plain, key) {
  try {
    const e = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(plain), CryptoJS.enc.Utf8.parse(String(key)),
      { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
    return e.ciphertext.toString(CryptoJS.enc.Base64);
  } catch (e) { return ""; }
}
// AES-CBC 加密 → hex（Cipher key/iv 同值）
function cbcEncHex(plain, key) {
  try {
    const e = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(plain), CryptoJS.enc.Utf8.parse(String(key)),
      { iv: CryptoJS.enc.Utf8.parse(String(key)), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return e.ciphertext.toString(CryptoJS.enc.Hex);
  } catch (e) { return ""; }
}
function pickData(d) {
  if (!d) return null;
  let o = d;
  if (typeof o === "string") { try { o = JSON.parse(o); } catch (e) { return decryptData(o); } }
  if (o && typeof o === "object" && o.data !== undefined) return decryptData(o.data);
  return o;
}
function uuid32() {
  try {
    if (CryptoJS.lib.WordArray.random) return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex).toUpperCase();
  } catch (e) {}
  let s = ""; for (let i = 0; i < 32; i++) s += "0123456789ABCDEF"[Math.floor(Math.random() * 16)];
  return s;
}
// 设备 JSON（严格对齐实测可用配置：M2012K11AC / vOs 13 / sdk 33）
function deviceBlock() {
  const u = uuid32();
  return {
    country: "CN", vName: VER, cpuId: "MT6893Z%2FCZA", young: 0, facturer: "Xiaomi",
    pkg: PKG, uuid: u, resolution: "1080x2272", mac: "02%3A00%3A00%3A00%3A00%3A00",
    abid: "397", model: "M2012K11AC", plat: "android", udid: u, dpi: "440", net: "1",
    lang: "zh", brand: "Xiaomi", density: "2.75", appName: APP_NAME, cpu: "arm64-v8a",
    chid: "10000", carrier: "%E8%81%94%E9%80%9A", _vOsCode: 33, vOs: "13", v: 1,
    tenantId: "", vApp: VER.replace(/\./g, ""), device: 0, androidID: "a1b2c3d4e5f67890",
  };
}
function jsonHeaders() {
  const dj = JSON.stringify(deviceBlock());
  const pd = cbcEncHex(dj, CIPHER);
  return {
    "User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json; charset=utf-8",
    publicParams: JSON.stringify({ paramsData: pd }),
  };
}

// 双重 ECB 解密（decrypt=1 时）：data → AES_ECB(dk) → AES_ECB(iv)
function decryptData(enc) {
  if (!enc || typeof enc !== "string") return null;
  if (DECRYPT === "0") {
    try { return JSON.parse(enc); } catch (e) { return enc; }
  }
  const s1 = ecbDecB64(enc, DATA_KEY);
  if (!s1) return null;
  let s2 = "";
  try { s2 = ecbDecB64(s1, DATA_IV); } catch (e) {}
  const txt = s2 || s1;
  try { return JSON.parse(txt); } catch (e) { return txt; }
}

async function boot() {
  if (booting) return booting;
  booting = (async () => {
    if (!HOST_ && CFG.site) {
      try {
        const r = await AX.get(CFG.site, { headers: { "User-Agent": UA }, timeout: 15000 });
        let d = r.data;
        if (typeof d === "string") { try { d = JSON.parse(d); } catch (e) {} }
        if (d && d.domain) HOST_ = String(d.domain).replace(/\/+$/, "");
      } catch (e) {}
    }
  })();
  return booting;
}

async function jget(path) {
  await boot();
  const r = await AX.get(HOST_ + path, { headers: jsonHeaders(), timeout: 20000 });
  let d = r.data;
  if (typeof d === "string") { try { d = JSON.parse(d); } catch (e) { return null; } }
  return d;
}

function cardOf(it) {
  const ci = it.coverImage || {};
  return {
    vod_id: String(it.id || ""),
    vod_name: it.name || "",
    vod_pic: ci.thumbnailPath || ci.path || "",
    vod_remarks: it.remark || "",
  };
}

// ================= 通用契约加固层（全源共用，构建时注入）=================
// 修的都是"加了就好、不加就出错、且不影响原有成功路径"的坑：
//
// 1) /category 入参可能是**中文分类名**而非数字 id
//    实测部分壳（含 OK影视）把 type_name 当 tid 传 → 源查不到数据、分类页空白
//    首次返回为空且 tid 非纯数字时，用 home 的分类表解析成 id 再试一次
// 2) /category 的 filters 值可能是"全部"/"不限"/"all"/"-1"
//    多数源会把这个**显示名**当真实值提交，上游当成未知值 → 返回 0 条
//    → 统一把这些哨兵值删掉（等于"不过滤"）
// 3) /play 失败必须带 message
//    没有 message 时壳只显示"一直加载"，用户不知道要换线路
// 4) /play 把**裸 id** 原样返回（解析没成功）→ 播放器永远转圈
//    判据：返回值与入参 id 完全相同且不是 http 地址 → 改成明确失败
// 5) /play 返回必须用 header（单数）—— bundle 的 HLS 加速器只读 obj.header
// 6) /detail 不支持批量 id —— 壳可能一次要多个，统一在外层循环补齐
function __hardenContract(H, meta) {
  var UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36";
  var ALL_SENTINEL = { "全部": 1, "不限": 1, "所有": 1, "all": 1, "-1": 1, "0": 0 };
  var clsCache = null, clsAt = 0;

  function qOf(rq) { return Object.assign({}, (rq && rq.query) || {}, (rq && rq.body) || {}); }
  function fOf(q) {
    var f = q && q.filters;
    if (!f) return null;
    if (typeof f === "object") return f;
    try { var o = JSON.parse(String(f)); return o && typeof o === "object" ? o : null; } catch (e) { return null; }
  }
  // 去掉"全部"类哨兵值
  function cleanFilters(q) {
    var f = fOf(q);
    if (!f) return q;
    var changed = false, out = {};
    for (var k in f) {
      var v = f[k];
      var s = String(v == null ? "" : v).trim();
      if (ALL_SENTINEL[s.toLowerCase()] === 1 || ALL_SENTINEL[s] === 1) { changed = true; continue; }
      out[k] = v;
    }
    if (!changed) return q;
    var q2 = Object.assign({}, q, { filters: out });
    return q2;
  }
  async function resolveTid(tid) {
    var t = String(tid == null ? "" : tid).trim();
    if (!t || /^\d+$/.test(t)) return "";
    var now = Date.now();
    if (!clsCache || now - clsAt > 60000) {
      try {
        var h = H["/home"] ? await H["/home"]({ query: {}, body: {}, params: {} }, { header: function () {} }) : null;
        var arr = (h && h["class"]) || [];
        var m = {};
        for (var i = 0; i < arr.length; i++) {
          var n = String((arr[i] && arr[i].type_name) || "").trim();
          if (n) m[n] = String(arr[i].type_id);
        }
        clsCache = m; clsAt = now;
      } catch (e) { clsCache = {}; clsAt = now; }
    }
    return clsCache[t] || "";
  }
  function replyOf() { return { header: function () { return this; }, code: function () { return this; } }; }

  var out = {};
  for (var k in H) {
    out[k] = (function (name, fn) {
      return async function (rq, rp) {
        var q0 = qOf(rq);
        var rp2 = rp || replyOf();

        // --- /category：清 filters 哨兵值 + 中文名兜底 ---
        if (name === "/category") {
          var q1 = cleanFilters(q0);
          var rq1 = { query: q1, body: q1, params: (rq && rq.params) || {} };
          var r = await fn(rq1, rp2);
          if (r && typeof r === "object" && !(r.list && r.list.length)) {
            var raw = q1.id != null ? q1.id : (q1.type_id != null ? q1.type_id : q1.tid);
            if (raw != null && !/^\d+$/.test(String(raw).trim())) {
              var rid = await resolveTid(raw);
              if (rid) {
                var q2 = Object.assign({}, q1, { id: rid, type_id: rid, tid: rid });
                var r2 = await fn({ query: q2, body: q2, params: (rq && rq.params) || {} }, rp2);
                if (r2 && r2.list && r2.list.length) return r2;
              }
            }
          }
          return r;
        }

        // --- /detail：批量 id 补齐 ---
        if (name === "/detail") {
          var r3 = await fn(rq, rp2);
          var ids = Array.isArray(q0.id) ? q0.id.filter(Boolean) : null;
          if (ids && ids.length > 1) {
            var got = (r3 && r3.list) || [];
            if (got.length >= ids.length) return r3;
            var acc = got.slice();
            var have = {};
            for (var g = 0; g < acc.length; g++) have[String(acc[g].vod_id)] = 1;
            // ★ v33: 串行 → 并发池（限 4）。detail 是纯读接口，并发安全。
            var miss = [];
            for (var n = 0; n < ids.length && n < 10; n++) {
              var one = String(ids[n]);
              if (!have[one]) miss.push(one);
            }
            var POOL = 4;
            for (var s0 = 0; s0 < miss.length; s0 += POOL) {
              var batch = miss.slice(s0, s0 + POOL);
              var res = await Promise.all(batch.map(function (one2) {
                var qq2 = Object.assign({}, q0, { id: one2 });
                return Promise.resolve(fn({ query: qq2, body: qq2, params: (rq && rq.params) || {} }, rp2))
                  .then(function (x) { return (x && x.list) || []; }, function () { return []; });
              }));
              for (var bi = 0; bi < res.length; bi++) {
                var l = res[bi];
                for (var m = 0; m < l.length; m++) if (!have[String(l[m].vod_id)]) { acc.push(l[m]); have[String(l[m].vod_id)] = 1; }
              }
            }
            return { list: acc };
          }
          return r3;
        }

        // --- /play：header 单数 + 失败必须带 message + 拒绝裸 id 直通 ---
        if (name === "/play") {
          var r4;
          try {
            r4 = await fn(rq, rp2);
          } catch (e) {
            // ★ 源内部抛异常时，壳会拿到 500 —— 用户只看到"一直加载"，连换线路都不知道
            //   这里兜成标准的失败响应（保留原因，便于排查）
            r4 = { parse: 0, url: "", message: "解析异常：" + String((e && e.message) || e).slice(0, 60) };
          }
          if (!r4 || typeof r4 !== "object") return r4;
          var u = r4.url || r4.m3u8_url || "";
          var inId = String(q0.id != null ? q0.id : (q0.url != null ? q0.url : ""));
          // 解析没成功 → 把入参当播放地址原样回传 = 播放器永远转圈
          if (u && !/^https?:\/\//i.test(String(u)) && String(u) === inId) {
            r4.url = "";
            if (!r4.m3u8_url) r4.parse = 0;
            if (!r4.message) r4.message = "该线路解析失败，请切换其它线路";
          }
          if (!r4.header || typeof r4.header !== "object") {
            r4.header = r4.headers && typeof r4.headers === "object" ? r4.headers : { "User-Agent": UA };
          }
          if (!(r4.url || r4.m3u8_url) && !r4.message && !r4.action) {
            r4.message = "该线路解析失败，请切换其它线路";
          }
          return r4;
        }

        return fn(rq, rp2);
      };
    })(k, H[k]);
  }
  return out;
}

function __okCreateSpider(name, config) {
  return {
    meta: { key: KEY, name: "天堂影视", type: 3 },
    api: async ({ get, post }) => {
      const H = {
        "/home": async () => {
          const cls = [];
          const filters = {};
          let list = [];
          // 1) 分类（明文 JSON，无需签名）
          const jc = await JC(jget("/api/v3/drama/getCategory?orderBy=type_id"));
          if (ok(jc) && jc.data) {
            for (const c of jc.data) {
              if (c.name === "公告") continue;
              if (c.name === "4K专区") continue;   // ★ 服务端 proto 返回空（实测 typeId1=23 单位元），不展示死标签
              cls.push({ type_id: String(c.id), type_name: c.name });
              // 筛选数据
              try {
                const cu = JSON.parse(c.converUrl || "{}");
                const fg = [];
                const K2N = { class: "类型", lang: "语言", area: "地区", year: "年份", extend_sort: "排序" };
                for (const k of Object.keys(cu)) {
                  if (!Array.isArray(cu[k])) continue;
                  const items = cu[k].map(x => typeof x === "string" ? { n: x, v: x } : { n: String(x.name || x.n || ""), v: String(x.value || x.v || "") });
                  if (items.length) fg.push({ key: k, name: K2N[k] || k, value: [{ n: "全部", v: "" }].concat(items) });
                }
                if (fg.length) filters[String(c.id)] = fg;
              } catch (e) {}
            }
          }
          // 2) 首页推荐（tag/list）
          const jt = await JC(jget("/api/ex/v3/security/tag/list"));
          if (ok(jt) && jt.data) {
            let arr = jt.data;
            if (typeof arr === "string") { try { arr = JSON.parse(arr); } catch (e) { arr = decryptData(arr); } }
            if (arr && typeof arr === "object" && !Array.isArray(arr) && arr.data) { arr = decryptData(arr.data); }
            if (Array.isArray(arr)) {
              for (const tag of arr) {
                for (const sec of (tag.sections || [])) {
                  for (const v of (sec.vodList || [])) list.push(cardOf(v));
                }
              }
            }
          }
          return homeOut(cls, filters, list.slice(0, 60));
        },
        "/category": async (rq, rp) => {
          const q = qof(rq);
          const f = q.filters || {};
          const pg = String(q.page || 1);
          await boot();          // ★ 修复：新会话直取 category 时缺 boot → HOST_ 为空 → 全空
          // ★ 修复：CCTV(21)/地方卫视(22) 服务端无独立列表；频道清单其实挂在「直播」(20) 下
          if (String(q.id) === "21" || String(q.id) === "22") {
            try {
              const want = String(q.id) === "21" ? "CCTV" : "地方卫视";
              const b0 = secureBody({ pagesize: "60", typeId1: "20", page: "1", vodOrderBy: "最新" }, DATA_KEY);
              const rr0 = await AX.post(HOST_ + "/api/proto/v5/drama/category", bytesToBuffer(b0), { headers: protoHeaders(), timeout: 20000, responseType: "arraybuffer" });
              let bu0;
              if (rr0.data && rr0.data.byteLength !== undefined) bu0 = Array.from(new Uint8Array(rr0.data));
              else if (Buffer.isBuffer(rr0.data)) bu0 = Array.from(rr0.data);
              else if (typeof rr0.data === "string") bu0 = Array.from(Buffer.from(rr0.data, "binary"));
              else bu0 = [];
              const top0 = pbFields(bu0), dat0 = top0[3] || [], beans0 = pbRepeated(dat0, 1);
              const all0 = beans0.map(function (bb) {
                const bf = pbFields(bb);
                let pic = bytesToUtf8(bf[2] || []).replace(/^\x12+/, "");
                const pi = pic.indexOf("http"); if (pi > 0) pic = pic.slice(pi);
                return { vod_id: String(bf[3] || ""), vod_name: bytesToUtf8(bf[5] || []), vod_pic: pic, vod_remarks: bytesToUtf8(bf[13] || "") };
              }).filter(function (v) { return v.vod_id && v.vod_name.indexOf(want) >= 0; });
              // all0 已是标准 vod 字段，不能再走 cardOf（cardOf 取 id/name/coverImage）
              if (all0.length) return catOut(all0, Number(pg), 1);
            } catch (e) {}
            return catOut([], Number(pg), 1);
          }
          const h = jsonHeaders();
          const url = HOST_ + "/api/ex/v3/security/drama/list?typeId1=" + encodeURIComponent(q.id || "21")
            + "&page=" + pg + "&pagesize=21"
            + (f.class ? "&vodClass=" + encodeURIComponent(f.class) : "")
            + (f.area ? "&vodArea=" + encodeURIComponent(f.area) : "")
            + (f.lang ? "&vodLang=" + encodeURIComponent(f.lang) : "")
            + (f.year ? "&vodYear=" + encodeURIComponent(f.year) : "")
            + (f.extend_sort ? "&vodOrderBy=" + encodeURIComponent(f.extend_sort) : "");
          const j = await JC(AX.get(url, { headers: h, timeout: 20000 }));
          if (!ok(j)) return catOut([], Number(pg), 0);
          let obj = pickData(j.data);
          if (obj && typeof obj === "string") { try { obj = JSON.parse(obj); } catch (e) {} }
          let lst = (obj && obj.list) || [];
          // proto 兜底（天堂/苹果走这条）
          if (!lst.length && PUBKEY) {
            try {
              const b = secureBody({ pagesize: "21", typeId1: String(q.id || "1"), page: pg, vodOrderBy: f.extend_sort || "最新" }, DATA_KEY);
              const rr = await AX.post(HOST_ + "/api/proto/v5/drama/category", bytesToBuffer(b), { headers: protoHeaders(), timeout: 20000, responseType: "arraybuffer" });
              let bu;
              if (rr.data && rr.data.byteLength !== undefined) bu = Array.from(new Uint8Array(rr.data));
              else if (Buffer.isBuffer(rr.data)) bu = Array.from(rr.data);
              else if (typeof rr.data === "string") bu = Array.from(Buffer.from(rr.data, "binary"));
              else bu = [];
              const top = pbFields(bu);
              const dat = top[3] || [];
              const beans = pbRepeated(dat, 1);
              lst = beans.map(bb => {
                const bf = pbFields(bb);
                // ⚠ f2 是带 \x12 长度前缀的图片原始串（需剥离 tel 前缀），f3=id f5=名字 f13=备注
                let pic = bytesToUtf8(bf[2] || []).replace(/^\x12+/, "");
                const pi = pic.indexOf("http");
                if (pi > 0) pic = pic.slice(pi);
                return {
                  vod_id: String(bf[3] || ""), vod_name: bytesToUtf8(bf[5] || []),
                  vod_pic: pic, vod_remarks: bytesToUtf8(bf[13] || []),
                };
              });
            } catch (e) {}
          }
          return catOut(lst.map(x => x.vod_id !== undefined ? x : cardOf(x)), Number(pg), lst.length >= 21 ? Number(pg) + 1 : Number(pg));
        },
        "/search": async (rq, rp) => {
          const q = qof(rq);
          const pg = String(q.page || 1);
          let lst = [];
          // JSON 路径
          const j = await JC(AX.get(HOST_ + "/api/ex/v3/security/drama/list?searchKeys=" + encodeURIComponent(q.wd || "") + "&page=" + pg + "&pagesize=21", { headers: jsonHeaders(), timeout: 20000 }));
          if (ok(j)) {
            let obj = pickData(j.data);
            if (obj && typeof obj === "string") { try { obj = JSON.parse(obj); } catch (e) {} }
            lst = (obj && obj.list) || [];
          }
          // proto 兜底
          if (!lst.length && PUBKEY) {
            try {
              const b = secureBody({ searchKeys: String(q.wd || ""), page: pg }, DATA_KEY);
              const rr = await AX.post(HOST_ + "/api/proto/v5/drama/search", bytesToBuffer(b), { headers: protoHeaders(), timeout: 20000, responseType: "arraybuffer" });
              let bu;
              if (rr.data && rr.data.byteLength !== undefined) bu = Array.from(new Uint8Array(rr.data));
              else if (Buffer.isBuffer(rr.data)) bu = Array.from(rr.data);
              else if (typeof rr.data === "string") bu = Array.from(Buffer.from(rr.data, "binary"));
              else bu = [];
              const top = pbFields(bu);
              if (Number(top[1]) === 200) {
                const u8 = (x) => bytesToUtf8(x || []);
                lst = pbRepeated(top[3] || [], 1).map(bb => {
                  const bf = pbFields(bb);
                  const ci = bf[2] ? pbFields(bf[2]) : {};
                  return { vod_id: String(bf[3] || ""), vod_name: u8(bf[5]), vod_pic: u8(ci[2]) || u8(ci[1]), vod_remarks: u8(bf[13]) };
                });
              }
            } catch (e) {}
          }
          return catOut(lst, Number(pg), lst.length >= 21 ? Number(pg) + 1 : Number(pg));
        },        "/detail": async (rq, rp) => {
          const q = qof(rq);
          const id = String(q.id || "");
          // ★ 优先走 proto getDetail（返回全部线路；security 端点常只有 1 条）
          if (PUBKEY) {
            try {
              const b = secureBody({ id: String(id) }, DATA_KEY);
              const rr = await AX.post(HOST_ + "/api/proto/v5/drama/getDetail", bytesToBuffer(b), { headers: protoHeaders(), timeout: 25000, responseType: "arraybuffer" });
              let bu;
              if (rr.data && rr.data.byteLength !== undefined) bu = Array.from(new Uint8Array(rr.data));
              else if (Buffer.isBuffer(rr.data)) bu = Array.from(rr.data);
              else if (typeof rr.data === "string") bu = Array.from(Buffer.from(rr.data, "binary"));
              else bu = [];
              const top = pbFields(bu);
              const code = top[1] !== undefined ? top[1] : -1;
              if (code === 200 && top[3]) {
                const d = pbFields(top[3]);
                const ci2 = d[2] ? pbFields(d[2]) : {};
                const vraw = pbRepeated(top[3], 29);
                const bySrc = {};
                for (const vb of vraw) {
                  const vf = pbFields(vb);
                  const scn = bytesToUtf8(vf[10] || []) || "线路";
                  const title = bytesToUtf8(vf[2] || []) || bytesToUtf8(vf[3] || []) || "";
                  const path = bytesToUtf8(vf[4] || []);
                  const src = bytesToUtf8(vf[9] || []);
                  if (!path) continue;
                  if (!bySrc[scn]) bySrc[scn] = [];
                  let ep;
                  try {
                    const payload = JSON.stringify({ vodPlayFrom: src, playUrl: path, title: title });
                    ep = (typeof btoa === "function") ? btoa(unescape(encodeURIComponent(payload))) : Buffer.from(payload, "utf8").toString("base64");
                  } catch (e) { ep = path; }
                  bySrc[scn].push((title || "播放") + "$" + ep);
                }
                const froms2 = Object.keys(bySrc);
                if (froms2.length) {
                  return detailOut({
                    vod_id: id,
                    vod_name: bytesToUtf8(d[9] || []),
                    vod_pic: bytesToUtf8(ci2[2] || ci2[1] || []),
                    vod_remarks: bytesToUtf8(d[26] || []),
                    vod_year: String(d[18] || "") || bytesToUtf8(d[28] || []),
                    vod_area: bytesToUtf8(d[1] || []),
                    vod_actor: bytesToUtf8(d[25] || []),
                    vod_director: bytesToUtf8(d[12] || []),
                    vod_content: String(bytesToUtf8(d[6] || [])).replace(/<[^>]+>/g, "").slice(0, 500),
                    vod_play_from: froms2.join("$$$"),
                    vod_play_url: froms2.map(ff => bySrc[ff].join("#")).join("$$$"),
                  });
                }
              }
            } catch (e) {}
          }
          // ---- 回退：security 单线端点 ----
          let lst0 = [];
          // 先试 JSON 路径
          const j = await JC(AX.get(HOST_ + "/api/ex/v3/security/drama/list?vodId=" + encodeURIComponent(id) + "&page=1&pagesize=1", { headers: jsonHeaders(), timeout: 20000 }));
          if (ok(j)) {
            let obj = pickData(j.data);
            if (obj && typeof obj === "string") { try { obj = JSON.parse(obj); } catch (e) {} }
            lst0 = (obj && obj.list) || [];
          }
          if (lst0.length) {
            const it = lst0[0];
            const ci = it.coverImage || {};
            const vids = it.videos || [];
            const bySrc = {};
            for (const v of vids) {
              const scn = v.sourceCn || v.source_cn || "线路";
              if (!bySrc[scn]) bySrc[scn] = [];
              let ep;
              try {
                const payload = JSON.stringify({ vodPlayFrom: v.source || v.sourceOld || scn, playUrl: v.path || "", title: v.title || "" });
                ep = (typeof btoa === "function") ? btoa(unescape(encodeURIComponent(payload))) : Buffer.from(payload, "utf8").toString("base64");
              } catch (e) { ep = v.path || ""; }
              bySrc[scn].push((v.title || "") + "$" + ep);
            }
            const froms = Object.keys(bySrc);
            return detailOut({
              vod_id: id, vod_name: it.name || "", vod_pic: ci.thumbnailPath || ci.path || "",
              vod_year: String(it.year || ""), vod_area: it.area || "", vod_actor: it.actor || "",
              vod_director: it.director || "", vod_remarks: it.remark || "",
              vod_content: (it.intro || it.brief || "").replace(/<[^>]+>/g, "").slice(0, 500),
              vod_play_from: froms.join("$$$"),
              vod_play_url: froms.map(f => bySrc[f].join("#")).join("$$$"),
            });
          }
          // proto 路径（getDetail）
          try {
            const b = secureBody({ id: id }, DATA_KEY);
            const rr = await AX.post(HOST_ + "/api/proto/v5/drama/getDetail", bytesToBuffer(b), { headers: protoHeaders(), timeout: 20000, responseType: "arraybuffer" });
            let bu;
            if (rr.data && rr.data.byteLength !== undefined) bu = Array.from(new Uint8Array(rr.data));
            else if (Buffer.isBuffer(rr.data)) bu = Array.from(rr.data);
            else if (typeof rr.data === "string") bu = Array.from(Buffer.from(rr.data, "binary"));
            else bu = [];
            const top = pbFields(bu);
            if (Number(top[1]) !== 200) return detailOut({ vod_id: id, vod_name: "" });
            const f = pbFields(top[3] || []);
            const u8 = (x) => bytesToUtf8(x || []);
            const vids = pbRepeated(top[3] || [], 29);
            const bySrc = {};
            for (const v of vids) {
              const vf = pbFields(v);
              const scn = u8(vf[10]) || "线路";
              const srcCode = u8(vf[9]) || u8(vf[11]) || scn;   // f9=source(机器码) f11=sourceOld
              const path = u8(vf[4]);
              const title = u8(vf[13]) || "1";
              if (!path) continue;
              if (!bySrc[scn]) bySrc[scn] = [];
              let ep;
              try {
                const payload = JSON.stringify({ vodPlayFrom: srcCode, playUrl: path, title: title });
                ep = (typeof btoa === "function") ? btoa(unescape(encodeURIComponent(payload))) : Buffer.from(payload, "utf8").toString("base64");
              } catch (e) { ep = path; }
              bySrc[scn].push(title + "$" + ep);
            }
            const froms = Object.keys(bySrc);
            const ci = f[2] ? pbFields(f[2]) : {};
            return detailOut({
              vod_id: id, vod_name: u8(f[9]), vod_pic: u8(ci[2]) || u8(ci[1]),
              vod_year: String(f[18] || ""), vod_area: u8(f[1]), vod_actor: u8(f[25]),
              vod_director: u8(f[12]), vod_remarks: u8(f[26]),
              vod_content: (u8(f[6]) || u8(f[7])).slice(0, 500),
              vod_play_from: froms.join("$$$"),
              vod_play_url: froms.map(f2 => bySrc[f2].join("#")).join("$$$"),
            });
          } catch (e) {}
          return detailOut({ vod_id: id, vod_name: "" });
        },        "/play": async (rq, rp) => {
          const q = qof(rq);
          let id = String(q.id || "");
          if (id.indexOf("$") >= 0) id = id.split("$").slice(1).join("$");
          if (id.indexOf("@") >= 0) id = id.split("@")[0];
          // 已是直链
          if (/^https?:\/\/.+\.(mp4|m3u8|flv|mkv|ts|mov)(\?.*)?$/i.test(id)) return { parse: 0, url: id, header: { "User-Agent": UA } };
          let info = null;
          try {
            const raw = (typeof atob === "function") ? decodeURIComponent(escape(atob(id))) : Buffer.from(id, "base64").toString("utf8");
            info = JSON.parse(raw);
          } catch (e) { info = null; }
          if (!info) return { parse: 1, url: id, header: {} };
          // 1) proto 版接口（天堂/苹果的主路径；security 版无解析配置）
          if (PUBKEY) {
            try {
              const b = secureBody({ vodPlayFrom: info.vodPlayFrom || "", playUrl: info.playUrl || "" }, DATA_KEY);
              const rr = await AX.post(HOST_ + "/api/proto/v5/videoUsableUrl", bytesToBuffer(b), { headers: protoHeaders(), timeout: 20000, responseType: "arraybuffer" });
              let bu;
              if (rr.data && rr.data.byteLength !== undefined) bu = Array.from(new Uint8Array(rr.data));
              else if (Buffer.isBuffer(rr.data)) bu = Array.from(rr.data);
              else if (typeof rr.data === "string") bu = Array.from(Buffer.from(rr.data, "binary"));
              else bu = [];
              const top = pbFields(bu);
              if (Number(top[1]) === 200 && top[3]) {
                const df = pbFields(top[3]);
                const pu = bytesToUtf8(df[1] || []);
                const msg = bytesToUtf8(df[9] || []);
                if (pu && pu !== info.playUrl && !msg) return { parse: 0, url: pu, header: {} };
              }
            } catch (e) {}
          }
          // 2) security 版接口（兜底）
          const u = HOST_ + "/api/ex/v3/security/videoUsableUrl?vodPlayFrom=" + encodeURIComponent(info.vodPlayFrom || "")
            + "&playUrl=" + encodeURIComponent(info.playUrl || "");
          const j = await JC(AX.get(u, { headers: jsonHeaders(), timeout: 20000 }));
          if (!ok(j) || !j.data) return { parse: 1, url: info.playUrl || id, header: {} };
          let obj = decryptData(j.data);
          if (obj && typeof obj === "string") { try { obj = JSON.parse(obj); } catch (e) {} }
          const pu = obj && (obj.playUrl || obj.play_url);
          const msg = (obj && obj.msg) || "";
          if (pu && pu !== info.playUrl && !msg) return { parse: 0, url: pu, header: obj.headers || {} };
          return { parse: 1, url: info.playUrl || id, header: {} };
        },
      };
      var __H = null; __H = __hardenContract(H); for (const p of Object.keys(__H)) { get(p, __H[p]); post(p, __H[p]); }
    },
    check: async () => { await boot(); },
  };
}


// ===== OK影视 契约适配（构建时注入）=====
var __okSpider = __okCreateSpider("天堂", (typeof globalThis.__OK_INIT_EXT__ !== 'undefined' && globalThis.__OK_INIT_EXT__) ? globalThis.__OK_INIT_EXT__ : "");
var __okRoutes = null;
(function () {
  var got = { routes: null };
  try {
    __okSpider.api({
      get: function (p, fn) { got.routes = got.routes || {}; got.routes[p] = fn; },
      post: function (p, fn) { got.routes = got.routes || {}; got.routes[p] = fn; },
      patch: function (p, fn) { if (!got.routes) got.routes = {}; got.routes[p] = fn; },
      del: function (p, fn) { if (!got.routes) got.routes = {}; got.routes[p] = fn; }
    });
  } catch (e) { }
  __okRoutes = got.routes || {};
})();
var __okApi = __okBuildAdapter(__okRoutes, __okSpider.meta || {});
export function __jsEvalReturn() { return __okApi; }
export default __okApi;
