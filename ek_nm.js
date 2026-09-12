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
/* 伯伯秒播 - 原站目录 + 播放语义校验 + 独播/文才故障切换；无 homeSections(). */
var SOURCE_TITLE='伯伯',HOST='https://vip.wwgz.cn:5200',TIMEOUT=30000;
var UA='Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1';
var H={'User-Agent':UA,'Referer':HOST+'/'};
/* 伯伯的 monday 线路当前返回 JPEG 分片伪 HLS，lzm3u8 线路也可能过期为 404 HTML。
 * 保留原站目录；播放语义校验失败时按片名/集数切到便携文才 API。 */
var WC_HOST='https://www.hkybqufgh.com';
var WC_KEY='cb808529bae6b6be45ecfab29a4889bc';
var WC_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36';
var DB_HOST='https://api.dbokutv.com';
var DB_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36';
var DB_H={'User-Agent':DB_UA,'Referer':'https://www.duboku.tv/','Connection':'Keep-Alive'};
var BB_META={};
function t(v){return v==null?'':String(v);} function tr(v){return t(v).replace(/^\s+|\s+$/g,'');}
function entity(v){return t(v).replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#0?39;|&apos;/gi,"'").replace(/&lt;/gi,'<').replace(/&gt;/gi,'>');}
function clean(v){return tr(entity(t(v).replace(/<br\s*\/?\s*>/gi,'\n').replace(/<[^>]+>/g,'')));}
function resp(v){if(v==null)return'';if(typeof v==='string')return v;if(v.body!=null)return t(v.body);if(v.content!=null)return t(v.content);try{return JSON.stringify(v);}catch(e){return t(v);}}
function get(u,h){try{return resp(request(u,JSON.stringify({headers:h||H,timeout:TIMEOUT})));}catch(e){return'';}}
function enc(v){try{if(typeof encodeUri==='function')return t(encodeUri(t(v)));}catch(e){}return encodeURIComponent(t(v));}
function dec(v){try{if(typeof decodeUri==='function')return t(decodeUri(t(v)));}catch(e){}try{return decodeURIComponent(t(v));}catch(e2){return t(v);}}
function json(v){if(v&&typeof v==='object')return v;try{return JSON.parse(t(v));}catch(e){try{return parseJson(t(v));}catch(e2){return null;}}}
function digest(n,v){try{if(n==='MD5'&&typeof md5==='function')return t(md5(t(v)));if(n==='SHA-1'&&typeof sha1==='function')return t(sha1(t(v)));return t(crypto.hash(n,t(v),{input:'utf8',output:'hex'}));}catch(e){return'';}}
function b64e(v){try{return t(base64Encode(t(v)));}catch(e1){}try{return t(crypto.base64.encode(t(v),{input:'utf8'}));}catch(e2){return'';}}
function b64d(v){try{return t(base64Decode(t(v)));}catch(e1){}try{return t(crypto.base64.decode(t(v),{output:'utf8'}));}catch(e2){return'';}}
function abs(u){u=entity(tr(u));if(!u)return'';if(/^https?:\/\//i.test(u))return u;if(u.indexOf('//')===0)return'https:'+u;return HOST+(u.charAt(0)==='/'?'':'/')+u;}
/* 原站的海报中混有证书不匹配的 mg.lzipic.com 和校验 Referer 的豆瓣图床。
 * 将前者切到同路径的正常 CDN 主机；后者用宿主支持的封面头后缀携带 Referer。 */
function image(u){
 u=abs(u);if(!u)return'';
 u=u.replace(/^https?:\/\/mg\.lzipic\.com\//i,'https://img.lzipic.com/');
 if(/^https?:\/\/[^/]*doubanio\.com\//i.test(u))return u+'@Referer=https://movie.douban.com/';
 return u;
}
function attr(s,k){var m=t(s).match(new RegExp(k+'\\s*=\\s*["\\\']([^"\\\']+)["\\\']','i'));return m?entity(m[1]):'';}
function typeOf(u){u=t(u).toLowerCase();if(u.indexOf('.m3u8')>=0||u.indexOf('.m3u')>=0)return'm3u8';if(u.indexOf('.mp4')>=0)return'mp4';if(u.indexOf('.flv')>=0)return'flv';return'auto';}
function unique(a){var o=[],seen={};for(var i=0;i<a.length;i++){var x=a[i]||{},id=t(x.id);if(id&&x.name&&!seen[id]){seen[id]=1;o.push(x);}}return o;}
function pictureCards(html){var out=[],re=/<li\b[^>]*>([\s\S]*?)<\/li>/gi,m;while((m=re.exec(t(html)))){var b=m[1],a=b.match(/<a\b([^>]*)href\s*=\s*["']([^"']*vod-detail[^"']*)["']([^>]*)>/i);if(!a)continue;var head=a[1]+' '+a[3],name=attr(head,'title');if(!name){var nm=b.match(/class\s*=\s*["']sTit["'][^>]*>([\s\S]*?)<\/span>/i);name=nm?clean(nm[1]):'';}var im=b.match(/<img\b([^>]*)>/i),pic=im?(attr(im[1],'data-echo')||attr(im[1],'data-original')||attr(im[1],'data-src')||attr(im[1],'src')):'';if(name)out.push({id:abs(a[2]),name:clean(name),pic:image(pic),remarks:''});}return unique(out);}
function mapCards(html,q,page){var all=[],re=/<li\b[^>]*>\s*<a\b[^>]*href\s*=\s*["']([^"']*vod-detail[^"']*)["'][^>]*>([\s\S]*?)<\/a>\s*<span[^>]*>([\s\S]*?)<\/span>/gi,m,needle=tr(q).toLowerCase();while((m=re.exec(t(html)))){var name=clean(m[2]);if(!needle||name.toLowerCase().indexOf(needle)>=0){var meta=clean(m[3]),p=meta.split('/');all.push({id:abs(m[1]),name:name,pic:'',type:p[0]||'',year:p[1]||'',remarks:meta});}}var start=(Math.max(1,Number(page)||1)-1)*30;return unique(all).slice(start,start+30);}
function categories(){return JSON.stringify([{key:'',title:'推荐'},{key:'1',title:'电影'},{key:'2',title:'电视剧'},{key:'3',title:'综艺'},{key:'4',title:'动漫'},{key:'26',title:'短剧'}]);}
function search(q,page){try{q=tr(q);page=Math.max(1,Number(page)||1);if(!q)return JSON.stringify(page===1?pictureCards(get(HOST+'/',H)).slice(0,60):[]);var live=get(HOST+'/vod-search-pg-'+page+'-wd-'+enc(q)+'.html',H),items=pictureCards(live);if(items.length)return JSON.stringify(items);return JSON.stringify(mapCards(get(HOST+'/vod-map.html',H),q,page));}catch(e){return'[]';}}
function searchFiltered(category,filters,page){try{filters=typeof filters==='string'?JSON.parse(filters):(filters||{});page=Math.max(1,Number(page)||1);var id=t(filters.cateId||category),area=t(filters.area||''),year=t(filters.year||''),by=t(filters.by||'');var u=HOST+'/index.php?m=vod-list-id-'+enc(id)+'-pg-'+page+'-order--by-'+enc(by)+'-class-0-year-'+enc(year)+'-letter--area-'+enc(area)+'-lang-.html';return JSON.stringify(pictureCards(get(u,H)));}catch(e){return'[]';}}
function first(s,re){var m=t(s).match(re);return m?m[1]:'';}
function bbEpisodeFlag(url,title,episode,ordinal){return'bb1|||'+enc(url)+'|||'+enc(title)+'|||'+enc(episode)+'|||'+t(ordinal||1);}
function parseBbFlag(flag){var p=t(flag).split('|||');if(p[0]!=='bb1')return null;return{url:dec(p[1]||''),title:dec(p[2]||''),episode:dec(p[3]||''),ordinal:Math.max(1,Number(p[4])||1)};}

function detail(id){
 try{
  id=abs(id);var html=get(id,H);
  var name=clean(first(html,/<h1\b[^>]*class\s*=\s*["']title["'][^>]*>[\s\S]*?<a\b[^>]*>([\s\S]*?)<\/a>/i));
  var pic=image(first(html,/<section\b[^>]*class\s*=\s*["']page-hd["'][^>]*>[\s\S]*?<img\b[^>]*(?:data-echo|data-original|data-src|src)\s*=\s*["']([^"']+)/i));
  var desc=clean(first(html,/<article\b[^>]*class\s*=\s*["']detail-con["'][^>]*>[\s\S]*?<p[^>]*>([\s\S]*?)<\/p>/i));
  var playPage=abs(first(html,/href\s*=\s*["']([^"']*vod-play[^"']*)["']/i)),ph=get(playPage,H);
  var from=first(ph,/mac_from\s*=\s*'([^']*)'/i),urls=first(ph,/mac_url\s*=\s*'([^']*)'/i),routes=from.split('$$$'),groups=urls.split('$$$'),eps=[];
  for(var r=0;r<groups.length;r++){
   var es=groups[r].split('#');
   for(var k=0;k<es.length;k++){
    var z=es[k],p=z.indexOf('$');
    if(p>0){var raw=tr(z.substring(p+1)),epName=clean(z.substring(0,p))||('第'+(k+1)+'集');if(raw){BB_META[raw]={url:raw,title:name,episode:epName,ordinal:k+1};eps.push({name:epName,route:clean(routes[r])||('线路'+(r+1)),url:bbEpisodeFlag(raw,name,epName,k+1)});}}
   }
  }
  var year=clean(first(html,/年代\s*[:：][\s\S]*?<a\b[^>]*>([^<]+)/i));
  return JSON.stringify({id:id,name:name,pic:pic,desc:desc,year:year,episodes:eps});
 }catch(e){return JSON.stringify({id:t(id),name:'',pic:'',desc:'',episodes:[]});}
}

function wcHeaders(raw){var ts=t(Date.now());return{'User-Agent':WC_UA,'Referer':WC_HOST,'t':ts,'sign':digest('SHA-1',digest('MD5',t(raw)+'&key='+WC_KEY+'&t='+ts))};}
function wcGet(path,raw){return json(get(WC_HOST+path,wcHeaders(raw)))||{};}
function wcSearch(title){var raw='keyword='+t(title)+'&pageNum=1&pageSize=8',root=wcGet('/api/mw-movie/anonymous/video/searchByWord?keyword='+enc(title)+'&pageNum=1&pageSize=8',raw),a=(((((root||{}).data||{}).result||{}).list)||[]),out=[];for(var i=0;i<a.length;i++){var x=a[i]||{},id=x.id!=null?x.id:(x.vodId!=null?x.vodId:x.vod_id),name=clean(x.name||x.vodName||x.vod_name);if(t(id)&&name)out.push({id:t(id),name:name});}return out;}
function normalizeTitle(v){return clean(v).replace(/[\s·•:：\-—_（）()【】\[\]]/g,'').toLowerCase();}
function wcFind(title){var a=wcSearch(title);if(!a.length)return null;var wanted=normalizeTitle(title),chosen=a[0];for(var i=0;i<a.length;i++){var got=normalizeTitle(a[i].name);if(got===wanted){chosen=a[i];break;}if(got.indexOf(wanted)>=0||wanted.indexOf(got)>=0)chosen=a[i];}var root=wcGet('/api/mw-movie/anonymous/video/detail?id='+enc(chosen.id),'id='+chosen.id),v=root.data||{},es=Array.isArray(v.episodeList)?v.episodeList:[],out=[];for(var k=0;k<es.length;k++){var e=es[k]||{};out.push({name:clean(e.name)||('第'+(k+1)+'集'),nid:t(e.nid),id:chosen.id});}return out.length?{name:clean(v.vodName)||chosen.name,episodes:out}:null;}
function wcPick(vod,episode,ordinal){var a=vod&&vod.episodes||[];if(!a.length)return null;var wanted=normalizeTitle(episode).replace(/^第/,'').replace(/集$/,'').replace(/^0+/,'');for(var i=0;i<a.length;i++){var got=normalizeTitle(a[i].name).replace(/^第/,'').replace(/集$/,'').replace(/^0+/,'');if(wanted&&got===wanted)return a[i];}return a[Math.min(Math.max(1,Number(ordinal)||1)-1,a.length-1)]||a[0];}
function wcPlay(e){if(!e)return{url:'',type:'auto'};var raw='clientType=1&id='+e.id+'&nid='+e.nid,root=wcGet('/api/mw-movie/anonymous/v2/video/episode/url?'+raw,raw),a=((root.data||{}).list)||[],u=a.length?t(a[0].url):'';return{url:u,type:typeOf(u),headers:{'User-Agent':WC_UA,'Referer':WC_HOST},userAgent:WC_UA,referer:WC_HOST,route:'备用·文才'};}
function dbDecode(v){v=tr(v).replace(/\./g,'=');var s='';for(var i=0;i<v.length;i+=10)s+=v.substring(i,i+10).split('').reverse().join('');return b64d(s);}
function dbRnd(n){var c='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',s='';while(s.length<n)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}
function dbQuery(){var now=Date.now(),r=Math.floor(Math.random()*800000001),a=t(100000000+r)+t(900000000-r),b=t(now),s='',n=Math.min(a.length,b.length);for(var i=0;i<n;i++)s+=a.charAt(i)+b.charAt(i);s+=a.substring(n)+b.substring(n);return'?sign='+dbRnd(60)+'&ssid='+b64e(s).replace(/=/g,'.')+'&token='+dbRnd(38);}
function dbFind(title){var a=json(get(DB_HOST+'/vodsearch'+dbQuery()+'&wd='+enc(title),DB_H))||[],wanted=normalizeTitle(title),chosen=null;for(var i=0;i<a.length;i++){var x=a[i]||{},name=clean(x.Name),id=dbDecode(x.DId),got=normalizeTitle(name);if(!id||!name)continue;if(!chosen)chosen={id:id,name:name};if(got===wanted){chosen={id:id,name:name};break;}if(got.indexOf(wanted)>=0||wanted.indexOf(got)>=0)chosen={id:id,name:name};}if(!chosen)return null;var d=json(get(DB_HOST+chosen.id+dbQuery(),DB_H))||{},list=d.Playlist||[],episodes=[];for(var k=0;k<list.length;k++){var p=list[k]||{},flag=dbDecode(p.VId);if(flag)episodes.push({name:clean(p.EpisodeName)||('第'+(k+1)+'集'),flag:flag});}return episodes.length?{name:clean(d.Name)||chosen.name,episodes:episodes}:null;}
function dbPick(vod,episode,ordinal){var a=vod&&vod.episodes||[];if(!a.length)return null;var wanted=normalizeTitle(episode).replace(/^第/,'').replace(/集$/,'').replace(/^0+/,'');for(var i=0;i<a.length;i++){var got=normalizeTitle(a[i].name).replace(/^第/,'').replace(/集$/,'').replace(/^0+/,'');if(wanted&&got===wanted)return a[i];}return a[Math.min(Math.max(1,Number(ordinal)||1)-1,a.length-1)]||a[0];}
function dbPlay(e){if(!e||!e.flag)return{url:'',type:'auto'};var x=json(get(DB_HOST+e.flag+dbQuery(),DB_H))||{},u=dbDecode(x.HId),headers={'User-Agent':DB_UA,'Origin':'https://w.duboku.io','Referer':'https://w.duboku.io/'};return{url:u,type:typeOf(u),headers:headers,userAgent:DB_UA,referer:'https://w.duboku.io/',route:'备用·独播'};}
function looksPlayable(url){url=tr(url);if(!/^https?:\/\//i.test(url))return false;if(!/\.m3u8?(?:$|[?#])/i.test(url))return true;var body=get(url,{'User-Agent':UA,'Referer':HOST+'/'});if(!/^\s*#EXTM3U/i.test(body))return false;var bad=/\.(?:jpe?g|png|webp|gif|bmp)(?:$|[?#])/im.test(body)||/\/origin\.jpg(?:$|[?#])/im.test(body);return!bad;}
function safeUrl(url){try{return encodeURI(tr(url));}catch(e){return tr(url);}}
function primaryResolve(u){
 if(u.indexOf('dJj')===0){var base=tr(get('http://103.36.222.35:9595/wexfnwshinidie/bobo/caonidie.php',{'User-Agent':'okhttp/4.12.0'})),p=base+enc(u),html=get(p,{'User-Agent':UA,'Referer':p});return first(t(html).replace(/\s/g,''),/video:\{url:'(.*?)',/i);}
 if(u.indexOf('aFHBRI09')===0){var p1='https://api.wwgz.cn:520/webcloud/m3u8.php?url='+enc(u);return first(t(get(p1,{'User-Agent':UA,'Referer':p1})).replace(/\s/g,''),/url='(.*?)';/i);}
 if(u.indexOf('bFWBFI09Z7X3J1pHYeWlwlvocW')===0){var p2='https://api.wwgz.cn:520/webcloud/nmm3.php?url='+enc(u);return first(t(get(p2,{'User-Agent':UA,'Referer':p2})).replace(/\s/g,''),/url='(.*?)';/i);}
 return u;
}
function play(flag){
 try{
  var meta=parseBbFlag(flag),legacy=tr(flag);if(!meta&&BB_META[legacy])meta=BB_META[legacy];
  if(!meta&&/^https?:\/\//i.test(legacy)){var tail=dec(legacy.split('/').pop().split(/[?#]/)[0]).replace(/\.(?:m3u8?|mp4|flv)$/i,'');if(tail&&!/^(?:index|chunklist|playlist)$/i.test(tail))meta={url:legacy,title:tail,episode:'',ordinal:1};}
  var u=primaryResolve(meta?meta.url:legacy);
  if(looksPlayable(u)){u=safeUrl(u);return JSON.stringify({url:u,type:typeOf(u),headers:{'User-Agent':UA,'Referer':HOST+'/'},userAgent:UA,referer:HOST+'/',route:'伯伯原站'});}
  if(meta&&meta.title){
   var direct=dbPlay(dbPick(dbFind(meta.title),meta.episode,meta.ordinal));
   if(direct.url&&looksPlayable(direct.url)){direct.url=safeUrl(direct.url);return JSON.stringify(direct);}
   var backup=wcPick(wcFind(meta.title),meta.episode,meta.ordinal),resolved=wcPlay(backup);
   if(resolved.url)return JSON.stringify(resolved);
  }
  return JSON.stringify({url:'',type:'auto',error:'原线路不是有效视频，备用线路未命中'});
 }catch(e){return JSON.stringify({url:'',type:'auto'});}
}
function config(){return JSON.stringify({kind:'video',browseOnly:false,source:SOURCE_TITLE});}
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
