import { Crypto } from 'assets://js/lib/cat.js';

// ===== ekan 桥 shim (drpy0 模块环境复刻易看Pro全局桥) =====
var __ek_ext = {};
function __ekOpts(o) {
    o = o || {};
    return { headers: o.headers || {}, timeout: o.timeout || 20000 };
}
function request(u, o) {
    var r = req(u, __ekOpts(typeof o === 'string' ? JSON.parse(o) : o));
    return (r && r.content != null) ? r.content : r;
}
function post(u, b, o) {
    var opt = __ekOpts(typeof o === 'string' ? JSON.parse(o) : o);
    opt.method = 'POST';
    opt.data = b == null ? '' : String(b);
    opt.postType = 'raw';
    var r = req(u, opt);
    return (r && r.content != null) ? r.content : r;
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
    }
};
// ===== shim 结束 =====
/* 闪电秒播 - YueYue exact API + protected CDN ngrSign flow; intentionally no homeSections(). */
var SOURCE_TITLE='闪电',YY='https://u.yyxdmn.com/api',TIMEOUT=30000,_token='',_app='lantianshipin',_channel='ltsp_sp02',_types=null;
var YY_KEY='aZ9$kU5%qI7=yC2=zH2#gM0@pX7^wF3a',YY_IV='hY2&tN3]kF7,dL7=',DEV_KEY='lanerc.yueyue.device.v1';
/* MyCrypto.ngrSign(fixedSecret,data) was recovered from libdecjni_hxq_v8.so:
 * raw MD5("6Jh7hrLCXBrutmJEYpMpvbU3LDEHwUZY" || data). */
var NGR_KEY='6Jh7hrLCXBrutmJEYpMpvbU3LDEHwUZY';
function t(v){return v==null?'':String(v);}function tr(v){return t(v).replace(/^\s+|\s+$/g,'');}function clean(v){return tr(t(v).replace(/<br\s*\/?\s*>/gi,'\n').replace(/<[^>]+>/g,'').replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&'));}
function j(v){if(v&&typeof v==='object')return v;try{if(typeof parseJson==='function')return parseJson(t(v));}catch(e){}try{return JSON.parse(t(v));}catch(e2){return null;}}
function resp(v){if(v==null)return'';if(typeof v==='string')return v;if(v.body!=null)return t(v.body);if(v.content!=null)return t(v.content);try{return JSON.stringify(v);}catch(e){return t(v);}}
function get(u,h){try{return resp(request(u,JSON.stringify({headers:h||{},timeout:TIMEOUT})));}catch(e){return'';}}
function postRaw(u,b,h){var o=JSON.stringify({headers:h||{},timeout:TIMEOUT});try{return resp(post(u,t(b),o));}catch(e){return'';}}
function enc(v){try{if(typeof encodeUri==='function')return t(encodeUri(t(v)));}catch(e){}return encodeURIComponent(t(v));}function dec(v){try{if(typeof decodeUri==='function')return t(decodeUri(t(v)));}catch(e){}try{return decodeURIComponent(t(v));}catch(e2){return t(v);}}
function b64e(v){try{return t(base64Encode(t(v)));}catch(e){}try{return t(crypto.base64.encode(t(v),{input:'utf8'}));}catch(e2){return'';}}function b64d(v){try{return t(base64Decode(t(v)));}catch(e){}try{return t(crypto.base64.decode(t(v),{output:'utf8'}));}catch(e2){return'';}}
function hash(n,v){try{if(n==='MD5'&&typeof md5==='function')return t(md5(t(v)));if(n==='SHA-1'&&typeof sha1==='function')return t(sha1(t(v)));return t(crypto.hash(n,t(v),{input:'utf8',output:'hex'}));}catch(e){return'';}}
function form(o){var a=[];for(var k in o)if(Object.prototype.hasOwnProperty.call(o,k))a.push(enc(k)+'='+enc(o[k]));return a.join('&');}function typeOf(u){u=t(u).toLowerCase();if(u.indexOf('.m3u8')>=0)return'm3u8';if(u.indexOf('.mp4')>=0)return'mp4';return'auto';}
function rndHex(n){var s='';while(s.length<n)s+=Math.floor(Math.random()*16).toString(16);return s;}function device(){var x='';try{x=t(getItem(DEV_KEY,''));}catch(e){}if(!/^[0-9a-f]{16}$/i.test(x)){x=rndHex(16);try{setItem(DEV_KEY,x);}catch(e2){}}return x;}
function yyHeaders(){var ts=t(Date.now()),d=device();return{'User-Agent':'okhttp/4.9.0','sys_platform':'2','device_id':d,'sysrelease':'12','sign':hash('MD5','zD9[bM4~sF4~uY2)'+d+ts).toUpperCase(),'cur_time':ts,'channel_code':_channel,'mobmodel':'V2238A','version':'51000','token':_token,'log-header':'I am the log request header.','mob_mfr':'vivo','package_name':'com.lineone.connecter','app_id':_app,'Content-Type':'application/x-www-form-urlencoded'};}
function yyCall(path,p,noInit){if(!noInit)yyInit();var raw=postRaw(YY+path,typeof p==='string'?p:form(p||{}),yyHeaders()),plain='';try{plain=t(crypto.aes.decrypt(tr(raw),YY_KEY,{mode:'CBC',padding:'PKCS7',keyFormat:'utf8',iv:YY_IV,ivFormat:'utf8',input:'base64',output:'utf8'}));}catch(e){}var x=j(plain);if(!x)throw Error('闪电响应解密失败');return x;}
function yyInit(){if(_token)return;var x=yyCall('/new_public/init_v2',{invited_by:'',ua:'Mozilla/5.0 (Linux; Android 11; M2012K10C Build/RP1A.200720.011; wv) AppleWebKit/537.36 Chrome/87.0.4280.141 Mobile Safari/537.36',is_install:'1'},true),u=((x.result||{}).user_info)||{};_token=t(u.token);_app=t(u.app_id)||_app;_channel=t(u.channel_code)||_channel;}
function base(id){return{sig:'',nc_token:'',code:'',phone:'',session_id:'',vod_id:t(id)};}function cards(a){a=Array.isArray(a)?a:[];var o=[];for(var i=0;i<a.length;i++){var x=a[i]||{};if(x.id&&x.vod_name)o.push({id:t(x.id),name:clean(x.vod_name),pic:t(x.vod_pic),type:clean(x.vod_tag),year:t(x.vod_year),remarks:clean(x.remarks||x.collection_new_title),desc:clean(x.vod_blurb)});}return o;}
function yyTypes(){if(_types)return _types;_types=((yyCall('/new_type/list_v2','').result)||[]);return _types;}
function categories(){try{var out=[{key:'',title:'推荐'}],a=yyTypes();for(var i=0;i<a.length;i++){var x=a[i]||{},it={key:t(x.id),title:clean(x.name)},fs=[],ms=x.msg||[];for(var k=0;k<ms.length;k++){var m=ms[k]||{};if(m.name==='tag_type')continue;var key=m.name==='type'?'class':m.name,val=m.data||[],vs=[{n:'全部',v:''}];for(var z=0;z<val.length;z++){var q=tr(val[z]);if(q&&q!=='全部'&&q!=='排序')vs.push({n:q,v:q});}if(vs.length>1)fs.push({key:key,name:key==='class'?'类型':key==='area'?'地区':key==='year'?'年份':'排序',value:vs});}if(fs.length)it.filters=fs;if(it.key&&it.title)out.push(it);}return JSON.stringify(out);}catch(e){return JSON.stringify([{key:'',title:'推荐'}]);}}
function yyList(id,p,f){f=f||{};return cards((yyCall('/new_search/screen_v2',{area:t(f.area),sort:t(f.sort),type:t(f['class']||f.type),year:t(f.year),pn:t(p),type_id:t(id)}).result)||[]);}function search(q,p){try{q=tr(q);p=Math.max(1,Number(p)||1);if(q)return JSON.stringify(cards((yyCall('/new_search/result_v2',{kw:q,pn:t(p)}).result)||[]));var a=yyTypes();return JSON.stringify(a.length?yyList(a[0].id,p,{}):[]);}catch(e){return'[]';}}function searchFiltered(c,f,p){try{return JSON.stringify(yyList(c,Math.max(1,Number(p)||1),j(f)||{}));}catch(e){return'[]';}}
function detail(id){try{var x=(yyCall('/new_video/result_v2',base(id)).result)||{},a=x.vod_collection||[],eps=[];for(var i=0;i<a.length;i++){var e=a[i]||{},meta={collection_id:t(e.id),vod_token:t(e.vod_token),cur_time:t(e.cur_time),vod_id:t(id),title:clean(x.vod_name),episode:clean(e.title)||t(i+1),index:i};eps.push({name:meta.episode,route:'闪电',url:'yy1:'+b64e(JSON.stringify(meta))});}return JSON.stringify({id:t(id),name:clean(x.vod_name),pic:t(x.vod_pic),desc:clean(x.vod_blurb),year:t(x.vod_year),area:clean(x.vod_area),type:clean(x.vod_tag),actor:clean(x.vod_actor),director:clean(x.vod_director),episodes:eps});}catch(e){return JSON.stringify({id:t(id),name:'',pic:'',desc:'',episodes:[]});}}

function ngrSign(data){return hash('MD5',NGR_KEY+t(data)).toLowerCase();}
function yyCk(v){var x=tr(b64d(v));return x||tr(v);}
function yySignedUrl(raw,ck,sec){var m=tr(raw).match(/^(https?:\/\/[^/]+)(\/[^?]*)/i);if(!m)return tr(raw);var tm=(sec==null?Math.floor(Date.now()/1000):Number(sec)).toString(16).toLowerCase(),q=yyCk(ck).replace(/^[?&]+/,'');return m[1]+m[2]+'?'+(q?q+'&':'')+'wsSecret='+ngrSign(m[2]+tm)+'&wsTime='+tm;}
function yyAlternates(r){var a=j(r&&r.m3u8_json)||[];if(!Array.isArray(a))return[];a=a.filter(function(x){return x&&/^https?:\/\//i.test(t(x.url));});a.sort(function(x,y){return(Number(y.weight)||0)-(Number(x.weight)||0);});return a;}
function yyRewriteM3u8(raw,ck){var signed=yySignedUrl(raw,ck),body=get(signed,{'User-Agent':'Mozi','Accept':'*/*'}),m=tr(raw).match(/^(https?:\/\/[^/]+)(\/.*\/)[^/]+(?:\?.*)?$/i);if(!m||body.indexOf('#EXTM3U')<0)return'';var lines=body.split(/\r?\n/),out=[];for(var i=0;i<lines.length;i++){var s=tr(lines[i]);if(!s||s.charAt(0)==='#'||/^https?:\/\//i.test(s)){out.push(lines[i]);continue;}var name=s.split('?')[0];out.push(yySignedUrl(m[1]+m[2]+name,ck));}return out.join('\n');}
/* Exact native behavior: the manifest path and every relative segment path get
 * their own lowercase-hex wsTime and MD5(NGR_KEY || path || wsTime).  A rewritten
 * all-absolute inline manifest avoids the Android-only Java proxy. */
function play(flag){try{if(t(flag).indexOf('yy1:')!==0)throw Error('闪电播放参数无效');var m=j(b64d(t(flag).substring(4)))||{},p=base(m.vod_id);p.collection_id=m.collection_id;p.vod_token=m.vod_token;p.cur_time=m.cur_time;var r=(yyCall('/new_video/collection_v2',p).result)||{},h={'User-Agent':'Mozi','Accept':'*/*'},signed=yySignedUrl(r.vod_url,r.ck),manifest=yyRewriteM3u8(r.vod_url,r.ck),u=manifest?'data:application/vnd.apple.mpegurl;base64,'+b64e(manifest):signed;return JSON.stringify({url:u,type:'m3u8',headers:h,route:manifest?'yueyue-ngr-inline':'yueyue-ngr',signedOrigin:signed,ck:yyCk(r.ck)});}catch(e){return JSON.stringify({url:'',type:'auto'});}}
function config(){return JSON.stringify({kind:'video',browseOnly:false,source:SOURCE_TITLE});}
// ===== drpy 适配层: 易看源 -> drpy0(TVBox/FongMi) 约定 =====
// 注意: drpy 函数一律用 drpy_ 前缀, 避免覆盖易看源的同名函数(hoisting 后者会赢)
function __ekCards(a) {
    a = (typeof a === 'string') ? JSON.parse(a || '[]') : (a || []);
    if (!Array.isArray(a)) a = [];
    return a.map(function (x) {
        return { vod_id: String(x.id || ''), vod_name: String(x.name || ''), vod_pic: String(x.pic || ''),
                 vod_remarks: String(x.remarks || ''), vod_year: String(x.year || ''),
                 vod_class: String(x.type || ''), vod_content: String(x.desc || '') };
    });
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
    } catch (e) {}
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
    } catch (e) {}
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
