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
/* 枫眠 4K - AppGet protocol source for Lanerc QuickJS */
var FM_EXT = (typeof ext !== 'undefined' && ext) ? ext : {};
if (typeof FM_EXT === 'string') { try { FM_EXT = JSON.parse(FM_EXT); } catch (e) { FM_EXT = {}; } }
var FM_HOST = String(FM_EXT.url || FM_EXT.host || 'https://appcms.4ksj.app').replace(/\/+$/, '');
if (/\/api\.php$/i.test(FM_HOST)) FM_HOST = FM_HOST.substring(0, FM_HOST.length - 8);
var FM_KEY = String(FM_EXT.dataKey || FM_EXT.datakey || FM_EXT.key || 'O3K6rYx75Q4xtiIE');
var FM_IV = String(FM_EXT.dataIv || FM_EXT.dataiv || FM_EXT.iv || FM_KEY);
var FM_UA = String(FM_EXT.ua || 'okhttp/3.10.0');
var FM_VERSION = String(FM_EXT.version || '112');
var FM_TOKEN = String(FM_EXT.token || '');
var FM_DEVICE = String(FM_EXT.deviceId || FM_EXT.deviceid || FM_EXT.id || '');
var FM_API = String(FM_EXT.api || FM_EXT.apiPrefix || '');
var FM_INIT = String(FM_EXT.init || 'initV119');
var FM_SEARCH = String(FM_EXT.search || 'searchList');
var FM_CACHE = null;
var FM_TYPES = null;
var FM_DETAIL = {};

function fmText(v) { return v == null ? '' : String(v); }
function fmTrim(v) { return fmText(v).replace(/^\s+|\s+$/g, ''); }
function fmParse(v, fallback) { if (v && typeof v === 'object') return v; try { return JSON.parse(fmText(v)); } catch (e) { return fallback == null ? {} : fallback; } }
function fmNow() { try { return Math.floor(timestamp() / 1000); } catch (e) { return Math.floor(Date.now() / 1000); } }
function fmEncode(v) { try { return encodeUri(fmText(v)); } catch (e) { return encodeURIComponent(fmText(v)); } }
function fmB64Encode(v) { try { return crypto.base64.encode(fmText(v)); } catch (e) { try { return base64Encode(fmText(v)); } catch (ignore) { return ''; } } }
function fmB64Decode(v) { try { return crypto.base64.decode(fmText(v)); } catch (e) { try { return base64Decode(fmText(v)); } catch (ignore) { return ''; } } }
function fmAesOpts() { return { mode: 'CBC', padding: 'PKCS7', keyFormat: 'utf8', ivFormat: 'utf8', iv: FM_IV, input: 'base64', output: 'utf8' }; }
function fmDecrypt(v) { try { return crypto.aes.decrypt(fmTrim(v), FM_KEY, fmAesOpts()); } catch (e) { return ''; } }
function fmEncrypt(v) { try { return crypto.aes.encrypt(fmText(v), FM_KEY, { mode: 'CBC', padding: 'PKCS7', keyFormat: 'utf8', ivFormat: 'utf8', iv: FM_IV, output: 'base64' }); } catch (e) { return ''; } }
function fmHeaders() {
    if (!FM_DEVICE) { try { FM_DEVICE = fmText(crypto.randomHex(16)); } catch (e) { FM_DEVICE = '0123456789abcdef0123456789abcdef'; } }
    var ts = fmText(fmNow()), h = { 'User-Agent': FM_UA, 'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'Keep-Alive', 'app-user-device-id': FM_DEVICE, 'app-version-code': FM_VERSION,
        'app-api-verify-time': ts, 'app-api-verify-sign': fmEncrypt(ts), 'app-ui-mode': 'light' };
    if (FM_TOKEN) h['app-user-token'] = FM_TOKEN;
    return h;
}
function fmForm(obj) { var out = []; obj = obj || {}; for (var k in obj) if (obj.hasOwnProperty(k) && obj[k] != null) out.push(fmEncode(k) + '=' + fmEncode(obj[k])); return out.join('&'); }
function fmPrefix() { if (FM_API === '1' || FM_API === 'getappapi.index') return 'getappapi.index'; if (FM_API === '2' || FM_API === 'qijiappapi.index') return 'qijiappapi.index'; if (FM_API === '3' || FM_API === 'appapi') return 'appapi'; return 'getappapi.index'; }
function fmPost(path, params) {
    try {
        var raw = post(FM_HOST + '/api.php/' + fmPrefix() + '/' + path.replace(/^\/+/, ''), fmForm(params || {}), JSON.stringify({ headers: fmHeaders(), timeout: 30000 }));
        var obj = fmParse(raw, {});
        if (obj && obj.data) {
            var plain = fmDecrypt(obj.data); if (plain) return fmParse(plain, {});
        }
        return obj || {};
    } catch (e) { return {}; }
}
function fmInit() {
    if (FM_CACHE) return FM_CACHE;
    FM_CACHE = fmPost(FM_INIT, {}) || {};
    var tl = FM_CACHE.type_list;
    FM_TYPES = tl instanceof Array ? tl : [];
    return FM_CACHE;
}
function fmCard(v, fallbackType) {
    v = v || {}; var id = v.vod_id != null ? v.vod_id : (v.id != null ? v.id : v.vodId); if (id == null || id === '') return null;
    return { id: fmText(id), name: fmTrim(v.vod_name || v.name || v.title || ''), pic: fmText(v.vod_pic || v.pic || v.cover || ''),
        type: fmTrim(v.vod_class || v.type_name || v.type || fallbackType || ''), year: fmText(v.vod_year || v.year || ''),
        remarks: fmTrim(v.vod_remarks || v.remarks || v.vod_serial || ''), desc: fmTrim(v.vod_blurb || v.vod_content || v.content || v.desc || '') };
}
function fmCards(list, fallbackType) { var out = [], arr = list instanceof Array ? list : []; for (var i = 0; i < arr.length; i++) { var c = fmCard(arr[i], fallbackType); if (c) out.push(c); } return out; }
function fmFilters(v) {
    var out = [], fs = v && v.filter_type_list instanceof Array ? v.filter_type_list : [], labels = { 'class': '类型', area: '地区', lang: '语言', year: '年份', sort: '排序' };
    for (var i = 0; i < fs.length; i++) { var f = fs[i] || {}, values = [], list = f.list instanceof Array ? f.list : []; if (!labels[f.name]) continue;
        for (var j = 0; j < list.length; j++) { var n = fmTrim(list[j]); if (n) values.push({ n: n, v: n === '全部' ? '' : n }); }
        if (values.length) out.push({ key: fmText(f.name), name: labels[f.name], value: values });
    }
    return out;
}
function fmType(key) { fmInit(); for (var i = 0; i < FM_TYPES.length; i++) if (fmText(FM_TYPES[i].type_id) === fmText(key)) return FM_TYPES[i]; return null; }
function fmList(typeId, page, filters) {
    var body = { type_id: fmText(typeId || '0'), page: String(Math.max(1, Number(page) || 1)) }, f = filters || {};
    var keys = ['class', 'area', 'lang', 'year', 'sort']; for (var i = 0; i < keys.length; i++) if (f[keys[i]] != null && fmText(f[keys[i]]) !== '') body[keys[i]] = f[keys[i]];
    var result = fmPost('typeFilterVodList?page=' + body.page, body) || {};
    return fmCards(result.recommend_list || result.list || result.vod_list, fmType(typeId) ? fmType(typeId).type_name : '影视');
}
function config() { return JSON.stringify({ kind: 'video', browseOnly: false, source: '枫眠' }); }
function categories() {
    fmInit(); var out = [{ key: '', title: '推荐' }];
    for (var i = 0; i < FM_TYPES.length; i++) { var t = FM_TYPES[i] || {}, id = fmText(t.type_id), n = fmTrim(t.type_name); if (!id || id === '0' || n === '全部' || /直播/.test(n)) continue; out.push({ key: id, title: n, filters: fmFilters(t) }); }
    return JSON.stringify(out);
}
function homeSections() {
    var home = fmInit(), cards = fmCards(home.recommend_list || [], '推荐');
    return JSON.stringify(cards.length ? [{ title: '推荐', key: '', items: cards.slice(0, 24) }] : []);
}
function search(keyword, page) {
    var key = fmTrim(keyword), p = Math.max(1, Number(page) || 1), home = fmInit();
    if (!key) return JSON.stringify(p === 1 ? fmCards(home.recommend_list || [], '推荐') : []);
    var result = fmPost(FM_SEARCH, { page: String(p), type_id: '0', keywords: key }) || {};
    return JSON.stringify(fmCards(result.search_list || result.list || result.vod_list, '影视'));
}
function searchFiltered(category, filtersJson, page) { return JSON.stringify(fmList(category, page, fmParse(filtersJson, {}))); }
function fmMeta(meta) { return 'fm|' + fmB64Encode(JSON.stringify(meta || {})); }
function detail(id) {
    var key = fmText(id); if (FM_DETAIL[key]) return JSON.stringify(FM_DETAIL[key]);
    var result = fmPost('vodDetail', { vod_id: key }) || {}, d = result.vod || {}, out = { id: key, name: fmTrim(d.vod_name || d.name || ''),
        pic: fmText(d.vod_pic || d.pic || ''), type: fmTrim(d.vod_class || d.type_name || ''), year: fmText(d.vod_year || ''),
        remarks: fmTrim(d.vod_remarks || ''), desc: fmTrim(d.vod_content || d.vod_blurb || ''), episodes: [] };
    var lines = result.vod_play_list instanceof Array ? result.vod_play_list : [];
    for (var i = 0; i < lines.length; i++) { var line = lines[i] || {}, pinfo = line.player_info || {}, route = fmTrim(pinfo.show || pinfo.name || ('线路' + (i + 1))), parse = fmText(pinfo.parse || ''), ua = fmText(pinfo.ua || pinfo.user_agent || '');
        var urls = line.urls instanceof Array ? line.urls : [];
        for (var j = 0; j < urls.length; j++) { var ep = urls[j] || {}, u = fmText(ep.url || ep.play_url || ''); if (!u) continue;
            out.episodes.push({ name: fmTrim(ep.name || ep.title) || ('第' + (j + 1) + '集'), route: route,
                url: fmMeta({ url: u, parse: parse, parseApi: fmText(ep.parse_api_url || ''), token: fmText(ep.token || ''), ua: ua, nid: fmText(ep.nid || '') }) });
        }
    }
    FM_DETAIL[key] = out; return JSON.stringify(out);
}
function fmJsonUrl(raw) { var s = fmTrim(raw), o = fmParse(s, {}); if (o.url) return fmText(o.url); if (o.data && o.data.url) return fmText(o.data.url); if (o.json) { var j = fmParse(o.json, {}); if (j.url) return fmText(j.url); } var m = s.match(/"url"\s*:\s*"([^\"]+)"/); return m ? m[1].replace(/\\\//g, '/') : ''; }
function fmTryParseApi(meta) {
    var parseApi = fmText(meta.parseApi), u = fmText(meta.url), ua = fmText(meta.ua || FM_UA), h = { 'User-Agent': ua };
    if (parseApi && /^https?:\/\//i.test(parseApi)) {
        var join = parseApi.indexOf('?') >= 0 ? '&' : '?', target = parseApi;
        if (parseApi.indexOf('url=') < 0) target += join + 'url=' + fmEncode(u);
        if (meta.token && target.indexOf('token=') < 0) target += '&token=' + fmEncode(meta.token);
        try { var got = request(target, JSON.stringify({ headers: h, timeout: 30000 })) || '', direct = fmJsonUrl(got); if (direct) return direct; if (/\.m3u8(?:\?|$)/i.test(got)) return target; } catch (e) {}
    }
    try {
        var body = fmForm({ parse_api: fmText(meta.parse || ''), url: fmEncrypt(u), token: fmText(meta.token || '') });
        var raw = post(FM_HOST + '/api.php/' + fmPrefix() + '/vodParse', body, JSON.stringify({ headers: fmHeaders(), timeout: 30000 }));
        var obj = fmParse(raw, {}), plain = obj.data ? fmDecrypt(obj.data) : ''; return fmJsonUrl(plain || raw);
    } catch (e2) { return ''; }
}
function play(flag) {
    var meta = {}; try { var s = fmText(flag); meta = s.indexOf('fm|') === 0 ? fmParse(fmB64Decode(s.substring(3)), {}) : fmParse(s, {}); } catch (e) {}
    var u = fmText(meta.url); if (!u) return JSON.stringify({ url: '', type: 'auto' });
    var direct = /^https?:\/\//i.test(u) && /(\.m3u8|\.mp4|\.mkv|\.flv)(?:\?|$)/i.test(u) ? u : fmTryParseApi(meta);
    return JSON.stringify({ url: direct || '', type: /\.m3u8(?:\?|$)/i.test(direct) ? 'm3u8' : (/\.mp4(?:\?|$)/i.test(direct) ? 'mp4' : 'auto'), headers: { 'User-Agent': fmText(meta.ua || FM_UA) } });
}
function related(id) { return '[]'; }
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
