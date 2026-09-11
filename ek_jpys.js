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
function text(value) {
    return value == null ? '' : String(value);
}

function trim(value) {
    return text(value).replace(/^\s+|\s+$/g, '');
}

function clean(value) {
    return trim(text(value)
        .replace(/<[^>]+>/g, '')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&quot;/gi, '"')
        .replace(/&#0?39;|&#x27;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&#(\d+);/g, function (all, code) {
            return String.fromCharCode(parseInt(code, 10));
        }));
}

function json(value) {
    if (value && typeof value === 'object') return value;
    try {
        if (typeof parseJson === 'function') return parseJson(text(value));
    } catch (ignore1) {}
    try { return JSON.parse(text(value)); } catch (ignore2) {}
    return null;
}

function logMessage(message) {
    try {
        if (typeof log === 'function') log('[Jpys] ' + message);
    } catch (ignore) {}
}

function extObject() {
    try {
        if (typeof ext === 'undefined' || ext == null) return {};
        if (typeof ext === 'object') return ext;
        var parsed = json(ext);
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (ignore) {}
    return {};
}

function cfg(key, fallback) {
    var value = extObject()[key];
    return value == null || text(value) === '' ? fallback : value;
}

function normalizeHost(value) {
    var host = trim(value).replace(/[\]\["']/g, '').replace(/\/+$/, '');
    return /^https?:\/\//i.test(host) ? host : '';
}

function appendHosts(out, value) {
    if (value == null) return;
    if (Array.isArray(value)) {
        for (var i = 0; i < value.length; i++) appendHosts(out, value[i]);
        return;
    }
    var values = text(value).match(/https?:\/\/[^,\]\["'\s]+/gi) || [];
    for (var j = 0; j < values.length; j++) {
        var host = normalizeHost(values[j]);
        if (host && out.indexOf(host) < 0) out.push(host);
    }
}

var HOSTS = (function () {
    var out = [];
    try {
        if (typeof ext !== 'undefined' && typeof ext === 'string') appendHosts(out, ext);
    } catch (ignore) {}
    var values = extObject();
    appendHosts(out, values.hosts);
    appendHosts(out, values.host);
    appendHosts(out, values.url);
    var defaults = [
        'https://y2s52n7.com',
        'https://www.hkybqufgh.com',
        'https://www.sizhengxt.com',
        'https://www.9zhoukj.com',
        'https://www.jiabaide.cn'
    ];
    appendHosts(out, defaults);
    return out;
})();

var SIGN_KEY = text(cfg('signKey', 'cb808529bae6b6be45ecfab29a4889bc'));
var UA = text(cfg('ua', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'));
var PLAY_ORIGIN = text(cfg('playOrigin', 'https://www.ghw9zwp5.com')).replace(/\/+$/, '');
var PLAY_REFERER = text(cfg('playReferer', PLAY_ORIGIN));
var TIMEOUT = parseInt(cfg('timeout', 12000), 10) || 12000;
var ANIME_ONLY = false;
var _hostIndex = 0;
var _activeHost = HOSTS[0];
var _deviceId = '';
var _categoriesCache = '';
var _detailCache = {};
var _detailOrder = [];
var _homeCache = '';

function nowMillis() {
    var value = 0;
    try {
        if (typeof timestamp === 'function') value = Number(timestamp());
    } catch (ignore1) {}
    if (!value) {
        try { value = Date.now(); } catch (ignore2) { value = new Date().getTime(); }
    }
    if (value < 100000000000) value *= 1000;
    return String(Math.floor(value));
}

function uuid() {
    var seed = Number(nowMillis()) || new Date().getTime();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (kind) {
        var random = (seed + Math.random() * 16) % 16 | 0;
        seed = Math.floor(seed / 16);
        return (kind === 'x' ? random : (random & 3) | 8).toString(16);
    });
}

function encode(value) {
    try {
        if (typeof encodeUri === 'function') return text(encodeUri(text(value)));
    } catch (ignore1) {}
    try { return encodeURIComponent(text(value)); } catch (ignore2) { return text(value); }
}

function javaDigest(algorithm, value) {
    try {
        var digest = java.security.MessageDigest.getInstance(algorithm);
        var bytes = digest.digest(new java.lang.String(text(value)).getBytes('UTF-8'));
        var result = new java.lang.StringBuilder();
        for (var i = 0; i < bytes.length; i++) {
            var number = bytes[i] & 255;
            if (number < 16) result.append('0');
            result.append(java.lang.Integer.toHexString(number));
        }
        return text(result.toString()).toLowerCase();
    } catch (ignore) {}
    return '';
}

function digest(name, value) {
    try {
        if (name === 'MD5' && typeof md5 === 'function') return text(md5(text(value))).toLowerCase();
        if (name === 'SHA-1' && typeof sha1 === 'function') return text(sha1(text(value))).toLowerCase();
    } catch (ignore) {}
    return javaDigest(name, value);
}

function canonical(pairs, timeValue) {
    var values = [];
    for (var i = 0; i < pairs.length; i++) {
        if (pairs[i][1] == null || text(pairs[i][1]) === '') continue;
        values.push(text(pairs[i][0]) + '=' + text(pairs[i][1]));
    }
    values.push('key=' + SIGN_KEY);
    values.push('t=' + timeValue);
    return values.join('&');
}

function queryString(pairs) {
    var values = [];
    for (var i = 0; i < pairs.length; i++) {
        if (pairs[i][1] == null) continue;
        values.push(text(pairs[i][0]) + '=' + encode(pairs[i][1]));
    }
    return values.join('&');
}

function responseText(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (value.body != null) return text(value.body);
    if (value.content != null) return text(value.content);
    try { return JSON.stringify(value); } catch (ignore) {}
    return text(value);
}

function getText(url, headers) {
    var options = { headers: headers || {}, timeout: TIMEOUT };
    try {
        if (typeof request === 'function') {
            var value = request(text(url), JSON.stringify(options));
            var body = responseText(value);
            if (body) return body;
        }
    } catch (firstError) {
        try {
            var second = request(text(url), options);
            var secondBody = responseText(second);
            if (secondBody) return secondBody;
        } catch (secondError) {}
    }
    var connection = null;
    try {
        connection = new java.net.URL(text(url)).openConnection();
        connection.setConnectTimeout(TIMEOUT);
        connection.setReadTimeout(TIMEOUT);
        connection.setUseCaches(false);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestMethod('GET');
        for (var key in headers) {
            if (headers.hasOwnProperty(key)) connection.setRequestProperty(text(key), text(headers[key]));
        }
        var status = connection.getResponseCode();
        if (status < 200 || status >= 300) return '';
        var reader = new java.io.BufferedReader(new java.io.InputStreamReader(connection.getInputStream(), 'UTF-8'));
        var output = new java.lang.StringBuilder();
        var line;
        while ((line = reader.readLine()) !== null) output.append(line);
        reader.close();
        return text(output.toString());
    } catch (ignore) {
        return '';
    } finally {
        if (connection !== null) {
            try { connection.disconnect(); } catch (ignoreDisconnect) {}
        }
    }
}

function api(path, pairs) {
    pairs = pairs || [];
    if (!_deviceId) _deviceId = text(cfg('deviceId', '')) || uuid();
    var query = queryString(pairs);
    for (var offset = 0; offset < HOSTS.length; offset++) {
        var index = (_hostIndex + offset) % HOSTS.length;
        var host = HOSTS[index];
        var timeValue = nowMillis();
        var md5Value = digest('MD5', canonical(pairs, timeValue));
        var sign = md5Value ? digest('SHA-1', md5Value) : '';
        if (!sign) return {};
        var raw = getText(host + path + (query ? '?' + query : ''), {
            'User-Agent': UA,
            'Accept': 'application/json, text/plain, */*',
            'sign': sign,
            't': timeValue,
            'deviceid': _deviceId
        });
        var result = json(raw);
        if (result && typeof result === 'object' && (result.code == null || Number(result.code) === 200)) {
            _hostIndex = index;
            _activeHost = host;
            return result;
        }
        logMessage('host failed: ' + host + path);
    }
    return {};
}

var CATEGORY_NAMES = {
    '1': '电影',
    '2': '电视剧',
    '3': '综艺',
    '4': '动漫',
    '88': '短剧'
};

function isAllowed(raw) {
    raw = raw || {};
    var value = text(raw.vodName) + ' ' + text(raw.vodClass) + ' ' + text(raw.tags);
    return !/(伦理|成人|三级|情色|性生活|性\/生活)/.test(value);
}

function isAnime(raw) {
    raw = raw || {};
    return text(raw.typeId1 != null ? raw.typeId1 : raw.type_id1) === '4';
}

function mapItem(raw) {
    raw = raw || {};
    var typeId = text(raw.typeId1 != null ? raw.typeId1 : raw.type_id1);
    return {
        id: text(raw.vodId != null ? raw.vodId : raw.id),
        name: clean(raw.vodName || raw.name),
        pic: trim(raw.vodPic || raw.pic),
        type: clean(raw.vodClass) || CATEGORY_NAMES[typeId] || '',
        year: text(raw.vodYear || raw.year).replace(/^null$/, ''),
        remarks: clean(raw.vodRemarks || raw.vodVersion || raw.remarks),
        desc: clean(raw.vodBlurb || raw.vodContent || raw.desc)
    };
}

function mapList(list, keyword) {
    var output = [];
    var needle = trim(keyword).toLowerCase();
    list = Array.isArray(list) ? list : [];
    for (var i = 0; i < list.length; i++) {
        var raw = list[i] || {};
        if (!isAllowed(raw) || (ANIME_ONLY && !isAnime(raw))) continue;
        var item = mapItem(raw);
        if (!item.id || !item.name) continue;
        if (needle && item.name.toLowerCase().indexOf(needle) < 0) continue;
        output.push(item);
    }
    return output;
}

function filterOptions(list, valueField) {
    var output = [{ n: '全部', v: '' }];
    list = Array.isArray(list) ? list : [];
    for (var i = 0; i < list.length; i++) {
        var name = clean(list[i].itemText);
        var value = trim(list[i][valueField]);
        if (name && value) output.push({ n: name, v: value });
    }
    return output;
}

function addFilter(output, key, name, list, valueField) {
    var values = filterOptions(list, valueField);
    if (values.length > 1) output.push({ key: key, name: name, value: values });
}

function filtersFor(categoryId, allFilters) {
    var data = allFilters && allFilters[categoryId] ? allFilters[categoryId] : {};
    var output = [];
    addFilter(output, 'type', '类型', data.typeList, 'itemValue');
    addFilter(output, 'v_class', '剧情', data.plotList, 'itemText');
    addFilter(output, 'area', '地区', data.districtList, 'itemText');
    addFilter(output, 'year', '年份', data.yearList, 'itemText');
    addFilter(output, 'lang', '语言', data.languageList, 'itemText');
    output.push({ key: 'sort', name: '排序', value: [
        { n: '默认', v: '1' },
        { n: '最近更新', v: '2' },
        { n: '人气最高', v: '3' },
        { n: '评分最高', v: '4' }
    ] });
    return output;
}

function fallbackCategories() {
    var ids = ANIME_ONLY ? ['4'] : ['1', '2', '3', '4', '88'];
    var output = [{ key: '', title: '推荐' }];
    for (var i = 0; i < ids.length; i++) {
        output.push({ key: ids[i], title: CATEGORY_NAMES[ids[i]], filters: filtersFor(ids[i], {}) });
    }
    return output;
}

function categories() {
    if (_categoriesCache) return _categoriesCache;
    var typesResult = api('/api/mw-movie/anonymous/get/filer/type', []);
    var filtersResult = api('/api/mw-movie/anonymous/v1/get/filer/list', []);
    var types = Array.isArray(typesResult.data) ? typesResult.data : [];
    var allFilters = filtersResult.data || {};
    var output = [{ key: '', title: '推荐' }];
    for (var i = 0; i < types.length; i++) {
        var id = text(types[i].typeId);
        var title = clean(types[i].typeName);
        if (!CATEGORY_NAMES.hasOwnProperty(id) || !title || (ANIME_ONLY && id !== '4')) continue;
        CATEGORY_NAMES[id] = title;
        output.push({ key: id, title: title, filters: filtersFor(id, allFilters) });
    }
    if (output.length === 1) output = fallbackCategories();
    if (ANIME_ONLY) {
        output.push({ key: '4:sort:3', title: '热播动漫' });
        output.push({ key: '4:sort:2', title: '更新动漫' });
        output.push({ key: '4:sort:4', title: '高分动漫' });
    }
    _categoriesCache = JSON.stringify(output);
    return _categoriesCache;
}

function categoryRequest(category, filters, page) {
    var selected = filters || {};
    var categoryId = trim(category) || (ANIME_ONLY ? '4' : '1');
    var parts = categoryId.split(':');
    categoryId = parts[0];
    if (parts.length >= 3 && !selected[parts[1]]) selected[parts[1]] = parts.slice(2).join(':');
    if (ANIME_ONLY) categoryId = '4';
    var pairs = [];
    if (trim(selected.area)) pairs.push(['area', trim(selected.area)]);
    pairs.push(['filterStatus', '1']);
    if (trim(selected.lang)) pairs.push(['lang', trim(selected.lang)]);
    pairs.push(['pageNum', String(parseInt(page, 10) || 1)]);
    pairs.push(['pageSize', '30']);
    pairs.push(['sort', trim(selected.sort) || '1']);
    pairs.push(['sortBy', '1']);
    if (trim(selected.type)) pairs.push(['type', trim(selected.type)]);
    pairs.push(['type1', categoryId]);
    if (trim(selected.v_class)) pairs.push(['v_class', trim(selected.v_class)]);
    if (trim(selected.year)) pairs.push(['year', trim(selected.year)]);
    var result = api('/api/mw-movie/anonymous/video/list', pairs);
    return mapList(result.data && result.data.list, '');
}

function uniqueItems(items, limit, seen) {
    var output = [];
    seen = seen || {};
    for (var i = 0; i < (items || []).length && output.length < limit; i++) {
        var item = items[i] || {};
        if (!item.id || seen[item.id]) continue;
        seen[item.id] = true;
        output.push(item);
    }
    return output;
}

function interleave(pools, limit) {
    var output = [];
    var seen = {};
    var index = 0;
    while (output.length < limit) {
        var added = false;
        for (var i = 0; i < pools.length && output.length < limit; i++) {
            var item = pools[i] && pools[i][index];
            if (!item || !item.id || seen[item.id]) continue;
            seen[item.id] = true;
            output.push(item);
            added = true;
        }
        if (!added) break;
        index++;
    }
    return output;
}

function addSection(output, title, key, items) {
    var cards = uniqueItems(items, 12, {});
    if (cards.length) output.push({ title: title, key: key, items: cards });
}

function homeSections() {
    if (_homeCache) return _homeCache;
    try {
        var output = [];
        var heroSeen = {};
        if (ANIME_ONLY) {
            var latest = categoryRequest('4', { sort: '1' }, 1);
            var updated = categoryRequest('4', { sort: '2' }, 1);
            var hottest = categoryRequest('4', { sort: '3' }, 1);
            var scored = categoryRequest('4', { sort: '4' }, 1);
            var hero = uniqueItems(interleave([hottest, latest], 24), 6, heroSeen);
            var hot = uniqueItems(hottest.concat(latest), 12, heroSeen);
            if (hero.length) output.push({ title: '轮播推荐', key: '__hero__', items: hero });
            if (hot.length) output.push({ title: '动漫热播', key: '4:sort:3', items: hot });
            addSection(output, '动漫新番', '4', latest);
            addSection(output, '最近更新', '4:sort:2', updated);
            addSection(output, '人气动漫', '4:sort:3', hottest);
            addSection(output, '高分动漫', '4:sort:4', scored);
        } else {
            var specs = [
                { id: '1', title: '电影热播' },
                { id: '2', title: '剧集热播' },
                { id: '3', title: '综艺热播' },
                { id: '4', title: '动漫热播' },
                { id: '88', title: '短剧热播' }
            ];
            var pools = [];
            for (var i = 0; i < specs.length; i++) pools.push(categoryRequest(specs[i].id, { sort: '3' }, 1));
            var hotResult = api('/api/mw-movie/anonymous/home/hotSearch', []);
            var recommendations = mapList(hotResult.data, '');
            var combined = recommendations.concat(interleave(pools, 60));
            var heroItems = uniqueItems(combined, 6, heroSeen);
            var hotItems = uniqueItems(combined, 12, heroSeen);
            if (heroItems.length) output.push({ title: '轮播推荐', key: '__hero__', items: heroItems });
            if (hotItems.length) output.push({ title: '热播推荐', key: '', items: hotItems });
            for (var s = 0; s < specs.length; s++) addSection(output, specs[s].title, specs[s].id, pools[s]);
        }
        _homeCache = JSON.stringify(output);
        return _homeCache;
    } catch (error) {
        logMessage('home failed: ' + error);
        return '[]';
    }
}

function search(keyword, page) {
    var key = trim(keyword);
    var currentPage = parseInt(page, 10) || 1;
    if (!key || /^(1|2|3|4|88)(:sort:[1-4])?$/.test(key)) {
        return JSON.stringify(categoryRequest(key || (ANIME_ONLY ? '4' : '1'), {}, currentPage));
    }
    var result = api('/api/mw-movie/anonymous/video/searchByWord', [
        ['keyword', key],
        ['pageNum', String(currentPage)],
        ['pageSize', '30'],
        ['sourceCode', '1']
    ]);
    var data = result.data || {};
    return JSON.stringify(mapList(data.result && data.result.list, key));
}

function searchFiltered(category, filtersJson, page) {
    return JSON.stringify(categoryRequest(category, json(filtersJson) || {}, page || 1));
}

function detail(id) {
    var key = trim(id).split('/')[0];
    if (_detailCache.hasOwnProperty(key)) return _detailCache[key];
    var empty = { id: key, name: '', pic: '', desc: '', type: '', remarks: '', year: '', episodes: [] };
    if (!key) return JSON.stringify(empty);
    var result = api('/api/mw-movie/anonymous/video/detail', [['id', key]]);
    var data = result.data || {};
    if (!isAllowed(data) || (ANIME_ONLY && !isAnime(data))) return JSON.stringify(empty);
    var output = mapItem(data);
    output.id = text(data.vodId || key);
    output.area = clean(data.vodArea);
    output.actor = clean(data.vodActor);
    output.director = clean(data.vodDirector);
    output.episodes = [];
    var episodes = Array.isArray(data.episodeList) ? data.episodeList : [];
    for (var i = 0; i < episodes.length; i++) {
        var nid = trim(episodes[i].nid);
        if (!nid) continue;
        var name = clean(episodes[i].name) || ('第' + (i + 1) + '集');
        if (/^\d$/.test(name)) name = '0' + name;
        output.episodes.push({ name: name, url: output.id + '-' + nid, route: '在线播放' });
    }
    var serialized = JSON.stringify(output);
    if (output.episodes.length) {
        _detailCache[key] = serialized;
        _detailOrder.push(key);
        if (_detailOrder.length > 80) delete _detailCache[_detailOrder.shift()];
    }
    return serialized;
}

function guessType(url) {
    var value = text(url).toLowerCase();
    if (value.indexOf('.m3u8') >= 0 || value.indexOf('m3u8') >= 0) return 'm3u8';
    if (value.indexOf('.mp4') >= 0) return 'mp4';
    if (value.indexOf('.flv') >= 0) return 'flv';
    return 'auto';
}

function play(flag) {
    var output = { url: '', type: 'auto' };
    var value = trim(flag);
    var splitAt = value.lastIndexOf('-');
    if (splitAt <= 0 || splitAt >= value.length - 1) return JSON.stringify(output);
    var videoId = value.substring(0, splitAt);
    var nid = value.substring(splitAt + 1);
    var result = api('/api/mw-movie/anonymous/v2/video/episode/url', [
        ['clientType', '1'],
        ['id', videoId],
        ['nid', nid]
    ]);
    var data = result.data || {};
    var list = Array.isArray(data.list) ? data.list : [];
    var url = list.length ? trim(list[0].url || list[0].playUrl) : trim(data.url || data.playUrl);
    if (!url) return JSON.stringify(output);
    var headers = { 'User-Agent': UA, 'Origin': PLAY_ORIGIN, 'Referer': PLAY_REFERER };
    output.url = url;
    output.type = guessType(url);
    output.header = headers;
    output.headers = JSON.stringify(headers);
    output.userAgent = UA;
    output.referer = PLAY_REFERER;
    return JSON.stringify(output);
}
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
