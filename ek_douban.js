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
/*
 * 豆瓣 · 影视索引 JS 源（config().browseOnly = true：首页逛片 / 看评分找片，点卡片跳 App 搜索页跨源找可播源；
 *   不参与多源搜索，detail/play 仅兜底、不提供地址）
 * 数据：豆瓣 explore 页同款 rexxar recommend 接口（无需 apikey，带浏览器 UA + Referer）
 *   https://m.douban.com/rexxar/api/v2/{movie|tv}/recommend?tags=喜剧,韩国,2024&sort=U|R|S&start=&count=
 *   tags 可自由叠加（实测 2026-09-07）：形式(电视剧/综艺/纪录片/动画) + 题材 + 地区 + 年代；单组合上限约 500 条。
 *   接口在响应 recommend_categories 里自报支持的「类型 / 地区」全部取值，下面的选项表按它抄，不是拍脑袋写的。
 *
 * 2026-09-07 优化：
 *   · 分类筛选加「地区」维度（华语 / 大陆 / 港 / 台 / 韩 / 日 / 泰 / 印 / 欧美 / 美 / 英 / 法 / 德 / 意 / 西 / 俄 / 加 / 澳，剧集多一个「国外」）；
 *   · 题材按 tab 分表：电影用豆瓣电影类型全表，剧集加古装 / 武侠 / 都市 / 家庭，综艺用真人秀 / 脱口秀 / 选秀…，
 *     纪录片用历史 / 自然 / 社会 / 人物…，动画用热血 / 恋爱 / 校园 / 治愈…（原来五个 tab 共用一张电影类型表，
 *     在综艺 / 纪录片 tab 里点「惊悚 / 西部」基本是空的）；
 *   · 「电视剧」tab 加 tags=电视剧，不再把综艺混进剧集列表（接口的「类型」控件对 tv 端只有 电视剧 / 综艺 两档）；
 *   · 年代补 70 年代 / 60 年代 / 更早；
 *   · 带筛选时 rexxar 返空**不再回退**老接口 search_subjects：老接口只认一个 tag，回退给出的是一堆不相干的「热门」，
 *     用户选了「泰国 + 喜剧」看到的却是无关热门片。只有无筛选的第 1 页返空（接口真挂了）才回退。
 * ext 可选：{ "ua": "自定义 UA" }
 */
var EXT = (typeof ext !== 'undefined' && ext) ? ext : {};
var REX_API = 'https://m.douban.com/rexxar/api/v2/';
var OLD_API = 'https://movie.douban.com/j/search_subjects';
var UA = String(EXT.ua || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
var PAGE = 20;
var TAB_MOVIE = '电影';
var TAB_TV = '电视剧';
var TAB_VARIETY = '综艺';
var TAB_DOCUMENTARY = '纪录片';
var TAB_ANIME = '动画';

// ── 筛选取值表（均为 rexxar tags 直接可叠的豆瓣标签）──
// 题材：按 tab 分表，见文件头
var GENRES_MOVIE = ['喜剧', '爱情', '动作', '科幻', '动画', '悬疑', '犯罪', '惊悚', '冒险', '奇幻', '恐怖', '战争', '历史', '传记', '音乐', '歌舞', '武侠', '灾难', '西部', '纪录片', '短片'];
var GENRES_TV = ['剧情', '喜剧', '爱情', '悬疑', '犯罪', '惊悚', '科幻', '奇幻', '动作', '冒险', '古装', '武侠', '都市', '家庭', '历史', '战争', '恐怖', '传记'];
var GENRES_VARIETY = ['真人秀', '脱口秀', '选秀', '音乐', '旅行', '喜剧'];
var GENRES_DOCUMENTARY = ['历史', '自然', '社会', '人物', '战争', '音乐', '传记', '犯罪'];
var GENRES_ANIME = ['热血', '冒险', '奇幻', '科幻', '搞笑', '恋爱', '校园', '治愈', '悬疑', '推理', '日常', '运动', '机战', '催泪'];
// 地区：接口 recommend_categories「地区」自报的取值，按国内用户常点的顺序排；tv 端多一个「国外」（= 非华语全体）
var REGIONS_MOVIE = ['华语', '中国大陆', '中国香港', '中国台湾', '韩国', '日本', '泰国', '印度', '欧美', '美国', '英国', '法国', '德国', '意大利', '西班牙', '俄罗斯', '加拿大', '澳大利亚'];
var REGIONS_TV = ['华语', '中国大陆', '中国香港', '中国台湾', '国外', '韩国', '日本', '泰国', '印度', '欧美', '美国', '英国', '法国', '德国', '意大利', '西班牙', '俄罗斯', '加拿大', '澳大利亚'];

function dbLog(value) {
    try { if (typeof log === 'function') log(String(value)); } catch (e) {}
}

function trim(s) { return s == null ? '' : String(s).replace(/^\s+|\s+$/g, ''); }

function reqOpt() {
    return JSON.stringify({
        timeout: 12000,
        // rexxar 校验 douban 域 Referer（explore 页面地址实测通过）
        headers: { 'User-Agent': UA, 'Referer': 'https://movie.douban.com/explore', 'Accept': 'application/json' }
    });
}

// tab key → rexxar 端点(kind) + 基础 tags + 本 tab 的题材 / 地区表
function rexParams(key) {
    if (key === TAB_MOVIE) return { kind: 'movie', base: [], genres: GENRES_MOVIE, regions: REGIONS_MOVIE };
    if (key === TAB_TV) return { kind: 'tv', base: ['电视剧'], genres: GENRES_TV, regions: REGIONS_TV };
    if (key === TAB_VARIETY) return { kind: 'tv', base: ['综艺'], genres: GENRES_VARIETY, regions: REGIONS_TV };
    if (key === TAB_DOCUMENTARY) return { kind: 'movie', base: ['纪录片'], genres: GENRES_DOCUMENTARY, regions: REGIONS_MOVIE };
    if (key === TAB_ANIME) return { kind: 'tv', base: ['动画'], genres: GENRES_ANIME, regions: REGIONS_TV };
    // 推荐 = 电影端全体，近期热度排序即当下热门
    return { kind: 'movie', base: [], genres: GENRES_MOVIE, regions: REGIONS_MOVIE };
}

// tab key → 兜底老接口 search_subjects 的 type + tag（只认单 tag，不认题材 / 地区 / 年代）
function oldParams(key) {
    if (key === TAB_MOVIE) return { type: 'movie', tag: '热门' };
    if (key === TAB_TV) return { type: 'tv', tag: '热门' };
    if (key === TAB_VARIETY) return { type: 'tv', tag: '综艺' };
    if (key === TAB_DOCUMENTARY) return { type: 'movie', tag: '纪录片' };
    if (key === TAB_ANIME) return { type: 'tv', tag: '动画' };
    return { type: 'movie', tag: '热门' };
}

// sort：U=近期热度 R=首映/首播时间 S=高分优先（接口还有 T=综合排序，但 T 是混排信息流、不分页，不给用）
function sortRex(v) { return v === 'new' ? 'R' : (v === 'score' ? 'S' : 'U'); }
function sortOld(v) { return v === 'new' ? 'time' : (v === 'score' ? 'rank' : 'recommend'); }

function cardType(key, kind) {
    if (key === TAB_MOVIE || key === TAB_DOCUMENTARY) return key;
    if (key === TAB_VARIETY) return TAB_VARIETY;
    if (key === TAB_ANIME) return TAB_ANIME;
    if (key === TAB_TV) return TAB_TV;
    return kind === 'tv' ? TAB_TV : TAB_MOVIE;
}

// rexxar item → 卡片（自带 year / 评分 / 副标题「年份 / 地区 / 类型 / 导演 / 主演」）
function mapRexCard(s, tabType) {
    if (!s || s.id == null) return null;
    // recommend 流里会插「豆瓣榜单 / 片单 / 广告」卡（id 形如 film_genre_31、type=playlist/ad），
    // 不是影片、点了也搜不到——按「影片 id 必为纯数字 + type 白名单」双重过滤掉
    var id = String(s.id);
    if (!/^\d+$/.test(id)) return null;
    if (s.type && s.type !== 'movie' && s.type !== 'tv') return null;
    var name = trim(s.title);
    if (!name) return null;
    var pic = s.pic || {};
    var rate = (s.rating && s.rating.value) ? String(s.rating.value) : '';
    return {
        id: id,
        name: name,
        pic: trim(pic.large || pic.normal || ''),
        type: tabType,
        year: trim(s.year),
        remarks: rate ? (rate + '分') : '',
        desc: trim(s.card_subtitle)
    };
}

// 老接口 item → 卡片
function mapOldCard(s, tabType) {
    if (!s || s.id == null) return null;
    var name = trim(s.title);
    if (!name) return null;
    var rate = trim(s.rate);
    var eps = trim(s.episodes_info);
    return {
        id: String(s.id),
        name: name,
        pic: trim(s.cover),
        type: tabType,
        year: '',
        remarks: rate ? (rate + '分') : eps,
        desc: ''
    };
}

// ① 主力：rexxar recommend（tags 叠加 形式 / 题材 / 地区 / 年代，真实筛选）
function fetchRex(kind, tags, sortV, page, tabType) {
    page = parseInt(page, 10) || 1;
    var start = (page - 1) * PAGE;
    var url = REX_API + kind + '/recommend?refresh=0&start=' + start + '&count=' + PAGE + '&tags=' + encodeUri(tags.join(',')) + '&sort=' + sortRex(sortV);
    var j = parseJson(request(url, reqOpt())) || {};
    var arr = j.items || [];
    dbLog('[douban] rexxar ' + arr.length + '条(total=' + (j.total == null ? '?' : j.total) + '): ' + url);
    var out = [];
    for (var i = 0; i < arr.length; i++) {
        var item = mapRexCard(arr[i], tabType);
        if (item) out.push(item);
    }
    return out;
}

// ② 兜底：老接口（tag 单值，无题材 / 地区 / 年代）
function fetchOld(type, tag, sortV, page, tabType) {
    page = parseInt(page, 10) || 1;
    var start = (page - 1) * PAGE;
    var url = OLD_API + '?type=' + type + '&tag=' + encodeUri(tag) + '&sort=' + sortOld(sortV) + '&page_limit=' + PAGE + '&page_start=' + start;
    var j = parseJson(request(url, reqOpt())) || {};
    var arr = j.subjects || [];
    var out = [];
    for (var i = 0; i < arr.length; i++) {
        var item = mapOldCard(arr[i], tabType);
        if (item) out.push(item);
    }
    return out;
}

/**
 * 分类取数统一入口。f = { genre, region, year, sort }（都可为空串）。
 * rexxar 主力；只有「无任何筛选 + 第 1 页」返空（接口真挂了）才回退老接口——带筛选时返空就是真没有
 *（老接口不认筛选，回退只会塞一堆不相干的热门片进来）；翻页返空如实返回「没有更多」。
 */
function fetchTab(key, f, page) {
    f = f || {};
    var genre = trim(f.genre), region = trim(f.region), year = trim(f.year);
    var sortV = trim(f.sort) || 'hot';
    var p = rexParams(key);
    var tags = p.base.slice();
    if (genre) tags.push(genre);
    if (region) tags.push(region);
    if (year) tags.push(year);
    var type = cardType(key, p.kind);
    var r = [];
    try { r = fetchRex(p.kind, tags, sortV, page, type); } catch (e) { dbLog('[douban] rexxar error: ' + e); }
    if (r.length || page > 1) return r;
    if (genre || region || year) return r;
    dbLog('[douban] rexxar 空，回退老接口');
    try {
        var o = oldParams(key);
        return fetchOld(o.type, o.tag, sortV, page, type);
    } catch (e2) {
        dbLog('[douban] old api error: ' + e2);
        return [];
    }
}

function optsOf(list) {
    var out = [{ n: '全部', v: '' }];
    for (var i = 0; i < list.length; i++) out.push({ n: list[i], v: list[i] });
    return out;
}

function yearOpts() {
    var out = [{ n: '全部', v: '' }];
    var y = (new Date()).getFullYear();
    // 逐年近 8 年 + 年代段（explore 年代标签体系，「更早」= 60 年代以前）
    for (var i = 0; i < 8; i++) out.push({ n: String(y - i), v: String(y - i) });
    var decades = ['2010年代', '2000年代', '90年代', '80年代', '70年代', '60年代', '更早'];
    for (var d = 0; d < decades.length; d++) out.push({ n: decades[d], v: decades[d] });
    return out;
}

function sortOpts() {
    return [{ n: '热度', v: 'hot' }, { n: '最新', v: 'new' }, { n: '评分', v: 'score' }];
}

// name 全部留空 = 不渲染「题材 / 地区 / 年代 / 排序」前缀文字（用户 2026-08-13 要求），胶囊直接从行首排
function filtersFor(key) {
    var p = rexParams(key);
    return [
        { key: 'genre', name: '', value: optsOf(p.genres) },
        { key: 'region', name: '', value: optsOf(p.regions) },
        { key: 'year', name: '', value: yearOpts() },
        { key: 'sort', name: '', value: sortOpts() }
    ];
}

// ─────────────────────────────────────────────── Ekanpro 契约

function config() {
    return JSON.stringify({ browseOnly: true });
}

function categories() {
    return JSON.stringify([
        { key: '', title: '推荐', filters: filtersFor('') },
        { key: TAB_MOVIE, title: '电影', filters: filtersFor(TAB_MOVIE) },
        { key: TAB_TV, title: '电视剧', filters: filtersFor(TAB_TV) },
        { key: TAB_VARIETY, title: '综艺', filters: filtersFor(TAB_VARIETY) },
        { key: TAB_DOCUMENTARY, title: '纪录片', filters: filtersFor(TAB_DOCUMENTARY) },
        { key: TAB_ANIME, title: '动画', filters: filtersFor(TAB_ANIME) }
    ]);
}

function homeSections() {
    var out = [];
    var hero = [];
    try { hero = fetchTab('', null, 1).slice(0, 6); } catch (e) {}
    if (hero.length) out.push({ title: '轮播推荐', key: '__hero__', items: hero });
    var specs = [
        { key: TAB_MOVIE, title: '热播电影' },
        { key: TAB_TV, title: '热播剧集' },
        { key: TAB_VARIETY, title: '热门综艺' },
        { key: TAB_DOCUMENTARY, title: '热门纪录片' },
        { key: TAB_ANIME, title: '热门动画' }
    ];
    for (var i = 0; i < specs.length; i++) {
        try {
            var items = fetchTab(specs[i].key, null, 1).slice(0, 12);
            if (items.length) out.push({ title: specs[i].title, key: specs[i].key, items: items });
        } catch (e2) {}
    }
    return JSON.stringify(out);
}

function mergeCards(a, b) {
    var out = [], seen = {};
    var all = (a || []).concat(b || []);
    for (var i = 0; i < all.length; i++) {
        var item = all[i];
        if (!item || !item.id || seen[item.id]) continue;
        seen[item.id] = true;
        out.push(item);
    }
    return out;
}

function search(keyword, page) {
    page = parseInt(page, 10) || 1;
    var key = trim(keyword);
    if (key === '' || key === TAB_MOVIE || key === TAB_TV || key === TAB_VARIETY || key === TAB_DOCUMENTARY || key === TAB_ANIME) {
        return JSON.stringify(fetchTab(key, null, page));
    }
    // 真实关键词：老接口按 tag 尽力找（browseOnly 点卡跳 App 搜索，这条很少走）
    if (page > 1) return JSON.stringify([]);
    var movie = [], tv = [];
    try { movie = fetchOld('movie', key, 'hot', 1, TAB_MOVIE); } catch (e) {}
    try { tv = fetchOld('tv', key, 'hot', 1, TAB_TV); } catch (e2) {}
    return JSON.stringify(mergeCards(movie, tv));
}

function searchFiltered(category, filtersJson, page) {
    var f = parseJson(filtersJson) || {};
    return JSON.stringify(fetchTab(trim(category), f, parseInt(page, 10) || 1));
}

// browseOnly=true 时不会被调用；保留兜底，不提供片源。
function detail(id) {
    return JSON.stringify({ id: id, name: '', pic: '', desc: '', type: '', remarks: '', year: '', episodes: [] });
}

function play(flag) {
    dbLog('[douban] browse-only, no play: ' + flag);
    return JSON.stringify({ url: '', type: 'auto' });
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
