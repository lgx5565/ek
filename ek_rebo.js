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
/* 热播 - direct QuickJS source, adapter=rebo */
var SOURCE_TITLE='热播', KIND='rebo', TIMEOUT=30000;
var _home=null, _yiApp='', _yiToken='';
function t(v){return v==null?'':String(v);} function tr(v){return t(v).replace(/^\s+|\s+$/g,'');}
function clean(v){return tr(t(v).replace(/<br\s*\/?\s*>/gi,'\n').replace(/<[^>]+>/g,'').replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'"));}
function j(v){if(v&&typeof v==='object')return v;try{if(typeof parseJson==='function')return parseJson(t(v));}catch(e1){}try{return JSON.parse(t(v));}catch(e2){return null;}}
function resp(v){if(v==null)return'';if(typeof v==='string')return v;if(v.body!=null)return t(v.body);if(v.content!=null)return t(v.content);try{return JSON.stringify(v);}catch(e){return t(v);}}
function get(u,h){try{return resp(request(u,JSON.stringify({headers:h||{},timeout:TIMEOUT})));}catch(e){return'';}}
function postRaw(u,b,h){var o=JSON.stringify({headers:h||{},timeout:TIMEOUT});try{return resp(post(u,t(b),o));}catch(e){return'';}}
function enc(v){try{if(typeof encodeUri==='function')return t(encodeUri(t(v)));}catch(e1){}return encodeURIComponent(t(v));}
function dec(v){try{if(typeof decodeUri==='function')return t(decodeUri(t(v)));}catch(e1){}try{return decodeURIComponent(t(v));}catch(e2){return t(v);}}
function b64e(v){try{return t(base64Encode(t(v)));}catch(e1){}try{return t(crypto.base64.encode(t(v),{input:'utf8'}));}catch(e2){return'';}}
function b64d(v){try{return t(base64Decode(t(v)));}catch(e1){}try{return t(crypto.base64.decode(t(v),{output:'utf8'}));}catch(e2){return'';}}
function hash(name,v){try{if(name==='MD5'&&typeof md5==='function')return t(md5(t(v)));if(name==='SHA-1'&&typeof sha1==='function')return t(sha1(t(v)));if(name==='SHA-256'&&typeof sha256==='function')return t(sha256(t(v)));return t(crypto.hash(name,t(v),{input:'utf8',output:'hex'}));}catch(e){return'';}}
function form(o){var a=[];for(var k in o)if(Object.prototype.hasOwnProperty.call(o,k))a.push(enc(k)+'='+enc(o[k]));return a.join('&');}
function typeOf(u){u=t(u).toLowerCase();if(u.indexOf('.m3u8')>=0)return'm3u8';if(u.indexOf('.mp4')>=0)return'mp4';if(u.indexOf('.flv')>=0)return'flv';return'auto';}
function card(v){v=v||{};return{id:t(v.id!=null?v.id:(v.vod_id!=null?v.vod_id:v.vodId)),name:clean(v.name||v.vod_name||v.vodName||v.Name),pic:t(v.pic||v.vod_pic||v.vodPic||v.TnId),type:clean(v.type_name||v.vod_class||v.type),year:t(v.vod_year||v.year),remarks:clean(v.remarks||v.vod_remarks||v.vodRemarks||v.Tag),desc:clean(v.desc||v.vod_content||v.vod_blurb)};}
function cards(a){a=Array.isArray(a)?a:[];var o=[];for(var i=0;i<a.length;i++){var c=card(a[i]);if(c.id&&c.name)o.push(c);}return o;}
function opts(raw){var a=[{n:'全部',v:''}],p=t(raw).split(',');for(var i=0;i<p.length;i++){var x=tr(p[i]);if(x)a.push({n:x,v:x});}return a;}

/* 独播库 */
var DB_HOST='https://api.dbokutv.com', DB_H={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36','Referer':'https://www.duboku.tv/','Connection':'Keep-Alive'};
function dbDecode(v){v=tr(v).replace(/\./g,'=');var s='';for(var i=0;i<v.length;i+=10)s+=v.substring(i,i+10).split('').reverse().join('');return b64d(s);}
function rnd(n){var c='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',s='';while(s.length<n)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}
function dbQuery(){var now=Date.now(),r=Math.floor(Math.random()*800000001),a=t(100000000+r)+t(900000000-r),b=t(now),s='',n=Math.min(a.length,b.length);for(var i=0;i<n;i++)s+=a.charAt(i)+b.charAt(i);s+=a.substring(n)+b.substring(n);return'?sign='+rnd(60)+'&ssid='+b64e(s).replace(/=/g,'.')+'&token='+rnd(38);}
function dbItems(a){var out=[];a=Array.isArray(a)?a:[];for(var i=0;i<a.length;i++){var x=a[i]||{},c=card({id:dbDecode(x.DId),name:x.Name,pic:dbDecode(x.TnId),remarks:x.Tag||(x.Rating!=null?x.Rating+'分':'')});if(c.id&&c.name)out.push(c);}return out;}
function dbHome(){var root=j(get(DB_HOST+'/home'+dbQuery(),DB_H))||[],out=[];for(var i=0;i<root.length;i++)out=out.concat(dbItems((root[i]||{}).VodList));return out;}
function dbSearch(q){return dbItems(j(get(DB_HOST+'/vodsearch'+dbQuery()+'&wd='+enc(q),DB_H))||[]);}
function dbCategory(id,page,f){f=f||{};var u='/vodshow/'+id+'-'+t(f.area||'')+'-'+t(f.by||'')+'-'+t(f['class']||'')+'-'+t(f.lang||'')+'----'+page+'---'+t(f.year||'');return dbItems((j(get(DB_HOST+u+dbQuery(),DB_H))||{}).VodList);}
function dbDetail(id){var x=j(get(DB_HOST+id+dbQuery(),DB_H))||{},eps=[],pl=x.Playlist||[];for(var i=0;i<pl.length;i++){var p=pl[i]||{};eps.push({name:clean(p.EpisodeName)||('第'+(i+1)+'集'),route:'独播库',url:dbDecode(p.VId)});}return{id:id,name:clean(x.Name),pic:dbDecode(x.TnId),desc:clean(x.Description),year:t(x.ReleaseYear),actor:Array.isArray(x.Actor)?x.Actor.join(','):'',director:clean(x.Director),episodes:eps};}
function dbPlay(f){var x=j(get(DB_HOST+f+dbQuery(),DB_H))||{},u=dbDecode(x.HId);return{url:u,type:typeOf(u),headers:{'User-Agent':DB_H['User-Agent'],'Origin':'https://w.duboku.io','Referer':'https://w.duboku.io/'}};}

/* 热播 */
var RB='http://v.rbotv.cn', RB_H={'User-Agent':'okhttp-okgo/jeasonlzy','Content-Type':'application/x-www-form-urlencoded'};
function rbParams(v){v=v||{};var ts=t(Math.floor(Date.now()/1000));v.sign=hash('MD5','7gp0bnd2sr85ydii2j32pcypscoc4w6c7g5spl'+ts);v.timestamp=ts;return v;}
function rbCall(path,v){return j(postRaw(RB+path,form(rbParams(v)),RB_H))||{};}
function rbList(root){var a=((root.data||{}).list)||[],out=[];for(var i=0;i<a.length;i++)out.push(card(a[i]));return cards(out);}
function rbDetail(id){var x=(rbCall('/v3/home/vod_details',{vod_id:id}).data)||{},eps=[],lines=x.vod_play_list||[];for(var i=0;i<lines.length;i++){var l=lines[i]||{},pa=(l.parse_urls||[])[0]||'',es=l.urls||[];for(var k=0;k<es.length;k++){var e=es[k]||{},u=t(e.url);if(pa)u=pa+enc(u);eps.push({name:clean(e.name)||('第'+(k+1)+'集'),route:clean(l.title)||('线路'+(i+1)),url:u});}}return{id:id,name:clean(x.vod_name),pic:t(x.vod_pic),desc:clean(x.vod_content),year:t(x.vod_year),area:clean(x.vod_area),type:clean(x.vod_class),actor:clean(x.vod_actor),director:clean(x.vod_director),episodes:eps};}
function rbPlay(f){if(f.indexOf('=')<0)return{url:f,type:typeOf(f),headers:{'User-Agent':'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/118.0 Mobile Safari/537.36'}};var x=j(get(f,{'User-Agent':'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/118.0 Mobile Safari/537.36'}))||{},u=t(x.url);if(!u){var m=f.match(/[?&]url=([^&]+)/);u=m?dec(m[1]):f;}return{url:u,type:typeOf(u)};}

/* 文才 */
var WC='https://www.hkybqufgh.com',WC_KEY='cb808529bae6b6be45ecfab29a4889bc',WC_H={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36','Referer':'https://www.hkybqufgh.com'};
function wcHeaders(raw){var ts=t(Date.now()),h={};for(var k in WC_H)h[k]=WC_H[k];h.t=ts;h.sign=hash('SHA-1',hash('MD5',raw+'&key='+WC_KEY+'&t='+ts));return h;}
function wcGet(path,raw){return j(get(WC+path,wcHeaders(raw)))||{};}
function wcCards(a){a=Array.isArray(a)?a:[];var out=[];for(var i=0;i<a.length;i++)out.push(card(a[i]));return cards(out);}
function wcSearch(q,p){var raw='keyword='+q+'&pageNum='+p+'&pageSize=8',x=wcGet('/api/mw-movie/anonymous/video/searchByWord?keyword='+enc(q)+'&pageNum='+p+'&pageSize=8',raw);return wcCards((((x.data||{}).result)||{}).list);}
function wcCategory(id,p,f){f=f||{};var raw='area='+t(f.area||'')+'&filterStatus=1&lang='+t(f.lang||'')+'&pageNum='+p+'&pageSize=30&sort='+t(f.sort||'1')+'&sortBy=1&type='+t(f.type||'')+'&type1='+id+'&v_class='+t(f.v_class||'')+'&year='+t(f.year||'');return wcCards(((wcGet('/api/mw-movie/anonymous/video/list?'+raw,raw).data)||{}).list);}
function wcHome(){var x=wcGet('/api/mw-movie/anonymous/home/hotSearch',''),a=x.data||[];return wcCards(a);}
function wcDetail(id){var x=(wcGet('/api/mw-movie/anonymous/video/detail?id='+enc(id),'id='+id).data)||{},eps=[],a=x.episodeList||[];for(var i=0;i<a.length;i++)eps.push({name:clean(a[i].name)||('第'+(i+1)+'集'),route:'文才',url:t(a[i].nid)+'|||'+id+'|||'+t(a[i].name)});return{id:id,name:clean(x.vodName),pic:t(x.vodPic),desc:clean(x.vodContent),year:t(x.vodYear),area:clean(x.vodArea),actor:clean(x.vodActor),director:clean(x.vodDirector),episodes:eps};}
function wcPlay(f){var a=t(f).split('|||'),raw='clientType=1&id='+a[1]+'&nid='+a[0],x=wcGet('/api/mw-movie/anonymous/v2/video/episode/url?'+raw,raw),ls=((x.data||{}).list)||[],u=ls.length?t(ls[0].url):'';return{url:u,type:typeOf(u),headers:{'User-Agent':WC_H['User-Agent'],'Referer':WC}};}

/* 伊影 */
var YI='https://aleig4ah.yiys05.com/vod-app',YI_PEM='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4qpeOgv+MeXi57MVPqZ\nF7SRmHR3FUelCTfrvI6vZ8kgTPpe1gMyP/8ZTvedTYjTDMqZBmn8o8Ym98yTx3zH\naskPpmDR80e+rcRciPoYZcWNpwpFkrHp1l6Pjs9xHLXzf3U+N3a8QneY+jSMvgMb\nr00DC4XfvamfrkPMXQ+x9t3gNcP5YtuRhGFREBKP2q20gP783MCOBFwyxhZTIAsF\niXrLkgZ97uaUAtqW6wtKR4HWpeaN+RLLxhBdnVjuMc9jaBl6sHMdSvTJgAajBTAd\n6LLA9cDmbGTxH7RGp//iZU86kFhxGl5yssZvBcx/K95ADeTmLKCsabexZVZ0Fu3d\nDQIDAQAB\n-----END PUBLIC KEY-----';
function yiInit(){if(_yiToken)return;_yiApp='';while(_yiApp.length<16)_yiApp+=Math.floor(Math.random()*16).toString(16);var ts=t(Math.floor(Date.now()/1000)),h={'User-Agent':'Android/OkHttp','APP-ID':_yiApp,'X-Auth-Flow':'1','Authorization':''},x=j(postRaw(YI+'/index/getGenerateKey',form({appID:_yiApp,timestamp:ts}),h))||{},cipher=t(x.data);var plain='';try{plain=t(crypto.rsa.decrypt(cipher,YI_PEM,{padding:'PKCS1',input:'base64',output:'utf8'}));}catch(e){}if(!plain)throw Error('伊影 token解密失败');_yiToken='&token='+plain;}
function yiCall(path,p){yiInit();var raw=[],k;for(k in p)if(Object.prototype.hasOwnProperty.call(p,k))raw.push(k+'='+t(p[k]));var sig=hash('SHA-256',raw.join('&')+_yiToken),h={'User-Agent':'Android/OkHttp','APP-ID':_yiApp,'X-HASH-Data':sig,'Authorization':''};return j(postRaw(YI+path,form(p),h))||{};}
function yiCards(a){a=Array.isArray(a)?a:[];var out=[];for(var i=0;i<a.length;i++)out.push(card({id:a[i].id,name:a[i].name,pic:a[i].vodPic,remarks:a[i].vodRemarks}));return cards(out);}
function yiSearch(q,p){var ts=t(Math.floor(Date.now()/1000)),x=yiCall('/vod/segSearch',{key:q,limit:'20',page:t(p),timestamp:ts});return yiCards(((x.data||{}).data)||[]);}
function yiCategory(id,p,f){f=f||{};var q={},ts=t(Math.floor(Date.now()/1000));if(f.area)q.area=f.area;q.by='time';if(f['class'])q['class']=f['class'];if(f.lang)q.lang=f.lang;q.limit='90';q.page=t(p);q.tid=t(id);q.timestamp=ts;if(f.year)q.year=f.year;var x=yiCall('/vod/list',q);return yiCards(((x.data||{}).data)||[]);}
function yiNav(){yiInit();var ts=t(Math.floor(Date.now()/1000)),raw='timestamp='+ts,h={'User-Agent':'Android/OkHttp','APP-ID':_yiApp,'X-HASH-Data':hash('SHA-256',raw+_yiToken),'Authorization':''},x=j(get(YI+'/type/list?'+raw,h))||{};return x.data||[];}
function yiDetail(id){var ts=t(Math.floor(Date.now()/1000)),x=yiCall('/vod/info',{tid:'',timestamp:ts,vodId:id}).data||{},eps=[],ss=x.vodSources||[];for(var i=0;i<ss.length;i++){var s=ss[i]||{},a=((s.vodPlayList||{}).urls)||[];for(var k=0;k<a.length;k++)eps.push({name:clean(a[k].name)||('第'+(k+1)+'集'),route:clean(s.sourceName)||('线路'+(i+1)),url:t(s.sourceCode)+'|||'+enc(a[k].url)});}return{id:id,name:clean(x.vodName),pic:t(x.vodPic),desc:clean(x.vodContent),year:t(x.vodYear),area:clean(x.vodArea),type:clean(x.vodClass),actor:clean(x.vodActor),episodes:eps};}
function yiPlay(f){var a=t(f).split('|||'),raw=dec(a.slice(1).join('|||'));if(raw.indexOf('http')>=0)return{url:raw,type:typeOf(raw),headers:{'User-Agent':'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/116.0 Mobile Safari/537.36'}};var ts=t(Math.floor(Date.now()/1000)),x=yiCall('/vod/playUrl',{sourceCode:a[0],timestamp:ts,urlEncode:a.slice(1).join('|||')}),u=t((x.data||{}).url);return{url:u,type:typeOf(u)};}

/* 梨园戏曲 */
var LY='http://103.36.222.35:9595/wexfnwshinidie/liyuan',LY_H={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36'};
function two(v){return v<10?'0'+v:t(v);} function dayKey(){var d=new Date();return d.getFullYear()+two(d.getMonth()+1)+two(d.getDate())+'woshini8';}
function lyCall(path){var raw=get(LY+path,LY_H),plain='';try{plain=t(crypto.aes.decrypt(raw,dayKey(),{mode:'CBC',padding:'PKCS7',keyFormat:'utf8',iv:'Wexfnwshinidieha',ivFormat:'utf8',input:'base64',output:'utf8'}));}catch(e){}return j(plain)||{};}
function lyCards(a,picKey){a=Array.isArray(a)?a:[];var out=[];for(var i=0;i<a.length;i++){var x=a[i]||{};out.push(card({id:x.code,name:x.name,pic:'http://ottphoto.daoran.tv/HD/'+t(x[picKey||'img'])}));}return cards(out);}
function lyCategory(id,p,f){f=f||{};var kind=t(f['class']||'jingju'),x;if(t(id)==='2'){x=lyCall('/namelist.php?type='+enc(kind)+'&pg='+p);return lyCards(((x.pb||{}).dataList)||[],'image');}if(t(id)==='1'){x=lyCall('/vodlist.php?type='+enc(kind)+'&pg='+p);return lyCards(((x.pb||{}).dataList)||[],'img');}x=lyCall('/nameidlist.php?nameid='+enc(id)+'&pg='+p);return lyCards(((x.pb||{}).dataList)||[],'img');}
function lySearch(q,p){var x=lyCall('/so.php?key='+enc(q)+'&pg='+p);return lyCards(((x.pb||{}).dataList)||[],'img');}
function lyDetail(id){var x=lyCall('/detail.php?vodid='+enc(id)),a=x.album||{},ls=((x.pb||{}).dataList)||[],eps=[];for(var i=0;i<ls.length;i++)eps.push({name:clean(ls[i].name)||('第'+(i+1)+'集'),route:'梨园',url:t(ls[i].code)});return{id:id,name:clean(a.name),pic:'http://ottphoto.daoran.tv/HD/'+t(a.img),desc:clean(a.des),actor:clean(a.artistName),episodes:eps};}
function lyPlay(f){var x=lyCall('/play.php?vodid='+enc(f)),u=t((x.playres||{}).playurl);return{url:u,type:typeOf(u),headers:LY_H};}

function config(){return JSON.stringify({kind:'video',browseOnly:false,source:SOURCE_TITLE});}
function categories(){try{var out=[{key:'',title:'推荐'}],a=[];if(KIND==='duboku')a=[['1','电影'],['2','电视剧'],['3','综艺'],['4','动漫'],['21','短剧'],['20','港剧']];else if(KIND==='wencai')a=[['1','电影'],['2','电视剧'],['3','综艺'],['4','动漫']];else if(KIND==='rebo'){var x=rbCall('/v3/type/top_type',{'':''});a=(x.data||{}).list||[];}else if(KIND==='yiying'){yiInit();a=yiNav();}
    else if(KIND==='liyuan')a=[['1','戏曲大全'],['2','名家大腕']];for(var i=0;i<a.length;i++){var x=a[i],id=t(Array.isArray(x)?x[0]:(x.type_id||x.typeId)),name=clean(Array.isArray(x)?x[1]:(x.type_name||x.typeName));if(id&&name){var it={key:id,title:name};if(KIND==='liyuan')it.filters=[{key:'class',name:'剧种',value:[{n:'京剧',v:'jingju'},{n:'豫剧',v:'yuju'},{n:'越剧',v:'yueju'},{n:'黄梅戏',v:'hmx'},{n:'相声',v:'xiang'},{n:'评书',v:'pingshu'}]}];out.push(it);}}return JSON.stringify(out);}catch(e){return JSON.stringify([{key:'',title:'推荐'}]);}}
function search(q,p){try{q=tr(q);p=Math.max(1,Number(p)||1);if(KIND==='duboku')return JSON.stringify(q?dbSearch(q):dbHome());if(KIND==='rebo')return JSON.stringify(q?rbList(rbCall('/v3/home/search',{keyword:q})):rbList(rbCall('/v3/home/type_search',{area:'',year:'',type_id:'1',page:t(p),lang:'','class':''})));if(KIND==='wencai')return JSON.stringify(q?wcSearch(q,p):wcHome());if(KIND==='yiying')return JSON.stringify(q?yiSearch(q,p):yiCategory('1',p,{}));if(KIND==='liyuan')return JSON.stringify(q?lySearch(q,p):lyCategory('1',p,{}));}catch(e){}return'[]';}
function searchFiltered(c,f,p){try{f=j(f)||{};if(KIND==='duboku')return JSON.stringify(dbCategory(c,p,f));if(KIND==='rebo')return JSON.stringify(rbList(rbCall('/v3/home/type_search',{area:t(f.area),year:t(f.year),type_id:t(c),page:t(p),lang:t(f.lang),'class':t(f['class'])})));if(KIND==='wencai')return JSON.stringify(wcCategory(c,p,f));if(KIND==='yiying')return JSON.stringify(yiCategory(c,p,f));if(KIND==='liyuan')return JSON.stringify(lyCategory(c,p,f));}catch(e){}return'[]';}
function detail(id){try{if(KIND==='duboku')return JSON.stringify(dbDetail(t(id)));if(KIND==='rebo')return JSON.stringify(rbDetail(t(id)));if(KIND==='wencai')return JSON.stringify(wcDetail(t(id)));if(KIND==='yiying')return JSON.stringify(yiDetail(t(id)));if(KIND==='liyuan')return JSON.stringify(lyDetail(t(id)));}catch(e){}return JSON.stringify({id:t(id),name:'',pic:'',desc:'',episodes:[]});}
function play(f){try{var x=KIND==='duboku'?dbPlay(f):KIND==='rebo'?rbPlay(f):KIND==='wencai'?wcPlay(f):KIND==='yiying'?yiPlay(f):KIND==='liyuan'?lyPlay(f):{url:''};return JSON.stringify(x);}catch(e){return JSON.stringify({url:'',type:'auto'});}}
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
