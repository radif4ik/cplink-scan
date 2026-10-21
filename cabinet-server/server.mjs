import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import http from 'node:http';
import {randomBytes,createHash} from 'node:crypto';
import {brotliCompressSync,gzipSync,constants as zlibConstants} from 'node:zlib';
import worker from './cabinet-worker.mjs';
import {createBridge,createAttendanceAPI} from './bridge.mjs';
import {createBrowserAuth} from './browser-auth.mjs';

const port=Number(process.env.PORT||8080);
if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid port');
const origins=(process.env.PUBLIC_ORIGINS||'').split(',').filter(Boolean).map(value=>{
  const url=new URL(value.trim());
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/')throw Error('Expected HTTPS public origin');
  return url.origin;
});
if(!origins.length)throw Error('Set PUBLIC_ORIGINS before starting the cabinet');
const env=Object.fromEntries(['PRODUCTION_API_KEY','TG_WEBAPP_SECRET','CABINET_SIGNING_KEY'].map(key=>{
  const value=process.env[key];if(!value&&!(key==='PRODUCTION_API_KEY'&&process.env.PRODUCTION_SOURCE==='local-bridge'))throw Error('Missing '+key);return [key,value];
}));
for(const key of ['TG_WEBAPP_SECRET','CABINET_SIGNING_KEY'])if(!/^[a-f0-9]{64}$/i.test(env[key]))throw Error('Invalid '+key);
const allowed=new Set(['/','/health','/ready','/api/weather','/api/cabinet','/api/history','/api/score','/api/score/calendar','/api/orders','/api/order','/api/session','/api/login','/api/logout','/auth/start','/auth/callback','/api/notifications','/api/notifications/read','/api/scan','/api/operation/prepare','/api/operation/confirm','/api/operation/status','/api/workbench','/api/activity','/api/payroll','/api/requests','/api/requests/create','/api/requests/review','/api/requests/photo','/api/login/start','/api/login/status']);
for(const p of ["/api/hub", "/api/hub/create", "/api/hub/edit", "/api/hub/comments", "/api/hub/comment/create", "/api/hub/comment/edit", "/api/hub/comment/remove", "/api/hub/react", "/api/hub/review", "/api/hub/photo", "/api/hub/settings", "/api/hub/shift", "/api/push/info", "/api/push/save", "/api/push/remove"])allowed.add(p);
for(const p of ['/api/password/login','/api/password/activate','/api/access/list','/api/access/issue'])allowed.add(p);
for(const p of ['/api/attendance','/api/attendance/create','/api/attendance/review','/api/attendance/cancel'])allowed.add(p);
for(const p of ['/favicon.ico','/sw.js','/manifest.webmanifest','/offline.html','/icon-192.png','/icon-512.png'])allowed.add(p);
allowed.add('/api/attendance/sync');
for(const p of ['/api/members','/api/members/profile','/api/members/photo','/api/members/like','/api/members/save'])allowed.add(p);
for(const p of ["/api/engagement", "/api/engagement/post", "/api/engagement/comment", "/api/engagement/notification", "/api/engagement/poll/create", "/api/engagement/poll/vote", "/api/engagement/poll/close", "/api/engagement/article/save", "/api/engagement/article/action", "/api/engagement/photo", "/api/engagement/lesson/save", "/api/engagement/lesson/answer", "/api/engagement/onboard"])allowed.add(p);

allowed.add('/api/knowledge/session');allowed.add('/api/knowledge/media');
const bridge=process.env.PRODUCTION_SOURCE==='local-bridge'?createBridge(env.CABINET_SIGNING_KEY):null;
if(bridge)env.PRODUCTION_FETCH=bridge.source;
const attendanceAPI=createAttendanceAPI(env.CABINET_SIGNING_KEY,bridge?.source,process.env.ATTENDANCE_INTEGRATION_TOKEN);
const browserAuth=createBrowserAuth(env.CABINET_SIGNING_KEY,process.env.TG_LOGIN_SECRET,process.env.TG_LOGIN_BOT_USERNAME||'postprocess_bot');
// Вход через приложение Telegram: виджет живёт на oauth.telegram.org, а с
// мобильного интернета этот домен молча недоступен. Код живёт 5 минут, привязан
// к nonce входного cookie браузера и подтверждается ботом через ключ моста.
const LOGIN_CODE=/^[a-f0-9]{32}$/,pendingLogins=new Map();
// С мобильного кабинет открывался секунды: страница 1 МБ шла без сжатия и с no-store.
// Текст сжимается; оболочка страницы получает ETag — она одинакова для всех,
// личного в ней нет, оно приходит запросами /api/*, и те остаются no-store.
const COMPRESSIBLE=/^(text\/|application\/(javascript|json|manifest\+json))/,shellCache=new Map();
function compress(body,accept){
  if(/\bbr\b/.test(accept))return ['br',brotliCompressSync(body,{params:{[zlibConstants.BROTLI_PARAM_QUALITY]:5}})];
  if(/\bgzip\b/.test(accept))return ['gzip',gzipSync(body,{level:6})];
  return [null,body];
}
function sweepLogins(){const t=Date.now();for(const[k,v]of pendingLogins)if(v.exp<t)pendingLogins.delete(k)}
const passwordTraffic=new Map();
const server=http.createServer(async(req,res)=>{
  try{
    if(await attendanceAPI(req,res))return;
    if(req.url==='/internal/bridge/poll'||req.url==='/internal/bridge/result'||req.url==='/internal/bridge/login'){
      res.setHeader('Cache-Control','no-store');
      if(!bridge||req.method!=='POST'||!bridge.authorized(req.headers.authorization)){res.writeHead(401);res.end();return}
      let size=0;const chunks=[];
      for await(const chunk of req){size+=chunk.length;if(size>2000000){res.writeHead(413);res.end();return}chunks.push(chunk)}
      const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if(req.url==='/internal/bridge/login'){
        sweepLogins();
        const code=String(value?.code||''),uid=Number(value?.telegram_id),login=pendingLogins.get(code);
        // Один код — одно подтверждение: повторное нажатие не перепривязывает вход.
        if(!LOGIN_CODE.test(code)||!Number.isSafeInteger(uid)||uid<=0||!login||login.uid){res.writeHead(409);res.end();return}
        login.uid=uid;res.writeHead(200);res.end();return;
      }
      if(req.url==='/internal/bridge/poll'){
        const jobs=await bridge.poll();res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({jobs}));return;
      }
      const accepted=bridge.complete(value);res.writeHead(accepted?200:409);res.end();return;
    }
    const origin=req.headers.origin;
    const host=req.headers.host;
    const base=origins.find(x=>new URL(x).host===host)||origins[0];
    if(origin&&!origins.includes(origin)){res.writeHead(403,{'Cache-Control':'no-store'});res.end();return}
    const url=new URL(req.url,origin||base);
    // Совы — отдельные файлы с хешем в имени; другие пути под /assets/ не открываются.
    const asset=/^\/assets\/owl-[a-z]+-[a-f0-9]{12}\.webp$/.test(url.pathname);
    if(!origins.includes(url.origin)||!allowed.has(url.pathname)&&!asset){res.writeHead(404);res.end();return}
    const session=browserAuth.session(req.headers.cookie);
    const renewal=session?browserAuth.renew(req.headers.cookie):null;
    function answer(data,status=200,cookies){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store, private','Referrer-Policy':'no-referrer',...(cookies?{'Set-Cookie':cookies}:{})});res.end(JSON.stringify(data))}
    async function completeLogin(user,csrf,redirect=false){
      if(!browserAuth.enabled||!bridge){answer({error:'Вход через браузер ещё настраивается'},503);return}
      if(!browserAuth.accepts(req.headers.cookie,csrf)){answer({error:'Обновите страницу входа'},403);return}
      const uid=browserAuth.verify(user);
      if(!uid){answer({error:'Не удалось проверить вход через Telegram'},401);return}
      await finishLogin(uid,redirect);
    }
    async function finishLogin(uid,redirect=false){
      const source=new URL('https://productionwages.axiomalink.ru/api/v1/cabinet/identity');source.searchParams.set('telegram_id',String(uid));
      const r=await bridge.source(source);const identity=await r.json();
      if(r.status===403){answer({error:identity.error||'Аккаунт не привязан к сотруднику'},403);return}
      if(!r.ok||identity.source!=='employee-cabinet-local'||identity.telegram_id!==uid||!Number.isSafeInteger(identity.employee_id)||identity.employee_id<=0){answer({error:'Не удалось получить регистрацию сотрудника'},503);return}
      const cookies=browserAuth.login(uid,identity.employee_id);
      if(redirect){res.writeHead(303,{Location:'/','Set-Cookie':cookies,'Cache-Control':'no-store, private','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});res.end();return}
      answer({ok:true},200,cookies);
    }
    if(url.pathname==='/auth/start'){
      if(req.method!=='GET'){answer({error:'Метод не поддерживается'},405);return}
      const botId=process.env.TG_LOGIN_BOT_ID||(browserAuth.bot==='postprocess_bot'?'8390363520':'');
      if(!browserAuth.enabled||!bridge||!/^\d+$/.test(botId)){answer({error:'Вход ещё настраивается. Откройте кабинет через Telegram-бота.'},503);return}
      const flow=browserAuth.challenge();
      const target=new URL('https://oauth.telegram.org/auth');target.searchParams.set('bot_id',botId);target.searchParams.set('origin',base);target.searchParams.set('lang','ru');target.searchParams.set('return_to',base+'/?login_state='+flow.csrf);
      res.writeHead(302,{Location:target.href,'Set-Cookie':flow.cookie,'Cache-Control':'no-store, private','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});res.end();return;
    }
    if(url.pathname==='/auth/callback'){
      if(req.method!=='GET'){answer({error:'Метод не поддерживается'},405);return}
      const entries=[...url.searchParams];
      if(req.url.length>16000||new Set(entries.map(([k])=>k)).size!==entries.length){answer({error:'Неверный ответ Telegram'},400);return}
      const user=Object.fromEntries(entries.filter(([k])=>k!=='state'));
      await completeLogin(user,url.searchParams.get('state'),true);return;
    }
    if(url.pathname==='/api/session'&&req.method==='GET'){
      const flow=browserAuth.challenge(req.headers.cookie);answer({authenticated:!!session,login_enabled:browserAuth.enabled,app_login:!!bridge,bot:browserAuth.bot,csrf:flow.csrf},200,[...(flow.cookie?[flow.cookie]:[]),...(renewal?[renewal]:[])]);return;
    }
    if(req.method==='HEAD'&&url.pathname==='/health'){res.writeHead(200,{'Cache-Control':'no-store'});res.end();return}
    let size=0;const chunks=[];
    for await(const chunk of req){size+=chunk.length;if(size>(['/api/requests/create','/api/hub/create','/api/hub/edit','/api/members/save','/api/engagement/article/save'].includes(url.pathname)?240000:20000)){res.writeHead(413);res.end();return}chunks.push(chunk)}
    const body=Buffer.concat(chunks).toString('utf8');
    if(url.pathname==='/api/login/start'||url.pathname==='/api/login/status'){
      if(req.method!=='POST'||origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      if(!bridge){answer({error:'Вход ещё настраивается'},503);return}
      const value=JSON.parse(body||'{}');
      sweepLogins();
      if(url.pathname==='/api/login/start'){
        const nonce=browserAuth.flowNonce(req.headers.cookie);
        if(!nonce||!browserAuth.accepts(req.headers.cookie,value.csrf)){answer({error:'Обновите страницу входа'},403);return}
        if(pendingLogins.size>=500){answer({error:'Слишком много попыток входа. Повторите через минуту'},429);return}
        const code=randomBytes(16).toString('hex');
        pendingLogins.set(code,{nonce,uid:0,exp:Date.now()+300000});
        answer({code,bot:browserAuth.bot});return;
      }
      const code=String(value.code||''),login=pendingLogins.get(code);
      if(!LOGIN_CODE.test(code)||!login){answer({error:'Ссылка входа устарела. Начните вход заново'},410);return}
      // Статус отдаётся только браузеру, начавшему вход: чужой код не открывает сессию.
      if(browserAuth.flowNonce(req.headers.cookie)!==login.nonce){answer({error:'Обновите страницу входа'},403);return}
      if(!login.uid){answer({pending:true});return}
      pendingLogins.delete(code);
      await finishLogin(login.uid);return;
    }
    if(['/api/password/login','/api/password/activate'].includes(url.pathname)){
      if(req.method!=='POST'||origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      const client=req.socket.remoteAddress||'proxy',now=Date.now();for(const [key,record] of passwordTraffic)if(now-record.since>60000)passwordTraffic.delete(key);const traffic=passwordTraffic.get(client)||{since:now,count:0};if(traffic.count>=120||passwordTraffic.size>2000){answer({error:'Слишком много попыток. Повторите позднее.'},429);return}traffic.count++;passwordTraffic.set(client,traffic);
      const value=JSON.parse(body),action=url.pathname.endsWith('/activate')?'password-activate':'password-login';
      if(!bridge||!browserAuth.accepts(req.headers.cookie,value.csrf)){answer({error:'Обновите страницу и повторите вход'},403);return}
      const login=String(value.login||'').trim().toLowerCase(),password=value.password,code=value.code;
      if(!/^[a-z0-9._-]{3,48}$/.test(login)||typeof password!=='string'||password.length>128||password.length<(action==='password-activate'?10:1)||/[\x00-\x1f]/.test(password)||action==='password-activate'&&!/^[A-Za-z0-9_-]{32}$/.test(code||'')){answer({error:'Проверьте логин, пароль и код активации'},401);return}
      const source=new URL('https://productionwages.axiomalink.ru/api/v1/cabinet/'+action);source.searchParams.set('login',login);source.searchParams.set('password',password);if(action==='password-activate')source.searchParams.set('code',code);
      const proof=await bridge.source(source),verified=await proof.json();
      if(proof.status===403||proof.status===422){answer({error:proof.status===403&&String(verified.error).includes('15 минут')?'Слишком много попыток. Повторите через 15 минут.':'Неверный логин, пароль или код активации'},401);return}
      if(!proof.ok||verified.source!=='employee-cabinet-local'||!Number.isSafeInteger(verified.telegram_id)||verified.telegram_id<=0||!Number.isSafeInteger(verified.employee_id)||verified.employee_id<=0){answer({error:'Не удалось проверить аккаунт. Попробуйте позднее.'},503);return}
      answer({ok:true},200,browserAuth.login(verified.telegram_id,verified.employee_id));return;
    }
    if(url.pathname==='/api/login'||url.pathname==='/api/logout'){
      if(req.method!=='POST'||origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      if(url.pathname==='/api/logout'){answer({ok:true},200,[...browserAuth.logout(),'__Secure-cplink_kb=; Path=/api/knowledge/; Max-Age=0; HttpOnly; Secure; SameSite=Strict']);return}
      const value=JSON.parse(body);
      await completeLogin(value.user,value.csrf);return;
    }
    const requestEnv={...env};
    if(session&&['GET','HEAD'].includes(req.method)&&url.pathname==='/api/knowledge/media')requestEnv.BROWSER_IDENTITY={uid:session.uid,employee_id:session.employee_id,exp:session.exp};
    if(session&&req.method==='POST'){
      if(origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      const value=JSON.parse(body);
      if(!value.ticket&&!value.initData)requestEnv.BROWSER_IDENTITY={uid:session.uid,employee_id:session.employee_id,exp:session.exp};
    }
    const request=new Request(url,{method:req.method,headers:req.headers,...(!['GET','HEAD'].includes(req.method)?{body}:{})});
    const result=await worker.fetch(request,requestEnv);
    const responseHeaders=Object.fromEntries(result.headers);
    if(renewal&&result.ok)responseHeaders['set-cookie']=[...result.headers.getSetCookie(),renewal];
    // Видео базы знаний идёт потоком, как и было: не сжимаем и не собираем в память.
    if(url.pathname==='/api/knowledge/media'&&result.body){res.writeHead(result.status,responseHeaders);await pipeline(Readable.fromWeb(result.body),res);return}
    let payload=Buffer.from(await result.arrayBuffer());
    const accept=String(req.headers['accept-encoding']||'');
    if(req.method==='GET'&&url.pathname==='/'&&result.status===200){
      const etag='W/"'+createHash('sha256').update(payload).digest('base64url').slice(0,22)+'"';
      responseHeaders['cache-control']='private, no-cache';responseHeaders.etag=etag;responseHeaders.vary='Accept-Encoding';
      if(req.headers['if-none-match']===etag){
        // Продление сессии отдаётся и здесь, иначе вход слетит у открывающих из кэша.
        const notModified={'cache-control':responseHeaders['cache-control'],etag,vary:responseHeaders.vary};
        if(responseHeaders['set-cookie'])notModified['set-cookie']=responseHeaders['set-cookie'];
        res.writeHead(304,notModified);res.end();return;
      }
      // Оболочка неизменна до нового выпуска — сжимаем её один раз на кодировку.
      const key=etag+'|'+(/\bbr\b/.test(accept)?'br':/\bgzip\b/.test(accept)?'gzip':'');
      if(!shellCache.has(key)){if(shellCache.size>8)shellCache.clear();shellCache.set(key,compress(payload,accept))}
      const [encoding,packed]=shellCache.get(key);
      if(encoding){responseHeaders['content-encoding']=encoding;delete responseHeaders['content-length'];payload=packed}
    }else if(payload.length>1024&&COMPRESSIBLE.test(String(responseHeaders['content-type']||''))&&!responseHeaders['content-encoding']){
      const [encoding,packed]=compress(payload,accept);
      if(encoding){responseHeaders['content-encoding']=encoding;responseHeaders.vary='Accept-Encoding';delete responseHeaders['content-length'];payload=packed}
    }
    res.writeHead(result.status,responseHeaders);res.end(payload);
  }catch{if(res.headersSent){res.destroy();return}res.writeHead(500,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"error":"Кабинет временно недоступен"}')}
});
server.headersTimeout=15000;server.requestTimeout=30000;
server.listen(port,'0.0.0.0',()=>console.log('Employee cabinet ready on port '+port));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
