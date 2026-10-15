import http from 'node:http';
import worker from './cabinet-worker.mjs';
import {createBridge} from './bridge.mjs';
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
const allowed=new Set(['/','/health','/ready','/api/cabinet','/api/history','/api/score','/api/orders','/api/order','/api/session','/api/login','/api/logout','/auth/callback','/api/notifications','/api/notifications/read','/api/scan','/api/operation/prepare','/api/operation/confirm','/api/operation/status','/api/activity','/api/payroll','/api/requests','/api/requests/create','/api/requests/review','/api/requests/photo']);
const bridge=process.env.PRODUCTION_SOURCE==='local-bridge'?createBridge(env.CABINET_SIGNING_KEY):null;
if(bridge)env.PRODUCTION_FETCH=bridge.source;
const browserAuth=createBrowserAuth(env.CABINET_SIGNING_KEY,process.env.TG_LOGIN_SECRET,process.env.TG_LOGIN_BOT_USERNAME||'postprocess_bot');
const server=http.createServer(async(req,res)=>{
  try{
    if(req.url==='/internal/bridge/poll'||req.url==='/internal/bridge/result'){
      res.setHeader('Cache-Control','no-store');
      if(!bridge||req.method!=='POST'||!bridge.authorized(req.headers.authorization)){res.writeHead(401);res.end();return}
      let size=0;const chunks=[];
      for await(const chunk of req){size+=chunk.length;if(size>2000000){res.writeHead(413);res.end();return}chunks.push(chunk)}
      const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
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
    if(!origins.includes(url.origin)||!allowed.has(url.pathname)){res.writeHead(404);res.end();return}
    const session=browserAuth.session(req.headers.cookie);
    function answer(data,status=200,cookies){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store, private','Referrer-Policy':'no-referrer',...(cookies?{'Set-Cookie':cookies}:{})});res.end(JSON.stringify(data))}
    async function completeLogin(user,csrf,redirect=false){
      if(!browserAuth.enabled||!bridge){answer({error:'Вход через браузер ещё настраивается'},503);return}
      if(!browserAuth.accepts(req.headers.cookie,csrf)){answer({error:'Обновите страницу входа'},403);return}
      const uid=browserAuth.verify(user);
      if(!uid){answer({error:'Не удалось проверить вход через Telegram'},401);return}
      const source=new URL('https://productionwages.axiomalink.ru/api/v1/cabinet/identity');source.searchParams.set('telegram_id',String(uid));
      const r=await bridge.source(source);const identity=await r.json();
      if(r.status===403){answer({error:identity.error||'Аккаунт не привязан к сотруднику'},403);return}
      if(!r.ok||identity.source!=='employee-cabinet-local'||identity.telegram_id!==uid||!Number.isSafeInteger(identity.employee_id)||identity.employee_id<=0){answer({error:'Не удалось получить регистрацию сотрудника'},503);return}
      const cookies=browserAuth.login(uid,identity.employee_id);
      if(redirect){res.writeHead(303,{Location:'/','Set-Cookie':cookies,'Cache-Control':'no-store, private','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});res.end();return}
      answer({ok:true},200,cookies);
    }
    if(url.pathname==='/auth/callback'){
      if(req.method!=='GET'){answer({error:'Метод не поддерживается'},405);return}
      const entries=[...url.searchParams];
      if(req.url.length>16000||new Set(entries.map(([k])=>k)).size!==entries.length){answer({error:'Неверный ответ Telegram'},400);return}
      const user=Object.fromEntries(entries.filter(([k])=>k!=='state'));
      await completeLogin(user,url.searchParams.get('state'),true);return;
    }
    if(url.pathname==='/api/session'&&req.method==='GET'){
      const flow=browserAuth.challenge();answer({authenticated:!!session,login_enabled:browserAuth.enabled,bot:browserAuth.bot,csrf:flow.csrf},200,[flow.cookie]);return;
    }
    if(req.method==='HEAD'&&url.pathname==='/health'){res.writeHead(200,{'Cache-Control':'no-store'});res.end();return}
    let size=0;const chunks=[];
    for await(const chunk of req){size+=chunk.length;if(size>(url.pathname==='/api/requests/create'?240000:20000)){res.writeHead(413);res.end();return}chunks.push(chunk)}
    const body=Buffer.concat(chunks).toString('utf8');
    if(url.pathname==='/api/login'||url.pathname==='/api/logout'){
      if(req.method!=='POST'||origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      if(url.pathname==='/api/logout'){answer({ok:true},200,browserAuth.logout());return}
      const value=JSON.parse(body);
      await completeLogin(value.user,value.csrf);return;
    }
    const requestEnv={...env};
    if(session&&req.method==='POST'){
      if(origin!==url.origin){answer({error:'Запрос отклонён'},403);return}
      const value=JSON.parse(body);
      if(!value.ticket&&!value.initData)requestEnv.BROWSER_IDENTITY={uid:session.uid,employee_id:session.employee_id,exp:session.exp};
    }
    const request=new Request(url,{method:req.method,headers:req.headers,...(!['GET','HEAD'].includes(req.method)?{body}:{})});
    const result=await worker.fetch(request,requestEnv);
    res.writeHead(result.status,Object.fromEntries(result.headers));res.end(Buffer.from(await result.arrayBuffer()));
  }catch{res.writeHead(500,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"error":"Кабинет временно недоступен"}')}
});
server.headersTimeout=15000;server.requestTimeout=30000;
server.listen(port,'0.0.0.0',()=>console.log('Employee cabinet ready on port '+port));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
