import http from 'node:http';
import worker from './cabinet-worker.mjs';

const port=Number(process.env.PORT||8080);
if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid port');
const origins=(process.env.PUBLIC_ORIGINS||'').split(',').filter(Boolean).map(value=>{
  const url=new URL(value.trim());
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/')throw Error('Expected HTTPS public origin');
  return url.origin;
});
if(!origins.length)throw Error('Set PUBLIC_ORIGINS before starting the cabinet');
const env=Object.fromEntries(['PRODUCTION_API_KEY','TG_WEBAPP_SECRET','CABINET_SIGNING_KEY'].map(key=>{
  const value=process.env[key];if(!value)throw Error('Missing '+key);return [key,value];
}));
for(const key of ['TG_WEBAPP_SECRET','CABINET_SIGNING_KEY'])if(!/^[a-f0-9]{64}$/i.test(env[key]))throw Error('Invalid '+key);
const allowed=new Set(['/','/health','/ready','/api/cabinet','/api/history']);
const server=http.createServer(async(req,res)=>{
  try{
    const origin=req.headers.origin;
    const host=req.headers.host;
    const base=origins.find(x=>new URL(x).host===host)||origins[0];
    if(origin&&!origins.includes(origin)){res.writeHead(403,{'Cache-Control':'no-store'});res.end();return}
    const url=new URL(req.url,origin||base);
    if(!origins.includes(url.origin)||!allowed.has(url.pathname)){res.writeHead(404);res.end();return}
    if(req.method==='HEAD'&&url.pathname==='/health'){res.writeHead(200,{'Cache-Control':'no-store'});res.end();return}
    let size=0;const chunks=[];
    for await(const chunk of req){size+=chunk.length;if(size>20000){res.writeHead(413);res.end();return}chunks.push(chunk)}
    const body=Buffer.concat(chunks).toString('utf8');
    const request=new Request(url,{method:req.method,headers:req.headers,...(!['GET','HEAD'].includes(req.method)?{body}:{})});
    const result=await worker.fetch(request,env);
    res.writeHead(result.status,Object.fromEntries(result.headers));res.end(Buffer.from(await result.arrayBuffer()));
  }catch{res.writeHead(500,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"error":"Кабинет временно недоступен"}')}
});
server.headersTimeout=15000;server.requestTimeout=30000;
server.listen(port,'0.0.0.0',()=>console.log('Employee cabinet ready on port '+port));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
