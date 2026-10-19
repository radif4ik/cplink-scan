import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';

export function createBridge(signingKey,{timeoutMs=30000,maxPending=30,pollMs=15000}={}) {
  const token=createHmac('sha256',Buffer.from(signingKey,'hex')).update('employee-cabinet-bridge-v1').digest('hex');
  const pending=new Map();
  let wake;
  function authorized(value) {
    const supplied=Buffer.from(value||'');const expected=Buffer.from('Bearer '+token);
    return supplied.length===expected.length&&timingSafeEqual(supplied,expected);
  }
  function validPath(path) {return /^(ping|employees|employees\/\d+\/(skills|attestations)|cabinet\/(identity|score|orders|order|notifications|read-notifications|scan|prepare|confirm|status|workbench|activity|score-calendar|payroll|requests|request-create|request-review|request-photo|members|member|member-save|member-like|member-photo|hub|hub-create|hub-edit|hub-comments|hub-comment-create|hub-comment-edit|hub-comment-remove|hub-react|hub-review|hub-photo|hub-settings|hub-shift|push-info|push-save|push-remove|password-login|password-activate|access-list|access-issue|attendance|attendance-create|attendance-review|attendance-cancel|attendance-feed|attendance-export|attendance-ack|attendance-sync|engagement|engagement-post|engagement-comment|engagement-notification|engagement-poll-create|engagement-poll-vote|engagement-poll-close|engagement-article-save|engagement-article-action|engagement-photo|engagement-lesson-save|engagement-lesson-answer|engagement-onboard))$/.test(path)}
  async function source(url) {
    if(url.origin!=='https://productionwages.axiomalink.ru'||!url.pathname.startsWith('/api/v1/'))throw Error('Invalid bridge source');
    const path=url.pathname.slice('/api/v1/'.length);
    if(!validPath(path)||pending.size>=maxPending)throw Error('Bridge unavailable');
    const id=randomUUID();let finish;
    const result=new Promise((resolve,reject)=>{finish={resolve,reject}});
    const timer=setTimeout(()=>{pending.delete(id);finish.reject(Error('Bridge timeout'))},timeoutMs);
    pending.set(id,{id,path,params:Object.fromEntries(url.searchParams),sent:false,...finish});
    wake?.();
    try{const response=await result;return Response.json(response.data,{status:response.status})}
    finally{clearTimeout(timer);pending.delete(id)}
  }
  async function poll() {
    if(![...pending.values()].some(x=>!x.sent)) {
      await new Promise(resolve=>{const timer=setTimeout(done,pollMs);function done(){clearTimeout(timer);if(wake===done)wake=null;resolve()}wake=done});
    }
    return [...pending.values()].filter(x=>!x.sent).slice(0,4).map(x=>{x.sent=true;return {id:x.id,path:x.path,params:x.params}});
  }
  function complete(value) {
    const job=pending.get(value?.id);
    if(!job||!job.sent||![200,403,409,422,503].includes(value.status)||!value.data||typeof value.data!=='object'||Array.isArray(value.data))return false;
    job.resolve({status:value.status,data:value.data});pending.delete(job.id);return true;
  }
  return {authorized,source,poll,complete};
}

// Dedicated server-to-server credential: no access to employee sessions or other bridge routes.
export function attendanceToken(signingKey){return createHmac('sha256',Buffer.from(signingKey,'hex')).update('cplink-portal-attendance-v1').digest('hex')}
export function createAttendanceAPI(signingKey,source,override){
 const token=override||attendanceToken(signingKey);if(!/^[a-f0-9]{64}$/.test(token))throw Error('Invalid attendance integration token');
 const expected=Buffer.from('Bearer '+token),prefix='/api/integrations/attendance/v1';let minute=0,count=0;
 return async function handle(req,res){
  const url=new URL(req.url,'https://cplink-lk.ru');if(url.pathname!==prefix&&!url.pathname.startsWith(prefix+'/'))return false;
  const answer=(body,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});res.end(JSON.stringify(body));return true};
  const error=(code,message,status)=>answer({error:{code,message}},status);
  const supplied=Buffer.from(req.headers.authorization||'');if(supplied.length!==expected.length||!timingSafeEqual(supplied,expected))return error('unauthorized','A dedicated integration token is required',401);
  if(req.headers.origin)return error('server_only','Use this API from the portal server, without a browser Origin header',403);
  const now=Math.floor(Date.now()/60000);if(now!==minute){minute=now;count=0}if(++count>120){res.setHeader('Retry-After','60');return error('rate_limit','Retry after one minute',429)}
  if(!source)return error('source_unavailable','The local bridge is unavailable',503);
  const idPattern=/^[a-f0-9]{32}$/,versionPattern=/^[a-f0-9]{64}$/,refPattern=/^[^\x00-\x20]{0,100}$/;
  let action,params;
  if(url.pathname===prefix+'/requests'){
   if(req.method!=='GET')return error('method_not_allowed','Use GET',405);
   if([...url.searchParams.keys()].some(k=>!['limit','cursor'].includes(k))||new Set(url.searchParams.keys()).size!==[...url.searchParams.keys()].length)return error('invalid_query','Only limit and cursor are supported',422);
   const limit=url.searchParams.get('limit')||'50',cursor=url.searchParams.get('cursor')||'';
   if(!/^\d{1,3}$/.test(limit)||Number(limit)<1||Number(limit)>100||!/^[-\w]{0,160}$/.test(cursor))return error('invalid_query','limit must be 1..100; cursor must be returned by this API',422);
   action='attendance-feed';params={limit,cursor};
  }else if(url.pathname.startsWith(prefix+'/requests/')){
   if(req.method!=='GET')return error('method_not_allowed','Use GET',405);
   const id=url.pathname.slice((prefix+'/requests/').length);if(!idPattern.test(id)||url.search)return error('invalid_id','Use an external_id returned by this API',422);
   action='attendance-export';params={id};
  }else if(url.pathname===prefix+'/ack'){
   if(req.method!=='POST')return error('method_not_allowed','Use POST',405);
   if(url.search||!String(req.headers['content-type']||'').startsWith('application/json'))return error('invalid_body','JSON is required',415);
   let bytes=0,chunks=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>8000)return error('body_too_large','Body must be at most 8000 bytes',413);chunks.push(chunk)}
   let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{return error('invalid_json','Invalid JSON',422)}
   const fields=['external_id','version','result','portal_request_id','correction_id','comment'];
   if(!value||Array.isArray(value)||typeof value!=='object'||Object.keys(value).some(k=>!fields.includes(k)))return error('invalid_fields','Unknown acknowledgement fields',422);
   const {external_id:id,version,result}=value;const request_id=value.portal_request_id??'',correction=value.correction_id??'',comment=value.comment??'';
   if(typeof id!=='string'||!idPattern.test(id)||typeof version!=='string'||!versionPattern.test(version)||!['received','applied','rejected'].includes(result)||typeof request_id!=='string'||!refPattern.test(request_id)||typeof correction!=='string'||!refPattern.test(correction)||typeof comment!=='string'||comment.length>1000||/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(comment))return error('invalid_fields','Check external_id, version, result and portal references',422);
   if(result==='received'&&(!request_id||correction)||result==='applied'&&!correction||result==='rejected'&&(!comment.trim()||correction))return error('missing_receipt','received requires portal_request_id; applied requires correction_id; rejected requires comment',422);
   action='attendance-ack';params={id,version,result,portal_request_id:request_id,correction_id:correction,comment};
  }else return error('not_found','Unknown integration method',404);
  try{
   const u=new URL('https://productionwages.axiomalink.ru/api/v1/cabinet/'+action);for(const[k,v]of Object.entries(params))u.searchParams.set(k,v);
   const response=await source(u),data=await response.json();
   if(response.status===422)return error('invalid_fields',data.error||'Check request fields',422);
   if(!response.ok||data.source!=='attendance-integration-local'||data.client!=='productionwages'||data.schema_version!==1)return error('source_unavailable','Cannot verify the request source',503);
   if(data.found===false)return error('not_found','An approved request with this external_id was not found',404);
   if(data.conflict)return error(data.conflict,'The acknowledgement conflicts with the saved request or receipt',409);
   const {source:unusedSource,client:unusedClient,...body}=data;return answer({source:'cplink-lk',...body});
  }catch{return error('source_unavailable','Cannot obtain a confirmed result; retry the same external_id and version',503)}
 };
}
