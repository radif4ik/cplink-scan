import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';

export function createBridge(signingKey,{timeoutMs=30000,maxPending=30,pollMs=15000}={}) {
  const token=createHmac('sha256',Buffer.from(signingKey,'hex')).update('employee-cabinet-bridge-v1').digest('hex');
  const pending=new Map();
  let wake;
  function authorized(value) {
    const supplied=Buffer.from(value||'');const expected=Buffer.from('Bearer '+token);
    return supplied.length===expected.length&&timingSafeEqual(supplied,expected);
  }
  function validPath(path) {return /^(ping|employees|employees\/\d+\/(skills|attestations)|cabinet\/(identity|score|orders|order|notifications|read-notifications|scan|prepare|confirm|status|workbench|activity|payroll|requests|request-create|request-review|request-photo))$/.test(path)}
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
