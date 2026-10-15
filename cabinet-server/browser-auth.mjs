import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
const SESSION='__Host-cplink_session', FLOW='__Host-cplink_login';
const now=()=>Math.floor(Date.now()/1000);
function equal(a,b){const x=Buffer.from(a||''),y=Buffer.from(b||'');return x.length===y.length&&timingSafeEqual(x,y)}
export function verifyLogin(data,loginKey,at=now()) {
  if(!/^[a-f0-9]{64}$/i.test(loginKey||'')||!data||typeof data!=='object'||Array.isArray(data))return null;
  const allowed=['id','first_name','last_name','username','photo_url','auth_date','hash'];
  if(Object.keys(data).some(k=>!allowed.includes(k)||!['string','number'].includes(typeof data[k])||String(data[k]).length>2048))return null;
  const uid=Number(data.id),date=Number(data.auth_date);
  if(!Number.isSafeInteger(uid)||uid<=0||!Number.isSafeInteger(date)||date>at+30||at-date>300||!date||!/^[a-f0-9]{64}$/i.test(data.hash||''))return null;
  const check=Object.keys(data).filter(k=>k!=='hash').sort().map(k=>k+'='+data[k]).join('\n');
  const hash=createHmac('sha256',Buffer.from(loginKey,'hex')).update(check).digest('hex');
  return equal(hash,data.hash.toLowerCase())?uid:null;
}
export function createBrowserAuth(signingKey,loginKey,bot='postprocess_bot') {
  const root=Buffer.from(signingKey,'hex');
  function seal(type,value){const body=Buffer.from(JSON.stringify(value)).toString('base64url');return body+'.'+createHmac('sha256',root).update(type+':'+body).digest('base64url')}
  function open(type,value){try{if(!value||value.length>2048)return null;const[b,s,...rest]=value.split('.');if(rest.length||!equal(s,createHmac('sha256',root).update(type+':'+b).digest('base64url')))return null;const d=JSON.parse(Buffer.from(b,'base64url').toString());return Number.isSafeInteger(d.iat)&&Number.isSafeInteger(d.exp)&&d.iat<=now()+30&&d.exp>now()&&d.exp-d.iat<=(type==='session'?3600:300)?d:null}catch{return null}}
  function cookies(header){return Object.fromEntries((header||'').split(';').map(x=>x.trim().split('='))) }
  function cookie(name,value,age){return name+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+age}
  function session(header){const d=open('session',cookies(header)[SESSION]);return d&&Number.isSafeInteger(d.uid)&&d.uid>0&&/^\d+$/.test(String(d.employee_id))?d:null}
  // Живой входной cookie не перевыпускается: сотрудник уходит подтверждать вход
  // в приложение Telegram, страница может перезагрузиться, а код входа привязан
  // к этому nonce. Новый выдаётся, когда у старого осталось меньше минуты.
  function challenge(header){const old=open('flow',cookies(header)[FLOW]);if(old&&old.exp-now()>60)return {csrf:old.nonce,cookie:null};const d={nonce:randomBytes(32).toString('hex'),iat:now(),exp:now()+300};return {csrf:d.nonce,cookie:cookie(FLOW,seal('flow',d),300)}}
  function flowNonce(header){const d=open('flow',cookies(header)[FLOW]);return d?d.nonce:null}
  function accepts(header,csrf){const d=open('flow',cookies(header)[FLOW]);return !!d&&equal(d.nonce,csrf)}
  function login(uid,employeeId){const d={uid,employee_id:Number(employeeId),iat:now(),exp:now()+3600};return [cookie(SESSION,seal('session',d),3600),cookie(FLOW,'',0)]}
  const enabled=/^[a-f0-9]{64}$/i.test(loginKey||'')&&/^[a-zA-Z0-9_]{5,32}$/.test(bot);
  return {session,challenge,flowNonce,accepts,login,verify:data=>verifyLogin(data,loginKey),enabled,bot,
    logout:()=>[cookie(SESSION,'',0),cookie(FLOW,'',0)]};
}
