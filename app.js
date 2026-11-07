let installPrompt;
const installButton = document.getElementById('install');
window.addEventListener('beforeinstallprompt', event => { event.preventDefault(); installPrompt = event; installButton.textContent = 'Instalar SVPAULCAR Apps'; });
installButton.addEventListener('click', async () => { if (installPrompt) { await installPrompt.prompt(); await installPrompt.userChoice; installPrompt = null; installButton.textContent = 'Cómo instalar'; } else { document.getElementById('instructions').showModal(); } });
if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(() => {});

// Remember only the opaque server session, never passwords or private app links.
import { API_BASE } from './config.js?v=9';
let accessToken = '', expiryTimer, personalApps = [];
const SESSION_KEY='svpaulcar-admin-session-v1';
let restoringSession=false;
const apiBase=API_BASE.replace(/\/$/,'');
const $=id=>document.getElementById(id);
async function api(path,{method='GET',data,auth=false}={}) {
 if(!apiBase)throw new Error('Este servicio estará disponible próximamente.');
 const controller=new AbortController();let timer;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('La conexión con el acceso administrador ha tardado demasiado. Comprueba tu conexión y vuelve a pulsar Entrar.'));},15000);});
 try {
  return await Promise.race([(async()=>{
   const response=await fetch(apiBase+path,{method,mode:'cors',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:controller.signal,headers:{...(data?{'Content-Type':'application/json'}:{}),...(auth?{Authorization:'Bearer '+accessToken}:{})},body:data?JSON.stringify(data):undefined});
   const result=await response.json();
   if(response.status===401&&auth){clearSession();throw new Error('Tu sesión ha caducado. Vuelve a entrar en Mis apps.');}
   if(!response.ok)throw new Error(result.error||'No se ha podido completar la solicitud.');return result;
  })(),timeout]);
 }catch(error){
  if(controller.signal.aborted)throw new Error('La conexión con el acceso administrador ha tardado demasiado. Comprueba tu conexión y vuelve a pulsar Entrar.');
  if(error instanceof TypeError)throw new Error('No se puede conectar con el acceso administrador. Prueba con otra conexión (Wi-Fi o datos móviles) y vuelve a entrar.');
  throw error;
 }finally{clearTimeout(timer);}
}
function showMessage(id,message){$(id).textContent=message;}
function clearSession(){
 try{localStorage.removeItem(SESSION_KEY);}catch{}
 accessToken='';clearTimeout(expiryTimer);personalApps=[];$('private-list').replaceChildren();$('personal-section').hidden=true;$('login-form').reset();
}
function scheduleExpiry(expires){
 clearTimeout(expiryTimer);
 const remaining=expires*1000-Date.now();
 if(remaining<=0){clearSession();return;}
 expiryTimer=setTimeout(()=>scheduleExpiry(expires),Math.min(remaining,2147483647));
}
function rememberSession(expires){
 try{localStorage.setItem(SESSION_KEY,JSON.stringify({token:accessToken,expires}));}catch{}
 scheduleExpiry(expires);
}
async function restoreSession(){
 if(restoringSession||accessToken)return;
 let saved;
 try{saved=JSON.parse(localStorage.getItem(SESSION_KEY)||'null');}catch{return;}
 if(!saved)return;
 if(!/^[A-Za-z0-9_-]{43}$/.test(saved.token||'')||!Number.isFinite(saved.expires)||saved.expires*1000<=Date.now()||saved.expires*1000>Date.now()+30*86400000){clearSession();return;}
 restoringSession=true;accessToken=saved.token;scheduleExpiry(saved.expires);
 try{await loadApps();$('personal-section').hidden=false;}
 catch{accessToken='';personalApps=[];$('private-list').replaceChildren();$('personal-section').hidden=true;}
 finally{restoringSession=false;}
}
$('open-personal').addEventListener('click',()=>{
 if(accessToken){$('personal-section').scrollIntoView({behavior:'smooth'});return;}
 showMessage('login-message','');$('login-dialog').showModal();$('personal-password').focus();
});
$('login-form').addEventListener('submit',async e=>{
 e.preventDefault();const button=$('login-submit');button.disabled=true;button.textContent='Comprobando…';showMessage('login-message','Conectando con el acceso administrador…');
 try{
  const result=await api('/auth/login',{method:'POST',data:{password:$('personal-password').value}});
  $('personal-password').value='';accessToken=result.token;
  rememberSession(result.expires);
  showMessage('login-message','Contraseña validada. Abriendo tus aplicaciones…');
  await loadApps();$('login-dialog').close();$('personal-section').hidden=false;$('personal-section').scrollIntoView({behavior:'smooth'});
 }catch(err){showMessage('login-message',err.message);$('personal-password').value='';if(accessToken)clearSession();}finally{button.disabled=false;button.textContent='Entrar';}
});
$('logout').addEventListener('click',async()=>{try{await api('/auth/logout',{method:'POST',auth:true});}catch{}finally{clearSession();}});
// Conceal private links when leaving, while retaining the requested 30-day session.
window.addEventListener('pagehide',()=>{accessToken='';clearTimeout(expiryTimer);personalApps=[];$('private-list').replaceChildren();$('personal-section').hidden=true;$('login-form').reset();});
window.addEventListener('pageshow',()=>restoreSession());
restoreSession();
async function loadApps(){const result=await api('/apps',{auth:true});personalApps=result.apps;renderApps();}
// Dedicated artwork for the two personal tools; other apps keep their configured icon.
function personalAppIcon(app){
 const name=app.name.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 if(name.includes('cuaderno'))return './cuaderno-profesor.png';
 if(name.includes('asistencia'))return './asistencia-v2.png';
 return app.icon;
}
function renderApps(){
 const list=$('private-list');list.replaceChildren();showMessage('private-message',personalApps.length?'':'No hay aplicaciones personales disponibles.');
 personalApps.forEach(app=>{
  const article=document.createElement('article');article.className='card private-card';
  const link=document.createElement('a');link.className='private-link';link.href=app.url;link.target='_blank';link.rel='noopener noreferrer';link.referrerPolicy='no-referrer';
  const img=document.createElement('img');img.className='app-icon';img.src=personalAppIcon(app);img.alt='';
  const name=document.createElement('strong');name.className='app-name';name.textContent=app.name;link.append(img,name);
  article.append(link);list.append(article);
 });
}
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));
$('login-dialog').addEventListener('close',()=>{$('login-form').reset();});

$('push-settings').addEventListener('click',()=>{$('push-settings-dialog').showModal();refreshNotifications();});
let pushConfig,deviceRegistered=false,pushRefresh=0;
let currentPushTest='',receivedPushTests=new Set();
function isIOS(){return /iPad|iPhone|iPod/.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);}
function fromBase64(value){return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));}
function samePushKey(sub,key){if(!sub.options?.applicationServerKey)return true;const stored=new Uint8Array(sub.options.applicationServerKey),expected=fromBase64(key);return stored.length===expected.length&&stored.every((v,i)=>v===expected[i]);}
async function supportsPushTest(registration){if(!registration.active)return false;return new Promise(resolve=>{const channel=new MessageChannel(),timer=setTimeout(()=>resolve(false),1800);channel.port1.onmessage=e=>{clearTimeout(timer);resolve(e.data?.supportsPushTest===true);};registration.active.postMessage({type:'push-self-test-capability'},[channel.port2]);});}
async function refreshNotifications(){
 const generation=++pushRefresh;
 $('push-test').disabled=true;
 if(!('serviceWorker'in navigator)||!('PushManager'in window)||!('Notification'in window)){$('push-toggle').disabled=true;showMessage('push-message',isIOS()?'En iPhone, añade esta app a la pantalla de inicio desde Safari y ábrela desde su icono (iOS 16.4 o posterior).':'Este navegador no permite notificaciones push.');return;}
 try{pushConfig=await api('/config');if(!pushConfig.pushEnabled){$('push-toggle').disabled=true;showMessage('push-message','El registro de avisos está desactivado en el servidor.');return;}
 const registration=await navigator.serviceWorker.ready,sub=await registration.pushManager.getSubscription();let registered=false;if(sub&&samePushKey(sub,pushConfig.publicKey)){const state=await api('/subscriptions/status',{method:'POST',data:sub.toJSON()});registered=state.registered;}
 if(generation!==pushRefresh)return;deviceRegistered=registered;$('push-settings').dataset.enabled=String(registered);$('push-settings').setAttribute('aria-label',(registered?'Avisos activados':'Avisos desactivados')+'. Configurar avisos de Sustituciones');$('push-toggle').disabled=false;$('push-toggle').textContent=registered?'Desactivar avisos':sub?'Reactivar avisos':'Activar avisos';$('push-toggle').dataset.enabled=String(registered);$('push-toggle').setAttribute('aria-label',(registered?'Desactivar':'Activar')+' notificaciones push de Sustituciones');const testReady=await supportsPushTest(registration);if(generation!==pushRefresh)return;$('push-test').disabled=!registered||!pushConfig.deliveryEnabled||!testReady;if(!testReady){showMessage('push-test-message','Actualizando los avisos. Recarga la app en unos segundos para probarlos.');registration.update().catch(()=>{});}else if(!currentPushTest)showMessage('push-test-message','La prueba se envía solo a este dispositivo.');
 showMessage('push-message',registered?(pushConfig.deliveryEnabled?'🔔 Avisos activados y dispositivo registrado.':'⏳ Dispositivo registrado. Los envíos están desactivados en el servidor.'):sub?'Este dispositivo necesita reactivar sus avisos.':'🔕 Avisos desactivados en este dispositivo.');
 }catch{showMessage('push-message','No se ha podido comprobar el registro de avisos. Vuelve a intentarlo recargando la app.');$('push-toggle').disabled=true;}
}
$('push-toggle').addEventListener('click',async()=>{const button=$('push-toggle');button.disabled=true;$('push-test').disabled=true;try{const registration=await navigator.serviceWorker.ready;let sub=await registration.pushManager.getSubscription();if(sub&&deviceRegistered){await api('/subscriptions',{method:'DELETE',data:sub.toJSON()});await sub.unsubscribe();}else{if(isIOS()&&!window.matchMedia('(display-mode: standalone)').matches&&!navigator.standalone)throw Error('Abre SVPAULCAR Apps desde su icono de la pantalla de inicio.');if(await Notification.requestPermission()!=='granted')throw Error('No se ha concedido permiso. Puedes cambiarlo en los ajustes del navegador.');if(sub&&!samePushKey(sub,pushConfig.publicKey)){await api('/subscriptions',{method:'DELETE',data:sub.toJSON()});await sub.unsubscribe();sub=null;}if(!sub)sub=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:fromBase64(pushConfig.publicKey)});try{await api('/subscriptions',{method:'POST',data:sub.toJSON()});}catch(err){await sub.unsubscribe();throw err;}}
 await refreshNotifications();}catch(err){showMessage('push-message',err.message);button.disabled=false;}});
if('serviceWorker'in navigator)navigator.serviceWorker.addEventListener('controllerchange',()=>refreshNotifications());
if('serviceWorker'in navigator)navigator.serviceWorker.addEventListener('message',event=>{const m=event.data;if(m?.type!=='push-test-received'||typeof m.testId!=='string')return;receivedPushTests.add(m.testId);if(m.testId===currentPushTest)showMessage('push-test-message','✅ Prueba recibida correctamente en este dispositivo. Si no aparece el aviso, revisa los ajustes de notificaciones del sistema.');});
$('push-test').addEventListener('click',async()=>{const button=$('push-test');button.disabled=true;showMessage('push-test-message','Enviando una prueba real solo a este dispositivo…');try{const registration=await navigator.serviceWorker.ready;const sub=await registration.pushManager.getSubscription();if(!sub)throw Error('Activa primero los avisos de este dispositivo.');const result=await api('/subscriptions/test',{method:'POST',data:sub.toJSON()});currentPushTest=result.testId;showMessage('push-test-message',receivedPushTests.has(currentPushTest)?'✅ Prueba recibida correctamente en este dispositivo.':'Prueba aceptada por el servicio. Esperando que llegue a este dispositivo…');const id=currentPushTest;setTimeout(()=>{if(currentPushTest===id&&!receivedPushTests.has(id))showMessage('push-test-message','El servicio aceptó la prueba, pero aún no se confirma la recepción. Comprueba los permisos del navegador y del sistema y vuelve a probar.');},20000);}catch(err){showMessage('push-test-message',err.message);}finally{button.disabled=!deviceRegistered||!pushConfig?.deliveryEnabled;}});
function showSubstitutions(){if(location.hash==='#sustituciones'){$('sustituciones').scrollIntoView({behavior:'smooth',block:'center'});$('sustituciones').focus();}}
window.addEventListener('hashchange',showSubstitutions);showSubstitutions();refreshNotifications();
