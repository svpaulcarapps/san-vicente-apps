// Sesión firmada recordada en el dispositivo durante 30 días. Los datos de las apps nunca entran en la caché offline.
(()=>{'use strict';
 const cfg=window.NATIVE_APP_CONFIG,API='https://svpaulcar-apps-api.carlos-mercader-conesa.workers.dev';
 if(!cfg||!['tic','comedor'].includes(cfg.service))throw Error('Configuración de app no válida.');
 const key='svp-native-session-'+cfg.service;let session=null,connection=null,overlay=null,resolveReady;
 try{const saved=JSON.parse(localStorage.getItem(key)||'null');if(saved?.expires>Date.now()+30000&&typeof saved.token==='string')session=saved;else localStorage.removeItem(key);}catch{}
 const ready=new Promise(resolve=>{resolveReady=resolve;});if(session)resolveReady(session);
 function show(message){
  if(!overlay){overlay=document.createElement('section');overlay.id='native-account-gate';overlay.style.cssText='position:fixed;inset:0;z-index:99999;display:grid;place-items:center;background:#f3f6fa;padding:20px;overflow:auto';
   overlay.innerHTML='<div style="max-width:440px;width:100%;text-align:center;background:#fff;border:1px solid #dbe3ed;border-radius:22px;padding:30px;font:16px system-ui;color:#17334f"><img alt="" style="width:88px;height:88px;border-radius:22px;object-fit:cover"><h1 style="font-size:25px;margin:18px 0 8px"></h1><p style="line-height:1.6">Conecta tu cuenta del colegio. La recordaremos durante 30 días en este dispositivo.</p><button type="button" style="font:inherit;min-height:48px;padding:12px 18px;background:#004379;color:white;border:0;border-radius:11px;width:100%">Conectar cuenta del colegio</button><p role="status" style="line-height:1.5;font-size:14px;min-height:22px"></p></div>';
   overlay.querySelector('img').src=cfg.icon;overlay.querySelector('h1').textContent=cfg.title;overlay.querySelector('button').onclick=()=>connect().catch(e=>show(e.message));document.body.appendChild(overlay);
  }
  overlay.hidden=false;overlay.style.display='grid';overlay.querySelector('[role=status]').textContent=message||'';
 }
 function hide(){if(overlay){overlay.hidden=true;overlay.style.display='none';}}
 async function connect(){
  if(session?.expires>Date.now()+30000){hide();return session;}if(connection)return connection.promise;
  const nonce=crypto.randomUUID(),url=new URL(cfg.loginURL);url.searchParams.set('nativeConnect',nonce);
  const popup=window.open(url.href,'svp-connect-'+cfg.service,'popup,width=520,height=700');
  if(!popup)throw Error('Permite abrir la ventana de Google para conectar tu cuenta.');
  let accept,decline;const promise=new Promise((resolve,reject)=>{accept=resolve;decline=reject;});
  const timeout=setTimeout(()=>{if(connection?.nonce===nonce){connection=null;decline(Error('La conexión ha caducado. Pulsa Conectar para intentarlo de nuevo.'));}},180000);
  connection={nonce,popup,promise,accept,decline,timeout};show('Completa el acceso de Google y vuelve a esta app.');return promise;
 }
 window.addEventListener('message',event=>{
  if(!connection||!/^https:\/\/(?:script|[a-z0-9-]+-script)\.googleusercontent\.com$/.test(event.origin))return;
  const message=event.data;if(message?.type!=='svpaulcar-native-auth'||message.service!==cfg.service||message.nonce!==connection.nonce)return;
  const pending=connection;connection=null;clearTimeout(pending.timeout);
  if(message.error){pending.decline(Error(message.error));show(message.error);return;}
  const s=message.session;if(typeof s?.token!=='string'||s.token.length>4096||typeof s.email!=='string'||!Number.isFinite(s.expires)||s.expires<=Date.now()||s.expires>Date.now()+30*86400000+60000){pending.decline(Error('Respuesta de acceso no válida.'));return;}
  session={token:s.token,email:s.email,expires:s.expires};try{localStorage.setItem(key,JSON.stringify(session));}catch{}hide();resolveReady(session);pending.accept(session);window.dispatchEvent(new CustomEvent('native-account-connected',{detail:{email:session.email}}));
 });
 async function rpc(method,...args){
  await ready;if(!session||session.expires<=Date.now()){session=null;try{localStorage.removeItem(key);}catch{}show('Tu sesión ha caducado. Vuelve a conectar tu cuenta.');throw Error('Vuelve a conectar tu cuenta del colegio.');}
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),60000);
  try{const response=await fetch(API+'/native/'+cfg.service+'/rpc',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json',Authorization:'Bearer '+session.token},body:JSON.stringify({method,args}),signal:controller.signal});let data;try{data=await response.json();}catch{throw Error('No se ha podido conectar con los datos.');}
   if(!response.ok){if(response.status===401){session=null;try{localStorage.removeItem(key);}catch{}show(data.error||'Vuelve a conectar tu cuenta.');}throw Error(data.error||'No se pudo completar la operación.');}return data.result;
  }catch(error){if(error.name==='AbortError')throw Error('La operación está tardando demasiado. Actualiza antes de repetir un envío.');throw error;}finally{clearTimeout(timer);}
 }
 function runner(success=()=>{},failure=console.error){return new Proxy({}, {get(_,name){if(name==='withSuccessHandler')return fn=>runner(fn,failure);if(name==='withFailureHandler')return fn=>runner(success,fn);if(name==='then')return undefined;return (...args)=>{rpc(String(name),...args).then(success,failure);};}});}
 window.NativeApp={ready,connect,rpc,get email(){return session?.email||'';},async disconnect(){try{if(session)await rpc('nativeLogout');}finally{try{localStorage.removeItem(key);sessionStorage.removeItem(key);}catch{}session=null;location.reload();}}};
 window.google={script:{run:runner()}};
 const mount=()=>{if(!session)show();};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
})();
