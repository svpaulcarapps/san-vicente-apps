const CACHE='svpaul-shell-v22';
const SHELL=['./','./index.html','./general-ios.png','./oaoa-biblioteca.png','./comedor.jpg','./base-datos.png','./justificantes.png','./sustituciones.png','./fichaje.png','./filmoteca.png','./parte-tic.png','./reserva-chromebooks.png','./parte-mantenimiento.png','./cuaderno-profesor.png','./asistencia-v2.png','./app.js?v=19','./config.js?v=9','./manifest.webmanifest'];
const urls=new Set(SHELL.map(path=>new URL(path,self.registration.scope).href));
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL)));self.skipWaiting();});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>(key.startsWith('svp-apps-')||key.startsWith('svpaul-shell-'))&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',event=>{
 // Only named public shell files can enter Cache Storage. No API or private data.
 if(event.request.method!=='GET'||!urls.has(event.request.url))return;
 event.respondWith(fetch(event.request,{cache:'no-store'}).then(response=>{if(response.ok){const copy=response.clone();event.waitUntil(caches.open(CACHE).then(cache=>cache.put(event.request,copy)));}return response;}).catch(()=>caches.match(event.request).then(cached=>cached||Response.error())));
});
function seenEvent(id){return new Promise((resolve,reject)=>{
 const open=indexedDB.open('svpaul-push-events',1);open.onupgradeneeded=()=>open.result.createObjectStore('seen');open.onerror=()=>reject(open.error);
 open.onsuccess=()=>{const db=open.result,tx=db.transaction('seen','readwrite'),store=tx.objectStore('seen');let seen=false;const get=store.get(id);get.onsuccess=()=>{seen=Boolean(get.result);if(!seen)store.put(Date.now(),id);const cursor=store.openCursor();cursor.onsuccess=()=>{const c=cursor.result;if(c){if(c.value<Date.now()-30*86400000)c.delete();c.continue();}};};tx.oncomplete=()=>{db.close();resolve(seen);};tx.onerror=()=>{db.close();reject(tx.error);};};
 });}
self.addEventListener('push',event=>{event.waitUntil((async()=>{
 let data;try{data=event.data.json();}catch{return;}
 if(data.type==='sustituciones-test'&&/^[a-f0-9-]{36}$/.test(data.testId||'')){await self.registration.showNotification('Prueba de avisos · Sustituciones',{body:'Este dispositivo ha recibido el aviso push de prueba.',icon:'./general-ios.png',tag:'prueba-'+data.testId,data:{type:'sustituciones-test'}});const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});windows.forEach(client=>client.postMessage({type:'push-test-received',testId:data.testId}));return;}
 if(data.type!=='sustituciones'||!/^[A-Za-z0-9_-]{43}$/.test(data.eventId||''))return;
 if(await seenEvent(data.eventId))return;
 await self.registration.showNotification('SVPAULCAR Apps',{body:'Sustituciones: hay una actualización disponible',icon:'./general-ios.png',tag:'sustituciones-'+data.eventId,data:{type:'sustituciones'},renotify:false});
 })());});
self.addEventListener('notificationclick',event=>{event.notification.close();if(!['sustituciones','sustituciones-test'].includes(event.notification.data?.type))return;event.waitUntil((async()=>{
 const target=new URL('./#sustituciones',self.registration.scope).href;
 const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});
 const existing=windows.find(client=>client.url.startsWith(self.registration.scope));
 if(existing){await existing.navigate(target);await existing.focus();}else await self.clients.openWindow(target);
 })());});

self.addEventListener('message',event=>{if(event.data?.type==='push-self-test-capability')event.ports?.[0]?.postMessage({supportsPushTest:true});});
