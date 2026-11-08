// src/push-crypto.js
var enc = new TextEncoder();
var b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
var un64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
var concat = (...a) => {
  const out = new Uint8Array(a.reduce((n, b) => n + b.length, 0));
  let offset = 0;
  for (const b of a) {
    out.set(b, offset);
    offset += b.length;
  }
  return out;
};
async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function expand(key, info, length) {
  return (await hmac(key, concat(info, new Uint8Array([1])))).slice(0, length);
}
async function cifrar(subscription, payload) {
  const ua = un64(subscription.keys.p256dh), auth = un64(subscription.keys.auth);
  if (ua.length !== 65 || auth.length !== 16) throw Error("Claves de suscripci\xF3n no v\xE1lidas");
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const server = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const client = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: client }, pair.privateKey, 256));
  const ikm = await expand(await hmac(auth, secret), concat(enc.encode("WebPush: info\0"), ua, server), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16)), prk = await hmac(salt, ikm);
  const key = await expand(prk, enc.encode("Content-Encoding: aes128gcm\0"), 16), nonce = await expand(prk, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(enc.encode(JSON.stringify(payload)), new Uint8Array([2]))));
  const header = new Uint8Array(21);
  header.set(salt);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = 65;
  return concat(header, server, cipher);
}
async function vapid(endpoint, env) {
  const header = b64(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" }))), body2 = b64(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1e3) + 3600, sub: env.VAPID_SUBJECT })));
  const text = header + "." + body2;
  const key = await crypto.subtle.importKey("jwk", JSON.parse(env.VAPID_PRIVATE_JWK), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(text));
  return text + "." + b64(signature);
}
async function buildPushPayload(message, subscription, keys) {
  const publicBytes = un64(keys.publicKey);
  const privateJwk = { kty: "EC", crv: "P-256", x: b64(publicBytes.slice(1, 33)), y: b64(publicBytes.slice(33, 65)), d: keys.privateKey };
  const env = { VAPID_PRIVATE_JWK: JSON.stringify(privateJwk), VAPID_PUBLIC_KEY: keys.publicKey, VAPID_SUBJECT: keys.subject };
  const data = typeof message.data === "string" ? JSON.parse(message.data) : message.data;
  return { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: String(message.options?.ttl || 60), ...message.options?.urgency ? { Urgency: message.options.urgency } : {}, Authorization: "vapid t=" + await vapid(subscription.endpoint, env) + ", k=" + keys.publicKey }, body: await cifrar(subscription, data) };
}

// src/security.js
var enc2 = new TextEncoder();
var b642 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
var unb64 = (value) => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4)), (c) => c.charCodeAt(0));
var randomToken = () => b642(crypto.getRandomValues(new Uint8Array(32)));
async function hash(value) {
  return b642(await crypto.subtle.digest("SHA-256", enc2.encode(value)));
}
async function equal(a, b) {
  const aa = await hash(a), bb = await hash(b);
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}
async function passwordHash(password, salt, iterations = 1e5, pepper = "") {
  const secret = await crypto.subtle.importKey("raw", enc2.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prepared = await crypto.subtle.sign("HMAC", secret, enc2.encode(password));
  const key = await crypto.subtle.importKey("raw", prepared, "PBKDF2", false, ["deriveBits"]);
  return b642(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(salt), iterations, hash: "SHA-256" }, key, 256));
}
async function verifyPassword(password, record, pepper) {
  if (typeof password !== "string" || password.length > 256 || !record || !pepper) return false;
  const [algorithm, iterations, salt, digest] = record.split("$");
  if (algorithm !== "pbkdf2" || Number(iterations) < 1e5 || Number(iterations) > 1e5 || !salt || !digest) return false;
  return equal(await passwordHash(password, salt, Number(iterations), pepper), digest);
}
function safeURL(value) {
  const u = new URL(value);
  if (u.protocol !== "https:" || u.username || u.password || value.length > 2048) throw new Error("URL HTTPS no v\xE1lida.");
  return u.href;
}
function cleanApp(input) {
  const name = String(input.name || "").trim();
  if (!name || name.length > 80) throw new Error("El nombre debe tener entre 1 y 80 caracteres.");
  const icon = String(input.icon || "general-ios.png");
  const icons = ["general-ios.png", "comedor.jpg", "base-datos.png", "justificantes.png", "sustituciones.png", "fichaje.png", "filmoteca.png", "parte-tic.png", "parte-mantenimiento.png"];
  if (!icons.includes(icon)) throw new Error("Selecciona un icono del cat\xE1logo.");
  return { name, url: safeURL(input.url), icon };
}
function cleanSubscription(s) {
  const u = new URL(s.endpoint);
  const host = u.hostname;
  const allowed = host === "fcm.googleapis.com" || host === "updates.push.services.mozilla.com" || host === "web.push.apple.com" || host.endsWith(".push.apple.com") || host.endsWith(".notify.windows.com");
  if (!allowed || u.protocol !== "https:" || u.port || u.username || u.password || u.hash || s.endpoint.length > 2048) throw new Error("Servicio push no admitido.");
  if (!s.keys || unb64(s.keys.p256dh).length !== 65 || unb64(s.keys.auth).length !== 16) throw new Error("Suscripci\xF3n no v\xE1lida.");
  return { endpoint: u.href, expirationTime: null, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } };
}

// src/worker.js
var now = () => Math.floor(Date.now() / 1e3);
var json = (body2, status = 200) => new Response(JSON.stringify(body2), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
async function body(req) {
  const text = await req.text();
  if (text.length > 8192) throw new Error("Solicitud demasiado grande.");
  return JSON.parse(text);
}
async function limit(env, key, max, seconds) {
  const time = now();
  const result = await env.DB.prepare("INSERT INTO rate_limits(key,hits,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN expires<=? THEN 1 ELSE hits+1 END, expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING hits").bind(key, time + seconds, time, time).first();
  return result.hits <= max;
}
async function session(req, env) {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
  return Boolean(await env.DB.prepare("SELECT expires FROM sessions WHERE token_hash=? AND expires>?").bind(await hash(token), now()).first());
}
async function sendWebPush(endpoint, payload) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15e3);
  try {
    return await fetch(endpoint, { ...payload, redirect: "manual", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
async function route(req, env, ctx) {
  if(new URL(req.url).pathname.startsWith('/native/'))return nativeDataRoute(req,env);
  if(new URL(req.url).pathname.startsWith('/tic/'))return ticRoute(req,env,ctx);
  const url = new URL(req.url), path = url.pathname;
  if (path === "/health" && req.method === "GET") return json({ ok: true });
  if (path === "/config" && req.method === "GET") return json({ pushEnabled: env.PUSH_SUBSCRIPTIONS_ENABLED === "true" && Boolean(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY), deliveryEnabled: env.PUSH_ENABLED === "true", publicKey: env.PUSH_SUBSCRIPTIONS_ENABLED === "true" ? env.VAPID_PUBLIC_KEY || "" : "" });
  const ip = await hash(req.headers.get("CF-Connecting-IP") || "local");
  if (path === "/auth/login" && req.method === "POST") {
    if (!env.PASSWORD_RECORD || !env.PASSWORD_PEPPER) return json({ error: "El acceso personal a\xFAn no est\xE1 configurado." }, 503);
    if (!await limit(env, "login:" + ip, 5, 900)) return json({ error: "Demasiados intentos. Espera 15 minutos." }, 429);
    const input = await body(req);
    if (!await verifyPassword(input.password, env.PASSWORD_RECORD, env.PASSWORD_PEPPER)) return json({ error: "Contrase\xF1a incorrecta." }, 401);
    const token = randomToken(), expires = now() + 30 * 86400;
    await env.DB.prepare("INSERT INTO sessions(token_hash,expires) VALUES(?,?)").bind(await hash(token), expires).run();
    return json({ token, expires });
  }
  if (path === "/auth/logout" && req.method === "POST") {
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hash(token)).run();
    return json({ ok: true });
  }
  if (path === "/apps" || path.startsWith("/apps/")) {
    if (!await session(req, env)) return json({ error: "Inicia sesi\xF3n en Mis apps." }, 401);
    if (path === "/apps" && req.method === "GET") return json({ apps: (await env.DB.prepare("SELECT id,name,url,icon,position FROM apps ORDER BY position,id").all()).results });
    if (path === "/apps" && req.method === "POST") {
      const app = cleanApp(await body(req)), id2 = crypto.randomUUID();
      if ((await env.DB.prepare("SELECT COUNT(*) AS total FROM apps").first()).total >= 100) return json({ error: "M\xE1ximo 100 aplicaciones." }, 400);
      await env.DB.prepare("INSERT INTO apps(id,name,url,icon,position) SELECT ?,?,?,?,COALESCE(MAX(position),-1)+1 FROM apps").bind(id2, app.name, app.url, app.icon).run();
      return json({ id: id2 }, 201);
    }
    if (path === "/apps/order" && req.method === "PUT") {
      const { ids } = await body(req), existing = (await env.DB.prepare("SELECT id FROM apps").all()).results.map((a) => a.id);
      if (!Array.isArray(ids) || ids.length !== existing.length || new Set(ids).size !== ids.length || ids.some((id2) => !existing.includes(id2))) return json({ error: "Orden no v\xE1lido. Recarga la lista." }, 400);
      if (ids.length) await env.DB.batch(ids.map((id2, i) => env.DB.prepare("UPDATE apps SET position=? WHERE id=?").bind(i, id2)));
      return json({ ok: true });
    }
    const id = path.slice(6);
    if (!/^[a-f0-9-]{36}$/.test(id)) return json({ error: "Aplicaci\xF3n no v\xE1lida." }, 400);
    if (req.method === "PUT") {
      const app = cleanApp(await body(req));
      await env.DB.prepare("UPDATE apps SET name=?,url=?,icon=? WHERE id=?").bind(app.name, app.url, app.icon, id).run();
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await env.DB.prepare("DELETE FROM apps WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }
  if (path === "/subscriptions" && req.method === "POST") {
    if (env.PUSH_SUBSCRIPTIONS_ENABLED !== "true") return json({ error: "Las notificaciones a\xFAn no est\xE1n activadas." }, 503);
    if (!await limit(env, "subscribe:" + ip, 20, 3600)) return json({ error: "Demasiadas solicitudes." }, 429);
    const sub = cleanSubscription(await body(req)), id = await hash(sub.endpoint);
    await env.DB.prepare("INSERT INTO subscriptions(id,endpoint,payload,created) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload").bind(id, sub.endpoint, JSON.stringify(sub), now()).run();
    return json({ ok: true });
  }
  if (path === "/subscriptions" && req.method === "DELETE") {
    const sub = cleanSubscription(await body(req)), id = await hash(sub.endpoint), row = await env.DB.prepare("SELECT payload FROM subscriptions WHERE id=?").bind(id).first();
    if (row && await equal(JSON.parse(row.payload).keys.auth, sub.keys.auth)) await env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(id).run();
    return json({ ok: true });
  }
  if (path === "/subscriptions/status" && req.method === "POST") {
    const sub = cleanSubscription(await body(req)), id = await hash(sub.endpoint), row = await env.DB.prepare("SELECT payload FROM subscriptions WHERE id=?").bind(id).first();
    const stored = row ? JSON.parse(row.payload) : null;
    return json({ registered: Boolean(stored && await equal(stored.keys.auth, sub.keys.auth) && await equal(stored.keys.p256dh, sub.keys.p256dh)), deliveryEnabled: env.PUSH_ENABLED === "true" });
  }
  if (path === "/subscriptions/test" && req.method === "POST") {
    if (env.PUSH_ENABLED !== "true") return json({ error: "Los env\xEDos push est\xE1n desactivados en el servidor." }, 503);
    if (!await limit(env, "push-test:" + ip, 6, 900)) return json({ error: "Espera unos minutos antes de repetir la prueba." }, 429);
    const sub = cleanSubscription(await body(req)), id = await hash(sub.endpoint), row = await env.DB.prepare("SELECT payload FROM subscriptions WHERE id=?").bind(id).first();
    const stored = row ? JSON.parse(row.payload) : null;
    if (!stored || !await equal(stored.keys.auth, sub.keys.auth) || !await equal(stored.keys.p256dh, sub.keys.p256dh)) return json({ error: "Este dispositivo no est\xE1 registrado. Activa sus avisos antes de probar." }, 409);
    if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) return json({ error: "Falta configurar la firma del servicio de avisos." }, 503);
    const testId = crypto.randomUUID();
    let status = 0, stage = "preparar";
    try {
      const payload = await buildPushPayload({ data: JSON.stringify({ type: "sustituciones-test", testId }), options: { ttl: 120, urgency: "high" } }, sub, { subject: env.VAPID_SUBJECT, publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY });
      stage = "conectar";
      status = (await sendWebPush(sub.endpoint, payload)).status;
    } catch (e) {
      return json({ error: "No se ha podido " + stage + " el aviso push de prueba (" + String(e.name || "Error").replace(/[^A-Za-z]/g, "") + "). Comprueba la configuraci\xF3n del servicio.", stage }, 502);
    }
    if (status === 404 || status === 410) {
      await env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(id).run();
      return json({ error: "La suscripci\xF3n ha caducado. Desactiva y vuelve a activar los avisos en este dispositivo." }, 410);
    }
    if (status < 200 || status >= 300) return json({ error: "El servicio de notificaciones rechaz\xF3 la prueba (HTTP " + status + ")." + ([401, 403].includes(status) ? " Es necesario revisar la firma de los avisos." : ""), providerStatus: status }, 502);
    return json({ ok: true, testId, accepted: true }, 202);
  }
  if (path === "/publish/status" && req.method === "GET") {
    if (!env.PUBLISH_SECRET || !await equal(req.headers.get("X-Publish-Key") || "", env.PUBLISH_SECRET)) return json({ error: "No autorizado." }, 401);
    const subs = await env.DB.prepare("SELECT COUNT(*) AS total FROM subscriptions").first(), events = await env.DB.prepare("SELECT COUNT(*) AS total FROM events").first();
    return json({ ok: true, deliveryEnabled: env.PUSH_ENABLED === "true", subscriptions: subs.total, acceptedPublications: events.total });
  }
  if (path === "/publish/sustituciones" && req.method === "POST") {
    if (!env.PUBLISH_SECRET || !await equal(req.headers.get("X-Publish-Key") || "", env.PUBLISH_SECRET)) return json({ error: "No autorizado." }, 401);
    if (env.PUSH_ENABLED !== "true") return json({ error: "Env\xEDo push desactivado." }, 503);
    const input = await body(req);
    if (input.source !== "sustituciones" || !/^\d{4}-\d{2}-\d{2}$/.test(input.date) || !Number.isInteger(input.version) || input.version < 1 || !/^[a-f0-9]{64}$/.test(input.contentHash)) return json({ error: "Publicaci\xF3n no v\xE1lida." }, 400);
    const id = await hash(input.date + ":" + input.version + ":" + input.contentHash);
    await env.DB.batch([
      env.DB.prepare("INSERT OR IGNORE INTO events(id,date,content_hash,created) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM publication_heads WHERE date=? AND (version>=? OR content_hash=?))").bind(id, input.date, input.version + ":" + input.contentHash, now(), input.date, input.version, input.contentHash),
      env.DB.prepare("INSERT OR IGNORE INTO deliveries(event_id,subscription_id) SELECT ?,id FROM subscriptions WHERE created<=(SELECT created FROM events WHERE id=?)").bind(id, id),
      env.DB.prepare("INSERT INTO publication_heads(date,version,content_hash) VALUES(?,?,?) ON CONFLICT(date) DO UPDATE SET version=excluded.version,content_hash=excluded.content_hash WHERE excluded.version>publication_heads.version").bind(input.date, input.version, input.contentHash)
    ]);
    ctx.waitUntil(deliver(env));
    return json({ ok: true, eventId: id }, 202);
  }
  return json({ error: "Ruta no disponible." }, 404);
}
async function deliver(env) {
  if (env.PUSH_ENABLED !== "true" || !env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) return;
  const rows = (await env.DB.prepare("SELECT d.event_id,d.subscription_id,d.attempts,s.payload FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id WHERE d.status='pending' AND d.retry_after<=? AND d.attempts<5 LIMIT 30").bind(now()).all()).results;
  for (const row of rows) {
    const claim = await env.DB.prepare("UPDATE deliveries SET status='sending',retry_after=? WHERE event_id=? AND subscription_id=? AND status='pending'").bind(now() + 300, row.event_id, row.subscription_id).run();
    if (!claim.meta.changes) continue;
    let status = 0;
    try {
      const subscription = cleanSubscription(JSON.parse(row.payload));
      const message = { data: JSON.stringify({ type: "sustituciones", eventId: row.event_id }), options: { ttl: 3600 } };
      const payload = await buildPushPayload(message, subscription, { subject: env.VAPID_SUBJECT, publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY });
      status = (await sendWebPush(subscription.endpoint, payload)).status;
    } catch {
    }
    if (status === 404 || status === 410) {
      await env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(row.subscription_id).run();
      await env.DB.prepare("UPDATE deliveries SET status='expired' WHERE event_id=? AND subscription_id=?").bind(row.event_id, row.subscription_id).run();
    } else {
      const done = status >= 200 && status < 300;
      const terminal = !done && status >= 400 && status < 500 && status !== 429;
      await env.DB.prepare("UPDATE deliveries SET status=?,attempts=attempts+1,retry_after=? WHERE event_id=? AND subscription_id=?").bind(done ? "sent" : terminal || row.attempts >= 4 ? "failed" : "pending", now() + Math.min(3600, 60 * 2 ** row.attempts), row.event_id, row.subscription_id).run();
    }
  }
}
// Avisos TIC: tablas y suscripciones independientes del Compendio.
const TIC_PUBLIC_JWK = {"kty":"RSA","n":"zsv3bkTinQkIP-em1jClChc4oWRs6kWs9M7WWZZcckae4_4fDc54kRZpwgTLEJrBqZhS8dtoYUoVUVXyKqxjrG8US0Z0xBXydyUzZRcx-FNUoNGZ_q_7GexhE2thmgH9Uj0tI-mOGK9GZ2RPfCTCIrx1DhLo5ajaUdTiFy5tcgooqamTRF0uRNxp9v90nfU2aAsCc7PfKlQ5KVuw6w5aHPbexj13vv7CFtScsVHTDxVRHYv8VlLlx5lr9YeCgleLo395WOBLfr6B0ixPyIFuTYpxHoRsxwsEjjGhIVx2gf0Nrsg_zCVHP06R468WAnKbK2deHuOzY_MQyNFNLZ2EPQ","e":"AQAB"};
const TIC_APP_URL='https://svpaulcarapps.github.io/control-partes-tic/';
async function ticClaims(req,kind){
 const token=(req.headers.get('Authorization')||'').replace(/^Bearer /,'');
 if(token.length>5000)throw Error('Firma no válida');
 const parts=token.split('.');if(parts.length!==3)throw Error('Firma necesaria');
 const header=JSON.parse(new TextDecoder().decode(unb64(parts[0]))),claims=JSON.parse(new TextDecoder().decode(unb64(parts[1])));
 if(header.alg!=='RS256'||claims.aud!=='partes-tic'||claims.kind!==kind||claims.sub!=='owner'||!Number.isInteger(claims.exp)||!Number.isInteger(claims.iat)||claims.exp<=now()||claims.iat>now()+60||claims.exp-claims.iat>(kind==='device'?28800:600))throw Error('Sesión no válida');
 const key=await crypto.subtle.importKey('jwk',TIC_PUBLIC_JWK,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(parts[2]),enc2.encode(parts[0]+'.'+parts[1])))throw Error('Firma no válida');return claims;
}
async function ticSchema(env){await env.DB.batch([
 env.DB.prepare("CREATE TABLE IF NOT EXISTS tic_subscriptions(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created INTEGER NOT NULL)"),
 env.DB.prepare("CREATE TABLE IF NOT EXISTS tic_events(id TEXT PRIMARY KEY,created INTEGER NOT NULL)"),
 env.DB.prepare("CREATE TABLE IF NOT EXISTS tic_deliveries(event_id TEXT NOT NULL,subscription_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,retry_after INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(event_id,subscription_id))")]);}
async function ticRoute(req,env,ctx){
 const path=new URL(req.url).pathname;
 if(path==='/tic/config'&&req.method==='GET')return json({publicKey:env.VAPID_PUBLIC_KEY||'',enabled:env.PUSH_ENABLED==='true',appURL:TIC_APP_URL});
 if(path==='/tic/publish'&&req.method==='POST'){
  let claim;try{claim=await ticClaims(req,'event');}catch{return json({error:'Firma TIC no válida.'},401);}
  if(!/^[a-f0-9]{64}$/.test(claim.eventId||''))return json({error:'Parte no válido.'},400);
  if(env.PUSH_ENABLED!=='true')return json({error:'Avisos desactivados.'},503);
  await ticSchema(env);const created=now();await env.DB.batch([
   env.DB.prepare('INSERT OR IGNORE INTO tic_events(id,created) VALUES(?,?)').bind(claim.eventId,created),
   env.DB.prepare('INSERT OR IGNORE INTO tic_deliveries(event_id,subscription_id) SELECT ?,id FROM tic_subscriptions WHERE created<=(SELECT created FROM tic_events WHERE id=?)').bind(claim.eventId,claim.eventId)]);
  ctx.waitUntil(ticDeliver(env));return json({ok:true,eventId:claim.eventId},202);
 }
 let claim;try{claim=await ticClaims(req,'device');}catch{return json({error:'Abre el panel con tu cuenta autorizada para conectar los avisos.'},401);}
 await ticSchema(env);
 if(['/tic/subscriptions','/tic/status','/tic/test'].includes(path)){
  const sub=cleanSubscription(await body(req)),id=await hash(sub.endpoint);
  if(path==='/tic/subscriptions'&&req.method==='POST'){
   await env.DB.prepare('INSERT INTO tic_subscriptions(id,payload,created) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload').bind(id,JSON.stringify(sub),now()).run();return json({ok:true});
  }
  const row=await env.DB.prepare('SELECT payload FROM tic_subscriptions WHERE id=?').bind(id).first(),stored=row?JSON.parse(row.payload):null;
  const registered=!!stored&&await equal(stored.keys.auth,sub.keys.auth)&&await equal(stored.keys.p256dh,sub.keys.p256dh);
  if(path==='/tic/status'&&req.method==='POST')return json({registered,enabled:env.PUSH_ENABLED==='true'});
  if(path==='/tic/subscriptions'&&req.method==='DELETE'){
   if(registered)await env.DB.prepare('DELETE FROM tic_subscriptions WHERE id=?').bind(id).run();return json({ok:true});
  }
  if(path==='/tic/test'&&req.method==='POST'){
   if(!registered)return json({error:'Activa antes los avisos en este dispositivo.'},409);
   if(!await limit(env,'tic-test:'+id,5,900))return json({error:'Espera unos minutos para repetir la prueba.'},429);
   const payload=await buildPushPayload({data:JSON.stringify({type:'partes-tic-test',eventId:crypto.randomUUID()}),options:{ttl:120,urgency:'high'}},sub,{subject:env.VAPID_SUBJECT,publicKey:env.VAPID_PUBLIC_KEY,privateKey:env.VAPID_PRIVATE_KEY});
   const response=await sendWebPush(sub.endpoint,payload);return response.status>=200&&response.status<300?json({ok:true},202):json({error:'El dispositivo ha rechazado la prueba (HTTP '+response.status+').'},502);
  }
 }
 return json({error:'Ruta TIC no disponible.'},404);
}
async function ticDeliver(env){
 if(env.PUSH_ENABLED!=='true'||!env.VAPID_PUBLIC_KEY||!env.VAPID_PRIVATE_KEY)return;
 await ticSchema(env);
 await env.DB.batch([
 env.DB.prepare("UPDATE tic_deliveries SET status='pending' WHERE status='sending' AND retry_after<=?").bind(now()),
 env.DB.prepare('DELETE FROM tic_deliveries WHERE event_id IN (SELECT id FROM tic_events WHERE created<?)').bind(now()-2592000),
 env.DB.prepare('DELETE FROM tic_events WHERE created<?').bind(now()-2592000)]);
 const rows=(await env.DB.prepare("SELECT d.event_id,d.subscription_id,d.attempts,s.payload FROM tic_deliveries d JOIN tic_subscriptions s ON s.id=d.subscription_id WHERE d.status='pending' AND d.retry_after<=? AND d.attempts<5 LIMIT 30").bind(now()).all()).results;
 for(const row of rows){
  const claim=await env.DB.prepare("UPDATE tic_deliveries SET status='sending',retry_after=? WHERE event_id=? AND subscription_id=? AND status='pending'").bind(now()+300,row.event_id,row.subscription_id).run();if(!claim.meta.changes)continue;
  let status=0;try{const sub=cleanSubscription(JSON.parse(row.payload));const payload=await buildPushPayload({data:JSON.stringify({type:'partes-tic',eventId:row.event_id}),options:{ttl:86400,urgency:'high'}},sub,{subject:env.VAPID_SUBJECT,publicKey:env.VAPID_PUBLIC_KEY,privateKey:env.VAPID_PRIVATE_KEY});status=(await sendWebPush(sub.endpoint,payload)).status;}catch{}
  if(status===404||status===410){await env.DB.prepare('DELETE FROM tic_subscriptions WHERE id=?').bind(row.subscription_id).run();}
  const done=status>=200&&status<300,terminal=status>=400&&status<500&&status!==429;
  await env.DB.prepare('UPDATE tic_deliveries SET status=?,attempts=attempts+1,retry_after=? WHERE event_id=? AND subscription_id=?').bind(done?'sent':terminal||row.attempts>=4?'failed':'pending',now()+Math.min(3600,60*2**row.attempts),row.event_id,row.subscription_id).run();
 }
}

var worker_default = {
  async fetch(req, env, ctx) {
    const origin = req.headers.get("Origin");
    if (origin && origin !== env.ALLOWED_ORIGIN) return json({ error: "Origen no autorizado." }, 403);
    let response;
    if (req.method === "OPTIONS") response = new Response(null, { status: 204 });
    else {
      try {
        response = await route(req, env, ctx);
      } catch {
        response = json({ error: "No se ha podido completar la solicitud." }, 400);
      }
    }
    const headers = new Headers(response.headers);
    if (origin === env.ALLOWED_ORIGIN) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization");
      headers.set("Vary", "Origin");
    }
    headers.set("Cache-Control", "no-store");
    return new Response(response.body, { status: response.status, headers });
  },
  async scheduled(event, env, ctx) {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE expires<=?").bind(now()),
      env.DB.prepare("DELETE FROM rate_limits WHERE expires<=?").bind(now()),
      env.DB.prepare("UPDATE deliveries SET status='pending' WHERE status='sending' AND retry_after<=?").bind(now()),
      env.DB.prepare("DELETE FROM deliveries WHERE subscription_id NOT IN (SELECT id FROM subscriptions)"),
      env.DB.prepare("DELETE FROM deliveries WHERE event_id IN (SELECT id FROM events WHERE created<?)").bind(now() - 2592e3),
      env.DB.prepare("DELETE FROM events WHERE created<?").bind(now() - 2592e3)
    ]);
    ctx.waitUntil(deliver(env));
    ctx.waitUntil(ticDeliver(env));
  }
};
export {
  worker_default as default,
  deliver,
  route
};

// Pasarela autenticada: reenvía operaciones concretas; no almacena datos ni sesiones de las apps.
const NATIVE_RPC_METHODS={
 tic:new Set(['obtenerHojasCursos','obtenerPartesTIC','guardarCambiosParte','obtenerCredencialPushTic']),
 comedor:new Set(['inicial','previsualizarPedido','guardarPedido','entrarComedor','comprobarSesionComedor','salirComedor','resumen','cambiarPedido','guardarFiado','pagarFiado','avisosComedor','leerAviso','prepararPedido','menuDelDia','alumnosComedorDia','ajustesAvisosComedor','guardarDispositivoComedor','generarPdfComedor'])
};
async function nativeDataRoute(req,env){
 const match=new URL(req.url).pathname.match(/^\/native\/(tic|comedor)\/rpc$/);
 if(!match||req.method!=='POST')return json({error:'Operación no permitida.'},404);
 const service=match[1],token=(req.headers.get('Authorization')||'').replace(/^Bearer /,'');
 if(token.length>4096||!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token))return json({error:'Conecta tu cuenta del colegio.'},401);
 let claims;try{claims=JSON.parse(new TextDecoder().decode(unb64(token.split('.')[1])));}catch{return json({error:'Sesión no válida.'},401);}
 if(claims.aud!=='svpaulcar-native-'+service||!Number.isInteger(claims.exp)||claims.exp<=now()||!Number.isInteger(claims.iat)||claims.iat>now()+30||claims.exp-claims.iat!==21600)return json({error:'La sesión ha caducado. Vuelve a conectar tu cuenta.'},401);
 const raw=await req.text();if(raw.length>65536)return json({error:'Solicitud demasiado grande.'},413);
 let input;try{input=JSON.parse(raw);}catch{return json({error:'Solicitud no válida.'},400);}
 if(!NATIVE_RPC_METHODS[service].has(input.method)||!Array.isArray(input.args)||input.args.length>8)return json({error:'Operación no permitida.'},400);
 const ip=req.headers.get('CF-Connecting-IP')||'unknown';
 if(!await limit(env,'native:'+service+':'+await hash(ip),180,60)||!await limit(env,'native-session:'+await hash(token),120,60))return json({error:'Espera unos segundos antes de volver a intentarlo.'},429);
 const endpoint=service==='tic'?env.TIC_DATA_API_URL:env.COMEDOR_DATA_API_URL;
 if(!endpoint||!/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/.test(endpoint))return json({error:'La conexión con los datos está en preparación.'},503);
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),55000);
 try{
  const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token,method:input.method,args:input.args}),redirect:'follow',signal:controller.signal});
  const url=new URL(response.url);if(url.protocol!=='https:'||!(url.hostname==='script.google.com'||url.hostname.endsWith('.googleusercontent.com')))throw Error('Respuesta no válida');
  if(!response.ok)return json({error:'No se ha podido conectar con los datos del colegio.'},502);
  const text=await response.text();if(text.length>12000000)return json({error:'El informe es demasiado grande.'},502);
  let result;try{result=JSON.parse(text);}catch{return json({error:'Google no ha permitido conectar con los datos.'},502);}
  if(result.ok!==true)return json({error:result.error||'No se pudo completar la operación.'},/sesión|sesion/i.test(result.error||'')?401:400);
  return json({result:result.result});
 }catch{return json({error:'No se ha podido conectar. Comprueba la conexión y vuelve a intentarlo.'},502);}finally{clearTimeout(timer);}
}
