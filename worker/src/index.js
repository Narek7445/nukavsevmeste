const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const TOKEN_TTL_SECONDS = 12 * 60 * 60;
const MAX_ARCHIVE_BYTES = 1_800_000;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/avif"]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN || "*";
  const headers = {
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
    "access-control-allow-headers": "Content-Type,Authorization",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
  if (allowed === "*") headers["access-control-allow-origin"] = "*";
  else if (origin === allowed) headers["access-control-allow-origin"] = origin;
  return headers;
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(request, env))) headers.set(key, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function importSigningKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function issueToken(secret) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ role: "admin", exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS })));
  const key = await importSigningKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return payload + "." + base64url(new Uint8Array(signature));
}

async function isAdmin(request, env) {
  if (!env.SESSION_SECRET) return false;
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  try {
    const key = await importSigningKey(env.SESSION_SECRET);
    const valid = await crypto.subtle.verify("HMAC", key, fromBase64url(parts[1]), new TextEncoder().encode(parts[0]));
    if (!valid) return false;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    return payload.role === "admin" && Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}




async function ensureArticlesTable(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS articles (slug TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '', content TEXT NOT NULL, cover_image TEXT, attachments_json TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL CHECK(status IN ('draft','published')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, published_at TEXT)").run();
}
function parseArticleRow(row) {
  if (!row) return null;
  let attachments=[];try{attachments=JSON.parse(row.attachments_json||"[]")}catch{}
  return {slug:row.slug,title:row.title,summary:row.summary||"",content:row.content||"",coverImage:row.cover_image||"",attachments:Array.isArray(attachments)?attachments:[],status:row.status,createdAt:row.created_at,updatedAt:row.updated_at,publishedAt:row.published_at||null};
}

async function readArchive(env) {
  const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("participants").first();
  if (!row) return [];
  try {
    const value = JSON.parse(row.value);
    return Array.isArray(value) ? value : [];
  } catch {
    throw new Error("Archive data in D1 is invalid JSON");
  }
}

function isHiddenPerformance(item) {
  return item?.hidden === true || item?.hidden === 1 ||
    ["true", "1"].includes(String(item?.hidden ?? "").trim().toLowerCase());
}

function publicArchive(participants) {
  const hiddenPhotoUrls = new Set();
  for (const item of participants) {
    if (!isHiddenPerformance(item)) continue;
    for (const src of [...(Array.isArray(item.photos) ? item.photos : []), item.photo || ""]) {
      if (typeof src === "string" && src) hiddenPhotoUrls.add(src);
    }
  }
  return participants.map(item => {
    if (isHiddenPerformance(item)) return item;
    const photos = (Array.isArray(item.photos) ? item.photos : []).filter(src =>
      typeof src === "string" && src && !hiddenPhotoUrls.has(src)
    );
    const photo = item.photo && !hiddenPhotoUrls.has(item.photo) ? item.photo : (photos[0] || "");
    const primaryPhoto = item.primaryPhoto && !hiddenPhotoUrls.has(item.primaryPhoto) &&
      (photos.includes(item.primaryPhoto) || item.primaryPhoto === photo) ? item.primaryPhoto : "";
    return { ...item, photos, photo, primaryPhoto };
  });
}

function validateArchive(value) {
  if (!Array.isArray(value)) return "Ожидается массив выступлений.";
  if (value.length > 5000) return "В архиве слишком много записей (максимум 5000).";
  const seenPerformances = new Set();
  const normalizePart = value => String(value ?? "").normalize("NFKC").trim().replace(/\\s+/g, " ").toLocaleLowerCase("ru");
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return "Каждая запись должна быть объектом.";
    if (!String(item.firstName || "").trim() || !String(item.song || "").trim()) {
      return "У каждой записи должны быть имя и название песни.";
    }
    const duplicateKey = JSON.stringify([
      normalizePart(item.firstName), normalizePart(item.lastName),
      normalizePart(item.season), normalizePart(item.episode), normalizePart(item.song)
    ]);
    if (seenPerformances.has(duplicateKey)) {
      return "В архиве обнаружено повторное выступление: один участник не может иметь одинаковую песню в том же сезоне и выпуске.";
    }
    seenPerformances.add(duplicateKey);
    if (item.videoUrl) { try { const videoUrl = new URL(String(item.videoUrl)); if (videoUrl.protocol !== "https:" || !["youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be", "www.youtube-nocookie.com"].includes(videoUrl.hostname) || String(item.videoUrl).length > 500) return "Ссылка на выступление должна вести на YouTube и использовать HTTPS."; } catch { return "Укажите корректную ссылку на видео выступления."; } }
    if (item.starGuests !== undefined && (!Array.isArray(item.starGuests) || item.starGuests.length > 20 || item.starGuests.some(g => !g || typeof g.name !== "string" || !g.name.trim() || g.name.length > 100 || typeof g.photo !== "string" || !/^https:\/\//.test(g.photo)))) return "Список звёздных гостей некорректен (максимум 20, нужны имя и HTTPS-фото).";
    if (typeof item.photo === "string" && item.photo.startsWith("data:")) return "Фотографии нужно загрузить в хранилище R2, а не сохранять в JSON.";
    if (Array.isArray(item.photos) && item.photos.some(photo => typeof photo === "string" && photo.startsWith("data:"))) {
      return "Фотографии нужно загрузить в хранилище R2, а не сохранять в JSON.";
    }
  }
  return null;
}

async function ensureVoteTable(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS performance_votes (performance_id TEXT NOT NULL, voter_id TEXT NOT NULL, choice TEXT NOT NULL CHECK(choice IN ('yes','no')), created_at TEXT NOT NULL, PRIMARY KEY(performance_id, voter_id))").run();
}

async function readPolls(env, ids) {
  await ensureVoteTable(env);
  const result = ids.length
    ? await env.DB.prepare("SELECT performance_id, choice, COUNT(*) AS count FROM performance_votes WHERE performance_id IN (" + ids.map(() => "?").join(",") + ") GROUP BY performance_id, choice").bind(...ids).all()
    : await env.DB.prepare("SELECT performance_id, choice, COUNT(*) AS count FROM performance_votes GROUP BY performance_id, choice").all();
  const polls = {};
  for (const id of ids) polls[id] = { yes: 0, no: 0 };
  for (const row of result.results || []) {
    if (!polls[row.performance_id]) polls[row.performance_id] = { yes: 0, no: 0 };
    polls[row.performance_id][row.choice] = Number(row.count) || 0;
  }
  return polls;
}



async function ensureSitePollVoteTable(env){await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_poll_votes (poll_id TEXT NOT NULL, voter_id TEXT NOT NULL, option_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(poll_id,voter_id))").run()}
async function ensureSitePollMultiVoteTable(env){await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_poll_multi_votes (poll_id TEXT NOT NULL, voter_id TEXT NOT NULL, option_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(poll_id,voter_id,option_id))").run()}
async function getSitePolls(env){const row=await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("site_polls").first();let polls=[];try{polls=row?JSON.parse(row.value):[]}catch{}return Array.isArray(polls)?polls:[]}
async function getSitePollResults(env,pollId){await ensureSitePollVoteTable(env);await ensureSitePollMultiVoteTable(env);const [legacy,multi]=await Promise.all([env.DB.prepare("SELECT option_id,COUNT(*) AS count FROM site_poll_votes WHERE poll_id=? GROUP BY option_id").bind(pollId).all(),env.DB.prepare("SELECT option_id,COUNT(*) AS count FROM site_poll_multi_votes WHERE poll_id=? GROUP BY option_id").bind(pollId).all()]);const counts={};let total=0;for(const r of [...(legacy.results||[]),...(multi.results||[])]){counts[r.option_id]=(counts[r.option_id]||0)+(Number(r.count)||0);total+=Number(r.count)||0}return {counts,total}}

async function ensureCommunityTables(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT NOT NULL, country TEXT NOT NULL, page TEXT NOT NULL, created_at TEXT NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', message TEXT NOT NULL, created_at TEXT NOT NULL)").run();
}

async function cachedJsonResponse(request, ttlSeconds, createResponse) {
  const cache = caches.default;
  const cacheRequest = new Request(request.url, { method: "GET" });
  try {
    const cached = await cache.match(cacheRequest);
    if (cached) return cached;
  } catch {}

  const response = await createResponse();
  if (!response.ok) return response;

  const headers = new Headers(response.headers);
  headers.set("cache-control", "public, max-age=" + ttlSeconds);
  const cacheable = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
  try { await cache.put(cacheRequest, cacheable.clone()); } catch {}
  return cacheable;
}

async function invalidatePublicCache(request, path) {
  try {
    const cacheRequest = new Request(new URL(path, request.url).toString(), { method: "GET" });
    await caches.default.delete(cacheRequest);
  } catch {}
}

async function handleApi(request, env, url) {
  const path = url.pathname;



  if (request.method === "POST" && path === "/api/analytics/view") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
    const visitorId = String(body?.visitorId || "");
    const page = String(body?.page || "/").slice(0, 120);
    if (!/^[a-zA-Z0-9._-]{16,100}$/.test(visitorId) || !/^\/[a-zA-Z0-9._/-]*$/.test(page)) return json({ error: "Некорректные данные посещения." }, 400);
    try {
      await ensureCommunityTables(env);
      const country = String(request.cf?.country || "XX").toUpperCase().slice(0, 2);
      await env.DB.prepare("INSERT INTO site_visits (visitor_id, country, page, created_at) VALUES (?, ?, ?, ?)")
        .bind(visitorId, country, page, new Date().toISOString()).run();
      return json({ ok: true }, 200, { "cache-control": "no-store" });
    } catch (error) { return json({ error: "Не удалось записать посещение.", detail: error.message }, 500); }
  }

  if (request.method === "POST" && path === "/api/feedback") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
    const name = String(body?.name || "").trim().slice(0, 80);
    const message = String(body?.message || "").trim();
    if (String(body?.website || "").trim()) return json({ ok: true });
    if (message.length < 5 || message.length > 2000) return json({ error: "Отзыв должен содержать от 5 до 2000 символов." }, 400);
    try {
      await ensureCommunityTables(env);
      await env.DB.prepare("INSERT INTO site_feedback (name, message, created_at) VALUES (?, ?, ?)")
        .bind(name, message, new Date().toISOString()).run();
      return json({ ok: true });
    } catch (error) { return json({ error: "Не удалось отправить отзыв.", detail: error.message }, 500); }
  }


  if (request.method === "GET" && path === "/api/articles") {
    try {
      await ensureArticlesTable(env);
      const slug=String(url.searchParams.get("id")||"").trim();
      if(slug){
        if(!/^[a-z0-9-]{1,180}$/.test(slug))return json({error:"Некорректная ссылка на статью."},400);
        const row=await env.DB.prepare("SELECT * FROM articles WHERE slug = ? AND status = 'published'").bind(slug).first();
        if(!row)return json({error:"Статья не найдена."},404,{ "cache-control":"no-store" });
        return json({article:parseArticleRow(row)},200,{ "cache-control":"public, max-age=60" });
      }
      const result=await env.DB.prepare("SELECT * FROM articles WHERE status = 'published' ORDER BY published_at DESC, created_at DESC LIMIT 100").all();
      return json({articles:(result.results||[]).map(parseArticleRow)},200,{ "cache-control":"public, max-age=60" });
    } catch(error){return json({error:"Не удалось загрузить статьи."},500);}
  }

  if (request.method === "GET" && path === "/api/site-status") {
    try { const row=await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("maintenance_mode").first(); let enabled=false; try{enabled=!!JSON.parse(row?.value||"false")}catch{} return json({maintenance:enabled},200,{"cache-control":"no-store"}); }
    catch(error){return json({maintenance:false,error:"status_unavailable"},200,{"cache-control":"no-store"});}
  }
  if (request.method === "GET" && path === "/api/events") {
    return cachedJsonResponse(request, 15, async () => {
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("events").first();
        let events = [];
        try { events = row ? JSON.parse(row.value) : []; } catch { events = []; }
        const now = Date.now();
        events = (Array.isArray(events) ? events : []).filter(event => event && typeof event.title === "string" && Number.isFinite(Date.parse(event.dateTime)) && Date.parse(event.dateTime) > now)
          .sort((a, b) => Date.parse(a.dateTime) - Date.parse(b.dateTime));
        return json({ events });
      } catch (error) { return json({ error: "Не удалось загрузить события.", detail: error.message }, 500); }
    });
  }

  if (request.method === "GET" && path === "/api/experts") {
    return cachedJsonResponse(request, 60, async () => {
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("experts").first();
        let experts = [];
        try { experts = row ? JSON.parse(row.value) : []; } catch { experts = []; }
        return json({ experts: Array.isArray(experts) ? experts : [] });
      } catch (error) { return json({ error: "Не удалось загрузить экспертов.", detail: error.message }, 500); }
    });
  }

  if (request.method === "GET" && path === "/api/participants") {
    return cachedJsonResponse(request, 60, async () => {
      try {
        const row = await env.DB.prepare("SELECT value, updated_at FROM app_state WHERE key = ?").bind("participants").first();
        let stored = [];
        try { stored = row ? JSON.parse(row.value) : []; } catch { throw new Error("Archive data in D1 is invalid JSON"); }
        const participants = publicArchive(Array.isArray(stored) ? stored : []);
        return json({ participants, updatedAt: row?.updated_at || null });
      } catch (error) {
        return json({ error: "Не удалось прочитать архив.", detail: error.message }, 500);
      }
    });
  }

  if (request.method === "GET" && path === "/api/site-polls") {
    return cachedJsonResponse(request, 15, async () => {
      try {
        const now = Date.now();
        const polls = (await getSitePolls(env)).filter(p => p && p.active !== false && (!p.endAt || Date.parse(p.endAt) > now));
        return json({ polls });
      } catch (error) { return json({ error: "Не удалось загрузить опросы.", detail: error.message }, 500); }
    });
  }
  if (request.method === "POST" && path === "/api/site-polls/vote") {let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}const pollId=String(body?.pollId||""),voterId=String(body?.voterId||""),optionIds=Array.isArray(body?.optionIds)?[...new Set(body.optionIds.map(x=>String(x)))]:[String(body?.optionId||"")];if(!/^[a-zA-Z0-9_-]{1,100}$/.test(pollId)||!/^[a-zA-Z0-9_-]{16,100}$/.test(voterId)||!optionIds.length||optionIds.length>3||optionIds.some(id=>!/^[a-zA-Z0-9_-]{1,100}$/.test(id)))return json({error:"Проверьте выбранные варианты ответа."},400);try{const poll=(await getSitePolls(env)).find(p=>p.id===pollId);if(!poll||poll.active===false)return json({error:"Опрос больше недоступен."},404);if(poll.endAt&&Date.parse(poll.endAt)<=Date.now())return json({error:"Время голосования завершилось."},410);const limit=Math.max(1,Math.min(3,Number(poll.maxSelections)||1));if(optionIds.length>limit)return json({error:"В этом опросе можно выбрать не более "+limit+" вариантов."},400);if(!Array.isArray(poll.options)||optionIds.some(id=>!poll.options.some(o=>o.id===id)))return json({error:"Такого варианта ответа нет."},400);await ensureSitePollVoteTable(env);await ensureSitePollMultiVoteTable(env);const existing=await env.DB.prepare("SELECT 1 AS voted FROM site_poll_votes WHERE poll_id=? AND voter_id=? UNION ALL SELECT 1 AS voted FROM site_poll_multi_votes WHERE poll_id=? AND voter_id=? LIMIT 1").bind(pollId,voterId,pollId,voterId).first();if(existing)return json({error:"Вы уже голосовали в этом опросе."},409);const now=new Date().toISOString();await env.DB.batch(optionIds.map(id=>env.DB.prepare("INSERT OR IGNORE INTO site_poll_multi_votes (poll_id,voter_id,option_id,created_at) VALUES (?,?,?,?)").bind(pollId,voterId,id,now)));const result=await getSitePollResults(env,pollId);return json({ok:true,...result},200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось сохранить голос.",detail:error.message},500)}}
  if (request.method === "GET" && path === "/api/site-polls/results") {const pollId=String(url.searchParams.get("id")||""),voterId=String(url.searchParams.get("voterId")||"");if(!/^[a-zA-Z0-9_-]{1,100}$/.test(pollId)|| (voterId&&!/^[a-zA-Z0-9_-]{16,100}$/.test(voterId)))return json({error:"Некорректный опрос."},400);try{const result=await getSitePollResults(env,pollId);let alreadyVoted=false;if(voterId){await ensureSitePollVoteTable(env);await ensureSitePollMultiVoteTable(env);const existing=await env.DB.prepare("SELECT 1 AS voted FROM site_poll_votes WHERE poll_id=? AND voter_id=? UNION ALL SELECT 1 AS voted FROM site_poll_multi_votes WHERE poll_id=? AND voter_id=? LIMIT 1").bind(pollId,voterId,pollId,voterId).first();alreadyVoted=!!existing}return json({...result,alreadyVoted},200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось загрузить результаты.",detail:error.message},500)}}
  if (request.method === "GET" && path === "/api/polls") {
    const ids = [...new Set((url.searchParams.get("ids") || "").split(",").map(x => x.trim()).filter(x => /^[a-zA-Z0-9._-]{1,100}$/.test(x)))].slice(0, 100);
    try { return json({ polls: await readPolls(env, ids) }, 200, { "cache-control": "no-store" }); }
    catch (error) { return json({ error: "Не удалось загрузить результаты опроса.", detail: error.message }, 500); }
  }

  if (request.method === "POST" && path === "/api/polls/vote") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
    const performanceId = String(body?.performanceId || "");
    const voterId = String(body?.voterId || "");
    const choice = String(body?.choice || "");
    if (!/^[a-zA-Z0-9._-]{1,100}$/.test(performanceId) || !/^[a-zA-Z0-9._-]{16,100}$/.test(voterId) || !["yes", "no"].includes(choice)) {
      return json({ error: "Проверьте данные голоса." }, 400);
    }
    try {
      await ensureVoteTable(env);
      const inserted = await env.DB.prepare("INSERT OR IGNORE INTO performance_votes (performance_id, voter_id, choice, created_at) VALUES (?, ?, ?, ?)")
        .bind(performanceId, voterId, choice, new Date().toISOString()).run();
      const polls = await readPolls(env, [performanceId]);
      return json({ ok: true, alreadyVoted: !(inserted.meta?.changes > 0), poll: polls[performanceId] }, 200, { "cache-control": "no-store" });
    } catch (error) {
      return json({ error: "Не удалось сохранить голос.", detail: error.message }, 500);
    }
  }

  if (request.method === "POST" && path === "/api/login") {
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "Сервер ещё не настроен: добавьте ADMIN_PASSWORD и SESSION_SECRET." }, 503);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
    if (typeof body.password !== "string" || body.password !== env.ADMIN_PASSWORD) return json({ error: "Неверный пароль." }, 401);
    return json({ token: await issueToken(env.SESSION_SECRET), expiresIn: TOKEN_TTL_SECONDS });
  }

  if (path.startsWith("/api/admin/")) {
    if (!(await isAdmin(request, env))) return json({ error: "Требуется авторизация администратора." }, 401);



    if (request.method === "GET" && path === "/api/admin/articles") {
      try { await ensureArticlesTable(env);const result=await env.DB.prepare("SELECT * FROM articles ORDER BY updated_at DESC").all();return json({articles:(result.results||[]).map(parseArticleRow)},200,{ "cache-control":"no-store" }); }
      catch(error){return json({error:"Не удалось загрузить статьи.",detail:error.message},500);}
    }
    if (request.method === "PUT" && path === "/api/admin/articles") {
      let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}
      const a=body?.article;if(!a||typeof a!=="object"||Array.isArray(a))return json({error:"Некорректная статья."},400);
      const slug=String(a.slug||"").trim(),title=String(a.title||"").trim(),summary=String(a.summary||""),content=String(a.content||""),coverImage=String(a.coverImage||""),status=String(a.status||"draft"),attachments=a.attachments;
      if(!/^[a-z0-9-]{1,180}$/.test(slug))return json({error:"Некорректный уникальный адрес статьи."},400);
      if(!title||title.length>160)return json({error:"Заголовок обязателен и не должен превышать 160 символов."},400);
      if(summary.length>400||!content.trim()||content.length>150000)return json({error:"Проверьте описание и текст статьи."},400);
      if(coverImage&&(!coverImage.startsWith("https://")||coverImage.length>2048))return json({error:"Некорректная обложка статьи."},400);
      if(!["draft","published"].includes(status))return json({error:"Некорректный статус статьи."},400);
      if(!Array.isArray(attachments)||attachments.length>50)return json({error:"Допускается не более 50 вложений."},400);
      const allowedTypes=new Set(["image","file","profile","performance","episode"]);
      for(const item of attachments){if(!item||!allowedTypes.has(item.type)||typeof item.name!=="string"||!item.name.trim()||item.name.length>300)return json({error:"Проверьте список вложений."},400);if(["image","file"].includes(item.type)&&(!String(item.url||"").startsWith("https://")||String(item.url).length>2048))return json({error:"Некорректная ссылка вложения."},400);if(item.href&&(!String(item.href).startsWith("/")||String(item.href).startsWith("//")))return json({error:"Некорректная ссылка на материал архива."},400)}
      const serialized=JSON.stringify(attachments);if(new TextEncoder().encode(serialized).length>100000)return json({error:"Вложения слишком велики."},413);
      try{
        await ensureArticlesTable(env);
        const existing=await env.DB.prepare("SELECT created_at,published_at FROM articles WHERE slug = ?").bind(slug).first();
        const now=new Date().toISOString(),publishedAt=status==="published"?(existing?.published_at||now):null;
        await env.DB.prepare("INSERT INTO articles (slug,title,summary,content,cover_image,attachments_json,status,created_at,updated_at,published_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET title=excluded.title,summary=excluded.summary,content=excluded.content,cover_image=excluded.cover_image,attachments_json=excluded.attachments_json,status=excluded.status,updated_at=excluded.updated_at,published_at=excluded.published_at")
          .bind(slug,title,summary,content,coverImage,serialized,status,existing?.created_at||now,now,publishedAt).run();
        const row=await env.DB.prepare("SELECT * FROM articles WHERE slug = ?").bind(slug).first();
        return json({ok:true,article:parseArticleRow(row)},200,{ "cache-control":"no-store" });
      }catch(error){return json({error:"Не удалось сохранить статью.",detail:error.message},500)}
    }
    if(request.method==="DELETE"&&path.startsWith("/api/admin/articles/")){
      let slug;try{slug=decodeURIComponent(path.slice("/api/admin/articles/".length))}catch{return json({error:"Некорректный адрес статьи."},400)}
      if(!/^[a-z0-9-]{1,180}$/.test(slug))return json({error:"Некорректный адрес статьи."},400);
      try{await ensureArticlesTable(env);const result=await env.DB.prepare("DELETE FROM articles WHERE slug = ?").bind(slug).run();if(!(result.meta?.changes>0))return json({error:"Статья не найдена."},404);return json({ok:true})}catch(error){return json({error:"Не удалось удалить статью.",detail:error.message},500)}
    }
    if(request.method==="POST"&&path==="/api/admin/article-upload"){
      if(!env.IMAGES)return json({error:"Хранилище R2 ещё не подключено."},503);
      let form;try{form=await request.formData()}catch{return json({error:"Не удалось прочитать файл."},400)}
      const file=form.get("file");if(!file||typeof file.arrayBuffer!=="function")return json({error:"Файл не выбран."},400);
      if(file.size>25*1024*1024)return json({error:"Размер файла не должен превышать 25 МБ."},413);
      const allowed=new Map([["image/jpeg","jpg"],["image/png","png"],["image/webp","webp"],["image/avif","avif"],["image/gif","gif"],["application/pdf","pdf"],["text/plain","txt"],["application/zip","zip"],["application/x-zip-compressed","zip"],["application/vnd.openxmlformats-officedocument.wordprocessingml.document","docx"],["application/msword","doc"],["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","xlsx"],["application/vnd.ms-excel","xls"],["application/vnd.openxmlformats-officedocument.presentationml.presentation","pptx"],["application/vnd.ms-powerpoint","ppt"]]);
      const extension=allowed.get(file.type);if(!extension)return json({error:"Формат файла не поддерживается. Разрешены изображения, PDF, Office, TXT и ZIP."},415);
      const key="articles/"+crypto.randomUUID()+"."+extension;
      try{await env.IMAGES.put(key,await file.arrayBuffer(),{httpMetadata:{contentType:file.type,cacheControl:"public, max-age=31536000, immutable"}});return json({url:new URL("/files/"+key,url.origin).toString(),key,name:String(file.name||"").slice(0,240),mime:file.type,size:file.size})}
      catch(error){return json({error:"Не удалось загрузить файл в R2.",detail:error.message},500)}
    }

    if (request.method === "GET" && path === "/api/admin/site-status") {
      try { const row=await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("maintenance_mode").first(); let enabled=false; try{enabled=!!JSON.parse(row?.value||"false")}catch{} return json({maintenance:enabled},200,{"cache-control":"no-store"}); }
      catch(error){return json({error:"Не удалось получить статус сайта."},500);}
    }
    if (request.method === "PUT" && path === "/api/admin/site-status") {
      let body; try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}
      if(typeof body?.maintenance!=="boolean")return json({error:"Укажите состояние сайта."},400);
      try{await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at").bind("maintenance_mode",JSON.stringify(body.maintenance),new Date().toISOString()).run();return json({ok:true,maintenance:body.maintenance},200,{"cache-control":"no-store"})}
      catch(error){return json({error:"Не удалось изменить режим сайта.",detail:error.message},500);}
    }
    if (request.method === "GET" && path === "/api/admin/versions") {
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("site_versions").first();
        let versions = [];
        try { versions = row ? JSON.parse(row.value) : []; } catch { versions = []; }
        if (!row) {
          versions = [{
            id: "release-1-0-0",
            version: "1.0.0",
            date: "2026-11-21T10:00:00+04:00",
            changes: [
              "Добавлен раздел «Версии сайта» в панели администратора.",
              "Создан общий журнал обновлений с сохранением записей в Cloudflare D1."
            ]
          }];
          await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at")
            .bind("site_versions", JSON.stringify(versions), new Date().toISOString()).run();
        }
        return json({ versions: Array.isArray(versions) ? versions : [] }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось загрузить историю версий.", detail: error.message }, 500); }
    }

    if (request.method === "POST" && path === "/api/admin/versions") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
      const version = String(body?.version || "").trim();
      const changes = body?.changes;
      if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][A-Za-z0-9.-]+)?$/.test(version) || version.length > 32)
        return json({ error: "Укажите версию в формате 1.2.3." }, 400);
      if (!Array.isArray(changes) || changes.length < 1 || changes.length > 30 || changes.some(change => typeof change !== "string" || !change.trim() || change.length > 400))
        return json({ error: "Добавьте от 1 до 30 корректных пунктов изменений (до 400 символов каждый)." }, 400);
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("site_versions").first();
        let versions = [];
        try { versions = row ? JSON.parse(row.value) : []; } catch { versions = []; }
        if (!Array.isArray(versions)) versions = [];
        if (versions.some(entry => entry.version === version)) return json({ error: "Эта версия уже есть в журнале." }, 409);
        const entry = { id: "release-" + crypto.randomUUID(), version, date: new Date().toISOString(), changes: changes.map(change => change.trim()) };
        versions.unshift(entry);
        if (versions.length > 200) versions = versions.slice(0, 200);
        const serialized = JSON.stringify(versions);
        if (new TextEncoder().encode(serialized).length > 100_000) return json({ error: "История версий слишком большая." }, 413);
        await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at")
          .bind("site_versions", serialized, new Date().toISOString()).run();
        return json({ ok: true, versions }, 201, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось сохранить версию.", detail: error.message }, 500); }
    }

    if (request.method === "GET" && path === "/api/admin/analytics") {
      try {
        await ensureCommunityTables(env);
        const [summary, countries, pages, recent] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS views, COUNT(DISTINCT visitor_id) AS visitors FROM site_visits").first(),
          env.DB.prepare("SELECT country, COUNT(*) AS views, COUNT(DISTINCT visitor_id) AS visitors FROM site_visits GROUP BY country ORDER BY views DESC LIMIT 30").all(),
          env.DB.prepare("SELECT page, COUNT(*) AS views FROM site_visits GROUP BY page ORDER BY views DESC LIMIT 10").all(),
          env.DB.prepare("SELECT COUNT(*) AS views FROM site_visits WHERE created_at >= ?").bind(new Date(Date.now()-30*86400000).toISOString()).first()
        ]);
        return json({ summary, countries: countries.results || [], pages: pages.results || [], last30Days: Number(recent?.views || 0) }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось загрузить аналитику.", detail: error.message }, 500); }
    }

    if (request.method === "DELETE" && path.startsWith("/api/admin/feedback/")) {
      const idText = path.slice("/api/admin/feedback/".length);
      if (!/^\d{1,12}$/.test(idText) || Number(idText) < 1) return json({ error: "Некорректный ID отзыва." }, 400);
      try {
        await ensureCommunityTables(env);
        const result = await env.DB.prepare("DELETE FROM site_feedback WHERE id = ?").bind(Number(idText)).run();
        if (!(result.meta?.changes > 0)) return json({ error: "Отзыв уже удалён или не найден." }, 404);
        return json({ ok: true, deletedId: Number(idText) }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось удалить отзыв.", detail: error.message }, 500); }
    }

    if (request.method === "GET" && path === "/api/admin/feedback") {
      try {
        await ensureCommunityTables(env);
        const result = await env.DB.prepare("SELECT id, name, message, created_at FROM site_feedback ORDER BY id DESC LIMIT 300").all();
        return json({ feedback: result.results || [] }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось загрузить отзывы.", detail: error.message }, 500); }
    }

    if (request.method === "GET" && path === "/api/admin/site-polls") {try{return json({polls:await getSitePolls(env)},200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось загрузить опросы.",detail:error.message},500)}}
    if (request.method === "PUT" && path === "/api/admin/site-polls") {let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}const polls=body?.polls;if(!Array.isArray(polls)||polls.length>100)return json({error:"Допускается не более 100 опросов."},400);const ids=new Set();for(const p of polls){if(!p||typeof p!=="object"||Array.isArray(p))return json({error:"Некорректный опрос."},400);const id=String(p.id||""),title=String(p.title||"").trim();if(!/^[a-zA-Z0-9_-]{1,100}$/.test(id)||ids.has(id))return json({error:"У опросов должны быть уникальные ID."},400);if(!title||title.length>140)return json({error:"Название опроса обязательно (до 140 символов)."},400);if(!Array.isArray(p.options)||p.options.length<2||p.options.some(o=>!o||typeof o.id!=="string"||!/^[a-zA-Z0-9_-]{1,100}$/.test(o.id)||typeof o.label!=="string"||!o.label.trim()||o.label.length>120))return json({error:"Укажите минимум два корректных варианта ответа."},400);if(p.maxSelections!==undefined&&(!Number.isInteger(Number(p.maxSelections))||Number(p.maxSelections)<1||Number(p.maxSelections)>3))return json({error:"Максимум выбранных ответов должен быть от 1 до 3."},400);if(p.endAt!==null&&p.endAt!==undefined&&(!Number.isFinite(Date.parse(p.endAt))))return json({error:"Некорректная дата окончания."},400);if(p.participants!==undefined&&(!Array.isArray(p.participants)||p.participants.length>100||p.participants.some(n=>typeof n!=="string"||n.length>250)))return json({error:"Некорректный список участников выпуска."},400);ids.add(id)}const value=JSON.stringify(polls);if(new TextEncoder().encode(value).length>150000)return json({error:"Список опросов слишком большой."},413);try{await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at").bind("site_polls",value,new Date().toISOString()).run();await invalidatePublicCache(request,"/api/site-polls");return json({ok:true,count:polls.length})}catch(error){return json({error:"Не удалось сохранить опросы.",detail:error.message},500)}}
    if (request.method === "GET" && path === "/api/admin/events") {
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("events").first();
        let events = [];
        try { events = row ? JSON.parse(row.value) : []; } catch { events = []; }
        return json({ events: Array.isArray(events) ? events : [] }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось загрузить события.", detail: error.message }, 500); }
    }

    if (request.method === "PUT" && path === "/api/admin/events") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
      const events = body?.events;
      if (!Array.isArray(events) || events.length > 100) return json({ error: "Ожидается список событий (максимум 100)." }, 400);
      const ids = new Set();
      for (const event of events) {
        if (!event || typeof event !== "object" || Array.isArray(event)) return json({ error: "Некорректная запись события." }, 400);
        const id = String(event.id || "");
        const title = String(event.title || "").trim();
        const dateTime = String(event.dateTime || "");
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id) || ids.has(id)) return json({ error: "У каждого события должен быть уникальный корректный ID." }, 400);
        if (!title || title.length > 120) return json({ error: "Название события обязательно и должно быть не длиннее 120 символов." }, 400);
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\+04:00$/.test(dateTime) || !Number.isFinite(Date.parse(dateTime))) return json({ error: "Укажите корректные дату и время по Еревану." }, 400);
        if (event.profiles !== undefined && (!Array.isArray(event.profiles) || event.profiles.length > 60 || event.profiles.some(profile => typeof profile !== "string" || !profile.trim() || profile.length > 250))) return json({ error: "Список профилей события некорректен (максимум 60)." }, 400);
        ids.add(id);
      }
      const serialized = JSON.stringify(events);
      if (new TextEncoder().encode(serialized).length > 100_000) return json({ error: "Список событий слишком большой." }, 413);
      const updatedAt = new Date().toISOString();
      try {
        await env.DB.prepare("INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
          .bind("events", serialized, updatedAt).run();
        await invalidatePublicCache(request, "/api/events");
        return json({ ok: true, count: events.length, updatedAt });
      } catch (error) { return json({ error: "Не удалось сохранить события.", detail: error.message }, 500); }
    }

    if (request.method === "GET" && path === "/api/admin/expert-tags") {
      try { const row=await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("expert_tags").first();let tags=[];try{tags=row?JSON.parse(row.value):[]}catch{}return json({tags:Array.isArray(tags)?tags:[]},200,{"cache-control":"no-store"}); }
      catch(error){return json({error:"Не удалось загрузить теги.",detail:error.message},500);}
    }
    if (request.method === "PUT" && path === "/api/admin/expert-tags") {
      let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}
      const tags=body?.tags;if(!Array.isArray(tags)||tags.length>200)return json({error:"Допускается не более 200 тегов."},400);
      const clean=[],seen=new Set();
      for(const value of tags){if(typeof value!=="string")return json({error:"Каждый тег должен быть текстом."},400);const tag=value.trim().replace(/\\s+/g," "),key=tag.toLocaleLowerCase("ru");if(!tag||tag.length>32||seen.has(key))return json({error:"Теги должны быть уникальными и содержать от 1 до 32 символов."},400);seen.add(key);clean.push(tag)}
      try{await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at").bind("expert_tags",JSON.stringify(clean),new Date().toISOString()).run();return json({ok:true,tags:clean})}
      catch(error){return json({error:"Не удалось сохранить теги.",detail:error.message},500)}
    }

    if (request.method === "GET" && path === "/api/admin/experts") {
      try {
        const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("experts").first();
        let experts = [];
        try { experts = row ? JSON.parse(row.value) : []; } catch { experts = []; }
        return json({ experts: Array.isArray(experts) ? experts : [] }, 200, { "cache-control": "no-store" });
      } catch (error) { return json({ error: "Не удалось загрузить экспертов.", detail: error.message }, 500); }
    }

    if (request.method === "PUT" && path === "/api/admin/experts") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
      const experts = body?.experts;
      if (!Array.isArray(experts) || experts.length > 300) return json({ error: "Ожидается список экспертов (максимум 300)." }, 400);
      const ids = new Set();
      for (const expert of experts) {
        if (!expert || typeof expert !== "object" || Array.isArray(expert)) return json({ error: "Некорректная запись эксперта." }, 400);
        const id = String(expert.id || ""), name = String(expert.name || "").trim(), photo = String(expert.photo || "");
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id) || ids.has(id)) return json({ error: "У каждого эксперта должен быть уникальный корректный ID." }, 400);
        if (!name || name.length > 120) return json({ error: "Имя эксперта обязательно и не должно превышать 120 символов." }, 400);
        if (!/^https:\/\//i.test(photo) || photo.length > 2048) return json({ error: "Добавьте фотографию эксперта через загрузку изображения." }, 400);
        if (typeof expert.bio !== "undefined" && (typeof expert.bio !== "string" || expert.bio.length > 3000)) return json({ error: "Комментарий эксперта не должен превышать 3000 символов." }, 400);
        if (typeof expert.leader !== "undefined" && typeof expert.leader !== "boolean") return json({ error: "Некорректная отметка лидера." }, 400);
        if (typeof expert.host !== "undefined" && typeof expert.host !== "boolean") return json({ error: "Некорректная отметка ведущего." }, 400);
        if (typeof expert.tags !== "undefined" && (!Array.isArray(expert.tags) || expert.tags.length > 30 || expert.tags.some(tag => typeof tag !== "string" || !tag.trim() || tag.length > 32))) return json({ error: "Некорректный список тегов эксперта." }, 400);
        ids.add(id);
      }
      if (experts.filter(expert => expert.leader === true).length > 1) return json({ error: "Лидером сотни может быть отмечен только один эксперт." }, 400);
      if (experts.filter(expert => expert.host === true).length > 1) return json({ error: "Ведущим шоу может быть отмечен только один эксперт." }, 400);
      const serialized = JSON.stringify(experts);
      if (new TextEncoder().encode(serialized).length > 150_000) return json({ error: "Список экспертов слишком большой." }, 413);
      const updatedAt = new Date().toISOString();
      try {
        await env.DB.prepare("INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
          .bind("experts", serialized, updatedAt).run();
        await invalidatePublicCache(request, "/api/experts");
        return json({ ok: true, count: experts.length, updatedAt });
      } catch (error) { return json({ error: "Не удалось сохранить экспертов.", detail: error.message }, 500); }
    }

    if (request.method === "GET" && path === "/api/admin/participants") {
      try { return json({ participants: await readArchive(env) }, 200, { "cache-control": "no-store" }); }
      catch (error) { return json({ error: "Не удалось прочитать архив.", detail: error.message }, 500); }
    }

    if (request.method === "PUT" && path === "/api/admin/participants") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Некорректный JSON." }, 400); }
      const participants = body?.participants;
      const validationError = validateArchive(participants);
      if (validationError) return json({ error: validationError }, 400);
      const serialized = JSON.stringify(participants);
      if (new TextEncoder().encode(serialized).length > MAX_ARCHIVE_BYTES) {
        return json({ error: "Архив слишком большой для одной записи D1. Сначала вынесите фотографии в R2." }, 413);
      }
      const updatedAt = new Date().toISOString();
      try {
        await env.DB.prepare("INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
          .bind("participants", serialized, updatedAt).run();
        await invalidatePublicCache(request, "/api/participants");
        return json({ ok: true, count: participants.length, updatedAt });
      } catch (error) {
        return json({ error: "Не удалось сохранить архив в D1.", detail: error.message }, 500);
      }
    }

    if (request.method === "DELETE" && path.startsWith("/api/admin/images/")) {
      if (!env.IMAGES) return json({ error: "Хранилище R2 ещё не подключено." }, 503);
      let key;
      try { key = decodeURIComponent(path.slice("/api/admin/images/".length)); } catch { return json({ error: "Некорректный ключ изображения." }, 400); }
      if (!key || !key.startsWith("participants/") || key.includes("..") || key.includes("\\")) return json({ error: "Некорректный ключ изображения." }, 400);
      try { await env.IMAGES.delete(key); return json({ ok: true, deletedKey: key }); }
      catch (error) { return json({ error: "Не удалось удалить фотографию из R2.", detail: error.message }, 500); }
    }

    if (request.method === "POST" && path === "/api/admin/upload") {
      if (!env.IMAGES) return json({ error: "Хранилище R2 ещё не подключено." }, 503);
      let form;
      try { form = await request.formData(); } catch { return json({ error: "Не удалось прочитать файл." }, 400); }
      const file = form.get("file");
      if (!file || typeof file.arrayBuffer !== "function") return json({ error: "Файл не выбран." }, 400);
      if (!ALLOWED_IMAGE_TYPES.has(file.type)) return json({ error: "Поддерживаются JPEG, PNG, WebP и AVIF." }, 415);
      if (file.size > MAX_IMAGE_BYTES) return json({ error: "Размер изображения не должен превышать 8 МБ." }, 413);
      const extension = ({ "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/avif": "avif" })[file.type];
      const key = "participants/" + crypto.randomUUID() + "." + extension;
      await env.IMAGES.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type, cacheControl: "public, max-age=31536000, immutable" } });
      return json({ url: new URL("/images/" + key, url.origin).toString(), key });
    }
  }

  return json({ error: "Маршрут не найден." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });


    if (request.method === "GET" && url.pathname.startsWith("/files/")) {
      if (!env.IMAGES) return new Response("File storage is not configured", { status:503 });
      let key;try{key=decodeURIComponent(url.pathname.slice("/files/".length))}catch{return new Response("Not found",{status:404})}
      if(!key||!key.startsWith("articles/")||key.includes("..")||key.includes("\\\\"))return new Response("Not found",{status:404});
      const object=await env.IMAGES.get(key);if(!object)return new Response("Not found",{status:404});
      const headers=new Headers();object.writeHttpMetadata(headers);headers.set("etag",object.httpEtag);headers.set("cache-control","public, max-age=31536000, immutable");
      return new Response(object.body,{headers});
    }

    if (request.method === "GET" && url.pathname.startsWith("/images/")) {
      if (!env.IMAGES) return new Response("Image storage is not configured", { status: 503 });
      const key = decodeURIComponent(url.pathname.slice("/images/".length));
      if (!key || key.includes("..")) return new Response("Not found", { status: 404 });
      const object = await env.IMAGES.get(key);
      if (!object) return new Response("Not found", { status: 404 });
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("etag", object.httpEtag);
      headers.set("cache-control", "public, max-age=31536000, immutable");
      return new Response(object.body, { headers });
    }

    let response;
    if (url.pathname.startsWith("/api/")) response = await handleApi(request, env, url);
    else response = json({ service: "nukavsevmeste-api", status: "ok" });
    return withCors(response, request, env);
  }
};
