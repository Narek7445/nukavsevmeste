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
async function getSitePolls(env){const row=await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("site_polls").first();let polls=[];try{polls=row?JSON.parse(row.value):[]}catch{}return Array.isArray(polls)?polls:[]}
async function getSitePollResults(env,pollId){await ensureSitePollVoteTable(env);const rows=await env.DB.prepare("SELECT option_id,COUNT(*) AS count FROM site_poll_votes WHERE poll_id=? GROUP BY option_id").bind(pollId).all();const counts={};let total=0;for(const r of rows.results||[]){counts[r.option_id]=Number(r.count)||0;total+=counts[r.option_id]}return {counts,total}}

async function ensureCommunityTables(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT NOT NULL, country TEXT NOT NULL, page TEXT NOT NULL, created_at TEXT NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS site_feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', message TEXT NOT NULL, created_at TEXT NOT NULL)").run();
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

  if (request.method === "GET" && path === "/api/events") {
    try {
      const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("events").first();
      let events = [];
      try { events = row ? JSON.parse(row.value) : []; } catch { events = []; }
      const now = Date.now();
      events = (Array.isArray(events) ? events : []).filter(event => event && typeof event.title === "string" && Number.isFinite(Date.parse(event.dateTime)) && Date.parse(event.dateTime) > now)
        .sort((a, b) => Date.parse(a.dateTime) - Date.parse(b.dateTime));
      return json({ events }, 200, { "cache-control": "public, max-age=15, stale-while-revalidate=30" });
    } catch (error) { return json({ error: "Не удалось загрузить события.", detail: error.message }, 500); }
  }

  if (request.method === "GET" && path === "/api/experts") {
    try {
      const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ?").bind("experts").first();
      let experts = [];
      try { experts = row ? JSON.parse(row.value) : []; } catch { experts = []; }
      return json({ experts: Array.isArray(experts) ? experts : [] }, 200, { "cache-control": "public, max-age=60, stale-while-revalidate=180" });
    } catch (error) { return json({ error: "Не удалось загрузить экспертов.", detail: error.message }, 500); }
  }

  if (request.method === "GET" && path === "/api/participants") {
    try {
      const participants = await readArchive(env);
      return json({ participants, updatedAt: await env.DB.prepare("SELECT updated_at FROM app_state WHERE key = ?").bind("participants").first().then(row => row?.updated_at || null) }, 200, { "cache-control": "public, max-age=30, stale-while-revalidate=120" });
    } catch (error) {
      return json({ error: "Не удалось прочитать архив.", detail: error.message }, 500);
    }
  }

  if (request.method === "GET" && path === "/api/site-polls") {try{const now=Date.now(),polls=(await getSitePolls(env)).filter(p=>p&&p.active!==false&&(!p.endAt||Date.parse(p.endAt)>now));return json({polls},200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось загрузить опросы.",detail:error.message},500)}}
  if (request.method === "POST" && path === "/api/site-polls/vote") {let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}const pollId=String(body?.pollId||""),voterId=String(body?.voterId||""),optionId=String(body?.optionId||"");if(!/^[a-zA-Z0-9_-]{1,100}$/.test(pollId)||!/^[a-zA-Z0-9_-]{16,100}$/.test(voterId)||!/^[a-zA-Z0-9_-]{1,100}$/.test(optionId))return json({error:"Проверьте данные голоса."},400);try{const poll=(await getSitePolls(env)).find(p=>p.id===pollId);if(!poll||poll.active===false)return json({error:"Опрос больше недоступен."},404);if(poll.endAt&&Date.parse(poll.endAt)<=Date.now())return json({error:"Время голосования завершилось."},410);if(!Array.isArray(poll.options)||!poll.options.some(o=>o.id===optionId))return json({error:"Такого варианта ответа нет."},400);await ensureSitePollVoteTable(env);await env.DB.prepare("INSERT OR IGNORE INTO site_poll_votes (poll_id,voter_id,option_id,created_at) VALUES (?,?,?,?)").bind(pollId,voterId,optionId,new Date().toISOString()).run();const result=await getSitePollResults(env,pollId);return json({ok:true,...result},200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось сохранить голос.",detail:error.message},500)}}
  if (request.method === "GET" && path === "/api/site-polls/results") {const pollId=String(url.searchParams.get("id")||"");if(!/^[a-zA-Z0-9_-]{1,100}$/.test(pollId))return json({error:"Некорректный опрос."},400);try{return json(await getSitePollResults(env,pollId),200,{"cache-control":"no-store"})}catch(error){return json({error:"Не удалось загрузить результаты.",detail:error.message},500)}}
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
    if (request.method === "PUT" && path === "/api/admin/site-polls") {let body;try{body=await request.json()}catch{return json({error:"Некорректный JSON."},400)}const polls=body?.polls;if(!Array.isArray(polls)||polls.length>100)return json({error:"Допускается не более 100 опросов."},400);const ids=new Set();for(const p of polls){if(!p||typeof p!=="object"||Array.isArray(p))return json({error:"Некорректный опрос."},400);const id=String(p.id||""),title=String(p.title||"").trim();if(!/^[a-zA-Z0-9_-]{1,100}$/.test(id)||ids.has(id))return json({error:"У опросов должны быть уникальные ID."},400);if(!title||title.length>140)return json({error:"Название опроса обязательно (до 140 символов)."},400);if(!Array.isArray(p.options)||p.options.length<2||p.options.length>8||p.options.some(o=>!o||typeof o.id!=="string"||!/^[a-zA-Z0-9_-]{1,100}$/.test(o.id)||typeof o.label!=="string"||!o.label.trim()||o.label.length>120))return json({error:"Укажите от 2 до 8 корректных вариантов ответа."},400);if(p.endAt!==null&&p.endAt!==undefined&&(!Number.isFinite(Date.parse(p.endAt))))return json({error:"Некорректная дата окончания."},400);if(p.participants!==undefined&&(!Array.isArray(p.participants)||p.participants.length>100||p.participants.some(n=>typeof n!=="string"||n.length>250)))return json({error:"Некорректный список участников выпуска."},400);ids.add(id)}const value=JSON.stringify(polls);if(new TextEncoder().encode(value).length>150000)return json({error:"Список опросов слишком большой."},413);try{await env.DB.prepare("INSERT INTO app_state (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at").bind("site_polls",value,new Date().toISOString()).run();return json({ok:true,count:polls.length})}catch(error){return json({error:"Не удалось сохранить опросы.",detail:error.message},500)}}
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
