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
    "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
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
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return "Каждая запись должна быть объектом.";
    if (!String(item.firstName || "").trim() || !String(item.lastName || "").trim() || !String(item.song || "").trim()) {
      return "У каждой записи должны быть имя, фамилия и название песни.";
    }
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
    if (!polls[row.performance_id]) continue;
    polls[row.performance_id][row.choice] = Number(row.count) || 0;
  }
  return polls;
}

async function handleApi(request, env, url) {
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/participants") {
    try {
      const participants = await readArchive(env);
      return json({ participants, updatedAt: await env.DB.prepare("SELECT updated_at FROM app_state WHERE key = ?").bind("participants").first().then(row => row?.updated_at || null) }, 200, { "cache-control": "public, max-age=30, stale-while-revalidate=120" });
    } catch (error) {
      return json({ error: "Не удалось прочитать архив.", detail: error.message }, 500);
    }
  }

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
