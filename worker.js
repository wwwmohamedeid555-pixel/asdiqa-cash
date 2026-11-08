const USERNAME = "Memo1233";

function html(content, status = 200) {
  return new Response(content, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[c]);
}

function page(title, content) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f3f4f6;margin:0;padding:24px;color:#222}
main{max-width:600px;margin:35px auto;background:white;padding:24px;border-radius:14px;box-shadow:0 3px 18px #0001}
h2{text-align:center;color:#b51f2b}
input,button{width:100%;padding:13px;margin:8px 0;border-radius:8px;font-size:16px}
input{border:1px solid #ccc}
button{border:0;background:#b51f2b;color:white;cursor:pointer}
.number{display:flex;gap:8px;align-items:center;padding:10px;border-bottom:1px solid #eee;direction:ltr}
.number span{flex:1;font-size:18px;overflow-wrap:anywhere}
.number button{width:auto;margin:0;padding:9px 14px}
.delete{background:#555}
.muted{text-align:center;color:#777}
a{color:#b51f2b}
</style>
</head>
<body><main>${content}</main></body></html>`;
}

function redirect(path, cookie) {
  const headers = { Location: path };
  if (cookie) headers["Set-Cookie"] = cookie;
  return new Response(null, { status: 303, headers });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(value)
  );
  return base64url(new Uint8Array(signature));
}

async function makeCookie(env) {
  const payload = `${USERNAME}|${Date.now() + 8 * 60 * 60 * 1000}`;
  const signature = await sign(payload, env.SESSION_SECRET);
  const token = base64url(new TextEncoder().encode(payload)) + "." + signature;
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`;
}

async function isLoggedIn(request, env) {
  if (!env.SESSION_SECRET) return false;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return false;

  try {
    const [encoded, signature] = match[1].split(".");
    const payload = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
    const expected = await sign(payload, env.SESSION_SECRET);
    const [user, expiry] = payload.split("|");
    return user === USERNAME &&
      Number(expiry) > Date.now() &&
      signature === expected;
  } catch {
    return false;
  }
}

async function ensureTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS numbers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone_number TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!env.DB || !env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
    return html(page("إعداد الموقع",
      "<h2>إعداد الموقع غير مكتمل</h2><p class='muted'>تأكد من إعداد DB و ADMIN_PASSWORD و SESSION_SECRET في Cloudflare.</p>"
    ), 500);
  }

  await ensureTable(env);

  if (path === "/login" && method === "GET") {
    return html(page("دخول الأدمن", `
      <h2>الأصدقاء للكاش</h2>
      <form method="POST" action="/login">
        <input name="username" placeholder="اسم المستخدم" required>
        <input name="password" type="password" placeholder="كلمة المرور" required>
        <button type="submit">تسجيل الدخول</button>
      </form>
    `));
  }

  if (path === "/login" && method === "POST") {
    const form = await request.formData();
    const username = form.get("username");
    const password = form.get("password");

    if (username === USERNAME && password === env.ADMIN_PASSWORD) {
      return redirect("/admin", await makeCookie(env));
    }

    return html(page("خطأ", `
      <h2>بيانات الدخول غير صحيحة</h2>
      <p class="muted"><a href="/login">حاول مرة أخرى</a></p>
    `), 401);
  }

  if (path === "/logout" && method === "POST") {
    return redirect("/", "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
  }

  if (path === "/" && method === "GET") {
    const result = await env.DB.prepare(
      "SELECT id, phone_number FROM numbers ORDER BY id DESC"
    ).all();

    const numbers = (result.results || []).map(item => `
      <div class="number">
        <span>${escapeHTML(item.phone_number)}</span>
        <button type="button" onclick="navigator.clipboard.writeText('${escapeHTML(item.phone_number)}').then(()=>this.textContent='تم النسخ')">نسخ</button>
      </div>
    `).join("");

    return html(page("الأصدقاء للكاش", `
      <h2>الأصدقاء للكاش</h2>
      <p class="muted">أرقام الهواتف المتاحة للنسخ</p>
      ${numbers || "<p class='muted'>لا توجد أرقام مضافة حاليًا.</p>"}
      <p class="muted"><a href="/login">دخول الإدارة</a></p>
    `));
  }

  if (path === "/admin") {
    if (!(await isLoggedIn(request, env))) return redirect("/login");

    if (method !== "GET") return new Response("Method Not Allowed", { status: 405 });

    const result = await env.DB.prepare(
      "SELECT id, phone_number FROM numbers ORDER BY id DESC"
    ).all();

    const numbers = (result.results || []).map(item => `
      <div class="number">
        <span>${escapeHTML(item.phone_number)}</span>
        <form method="POST" action="/delete">
          <input type="hidden" name="id" value="${item.id}">
          <button class="delete" type="submit">حذف</button>
        </form>
      </div>
    `).join("");

    return html(page("لوحة الإدارة", `
      <h2>لوحة إدارة الأصدقاء للكاش</h2>
      <form method="POST" action="/add">
        <input name="phone_number" type="tel" placeholder="اكتب رقم الهاتف" required>
        <button type="submit">إضافة رقم</button>
      </form>
      <h3>الأرقام المسجلة</h3>
      ${numbers || "<p class='muted'>لا توجد أرقام بعد.</p>"}
      <form method="POST" action="/logout">
        <button class="delete" type="submit">تسجيل الخروج</button>
      </form>
      <p class="muted"><a href="/">عرض الصفحة الرئيسية</a></p>
    `));
  }

  if (path === "/add" && method === "POST") {
    if (!(await isLoggedIn(request, env))) return redirect("/login");

    const form = await request.formData();
    const number = String(form.get("phone_number") || "").trim();

    if (!/^[0-9+\-\s()]{5,25}$/.test(number)) {
      return html(page("رقم غير صحيح",
        "<h2>رقم الهاتف غير صحيح</h2><a href='/admin'>العودة</a>"
      ), 400);
    }

    try {
      await env.DB.prepare(
        "INSERT INTO numbers (phone_number) VALUES (?)"
      ).bind(number).run();
    } catch {
      return html(page("تنبيه",
        "<h2>الرقم موجود بالفعل أو تعذرت إضافته</h2><a href='/admin'>العودة</a>"
      ), 400);
    }

    return redirect("/admin");
  }

  if (path === "/delete" && method === "POST") {
    if (!(await isLoggedIn(request, env))) return redirect("/login");

    const form = await request.formData();
    const id = Number(form.get("id"));

    if (Number.isInteger(id) && id > 0) {
      await env.DB.prepare("DELETE FROM numbers WHERE id = ?").bind(id).run();
    }

    return redirect("/admin");
  }

  return new Response("Not Found", { status: 404 });
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      return html(page("خطأ", `
        <h2>حدث خطأ داخلي</h2>
        <p>راجع سجلات Cloudflare لمعرفة التفاصيل.</p>
      `), 500);
    }
  }
};
