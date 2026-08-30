const SESSION_COOKIE = 'raghad_session';
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request) });

      if (url.pathname === '/api/config' && request.method === 'GET') return json({ turnstileSiteKey: env.TURNSTILE_SITE_KEY || '' }, request);
      if (url.pathname === '/api/auth/register' && request.method === 'POST') return register(request, env);
      if (url.pathname === '/api/auth/login' && request.method === 'POST') return login(request, env);
      if (url.pathname === '/api/auth/logout' && request.method === 'POST') return logout(request, env);
      if (url.pathname === '/api/auth/me' && request.method === 'GET') return me(request, env);
      if (url.pathname === '/api/products' && request.method === 'GET') return listProducts(request, env);
      if (url.pathname === '/api/orders' && request.method === 'POST') return createOrder(request, env);
      if (url.pathname === '/api/admin/products' && request.method === 'POST') return createProduct(request, env);
      if (url.pathname === '/api/admin/images' && request.method === 'POST') return uploadImage(request, env);
      if (url.pathname === '/api/admin/orders' && request.method === 'GET') return adminOrders(request, env);

      const productDelete = url.pathname.match(/^\/api\/admin\/products\/([^/]+)$/);
      if (productDelete && request.method === 'DELETE') return deleteProduct(request, env, productDelete[1]);
      if (productDelete && request.method === 'PATCH') return updateProduct(request, env, productDelete[1]);

      const orderStatus = url.pathname.match(/^\/api\/admin\/orders\/([^/]+)\/status$/);
      if (orderStatus && request.method === 'PATCH') return updateOrderStatus(request, env, orderStatus[1]);

      const orderDelete = url.pathname.match(/^\/api\/admin\/orders\/([^/]+)$/);
      if (orderDelete && request.method === 'DELETE') return deleteOrder(request, env, orderDelete[1]);

      return json({ error: 'Not found' }, request, 404);
    } catch (error) {
      return json({ error: 'حدث خطأ غير متوقع. يرجى المحاولة لاحقاً.' }, request, 500);
    }
  }
};

function corsHeaders(request) {
  const origin = request.headers.get('origin');
  return {
    'access-control-allow-origin': origin || '*',
    'access-control-allow-methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'access-control-allow-headers': 'content-type,x-turnstile-token,x-csrf-token',
    'access-control-allow-credentials': 'true',
    'vary': 'Origin'
  };
}

function json(data, request, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...corsHeaders(request), ...extraHeaders } });
}

async function readJson(request) {
  const type = request.headers.get('content-type') || '';
  if (!type.includes('application/json')) throw new Error('Invalid content type');
  return request.json();
}

function now() { return Date.now(); }
function id(prefix) { return `${prefix}_${crypto.randomUUID().replaceAll('-', '')}`; }
function normalizeIdentifier(value) { return String(value || '').trim().toLowerCase(); }
function isStrongPassword(value) { return typeof value === 'string' && value.length >= 8 && value.length <= 256; }
function validIdentifier(value) { return /^[a-zA-Z0-9_.@-]{3,80}$/.test(value); }
function bytesToBase64(bytes) { let s = ''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s); }
function base64ToBytes(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
async function sha256(value) { return bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))); }

async function hashPassword(password, saltBytes, iterations = 150000) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, key, 256);
  return bytesToBase64(new Uint8Array(bits));
}

async function makePasswordRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: bytesToBase64(salt), iterations: 150000, hash: await hashPassword(password, salt, 150000) };
}

async function verifyPassword(password, user) {
  const hash = await hashPassword(password, base64ToBytes(user.password_salt), user.password_iterations);
  return timingSafeEqual(hash, user.password_hash);
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function rateLimit(request, env, bucket, limit, windowMs) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const keyHash = await sha256(`${bucket}:${ip}`);
  const windowStart = Math.floor(now() / windowMs) * windowMs;
  const expiresAt = windowStart + windowMs;
  const key = `${bucket}:${keyHash}`;
  const existing = await env.DB.prepare('SELECT count, window_start FROM rate_limits WHERE id = ?').bind(key).first();
  if (!existing || existing.window_start !== windowStart) {
    await env.DB.prepare('INSERT OR REPLACE INTO rate_limits (id, bucket, key_hash, count, window_start, expires_at) VALUES (?, ?, ?, 1, ?, ?)').bind(key, bucket, keyHash, windowStart, expiresAt).run();
    return true;
  }
  if (existing.count >= limit) return false;
  await env.DB.prepare('UPDATE rate_limits SET count = count + 1, expires_at = ? WHERE id = ?').bind(expiresAt, key).run();
  return true;
}

async function verifyTurnstile(request, env, token) {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', token);
  form.append('remoteip', request.headers.get('cf-connecting-ip') || '');
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = await res.json();
  return !!data.success;
}

async function createSession(request, env, userId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64(tokenBytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const tokenHash = await sha256(`${requiredEnv(env, 'SESSION_SECRET')}:${token}`);
  const createdAt = now();
  const days = Number(env.SESSION_DAYS || 7);
  const expiresAt = createdAt + days * 24 * 60 * 60 * 1000;
  const ipHash = await sha256(request.headers.get('cf-connecting-ip') || 'unknown');
  const uaHash = await sha256(request.headers.get('user-agent') || 'unknown');
  await env.DB.prepare('INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip_hash, user_agent_hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id('sess'), userId, tokenHash, createdAt, expiresAt, ipHash, uaHash).run();
  return { token, expiresAt };
}

function sessionCookie(token, expiresAt) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(expiresAt).toUTCString()}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function getCookie(request, name) {
  const cookie = request.headers.get('cookie') || '';
  return cookie.split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`))?.slice(name.length + 1) || '';
}

async function currentUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256(`${requiredEnv(env, 'SESSION_SECRET')}:${token}`);
  const row = await env.DB.prepare(`
    SELECT users.id, users.identifier, users.created_at
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.revoked_at IS NULL AND sessions.expires_at > ?
  `).bind(tokenHash, now()).first();
  if (!row) return null;
  return { ...row, isAdmin: isAdmin(row, env) };
}

function requiredEnv(env, key) {
  const value = env[key];
  if (!value) throw new Error(`${key} is not configured`);
  return value;
}

function isAdmin(user, env) {
  const adminIdentifier = String(env.ADMIN_IDENTIFIER || '').trim().toLowerCase();
  return !!(user && adminIdentifier && String(user.identifier || '').trim().toLowerCase() === adminIdentifier);
}

async function requireAdmin(request, env) {
  const user = await currentUser(request, env);
  if (!user || !user.isAdmin) return null;
  return user;
}

async function register(request, env) {
  if (!(await rateLimit(request, env, 'register', 10, 15 * 60 * 1000))) return json({ error: 'محاولات كثيرة. يرجى المحاولة لاحقاً.' }, request, 429);
  const body = await readJson(request);
  if (!(await verifyTurnstile(request, env, body.turnstileToken))) return json({ error: 'تعذر التحقق الأمني.' }, request, 400);
  const identifier = normalizeIdentifier(body.identifier);
  if (!validIdentifier(identifier)) return json({ error: 'المعرف غير صالح. استخدم 3 إلى 80 حرفاً من الحروف أو الأرقام أو الرموز . _ - @' }, request, 400);
  if (!isStrongPassword(body.password)) return json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل.' }, request, 400);
  const exists = await env.DB.prepare('SELECT id FROM users WHERE identifier = ?').bind(identifier).first();
  if (exists) return json({ error: 'تم استخدام هذا المعرف من قبل' }, request, 409);
  const rec = await makePasswordRecord(body.password);
  const userId = id('usr');
  const ts = now();
  await env.DB.prepare('INSERT INTO users (id, identifier, password_hash, password_salt, password_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(userId, identifier, rec.hash, rec.salt, rec.iterations, ts, ts).run();
  const session = await createSession(request, env, userId);
  return json({ authenticated: true, user: { identifier, isAdmin: identifier === String(env.ADMIN_IDENTIFIER || '').trim().toLowerCase() } }, request, 201, { 'set-cookie': sessionCookie(session.token, session.expiresAt) });
}

async function login(request, env) {
  if (!(await rateLimit(request, env, 'login', 12, 15 * 60 * 1000))) return json({ error: 'محاولات كثيرة. يرجى المحاولة لاحقاً.' }, request, 429);
  const body = await readJson(request);
  if (!(await verifyTurnstile(request, env, body.turnstileToken))) return json({ error: 'تعذر التحقق الأمني.' }, request, 400);
  const identifier = normalizeIdentifier(body.identifier);
  const user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ?').bind(identifier).first();
  if (!user || !(await verifyPassword(String(body.password || ''), user))) return json({ error: 'المعرف أو كلمة المرور غير صحيحة.' }, request, 401);
  await env.DB.prepare('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?').bind(now(), now(), user.id).run();
  const session = await createSession(request, env, user.id);
  return json({ authenticated: true, user: publicUser(user, env) }, request, 200, { 'set-cookie': sessionCookie(session.token, session.expiresAt) });
}

async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) {
    const tokenHash = await sha256(`${requiredEnv(env, 'SESSION_SECRET')}:${token}`);
    await env.DB.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?').bind(now(), tokenHash).run();
  }
  return json({ ok: true }, request, 200, { 'set-cookie': clearSessionCookie() });
}

async function me(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ authenticated: false }, request);
  return json({ authenticated: true, user: publicUser(user, env) }, request);
}

function publicUser(user, env) {
  return { id: user.id, identifier: user.identifier, isAdmin: isAdmin(user, env) };
}

async function listProducts(request, env) {
  const products = await env.DB.prepare(`
    SELECT p.id, p.name, p.description, p.price, p.discount_price, p.origin, p.created_at,
      COALESCE(json_group_array(pi.url) FILTER (WHERE pi.url IS NOT NULL), '[]') AS images
    FROM products p
    LEFT JOIN product_images pi ON pi.product_id = p.id
    WHERE p.status = 'active'
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `).all();
  return json({ products: products.results.map(mapProduct) }, request);
}

function mapProduct(row) {
  const images = JSON.parse(row.images || '[]');
  return { id: row.id, name: row.name, description: row.description || '', price: row.price, discountPrice: row.discount_price, origin: row.origin, image: images[0] || '', images, createdAt: row.created_at };
}

async function createProduct(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  const body = await readJson(request);
  const validated = validateProduct(body);
  if (validated.error) return json({ error: validated.error }, request, 400);
  const ts = now();
  const productId = id('prod');
  await env.DB.batch([
    env.DB.prepare('INSERT INTO products (id, name, description, price, discount_price, origin, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(productId, validated.name, validated.description, validated.price, validated.discountPrice, validated.origin, 'active', admin.id, ts, ts),
    ...validated.images.map((url, index) => env.DB.prepare('INSERT INTO product_images (id, product_id, url, sort_order, alt_text, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id('img'), productId, url, index, validated.name, ts))
  ]);
  await audit(env, admin, 'create_product', 'product', productId, request);
  return json({ product: { id: productId, ...validated, discountPrice: validated.discountPrice, image: validated.images[0], createdAt: ts } }, request, 201);
}

async function updateProduct(request, env, productId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  const body = await readJson(request);
  const validated = validateProduct(body);
  if (validated.error) return json({ error: validated.error }, request, 400);
  const ts = now();
  await env.DB.batch([
    env.DB.prepare('UPDATE products SET name = ?, description = ?, price = ?, discount_price = ?, origin = ?, updated_at = ? WHERE id = ? AND status != ?')
      .bind(validated.name, validated.description, validated.price, validated.discountPrice, validated.origin, ts, productId, 'deleted'),
    env.DB.prepare('DELETE FROM product_images WHERE product_id = ?').bind(productId),
    ...validated.images.map((url, index) => env.DB.prepare('INSERT INTO product_images (id, product_id, url, sort_order, alt_text, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id('img'), productId, url, index, validated.name, ts))
  ]);
  await audit(env, admin, 'update_product', 'product', productId, request);
  return json({ ok: true }, request);
}

function validateProduct(body) {
  const name = String(body.name || '').trim();
  const description = String(body.description || '').trim();
  const origin = String(body.origin || '').trim();
  const price = Number(body.price);
  const discountPrice = body.discountPrice === undefined || body.discountPrice === null || body.discountPrice === '' ? null : Number(body.discountPrice);
  const images = Array.isArray(body.images) ? body.images.map(String).filter(v => /^https?:\/\//.test(v)) : [];
  if (!name || name.length > 180) return { error: 'اسم المنتج غير صالح.' };
  if (!origin || origin.length > 100) return { error: 'بلد المنشأ غير صالح.' };
  if (!Number.isFinite(price) || price <= 0) return { error: 'السعر غير صالح.' };
  if (discountPrice !== null && (!Number.isFinite(discountPrice) || discountPrice <= 0 || discountPrice >= price)) return { error: 'سعر الخصم غير صالح.' };
  if (images.length === 0 || images.length > 12) return { error: 'يرجى رفع صورة واحدة على الأقل وبحد أقصى 12 صورة.' };
  return { name, description, origin, price, discountPrice, images };
}

async function deleteProduct(request, env, productId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  await env.DB.prepare('UPDATE products SET status = ?, updated_at = ? WHERE id = ?').bind('deleted', now(), productId).run();
  await audit(env, admin, 'delete_product', 'product', productId, request);
  return json({ ok: true }, request);
}

async function uploadImage(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  if (!(await rateLimit(request, env, 'image_upload', 60, 60 * 60 * 1000))) return json({ error: 'محاولات رفع كثيرة. يرجى المحاولة لاحقاً.' }, request, 429);
  const form = await request.formData();
  const file = form.get('image');
  if (!(file instanceof File) || !file.type.startsWith('image/') || file.size > 8 * 1024 * 1024) return json({ error: 'ملف الصورة غير صالح.' }, request, 400);
  const url = await storeImage(file, env);
  await audit(env, admin, 'upload_image', 'image', null, request);
  return json({ url }, request, 201);
}

async function storeImage(file, env) {
  const key = `products/${crypto.randomUUID()}-${safeFileName(file.name || 'image')}`;
  if (env.IMAGE_PIPELINE && typeof env.IMAGE_PIPELINE.fetch === 'function') {
    const fd = new FormData();
    fd.append('image', file, file.name || key);
    fd.append('key', key);
    const res = await env.IMAGE_PIPELINE.fetch(new Request('https://image-pipeline/upload', { method: 'POST', body: fd }));
    if (!res.ok) throw new Error('Image pipeline failed');
    const data = await res.json();
    if (!data.url) throw new Error('Image pipeline returned no URL');
    return String(data.url);
  }
  if (env.IMAGE_PIPELINE_URL) {
    const fd = new FormData();
    fd.append('image', file, file.name || key);
    fd.append('key', key);
    const headers = env.IMAGE_PIPELINE_TOKEN ? { authorization: `Bearer ${env.IMAGE_PIPELINE_TOKEN}` } : {};
    const res = await fetch(env.IMAGE_PIPELINE_URL, { method: 'POST', headers, body: fd });
    if (!res.ok) throw new Error('Image pipeline failed');
    const data = await res.json();
    if (!data.url) throw new Error('Image pipeline returned no URL');
    return String(data.url);
  }
  if (env.IMAGES_BUCKET && env.PUBLIC_IMAGES_BASE_URL) {
    await env.IMAGES_BUCKET.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
    return `${String(env.PUBLIC_IMAGES_BASE_URL).replace(/\/$/, '')}/${key}`;
  }
  throw new Error('Image storage is not configured');
}

function safeFileName(name) { return name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'image'; }

async function createOrder(request, env) {
  if (!(await rateLimit(request, env, 'create_order', 20, 60 * 60 * 1000))) return json({ error: 'محاولات كثيرة. يرجى المحاولة لاحقاً.' }, request, 429);
  const body = await readJson(request);
  if (!(await verifyTurnstile(request, env, body.turnstileToken))) return json({ error: 'تعذر التحقق الأمني.' }, request, 400);
  const user = await currentUser(request, env);
  const phone = String(body.customerPhone || '').trim();
  const address = String(body.customerAddress || '').trim();
  const items = Array.isArray(body.items) ? body.items : [];
  if (!/^01[0125]\d{8}$/.test(phone)) return json({ error: 'رقم جوال غير صالح.' }, request, 400);
  if (address.length < 8 || address.length > 500) return json({ error: 'عنوان التوصيل غير صالح.' }, request, 400);
  if (items.length === 0 || items.length > 50) return json({ error: 'السلة غير صالحة.' }, request, 400);
  const ids = items.map(i => String(i.productId || ''));
  const placeholders = ids.map(() => '?').join(',');
  const rows = await env.DB.prepare(`SELECT id, name, price, discount_price FROM products WHERE status = 'active' AND id IN (${placeholders})`).bind(...ids).all();
  const productMap = new Map(rows.results.map(p => [p.id, p]));
  const orderItems = [];
  let total = 0;
  for (const item of items) {
    const product = productMap.get(String(item.productId || ''));
    const quantity = Number(item.quantity);
    if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 99) return json({ error: 'بيانات السلة غير صالحة.' }, request, 400);
    const unitPrice = product.discount_price ?? product.price;
    const lineTotal = Math.round(unitPrice * quantity * 100) / 100;
    total += lineTotal;
    orderItems.push({ productId: product.id, productName: product.name, unitPrice, quantity, lineTotal });
  }
  total = Math.round(total * 100) / 100;
  const ts = now();
  const orderId = id('ord');
  const orderNumber = `ORD-${String(ts).slice(-6)}-${Math.floor(100 + Math.random() * 900)}`;
  await env.DB.batch([
    env.DB.prepare('INSERT INTO orders (id, order_number, user_id, customer_identifier, customer_phone, customer_address, total, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(orderId, orderNumber, user?.id || null, user?.identifier || null, phone, address, total, 'pending', ts, ts),
    ...orderItems.map(item => env.DB.prepare('INSERT INTO order_items (id, order_id, product_id, product_name, unit_price, quantity, line_total) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(id('item'), orderId, item.productId, item.productName, item.unitPrice, item.quantity, item.lineTotal))
  ]);
  const whatsappUrl = buildWhatsAppUrl(env, { orderNumber, phone, address, items: orderItems, total });
  return json({ orderId, orderNumber, whatsappUrl }, request, 201);
}

function buildWhatsAppUrl(env, order) {
  const phone = String(env.WHATSAPP_PHONE || '').replace(/[^0-9]/g, '');
  if (!phone) throw new Error('WhatsApp is not configured');
  const lines = [
    'طلب جديد من متجر رغد', '',
    `رقم الطلب: ${order.orderNumber}`,
    `رقم العميل: ${order.phone}`,
    `العنوان: ${order.address}`,
    '',
    'المنتجات:',
    ...order.items.flatMap((item, idx) => [`${idx + 1}) ${item.productName}`, `الكمية: ${item.quantity}`, `السعر: ${item.unitPrice} جنيه`, `الإجمالي: ${item.lineTotal} جنيه`, '']),
    `المجموع الكلي: ${order.total} جنيه`
  ];
  return `https://wa.me/${phone}?text=${encodeURIComponent(lines.join('\n'))}`;
}


async function adminOrders(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  const rows = await env.DB.prepare(`
    SELECT o.*, COALESCE(json_group_array(json_object('productId', oi.product_id, 'name', oi.product_name, 'price', oi.unit_price, 'quantity', oi.quantity)) FILTER (WHERE oi.id IS NOT NULL), '[]') AS items
    FROM orders o LEFT JOIN order_items oi ON oi.order_id = o.id
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `).all();
  const orders = rows.results.map(o => ({ id: o.order_number, dbId: o.id, customerName: o.customer_identifier || `عميل (${o.customer_phone})`, customerPhone: o.customer_phone, customerAddress: o.customer_address, total: o.total, status: o.status, createdAt: o.created_at, items: JSON.parse(o.items || '[]') }));
  return json({ orders }, request);
}

async function updateOrderStatus(request, env, orderId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  const body = await readJson(request);
  const status = String(body.status || '');
  if (!['pending', 'completed', 'cancelled'].includes(status)) return json({ error: 'حالة الطلب غير صالحة.' }, request, 400);
  await env.DB.prepare('UPDATE orders SET status = ?, updated_at = ? WHERE id = ? OR order_number = ?').bind(status, now(), orderId, orderId).run();
  await audit(env, admin, 'update_order_status', 'order', orderId, request);
  return json({ ok: true }, request);
}

async function deleteOrder(request, env, orderId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'غير مصرح.' }, request, 403);
  await env.DB.prepare('DELETE FROM orders WHERE id = ? OR order_number = ?').bind(orderId, orderId).run();
  await audit(env, admin, 'delete_order', 'order', orderId, request);
  return json({ ok: true }, request);
}

async function audit(env, user, action, entityType, entityId, request) {
  const ipHash = await sha256(request.headers.get('cf-connecting-ip') || 'unknown');
  await env.DB.prepare('INSERT INTO audit_logs (id, actor_user_id, action, entity_type, entity_id, created_at, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id('audit'), user?.id || null, action, entityType, entityId, now(), ipHash).run();
}
