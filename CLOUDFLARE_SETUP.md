# إعداد Cloudflare لمتجر رغد

## الملفات

- `RAGHAD_STORE_SITE.html`: واجهة المتجر الحالية بعد ربطها بالـWorker.
- `src/worker.js`: Cloudflare Worker المسؤول عن الحسابات والمنتجات والطلبات ورفع الصور.
- `migrations/0001_initial.sql`: D1 schema كامل وقابل للتنفيذ.
- `wrangler.toml`: إعدادات Worker والـbindings بأسماء واضحة وقيم غير حقيقية.
- `package.json`: أوامر تشغيل ونشر مساعدة.

## المتغيرات والـbindings

| الاسم | النوع | أين يوضع | Secret | الغرض |
| --- | --- | --- | --- | --- |
| `DB` | D1 binding | `wrangler.toml` أو لوحة Cloudflare | لا | اتصال Worker بقاعدة D1 |
| `ADMIN_IDENTIFIER` | Worker secret | Cloudflare Worker Secrets | نعم | معرف الحساب الإداري المحدد مسبقًا، وتُحسب صلاحية الإدارة server-side فقط |
| `WHATSAPP_PHONE` | Worker secret | Cloudflare Worker Secrets | نعم | رقم WhatsApp بصيغة دولية بدون `+` لبناء رابط الطلب |
| `SESSION_SECRET` | Worker secret | Cloudflare Worker Secrets | نعم | حماية جلسات المستخدمين واشتقاق hash آمن للـcookies |
| `TURNSTILE_SITE_KEY` | Worker variable | `wrangler.toml` أو لوحة Cloudflare | لا | مفتاح Turnstile العام إذا أردت تفعيله في الواجهة |
| `TURNSTILE_SECRET_KEY` | Worker secret | Cloudflare Worker Secrets | نعم | التحقق server-side من Turnstile |
| `SESSION_DAYS` | Worker variable | `wrangler.toml` أو لوحة Cloudflare | لا | عدد أيام صلاحية الجلسة |
| `IMAGE_PIPELINE` | Service binding اختياري | Cloudflare Worker bindings | لا | Pipeline مخصص يستقبل الصورة ويرجع JSON يحتوي `url` |
| `IMAGE_PIPELINE_URL` | Worker variable اختياري | `wrangler.toml` أو لوحة Cloudflare | لا | endpoint خارجي/داخلي للـPipeline يرجع JSON يحتوي `url` |
| `IMAGE_PIPELINE_TOKEN` | Worker secret اختياري | Cloudflare Worker Secrets | نعم | Bearer token للـPipeline إذا كان endpoint يتطلبه |
| `IMAGES_BUCKET` | R2 binding اختياري | Cloudflare Worker bindings | لا | بديل تخزين صور في R2 إذا استخدمته |
| `PUBLIC_IMAGES_BASE_URL` | Worker variable اختياري | `wrangler.toml` أو لوحة Cloudflare | لا | الدومين العام لعرض صور R2 |

## إعداد D1

1. أنشئ قاعدة D1 من Cloudflare أو Wrangler.
2. اربطها بالـWorker باسم binding التالي فقط:

```text
DB
```

3. ضع `database_id` الحقيقي مكان:

```text
REPLACE_WITH_YOUR_D1_DATABASE_ID
```

4. شغل migration:

```bash
npm run d1:migrate:remote
```

أو عدل اسم قاعدة البيانات في `package.json` إذا غيرت `database_name`.

## إعداد الأسرار

نفذ الأوامر التالية وضع القيم الحقيقية عند السؤال:

```bash
npx wrangler secret put ADMIN_IDENTIFIER
npx wrangler secret put WHATSAPP_PHONE
npx wrangler secret put SESSION_SECRET
npx wrangler secret put TURNSTILE_SECRET_KEY
```

إذا استخدمت pipeline يحتاج token:

```bash
npx wrangler secret put IMAGE_PIPELINE_TOKEN
```

## إعداد الصور

يدعم Worker ثلاث طرق، اختر واحدة فقط في Cloudflare:

1. Service binding باسم `IMAGE_PIPELINE` يستقبل `POST` يحتوي `FormData` بالحقل `image` ويرجع:

```json
{ "url": "https://example.com/image.webp" }
```

2. متغير `IMAGE_PIPELINE_URL` يشير إلى endpoint يستقبل `FormData` بالحقل `image` ويرجع نفس JSON.

3. R2 binding باسم `IMAGES_BUCKET` مع `PUBLIC_IMAGES_BASE_URL` لعرض الصور.

في كل الحالات D1 يخزن URL فقط ولا يخزن ملف الصورة أو Base64.

## إعداد Turnstile

إذا وضعت `TURNSTILE_SECRET_KEY` في Worker فسيطلب Worker توكن Turnstile في التسجيل وتسجيل الدخول وإنشاء الطلب. إذا تركته غير مضبوط فلن يمنع الطلبات بسبب Turnstile، وتبقى حماية rate limiting داخل D1 فعالة.

## تشغيل محلي

```bash
npm install
npm run dev
```

## النشر

```bash
npm run deploy
```

## ملاحظات أمنية

- لا تضع `ADMIN_IDENTIFIER` أو `WHATSAPP_PHONE` أو `SESSION_SECRET` داخل HTML.
- لا تحفظ كلمات المرور كنص صريح؛ Worker يستخدم PBKDF2 مع salt لكل مستخدم.
- لا توجد خانة صلاحية في التسجيل، وكل حساب جديد مستخدم عادي ضمنيًا، والأدمن يُحدد فقط بمطابقة `ADMIN_IDENTIFIER`.
- الطلب لا يحتوي على شركة شحن، والشراء متاح كضيف أو كمستخدم مسجل.
- صلاحية الإدارة تتحقق داخل Worker لكل endpoint إداري.
- الطلبات تحفظ في D1 قبل إرجاع رابط WhatsApp.
- السلة تبقى محلية في المتصفح حتى تأكيد الطلب فقط.
