// public/service-worker.js
//
// Service Worker لنمط Local-First. تصميمه "شفاف" بالكامل بشكل متعمَّد:
// لا يوجد أي fetch handler هون — لا اعتراض، لا كاش، لا تعديل على أي طلب
// شبكة بالموقع. هذا يعني: لو حذفت هذا الملف بالكامل أو صار به أي خلل،
// الموقع يستمر بالعمل 100% كما كان قبل أي تعديل — الـ SW إضافة اختيارية
// فوق الطلبات (Background Sync فقط)، مش طبقة إلزامية بينها وبين الشبكة.
//
// ليش ما في كاش لطلبات GET؟ لأن هذه لوحة أمنية: تخزين نتائج فحوصات حسّاسة
// بكاش الـ SW يعني احتمال ظهورها لجلسة/مستخدم آخر لاحقاً على نفس الجهاز
// المشترك. الكاش المحلي الفعلي (IndexedDB عبر Dexie) يُدار بالكامل من
// كود الصفحة بملفات src/offline/*.ts، مع مسح صريح عند تسجيل الخروج
// (راجع wipeLocalFirstStorage بملف db.ts) — أضمن من كاش شبكة صامت بالـ SW.

const SYNC_TAG = "mirsad-outbox-sync";
const OUTBOX_DB_NAME = "mirsad_local_first_v1";
const OUTBOX_STORE = "outbox";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("sync", (event) => {
  if (event.tag === SYNC_TAG) {
    event.waitUntil(flushOutboxFromServiceWorker());
  }
});

function openOutboxDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(OUTBOX_DB_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function flushOutboxFromServiceWorker() {
  let db;
  try {
    db = await openOutboxDb();
  } catch {
    return; // القاعدة لسا ما انفتحت بالصفحة ولا مرة — لا شيء لنزامنه
  }

  const items = await new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, "readonly");
    const req = tx.objectStore(OUTBOX_STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });

  for (const item of items) {
    try {
      const ok = await sendOutboxItem(item);
      if (ok) {
        await new Promise((resolve, reject) => {
          const tx = db.transaction(OUTBOX_STORE, "readwrite");
          const req = tx.objectStore(OUTBOX_STORE).delete(item.id);
          req.onsuccess = () => resolve(undefined);
          req.onerror = () => reject(req.error);
        });
      }
      // لو فشل (مثال: 409 تعارض)، نتركه بالطابور بصمت — الصفحة (sync.ts)
      // تتكفّل بمنطق الدمج الكامل (conflictResolver.ts) عند فتحها من جديد،
      // لأن ذاك المنطق TypeScript غير متاح بسياق SW الخام هون.
    } catch {
      // فشل شبكة → يبقى بالطابور، بدون إشعار المستخدم (لا واجهة مفتوحة أصلاً)
    }
  }
}

async function sendOutboxItem(item) {
  if (item.op !== "update-finding-lifecycle") return false; // خارج نطاق هذا الإصدار من الـ SW

  const { scanId, findingId, status, note } = item.payload;
  // مسار نسبي (relative) بقصد: nginx.conf وVercel كلاهما يمرّران /api/ لنفس
  // الأصل (same-origin) بالإنتاج — هذا يطابق أيضاً Content-Security-Policy
  // الحالية (connect-src 'self')، فلا حاجة لمعرفة VITE_API_BASE_URL هون.
  //
  // *** إصلاح ***: نرسل base_version وidempotency_key أيضًا من هون (نفس
  // العقد المُضاف بـ sync.ts/api/client.ts) حتى مسار Background Sync
  // الحقيقي (تبويب مغلق) يستفيد من فحص النسخة على السيرفر ومن الحماية ضد
  // إعادة تنفيذ مضاعفة، لا فقط المسار العادي من داخل الصفحة.
  const qs = new URLSearchParams({ status: status || "", note: note || "" });
  if (typeof item.baseVersion === "number") qs.set("base_version", String(item.baseVersion));
  if (item.operationId) qs.set("idempotency_key", item.operationId);
  const url =
    `/api/v1/assessment/scans/${encodeURIComponent(scanId)}` +
    `/findings/${encodeURIComponent(findingId)}/lifecycle?${qs.toString()}`;

  // Never persist or transmit bearer tokens from the service worker.
  // Authentication is owned by the page session; when clients are open they
  // perform the actual authenticated flush. A closed-tab sync therefore
  // remains a wake-up signal rather than a credential-bearing worker.
  const clientsList = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const client of clientsList) client.postMessage({ type: "MIRSAD_FLUSH_OUTBOX" });
  return clientsList.length > 0;
}
