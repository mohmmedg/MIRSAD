// frontend/src/offline/registerServiceWorker.ts
//
// نقطة التفعيل الوحيدة لكامل نظام Local-First. مغلَّفة بمتغيّر بيئة
// (VITE_ENABLE_LOCAL_FIRST) كمفتاح إيقاف فوري: تعطيل الميزة بالكامل =
// حذف/تصفير هذا المتغيّر بملف .env وإعادة نشر الموقع، بدون لمس أي كود آخر.
//
// هذا الملف هو الشيء الوحيد الذي يُستدعى من main.tsx — كل بقية هذا المجلد
// (offline/*) لا يُحمَّل أو يُنفَّذ إطلاقاً إذا كان المفتاح غير مفعَّل.

/**
 * *** إضافة ***: يقرأها أي مكان بالواجهة (مثل FindingDrawer.tsx) ليقرر
 * هل يستخدم المسار المتفائل (enqueueFindingLifecycleUpdate) أو المسار
 * القديم المباشر (updateFindingLifecycle) — بدون تكرار قراءة
 * import.meta.env في كل مكان، ونفس مصدر الحقيقة المستخدم بالتسجيل.
 */
export function isLocalFirstEnabled(): boolean {
  return import.meta.env.VITE_ENABLE_LOCAL_FIRST === "true";
}

export function registerLocalFirst(): void {
  const enabled = isLocalFirstEnabled();
  if (!("serviceWorker" in navigator)) return;

  if (!enabled) {
    // If an older build enabled Local-First, simply setting the flag to false
    // must also remove that old worker. Otherwise a previously registered
    // worker can survive a rebuild and keep controlling this origin.
    window.addEventListener("load", () => {
      void navigator.serviceWorker.getRegistrations().then((registrations) => {
        for (const registration of registrations) {
          const url = registration.active?.scriptURL || registration.waiting?.scriptURL || registration.installing?.scriptURL || "";
          if (url === new URL("/service-worker.js", window.location.origin).href) {
            void registration.unregister();
          }
        }
      }).catch(() => undefined);
    });
    return;
  }

  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/service-worker.js").catch((err: unknown) => {
      // فشل تسجيل الـ Service Worker لا يوقف الموقع أبداً — الموقع يستمر
      // بالعمل بنمط Server-First العادي تماماً كما كان قبل هذا التعديل،
      // وتُفقَد فقط ميزة Background Sync الإضافية.
      // eslint-disable-next-line no-console
      console.warn("[local-first] service worker registration failed:", err);
    });
  });

  void import("./sync").then(({ initSyncOnReconnect }) => initSyncOnReconnect());
}
