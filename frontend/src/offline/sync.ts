// frontend/src/offline/sync.ts
//
// محرك التزامن. مسؤول عن ثلاثة أشياء منفصلة بوضوح:
// 1) flushOutbox: إرسال كل عناصر outbox المعلَّقة للسيرفر بالترتيب.
// 2) requestBackgroundSync / scheduleFallbackSync: تسجيل Background Sync
//    الحقيقي عند دعمه، أو fallback بسيط (سنشن اتصال + مؤقّت دوري) عند عدمه
//    (Safari وFirefox حالياً لا يدعمان SyncManager).
// 3) syncFindingLifecycleFromServer: قراءة الحقيقة من السيرفر ودمجها مع أي
//    تعديل محلي معلَّق، بدون الكتابة فوق تعديل لسا ما اتزامن.
//
// *** إصلاحات مقابل النسخة السابقة (بعد تدقيق) ***
// أ) rollbackOutboxItem أصبح يستعيد فعليًا القيمة المحفوظة بـ
//    item.previousValue بدل تصفير _dirty فقط — لا تبقى قيمة خاطئة بالشاشة
//    بعد رفض صريح من السيرفر.
// ب) baseVersion وoperationId يُرسلان فعليًا للسيرفر (base_version /
//    idempotency_key) — راجع backend/app/core/assessment_lifecycle.py
//    وbackend/app/api/routes/assessment.py لطرف السيرفر المقابل.
// ج) 409 أصبح مسارًا حقيقيًا قابلاً للحدوث فعليًا (السيرفر يرجّعه الآن عند
//    تعارض نسخة) ويُعالَج بدمج LWW الحالي ثم إما إسقاط العنصر (لو خسر
//    التعديل المحلي كل الحقول) أو إعادة إرساله بنسخة أساس جديدة.

import { localDb, type OutboxRecord, type FindingLifecycleRecord } from "./db";
import { mergeByFieldLWW } from "./conflictResolver";
import { updateFindingLifecycle, getFindingLifecycle, ApiError } from "../api/client";

export type SyncListener = (event: { pending: number; syncing: boolean }) => void;
const listeners = new Set<SyncListener>();

export function onSyncStatusChange(fn: SyncListener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify(pending: number, syncing: boolean): void {
  for (const fn of listeners) fn({ pending, syncing });
}

let flushing = false;

/** يرسل كل عناصر outbox المعلَّقة. آمن للاستدعاء المتكرر (لا يشغّل مرتين بالتوازي). */
export async function flushOutbox(): Promise<void> {
  if (flushing) return;
  flushing = true;
  try {
    const pending = await localDb.outbox.orderBy("createdAt").toArray();
    notify(pending.length, true);
    for (const item of pending) {
      await processOutboxItem(item);
    }
  } finally {
    flushing = false;
    const remaining = await localDb.outbox.count();
    notify(remaining, false);
  }
}

async function processOutboxItem(item: OutboxRecord): Promise<void> {
  try {
    if (item.op === "update-finding-lifecycle") {
      const { scanId, findingId, status, note } = item.payload as {
        scanId: string;
        findingId: string;
        status: string;
        note: string;
      };
      // *** إصلاح ب: نرسل baseVersion وoperationId فعليًا ***
      await updateFindingLifecycle(scanId, findingId, status, note, item.baseVersion, item.operationId);

      // بعد نجاح الإرسال، نجيب أحدث نسخة كاملة من السيرفر لنفس الفحص
      // (الـ endpoint الحالي بالـ backend يرجّع lifecycle الفحص كامل، مو
      // سجل مفرد) ونطبّق دمج الحقل بالحقل تحسباً لتعديل موازٍ حصل على
      // نفس الـ finding من جلسة/جهاز آخر بين لحظة enqueue ولحظة الإرسال.
      await reconcileAfterSuccessfulWrite(item.entityKey, scanId, findingId);
    } else if (item.op === "update-filter-settings") {
      // مثال إضافي جاهز: لو صار عندك مستقبلاً endpoint لحفظ فلاتر اللوحة
      // بالسيرفر (لا يوجد حالياً بالـ backend)، نفس نمط finding-lifecycle
      // يتكرر هون. حالياً الفلاتر تُخزَّن محلياً فقط.
      await Promise.resolve();
    }

    await localDb.outbox.delete(item.id!);
  } catch (err) {
    const status = err instanceof ApiError ? err.status : undefined;
    const body = err instanceof ApiError ? err.body : undefined;

    if (status === 409) {
      // *** إصلاح ج: تعارض نسخة حقيقي من السيرفر ***
      // جسم الاستجابة يحمل الحالة الحالية بالسيرفر (current_status/current_note/
      // current_version) — راجع assessment.py. ندمجها بالمحلي حقل-حقل، ثم:
      // - لو التعديل المحلي انهزم بكل حقوله → نسقط العنصر (لا شيء نرسله بعد).
      // - لو فاز التعديل المحلي بحقل واحد على الأقل → نحدّث baseVersion
      //   ونعيد المحاولة بالمرة القادمة (نُبقيه بالطابور).
      await handleVersionConflict(item, body);
    } else if (status !== undefined && status >= 400 && status < 500 && status !== 401) {
      // رفض صريح آخر من السيرفر (مثال: صلاحيات غير كافية) → rollback حقيقي،
      // لأن إعادة المحاولة لن تنجح مهما تكررت.
      await rollbackOutboxItem(item);
      await localDb.outbox.delete(item.id!);
    } else {
      // فشل شبكة، أو 401 (توكن منتهي بانتظار تجديد) → يبقى بالطابور ويُعاد لاحقاً.
      await localDb.outbox.update(item.id!, {
        attempts: item.attempts + 1,
        lastError: String((err as Error)?.message ?? err),
      });
    }
  }
}

async function reconcileAfterSuccessfulWrite(entityKey: string, scanId: string, findingId: string): Promise<void> {
  const serverState = await getFindingLifecycle(scanId);
  const serverItem = serverState.items.find((i) => i.finding_id === findingId);
  const local = await localDb.findingLifecycle.get(entityKey);
  if (!serverItem || !local) return;
  const { merged, overridden } = mergeByFieldLWW(
    local,
    {
      ...local,
      status: serverItem.status,
      note: serverItem.note,
      _updatedAt: new Date(serverItem.updated_at).getTime(),
      _version: serverItem.version,
    },
    ["status", "note"]
  );
  if (overridden.length > 0) {
    await localDb.conflictLog.add({
      entityKey,
      table: "findingLifecycle",
      localValue: local,
      serverValue: serverItem,
      resolvedValue: merged,
      overriddenFields: overridden.map((o) => String(o.field)),
      resolvedAt: Date.now(),
    });
  }
  await localDb.findingLifecycle.put({ ...merged, _dirty: 0 });
}

/**
 * يعالج 409 (تعارض نسخة حقيقي أرجعه السيرفر الآن). يدمج الحالة المحلية
 * المعلَّقة مع حالة السيرفر الحالية (اللي وصلت بجسم خطأ الـ 409 نفسه —
 * بدون الحاجة لطلب GET إضافي)، ثم يقرر إسقاط العنصر أو إعادة جدولته
 * بنسخة أساس جديدة.
 */
async function handleVersionConflict(item: OutboxRecord, body: Record<string, unknown> | undefined): Promise<void> {
  const local = await localDb.findingLifecycle.get(item.entityKey);
  if (!local) {
    await localDb.outbox.delete(item.id!);
    return;
  }
  const serverStatus = typeof body?.current_status === "string" ? body.current_status : local.status;
  const serverNote = typeof body?.current_note === "string" ? body.current_note : local.note;
  const serverVersion = typeof body?.current_version === "number" ? body.current_version : local._version;
  const serverUpdatedAt =
    typeof body?.current_updated_at === "string" ? new Date(body.current_updated_at).getTime() : Date.now();

  const { merged, overridden } = mergeByFieldLWW(
    local,
    { ...local, status: serverStatus, note: serverNote, _updatedAt: serverUpdatedAt, _version: serverVersion },
    ["status", "note"]
  );

  await localDb.conflictLog.add({
    entityKey: item.entityKey,
    table: "findingLifecycle",
    localValue: local,
    serverValue: { status: serverStatus, note: serverNote, version: serverVersion },
    resolvedValue: merged,
    overriddenFields: overridden.map((o) => String(o.field)),
    resolvedAt: Date.now(),
  });

  if (overridden.length === 0) {
    // التعديل المحلي لم يفز بأي حقل — السيرفر هو الأحدث بالكامل. نطبّق
    // قيمته محليًا ونسقط العنصر من الطابور (لا شيء إضافي لإرساله).
    await localDb.findingLifecycle.put({ ...merged, _dirty: 0 });
    await localDb.outbox.delete(item.id!);
    return;
  }

  // التعديل المحلي فاز بحقل واحد على الأقل — نطبّق النتيجة المدموجة
  // محليًا (تبقى _dirty=1 لأنها لسا غير مؤكدة بالسيرفر) ونعيد جدولة نفس
  // العملية بنسخة أساس جديدة (serverVersion) بدل النسخة القديمة المرفوضة.
  await localDb.findingLifecycle.put({ ...merged, _dirty: 1 });
  await localDb.outbox.update(item.id!, {
    baseVersion: serverVersion,
    payload: { ...item.payload, status: merged.status, note: merged.note },
    attempts: item.attempts + 1,
    lastError: "version_conflict_merged_retry",
  });
}

async function rollbackOutboxItem(item: OutboxRecord): Promise<void> {
  if (item.op === "update-finding-lifecycle") {
    // *** إصلاح أ: استرجاع حقيقي للقيمة السابقة ***
    // سابقًا: كنا نزيل علامة "_dirty" فقط ونترك القيمة المرفوضة معروضة
    // بالشاشة لحد ما تُعاد قراءة الصفحة. الآن نعيد فعليًا القيمة كما كانت
    // قبل هذا التعديل تحديدًا (previousValue المحفوظة وقت enqueue).
    if (item.previousValue) {
      await localDb.findingLifecycle.put({
        ...(item.previousValue as unknown as FindingLifecycleRecord),
        _dirty: 0,
      });
    } else {
      // لم يكن للسجل وجود محلي قبل هذا التعديل (أول كتابة من هذا الجهاز) —
      // أقرب سلوك صحيح هو حذفه محليًا (tombstone) بدل ترك قيمة مرفوضة معروضة.
      await localDb.findingLifecycle.update(item.entityKey, { _dirty: 0, _deleted: 1 });
    }
  }
}

/**
 * يقرأ حالة lifecycle الحقيقية من السيرفر ويدمجها بالكاش المحلي، بدون
 * الكتابة فوق أي سجل عليه تعديل محلي معلَّق بالطابور بعد (_dirty === 1) —
 * ذاك يُترك لـ processOutboxItem ليدمجه بعد إرساله فعلياً.
 */
export async function syncFindingLifecycleFromServer(scanId: string, tenantId: string): Promise<void> {
  const server = await getFindingLifecycle(scanId);
  for (const s of server.items) {
    const key = `${scanId}::${s.finding_id}`;
    const local = await localDb.findingLifecycle.get(key);
    if (local && local._dirty === 1) continue;
    await localDb.findingLifecycle.put({
      key,
      scanId,
      findingId: s.finding_id,
      status: s.status,
      note: s.note,
      _tenantId: tenantId,
      _updatedAt: new Date(s.updated_at).getTime(),
      _version: s.version,
      _dirty: 0,
      _deleted: 0,
    });
  }
}

// --- Background Sync + fallback ---

const SYNC_TAG = "mirsad-outbox-sync";

export function supportsBackgroundSync(): boolean {
  return "serviceWorker" in navigator && "SyncManager" in window;
}

/** يسجّل Background Sync الحقيقي عند دعم المتصفح له، وإلا يفعّل الـ fallback فوراً. */
export async function requestBackgroundSync(): Promise<void> {
  if (!supportsBackgroundSync()) {
    scheduleFallbackSync();
    return;
  }
  try {
    const reg = await navigator.serviceWorker.ready;
    // SyncManager غير موجود بأنواع TypeScript القياسية بعد (lib.dom.d.ts) —
    // الاستدعاء صحيح وقت التشغيل بالمتصفحات الداعمة (Chrome/Edge/Android).
    await (reg as ServiceWorkerRegistration & { sync: { register(tag: string): Promise<void> } }).sync.register(
      SYNC_TAG
    );
  } catch {
    // بعض المتصفحات تدّعي الدعم لكن ترفض التسجيل فعلياً (مثال: خاصية معطّلة
    // بإعدادات المستخدم) — نرجع لل fallback بدل ترك الطابور معلَّقاً بلا محاولة.
    scheduleFallbackSync();
  }
}

let fallbackTimer: number | null = null;

/** Fallback لما Background Sync غير مدعوم: محاولة دورية كل 20 ثانية طالما فيه اتصال. */
export function scheduleFallbackSync(): void {
  if (fallbackTimer !== null) return;
  fallbackTimer = window.setInterval(() => {
    if (!navigator.onLine) return;
    void localDb.outbox.count().then((count) => {
      if (count === 0) {
        if (fallbackTimer !== null) window.clearInterval(fallbackTimer);
        fallbackTimer = null;
        return;
      }
      void flushOutbox();
    });
  }, 20_000);
}

/** يفعّل "sync-on-reconnect": إرسال فوري عند رجوع الاتصال، ومحاولة أولى عند تحميل الصفحة. */
export function initSyncOnReconnect(): void {
  window.addEventListener("online", () => {
    void flushOutbox();
  });
  if (navigator.onLine) void flushOutbox();
}
