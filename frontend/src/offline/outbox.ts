// frontend/src/offline/outbox.ts
//
// نقطة الدخول الوحيدة لأي "كتابة متفائلة" (Optimistic UI Update). أي مكان
// بالواجهة يستدعي دالة من هذا الملف يحصل تلقائياً على:
// 1) تحديث فوري بـ IndexedDB (Instant Write) — الواجهة تعكسه بدون انتظار الشبكة.
// 2) إضافة العملية لطابور outbox، مع حفظ القيمة *السابقة* كاملة (previousValue)
//    حتى يكون الـ rollback لاحقًا استرجاعًا حقيقيًا للقيمة، لا مجرد تصفير علم.
// 3) محاولة إرسال فورية لو في اتصال.
// 4) تسجيل Background Sync (أو fallback) كخط دفاع ثانٍ لو الإرسال الفوري فشل
//    أو التبويب انقفل قبل اكتماله.
//
// *** إصلاح مقابل النسخة السابقة ***
// - previousValue: يحفظ السجل بالكامل كما كان قبل الكتابة المتفائلة، بدل
//   الاعتماد فقط على "_dirty=0" كعلامة تراجع (كانت تُبقي القيمة الخاطئة
//   بالشاشة لحد ما تُعاد قراءة الصفحة من السيرفر).
// - operationId: UUID فريد لكل عملية، يُرسل كـ Idempotency-Key للسيرفر
//   (راجع sync.ts وapi/client.ts) بدل الاعتماد فقط على كون العملية "set"
//   طبيعيًا آمنة عند التكرار.

import { localDb } from "./db";
import { flushOutbox, requestBackgroundSync } from "./sync";

function newOperationId(): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  if (uuid) return uuid;
  // fallback لبيئات بدون crypto.randomUUID (متصفحات قديمة جدًا)
  return `op_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
}

export async function enqueueFindingLifecycleUpdate(params: {
  scanId: string;
  findingId: string;
  status: string;
  note: string;
  tenantId: string;
}): Promise<void> {
  const key = `${params.scanId}::${params.findingId}`;
  const existing = await localDb.findingLifecycle.get(key);
  const baseVersion = existing?._version ?? 0;

  // *** إصلاح: نحفظ نسخة كاملة من السجل الحالي (قبل الكتابة المتفائلة) ***
  // هذه هي القيمة التي سنعيدها فعليًا للشاشة لو رفض السيرفر العملية صراحةً.
  const previousValue: Record<string, unknown> | null = existing
    ? { ...existing }
    : null;

  const operationId = newOperationId();

  // 1) الكتابة المحلية الفورية.
  await localDb.findingLifecycle.put({
    key,
    scanId: params.scanId,
    findingId: params.findingId,
    status: params.status,
    note: params.note,
    _tenantId: params.tenantId,
    _updatedAt: Date.now(),
    _version: baseVersion,
    _dirty: 1,
    _deleted: 0,
  });

  // 2) الإضافة لطابور outbox — مع previousValue وoperationId وbaseVersion
  //    (الثلاثة تُستخدم فعليًا الآن بـ sync.ts، وليست حقولاً زخرفية).
  await localDb.outbox.add({
    op: "update-finding-lifecycle",
    entityKey: key,
    operationId,
    payload: { scanId: params.scanId, findingId: params.findingId, status: params.status, note: params.note },
    previousValue,
    baseVersion,
    attempts: 0,
    createdAt: Date.now(),
  });

  // 3) محاولة فورية + 4) تسجيل خط الدفاع الثاني
  if (navigator.onLine) void flushOutbox();
  void requestBackgroundSync();
}
