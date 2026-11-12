// frontend/src/offline/db.ts
//
// طبقة التخزين المحلي (IndexedDB عبر Dexie) لنمط Local-First.
// هذا الملف مستقل بالكامل عن باقي المشروع: لا يستورد أي شيء من api/client.ts
// أو من أي صفحة موجودة. أي صفحة لا تستخدمه تستمر بالعمل تماماً كما كانت
// قبل هذا التعديل — الإضافة بالكامل additive وليست تعديلاً على شيء قائم.
//
// ملاحظة أمنية مهمة (المشروع منصة فحص أمني): البيانات المخزَّنة هون تُقرأ
// من متصفح المستخدم بلا تشفير إضافي فوق حماية المتصفح نفسها. لهذا:
// - نخزّن فقط snapshot النتيجة الموحدة للفحص الحالي كي تبقى صفحات
//   Progress/Graph/Findings/Risk/Report متزامنة بعد التنقل أو إعادة تحميل الصفحة.
//   عند تسجيل الخروج تُمسح قاعدة Local-First بالكامل، فلا تبقى بيانات المستأجر
//   السابق على الجهاز المشترك.
// - `wipeLocalFirstStorage()` (بالأسفل) مربوطة فعلياً بدالة تسجيل الخروج
//   في auth/supabase.ts (استدعاء ديناميكي عبر import عند logout)، حتى لا
//   تبقى بيانات فحوصات مستأجر سابق داخل IndexedDB على جهاز مشترك.

import Dexie, { type Table } from "dexie";

export const LOCAL_FIRST_DB_NAME = "mirsad_local_first_v1";

// كل سجل مخزَّن محلياً يحمل حقول تحكّم إضافية (metadata) فوق حقول الـ backend
// الأصلية، تُستخدم لاحقاً بمحرك التزامن وحل التعارضات:
// - _tenantId: عزل بيانات كل مستأجر عن الآخر داخل نفس المتصفح (نفس مبدأ RLS بالسيرفر)
// - _updatedAt: طابع زمني محلي لآخر تعديل (أساس LWW بحل التعارضات)
// - _version: عدّاد نسخة السجل، يزيد بكل مزامنة ناجحة (لتمييز "قديم" عن "حديث")
// - _dirty: 1 يعني فيه تعديل محلي لسا ما تأكد نجاحه بالسيرفر (لا تُكتب فوقه من الشبكة)
// - _deleted: tombstone بدل الحذف الفعلي، ليصير الحذف نفسه قابلاً للمزامنة لاحقاً

export interface FindingLifecycleRecord {
  key: string; // `${scanId}::${findingId}`
  scanId: string;
  findingId: string;
  status: string;
  note: string;
  _tenantId: string;
  _updatedAt: number;
  _version: number;
  _dirty: 0 | 1;
  _deleted: 0 | 1;
}

export interface ScanSnapshotRecord {
  key: string; // scanId
  scanId: string;
  data: unknown; // نفس شكل ScanHistoryRecord / UnifiedScanResult كما يرجعه الـ backend
  _tenantId: string;
  _updatedAt: number;
  _version: number;
  _dirty: 0 | 1;
  _deleted: 0 | 1;
}

export interface ReportRecord {
  key: string; // scanId أو معرّف التقرير حسب الاستخدام
  scanId: string;
  content: unknown;
  _tenantId: string;
  _updatedAt: number;
  _version: number;
  _dirty: 0 | 1;
  _deleted: 0 | 1;
}

export interface FilterSettingsRecord {
  key: string; // مثال: "findings-page", "assets-page"
  value: Record<string, unknown>;
  _tenantId: string;
  _updatedAt: number;
  _version: number;
  _dirty: 0 | 1;
  _deleted: 0 | 1;
}

export type OutboxOp = "update-finding-lifecycle" | "update-filter-settings";

export interface OutboxRecord {
  id?: number; // auto-increment من Dexie
  op: OutboxOp;
  entityKey: string; // يشير لسجل الجدول المتأثر أعلاه
  operationId: string; // معرّف فريد للعملية (UUID) — يُرسل للسيرفر كـ Idempotency-Key
  payload: Record<string, unknown>;
  previousValue: Record<string, unknown> | null; // *** إصلاح ***: نسخة كاملة من السجل قبل هذا التعديل، لازمة لـ rollback حقيقي (سابقًا كنا نمسح _dirty فقط بدون استرجاع القيمة)
  baseVersion: number; // نسخة السجل وقت بدء التعديل — تُرسَل فعليًا للسيرفر الآن (كانت مخزَّنة فقط بدون استخدام)
  attempts: number;
  createdAt: number;
  lastError?: string;
}

export interface ConflictLogRecord {
  id?: number;
  entityKey: string;
  table: string;
  localValue: unknown;
  serverValue: unknown;
  resolvedValue: unknown;
  overriddenFields: string[];
  resolvedAt: number;
}

class LocalFirstDatabase extends Dexie {
  findingLifecycle!: Table<FindingLifecycleRecord, string>;
  scanSnapshots!: Table<ScanSnapshotRecord, string>;
  reports!: Table<ReportRecord, string>;
  filterSettings!: Table<FilterSettingsRecord, string>;
  outbox!: Table<OutboxRecord, number>;
  conflictLog!: Table<ConflictLogRecord, number>;

  constructor() {
    super(LOCAL_FIRST_DB_NAME);
    // v1: أول نسخة من الـschema. أي تعديل مستقبلي على الحقول يجب أن يكون
    // .version(2).stores({...}).upgrade(...) جديد فوق هذا — Dexie يتكفّل
    // بترحيل بيانات المستخدمين الحاليين تلقائياً بدون فقدانها.
    this.version(1).stores({
      findingLifecycle: "key, scanId, _tenantId, _dirty",
      scanSnapshots: "key, _tenantId, _dirty",
      reports: "key, scanId, _tenantId, _dirty",
      filterSettings: "key, _tenantId, _dirty",
      outbox: "++id, entityKey, createdAt",
      conflictLog: "++id, entityKey, resolvedAt",
    });
    this.version(2).stores({
      findingLifecycle: "key, scanId, _tenantId, _dirty",
      scanSnapshots: "key, _tenantId, _dirty",
      reports: "key, scanId, _tenantId, _dirty",
      filterSettings: "key, _tenantId, _dirty",
      outbox: "++id, entityKey, createdAt",
      conflictLog: "++id, entityKey, resolvedAt",
    }).upgrade(async (tx) => {
      await tx.table("outbox").toCollection().modify((record: Record<string, unknown>) => { delete record.accessToken; });
    });
  }
}

export const localDb = new LocalFirstDatabase();

/**
 * يمسح كل بيانات Local-First من المتصفح دفعة واحدة. استدعِها من دالة
 * تسجيل الخروج الحالية بالمشروع (مثال: داخل src/auth/supabase.ts، بالدالة
 * التي تصفّر الجلسة) حتى لا تبقى بيانات فحوصات مستأجر سابق على جهاز مشترك.
 */

export const CURRENT_SCAN_ID_KEY = "mirsad_current_scan_id";

export async function saveCurrentScanSnapshot(data: unknown, scanId: string, tenantId = ""): Promise<void> {
  await localDb.scanSnapshots.put({
    key: scanId,
    scanId,
    data,
    _tenantId: tenantId,
    _updatedAt: Date.now(),
    _version: 1,
    _dirty: 0,
    _deleted: 0,
  });
  try { localStorage.setItem(CURRENT_SCAN_ID_KEY, scanId); } catch { /* storage unavailable */ }
}

export async function loadCurrentScanSnapshot(tenantId?: string): Promise<ScanSnapshotRecord | null> {
  let scanId = "";
  try { scanId = localStorage.getItem(CURRENT_SCAN_ID_KEY) ?? ""; } catch { /* storage unavailable */ }
  if (!scanId) return null;
  const record = await localDb.scanSnapshots.get(scanId);
  if (!record || record._deleted) return null;
  if (tenantId && record._tenantId && record._tenantId !== tenantId) return null;
  return record;
}

export async function clearCurrentScanSnapshot(): Promise<void> {
  let scanId = "";
  try { scanId = localStorage.getItem(CURRENT_SCAN_ID_KEY) ?? ""; localStorage.removeItem(CURRENT_SCAN_ID_KEY); } catch { /* storage unavailable */ }
  if (scanId) await localDb.scanSnapshots.delete(scanId);
}

export async function wipeLocalFirstStorage(): Promise<void> {
  await localDb.delete();
}
