// frontend/src/offline/conflictResolver.ts
//
// حل تعارضات مبسّط (simplified CRDT) على مستوى الحقل الواحد: LWW-Register
// (Last-Write-Wins) لكل حقل بمفرده، وليس للسجل كامل. الفرق مهم عملياً:
// لو المستخدم عدّل status من جهاز وnote من جهاز ثاني بنفس الوقت تقريباً،
// الدمج يحافظ على أحدث قيمة بكل حقل على حدة، بدل ما يخسر أحد التعديلين
// بالكامل لصالح الآخر (وهذا ما كان سيحصل مع "آخر كتابة تفوز على السجل
// كله"، وهو الخطأ الشائع بالتطبيقات التي "تحل التعارض" بسذاجة).
//
// ليش مو CRDT كامل (Yjs / Automerge)؟
// لأن بيانات اللوحة هون عبارة عن سجلات منظَّمة قصيرة (status, note قصيرة،
// فلاتر) وليست نصاً تشاركياً حياً يُكتب حرفاً-حرفاً من عدة مستخدمين بنفس
// اللحظة. LWW بمستوى الحقل يعطي نفس ضمان "لا فقدان صامت للتعديل" بدون
// إضافة مكتبة CRDT كاملة وتعقيدها. البنية هون (سجل + _updatedAt + سجل
// تعارضات منفصل) مصمَّمة بحيث الانتقال لـ Yjs مستقبلاً — لو صار في تحرير
// نصي جماعي حقيقي، مثلاً ملاحظات تقرير طويلة يحررها أكثر من محلل بنفس
// اللحظة — ممكن بدون إعادة كتابة الطبقة كاملة.

export interface Timestamped {
  _updatedAt: number;
}

export interface MergeResult<T> {
  merged: T;
  overridden: Array<{ field: keyof T; from: unknown; to: unknown }>;
}

/**
 * يدمج قيمة محلية غير مُزامَنة بعد مع قيمة وصلت حديثاً من السيرفر،
 * حقل-حقل، ويرجع القيمة النهائية + قائمة الحقول التي "تجاوزت" قيمة
 * السيرفر (حتى تُحفظ بجدول conflictLog للمراجعة اللاحقة — لا نريد فقداناً
 * صامتاً حتى لو كان الحل تلقائياً).
 *
 * القاعدة: بما إنه ما عنا طابع زمني منفصل لكل حقل (لتبسيط الموديل)، نعتبر
 * السجل المحلي "فائزاً" فقط إذا كان _updatedAt المحلي أحدث من _updatedAt
 * القادم من السيرفر لنفس السجل. غير هيك، نسخة السيرفر هي المصدر الموثوق
 * لكل الحقول — لأنها تعني أن جهازاً/جلسة أخرى عدّلت بعد آخر تعديل معروف هنا.
 */
export function mergeByFieldLWW<T extends Record<string, unknown> & Timestamped>(
  local: T,
  server: T,
  fieldsToTrack: (keyof T)[]
): MergeResult<T> {
  const merged: T = { ...server };
  const overridden: Array<{ field: keyof T; from: unknown; to: unknown }> = [];

  if (local._updatedAt > server._updatedAt) {
    for (const field of fieldsToTrack) {
      if (local[field] !== server[field]) {
        overridden.push({ field, from: server[field], to: local[field] });
        merged[field] = local[field];
      }
    }
    merged._updatedAt = local._updatedAt;
  }

  return { merged, overridden };
}
