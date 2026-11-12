// frontend/src/offline/useFindingLifecycleLocalFirst.ts
//
// Hook جاهز يستبدل useState/useEffect العادي لأي صفحة تعرض حالة/ملاحظات
// findings (مثال: FindingsPage). أول رسم بالشاشة يجي فوراً من IndexedDB
// (حتى بدون إنترنت)، وبالخلفية يُطلب السيرفر ويُدمج الفرق. لا يغيّر أي
// شيء بمنطق أو تصميم الصفحة نفسها — فقط طبقة القراءة.

import { useCallback, useEffect, useState } from "react";
import { localDb, type FindingLifecycleRecord } from "./db";
import { syncFindingLifecycleFromServer } from "./sync";

export interface UseFindingLifecycleResult {
  items: FindingLifecycleRecord[];
  loading: boolean; // true فقط أول مرة قبل أول قراءة محلية (نادراً ما يظهر — سريع جداً)
  syncing: boolean; // true أثناء انتظار تأكيد السيرفر بالخلفية (الواجهة لا تُحجب بسببه)
  offlineStale: boolean; // true = المعروض حالياً من كاش محلي لم يتأكد بعد من السيرفر (لا يوجد اتصال)
}

export function useFindingLifecycleLocalFirst(scanId: string, tenantId: string): UseFindingLifecycleResult {
  const [items, setItems] = useState<FindingLifecycleRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [offlineStale, setOfflineStale] = useState(false);

  const readLocal = useCallback(async () => {
    const rows = await localDb.findingLifecycle
      .where("scanId")
      .equals(scanId)
      .filter((r) => r._tenantId === tenantId && r._deleted === 0)
      .toArray();
    setItems(rows);
  }, [scanId, tenantId]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await readLocal(); // رسم فوري (Zero-Latency) — قد يكون فارغاً أول زيارة على هذا الجهاز
      if (cancelled) return;
      setLoading(false);
      setSyncing(true);
      try {
        await syncFindingLifecycleFromServer(scanId, tenantId);
        if (!cancelled) {
          await readLocal();
          setOfflineStale(false);
        }
      } catch {
        // فشل الشبكة هون لا يفرغ الشاشة أبداً — يبقى المعروض آخر نسخة محلية معروفة
        if (!cancelled) setOfflineStale(true);
      } finally {
        if (!cancelled) setSyncing(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId, tenantId, readLocal]);

  return { items, loading, syncing, offlineStale };
}
