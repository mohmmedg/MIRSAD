import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { TableHead } from "@/components/ui/table";

type Value = string | number | null | undefined;
type Dir = "asc" | "desc";

/** Click-to-sort for admin tables. Clicking a column cycles asc → desc → original order. */
export function useSort<T>(items: T[], getters: Record<string, (item: T) => Value>) {
  const [sort, setSort] = useState<{ key: string; dir: Dir } | null>(null);
  const sorted = useMemo(() => {
    const get = sort && getters[sort.key];
    if (!sort || !get) return items;
    const sign = sort.dir === "asc" ? 1 : -1;
    return [...items].sort((a, b) => {
      const x = get(a), y = get(b);
      if (x == null && y == null) return 0;
      if (x == null) return 1; // empty values always last
      if (y == null) return -1;
      return sign * (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" }));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- getters are inline literals; items + sort are the real inputs
  }, [items, sort]);
  const toggle = (key: string) =>
    setSort((cur) => (cur?.key !== key ? { key, dir: "asc" } : cur.dir === "asc" ? { key, dir: "desc" } : null));
  return { sorted, sort, toggle };
}

export function SortHead({ id, sort, onSort, children, className }: {
  id: string; sort: { key: string; dir: Dir } | null; onSort: (key: string) => void; children: React.ReactNode; className?: string;
}) {
  const dir = sort?.key === id ? sort.dir : null;
  const Icon = dir === "asc" ? ArrowUp : dir === "desc" ? ArrowDown : ChevronsUpDown;
  return (
    <TableHead className={className} aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : "none"}>
      <button type="button" onClick={() => onSort(id)} className="-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        {children}
        <Icon className={dir ? "size-3.5" : "size-3.5 opacity-40"} aria-hidden="true" />
      </button>
    </TableHead>
  );
}
