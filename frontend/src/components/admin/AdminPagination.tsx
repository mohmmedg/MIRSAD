import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useLanguage } from "../../i18n/LanguageContext";
import { adminSectionText as text } from "./sectionText";
import { Button } from "@/components/ui/button";

export const ADMIN_PAGE_SIZE = 10;

/** Client-side pagination; the page snaps back to 1 whenever `resetKey` changes (e.g. the search text). */
export function usePagination<T>(items: T[], resetKey: string = "", size = ADMIN_PAGE_SIZE) {
  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [resetKey]);
  const pages = Math.max(1, Math.ceil(items.length / size));
  const current = Math.min(page, pages);
  return {
    pageItems: items.slice((current - 1) * size, current * size),
    page: current, pages, total: items.length, size, setPage,
  };
}

export function PaginationBar({ page, pages, total, size, setPage }: Pick<ReturnType<typeof usePagination>, "page" | "pages" | "total" | "size" | "setPage">) {
  const { language } = useLanguage();
  if (total <= size) return null;
  const from = (page - 1) * size + 1;
  const to = Math.min(page * size, total);
  return (
    <nav className="flex items-center justify-between gap-3 pt-1" aria-label={text(language, "ترقيم الصفحات", "Pagination")}>
      <p className="text-xs text-muted-foreground">
        {text(language, `${from}–${to} من ${total}`, `${from}–${to} of ${total}`)}
      </p>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label={text(language, "الصفحة السابقة", "Previous page")}>
          <ChevronRight className="ltr:rotate-180" aria-hidden="true" />
        </Button>
        <span className="min-w-14 text-center text-xs tabular-nums text-muted-foreground">{page} / {pages}</span>
        <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label={text(language, "الصفحة التالية", "Next page")}>
          <ChevronLeft className="ltr:rotate-180" aria-hidden="true" />
        </Button>
      </div>
    </nav>
  );
}
