/**
 * شعار "مرصاد": منارة/رادار مراقبة مبسّطة — قاعدة (المنصّة) + عمود مراقبة
 * + قوسا مسح دائريان يمثّلان الفحص المستمر لسطح الهجوم، وبؤرة مركزية
 * (الاكتشاف). مصمَّم كخط واحد نظيف يعمل بحجم صغير (18px بالـ Sidebar) وحجم
 * أكبر (شاشة الدخول) بلا فقدان وضوح.
 */
export function MirsadMark({ size = 20 }: { size?: number }) {
  const id = "mirsad-mark-gradient";
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="2" y1="21" x2="22" y2="3" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#f7c876" />
          <stop offset="0.5" stopColor="#ec8a3d" />
          <stop offset="1" stopColor="#6a5cf7" />
        </linearGradient>
      </defs>
      {/* قوسا المسح (رادار/رصد مستمر) */}
      <path d="M6.5 9.5a8 8 0 0 1 11-7.2" stroke={`url(#${id})`} strokeWidth="1.6" strokeLinecap="round" opacity="0.85" />
      <path d="M4 12.5A11 11 0 0 1 18.5 1.3" stroke={`url(#${id})`} strokeWidth="1.4" strokeLinecap="round" opacity="0.45" />
      {/* عمود المنارة */}
      <path d="M12 8.5 16 21H8l4-12.5Z" fill={`url(#${id})`} />
      {/* البؤرة/عين الرصد */}
      <circle cx="12" cy="8.5" r="2.4" fill={`url(#${id})`} />
      <circle cx="12" cy="8.5" r="1" fill="#0a0d11" />
    </svg>
  );
}
