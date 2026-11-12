/**
 * شعار "مرصاد" الرسمي: إبرة بوصلة/رادار برونزية تقطع حرف M بتدرّج
 * زمردي غامق، مع نقاط ومسارات دارات (circuit) ترمز للفحص التقني، وحلقة
 * تتبّع محيطة ترمز للمسح المستمر لسطح الهجوم. هذا الملف يعرض الشعار
 * الرسمي (frontend/src/assets/mirsad-icon.svg — نسخة مقصوصة بدون النص
 * لتلائم أحجام الأيقونة الصغيرة). للشعار الكامل مع النص، استورد
 * mirsad-logo-full.svg مباشرة.
 */
import mirsadIcon from "../assets/mirsad-icon.svg";

export function MirsadMark({ size = 32 }: { size?: number }) {
  return (
    <img
      src={mirsadIcon}
      width={size}
      height={size}
      alt="Mirsad"
      aria-hidden="true"
      style={{ display: "block", objectFit: "contain" }}
    />
  );
}
