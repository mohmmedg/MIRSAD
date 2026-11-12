# Dockerfile للواجهة الأمامية — وضع تطوير (Vite dev server).
#
# ملاحظة متعمّدة: ما استخدمنا build إنتاجي متعدد المراحل (multi-stage) هون
# لأن VITE_API_BASE_URL تُقرأ وقت الـ build بـ Vite (import.meta.env)،
# فأي build إنتاجي جاهز داخل الصورة لازم يعرف قيمهم مسبقاً وقت docker build —
# وهذا غير عملي لمشروع تخرج/demo بيئته تتغيّر (localhost مقابل بيئة أخرى).
# وضع dev server هون يقرأ .env وقت التشغيل عبر bind mount، وهو الأنسب هلق.
# لنشر إنتاجي حقيقي لاحقاً: ابنِ `npm run build` بصورة منفصلة واخدم `dist/`
# عبر nginx مع الـ env vars مضبوطة وقت الـ CI build.
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN timeout 3600 npm ci && test -d node_modules && test -f node_modules/.package-lock.json

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
