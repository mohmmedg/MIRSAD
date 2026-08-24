# AI-Powered Security Scanner — Backend Dockerfile
#
# يشمل nmap مثبّت بالـ image (مطلوب لمحرك network_scan)، بالإضافة لمكتبات
# النظام اللازمة لبناء بعض حزم بايثون. صورة الإنتاج نهائية (single-stage
# كافٍ هون؛ المشروع صغير بما يكفي إن over-engineering بـ multi-stage build
# ما يستاهل التعقيد الإضافي حالياً).

FROM python:3.12-slim

# nmap: أداة فحص الشبكات الأساسية اللي يعتمد عليها network_scan/scanner.py
# ca-certificates: مطلوبة لطلبات HTTPS الصادرة (web_scan، Gemini API)
# libcap2-bin: يوفر setcap — نحتاجه أدناه عشان نعطي nmap صلاحية raw sockets
# لمستخدم غير-root بدل ما نشغّل الحاوية كاملة كـ root (OS detection عبر -O
# يحتاج CAP_NET_RAW/CAP_NET_ADMIN وإلا يفشل بصمت لمستخدم عادي)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        libcap2-bin \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# نسخ requirements أولاً لوحدها عشان طبقة Docker الخاصة بـ pip install
# تُخزَّن مؤقتاً (cache) وما تُعاد إلا لو requirements.txt تغيّر فعلياً —
# أسرع بكثير لإعادة البناء المتكررة أثناء التطوير
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# مستخدم غير-root لتشغيل التطبيق (نمنع صلاحيات root غير الضرورية بالحاوية)
RUN useradd --create-home --shell /bin/bash scanner \
    && mkdir -p /app/data \
    && chown -R scanner:scanner /app
USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
