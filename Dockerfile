# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: production image ─────────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user
RUN groupadd --gid 1001 cardioai \
 && useradd  --uid 1001 --gid cardioai --no-create-home --shell /bin/false cardioai

WORKDIR /app

COPY --from=builder /install /usr/local

COPY iomt_cardioai_production.py .
COPY IoMT_implementation.py      .
COPY IoMT_clinical_workflow.py   .
COPY IoMT_gcp_compduide.py       .

RUN chown -R cardioai:cardioai /app

USER cardioai

ENV LOG_FORMAT=json \
    LOG_LEVEL=INFO  \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8080/health',timeout=8); sys.exit(0)"

EXPOSE 8765 8080

CMD ["python", "-u", "iomt_cardioai_production.py"]
