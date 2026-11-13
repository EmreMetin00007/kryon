FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY scripts/lab/vuln_lab.py /app/vuln_lab.py

EXPOSE 8899

HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8899/healthz', timeout=2).read()"

CMD ["python3", "/app/vuln_lab.py", "8899"]
