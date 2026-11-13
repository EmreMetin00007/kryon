# VulnLab

Loopback-only, intentionally vulnerable test target for Hunter and Validator end-to-end checks.

## Local Embedded Run

`python3 scripts/lab-validate.py`

This starts the lab in-process on a random loopback port and runs the full e2e validation.

## Docker Run

```bash
docker compose -f scripts/lab/docker-compose.yml up --build -d vuln-lab
python3 scripts/lab-validate.py --base-url http://127.0.0.1:8899 --skip-rag
docker compose -f scripts/lab/docker-compose.yml down
```

## Covered Vulnerabilities

- Reflected XSS: `/search?q=`
- Error-based SQLi: `/item?id=`
- IDOR/BOLA: `/api/orders/<id>`
- Auth bypass/BFLA: `/admin/export`
- Business logic: `/checkout?price=&quantity=`
- Open redirect: `/go?next=`
