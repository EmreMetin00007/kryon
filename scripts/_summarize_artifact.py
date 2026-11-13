#!/usr/bin/env python3
"""Summarize a validator artifact without dumping raw bodies/secrets."""
import json
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    d = json.load(handle)

art = d.get("artifact") or {}
print("validation_id:", d.get("validation_id"))
print("vuln_type:", d.get("vuln_type"))
print("verdict:", d.get("verdict"))
print("confidence:", d.get("confidence"))
print("severity:", d.get("severity"))
print("oracle:", d.get("oracle"))
print("reportable:", d.get("reportable"))
print("artifact.path:", art.get("path"))
print("artifact.persisted:", art.get("persisted"))
print("artifact.sha256:", (art.get("content_sha256") or "")[:16])
print("evidence:", json.dumps(d.get("evidence"), ensure_ascii=False)[:400])
print("reproduction:", json.dumps(d.get("reproduction"), ensure_ascii=False)[:600])
print("guard.transport_ok:", (d.get("guard") or {}).get("transport_ok"))
print("guard.decision_rule:", (d.get("guard") or {}).get("decision_rule"))
for i, ev in enumerate(d.get("request_evidence") or []):
    ex = ev.get("excerpt") or ""
    flags = re.findall(r"(?:flag|FLAG|CTF)\{[^}]{0,80}\}", ex)
    markers = [m for m in ("AUTHORIZED_VAULT_ACCESS", "master_encryption_key", "kms", "KMS") if m in ex]
    print(f"request_evidence[{i}]: role={ev.get('role')} status={ev.get('status')} "
          f"excerpt_len={len(ex)} markers={markers} flags={flags[:2]}")
