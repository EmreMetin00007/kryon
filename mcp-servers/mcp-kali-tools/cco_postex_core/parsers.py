"""Deterministik linpeas/winPEAS cikti parser'lari (pure functions)."""

from __future__ import annotations

import re

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
WS_RE = re.compile(r"[ \t]+")
PERMS_RE = re.compile(r"^-[rwxst-]{9}")
HELP_LINE_RE = re.compile(r"^\s*-[A-Za-z]\s+\S")
DECORATION_RE = re.compile(r"^[═╚╔]|^https?://")
ENV_PWD_RE = re.compile(r"(?i)^(OLD)?PWD\s*[:=]\s*/")

SECRET_VALUE_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|apikey|api[_-]?key|token|hash)\s*[:=]\s*\S+"
)
AUTOLOGON_RE = re.compile(r"(?i)(autologon\s*:\s*)\S+")

MAX_EVIDENCE = 220
MAX_FINDINGS = 200


def _clean(line: str) -> str:
    line = ANSI_RE.sub("", line or "")
    line = WS_RE.sub(" ", line).strip()
    return line


def _mask(text: str) -> str:
    masked = SECRET_VALUE_RE.sub(lambda m: m.group(0).split(":")[0].split("=")[0] + ":<masked>", text)
    return AUTOLOGON_RE.sub(r"\1<masked>", masked)


def _finding(fclass: str, severity: str, title: str, evidence: str = "",
             sensitive: bool = False, remediation: str = "") -> dict:
    evidence = _clean(evidence)
    if sensitive:
        evidence = _mask(evidence)
    return {
        "class": fclass,
        "severity": severity,
        "title": title,
        "evidence": evidence[:MAX_EVIDENCE],
        "sensitive": sensitive,
        "remediation": remediation,
    }


# ── LINPEAS ──────────────────────────────────────────────────────────

_LINPEAS_RULES = [
    # (id-snippet regex, class, severity, title, sensitive, remediation)
    (re.compile(r"-rws", re.I), "suid_binary", "medium",
     "SUID binary mevcut", False, "GTFOBins karsiligi ve gereksiz SUID temizligi"),
    (re.compile(r"cap_|capabilities", re.I), "linux_capability", "medium",
     "Dosya capability atamasi", False, "cap_setuid/cap_dac_override icerenler oncelikli"),
    (re.compile(r"NOPASSWD", re.I), "sudo_nopasswd", "high",
     "Sudo NOPASSWD yetkisi", False, "Yetkiyi kaldir veya komutu daralt"),
    (re.compile(r"\(ALL(:?,\s*nopasswd)?\s*:\s*ALL\)", re.I), "sudo_all", "critical",
     "Sudo ALL yetkisi", False, "Acil daraltma gerekli"),
    (re.compile(r"/etc/cron|/var/spool/cron|crontab", re.I), "cron_job", "medium",
     "Cron isi / zamanlanmis gorev", False, "Yazilabilir cron dosya/script sahipligi denetimi"),
    (re.compile(r"writable.*path|path.*writable", re.I), "writable_path", "high",
     "Yazilabilir PATH dizini", False, "Dizin izinlerini sikilastir"),
    (re.compile(r"no_root_squash", re.I), "nfs_misconfig", "high",
     "NFS no_root_squash", False, "root_squash etkinlestir"),
    (re.compile(r"docker\.sock|/var/run/docker", re.I), "docker_socket", "high",
     "Docker soketine erisim", False, "docker grubu ve soket izni denetimi"),
    (re.compile(r"\.ssh/id_|private key|BEGIN .*PRIVATE", re.I), "ssh_key_exposure", "high",
     "SSH ozel anahtar kalintisi", True, "Anahtari kaldir, vault'a tasi, rotate et"),
    (re.compile(r"password|passwd|pwd\s*[:=]", re.I), "credential_hint", "high",
     "Dosyada parola kalintisi", True, "Secret'i kaldir, vault + rotasyon"),
    (re.compile(r"mysql_history|bash_history|ps_history|\.history", re.I), "history_secret", "medium",
     "Kabuk gecmis dosyasi", True, "Gecmisi temizle, HISTCONTROL kullan"),
    (re.compile(r"kernel\s+\d+\.|linux version", re.I), "kernel_info", "info",
     "Kernel surum bilgisi", False, "Unpatched CVE eslestirmesi yap"),
    (re.compile(r"sudo version|sudo ver", re.I), "sudo_version", "info",
     "Sudo surum bilgisi", False, "Bilinen sudo CVE eslestirmesi yap"),
    (re.compile(r"lxc|lxd\s", re.I), "lxd_group", "high",
     "LXD/LXC uyeligi", False, "lxd grubu uyeligini gozden gecir"),
]


def parse_linpeas(text: str) -> dict:
    """Linpeas stdout'unu yapisal bulgulara cevirir."""
    findings: list[dict] = []
    seen: set[str] = set()
    lines = (text or "").splitlines()
    hot = 0
    for raw in lines:
        line = _clean(raw)
        if not line or len(line) < 4:
            continue
        if HELP_LINE_RE.match(line) and not PERMS_RE.match(line):
            continue  # kullanim yardimi satiri, bulgu degil
        if DECORATION_RE.match(line):
            continue  # banner/dokuman referans satiri
        hot_marker = "95m" in (raw or "") or "[+]" in line or "[!]" in line
        if hot_marker:
            hot += 1
        for rx, fclass, severity, title, sensitive, remediation in _LINPEAS_RULES:
            if not rx.search(line):
                continue
            if fclass == "credential_hint" and ENV_PWD_RE.match(line):
                continue  # PWD=/OLDPWD= ortam degiskeni, parola degil
            key = f"{fclass}:{line[:80]}"
            if key in seen:
                break
            seen.add(key)
            if len(findings) >= MAX_FINDINGS:
                break
            findings.append(_finding(fclass, severity, title, line, sensitive, remediation))
            break
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 5))
    return {
        "platform": "linux",
        "parser": "cco_postex_core.parse_linpeas",
        "lines_scanned": len(lines),
        "hot_markers": hot,
        "finding_count": len(findings),
        "findings": findings,
    }


# ── WINPEAS ──────────────────────────────────────────────────────────

_WINPEAS_PRIVS = {
    "SeImpersonatePrivilege": ("token_privilege", "critical", "SeImpersonate token yetkisi (Potato ailesi)"),
    "SeAssignPrimaryTokenPrivilege": ("token_privilege", "critical", "SeAssignPrimaryToken yetkisi"),
    "SeTcbPrivilege": ("token_privilege", "critical", "SeTcbPrivilege (SYSTEM esdegeri)"),
    "SeBackupPrivilege": ("backup_privilege", "high", "SeBackupPrivilege (dosya okuma)"),
    "SeRestorePrivilege": ("restore_privilege", "high", "SeRestorePrivilege (dosya yazma)"),
    "SeDebugPrivilege": ("debug_privilege", "high", "SeDebugPrivilege (LSASS okuma)"),
    "SeTakeOwnershipPrivilege": ("ownership_privilege", "high", "SeTakeOwnershipPrivilege"),
}

_WINPEAS_RULES = [
    (re.compile(r"AlwaysInstallElevated\s+.*1|alwaysinstall\.elevated", re.I),
     "always_install_elevated", "critical", "AlwaysInstallElevated etkin", False,
     "HKLM/HKCU AlwaysInstallElevated anahtarlarini kapat"),
    (re.compile(r"unquoted|no quotes and space", re.I),
     "unquoted_service_path", "high", "Tirnaklanmamis servis yolu", False,
     "Servis ImagePath degerini tirnakla"),
    (re.compile(r"modifiabl[ea]\s+service|writable service|service.*writable", re.I),
     "modifiable_service", "high", "Yazilabilir servis konfigurasyonu", False,
     "Servis DACL izinlerini sikilastir"),
    (re.compile(r"autorun|scheduled task", re.I),
     "autorun_task", "medium", "Autorun / zamanlanmis gorev", False,
     "Yazilabilir autorun hedeflerini denetle"),
    (re.compile(r"autologon|AutoAdminLogon|DefaultPassword", re.I),
     "autologon_credential", "high", "Autologon kimlik kalintisi", True,
     "Autologon parolasini kaldir, LAPS kullan"),
    (re.compile(r"stored credential|windows credential|credential manager", re.I),
     "stored_credential", "high", "Kayitli Windows kimlik bilgisi", True,
     "Vault'a tasi, gereksiz kayitlari sil"),
    (re.compile(r"dpapi|master ?key", re.I),
     "dpapi_masterkey", "medium", "DPAPI master key kalintisi", True,
     "Kullanici baglami disinda erisimi engelle"),
    (re.compile(r"powershell.*history|consolehost_history", re.I),
     "powershell_history", "medium", "PowerShell gecmis dosyasi", True,
     "Gecmisi temizle, secret'i kaldir"),
    (re.compile(r"interesting file|password.*file|config.*password", re.I),
     "interesting_file", "medium", "Ilginc dosya / parola adayi", True,
     "Dosyayi incele, secret varsa vault'a tasi"),
    (re.compile(r"mimikatz|lsass|sekurlsa", re.I),
     "lsass_hint", "info", "LSASS erisim ipucu", False, "SeDebug + PPL durumunu dogrula"),
]


def parse_winpeas(text: str) -> dict:
    """WinPEAS stdout'unu yapisal bulgulara cevirir."""
    findings: list[dict] = []
    seen: set[str] = set()
    lines = (text or "").splitlines()
    hot = 0
    for raw in lines:
        line = _clean(raw)
        if not line or len(line) < 4:
            continue
        if "[!]" in line or "[X]" in line or "[+]" in line:
            hot += 1
        matched = False
        for priv, (fclass, severity, title) in _WINPEAS_PRIVS.items():
            if priv.lower() in line.lower() and "disabled" not in line.lower():
                key = f"{fclass}:{priv}"
                if key not in seen:
                    seen.add(key)
                    findings.append(_finding(
                        fclass, severity, title, line, False,
                        "Token yetkisini kaldir veya sureci dusuk-butunlukte calistir"))
                matched = True
                break
        if matched:
            continue
        for rx, fclass, severity, title, sensitive, remediation in _WINPEAS_RULES:
            if not rx.search(line):
                continue
            key = f"{fclass}:{line[:80]}"
            if key in seen:
                break
            seen.add(key)
            if len(findings) >= MAX_FINDINGS:
                break
            findings.append(_finding(fclass, severity, title, line, sensitive, remediation))
            break
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 5))
    return {
        "platform": "windows",
        "parser": "cco_postex_core.parse_winpeas",
        "lines_scanned": len(lines),
        "hot_markers": hot,
        "finding_count": len(findings),
        "findings": findings,
    }
