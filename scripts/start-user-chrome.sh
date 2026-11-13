#!/usr/bin/env bash
# Kullanıcının masaüstü oturumunda CDP'li Chromium açar (ajan attach için).
#
# Neden böyle: ajan root çalışır, masaüstü (Xfce/:0) kali kullanıcısınındır.
# Root açılan tarayıcı X11'de var olur ama kullanıcının ekranına düşmez ve
# GPU çizimi donar. Bu script tarayıcıyı masaüstü kullanıcısıyla, GPU kapalı
# başlatır. Zaten çalışıyorsa dokunmaz (idempotent).
#
# Kullanım: ./scripts/start-user-chrome.sh [port]
set -euo pipefail

PORT="${1:-9222}"
CDP="http://127.0.0.1:${PORT}"

if curl -s -m 2 "${CDP}/json/version" >/dev/null 2>&1; then
    echo "zaten çalışıyor: ${CDP}"
    exit 0
fi

# Masaüstü oturum kullanıcısı (seat0) — bulunamazsa kali varsay
DESKTOP_USER="$(loginctl list-sessions --no-legend 2>/dev/null \
    | awk '$4=="seat0"{print $3}' | head -n1 || true)"
DESKTOP_USER="${DESKTOP_USER:-kali}"
USER_HOME="$(getent passwd "$DESKTOP_USER" | cut -d: -f6)"
PROFILE="${USER_HOME}/cco-chrome-prof"

echo "masaüstü kullanıcısı: ${DESKTOP_USER} (profil: ${PROFILE})"
PROXY="${CCO_PROXY:-http://127.0.0.1:8080}"
setsid -f su - "$DESKTOP_USER" -c \
    "DISPLAY=:0.0 XAUTHORITY=${USER_HOME}/.Xauthority chromium \
     --no-sandbox --disable-gpu --disable-dev-shm-usage \
     --proxy-server=${PROXY} --ignore-certificate-errors --disable-quic \
     --remote-debugging-port=${PORT} --user-data-dir=${PROFILE} \
     --start-maximized about:blank" \
    </dev/null >>/tmp/cco-chromium-user.log 2>&1
echo "proxy: ${PROXY} (test profili; CCO_PROXY='' ile kapatılır)"

for _ in $(seq 1 15); do
    if curl -s -m 2 "${CDP}/json/version" >/dev/null 2>&1; then
        echo "hazır: ${CDP} — pencerede login olup ajanı çağırın"
        exit 0
    fi
    sleep 1
done
echo "HATA: CDP açılmadı; log: /tmp/cco-chromium-user.log" >&2
exit 1
