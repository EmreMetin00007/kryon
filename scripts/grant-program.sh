#!/usr/bin/env bash
# Operator grant helper: issues the standard grant set for a program.
# Usage: ./scripts/grant-program.sh <circle|coupang|eudi|anduril|rapyd|fiserv|expedia> [ttl_seconds]
# Must be run by the OPERATOR (bootstrap grants cannot come from agents).
set -u
PROG="${1:?usage: grant-program.sh <circle|coupang|eudi|anduril|rapyd|fiserv|expedia> [ttl_seconds]}"
TTL="${2:-28800}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
export CCO_HOME="${CCO_HOME:-$REPO_DIR/.cco}"
HANDLE="${HACKERONE_HANDLE:-operator}"
case "$PROG" in
  circle)
    TARGETS=('*.arc.io' 'arc.io' '*.testnet.arc.network')
    ;;
  coupang)
    TARGETS=('*.coupang.com' '*.coupangcorp.com' 'tw.coupangls.com')
    ;;
  eudi)
    TARGETS=('wallet-backend-sandbox.apps.sandbox.nwb.youniqx.com' 'playground.eudi-wallet.org')
    ;;
  anduril)
    TARGETS=('*.anduril.com' 'anduril.com' '*.andurildev.com' 'andurildev.com' '*.anduril.dev' 'anduril.dev' '*.andurildev.au' 'andurildev.au' '*.anduril.au' 'anduril.au' '*.anduril.com.au' 'anduril.com.au')
    ;;
  rapyd)
    TARGETS=('api.rapyd.net' 'dashboard.rapyd.net' 'verify.rapyd.net' 'checkout.rapyd.net' '*.rapyd.net' '*.korta.is' 'jointhemoment.net' '*.rapyd.com' '*.rapyd.org' '*.kortathjonustan.is')
    ;;
  fiserv)
    # 57 scope root (OOS *.clover/firstdata/fiserv.com haric), bare + wildcard.
    TARGETS=('azulzinhapay.com.br' '*.azulzinhapay.com.br' 'bankofamerica.com' '*.bankofamerica.com' 'bbt.com' '*.bbt.com' 'bentopreprod.com' '*.bentopreprod.com' 'bmoharris.com' '*.bmoharris.com' 'bpm-int.io' '*.bpm-int.io' 'businesstrack.com' '*.businesstrack.com' 'bwwbonus.com' '*.bwwbonus.com' 'bypassmobile.com' '*.bypassmobile.com' 'caaweb.com' '*.caaweb.com' 'cardconnect.com' '*.cardconnect.com' 'cardpointe.com' '*.cardpointe.com' 'ccreward.com' '*.ccreward.com' 'checkfree.com' '*.checkfree.com' 'checkout-lane.com' '*.checkout-lane.com' 'citizensbankonline.com' '*.citizensbankonline.com' 'cloveronline.com' '*.cloveronline.com' 'commercehub.solutions' '*.commercehub.solutions' 'fdecs.com' '*.fdecs.com' 'fimu.me' '*.fimu.me' 'financial-net.com' '*.financial-net.com' 'firstdata.eu' '*.firstdata.eu' 'firsthorizonsignaturerewards.com' '*.firsthorizonsignaturerewards.com' 'fiserv.com.br' '*.fiserv.com.br' 'fiserv.io' '*.fiserv.io' 'fiservapis.com' '*.fiservapis.com' 'fiservapp.com' '*.fiservapp.com' 'fiservapps.com' '*.fiservapps.com' 'flagstar.com' '*.flagstar.com' 'getbento.com' '*.getbento.com' 'gift.solutions' '*.gift.solutions' 'govone.com' '*.govone.com' 'gyft.com' '*.gyft.com' 'hepsiian.com' '*.hepsiian.com' 'olbanking.com' '*.olbanking.com' 'ondotsystems.com' '*.ondotsystems.com' 'onefiserv.com' '*.onefiserv.com' 'onlinebank.com' '*.onlinebank.com' 'payeezy.com' '*.payeezy.com' 'prinpay.com' '*.prinpay.com' 'qacitizensbankonline.com' '*.qacitizensbankonline.com' 'santanderbank.com' '*.santanderbank.com' 'secure-banking.com' '*.secure-banking.com' 'securehostedpayments.com' '*.securehostedpayments.com' 'skytef.com.br' '*.skytef.com.br' 'smsservicesnow.com' '*.smsservicesnow.com' 'softwareexpress.com.br' '*.softwareexpress.com.br' 'streamlendvelocity.net' '*.streamlendvelocity.net' 'svb.com' '*.svb.com' 'test-smsservicesnow.com' '*.test-smsservicesnow.com' 'thepayplace.com' '*.thepayplace.com' 'thepineapplestage.com' '*.thepineapplestage.com' 'trunkclover.com' '*.trunkclover.com' 'usdirectexpress.com' '*.usdirectexpress.com' 'wgiftcard.co' '*.wgiftcard.co' 'wgiftcard.com' '*.wgiftcard.com' 'yacare.com' '*.yacare.com')
    ;;
  fiserv-full)
    # 786 root tek tek yazilamaz; scope.json sinirlamayi yapar, grant sadece onay
    # katmanidir. Kisa TTL + bu programla sinirli reason zorunlu.
    TARGETS=('*')
    ;;
  expedia)
    TARGETS=('*.expedia.biz' 'expedia.biz' '*.expedia.com' 'expedia.com' '*.expediagroup.com' 'expediagroup.com' '*.hotels.com' 'hotels.com' '*.vrbo.com' 'vrbo.com' '*.carrentals.com' 'carrentals.com' '*.hotwire.com' 'hotwire.com' '*.orbitz.com' 'orbitz.com' '*.travelocity.com' 'travelocity.com' '*.expediapartnercentral.com' 'expediapartnercentral.com' '*.expediapartnersolutions.com' 'expediapartnersolutions.com' '*.expediataap.com' 'expediataap.com')
    ;;
  *)
    echo "unknown program: $PROG (circle|coupang|eudi|anduril|rapyd|fiserv|fiserv-full|expedia)" >&2
    exit 1
    ;;
esac
for target in "${TARGETS[@]}"; do
  "$REPO_DIR/scripts/cco.sh" security approve \
    --tool-pattern '*' --target-pattern "$target" \
    --ttl "$TTL" --reason "$PROG-$HANDLE"
done
"$REPO_DIR/scripts/cco.sh" security approvals
