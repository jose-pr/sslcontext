#!/usr/bin/env bash
# Insert a virtual CAC smart card for tests/integration/test_pkcs11.py.
#
# Needs pcscd with vsmartcard's vpcd reader driver, OpenSC, SoftHSM2,
# gnutls-utils, nss-tools and a built virt_cacard
# (https://github.com/Jakuje/virt_cacard). pcscd must accept the caller
# (on WSL or in a container: run it with --disable-polkit). The card runs
# until this shell session ends; its PIN is 12345678.
set -euo pipefail

VIRT_CACARD=${SSLCONTEXT_TEST_VIRT_CACARD:-$HOME/build/virt_cacard/virt_cacard}
WORK=${XDG_CACHE_HOME:-$HOME/.cache}/sslcontext-vcard
OPENSC=${SSLCONTEXT_TEST_OPENSC:-/usr/lib64/pkcs11/opensc-pkcs11.so}

# vpcd listens only while pcscd runs, and pcscd is usually socket-activated.
pkcs11-tool --module "$OPENSC" -L >/dev/null 2>&1 || true

if [ ! -d "$WORK/tokens" ]; then
    mkdir -p "$WORK"
    (cd "$WORK" && bash "$(dirname "$VIRT_CACARD")/setup-softhsm2.sh" >/dev/null)
fi
if ! pgrep -x virt_cacard >/dev/null; then
    (cd "$WORK" && SOFTHSM2_CONF="$WORK/softhsm2.conf" \
        nohup "$VIRT_CACARD" -s 0 >"$WORK/virt_cacard.log" 2>&1 &)
    sleep 3
fi
pkcs11-tool --module "$OPENSC" -L | grep -q "CAC II" && echo "virtual card inserted"
