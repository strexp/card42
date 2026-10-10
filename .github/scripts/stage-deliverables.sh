#!/usr/bin/env bash
#
# Stage the build output into the flat dist/card and dist/host trees used by the
# CI/release artifact uploads:
#
#   dist/card  the three CAPs and their export files (written to a card)
#   dist/host  the five host jars: the card42-common.jar shared library, the
#              card42-emv.jar / card42-emrtd.jar libraries and the runnable
#              card42-emv-cli.jar / card42-emrtd-cli.jar CLIs
#
# Run after `make`.

set -euo pipefail

D=build/deliverables
rm -rf dist
mkdir -p dist/card dist/host

cp "$D/card42common/card42/common/javacard/common.cap" dist/card/card42common.cap
cp "$D/card42common/card42/common/javacard/common.exp" dist/card/card42common.exp
cp "$D/card42/emv/javacard/emv.cap"                     dist/card/card42-emv.cap
cp "$D/card42/emv/javacard/emv.exp"                     dist/card/card42-emv.exp
cp "$D/card42/emrtd/javacard/emrtd.cap"                 dist/card/card42-emrtd.cap
cp "$D/card42/emrtd/javacard/emrtd.exp"                 dist/card/card42-emrtd.exp

cp "$D/card42-common.jar" "$D/card42-emv.jar" "$D/card42-emrtd.jar" \
   "$D/card42-emv-cli.jar" "$D/card42-emrtd-cli.jar" dist/host/

echo ">>> dist/card"
ls -l dist/card
echo ">>> dist/host"
ls -l dist/host
