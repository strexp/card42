#!/usr/bin/env bash
#
# Stage the build output into the flat dist trees used by the CI/release
# artifact uploads:
#
#   dist/card          the three debug CAPs and their export files (written to a
#                      card with on-card debugging enabled)
#   dist/card-release  the same three CAPs built without the converter's
#                      `-debug` flag (production, ~20-25% smaller)
#   dist/host          the five host jars: the card42-common.jar shared library,
#                      the card42-emv.jar / card42-emrtd.jar libraries and the
#                      runnable card42-emv-cli.jar / card42-emrtd-cli.jar CLIs
#
# Run after `make release` (which builds both the debug and the release CAPs).

set -euo pipefail

D=build/deliverables
R=build/release
rm -rf dist
mkdir -p dist/card dist/card-release dist/host

# Debug CAPs (keep the unsuffixed names for backwards compatibility).
cp "$D/card42common/card42/common/javacard/common.cap" dist/card/card42common.cap
cp "$D/card42common/card42/common/javacard/common.exp" dist/card/card42common.exp
cp "$D/card42/emv/javacard/emv.cap"                     dist/card/card42-emv.cap
cp "$D/card42/emv/javacard/emv.exp"                     dist/card/card42-emv.exp
cp "$D/card42/emrtd/javacard/emrtd.cap"                 dist/card/card42-emrtd.cap
cp "$D/card42/emrtd/javacard/emrtd.exp"                 dist/card/card42-emrtd.exp

# Release CAPs (no -debug), suffixed so both can be attached to one release.
if [ ! -f "$R/card42/emrtd/javacard/emrtd.cap" ]; then
  echo "stage-deliverables: no release CAPs; run 'make release' first" >&2
  exit 1
fi
cp "$R/card42common/card42/common/javacard/common.cap" dist/card-release/card42common-release.cap
cp "$R/card42common/card42/common/javacard/common.exp" dist/card-release/card42common-release.exp
cp "$R/card42/emv/javacard/emv.cap"                     dist/card-release/card42-emv-release.cap
cp "$R/card42/emv/javacard/emv.exp"                     dist/card-release/card42-emv-release.exp
cp "$R/card42/emrtd/javacard/emrtd.cap"                 dist/card-release/card42-emrtd-release.cap
cp "$R/card42/emrtd/javacard/emrtd.exp"                 dist/card-release/card42-emrtd-release.exp

cp "$D/card42-common.jar" "$D/card42-emv.jar" "$D/card42-emrtd.jar" \
   "$D/card42-emv-cli.jar" "$D/card42-emrtd-cli.jar" dist/host/

echo ">>> dist/card (debug)"
ls -l dist/card
echo ">>> dist/card-release (no debug)"
ls -l dist/card-release
echo ">>> dist/host"
ls -l dist/host
