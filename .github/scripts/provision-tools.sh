#!/usr/bin/env bash
#
# Provision the two git-ignored external toolchains that `make` auto-detects
# under tools/ (see tools/README.md and docs/specs/common/toolchain.md §1):
#
#   1. Oracle Java Card Development Kit Tools v26.0 - converter.sh/verifyexp.sh
#      plus api_classic-3.0.5.jar and tools.jar.
#   2. GlobalPlatform Card API org.globalplatform 1.6 - gpapi-globalplatform.jar
#      for javac and the converter export files (exports23/.../globalplatform.exp).
#
# Everything comes from mvn.javacard.pro, which repackages the publicly
# available Oracle SDK (a repack of martinpaljak/oracle_javacard_sdks) and the
# GlobalPlatform API export files.  Both are pinned and SHA-256 verified so the
# CI does not depend on an Oracle/GlobalPlatform account.
#
# The names and the `1.6/exports23` layout must match the wildcards in
# config/externals.mk and the -exportpath used by the Makefile.

set -euo pipefail

JC_KIT_DIR="tools/java_card_devkit_tools-bin-v26.0"
GPAPI_DIR="tools/GlobalPlatform_Card_API-org.globalplatform-v1.6/1.6"

JC_SDK_URL="https://mvn.javacard.pro/vendors/vnd/oracle/javacard-sdk/26.0/javacard-sdk-26.0.zip"
JC_SDK_SHA256="91782b3262c5c6769867c01b6a9b8eac1370ab997f333a73b820b1c9f568da53"

GPAPI_URL="https://mvn.javacard.pro/vendors/vnd/globalplatform/api/1.6/api-1.6.jar"
GPAPI_SHA256="6fc2d1866633b9ca64522b0b757095e8e2151910592381c102f76c9492b12ee5"

GPAPI_EXP_URL="https://mvn.javacard.pro/vendors/vnd/globalplatform/api/1.6/api-1.6-export-2.3.jar"
GPAPI_EXP_SHA256="6d7d26859fe205fac72f5a1108ba50baa09509a1bab0cd045735f67ccd6c6d6b"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # <url> <sha256> <dest>
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

echo ">>> Java Card Development Kit Tools v26.0 -> $JC_KIT_DIR"
fetch "$JC_SDK_URL" "$JC_SDK_SHA256" "$tmp/jc-sdk.zip"
mkdir -p "$JC_KIT_DIR"
unzip -q "$tmp/jc-sdk.zip" -d "$JC_KIT_DIR"

echo ">>> GlobalPlatform Card API 1.6 -> $GPAPI_DIR"
mkdir -p "$GPAPI_DIR"
fetch "$GPAPI_URL" "$GPAPI_SHA256" "$GPAPI_DIR/gpapi-globalplatform.jar"
fetch "$GPAPI_EXP_URL" "$GPAPI_EXP_SHA256" "$tmp/gpapi-exp23.jar"
exp_dir="$GPAPI_DIR/exports23/org/globalplatform/javacard"
mkdir -p "$exp_dir"
unzip -p "$tmp/gpapi-exp23.jar" org/globalplatform/javacard/globalplatform.exp \
  > "$exp_dir/globalplatform.exp"

echo ">>> tools ready:"
ls -l "$JC_KIT_DIR/bin/converter.sh" \
      "$JC_KIT_DIR/lib/api_classic-3.0.5.jar" \
      "$GPAPI_DIR/gpapi-globalplatform.jar" \
      "$exp_dir/globalplatform.exp"
