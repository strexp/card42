#!/usr/bin/env bash
#
# Run one or more card42.test.<Suite> integration suites in their own JVM.
# The EMV and eMRTD matrices only differ in class path, working directory and
# transport, so the loop lives here once (docs/specs/common/toolchain.md §6).
#
# Every suite runs in its own JVM: Checks is process-wide and a failing suite
# exits non-zero, so the first failure stops the run.
#
# Environment:
#   SUITE_JAVA     java binary                    (required)
#   SUITE_CLASSES  compiled host+test classes dir  (required, absolute)
#   COM_SERVICE    COMService module dir (socket provider), absolute (required)
#   SUITE_HOST     transport: socket:<host>:<port> or pcsc[:<idx>]  (required)
#   SUITE_CWD      directory to run in (default: current); eMRTD PA reads the
#                  CSCA fixture relative to the repo root, so it uses the root
#
# Usage:
#   run-suite.sh <Suite> [<Suite> ...]      # simple class names (card42.test.*)
set -euo pipefail

: "${SUITE_JAVA:?SUITE_JAVA is required}"
: "${SUITE_CLASSES:?SUITE_CLASSES is required}"
: "${COM_SERVICE:?COM_SERVICE is required}"
: "${SUITE_HOST:?SUITE_HOST is required}"

cd "${SUITE_CWD:-.}"

for s in "$@"; do
    [ -z "$s" ] && continue
    echo ">>> $s"
    "$SUITE_JAVA" -p "$COM_SERVICE" --add-modules ALL-MODULE-PATH \
        -cp "$SUITE_CLASSES" "card42.test.$s" "-host=$SUITE_HOST"
done
