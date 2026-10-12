#!/usr/bin/env bash
#
# Run a personalization exporter and pipe its per-instance DGI blobs into
# gp.sh's `perso` command (GlobalPlatformPro `--personalize <AID>
# --store-data <hex>`).  Both the EMV (`card42.host.emv.cli.Main perso export`)
# and eMRTD (`card42.host.emrtd.perso.EmrtdPersoExporter`) exporters print one
# "<aid-hex> <data-hex>" line per instance on stdout, so the same driver serves
# both (docs/specs/common/toolchain.md §4/§5).
#
# Environment:
#   GP_JAVA       java binary                     (required)
#   GP_JAR        globalplatformpro jar           (required)
#   GP_TRANSPORT  extra GPPro flags (transport / SCP keys); word-split, may be empty
#   GP_SH         path to gp.sh (defaults to the sibling script)
#
# Usage:
#   perso.sh <exporter-command...>
#
# Example:
#   GP_JAVA=java GP_JAR=gp.jar GP_TRANSPORT="--ng ..." \
#     perso.sh "$JAVA" -cp build/host/classes \
#       card42.host.emv.cli.Main perso export -script=... -keys=...
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
: "${GP_SH:=$here/gp.sh}"

if [ "$#" -eq 0 ]; then
    echo "usage: perso.sh <exporter-command...>" >&2
    exit 2
fi

lines=$("$@") || exit 1
printf '%s\n' "$lines" |
    GP_JAVA="${GP_JAVA:?GP_JAVA is required}" \
    GP_JAR="${GP_JAR:?GP_JAR is required}" \
    GP_TRANSPORT="${GP_TRANSPORT:-}" \
    "$GP_SH" perso
