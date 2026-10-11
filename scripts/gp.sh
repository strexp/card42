#!/usr/bin/env bash
#
# Shared GlobalPlatformPro driver for the card42 install / personalize targets
# (docs/specs/common/toolchain.md §4/§5).  The simulator and real-card flows run
# the same load / create / personalize / delete loops; only the transport flags
# differ (GP_SIM vs GP_ARGS), so the loops live here once instead of being
# repeated in the Makefile.
#
# Environment:
#   GP_JAVA       java binary (required)
#   GP_JAR        globalplatformpro jar (required)
#   GP_TRANSPORT  extra GPPro flags (transport / SCP keys); word-split, may be empty
#   EMV_PACKAGE   package AID hex for --create (required for `create`)
#   EMRTD_PACKAGE eMRTD package AID hex; when set, a class whose AID starts with
#                 it is created under this package (defaults to EMV_PACKAGE)
#   EMRTD_AID     the instance AID that needs `--privs` (optional)
#   EMRTD_PRIVS   the `--privs` value for EMRTD_AID (required when EMRTD_AID is set)
#
# Commands:
#   gp.sh load   <cap> [<cap> ...]
#   gp.sh create <deploy-conf>
#   gp.sh perso                      (reads "aid hex" lines on stdin)
#   gp.sh delete <deploy-conf> [<package> ...]
#
set -euo pipefail

: "${GP_JAVA:?GP_JAVA is required}"
: "${GP_JAR:?GP_JAR is required}"

# GP_TRANSPORT is intentionally expanded unquoted so a transport/keyset with
# several flags becomes several arguments; the values never contain whitespace
# or shell metacharacters.
gp() {
    # shellcheck disable=SC2086
    "$GP_JAVA" -jar "$GP_JAR" ${GP_TRANSPORT:-} "$@"
}

create() {
    local conf=$1
    awk '!/^[[:space:]]*#/ && NF >= 2 { print $1, $2 }' "$conf" |
    while read -r instance class; do
        local pkg=${EMV_PACKAGE:?EMV_PACKAGE is required}
        if [ -n "${EMRTD_PACKAGE:-}" ]; then
            case "$class" in "$EMRTD_PACKAGE"*) pkg=$EMRTD_PACKAGE;; esac
        fi
        local privs=()
        if [ -n "${EMRTD_AID:-}" ] && [ "$instance" = "$EMRTD_AID" ]; then
            privs=(--privs "${EMRTD_PRIVS:?EMRTD_PRIVS is required}")
        fi
        echo ">>> create $instance (applet $class, package $pkg)"
        gp --create "$instance" --applet "$class" --package "$pkg" \
            ${privs[@]+"${privs[@]}"}
    done
}

case "${1:-}" in
load)
    shift
    for cap in "$@"; do
        echo ">>> load $cap"
        gp --load "$cap"
    done
    ;;
create)
    shift
    create "$@"
    ;;
perso)
    # One "aid hex" pair per line, as exported by the perso exporters.
    while read -r aid hex; do
        [ -z "$aid" ] && continue
        echo ">>> personalize $aid ($(( ${#hex} / 2 )) bytes)"
        gp --personalize "$aid" --store-data "$hex"
    done
    ;;
delete)
    shift
    conf=$1
    shift
    awk '!/^[[:space:]]*#/ && NF >= 1 { print $1 }' "$conf" |
    while read -r aid; do
        echo ">>> delete applet $aid"
        # shellcheck disable=SC2086
        gp --delete "$aid" ${GP_FORCE:-} || true
    done
    for pkg in "$@"; do
        echo ">>> delete package $pkg"
        # shellcheck disable=SC2086
        gp --delete "$pkg" ${GP_FORCE:-} || true
    done
    ;;
*)
    echo "usage: gp.sh {load|create|perso|delete} ..." >&2
    exit 2
    ;;
esac
