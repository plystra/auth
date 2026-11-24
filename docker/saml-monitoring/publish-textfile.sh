#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf '%s\n' 'Usage: publish-textfile.sh /absolute/textfile-directory [warning-window]' >&2
    exit 1
fi
case "$1" in
    /*) directory=$1 ;;
    *) printf '%s\n' 'The textfile directory must be an absolute path' >&2; exit 1 ;;
esac

umask 077
pending=$(mktemp "$directory/.plystra-auth-saml-signing-trust.XXXXXX")
trap 'rm -f "$pending"' EXIT
trap 'exit 1' HUP INT TERM

status=0
plystra-auth sso check-saml-certificates --format prometheus --within "${2:-720h}" >"$pending" || status=$?
case "$status" in
    0|2) test -s "$pending" ;;
    *) exit "$status" ;;
esac
chmod 0644 "$pending"
mv -f "$pending" "$directory/plystra-auth-saml-signing-trust.prom"
