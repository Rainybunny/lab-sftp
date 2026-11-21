#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: sh test/roundtrip.sh username@hostname\n' >&2
    exit 2
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -x "$repo/build/client" ]; then
    printf 'Build the client in build/ first.\n' >&2
    exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' 0
trap 'exit 1' HUP INT TERM
cd "$workdir"
mkdir send
cp "$repo/client.c" send/client.c

printf 'In the client, enter: put send/client.c, get client.c, then bye.\n'
"$repo/build/client" "$1"
cmp send/client.c client.c
printf 'cmp send/client.c client.c succeeded: files are identical.\n'
