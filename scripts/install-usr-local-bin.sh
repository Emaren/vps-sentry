#!/usr/bin/env bash
set -euo pipefail
umask 022

REPO_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_DIR/deploy/usr-local/bin"
DEST_DIR="/usr/local/bin"
ts="$(date +%Y%m%d-%H%M%S)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "FATAL: missing $SRC_DIR" >&2
  exit 1
fi

count=0
for src in "$SRC_DIR"/*; do
  [[ -f "$src" ]] || continue
  base="$(basename "$src")"

  if [[ -e "$DEST_DIR/$base" ]]; then
    cp -a "$DEST_DIR/$base" "$DEST_DIR/$base.bak-$ts"
  fi

  install -o root -g root -m 0755 "$src" "$DEST_DIR/$base"
  count=$((count + 1))
done

echo "OK: installed $count tool(s) to $DEST_DIR (backups: *.bak-$ts)"