#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_DIR/deploy/usr-local/bin"
DST="/usr/local/bin"

if [[ ! -d "$SRC" ]]; then
  echo "FATAL: missing $SRC" >&2
  exit 1
fi

echo "=== audit: repo -> /usr/local/bin"
missing=0
differs=0

# Check every repo tool exists + matches in /usr/local/bin
while IFS= read -r -d '' f; do
  base="$(basename "$f")"
  if [[ ! -f "$DST/$base" ]]; then
    echo "MISSING: $DST/$base"
    missing=$((missing+1))
    continue
  fi

  # compare bytes + mode/owner (we expect root-owned in /usr/local/bin)
  if ! cmp -s "$f" "$DST/$base"; then
    echo "DIFFERS: $base (content mismatch)"
    differs=$((differs+1))
  fi
done < <(find "$SRC" -maxdepth 1 -type f -print0)

echo
echo "=== extras in /usr/local/bin (not in repo set)"
for f in "$DST"/vps-sentry* "$DST"/as-*; do
  [[ -f "$f" ]] || continue
  base="$(basename "$f")"
  if [[ ! -f "$SRC/$base" ]]; then
    echo "EXTRA: $f"
  fi
done

echo
echo "RESULT: missing=$missing differs=$differs"
if [[ "$missing" -eq 0 && "$differs" -eq 0 ]]; then
  echo "OK: /usr/local/bin matches repo deploy set."
  exit 0
fi

exit 1