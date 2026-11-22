#!/usr/bin/env bash
set -euo pipefail
umask 022

REPO_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_DIR/deploy/usr-local/bin"
DEST_DIR="/usr/local/bin"
ts="$(date +%Y%m%d-%H%M%S)"

# Original installer: optional one-Sentry-controller admission without reinstalling
# every other /usr/local/bin program. This is a source/host exactness guard,
# not a signature or a new privilege grant.
only_name=""
expected_sha=""
if [[ "${1:-}" == "--only" ]]; then
  if [[ $# -ne 4 || "${2:-}" != "vps-sentry-garbage-estimate" || "${3:-}" != "--source-sha256" || ! "${4:-}" =~ ^[a-f0-9]{64}$ ]]; then
    echo "HOLD: only exact vps-sentry-garbage-estimate plus full SHA256 is permitted" >&2
    exit 12
  fi
  only_name="$2"
  expected_sha="$4"
  if [[ "$EUID" -ne 0 ]]; then
    echo "HOLD: original root installer required" >&2
    exit 12
  fi
  if [[ -L "$REPO_DIR" || -L "$SRC_DIR" || -L "$SRC_DIR/$only_name" || -L "$DEST_DIR/$only_name" ]]; then
    echo "HOLD: symlink source or destination" >&2
    exit 12
  fi
  src_stat="$(stat -c '%u:%g:%h:%a' "$SRC_DIR/$only_name")"
  if [[ "$src_stat" != 0:0:1:* ]]; then
    echo "HOLD: original root-owned singleton source required" >&2
    exit 12
  fi
  actual="$(sha256sum "$SRC_DIR/$only_name" | awk '{print $1}')"
  if [[ "$actual" != "$expected_sha" ]]; then
    echo "HOLD: original source checksum mismatch" >&2
    exit 12
  fi
  if [[ -e "$DEST_DIR/$only_name" ]]; then
    target_stat="$(stat -c '%u:%g:%h:%a' "$DEST_DIR/$only_name")"
    if [[ "$target_stat" != 0:0:1:* ]]; then
      echo "HOLD: original installed controller custody changed" >&2
      exit 12
    fi
  fi
fi

if [[ ! -d "$SRC_DIR" ]]; then
  echo "FATAL: missing $SRC_DIR" >&2
  exit 1
fi

count=0
for src in "$SRC_DIR"/*; do
  [[ -f "$src" ]] || continue
  base="$(basename "$src")"
  if [[ -n "$only_name" && "$base" != "$only_name" ]]; then
    continue
  fi

  if [[ -e "$DEST_DIR/$base" ]]; then
    if [[ -n "$only_name" && -e "$DEST_DIR/$base.bak-$ts" ]]; then
      echo "HOLD: original controller preimage backup collision" >&2
      exit 12
    fi
    cp -a "$DEST_DIR/$base" "$DEST_DIR/$base.bak-$ts"
  fi

  install -o root -g root -m 0755 "$src" "$DEST_DIR/$base"
  if [[ -n "$only_name" ]]; then
    installed="$(sha256sum "$DEST_DIR/$base" | awk '{print $1}')"
    if [[ "$installed" != "$expected_sha" ]]; then
      echo "HOLD: installed original controller did not match exact source" >&2
      exit 12
    fi
  fi
  count=$((count + 1))
done

echo "OK: installed $count tool(s) to $DEST_DIR (backups: *.bak-$ts)"