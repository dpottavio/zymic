#!/bin/sh
set -eu

show_help() {
  cat <<EOF
Usage: [PREFIX=/usr/local] [DESTDIR=] [DRY_RUN=1] ./install.sh [OPTIONS]

Options:
  -h, --help     Show this help message and exit.

Environment variables:
  PREFIX   Installation prefix (default: /usr/local)
  DESTDIR  Staging directory for package builds (default: empty)
  DRY_RUN  If set to 1, just print commands instead of executing them
EOF
}

# Parse flags
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      show_help
      exit 1
      ;;
  esac
done

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
ROOT="${DESTDIR}${PREFIX}"
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

DRY_RUN="${DRY_RUN:-0}"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s\n' "$*"
  else
    $*
  fi
}

echo "Installing to $ROOT"

# Binary
run install -Dm755 "$SELF_DIR/zymic" "$ROOT/bin/zymic"

# Man pages
for f in "$SELF_DIR"/man/*.1.gz; do
  [ -f "$f" ] || continue
  run install -Dm644 "$f" "$ROOT/share/man/man1/$(basename "$f")"
done

# Completions
[ -f "$SELF_DIR/completions/zymic.bash" ] && \
  run install -Dm644 "$SELF_DIR/completions/zymic.bash" \
    "$ROOT/share/bash-completion/completions/zymic"

[ -f "$SELF_DIR/completions/_zymic" ] && \
  run install -Dm644 "$SELF_DIR/completions/_zymic" \
    "$ROOT/share/zsh/site-functions/_zymic"

[ -f "$SELF_DIR/completions/zymic.fish" ] && \
  run install -Dm644 "$SELF_DIR/completions/zymic.fish" \
    "$ROOT/share/fish/vendor_completions.d/zymic.fish"

[ -f "$SELF_DIR/completions/zymic.elv" ] && \
  run install -Dm644 "$SELF_DIR/completions/zymic.elv" \
    "$ROOT/share/elvish/lib/zymic.elv"

# Update man db if available
if command -v mandb >/dev/null 2>&1; then
  run mandb -q
fi

echo "Done."
[ "$DRY_RUN" = "1" ] && echo "(dry-run only, no files changed)"
