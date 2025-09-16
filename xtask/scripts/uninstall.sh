#!/bin/sh
set -eu

show_help() {
  cat <<EOF
Usage: [PREFIX=/usr/local] [DESTDIR=] [DRY_RUN=1] ./uninstall.sh [OPTIONS]

Options:
  -h, --help     Show this help message and exit.

Environment variables:
  PREFIX   Installation prefix used at install time (default: /usr/local)
  DESTDIR  Staging directory used at install time (default: empty)
  DRY_RUN  If set to 1, print commands instead of executing them
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) show_help; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; show_help; exit 1 ;;
  esac
done

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
ROOT="${DESTDIR}${PREFIX}"
DRY_RUN="${DRY_RUN:-0}"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

echo "Uninstalling from $ROOT"

# Files to remove (keep in sync with install.sh)
rm -f \
  "$ROOT/bin/zymic" \
  "$ROOT/share/man/man1/zymic.1.gz" \
  "$ROOT/share/man/man1/zymic-enc.1.gz" \
  "$ROOT/share/man/man1/zymic-dec.1.gz" \
  "$ROOT/share/man/man1/zymic-key.1.gz" \
  "$ROOT/share/man/man1/zymic-key-new.1.gz" \
  "$ROOT/share/man/man1/zymic-key-info.1.gz" \
  "$ROOT/share/man/man1/zymic-key-password.1.gz" \
  "$ROOT/share/bash-completion/completions/zymic" \
  "$ROOT/share/zsh/site-functions/_zymic" \
  "$ROOT/share/fish/vendor_completions.d/zymic.fish" \
  "$ROOT/share/elvish/lib/zymic.elv" 2>/dev/null || true

# Use run for commands that may fail/are optional
run rmdir "$ROOT/share/elvish/lib" 2>/dev/null || true
run rmdir "$ROOT/share/elvish" 2>/dev/null || true
run rmdir "$ROOT/share/fish/vendor_completions.d" 2>/dev/null || true
run rmdir "$ROOT/share/fish" 2>/dev/null || true
run rmdir "$ROOT/share/zsh/site-functions" 2>/dev/null || true
run rmdir "$ROOT/share/zsh" 2>/dev/null || true
run rmdir "$ROOT/share/bash-completion/completions" 2>/dev/null || true
run rmdir "$ROOT/share/bash-completion" 2>/dev/null || true
run rmdir "$ROOT/share/man/man1" 2>/dev/null || true
run rmdir "$ROOT/share/man" 2>/dev/null || true

if command -v mandb >/dev/null 2>&1; then
  run mandb -q
fi

echo "Done."
[ "$DRY_RUN" = "1" ] && echo "(dry-run only, no files changed)"
