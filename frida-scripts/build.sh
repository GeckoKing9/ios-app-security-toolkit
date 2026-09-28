#!/usr/bin/env bash
# Recompile every ObjC-bridge Frida script in src/ to the parent dir.
# Frida 17 dropped the ObjC/Swift globals, so these must be bundled with the
# frida-objc-bridge at build time. Scripts that only hook C functions
# (e.g. crypto-monitor.js) live directly in the parent dir and need no build.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
FC="$ROOT/node_modules/.bin/frida-compile"
for src in "$HERE"/src/*.js; do
  name="$(basename "$src")"
  "$FC" "$src" -o "$HERE/$name"
  echo "compiled $name"
done
