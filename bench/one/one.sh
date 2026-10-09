#!/usr/bin/env bash
# Build (once) and run The ONE in batch mode.
#   bench/one/one.sh build
#   bench/one/one.sh run <runs> <settings>...   (settings relative to bench/one)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ONE="$HERE/../external/the-one"
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"

build() {
  cd "$ONE"
  mkdir -p target
  javac -nowarn -sourcepath src -d target -cp lib/ECLA.jar:lib/DTNConsoleConnection.jar \
    src/core/*.java src/movement/*.java src/report/*.java src/routing/*.java \
    src/gui/*.java src/input/*.java src/applications/*.java src/interfaces/*.java 2>&1 | grep -v '^Note:' || true
  [ -d target/gui/buttonGraphics ] || cp -R src/gui/buttonGraphics target/gui/
  java -version 2>&1 | head -1
}

run() {
  local runs="$1"; shift
  local files=()
  for f in "$@"; do files+=("$HERE/$f"); done
  # ONE resolves data/ and reports/ against its working directory.
  cd "$ONE"
  # MaxPropRouter's comparator isn't transitive; Java 7+ TimSort rejects it.
  java -Xmx4G -Djava.util.Arrays.useLegacyMergeSort=true -cp target:lib/ECLA.jar:lib/DTNConsoleConnection.jar core.DTNSim -b "$runs" "${files[@]}"
}

case "${1:-}" in
  build) build ;;
  run) shift; run "$@" ;;
  *) echo "usage: $0 build | run <runs> <settings>..." >&2; exit 2 ;;
esac
