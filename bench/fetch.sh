#!/usr/bin/env bash
# Fetch the external tools and datasets the benchmarks use (docs/BENCHMARKS.md).
# Everything lands in bench/external/ and bench/data/ (both gitignored).
#
#   bench/fetch.sh            # everything
#   bench/fetch.sh traces     # contact traces only
#   bench/fetch.sh tools      # The ONE + Meshtasticator only
set -euo pipefail
cd "$(dirname "$0")"
WHAT="${1:-all}"

# Pinned upstream commits (the versions BENCHMARKS.md reports).
ONE_REPO=https://github.com/akeranen/the-one.git
ONE_COMMIT=c973bfb892ee3d624549a0142018f4d1dedf17d7
MESH_REPO=https://github.com/GUVWAF/Meshtasticator.git
MESH_COMMIT=17ceb8231079d87b070abc6132181e4c6b20202d

# CRAWDAD cambridge/haggle iMote traces (Scott, Gass, Crowcroft, Hui, Diot,
# Chaintreau; CRAWDAD, doi:10.15783/C70011, CC BY 4.0 per IEEE DataPort).
# IEEE DataPort needs a login, so we take the unmodified files from the mobemu
# repository (Ciobanu et al.), which redistributes them.
TRACES=https://raw.githubusercontent.com/raduciobanu/mobemu/master/traces

fetch() { # url dest
  [ -s "$2" ] && return 0
  mkdir -p "$(dirname "$2")"
  curl -sfL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2"
  echo "fetched $2"
}

clone() { # repo commit dir
  if [ ! -d "$3/.git" ]; then
    git clone -q "$1" "$3"
  fi
  git -C "$3" fetch -q --depth 1 origin "$2" 2>/dev/null || true
  git -C "$3" checkout -q "$2"
  echo "$3 at $(git -C "$3" rev-parse --short HEAD)"
}

if [ "$WHAT" = all ] || [ "$WHAT" = traces ]; then
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/contacts.Exp6.dat" data/infocom2006/contacts.Exp6.dat
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/Exp6.README"       data/infocom2006/Exp6.README
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/General.README"    data/infocom2006/General.README
  fetch "$TRACES/cambridge-haggle-imote-infocom/contacts.Exp3.dat"     data/infocom2005/contacts.Exp3.dat
  fetch "$TRACES/cambridge-haggle-imote-infocom/Exp3.README.txt"       data/infocom2005/Exp3.README.txt
  fetch "$TRACES/cambridge-haggle-imote-cambridge/contacts.Exp2.dat"   data/cambridge/contacts.Exp2.dat
  fetch "$TRACES/cambridge-haggle-imote-cambridge/Exp2.README.txt"     data/cambridge/Exp2.README.txt
fi

if [ "$WHAT" = all ] || [ "$WHAT" = tools ]; then
  mkdir -p external
  clone "$ONE_REPO" "$ONE_COMMIT" external/the-one
  clone "$MESH_REPO" "$MESH_COMMIT" external/Meshtasticator
fi
