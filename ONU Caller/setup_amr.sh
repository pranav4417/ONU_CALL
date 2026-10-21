#!/bin/bash
# Builds the AMR-WB codec libraries for a real iPhone (arm64) and puts them in
# <project folder>/AMR. Run once on your Mac:
#
#   chmod +x setup_amr.sh
#   ./setup_amr.sh "/Users/pranav/Music/xcode/ONU Caller"
#
# <project folder> = the folder that contains "ONU Caller.xcodeproj".
set -euo pipefail

PROJECT="${1:?usage: ./setup_amr.sh <folder that contains the .xcodeproj>}"
DEST="$PROJECT/AMR"
WORK="$(mktemp -d)"
PREFIX="$WORK/out"          # no spaces here: libtool's install breaks on spaces
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CC="$(xcrun --sdk iphoneos -f clang)"
CXX="$(xcrun --sdk iphoneos -f clang++)"
FLAGS="-arch arm64 -isysroot $SDK -miphoneos-version-min=16.0 -O2"

mkdir -p "$DEST"
cd "$WORK"

echo "==> downloading sources"
curl -fL -o opencore.tar.gz "https://downloads.sourceforge.net/project/opencore-amr/opencore-amr/opencore-amr-0.1.6.tar.gz"
curl -fL -o voamrwb.tar.gz  "https://downloads.sourceforge.net/project/opencore-amr/vo-amrwbenc/vo-amrwbenc-0.1.3.tar.gz"

for pkg in opencore voamrwb; do
  echo "==> building $pkg"
  mkdir "$pkg"
  tar xzf "$pkg.tar.gz" -C "$pkg" --strip-components=1
  (
    cd "$pkg"
    ./configure --host=arm-apple-darwin --prefix="$PREFIX" \
      --disable-shared --enable-static \
      CC="$CC" CXX="$CXX" CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" \
      LDFLAGS="-arch arm64 -isysroot $SDK"
    make -j8
    make install
  )
done

rm -rf "$DEST/lib" "$DEST/include"
cp -R "$PREFIX/lib" "$PREFIX/include" "$DEST/"

cat > "$DEST/ONU-Bridging-Header.h" <<'EOF'
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>
EOF

echo
echo "Done. Created:"
ls "$DEST/lib" "$DEST/include"
echo
echo "Now follow step 4 of the README (build settings)."