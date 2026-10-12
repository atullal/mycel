#!/bin/sh
set -eu
RETAINED_TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RETAINED_PLUGIN_DIR=$(CDPATH= cd -- "$RETAINED_TEST_DIR/../.." && pwd)
RETAINED_BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$RETAINED_BUILD_DIR"' EXIT
xcrun swiftc -emit-library -emit-module -module-name Tauri "$RETAINED_TEST_DIR/TauriStub.swift" -o "$RETAINED_BUILD_DIR/libTauri.dylib" -emit-module-path "$RETAINED_BUILD_DIR/Tauri.swiftmodule"
xcrun swiftc -I "$RETAINED_BUILD_DIR" -L "$RETAINED_BUILD_DIR" -lTauri -Xlinker -rpath -Xlinker "$RETAINED_BUILD_DIR" "$RETAINED_TEST_DIR/Models.swift" "$RETAINED_PLUGIN_DIR/ios/Sources/NotificationManager.swift" "$RETAINED_PLUGIN_DIR/ios/Sources/NotificationHandler.swift" "$RETAINED_TEST_DIR/main.swift" -o "$RETAINED_BUILD_DIR/retained-test"
"$RETAINED_BUILD_DIR/retained-test"
