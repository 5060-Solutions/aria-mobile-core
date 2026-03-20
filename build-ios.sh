#!/bin/bash
# Build aria-mobile-core for iOS and update the iOS app.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Xcode + xcodegen installed
#
# Usage:
#   ./build-ios.sh [debug|release]

set -euo pipefail

MODE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_DIR="$SCRIPT_DIR/../aria-ios"
BRIDGE_DIR="$IOS_DIR/AriaSoftphone/Bridge"
FRAMEWORK_DIR="$IOS_DIR/AriaMobileCore.xcframework"

CARGO_FLAGS=""
TARGET_DIR="debug"
if [ "$MODE" = "release" ]; then
    CARGO_FLAGS="--release"
    TARGET_DIR="release"
fi

cd "$SCRIPT_DIR"
export CMAKE_POLICY_VERSION_MINIMUM=3.5

echo "=== Building aria-mobile-core for iOS ($MODE) ==="

# Build device library
echo "Building aarch64-apple-ios (device)..."
cargo rustc $CARGO_FLAGS --target aarch64-apple-ios --lib --crate-type staticlib

# Build simulator library
echo "Building aarch64-apple-ios-sim (simulator)..."
cargo rustc $CARGO_FLAGS --target aarch64-apple-ios-sim --lib --crate-type staticlib

# Universal simulator lib (just arm64 sim for now)
SIM_LIB="target/universal-ios-sim/$TARGET_DIR"
mkdir -p "$SIM_LIB"
cp "target/aarch64-apple-ios-sim/$TARGET_DIR/libaria_mobile_core.a" "$SIM_LIB/libaria_mobile_core.a"

# Generate Swift bindings
echo "Generating UniFFI Swift bindings..."
cargo run --features uniffi/cli -- generate src/aria_mobile.udl \
    --language swift \
    --out-dir "$BRIDGE_DIR"

# Prepare headers for xcframework (C header + modulemap only)
HEADERS_DIR="target/xcframework-headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR"
cp "$BRIDGE_DIR/aria_mobileFFI.h" "$HEADERS_DIR/"
cp "$BRIDGE_DIR/aria_mobileFFI.modulemap" "$HEADERS_DIR/module.modulemap"

# Create xcframework
echo "Creating XCFramework..."
rm -rf "$FRAMEWORK_DIR"
xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/$TARGET_DIR/libaria_mobile_core.a" \
    -headers "$HEADERS_DIR" \
    -library "$SIM_LIB/libaria_mobile_core.a" \
    -headers "$HEADERS_DIR" \
    -output "$FRAMEWORK_DIR"

# Regenerate Xcode project if xcodegen is available
if command -v xcodegen &>/dev/null && [ -f "$IOS_DIR/project.yml" ]; then
    echo "Regenerating Xcode project..."
    cd "$IOS_DIR" && xcodegen generate
fi

echo ""
echo "=== Done ==="
echo "XCFramework: $FRAMEWORK_DIR"
echo "Swift bindings: $BRIDGE_DIR/aria_mobile.swift"
echo ""
echo "Now build in Xcode or:"
echo "  cd $IOS_DIR"
echo "  xcodebuild -project AriaSoftphone.xcodeproj -scheme AriaSoftphone \\"
echo "    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \\"
echo "    -sdk iphonesimulator build"
