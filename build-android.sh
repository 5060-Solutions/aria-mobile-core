#!/bin/bash
# Build aria-mobile-core for Android and update the Android app.
#
# Prerequisites:
#   rustup target add aarch64-linux-android x86_64-linux-android
#   Android NDK installed via Android Studio
#
# Usage:
#   ./build-android.sh [debug|release]

set -euo pipefail

MODE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$SCRIPT_DIR/../aria-android"
JNILIB_DIR="$ANDROID_DIR/app/src/main/jniLibs"
KOTLIN_DIR="$ANDROID_DIR/app/src/main/kotlin/com/solutions5060/aria/bridge/uniffi/uniffi/aria_mobile"

# Find NDK
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    for ndk in "$HOME/Library/Android/sdk/ndk"/*/; do
        if [ -d "$ndk/toolchains/llvm/prebuilt" ]; then
            export ANDROID_NDK_HOME="${ndk%/}"
            break
        fi
    done
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "Error: ANDROID_NDK_HOME not set and no NDK found"
    exit 1
fi

# Find prebuilt toolchain
PREBUILT=$(ls -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/"*/ 2>/dev/null | head -1)
if [ -z "$PREBUILT" ]; then
    echo "Error: No prebuilt toolchain found in $ANDROID_NDK_HOME"
    exit 1
fi
export PATH="$PREBUILT/bin:$PATH"
export CMAKE_POLICY_VERSION_MINIMUM=3.5

CARGO_FLAGS=""
TARGET_DIR="debug"
if [ "$MODE" = "release" ]; then
    CARGO_FLAGS="--release"
    TARGET_DIR="release"
fi

cd "$SCRIPT_DIR"

echo "=== Building aria-mobile-core for Android ($MODE) ==="
echo "NDK: $ANDROID_NDK_HOME"

# Build for arm64 (primary — all modern phones)
echo "Building aarch64-linux-android..."
cargo build $CARGO_FLAGS --target aarch64-linux-android --lib

# Build for x86_64 (emulator)
echo "Building x86_64-linux-android..."
cargo build $CARGO_FLAGS --target x86_64-linux-android --lib

# Copy .so files with the name UniFFI expects
echo "Copying .so files..."
mkdir -p "$JNILIB_DIR/arm64-v8a" "$JNILIB_DIR/x86_64"
cp "target/aarch64-linux-android/$TARGET_DIR/libaria_mobile_core.so" "$JNILIB_DIR/arm64-v8a/libuniffi_aria_mobile.so"
cp "target/x86_64-linux-android/$TARGET_DIR/libaria_mobile_core.so" "$JNILIB_DIR/x86_64/libuniffi_aria_mobile.so"

# Generate Kotlin bindings
echo "Generating UniFFI Kotlin bindings..."
cargo run --features uniffi/cli -- generate src/aria_mobile.udl \
    --language kotlin \
    --out-dir "$KOTLIN_DIR"

echo ""
echo "=== Done ==="
echo "Native libs: $JNILIB_DIR/{arm64-v8a,x86_64}/libuniffi_aria_mobile.so"
echo "Kotlin bindings: $KOTLIN_DIR/aria_mobile.kt"
echo ""
echo "Now build the APK:"
echo "  cd $ANDROID_DIR && ./gradlew assembleDebug"
