#!/usr/bin/env bash
#
# This script builds the crate in the target directory into a staticlib XCFramework for iOS.

BUILD_PROFILE="release"
FRAMEWORK_NAME="AttestationBindings"
IS_FOCUS=
# FRAMEWORK_FILENAME exist purely because we would like to ship
# multiple frameworks that have the same swift code
# namely for focus. However, componenets that use
# uniffi, can only declare a single framework name.
#
# So we keep the framework the same, but store them
# under different file names.
FRAMEWORK_FILENAME=$FRAMEWORK_NAME
while [[ "$#" -gt 0 ]]; do case $1 in
  --build-profile) BUILD_PROFILE="$2"; shift;shift;;
  --framework-name) FRAMEWORK_NAME="$2"; shift;shift;;
  *) echo "Unknown parameter: $1"; exit 1;
esac; done

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WORKING_DIR=
if [[ -n $IS_FOCUS ]]; then
  WORKING_DIR="$THIS_DIR/focus"
else
  WORKING_DIR=$THIS_DIR
fi
REPO_ROOT="$( dirname "$THIS_DIR" )"

MANIFEST_PATH="$WORKING_DIR/Cargo.toml"

if [[ ! -f "$MANIFEST_PATH" ]]; then
  echo "Could not locate Cargo.toml in $MANIFEST_PATH"
  exit 1
fi

CRATE_NAME=$(grep --max-count=1 '^name =' "$MANIFEST_PATH" | cut -d '"' -f 2)
if [[ -z "$CRATE_NAME" ]]; then
  echo "Could not determine crate name from $MANIFEST_PATH"
  exit 1
fi

LIB_NAME="lib${CRATE_NAME}.a"
LIB_NAME="${LIB_NAME//-/_}"

####
##
## 1) Build the rust code individually for each target architecture.
##
####

# Helper to run the cargo build command in a controlled environment.
# It's important that we don't let environment variables from the user's default
# desktop build environment leak into the iOS build, otherwise it might e.g.
# link against the desktop build of NSS.

CARGO="$HOME/.cargo/bin/cargo"
LIBS_DIR="$REPO_ROOT/libs"

DEFAULT_RUSTFLAGS=""
BUILD_ARGS=(build --manifest-path "$MANIFEST_PATH" --lib)
case $BUILD_PROFILE in
  debug) ;;
  release)
    BUILD_ARGS=("${BUILD_ARGS[@]}" --release)
    # With debuginfo, the zipped artifact quickly baloons to many
    # hundred megabytes in size. Ideally we'd find a way to keep
    # the debug info but in a separate artifact.
    DEFAULT_RUSTFLAGS="-C debuginfo=0"
    ;;
  *) echo "Unknown build profile: $BUILD_PROFILE"; exit 1;
esac

cargo_build () {
  TARGET=$1
    "$CARGO" "${BUILD_ARGS[@]}" --target "$TARGET"
}

set -euvx

rustup install nightly
rustup target add x86_64-apple-ios
rustup target add aarch64-apple-ios-sim

# Intel iOS simulator
CFLAGS_x86_64_apple_ios="-target x86_64-apple-ios" \
  cargo +nightly build --target x86_64-apple-ios --release

# Hardware iOS targets
cargo +nightly build --target aarch64-apple-ios --release

# M1 iOS simulator.
# CFLAGS_aarch64_apple_ios_sim="-target aarch64-apple-ios-sim" \
  # cargo_build aarch64-apple-ios-sim

cargo +nightly build -Z build-std --target aarch64-apple-ios-sim --release

# TODO: would it be useful to also include desktop builds here?
# It might make it possible to run the Swift tests via `swift test`
# rather than through Xcode.

####
##
## 2) Stitch the individual builds together an XCFramework bundle.
##
####

TARGET_DIR="$REPO_ROOT/target"
XCFRAMEWORK_ROOT="$TARGET_DIR/$FRAMEWORK_FILENAME.xcframework"

# Start from a clean slate.

rm -rf "$XCFRAMEWORK_ROOT"

# Build the directory structure right for an individual framework.
# Most of this doesn't change between architectures.

COMMON="$XCFRAMEWORK_ROOT/common/$FRAMEWORK_NAME.framework"

mkdir -p "$COMMON/Modules"
cp "$WORKING_DIR/module.modulemap" "$COMMON/Modules/"

mkdir -p "$COMMON/Headers"

cp "$WORKING_DIR/$FRAMEWORK_NAME.h" "$COMMON/Headers"
cp "$REPO_ROOT/swift-attestation-bindings/ios/AttestationBindingsRustFFI.h" "$COMMON/Headers"
cp "$REPO_ROOT/swift-attestation-bindings/ios/Info.plist" "$COMMON"
rm -rf "$COMMON"/Headers/*.swift

# Flesh out the framework for each architecture based on the common files.
# It's a little fiddly, because we apparently need to put all the simulator targets
# together into a single fat binary, but keep the hardware target separate.
# (TODO: we should try harder to see if we can avoid using `lipo` here, eliminating it
# would make the overall system simpler to understand).

# iOS hardware
mkdir -p "$XCFRAMEWORK_ROOT/ios-arm64"
cp -r "$COMMON" "$XCFRAMEWORK_ROOT/ios-arm64/$FRAMEWORK_NAME.framework"
cp "$TARGET_DIR/aarch64-apple-ios/$BUILD_PROFILE/$LIB_NAME" "$XCFRAMEWORK_ROOT/ios-arm64/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME"

# iOS simulator, with both platforms as a fat binary for mysterious reasons
mkdir -p "$XCFRAMEWORK_ROOT/ios-arm64_x86_64-simulator"
cp -r "$COMMON" "$XCFRAMEWORK_ROOT/ios-arm64_x86_64-simulator/$FRAMEWORK_NAME.framework"
lipo -create \
  -output "$XCFRAMEWORK_ROOT/ios-arm64_x86_64-simulator/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME" \
  "$TARGET_DIR/aarch64-apple-ios-sim/$BUILD_PROFILE/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-ios/$BUILD_PROFILE/$LIB_NAME"

# Set up the metadata for the XCFramework as a whole.

cp "$WORKING_DIR/Info.plist" "$XCFRAMEWORK_ROOT/Info.plist"

rm -rf "$XCFRAMEWORK_ROOT/common"

# Zip it all up into a bundle for distribution.

(cd "$TARGET_DIR" && zip -9 -r "$FRAMEWORK_FILENAME.xcframework.zip" "$FRAMEWORK_FILENAME.xcframework")
