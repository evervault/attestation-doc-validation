#!/usr/bin/env bash
ANDROID_SDK_PATH=$1

cross build --release --lib \
    --target x86_64-linux-android  \
    --target i686-linux-android \
    --target armv7-linux-androideabi \
    --target aarch64-linux-android

cp ../target/x86_64-linux-android/release/libbindings.so $ANDROID_SDK_PATH/evervault-inputs/src/main/jniLibs/x86_64/libuniffi_bindings.so
cp ../target/aarch64-linux-android/release/libbindings.so $ANDROID_SDK_PATH/evervault-inputs/src/main/jniLibs/arm64-v8a/libuniffi_bindings.so
cp ../target/armv7-linux-androideabi/release/libbindings.so $ANDROID_SDK_PATH/evervault-inputs/src/main/jniLibs/armeabi-v7a/libuniffi_bindings.so
cp ../target/i686-linux-android/release/libbindings.so $ANDROID_SDK_PATH/evervault-inputs/src/main/jniLibs/x86/libuniffi_bindings.so

cargo run --features=uniffi/cli --bin uniffi-bindgen generate --language kotlin src/bindings.udl
cp src/uniffi/bindings/bindings.kt $ANDROID_SDK_PATH/evervault-inputs/src/main/java/uniffi/bindings/bindings.kt
