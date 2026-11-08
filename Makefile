# p2f-lib: one C library for desktop, PS4, WebAssembly, Android and iOS.
#
#   make              desktop library + p2f-cli     -> build/host/
#   make test         desktop build + end-to-end tests (needs Node 20+)
#   make ps4          PS4 library (OpenOrbis)        -> build/ps4/libp2f.a
#                     needs OO_PS4_TOOLCHAIN=/path/to/PS4Toolchain. It has no
#                     platform layer: the app defines the hooks in
#                     include/p2f_platform.h (P2PS: ps4/platform_ps4.c).
#   make wasm         WebAssembly core for the JavaScript package
#                     -> build/wasm/p2f.wasm; needs WASI_SDK_PATH=/path/to/wasi-sdk
#   make android      Android libraries (NDK r26+)   -> build/android/<abi>/libp2f.a
#                     for arm64-v8a, armeabi-v7a and x86_64; needs
#                     ANDROID_NDK_HOME=/path/to/ndk
#   make ios          iOS XCFramework (macOS + Xcode) -> build/ios/P2F.xcframework
#                     device arm64, simulator arm64 + x86_64
#   make dist         release bundles                -> dist/
#                     (dist-android and dist-ios are separate targets)
#
# Third-party sources: scripts/fetch_deps.sh (mbedTLS, cJSON).

VERSION  := $(shell cat VERSION)
MBEDTLS  := third_party/mbedtls
CJSON    := third_party/cJSON

CORE_SRC := src/p2f_client.c src/p2f_http.c src/p2f_crypto.c src/p2f_policy.c \
            src/p2f_download.c src/p2f_tls.c src/p2f_dns.c src/ca_bundle.c \
            $(CJSON)/cJSON.c
MBED_SRC := $(wildcard $(MBEDTLS)/library/*.c)
DEFS     := -DMBEDTLS_CONFIG_FILE='"p2f_mbedtls_config.h"' -DP2F_VERSION='"$(VERSION)"'
INCS     := -Iinclude -Isrc -I$(MBEDTLS)/include -I$(CJSON)

all: host

# ---- Desktop -------------------------------------------------------------

CC        ?= cc
AR        ?= ar
HOST      := build/host
HOST_CFLAGS := -O2 -Wall -Wextra -fPIC $(INCS) $(DEFS)
HOST_OBJ  := $(patsubst %.c,$(HOST)/%.o,$(CORE_SRC) src/platform/posix.c $(MBED_SRC))

host: $(HOST)/libp2f.a $(HOST)/p2f-cli

$(HOST)/libp2f.a: $(HOST_OBJ)
	rm -f $@
	$(AR) rcs $@ $^

$(HOST)/p2f-cli: $(HOST)/tools/p2f_cli.o $(HOST)/libp2f.a
	$(CC) -o $@ $^

$(HOST)/$(MBEDTLS)/%.o: $(MBEDTLS)/%.c src/p2f_mbedtls_config.h
	@mkdir -p $(dir $@)
	$(CC) $(HOST_CFLAGS) -w -c -o $@ $<

$(HOST)/%.o: %.c src/p2f_mbedtls_config.h VERSION
	@mkdir -p $(dir $@)
	$(CC) $(HOST_CFLAGS) -c -o $@ $<

test: host
	tools/test_host.sh

# ---- PS4 (OpenOrbis) -----------------------------------------------------

PS4       := build/ps4
PS4_CC    ?= clang
PS4_AR    ?= llvm-ar
PS4_CFLAGS = --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -O2 \
             -isysroot $(OO_PS4_TOOLCHAIN) -isystem $(OO_PS4_TOOLCHAIN)/include \
             $(INCS) $(DEFS)
PS4_OBJ   := $(patsubst %.c,$(PS4)/%.o,$(CORE_SRC) $(MBED_SRC))

ps4: $(PS4)/libp2f.a

$(PS4)/libp2f.a: $(PS4_OBJ)
	rm -f $@
	$(PS4_AR) rcs $@ $^

$(PS4)/$(MBEDTLS)/%.o: $(MBEDTLS)/%.c src/p2f_mbedtls_config.h
	@test -n "$(OO_PS4_TOOLCHAIN)" || { echo "Set OO_PS4_TOOLCHAIN"; exit 1; }
	@mkdir -p $(dir $@)
	$(PS4_CC) $(PS4_CFLAGS) -w -c -o $@ $<

$(PS4)/%.o: %.c src/p2f_mbedtls_config.h VERSION
	@test -n "$(OO_PS4_TOOLCHAIN)" || { echo "Set OO_PS4_TOOLCHAIN"; exit 1; }
	@mkdir -p $(dir $@)
	$(PS4_CC) $(PS4_CFLAGS) -Wall -c -o $@ $<

# ---- WebAssembly ---------------------------------------------------------
# Only the parts with no sockets: crypto, policy, and the exports in
# src/wasm/. The JavaScript package does the HTTP with fetch().

WASM      := build/wasm
WASM_CC    = $(WASI_SDK_PATH)/bin/clang
WASM_CFLAGS = --target=wasm32-wasip1 -O2 -flto -Iinclude -Isrc -I$(MBEDTLS)/include \
              -DMBEDTLS_CONFIG_FILE='"p2f_mbedtls_config_wasm.h"' -DP2F_VERSION='"$(VERSION)"'
WASM_MBED := aes gcm cipher cipher_wrap ecp ecp_curves ecdh bignum bignum_core \
             hkdf md sha256 base64 platform_util constant_time
WASM_SRC  := src/p2f_crypto.c src/p2f_policy.c src/platform/wasm.c src/wasm/exports.c \
             $(patsubst %,$(MBEDTLS)/library/%.c,$(WASM_MBED))
WASM_OBJ  := $(patsubst %.c,$(WASM)/%.o,$(WASM_SRC))

wasm: $(WASM)/p2f.wasm

$(WASM)/p2f.wasm: $(WASM_OBJ)
	$(WASM_CC) --target=wasm32-wasip1 -O2 -flto -mexec-model=reactor \
	  -Wl,--strip-all -o $@ $^

$(WASM)/$(MBEDTLS)/%.o: $(MBEDTLS)/%.c src/p2f_mbedtls_config_wasm.h
	@test -n "$(WASI_SDK_PATH)" || { echo "Set WASI_SDK_PATH"; exit 1; }
	@mkdir -p $(dir $@)
	$(WASM_CC) $(WASM_CFLAGS) -w -c -o $@ $<

$(WASM)/%.o: %.c src/p2f_mbedtls_config_wasm.h VERSION
	@test -n "$(WASI_SDK_PATH)" || { echo "Set WASI_SDK_PATH"; exit 1; }
	@mkdir -p $(dir $@)
	$(WASM_CC) $(WASM_CFLAGS) -Wall -c -o $@ $<

# ---- Android and iOS ----------------------------------------------------
# Static libraries with the POSIX platform hooks (weak, so the app can
# replace any of them; see include/p2f_platform.h).
#
# $(1) build dir, $(2) compiler command, $(3) archive command, $(4) flags
define static_lib
$(1)/libp2f.a: $(patsubst %.c,$(1)/%.o,$(CORE_SRC) src/platform/posix.c $(MBED_SRC))
	rm -f $$@
	$(3) $$@ $$^

$(1)/$(MBEDTLS)/%.o: $(MBEDTLS)/%.c src/p2f_mbedtls_config.h
	@mkdir -p $$(dir $$@)
	$(2) $(4) -w -c -o $$@ $$<

$(1)/%.o: %.c src/p2f_mbedtls_config.h VERSION
	@mkdir -p $$(dir $$@)
	$(2) $(4) -Wall -Wextra -c -o $$@ $$<
endef

MOBILE_CFLAGS := -O2 -fPIC $(INCS) $(DEFS)

# Android: one library per ABI, API level 24 (Android 7.0) and up.
ANDROID_API   ?= 24
ANDROID_HOST  := $(if $(filter Darwin,$(shell uname -s)),darwin,linux)-x86_64
ANDROID_BIN    = $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(ANDROID_HOST)/bin
ANDROID_ABIS  := arm64-v8a armeabi-v7a x86_64
android_triple = $(if $(filter arm64-v8a,$(1)),aarch64-linux-android,$(if $(filter armeabi-v7a,$(1)),armv7a-linux-androideabi,x86_64-linux-android))
ANDROID_OBJ   := $(foreach a,$(ANDROID_ABIS),$(patsubst %.c,build/android/$(a)/%.o,$(CORE_SRC) src/platform/posix.c $(MBED_SRC)))

android: $(foreach a,$(ANDROID_ABIS),build/android/$(a)/libp2f.a)

android-check:
	@test -n "$(ANDROID_NDK_HOME)" -a -x "$(ANDROID_BIN)/clang" || { echo "Set ANDROID_NDK_HOME to an Android NDK (r26+)"; exit 1; }

$(ANDROID_OBJ): | android-check

$(foreach a,$(ANDROID_ABIS),$(eval $(call static_lib,build/android/$(a),$(ANDROID_BIN)/clang,$(ANDROID_BIN)/llvm-ar rcs,--target=$(call android_triple,$(a))$(ANDROID_API) $(MOBILE_CFLAGS))))

# iOS: needs macOS with Xcode. One XCFramework for device and simulator.
IOS_MIN       ?= 13.0
IOS_DEV_CC    := xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=$(IOS_MIN)
IOS_SIM_CC    := xcrun -sdk iphonesimulator clang -arch arm64 -arch x86_64 -mios-simulator-version-min=$(IOS_MIN)

$(eval $(call static_lib,build/ios/device,$(IOS_DEV_CC),libtool -static -o,$(MOBILE_CFLAGS)))
$(eval $(call static_lib,build/ios/simulator,$(IOS_SIM_CC),libtool -static -o,$(MOBILE_CFLAGS)))

ios: build/ios/P2F.xcframework

build/ios/P2F.xcframework: build/ios/device/libp2f.a build/ios/simulator/libp2f.a
	rm -rf build/ios/P2F.xcframework build/ios/headers
	mkdir -p build/ios/headers
	cp include/p2f.h include/p2f_platform.h build/ios/headers/
	xcodebuild -create-xcframework \
	  -library build/ios/device/libp2f.a -headers build/ios/headers \
	  -library build/ios/simulator/libp2f.a -headers build/ios/headers \
	  -output $@

# ---- Release bundles -----------------------------------------------------
# dist/p2f-lib-<v>-<target>.tar.gz: include/p2f.h + lib/libp2f.a + licenses.
# The archive already holds mbedTLS and cJSON: link only libp2f.a.

HOST_TARGET := $(shell uname -s | tr A-Z a-z)-$(shell uname -m)

dist-ps4: build/ps4/libp2f.a
	$(call bundle,ps4,$<)

dist-host: build/host/libp2f.a build/host/p2f-cli
	$(call bundle,$(HOST_TARGET),$<,build/host/p2f-cli)

dist-wasm: build/wasm/p2f.wasm
	mkdir -p dist
	cp $< dist/p2f-$(VERSION).wasm

dist: dist-host dist-ps4 dist-wasm

# dist/p2f-lib-<v>-android.tar.gz: include/ + lib/<abi>/libp2f.a
dist-android: android
	rm -rf build/dist/p2f-lib-android
	mkdir -p build/dist/p2f-lib-android/include dist
	cp include/p2f.h include/p2f_platform.h build/dist/p2f-lib-android/include/
	for a in $(ANDROID_ABIS); do mkdir -p build/dist/p2f-lib-android/lib/$$a && cp build/android/$$a/libp2f.a build/dist/p2f-lib-android/lib/$$a/; done
	cp LICENSE THIRD_PARTY.md VERSION build/dist/p2f-lib-android/
	tar -C build/dist -czf dist/p2f-lib-$(VERSION)-android.tar.gz p2f-lib-android

# dist/p2f-lib-<v>-ios.zip: P2F.xcframework + licenses
dist-ios: ios
	rm -rf build/dist/p2f-lib-ios
	mkdir -p build/dist/p2f-lib-ios dist
	cp -R build/ios/P2F.xcframework build/dist/p2f-lib-ios/
	cp LICENSE THIRD_PARTY.md VERSION build/dist/p2f-lib-ios/
	rm -f dist/p2f-lib-$(VERSION)-ios.zip
	cd build/dist && zip -qry ../../dist/p2f-lib-$(VERSION)-ios.zip p2f-lib-ios

# $(1) target name, $(2) libp2f.a, $(3) optional binary
define bundle
	rm -rf build/dist/p2f-lib-$(1)
	mkdir -p build/dist/p2f-lib-$(1)/include build/dist/p2f-lib-$(1)/lib dist
	cp include/p2f.h include/p2f_platform.h build/dist/p2f-lib-$(1)/include/
	cp $(2) build/dist/p2f-lib-$(1)/lib/
	$(if $(3),mkdir -p build/dist/p2f-lib-$(1)/bin && cp $(3) build/dist/p2f-lib-$(1)/bin/)
	cp LICENSE THIRD_PARTY.md VERSION build/dist/p2f-lib-$(1)/
	tar -C build/dist -czf dist/p2f-lib-$(VERSION)-$(1).tar.gz p2f-lib-$(1)
endef

clean:
	rm -rf build dist

.PHONY: all host test ps4 wasm android android-check ios dist dist-host dist-ps4 dist-wasm dist-android dist-ios clean
