IDENTITY = $(shell security find-identity -p codesigning -v | head -1 | cut -d ' ' -f 4 | tr -d '\n')

atsprobe: main.swift atsprobe.entitlements Info.plist
	swiftc -gnone -O -whole-module-optimization -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist -o $@ $<
	codesign --force --sign $(IDENTITY) --entitlements $@.entitlements $@

atsprobe_noats: main.swift atsprobe.entitlements Info_noats.plist
	swiftc -gnone -O -whole-module-optimization -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info_noats.plist -o $@ $<
	codesign --force --sign $(IDENTITY) --entitlements atsprobe.entitlements $@

all: atsprobe atsprobe_noats

clean:
	rm -f atsprobe atsprobe_noats
	rm -rf _CodeSignature

.phony: all clean
