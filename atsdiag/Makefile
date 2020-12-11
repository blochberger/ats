IDENTITY = $(shell security find-identity -p codesigning -v | head -1 | cut -d ' ' -f 4 | tr -d '\n')

atsdiag: atsdiag.swift atsdiag.entitlements Info.plist
	swiftc -gnone -O -whole-module-optimization -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist -o $@ $<
	codesign --force --sign $(IDENTITY) --entitlements $@.entitlements $@

all:
	atsdiag

clean:
	rm -f atsdiag
	rm -rf _CodeSignature

.phony: all clean
