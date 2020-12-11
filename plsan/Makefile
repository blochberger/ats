IDENTITY = $(shell security find-identity -p codesigning -v | head -1 | cut -d ' ' -f 4 | tr -d '\n')

plsan: plsan.swift
	swiftc -gnone -O -whole-module-optimization -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist -o $@ $<
	codesign --force --sign $(IDENTITY) --entitlements $@.entitlements $@

all:
	plsan
	rm -rf _CodeSignature

clean:
	rm -f plsan

.phony: all clean
