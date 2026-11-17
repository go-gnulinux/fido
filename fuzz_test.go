// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"strings"
	"testing"
	"testing/fstest"
)

// The bytes below are read out of a device's report descriptor and its sysfs
// uevent file: both are written by whatever is plugged in, so a malicious or
// broken USB device chooses them. The parsers must never panic, loop, or let a
// device pick the size of an allocation.

// yubikeyDescriptor is the report descriptor of a FIDO HID interface: usage
// page 0xF1D0, one 64-byte input report and one 64-byte output report.
var yubikeyDescriptor = []byte{
	0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
	0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00,
	0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0,
}

func FuzzUsagePages(f *testing.F) {
	f.Add(yubikeyDescriptor)
	f.Add([]byte{0x06})                   // a usage page item cut short
	f.Add([]byte{0xFE, 0xFF, 0x00})       // a long item
	f.Add([]byte{0x07, 0xD0, 0xF1, 0, 0}) // a four-byte usage page that does not fit 16 bits
	f.Fuzz(func(t *testing.T, d []byte) {
		pages := usagePages(d)
		// Every page is produced by consuming at least its tag and its value, so
		// there can never be more pages than bytes.
		if len(pages) > len(d) {
			t.Fatalf("%d pages from %d bytes", len(pages), len(d))
		}
		found := false
		for _, p := range pages {
			found = found || p == UsagePageFIDO
		}
		if speaksCTAP(d) != found {
			t.Fatalf("speaksCTAP disagrees with usagePages for %x", d)
		}
	})
}

func FuzzReportLengths(f *testing.F) {
	f.Add(yubikeyDescriptor)
	f.Add([]byte{0x96, 0xFF, 0xFF, 0x81, 0x02, 0x91, 0x02}) // a count of 65535: a device must not choose that
	f.Add([]byte{0x95, 0x40, 0x81})
	f.Fuzz(func(t *testing.T, d []byte) {
		in, out, ok := reportLengths(d)
		if !ok {
			if in != 0 || out != 0 {
				t.Fatalf("not ok but %d, %d", in, out)
			}
			return
		}
		if in <= 0 || out <= 0 || in > maxReportLen || out > maxReportLen {
			t.Fatalf("a device chose report sizes %d and %d", in, out)
		}
	})
}

func FuzzParseUevent(f *testing.F) {
	f.Add("DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey FIDO\n")
	f.Add("HID_ID=::\n")
	f.Add("HID_ID=0003:FFFFFFFFF:00000407\n")
	f.Fuzz(func(t *testing.T, s string) {
		d, err := parseUevent(s)
		if err != nil {
			return
		}
		if !strings.Contains(s, "HID_ID=") {
			t.Fatalf("a device came out of a uevent with no HID_ID: %+v", d)
		}
	})
}

// FuzzDiscover walks a whole sysfs tree built from fuzzed text and descriptor:
// whatever they say, discovery returns devices that really declared the usage
// page, and never fails.
func FuzzDiscover(f *testing.F) {
	f.Add("HID_ID=0003:00001050:00000407\nHID_NAME=k\n", yubikeyDescriptor)
	f.Fuzz(func(t *testing.T, uevent string, desc []byte) {
		fsys := fstest.MapFS{
			"class/hidraw/hidraw0/device/uevent": {Data: []byte(uevent)},
		}
		got, err := discover(fsys, func(string) ([]byte, error) { return desc, nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range got {
			if !speaksCTAP(desc) {
				t.Fatalf("%v listed without the FIDO usage page", d)
			}
		}
	})
}
