// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// fidoDescriptor is the U2F HID report descriptor.
//
// ⚠ This one is written from the FIDO specification, NOT captured from a key,
// because no key was attached when these tests were written. A fixture written
// from a specification proves only that the code agrees with whoever wrote the
// fixture -- so the parser is ALSO checked against
// testdata/real-report-descriptors.txt, which holds bytes this project did not
// write and an answer it did not compute. Replace this with a captured
// descriptor when a key is to hand.
var fidoDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (0xF1D0)
	0x09, 0x01, //       Usage (1)
	0xA1, 0x01, //       Collection (Application)
	0x09, 0x20, //         Usage (0x20)
	0x15, 0x00, //         Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //         Report Size (8)
	0x95, 0x40, //         Report Count (64)
	0x81, 0x02, //         Input (Data,Var,Abs)
	0x09, 0x21, //         Usage (0x21)
	0x15, 0x00, //         Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //         Report Size (8)
	0x95, 0x40, //         Report Count (64)
	0x91, 0x02, //         Output (Data,Var,Abs)
	0xC0, //             End Collection
}

// TestTheParserAgreesWithIOKitOnRealDevices is the witness that matters.
//
// The bytes in testdata came off this machine's HID devices, and the page each
// line names was computed by IOKit from those same bytes. Nothing in this
// repository produced either. If the walk mis-sizes a single item -- and item
// widths of one and two bytes both appear here -- the pages come out shifted
// and the comparison fails.
func TestTheParserAgreesWithIOKitOnRealDevices(t *testing.T) {
	b, err := os.ReadFile("testdata/real-report-descriptors.txt")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Fatalf("testdata line is not three fields: %q", line)
		}
		want, err := strconv.ParseUint(f[0], 10, 16)
		if err != nil {
			t.Fatalf("testdata page %q: %v", f[0], err)
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil {
			t.Fatalf("testdata bytes for %q: %v", f[1], err)
		}
		pages := usagePages(raw)
		if len(pages) == 0 {
			t.Errorf("%s: no usage page found in %d real bytes", f[1], len(raw))
			continue
		}
		// IOKit reports the page of the PRIMARY (first) collection.
		if got := pages[0]; got != uint16(want) {
			t.Errorf("%s: first usage page 0x%04x, IOKit says 0x%04x", f[1], got, want)
		}
		n++
	}
	if n < 5 {
		t.Fatalf("only %d real descriptors exercised; the witness is too thin", n)
	}
	t.Logf("%d real descriptors, all agreeing with IOKit", n)
}

// TestNoneOfThisMachinesDevicesIsASecurityKey is a NEGATIVE control on the
// same real bytes. A filter that said yes to everything would pass the test
// above and still be useless.
func TestNoneOfThisMachinesDevicesIsASecurityKey(t *testing.T) {
	b, err := os.ReadFile("testdata/real-report-descriptors.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		raw, _ := hex.DecodeString(f[2])
		if speaksCTAP(raw) {
			t.Errorf("%s was taken for a security key", f[1])
		}
	}
	if !speaksCTAP(fidoDescriptor) {
		t.Error("and the FIDO descriptor was not")
	}
}

func TestUsagePagesReadsEveryItemWidth(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
		want []uint16
	}{
		{"one byte", []byte{0x05, 0x01}, []uint16{1}},
		{"two bytes", []byte{0x06, 0xD0, 0xF1}, []uint16{0xF1D0}},
		{"zero bytes is page zero", []byte{0x04}, []uint16{0}},
		{"four bytes that fit", []byte{0x07, 0x34, 0x12, 0x00, 0x00}, []uint16{0x1234}},
		// A four-byte page above 0xFFFF is not a usage page; truncating it
		// would INVENT one, and 0xF1D0 is exactly the value an attacker-shaped
		// descriptor would try to forge that way.
		{"four bytes too large", []byte{0x07, 0xD0, 0xF1, 0x01, 0x00}, nil},
		{"several", []byte{0x05, 0x01, 0x05, 0x09, 0x06, 0xD0, 0xF1}, []uint16{1, 9, 0xF1D0}},
		{"a long item stops the walk", []byte{0x05, 0x01, 0xFE, 0x02, 0x00, 0x05, 0x09}, []uint16{1}},
		{"a truncated item stops the walk", []byte{0x05, 0x01, 0x06, 0xD0}, []uint16{1}},
		{"nothing", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := usagePages(c.in)
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("usagePages = %v, want %v", got, c.want)
			}
		})
	}
}

// TestAFIDOPageBehindAnotherCollectionIsStillFound is the deliberate
// divergence from libfido2, which overwrites one variable as it walks and so
// judges by the LAST page it saw.
func TestAFIDOPageBehindAnotherCollectionIsStillFound(t *testing.T) {
	masked := append(append([]byte{}, fidoDescriptor...), 0x05, 0x01, 0xA1, 0x01, 0xC0)
	if !speaksCTAP(masked) {
		t.Error("a FIDO collection followed by another was missed")
	}
	if pages := usagePages(masked); pages[len(pages)-1] == UsagePageFIDO {
		t.Fatal("the fixture does not actually put another page last, so it proves nothing")
	}
}

func TestReportLengthsComeFromTheDescriptor(t *testing.T) {
	in, out, ok := reportLengths(fidoDescriptor)
	if !ok {
		t.Fatal("the FIDO descriptor declared no report lengths")
	}
	if in != ReportSize || out != ReportSize {
		t.Errorf("in=%d out=%d, want %d and %d", in, out, ReportSize, ReportSize)
	}
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"no input", []byte{0x95, 0x40, 0x91, 0x02}},
		{"no output", []byte{0x95, 0x40, 0x81, 0x02}},
		{"a count of zero", []byte{0x95, 0x00, 0x81, 0x02, 0x91, 0x02}},
		{"a long item", []byte{0xFE, 0x02, 0x00, 0x95, 0x40, 0x81, 0x02, 0x91, 0x02}},
		{"truncated", []byte{0x95, 0x40, 0x81}},
		{"an output count of zero", []byte{0x95, 0x40, 0x81, 0x02, 0x95, 0x00, 0x91, 0x02}},
		{"a four-byte count that is absurd", []byte{0x97, 0x00, 0x00, 0x00, 0x80, 0x81, 0x02, 0x91, 0x02, 0x95, 0x00}},
		{"nothing", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, ok := reportLengths(c.in); ok {
				t.Error("accepted")
			}
		})
	}
}

const yubikeyUevent = `DRIVER=hid-generic
HID_ID=0003:00001050:00000402
HID_NAME=Yubico YubiKey FIDO+CCID
HID_PHYS=usb-0000:00:14.0-3/input0
HID_UNIQ=
MODALIAS=hid:b0003g0001v00001050p00000402
`

func TestParseUevent(t *testing.T) {
	d, err := parseUevent(yubikeyUevent)
	if err != nil {
		t.Fatal(err)
	}
	if d.Bus != 3 || d.VendorID != 0x1050 || d.ProductID != 0x0402 {
		t.Errorf("bus=%d %04x:%04x, want bus=3 1050:0402", d.Bus, d.VendorID, d.ProductID)
	}
	if d.Name != "Yubico YubiKey FIDO+CCID" {
		t.Errorf("name %q", d.Name)
	}
	for _, c := range []struct{ name, in string }{
		{"no HID_ID at all", "HID_NAME=x\n"},
		{"too few fields", "HID_ID=0003:00001050\n"},
		{"not hexadecimal", "HID_ID=0003:zzzz:00000402\n"},
		{"a bus that does not fit", "HID_ID=100000:1050:0402\n"},
		{"empty", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseUevent(c.in); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// sysfs builds a fake /sys holding the named hidraw nodes.
func sysfs(nodes map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for node, uevent := range nodes {
		m["class/hidraw/"+node+"/device/uevent"] = &fstest.MapFile{Data: []byte(uevent)}
	}
	return m
}

func TestDiscoverFindsOnlyTheSecurityKey(t *testing.T) {
	fsys := sysfs(map[string]string{
		"hidraw0": "HID_ID=0003:000005AC:00000342\nHID_NAME=Apple Keyboard\n",
		"hidraw1": yubikeyUevent,
	})
	desc := func(path string) ([]byte, error) {
		if path == "/dev/hidraw1" {
			return fidoDescriptor, nil
		}
		return []byte{0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0xC0}, nil
	}
	got, err := discover(fsys, desc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("found %d devices, want 1: %v", len(got), got)
	}
	if got[0].Path != "/dev/hidraw1" || got[0].Node != "hidraw1" {
		t.Errorf("found %+v", got[0])
	}
	if !strings.Contains(got[0].String(), "1050:0402") {
		t.Errorf("String() = %q, which does not name the model", got[0].String())
	}
}

// TestOneUnreadableNodeDoesNotHideTheNext. A machine can hold a hidraw node
// this user may not touch beside the key they may. Abandoning the scan at the
// first refusal would report no key at all.
func TestOneUnreadableNodeDoesNotHideTheNext(t *testing.T) {
	fsys := sysfs(map[string]string{
		"hidraw0": "HID_ID=0003:00001050:00000402\nHID_NAME=locked\n",
		"hidraw9": yubikeyUevent,
	})
	desc := func(path string) ([]byte, error) {
		if path == "/dev/hidraw0" {
			return nil, os.ErrPermission
		}
		return fidoDescriptor, nil
	}
	got, err := discover(fsys, desc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Node != "hidraw9" {
		t.Fatalf("found %v, want only hidraw9", got)
	}
}

func TestDiscoverSkipsWhatItCannotUse(t *testing.T) {
	fsys := sysfs(map[string]string{
		"hidraw0": "no HID_ID here\n",
		"hidraw1": yubikeyUevent,
	})
	// A directory that is not a hidraw node at all, and a node with no uevent.
	fsys["class/hidraw/README"] = &fstest.MapFile{Data: []byte("x")}
	fsys["class/hidraw/hidraw7/other"] = &fstest.MapFile{Data: []byte("x")}
	got, err := discover(fsys, func(string) ([]byte, error) { return fidoDescriptor, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Node != "hidraw1" {
		t.Fatalf("found %v", got)
	}
}

// TestNoHidrawClassIsNotAnError: a kernel without the driver, or a machine
// with no HID device, has not failed. It has no keys.
func TestNoHidrawClassIsNotAnError(t *testing.T) {
	got, err := discover(fstest.MapFS{}, func(string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatalf("an empty /sys was an error: %v", err)
	}
	if got != nil {
		t.Errorf("found %v in an empty /sys", got)
	}
}

// TestTheOrderIsStable. "The first key" must mean the same device twice in a
// row, and directory order does not promise that.
func TestTheOrderIsStable(t *testing.T) {
	fsys := sysfs(map[string]string{
		"hidraw12": yubikeyUevent,
		"hidraw2":  yubikeyUevent,
		"hidraw10": yubikeyUevent,
	})
	desc := func(string) ([]byte, error) { return fidoDescriptor, nil }
	first, err := discover(fsys, desc)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := discover(fsys, desc)
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("two scans disagreed:\n%v\n%v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("found %d, want 3", len(first))
	}
}

func TestDeviceStringWithoutAName(t *testing.T) {
	d := Device{Path: "/dev/hidraw3", VendorID: 0x1050, ProductID: 0x0402}
	if got := d.String(); got != "1050:0402 at /dev/hidraw3" {
		t.Errorf("String() = %q", got)
	}
}

// TestPermissionIsNotAbsence. The two are told apart because they send a
// person to different places: a cable, or a udev rule.
func TestPermissionIsNotAbsence(t *testing.T) {
	if errors.Is(ErrPermission, ErrNoKey) || errors.Is(ErrNoKey, ErrPermission) {
		t.Fatal("the two errors are interchangeable")
	}
	if !strings.Contains(ErrPermission.Error(), "udev") {
		t.Error("the permission error does not say what to do about it")
	}
}
