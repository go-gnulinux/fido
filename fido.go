// Copyright (c) the go-linux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package fido reaches a FIDO security key on Linux, over hidraw, in pure Go
// with CGO_ENABLED=0.
//
// It is a transport and nothing else. The protocol — CTAPHID, CTAP2,
// ClientPIN, credentials — lives in github.com/go-authn/fido, which knows
// nothing about any operating system. What is here is the part that cannot be
// portable: finding the device and moving 64-byte reports.
//
//	k, err := fido.Open(ctx)   // finds the key, speaks the handshake
//	defer k.Close()
//	fmt.Println(k)             // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, ...)
//
// # No libudev
//
// The reference implementation enumerates with libudev, which is a C library
// and would cost cgo. It does not have to: libudev is used only to LIST the
// hidraw nodes, and /sys/class/hidraw already lists them. Everything else
// libfido2 reads, it reads out of the sysfs "uevent" file by hand — so this
// package does the same, and stays pure Go.
//
// # The permission is the obstacle, not the API
//
// /dev/hidraw* belongs to root on a stock system. libfido2 ships a udev rule
// (70-u2f.rules) that hands the console user access to known keys. Without it
// a plugged-in key is found and then refuses to open, so [ErrPermission] says
// exactly that rather than letting it look like an absent key.
package fido

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// ReportSize is the CTAPHID report size, which every FIDO device uses.
const ReportSize = 64

// maxReportLen bounds a report size read out of a device descriptor. CTAPHID
// uses 64 and nothing else; this leaves room to be wrong without letting a
// device choose the size of an allocation.
const maxReportLen = 1024

// UsagePageFIDO is the HID usage page that marks a device as speaking CTAP.
// It is the same number on every operating system; it is how a security key
// is told apart from a keyboard on the same bus.
const UsagePageFIDO = 0xF1D0

var (
	// ErrNoKey is returned when nothing on this machine speaks CTAP.
	ErrNoKey = errors.New("fido: no security key is attached")

	// ErrPermission is returned when a key was FOUND and could not be opened.
	//
	// It is deliberately distinct from ErrNoKey. On a stock system
	// /dev/hidraw* is root-only, and a caller that reported "no key" here
	// would send a person to check a cable when the answer is a udev rule.
	ErrPermission = errors.New("fido: a security key is attached but this user cannot open it; " +
		"install a udev rule for /dev/hidraw* (see libfido2's udev/70-u2f.rules)")
)

// Device is one hidraw node that speaks CTAP.
type Device struct {
	// Path is the node to open, e.g. "/dev/hidraw3".
	Path string
	// Node is the sysfs name, e.g. "hidraw3".
	Node string
	// Bus is the HID bus number from HID_ID (3 is USB, 5 is Bluetooth).
	Bus uint16
	// VendorID and ProductID identify the model.
	VendorID, ProductID uint16
	// Name is what the device calls itself, for a person to read.
	Name string
}

// String names the device the way an error message should.
func (d Device) String() string {
	if d.Name == "" {
		return fmt.Sprintf("%04x:%04x at %s", d.VendorID, d.ProductID, d.Path)
	}
	return fmt.Sprintf("%s (%04x:%04x) at %s", d.Name, d.VendorID, d.ProductID, d.Path)
}

// descriptorFunc reads a device's HID report descriptor. It is a parameter
// rather than a call so that discovery — the walking, the parsing, the
// filtering — is testable on any machine, with no /sys and no key.
type descriptorFunc func(node string) ([]byte, error)

// discover lists the CTAP-speaking devices under a sysfs tree.
//
// fsys is rooted at /sys. Nodes whose descriptor cannot be read are SKIPPED
// rather than failing the whole scan: a machine may hold a hidraw node this
// user cannot touch alongside the key they can, and refusing to look at the
// second because of the first would be a worse answer than a short list.
func discover(fsys fs.FS, desc descriptorFunc) ([]Device, error) {
	entries, err := fs.ReadDir(fsys, "class/hidraw")
	if err != nil {
		// No hidraw class at all is not a broken machine; it is a machine
		// with no HID devices, or a kernel without the driver.
		return nil, nil
	}
	var found []Device
	for _, e := range entries {
		node := e.Name()
		if !strings.HasPrefix(node, "hidraw") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join("class/hidraw", node, "device/uevent"))
		if err != nil {
			continue
		}
		d, err := parseUevent(string(b))
		if err != nil {
			continue
		}
		d.Node = node
		d.Path = "/dev/" + node
		rd, err := desc(d.Path)
		if err != nil {
			continue
		}
		if !speaksCTAP(rd) {
			continue
		}
		found = append(found, d)
	}
	// A stable order, because "the first key" must mean the same thing twice
	// in a row. Directory order does not promise that.
	sort.Slice(found, func(i, j int) bool { return found[i].Node < found[j].Node })
	return found, nil
}

// parseUevent reads the sysfs uevent file of a HID device.
//
// The interesting lines are HID_ID=bus:vendor:product, in hexadecimal and
// zero-padded to eight digits each, and HID_NAME. This is what libfido2 parses
// too, once udev has handed it the same text.
func parseUevent(s string) (Device, error) {
	var d Device
	var gotID bool
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "HID_ID="):
			f := strings.Split(strings.TrimPrefix(line, "HID_ID="), ":")
			if len(f) != 3 {
				continue
			}
			bus, err1 := strconv.ParseUint(strings.TrimSpace(f[0]), 16, 16)
			vid, err2 := strconv.ParseUint(strings.TrimSpace(f[1]), 16, 16)
			pid, err3 := strconv.ParseUint(strings.TrimSpace(f[2]), 16, 16)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			d.Bus, d.VendorID, d.ProductID = uint16(bus), uint16(vid), uint16(pid)
			gotID = true
		case strings.HasPrefix(line, "HID_NAME="):
			d.Name = strings.TrimSpace(strings.TrimPrefix(line, "HID_NAME="))
		}
	}
	if !gotID {
		return Device{}, fmt.Errorf("fido: uevent has no usable HID_ID")
	}
	return d, nil
}

// speaksCTAP reports whether a report descriptor declares the FIDO usage page.
//
// It differs from libfido2 in one way, on purpose. libfido2 keeps overwriting
// a single variable as it walks, so the LAST usage page in the descriptor is
// the one it judges by; a descriptor with several top-level collections could
// therefore hide a FIDO one behind whatever follows it. Asking whether ANY of
// them is 0xF1D0 cannot lose a device, and on the single-collection
// descriptors every real key emits the two answers are identical.
func speaksCTAP(descriptor []byte) bool {
	for _, p := range usagePages(descriptor) {
		if p == UsagePageFIDO {
			return true
		}
	}
	return false
}

// usagePages returns every usage page declared in a HID report descriptor.
//
// A short item is a one-byte tag followed by 0, 1, 2 or 4 bytes of value; the
// tag's low two bits give that length, with 3 meaning four bytes. Usage Page
// is the key 0x04.
//
// A malformed descriptor yields what was read before the damage rather than an
// error: this is used to decide "is this a security key", and the answer to
// that question for a device whose descriptor is nonsense is no.
func usagePages(d []byte) []uint16 {
	var pages []uint16
	for len(d) > 0 {
		tag := d[0]
		d = d[1:]
		// 0xFx is a long item, whose length lives in the next byte. No FIDO
		// device emits one, and misreading it would desynchronise the walk,
		// so the walk stops rather than guessing -- which is what libfido2
		// does too.
		if tag&0xF0 == 0xF0 {
			return pages
		}
		n := int(tag & 0x03)
		if n == 3 {
			n = 4
		}
		if n > len(d) {
			return pages
		}
		if tag&0xFC == 0x04 { // Usage Page
			var v uint32
			for i := 0; i < n; i++ {
				v |= uint32(d[i]) << (8 * i)
			}
			// A usage page is 16 bits. A four-byte item that does not fit is
			// not a page this cares about, and truncating it would invent one.
			if v <= 0xFFFF {
				pages = append(pages, uint16(v))
			}
		}
		d = d[n:]
	}
	return pages
}

// reportLengths returns the input and output report sizes a descriptor
// declares, and whether both were found.
//
// The keys are Report Count (0x94), Input (0x80) and Output (0x90): the count
// most recently seen is the size of the report the next Input or Output
// declares. Every FIDO device declares 64 and 64, but reading it rather than
// assuming it is what tells [transport] how many bytes a write must carry --
// and on Linux a write carries one MORE than that. See hidraw_linux.go.
func reportLengths(d []byte) (in, out int, ok bool) {
	var count uint32
	var haveIn, haveOut bool
	for len(d) > 0 {
		tag := d[0]
		d = d[1:]
		if tag&0xF0 == 0xF0 {
			break
		}
		n := int(tag & 0x03)
		if n == 3 {
			n = 4
		}
		if n > len(d) {
			break
		}
		var v uint32
		for i := 0; i < n; i++ {
			v |= uint32(d[i]) << (8 * i)
		}
		switch tag & 0xFC {
		case 0x94: // Report Count
			count = v
		case 0x80: // Input
			in, haveIn = int(count), true
		case 0x90: // Output
			out, haveOut = int(count), true
		}
		d = d[n:]
	}
	if !haveIn || !haveOut || in <= 0 || out <= 0 || in > maxReportLen || out > maxReportLen {
		return 0, 0, false
	}
	return in, out, true
}
