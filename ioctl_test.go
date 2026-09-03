// Copyright (c) the go-linux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import "testing"

// TestTheIoctlNumbersMatchTheKernelHeaders pins both encodings.
//
// The expected values are computed by hand from the kernel's own macros:
//
//	HIDIOCGRDESCSIZE = _IOR('H', 0x01, int)                          size 4
//	HIDIOCGRDESC     = _IOR('H', 0x02, hidraw_report_descriptor)     size 4100
//
// with _IOC(dir,type,nr,size) = dir<<DIRSHIFT | size<<16 | type<<8 | nr,
// _IOC_READ = 2, and DIRSHIFT = 16 + _IOC_SIZEBITS.
//
// ⛔ Both rows matter. The generic one is what every architecture uses EXCEPT
// powerpc and mips, which narrow the size field to 13 bits and so shift the
// direction down one. A single-row version of this test would pass on the
// machine it was written on and be wrong on ppc64le -- where the kernel answers
// ENOTTY and this package would have called a real key "not a security key".
func TestTheIoctlNumbersMatchTheKernelHeaders(t *testing.T) {
	const (
		descriptorStructSize = 4 + descriptorMaxForTest // __u32 size + __u8 value[4096]
		intSize              = 4
	)
	for _, c := range []struct {
		arches            string
		sizeBits          uint32
		wantSize, wantDsc uint
	}{
		{"amd64 arm64 arm 386 riscv64 s390x loong64", 14, 0x80044801, 0x90044802},
		{"ppc64 ppc64le mips mipsle mips64 mips64le", 13, 0x40044801, 0x50044802},
	} {
		t.Run(c.arches, func(t *testing.T) {
			if got := ior('H', 0x01, intSize, c.sizeBits); got != c.wantSize {
				t.Errorf("HIDIOCGRDESCSIZE = %#x, want %#x", got, c.wantSize)
			}
			if got := ior('H', 0x02, descriptorStructSize, c.sizeBits); got != c.wantDsc {
				t.Errorf("HIDIOCGRDESC = %#x, want %#x", got, c.wantDsc)
			}
		})
	}
}

// descriptorMaxForTest repeats HID_MAX_DESCRIPTOR_SIZE, because descriptorMax
// itself is compiled only on Linux and this test runs everywhere.
const descriptorMaxForTest = 4096

// TestTheSizeFieldIsWideEnough. 4100 needs 13 bits; the narrow encoding gives
// exactly 13. One more byte in the struct and the size would silently wrap into
// the direction field.
func TestTheSizeFieldIsWideEnough(t *testing.T) {
	const size = 4 + descriptorMaxForTest
	if size >= 1<<13 {
		t.Fatalf("a %d-byte struct does not fit the 13-bit size field", size)
	}
}
