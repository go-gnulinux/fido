// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package fido

import (
	"testing"
	"unsafe"
)

// TestTheStructMatchesTheKernels. The ioctl number CARRIES the size, so a Go
// struct that does not match struct hidraw_report_descriptor byte for byte
// produces a request the kernel does not recognise -- not a short read, an
// ENOTTY. The number and the memory have to agree, and this checks the half
// the arithmetic cannot.
func TestTheStructMatchesTheKernels(t *testing.T) {
	if got := unsafe.Sizeof(rawDescriptor{}); got != 4+descriptorMax {
		t.Errorf("rawDescriptor is %d bytes, the kernel's is %d", got, 4+descriptorMax)
	}
	var size int32
	if got := unsafe.Sizeof(size); got != 4 {
		t.Errorf("the size argument is %d bytes, the kernel's int is 4", got)
	}
}
