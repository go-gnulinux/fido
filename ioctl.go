// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

// The Linux ioctl request encoding, as arithmetic rather than as hexadecimal
// literals copied per architecture.
//
// A request packs a direction, a size, a type and a number into 32 bits. The
// generic layout is in include/uapi/asm-generic/ioctl.h -- but that file wraps
// _IOC_SIZEBITS in "#ifndef", and THREE architectures override it:
//
//	powerpc, mips, alpha:  _IOC_SIZEBITS 13, _IOC_DIRBITS 3
//	everything else:       _IOC_SIZEBITS 14, _IOC_DIRBITS 2
//
// ⛔ That moves the direction field by one bit, so a request built with the
// generic numbers is simply WRONG on ppc64/ppc64le/mips*. The kernel answers
// such a request with ENOTTY, which this package would have reported as "not a
// security key" -- a device found, filtered out, and never mentioned again.
//
// Cross-compiling all nine architectures does NOT catch this: the arithmetic
// compiles perfectly and produces the wrong number. Only reading the
// architecture's own header does. See [iocSizeBits], which is build-tagged.
const (
	iocNRShift   = 0
	iocTypeShift = 8  // after 8 bits of number
	iocSizeShift = 16 // after 8 more bits of type

	// iocRead is the direction of a request that reads from the kernel. It is
	// 2 on every architecture Go targets -- but not everywhere: parisc swaps
	// read and write. Go does not target it; the note is here so that adding
	// an architecture means checking, not assuming.
	iocRead = 2
)

// ior builds _IOR(typ, nr, size) for an architecture whose size field is
// sizeBits wide.
func ior(typ, nr, size, sizeBits uint32) uint {
	dirShift := uint32(iocSizeShift) + sizeBits
	return uint(uint32(iocRead)<<dirShift |
		size<<iocSizeShift |
		typ<<iocTypeShift |
		nr<<iocNRShift)
}
