// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && (ppc64 || ppc64le || mips || mipsle || mips64 || mips64le)

package fido

// iocSizeBits is narrower on these architectures, from
// arch/powerpc/include/uapi/asm/ioctl.h and arch/mips/include/uapi/asm/ioctl.h,
// which define _IOC_SIZEBITS 13 and _IOC_DIRBITS 3. One bit narrower here moves
// the direction field one bit down, so the whole request number differs.
const iocSizeBits = 13
