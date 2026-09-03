// Copyright (c) the go-linux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ppc64 && !ppc64le && !mips && !mipsle && !mips64 && !mips64le

package fido

// iocSizeBits is the generic width, from include/uapi/asm-generic/ioctl.h.
const iocSizeBits = 14
