// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package fido

import (
	"context"
	"errors"

	authn "github.com/go-authn/fido"
)

// ErrUnsupported is what this package reports off Linux.
//
// The protocol is portable and lives in github.com/go-authn/fido; only the
// hidraw transport is here. macOS has its own, go-macos/fido.
var ErrUnsupported = errors.New("fido: only Linux is implemented here; see go-authn/fido for the protocol")

// Devices lists nothing off Linux.
func Devices() ([]Device, error) { return nil, ErrUnsupported }

// Transport is unavailable off Linux.
func Transport() (authn.Transport, error) { return nil, ErrUnsupported }

// OpenDevice is unavailable off Linux.
func OpenDevice(Device) (authn.Transport, error) { return nil, ErrUnsupported }

// Open is unavailable off Linux.
func Open(context.Context) (*authn.Key, error) { return nil, ErrUnsupported }
