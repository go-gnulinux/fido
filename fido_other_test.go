// Copyright (c) the go-linux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package fido

import (
	"context"
	"errors"
	"testing"
)

// TestOffLinuxEverythingSaysSoAndNamesTheAlternative. A caller on macOS is not
// told "no key"; they are told this is the wrong package, and which one is
// right. Reporting absence here would send somebody to check a cable.
func TestOffLinuxEverythingSaysSo(t *testing.T) {
	if _, err := Devices(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Devices = %v", err)
	}
	if _, err := Transport(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Transport = %v", err)
	}
	if _, err := OpenDevice(Device{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("OpenDevice = %v", err)
	}
	if _, err := Open(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Open = %v", err)
	}
	if errors.Is(ErrUnsupported, ErrNoKey) {
		t.Error("the wrong operating system reads as an absent key")
	}
}
