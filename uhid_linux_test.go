// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package fido

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	authn "github.com/go-authn/fido"
	"golang.org/x/sys/unix"
)

// The uhid protocol, from include/uapi/linux/uhid.h.
//
// Every structure there is __packed, so the bytes are laid out by hand rather
// than through a Go struct: Go has no packed layout, and a mismatch would look
// like the kernel misbehaving rather than like a test bug.
const (
	uhidDestroy = 1
	uhidStart   = 2
	uhidStop    = 3
	uhidOpen    = 4
	uhidClose   = 5
	uhidOutput  = 6
	uhidCreate2 = 11
	uhidInput2  = 12

	uhidDataMax = 4096
	// create2_req: name[128] phys[64] uniq[64] rd_size(2) bus(2) vendor(4)
	// product(4) version(4) country(4) rd_data[4096]
	uhidCreate2Size = 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + uhidDataMax
	// uhid_event: type(4) followed by the largest union member.
	uhidEventSize = 4 + uhidCreate2Size

	uhidBusUSB = 0x03
)

// testDeviceName is distinctive on purpose: a developer running this with a
// REAL key plugged in must not have their key talked to, so the device is
// found by name rather than by being first.
const testDeviceName = "go-gnulinux fido test device"

func uhidCreateEvent(name string, vendor, product uint32, rd []byte) []byte {
	ev := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(ev[0:4], uhidCreate2)
	b := ev[4:]
	copy(b[0:128], name)
	off := 128 + 64 + 64
	binary.LittleEndian.PutUint16(b[off:off+2], uint16(len(rd)))
	binary.LittleEndian.PutUint16(b[off+2:off+4], uhidBusUSB)
	binary.LittleEndian.PutUint32(b[off+4:off+8], vendor)
	binary.LittleEndian.PutUint32(b[off+8:off+12], product)
	binary.LittleEndian.PutUint32(b[off+12:off+16], 1)
	copy(b[off+20:], rd)
	return ev
}

func uhidInputEvent(report []byte) []byte {
	ev := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(ev[0:4], uhidInput2)
	binary.LittleEndian.PutUint16(ev[4:6], uint16(len(report)))
	copy(ev[6:], report)
	return ev
}

// uhidOutputPayload reads an OUTPUT event: data[4096], THEN size(2), then
// rtype(1) -- the length comes after the data in this one, unlike input2.
func uhidOutputPayload(ev []byte) []byte {
	b := ev[4:]
	n := binary.LittleEndian.Uint16(b[uhidDataMax : uhidDataMax+2])
	if int(n) == 0 || int(n) > uhidDataMax {
		return nil
	}
	return append([]byte(nil), b[:n]...)
}

// TestAgainstAKernelMadeDevice is the only test here that exercises the wire.
//
// /dev/uhid is the kernel's userspace HID transport: hand it a report
// descriptor and it makes a real hidraw node, indistinguishable from a plugged
// device to everything above it. So this covers what no fake can -- the sysfs
// walk against a real /sys, the ioctl NUMBERS on this architecture, the
// usage-page filter, the report-id byte, the poll loop -- with no security key
// and nobody to touch one.
//
// It skips where /dev/uhid cannot be opened, which is most machines: the module
// is not always built, and it needs root. A skip is honest; passing by not
// looking would not be.
func TestAgainstAKernelMadeDevice(t *testing.T) {
	fd, err := unix.Open("/dev/uhid", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/uhid here (%v): this test needs the uhid module and root", err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	if _, err := unix.Write(fd, uhidCreateEvent(testDeviceName, 0x1050, 0x0402, fidoDescriptor)); err != nil {
		t.Fatalf("UHID_CREATE2: %v", err)
	}
	t.Cleanup(func() {
		ev := make([]byte, uhidEventSize)
		binary.LittleEndian.PutUint32(ev[0:4], uhidDestroy)
		_, _ = unix.Write(fd, ev)
	})

	reports := make(chan int, 4)
	go fakeAuthenticator(fd, reports)

	// The kernel makes the node asynchronously.
	var dev Device
	deadline := time.Now().Add(5 * time.Second)
	for dev.Path == "" && time.Now().Before(deadline) {
		devs, err := Devices()
		if err != nil {
			t.Fatalf("Devices: %v", err)
		}
		for _, d := range devs {
			if d.Name == testDeviceName {
				dev = d
			}
		}
		if dev.Path == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if dev.Path == "" {
		t.Fatal("the device was created but not found: the sysfs walk, the ioctls or the usage-page filter did not work")
	}
	if dev.VendorID != 0x1050 || dev.ProductID != 0x0402 || dev.Bus != uhidBusUSB {
		t.Errorf("found %+v, which does not match what was created", dev)
	}
	t.Logf("found %s", dev)

	tr, err := OpenDevice(dev)
	if err != nil {
		t.Fatalf("OpenDevice: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	k, err := authn.Open(ctx, tr)
	if err != nil {
		_ = tr.Close()
		t.Fatalf("the CTAPHID handshake: %v", err)
	}
	defer k.Close()
	t.Logf("handshake: %s", k)

	// ⭐ MEASURED: the report reaches the device as 65 bytes whose first is the
	// report id. hidraw's write() ABI is [report id][payload] and that is what
	// Send writes; what differs is who strips it. usbhid drops the id before
	// the wire, so a real key sees 64 -- uhid is a raw transport and passes
	// down what the HID core held, id included. The fake strips it to behave
	// like a key, and asserts the byte was the id rather than data.
	select {
	case n := <-reports:
		if n != ReportSize {
			t.Fatalf("the device was handed %d bytes per report, want %d", n, ReportSize)
		}
	default:
		t.Fatal("the device saw nothing, yet the handshake succeeded")
	}

	sent := []byte("a round trip through the kernel")
	got, err := k.Ping(ctx, sent)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if string(got) != string(sent) {
		t.Fatalf("the ping came back as %q", got)
	}

	// Closing while a Receive is in flight is the use-after-free shape that
	// bit the macOS transport: the descriptor must not be closed under a
	// syscall already using it.
	done := make(chan error, 1)
	go func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer rcancel()
		_, err := tr.(interface {
			Receive(context.Context) ([]byte, error)
		}).Receive(rctx)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if err := k.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := <-done; err == nil {
		t.Error("a Receive in flight returned successfully after Close")
	} else if !errors.Is(err, os.ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("the in-flight Receive ended with %v", err)
	}
}

// fakeAuthenticator answers CTAPHID over uhid.
func fakeAuthenticator(fd int, reports chan<- int) {
	const channel = 0x0A0B0C0D
	bcast := authn.NewReassembler(authn.BroadcastChannel)
	own := authn.NewReassembler(channel)
	told := false

	buf := make([]byte, uhidEventSize)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil || n < 4 {
			return
		}
		if binary.LittleEndian.Uint32(buf[0:4]) != uhidOutput {
			continue
		}
		report := uhidOutputPayload(buf[:n])
		if len(report) == ReportSize+1 && report[0] == 0 {
			report = report[1:]
		}
		if len(report) != ReportSize {
			continue
		}
		if !told {
			reports <- len(report)
			told = true
		}
		var msg authn.Message
		var done bool
		if binary.BigEndian.Uint32(report[0:4]) == authn.BroadcastChannel {
			msg, done, _ = bcast.Feed(report)
		} else {
			msg, done, _ = own.Feed(report)
		}
		if !done {
			continue
		}
		var pkts [][]byte
		switch msg.Cmd {
		case authn.CmdInit:
			payload := make([]byte, 17)
			copy(payload, msg.Data)
			binary.BigEndian.PutUint32(payload[8:12], channel)
			payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
			payload[16] = byte(authn.CapCBOR | authn.CapWink)
			pkts, _ = authn.Split(authn.BroadcastChannel, authn.CmdInit, payload)
		case authn.CmdPing:
			pkts, _ = authn.Split(channel, authn.CmdPing, msg.Data)
		default:
			continue
		}
		for _, p := range pkts {
			if _, err := unix.Write(fd, uhidInputEvent(p)); err != nil {
				return
			}
		}
	}
}
