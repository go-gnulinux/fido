// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package fido

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	authn "github.com/go-authn/fido"
	"golang.org/x/sys/unix"
)

// descriptorMax is HID_MAX_DESCRIPTOR_SIZE: the value[] field of struct
// hidraw_report_descriptor, from include/uapi/linux/hidraw.h.
const descriptorMax = 4096

// rawDescriptor mirrors struct hidraw_report_descriptor.
type rawDescriptor struct {
	size  uint32
	value [descriptorMax]byte
}

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// readDescriptor asks the kernel for a device's HID report descriptor.
//
// It opens the node read-only. A device that this user may not touch fails
// HERE, during discovery, which is why discovery skips it rather than
// abandoning the scan: the key one CAN open may be the next node along.
func readDescriptor(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	var size int32
	if err := ioctl(fd, ior('H', 0x01, uint32(unsafe.Sizeof(size)), iocSizeBits), unsafe.Pointer(&size)); err != nil {
		return nil, fmt.Errorf("fido: HIDIOCGRDESCSIZE on %s: %w", path, err)
	}
	if size <= 0 || size > descriptorMax {
		return nil, fmt.Errorf("fido: %s declares a %d-byte report descriptor", path, size)
	}
	var raw rawDescriptor
	raw.size = uint32(size)
	if err := ioctl(fd, ior('H', 0x02, uint32(unsafe.Sizeof(raw)), iocSizeBits), unsafe.Pointer(&raw)); err != nil {
		return nil, fmt.Errorf("fido: HIDIOCGRDESC on %s: %w", path, err)
	}
	return append([]byte(nil), raw.value[:size]...), nil
}

// Devices lists the security keys attached to this machine.
func Devices() ([]Device, error) {
	return discover(os.DirFS("/sys"), readDescriptor)
}

// transport moves CTAPHID reports over a hidraw node.
type transport struct {
	dev Device

	mu     sync.Mutex
	fd     int
	closed bool

	// out is what a write must carry, WITHOUT the report-id byte.
	out int
	// in is what a read returns.
	in int
}

// Transport opens the first attached security key.
//
// It is the seam github.com/go-authn/fido asks for: everything above this --
// the handshake, CTAP2, ClientPIN -- is portable and lives there.
func Transport() (authn.Transport, error) {
	devs, err := Devices()
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, ErrNoKey
	}
	return OpenDevice(devs[0])
}

// OpenDevice opens one particular key, for a machine with more than one.
func OpenDevice(d Device) (authn.Transport, error) {
	// O_NONBLOCK matters: a blocking read on hidraw parks a goroutine in the
	// kernel until a person touches the key, and nothing short of that gets it
	// back -- not a cancelled context, not Close. Polling a non-blocking
	// descriptor keeps cancellation in this package's hands.
	fd, err := unix.Open(d.Path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("%w: %s", ErrPermission, d)
		}
		return nil, fmt.Errorf("fido: opening %s: %w", d, err)
	}
	t := &transport{dev: d, fd: fd, in: ReportSize, out: ReportSize}
	if rd, err := readDescriptor(d.Path); err == nil {
		if in, out, ok := reportLengths(rd); ok {
			t.in, t.out = in, out
		}
	}
	return t, nil
}

// Name is what the device calls itself.
func (t *transport) Name() string { return t.dev.String() }

// Send writes one report.
//
// ⚠ The write carries ONE MORE byte than the report: hidraw expects a leading
// report-id, and CTAPHID's is zero. The read side does NOT carry it. That
// asymmetry is invisible on macOS, where IOKit takes the report id as a
// separate argument, and a transport ported across without noticing sends
// every report shifted by one byte -- which a key answers with silence rather
// than with an error.
func (t *transport) Send(report []byte) error {
	if len(report) != t.out {
		return fmt.Errorf("fido: report is %d bytes, %s takes %d", len(report), t.dev.Name, t.out)
	}
	buf := make([]byte, t.out+1)
	copy(buf[1:], report) // buf[0] is the report id, zero for CTAPHID.

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return os.ErrClosed
	}
	n, err := unix.Write(t.fd, buf)
	if err != nil {
		return fmt.Errorf("fido: writing to %s: %w", t.dev.Name, err)
	}
	if n != len(buf) {
		return fmt.Errorf("fido: wrote %d of %d bytes to %s", n, len(buf), t.dev.Name)
	}
	return nil
}

// pollSlice is how long one wait lasts before the context is looked at again.
//
// It bounds how long Close waits for a Receive in flight. It is not a timeout:
// Receive keeps waiting until the context says otherwise, because a person
// deciding whether to touch their key takes as long as they take.
const pollSlice = 100 // milliseconds

// Receive returns the next report, waiting until one arrives or ctx ends.
func (t *transport) Receive(ctx context.Context) ([]byte, error) {
	buf := make([]byte, t.in)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, os.ErrClosed
		}
		fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, pollSlice)
		if err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			var got int
			got, err = unix.Read(t.fd, buf)
			t.mu.Unlock()
			switch {
			case errors.Is(err, unix.EAGAIN):
				continue // poll said ready, the read disagreed: wait again.
			case err != nil:
				return nil, fmt.Errorf("fido: reading from %s: %w", t.dev.Name, err)
			case got != t.in:
				return nil, fmt.Errorf("fido: read %d bytes from %s, expected %d", got, t.dev.Name, t.in)
			}
			return append([]byte(nil), buf...), nil
		}
		hung := err == nil && n > 0 && fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0
		t.mu.Unlock()
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return nil, fmt.Errorf("fido: waiting on %s: %w", t.dev.Name, err)
		case hung:
			// The key was unplugged mid-exchange. Saying so beats waiting for
			// a context that will now run to its end.
			return nil, fmt.Errorf("fido: %s went away", t.dev.Name)
		}
	}
}

// Close releases the device.
//
// The lock is what makes this safe: a Receive in flight holds it across its
// poll and its read, so the descriptor cannot be closed under a syscall that
// is already using it. Closing an fd another goroutine is polling is not
// merely rude -- the number is reused, and the poll starts watching whatever
// opened next.
func (t *transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return unix.Close(t.fd)
}

// Open finds a key and speaks the CTAPHID handshake to it.
func Open(ctx context.Context) (*authn.Key, error) {
	t, err := Transport()
	if err != nil {
		return nil, err
	}
	k, err := authn.Open(ctx, t)
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	return k, nil
}
