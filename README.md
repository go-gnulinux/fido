# fido

[![Go Reference](https://pkg.go.dev/badge/github.com/go-gnulinux/fido.svg)](https://pkg.go.dev/github.com/go-gnulinux/fido)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-gnulinux/fido/actions/workflows/ci.yml/badge.svg)](https://github.com/go-gnulinux/fido/actions/workflows/ci.yml)

Reaches a FIDO security key on Linux, over `hidraw`, in pure Go with
`CGO_ENABLED=0`.

```go
k, err := fido.Open(ctx)   // finds the key, speaks the CTAPHID handshake
defer k.Close()
fmt.Println(k)             // YubiKey FIDO (CTAPHID v2, firmware 5.7.4, wink, ctap2, ctap1)
```

This is a transport and nothing else. The protocol —
CTAPHID, CTAP2, ClientPIN, credentials — lives in
[go-authn/fido](https://github.com/go-authn/fido) and knows about no operating
system at all. The macOS twin is [go-macos/fido](https://github.com/go-macos/fido).

## No libudev, and therefore no cgo

The reference implementation enumerates with `libudev`, which is C. It does not
have to: udev is used only to *list* the hidraw nodes, and `/sys/class/hidraw`
already lists them. Everything else libfido2 wants, it parses by hand out of the
sysfs `uevent` file — `HID_ID=bus:vendor:product`, `HID_NAME=` — so this package
reads the same text and stays pure Go.

The FIDO test is the same on every platform: usage page **`0xF1D0`**, read from
the report descriptor through `HIDIOCGRDESCSIZE` and `HIDIOCGRDESC`.

## The ioctl number is not the same on every architecture

That is not a detail this package inherited; it is one it nearly got wrong.
`asm-generic/ioctl.h` wraps `_IOC_SIZEBITS` in an `#ifndef`, and **powerpc and
mips override it** — 13 bits instead of 14, which moves the direction field down
one bit and changes every request number:

| | `HIDIOCGRDESCSIZE` | `HIDIOCGRDESC` |
|---|---|---|
| generic | `0x80044801` | `0x90044802` |
| ppc64, ppc64le, mips* | `0x40044801` | `0x50044802` |

The kernel answers a wrong request with `ENOTTY`, which this package would have
reported as *not a security key* — a real key found, filtered out, and never
mentioned. **Cross-compiling all eleven architectures does not catch it**: the
arithmetic compiles perfectly and produces the wrong number. Reading the
architectures own header does. Both encodings are pinned by a test, and the
width is build-tagged.

## The trap that does not exist on macOS

**A hidraw write carries one byte more than the report. A read does not.**

Linux expects a leading report-id byte on the way out — zero, for CTAPHID — and
returns the report without it. On macOS the report id is a separate argument to
IOKit, so a transport ported across without noticing sends every report shifted
by one byte. A key answers that with **silence**, not with an error.

## What it refuses to confuse

- **A key you may not open is not an absent key.** `/dev/hidraw*` is root-only
  on a stock system; libfido2 ships `udev/70-u2f.rules` to change that.
  `ErrPermission` is separate from `ErrNoKey` and names the rule, because the
  two send a person to different places — a cable, or a file in `/etc/udev`.
- **One unreadable node does not hide the next.** A machine can hold a hidraw
  node this user may not touch beside the key they may. Abandoning the scan at
  the first refusal would report no key at all.
- **A report length read from a device does not size an allocation.** A
  descriptor item is four bytes wide, so a report count of `0x80000000` is a
  two-gigabyte `make()` away from whoever plugged something in. The value is
  bounded. A test caught this: the first version only checked it was positive.
- **A FIDO collection behind another one is still found.** libfido2 overwrites a
  single variable as it walks, so it judges by the *last* usage page it saw;
  this asks whether *any* is `0xF1D0`, which cannot lose a device and gives the
  same answer on the single-collection descriptors real keys emit.
- **A blocking read is not used.** A blocking `read` on hidraw parks a goroutine
  in the kernel until somebody touches the key, and neither a cancelled context
  nor `Close` gets it back. The descriptor is opened `O_NONBLOCK` and polled, so
  cancellation stays in this package's hands.

## What is proven, and what is not

**Proven.** The report-descriptor parser is checked against **17 real
descriptors read off a live machine's HID devices**, with IOKit's own
`PrimaryUsagePage` as the answer — bytes this project did not write and a
verdict it did not compute. One- and two-byte item widths both appear in them,
so an item mis-sized by one byte shifts every page and fails the comparison.
None of those 17 devices is a security key, which is the negative control: a
filter that said yes to everything would pass the first test and be useless.

Everything that runs without a key is covered to 100%, and the gate says so
where that is the whole compiled set.

**Not proven.** `hidraw_linux.go` — the ioctls, the poll loop, the read and the
write — **has never run against a key**, because the machine this was written on
is a Mac and no key was attached when the fixtures were made. The FIDO
descriptor in the tests is written from the specification, not captured, and it
is labelled as such. Cross-compiling eleven architectures proves the sizes and the syscall shapes
agree. The ioctl numbers are pinned against the kernel headers by a test, for
both encodings; what remains unproven is that a real kernel accepts them.

That is the honest state. It wants one run on a Linux machine with a key in it.
