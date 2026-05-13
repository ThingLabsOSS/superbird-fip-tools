//go:build !cgo

// amlboot_stub.go — no-USB stand-ins for the CGO_ENABLED=0 build.
//
// The USB transport (amlboot.go) needs cgo + libusb via gousb. Only `ramboot`
// and live `flash` use it; the build-host path (`sign`, `flash --dry-run`,
// `decrypt`) is pure Go. Building with CGO_ENABLED=0 drops gousb entirely —
// no libusb, no external modules, a small static binary ideal for embedding in
// a build pipeline (e.g. signing u-boot in a Yocto recipe). These stubs keep
// ramboot.go and flash.go compiling; invoking a USB path in such a build fails
// loudly rather than silently doing nothing.

package main

import "errors"

// addrBL2 is where BL2 is loaded and executed (fixed by the SoC ROM). Mirrors
// the cgo build's value so ramboot.go compiles either way.
const addrBL2 uint32 = 0xfffa0000

var errNoUSB = errors.New("this fip-tool was built without USB support (CGO_ENABLED=0); rebuild with cgo (libusb) for ramboot / flash-to-device")

// Device matches the cgo build's transport handle (incl. the verbose field
// ramboot.go reads). Every method errors; nothing is ever opened.
type Device struct {
	verbose bool
}

func Open(vid, pid uint16, verbose bool) (*Device, error) { return nil, errNoUSB }

func (d *Device) Close()                   {}
func (d *Device) Product() (string, error) { return "", errNoUSB }
func (d *Device) Run(address uint32) error { return errNoUSB }

func (d *Device) BulkCmd(command string) (string, error) { return "", errNoUSB }

func (d *Device) WriteLargeMemory(address uint32, data []byte, blockLength int, appendZeros bool) error {
	return errNoUSB
}

func (d *Device) GetBootAMLC() (length, offset uint32, err error) { return 0, 0, errNoUSB }

func (d *Device) WriteAMLCData(seq uint8, amlcOffset uint32, data []byte) error { return errNoUSB }
