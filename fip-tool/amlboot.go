//go:build cgo

// amlboot.go — the subset of the Amlogic USB boot protocol needed to
// stream a signed FIP into DRAM via mask-ROM → BL2 → AMLC.
//
// USB transport requires cgo (libusb via gousb). The build-host signing path
// (sign / flash --dry-run / decrypt) is pure Go and needs none of this, so this
// file is gated behind `cgo`; amlboot_stub.go supplies error stubs for the
// CGO_ENABLED=0 build. See that file for the build-mode rationale.
//
// This is a faithful Go port of the five pyamlboot primitives that
// superbird-tool's bl2_boot()/--burn_mode path uses: writeLargeMemory,
// run, getBootAMLC, writeAMLCData, plus product-string detection. The
// wire format (vendor control transfers + bulk OUT/IN) matches
// pyamlboot exactly, so behaviour tracks the proven Python tool.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/google/gousb"
)

// Vendor control-transfer request codes (pyamlboot REQ_*).
const (
	reqRunInAddr  = 0x05
	reqWrLargeMem = 0x11
	reqBulkCmd    = 0x34
	reqGetAMLC    = 0x50
	reqWriteAMLC  = 0x60
)

const (
	flagKeepPowerOn = 0x10 // OR'd into the run address to keep power on

	amlcAMLSBlockLen   = 0x200  // AMLC/AMLS framing unit
	amlcMaxBlockLen    = 0x4000 // max bulk block per AMLC data write
	amlcMaxTransferLen = 65536  // max bytes per AMLC transfer chunk
	maxLargeBlockCount = 65535  // max blocks per writeLargeMemory transfer

	// bmRequestType: vendor request, host->device (out) / device->host (in).
	rtVendorOut = 0x40

	bulkTimeout = 8 * time.Second
)

// addrBL2 is where BL2 is loaded and executed. Fixed by the SoC ROM.
const addrBL2 uint32 = 0xfffa0000

// Device wraps an opened Amlogic SoC in USB boot mode plus its claimed
// bulk endpoints.
type Device struct {
	ctx     *gousb.Context
	dev     *gousb.Device
	cfg     *gousb.Config
	intf    *gousb.Interface
	epOut   *gousb.OutEndpoint
	epIn    *gousb.InEndpoint
	verbose bool
}

// Open finds and opens the device at vid:pid and claims its bulk
// interface. Returns a friendly error if the device isn't present.
func Open(vid, pid uint16, verbose bool) (*Device, error) {
	ctx := gousb.NewContext()
	dev, err := ctx.OpenDeviceWithVIDPID(gousb.ID(vid), gousb.ID(pid))
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("opening %04x:%04x: %w", vid, pid, err)
	}
	if dev == nil {
		ctx.Close()
		return nil, fmt.Errorf("device %04x:%04x not found — is it in mask-ROM USB mode? "+
			"(hold buttons 1+4, then reset)", vid, pid)
	}

	d := &Device{ctx: ctx, dev: dev, verbose: verbose}
	// Detach any kernel driver so we can claim the interface (Linux).
	_ = dev.SetAutoDetach(true)
	dev.ControlTimeout = 5 * time.Second

	if err := d.claim(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// claim selects the active configuration, claims interface 0, and finds
// the bulk OUT/IN endpoints (pyamlboot picks "the first OUT/IN").
func (d *Device) claim() error {
	num, err := d.dev.ActiveConfigNum()
	if err != nil {
		return fmt.Errorf("reading active config: %w", err)
	}
	if d.cfg, err = d.dev.Config(num); err != nil {
		return fmt.Errorf("selecting config %d: %w", num, err)
	}
	if d.intf, err = d.cfg.Interface(0, 0); err != nil {
		return fmt.Errorf("claiming interface 0: %w", err)
	}

	outNum, inNum := -1, -1
	for _, ep := range d.intf.Setting.Endpoints {
		if ep.TransferType != gousb.TransferTypeBulk {
			continue
		}
		if ep.Direction == gousb.EndpointDirectionOut {
			outNum = ep.Number
		} else {
			inNum = ep.Number
		}
	}
	if outNum < 0 || inNum < 0 {
		return fmt.Errorf("could not find bulk OUT/IN endpoints on interface 0")
	}
	if d.epOut, err = d.intf.OutEndpoint(outNum); err != nil {
		return fmt.Errorf("opening OUT endpoint %d: %w", outNum, err)
	}
	if d.epIn, err = d.intf.InEndpoint(inNum); err != nil {
		return fmt.Errorf("opening IN endpoint %d: %w", inNum, err)
	}
	return nil
}

// Product returns the USB product string ("GX-CHIP" = mask-ROM,
// "M8-CHIP" = already past BL2).
func (d *Device) Product() (string, error) { return d.dev.Product() }

// Close releases the interface, config, device and context.
func (d *Device) Close() {
	if d.intf != nil {
		d.intf.Close()
	}
	if d.cfg != nil {
		d.cfg.Close()
	}
	if d.dev != nil {
		d.dev.Close()
	}
	if d.ctx != nil {
		d.ctx.Close()
	}
}

func (d *Device) ctrlOut(req uint8, val, idx uint16, data []byte) error {
	_, err := d.dev.Control(rtVendorOut, req, val, idx, data)
	return err
}

func (d *Device) writeBulk(b []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), bulkTimeout)
	defer cancel()
	_, err := d.epOut.WriteContext(ctx, b)
	return err
}

func (d *Device) readBulk(n int) ([]byte, error) {
	buf := make([]byte, n)
	ctx, cancel := context.WithTimeout(context.Background(), bulkTimeout)
	defer cancel()
	got, err := d.epIn.ReadContext(ctx, buf)
	if err != nil {
		return nil, err
	}
	return buf[:got], nil
}

// Run executes code previously loaded at address. keep-power is always
// set, matching pyamlboot's run(keep_power=True).
func (d *Device) Run(address uint32) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, address|flagKeepPowerOn)
	return d.ctrlOut(reqRunInAddr, uint16(address>>16), uint16(address&0xffff), buf)
}

// BulkCmd sends a NUL-terminated u-boot console command to vendor burn-mode
// u-boot and returns the trimmed reply (used by `flash`). pyamlboot caps the
// command at 127 chars.
func (d *Device) BulkCmd(command string) (string, error) {
	if len(command)+1 >= 128 {
		return "", fmt.Errorf("bulk command too long (max 126 chars): %q", command)
	}
	if err := d.ctrlOut(reqBulkCmd, 0, 2, append([]byte(command), 0)); err != nil {
		return "", err
	}
	reply, err := d.readBulk(512)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(reply), " \x00"), nil
}

// WriteLargeMemory uploads data to address in blocks of blockLength,
// splitting into transfers of at most maxLargeBlockCount blocks each.
func (d *Device) WriteLargeMemory(address uint32, data []byte, blockLength int, appendZeros bool) error {
	blockCount := ceilDiv(len(data), blockLength)
	transferCount := ceilDiv(blockCount, maxLargeBlockCount)
	offset := 0
	for transferCount > 0 {
		writeLength := maxLargeBlockCount * blockLength
		if offset+writeLength > len(data) {
			writeLength = len(data) - offset
		}
		if err := d.writeLargeMemoryChunk(address+uint32(offset), data[offset:offset+writeLength], blockLength, appendZeros); err != nil {
			return err
		}
		offset += writeLength
		transferCount--
	}
	return nil
}

func (d *Device) writeLargeMemoryChunk(address uint32, data []byte, blockLength int, appendZeros bool) error {
	if appendZeros {
		// Matches pyamlboot's padding (a no-op when data is already a
		// multiple of blockLength, which the 64 KiB BL2 is).
		if pad := len(data) % blockLength; pad > 0 {
			padded := make([]byte, len(data)+pad)
			copy(padded, data)
			data = padded
		}
	} else if len(data)%blockLength != 0 {
		return fmt.Errorf("large data must be a multiple of block length %d", blockLength)
	}

	blockCount := ceilDiv(len(data), blockLength)
	ctrl := make([]byte, 16)
	binary.LittleEndian.PutUint32(ctrl[0:4], address)
	binary.LittleEndian.PutUint32(ctrl[4:8], uint32(len(data)))
	if err := d.ctrlOut(reqWrLargeMem, uint16(blockLength), uint16(blockCount), ctrl); err != nil {
		return err
	}
	for off := 0; off < len(data); off += blockLength {
		end := min(off+blockLength, len(data))
		if err := d.writeBulk(data[off:end]); err != nil {
			return err
		}
	}
	return nil
}

// GetBootAMLC issues an AMLC data request: BL2 tells us which slice of
// the image it wants next (length, offset). We ack with "OKAY".
func (d *Device) GetBootAMLC() (length, offset uint32, err error) {
	if err = d.ctrlOut(reqGetAMLC, amlcAMLSBlockLen, 0, nil); err != nil {
		return 0, 0, err
	}
	data, err := d.readBulk(amlcAMLSBlockLen)
	if err != nil {
		return 0, 0, err
	}
	if len(data) < 16 {
		return 0, 0, fmt.Errorf("short AMLC header: %d bytes", len(data))
	}
	if !strings.Contains(string(data[0:4]), "AMLC") {
		return 0, 0, fmt.Errorf("invalid AMLC request, tag=%q", data[0:4])
	}
	// layout: tag[0:4], rsvd[4:8], length[8:12], offset[12:16]
	length = binary.LittleEndian.Uint32(data[8:12])
	offset = binary.LittleEndian.Uint32(data[12:16])

	okay := make([]byte, 16)
	copy(okay, "OKAY")
	if err = d.writeBulk(okay); err != nil {
		return 0, 0, err
	}
	return length, offset, nil
}

// WriteAMLCData answers a GetBootAMLC request: stream the requested data
// blocks, then a trailing AMLS block carrying a checksum over the whole
// slice. amlcOffset is the offset BL2 asked for; data is that slice.
func (d *Device) WriteAMLCData(seq uint8, amlcOffset uint32, data []byte) error {
	offset := 0
	for offset < len(data) {
		writeLength := min(amlcMaxTransferLen, len(data)-offset)
		if err := d.writeAMLCChunk(uint32(offset), data[offset:offset+writeLength]); err != nil {
			return err
		}
		offset += writeLength
	}

	// AMLS trailer: 16-byte header (tag, seq, checksum) + bytes [16:512]
	// of the slice, exactly as pyamlboot builds it.
	amls := make([]byte, 16)
	copy(amls[0:4], "AMLS")
	amls[4] = seq
	binary.LittleEndian.PutUint32(amls[8:12], amlsChecksum(data))
	tail := data
	if len(tail) > 512 {
		tail = tail[:512]
	}
	if len(tail) > 16 {
		amls = append(amls, tail[16:]...)
	}
	return d.writeAMLCChunk(amlcOffset, amls)
}

func (d *Device) writeAMLCChunk(offset uint32, data []byte) error {
	if err := d.ctrlOut(reqWriteAMLC, uint16(offset/amlcAMLSBlockLen), uint16(len(data)-1), nil); err != nil {
		return err
	}
	for off := 0; off < len(data); off += amlcMaxBlockLen {
		end := min(off+amlcMaxBlockLen, len(data))
		if err := d.writeBulk(data[off:end]); err != nil {
			return err
		}
	}
	ack, err := d.readBulk(amlcAMLSBlockLen)
	if err != nil {
		return err
	}
	if !strings.Contains(string(ack), "OKAY") {
		return fmt.Errorf("missing OKAY ack for AMLC write (got %q)", ack)
	}
	return nil
}

// amlsChecksum sums the data as little-endian uint32 words (mod 2^32),
// matching pyamlboot's _amlsChecksum (tail bytes handled for safety).
func amlsChecksum(data []byte) uint32 {
	var sum uint32
	for off := 0; off < len(data); off += 4 {
		var val uint32
		switch left := len(data) - off; {
		case left >= 4:
			val = binary.LittleEndian.Uint32(data[off : off+4])
		case left == 3:
			val = uint32(data[off]) | uint32(data[off+1])<<8 | uint32(data[off+2])<<16
		case left == 2:
			val = uint32(binary.LittleEndian.Uint16(data[off : off+2]))
		default:
			val = uint32(data[off])
		}
		sum += val
	}
	return sum
}

func ceilDiv(a, b int) int {
	if a%b > 0 {
		return a/b + 1
	}
	return a / b
}
