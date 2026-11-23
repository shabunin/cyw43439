package cyw43439

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/soypat/cyw43439/whd"
)

// ScanSecurity flags the security a scanned network advertises. None set
// means an open network.
type ScanSecurity uint8

const (
	ScanWEP        ScanSecurity = 1 << iota // privacy without WPA: WEP
	ScanWPA                                 // WPA (the WPA vendor IE)
	ScanWPA2                                // RSN with a PSK key management
	ScanWPA3                                // RSN with SAE
	ScanEnterprise                          // 802.1X key management
)

// ScanResult is a network (BSS) a scan found. A scan may report the same
// network more than once.
type ScanResult struct {
	BSSID    [6]byte
	SSID     [32]byte
	SSIDLen  uint8 // 0 for a hidden network
	Channel  uint8
	RSSI     int16 // dBm
	Security ScanSecurity
}

// Name is the network's SSID.
func (r *ScanResult) Name() []byte { return r.SSID[:min(int(r.SSIDLen), len(r.SSID))] }

var (
	errScanTimeout = errors.New("cyw43439: scan did not complete")
	errScanAborted = errors.New("cyw43439: scan aborted")
)

// scanTimeout bounds a scan; one over all 2.4 GHz channels takes 2-4 s.
const scanTimeout = 10 * time.Second

// Scan scans every channel for networks, active (with probe requests), and
// calls fn with each result as it arrives. It returns once the chip reports
// the scan complete. fn runs with the device locked: it must not call the
// Device. Ethernet frames that arrive meanwhile go to the receive handler
// as usual. The chip can scan while joined, leaving the channel briefly.
//
// Reference: cyw43_ll_wifi_scan and cyw43_ll_wifi_parse_scan_result in
// cyw43-driver.
func (d *Device) Scan(fn func(ScanResult)) error {
	err := d.acquire(modeWifi)
	defer d.release()
	if err != nil {
		return err
	}
	// wl_escan_params: version, action, sync ID, then wl_scan_params:
	// SSID (length and 32 bytes; none: all), BSSID (broadcast), BSS type,
	// scan type, probes and times (-1: the chip's defaults), channels (0:
	// all), one channel list entry.
	var p [76]byte
	le := binary.LittleEndian
	le.PutUint32(p[0:], 1) // ESCAN_REQ_VERSION
	le.PutUint16(p[4:], 1) // WL_SCAN_ACTION_START
	for i := 44; i < 50; i++ {
		p[i] = 0xff
	}
	p[50] = 2 // any BSS type
	p[51] = 0 // active
	for off := 52; off < 68; off += 4 {
		le.PutUint32(p[off:], 0xffffffff)
	}
	d.scanFn, d.scanDone, d.scanStatus = fn, false, 0
	defer func() { d.scanFn = nil }()
	if err := d.set_iovar_n("escan", whd.IF_STA, p[:]); err != nil {
		return err
	}
	deadline := time.Now().Add(scanTimeout)
	for !d.scanDone {
		if time.Now().After(deadline) {
			return errScanTimeout
		}
		time.Sleep(50 * time.Millisecond)
		if err := d.check_status(d._sendIoctlBuf[:]); err != nil {
			return err
		}
	}
	if d.scanStatus != whd.EStatusSuccess {
		return errScanAborted
	}
	return nil
}

// rxScanEvent handles an ESCAN_RESULT event while a scan runs: a result
// (status partial) or the end of the scan. payload follows the event
// message: a wl_escan_result, little-endian.
func (d *Device) rxScanEvent(status whd.EStatus, payload []byte) {
	if d.scanFn == nil {
		return
	}
	if status != whd.EStatusPartial {
		d.scanDone, d.scanStatus = true, status
		return
	}
	if r, ok := parseScanResult(payload); ok {
		d.scanFn(r)
	}
}

// parseScanResult decodes the first wl_bss_info of a wl_escan_result.
func parseScanResult(payload []byte) (r ScanResult, ok bool) {
	const (
		escanHeader = 12  // buffer length, version, sync ID, BSS count
		bssMin      = 128 // wl_bss_info up to its IEs
	)
	if len(payload) < escanHeader+bssMin {
		return r, false
	}
	bss := payload[escanHeader:]
	le := binary.LittleEndian
	length := int(le.Uint32(bss[4:]))
	ieOff, ieLen := int(le.Uint16(bss[116:])), int(le.Uint32(bss[120:]))
	if length > len(bss) || ieOff+ieLen > length || ieOff < bssMin {
		return r, false
	}
	copy(r.BSSID[:], bss[8:14])
	r.SSIDLen = min(bss[18], 32)
	copy(r.SSID[:], bss[19:19+int(r.SSIDLen)])
	r.Channel = uint8(le.Uint16(bss[72:])) // chanspec: channel in the low byte
	r.RSSI = int16(le.Uint16(bss[78:]))
	r.Security = scanSecurity(le.Uint16(bss[16:]), bss[ieOff:ieOff+ieLen])
	return r, true
}

// scanSecurity reads a network's security from its capability field and
// information elements: an RSN IE (WPA2, WPA3) and the WPA vendor IE.
func scanSecurity(capability uint16, ies []byte) ScanSecurity {
	const (
		capPrivacy = 0x0010
		ieRSN      = 48
		ieVendor   = 221
	)
	var sec ScanSecurity
	for len(ies) >= 2 {
		id, n := ies[0], int(ies[1])
		if 2+n > len(ies) {
			break
		}
		body := ies[2 : 2+n]
		switch {
		case id == ieRSN:
			sec |= akmSecurity(body, 2, false)
		case id == ieVendor && len(body) >= 4 && body[0] == 0x00 && body[1] == 0x50 && body[2] == 0xf2 && body[3] == 1:
			sec |= akmSecurity(body, 6, true)
		}
		ies = ies[2+n:]
	}
	if sec == 0 && capability&capPrivacy != 0 {
		sec = ScanWEP
	}
	return sec
}

// akmSecurity reads the key management suites of an RSN or WPA element
// body, whose version field ends at off: then a group cipher suite, the
// pairwise suites and the AKM suites, each counted list little-endian.
func akmSecurity(body []byte, off int, wpa bool) ScanSecurity {
	sec := ScanWPA2
	if wpa {
		sec = ScanWPA
	}
	off += 4 // group cipher suite
	if off+2 > len(body) {
		return sec // no more fields: the defaults (PSK)
	}
	off += 2 + 4*int(binary.LittleEndian.Uint16(body[off:]))
	if off+2 > len(body) {
		return sec
	}
	n := int(binary.LittleEndian.Uint16(body[off:]))
	off += 2
	var got ScanSecurity
	for i := 0; i < n && off+4 <= len(body); i, off = i+1, off+4 {
		switch body[off+3] {
		case 1, 3, 5: // 802.1X, FT 802.1X, 802.1X SHA-256
			got |= ScanEnterprise
		case 2, 4, 6: // PSK, FT PSK, PSK SHA-256
			got |= sec
		case 8, 9: // SAE, FT SAE
			got |= ScanWPA3
		}
	}
	if got == 0 {
		return sec
	}
	return got
}
