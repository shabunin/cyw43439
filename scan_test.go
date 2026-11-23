package cyw43439

import (
	"encoding/binary"
	"testing"
)

// escanResult builds a wl_escan_result with one wl_bss_info, laid out as
// cyw43-driver reads it: IEs at offset 128 of the BSS info.
func escanResult(ssid string, channel uint16, rssi int16, capability uint16, ies []byte) []byte {
	le := binary.LittleEndian
	bss := make([]byte, 128+len(ies))
	le.PutUint32(bss[0:], 109)
	le.PutUint32(bss[4:], uint32(len(bss)))
	copy(bss[8:], []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55})
	le.PutUint16(bss[16:], capability)
	bss[18] = byte(len(ssid))
	copy(bss[19:], ssid)
	le.PutUint16(bss[72:], 0x1000|channel) // chanspec: 2.4 GHz band bits
	le.PutUint16(bss[78:], uint16(rssi))
	le.PutUint16(bss[116:], 128)
	le.PutUint32(bss[120:], uint32(len(ies)))
	copy(bss[128:], ies)
	p := make([]byte, 12, 12+len(bss))
	le.PutUint32(p[0:], uint32(12+len(bss)))
	le.PutUint16(p[10:], 1)
	return append(p, bss...)
}

// rsn is an RSN element with CCMP and the given AKM suite types.
func rsn(akms ...byte) []byte {
	b := []byte{1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, byte(len(akms)), 0}
	for _, a := range akms {
		b = append(b, 0x00, 0x0f, 0xac, a)
	}
	b = append(b, 0, 0) // RSN capabilities
	return append([]byte{48, byte(len(b))}, b...)
}

func TestParseScanResult(t *testing.T) {
	ssidIE := []byte{0, 4, 'h', 'o', 'm', 'e'}
	wpa := []byte{221, 22, 0x00, 0x50, 0xf2, 1, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 2}
	cases := []struct {
		name string
		cap  uint16
		ies  []byte
		want ScanSecurity
	}{
		{"open", 0x0001, ssidIE, 0},
		{"wep", 0x0011, ssidIE, ScanWEP},
		{"wpa2", 0x0011, append(append([]byte{}, ssidIE...), rsn(2)...), ScanWPA2},
		{"wpa3", 0x0011, rsn(8), ScanWPA3},
		{"wpa2/wpa3", 0x0011, rsn(2, 8), ScanWPA2 | ScanWPA3},
		{"wpa/wpa2", 0x0011, append(rsn(2), wpa...), ScanWPA | ScanWPA2},
		{"enterprise", 0x0011, rsn(1), ScanEnterprise},
	}
	for _, c := range cases {
		r, ok := parseScanResult(escanResult("home", 6, -52, c.cap, c.ies))
		if !ok {
			t.Fatalf("%s: not parsed", c.name)
		}
		if string(r.Name()) != "home" || r.Channel != 6 || r.RSSI != -52 || r.BSSID[5] != 0x55 {
			t.Errorf("%s: got %q ch %d rssi %d bssid %x", c.name, r.Name(), r.Channel, r.RSSI, r.BSSID)
		}
		if r.Security != c.want {
			t.Errorf("%s: security %b, want %b", c.name, r.Security, c.want)
		}
	}
}

func TestParseScanResultBounds(t *testing.T) {
	p := escanResult("x", 1, -70, 0, rsn(2))
	if _, ok := parseScanResult(p[:len(p)-1]); ok {
		t.Error("truncated result parsed")
	}
	binary.LittleEndian.PutUint32(p[12+120:], 1000) // IE length past the BSS
	if _, ok := parseScanResult(p); ok {
		t.Error("IEs past the BSS parsed")
	}
	bad := escanResult("x", 1, -70, 0, []byte{48, 30, 1, 0}) // element longer than the IEs
	if r, ok := parseScanResult(bad); !ok || r.Security != 0 {
		t.Errorf("truncated IE: ok %v security %b", ok, r.Security)
	}
	if _, ok := parseScanResult(nil); ok {
		t.Error("empty payload parsed")
	}
}
