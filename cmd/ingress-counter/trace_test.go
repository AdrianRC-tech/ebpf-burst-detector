package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildTraceRecord constructs a synthetic 32-byte pkt_trace ring buffer record
// using the same layout as the BPF struct:
//
//	0   timestamp_ns  uint64 little-endian
//	8   len           uint32 little-endian  (skb->len — includes 14-byte Ethernet header)
//	12  saddr         uint32 network byte order
//	16  daddr         uint32 network byte order
//	20  sport         uint16 network byte order
//	22  dport         uint16 network byte order
//	24  protocol      uint8
//	25  family        uint8
//	26  _pad[6]
func buildTraceRecord(ts uint64, length uint32, saddr, daddr [4]byte, sport, dport uint16, proto, family uint8) []byte {
	raw := make([]byte, pktTraceSize)
	binary.LittleEndian.PutUint64(raw[0:8], ts)
	binary.LittleEndian.PutUint32(raw[8:12], length)
	copy(raw[12:16], saddr[:])
	copy(raw[16:20], daddr[:])
	binary.BigEndian.PutUint16(raw[20:22], sport)
	binary.BigEndian.PutUint16(raw[22:24], dport)
	raw[24] = proto
	raw[25] = family
	return raw
}

func TestDecodePktTrace(t *testing.T) {
	// Network-order bytes for 192.0.2.1 and 192.0.2.2 (RFC-5737 doc addresses).
	src := [4]byte{192, 0, 2, 1}
	dst := [4]byte{192, 0, 2, 2}

	tests := []struct {
		name      string
		raw       []byte
		wantErr   bool
		wantLen   uint32
		wantSrc   net.IP
		wantDst   net.IP
		wantSport uint16
		wantDport uint16
		wantProto uint8
		wantFam   uint8
	}{
		{
			name: "IPv4 TCP — Len reflects skb->len including Ethernet overhead",
			// A TCP SYN with no payload: 14 (Ethernet) + 20 (IP) + 20 (TCP) = 54 bytes.
			// skb->len = 54, NOT 40 (which would be IP+TCP only).
			raw:       buildTraceRecord(1_000_000_000, 54, src, dst, 1234, 80, 6, 4),
			wantLen:   54,
			wantSrc:   net.IP{192, 0, 2, 1},
			wantDst:   net.IP{192, 0, 2, 2},
			wantSport: 1234,
			wantDport: 80,
			wantProto: 6,
			wantFam:   4,
		},
		{
			name: "IPv4 ICMP ping — Len includes Ethernet, ports are zero",
			// 56-byte ping payload: 14 (Ethernet) + 20 (IP) + 8 (ICMP) + 56 = 98 bytes.
			// BPF leaves sport/dport=0 for ICMP (not TCP/UDP).
			raw:       buildTraceRecord(2_000_000_000, 98, src, dst, 0, 0, 1, 4),
			wantLen:   98,
			wantSrc:   net.IP{192, 0, 2, 1},
			wantDst:   net.IP{192, 0, 2, 2},
			wantSport: 0,
			wantDport: 0,
			wantProto: 1,
			wantFam:   4,
		},
		{
			name: "IPv4 UDP",
			// 14 (Ethernet) + 20 (IP) + 8 (UDP) + 10 (payload) = 52 bytes.
			raw:       buildTraceRecord(3_000_000_000, 52, src, dst, 5353, 5353, 17, 4),
			wantLen:   52,
			wantSport: 5353,
			wantDport: 5353,
			wantProto: 17,
			wantFam:   4,
		},
		{
			name: "non-IPv4 (ARP, family=0) — timestamp and Len still recorded, tuple zeroed",
			// ARP frame: 14 (Ethernet) + 28 (ARP) = 42 bytes. BPF records len but leaves
			// addresses/ports at zero and family=0 because skb->protocol != ETH_P_IP.
			raw:       buildTraceRecord(4_000_000_000, 42, [4]byte{}, [4]byte{}, 0, 0, 0, 0),
			wantLen:   42,
			wantSrc:   net.IP{0, 0, 0, 0},
			wantDst:   net.IP{0, 0, 0, 0},
			wantSport: 0,
			wantDport: 0,
			wantProto: 0,
			wantFam:   0,
		},
		{
			name:    "record too short — error returned",
			raw:     make([]byte, pktTraceSize-1),
			wantErr: true,
		},
		{
			name:    "empty slice — error returned",
			raw:     []byte{},
			wantErr: true,
		},
		{
			name: "port byte order — BigEndian from packet matches host uint16",
			// sport=0x1234 in network order → bytes [0x12, 0x34] → host uint16 = 0x1234 = 4660.
			// dport=0x0050 in network order → bytes [0x00, 0x50] → host uint16 = 80.
			raw:       buildTraceRecord(5_000_000_000, 54, src, dst, 0x1234, 0x0050, 6, 4),
			wantLen:   54,
			wantSport: 0x1234,
			wantDport: 0x0050,
			wantProto: 6,
			wantFam:   4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodePktTrace(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("decodePktTrace() err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if got.Len != tc.wantLen {
				t.Errorf("Len = %d, want %d", got.Len, tc.wantLen)
			}
			if tc.wantSrc != nil && !got.SrcIP.Equal(tc.wantSrc) {
				t.Errorf("SrcIP = %v, want %v", got.SrcIP, tc.wantSrc)
			}
			if tc.wantDst != nil && !got.DstIP.Equal(tc.wantDst) {
				t.Errorf("DstIP = %v, want %v", got.DstIP, tc.wantDst)
			}
			if got.SrcPort != tc.wantSport {
				t.Errorf("SrcPort = %d, want %d", got.SrcPort, tc.wantSport)
			}
			if got.DstPort != tc.wantDport {
				t.Errorf("DstPort = %d, want %d", got.DstPort, tc.wantDport)
			}
			if got.Protocol != tc.wantProto {
				t.Errorf("Protocol = %d, want %d", got.Protocol, tc.wantProto)
			}
			if got.Family != tc.wantFam {
				t.Errorf("Family = %d, want %d", got.Family, tc.wantFam)
			}
		})
	}
}
