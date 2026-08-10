// Copyright 2014 Google Inc. All rights reserved.
// Copyright 2026 Will Angley. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package isoping implements the isoping protocol: like ping, but sends
// packets isochronously (equally spaced in time) in each direction. By being
// clever, we can use the known timing of each packet to determine, on a
// noisy network, which direction is dropping or delaying packets and by how
// much.
package isoping

import (
	"encoding/binary"
	"fmt"
)

// Magic is a magic number placed at the start of every packet, used to
// reject bogus packets.
const Magic uint32 = 0x424c4950

// ServerPort is the default UDP port isoping listens and connects on.
const ServerPort = 4948

// CookieSize is the number of bytes used to store a handshake cookie, which
// is a SHA-256 hash.
const CookieSize = 32

// CookieSecretSize is the number of bytes used to store the random cookie
// secret.
const CookieSecretSize = 16

// NumAcks is the number of ack entries carried in an ack packet.
const NumAcks = 64

// PacketType identifies whether a Packet carries ack data or handshake data.
type PacketType uint8

const (
	// PacketTypeAck marks a packet carrying timing acks.
	PacketTypeAck PacketType = iota
	// PacketTypeHandshake marks a packet carrying handshake data.
	PacketTypeHandshake
)

// Ack records the id and receive time of a previously received packet, sent
// back to the peer so it can compute one-way latency in that direction.
// TxTime==0 (that is, ID and RxTime both zero) marks an empty slot.
type Ack struct {
	ID     uint32 // id field from a received packet
	RxTime uint32 // receiver's monotonic time when the packet arrived
}

// Handshake carries the data exchanged while establishing a session.
type Handshake struct {
	Version     uint32           // max version of the isoping protocol supported
	CookieEpoch uint32           // which cookie secret was used
	Cookie      [CookieSize]byte // actual cookie value
}

// Packet is the layout of the UDP packets exchanged between client and
// server. Packets have exactly the same structure in both directions.
//
// On the wire, Handshake and Acks occupy the same 512-byte region (a union
// in the original C implementation): only one is meaningful, chosen by
// PacketType. In memory here they're kept as separate fields so a Session
// can accumulate Acks incrementally without disturbing Handshake, matching
// the original's persistent tx/rx packet buffers.
type Packet struct {
	Magic      uint32 // magic number to reject bogus packets
	ID         uint32 // sequential packet id number
	TxTime     uint32 // transmitter's monotonic time when pkt was sent
	ClockDiff  uint32 // estimate of (transmitter's clk) - (receiver's clk)
	UsecPerPkt uint32 // microseconds of delay between packets
	NumLost    uint32 // number of pkts transmitter expected to get but didn't
	PacketType PacketType
	FirstAck   uint8 // starting index in Acks[] circular buffer

	Handshake Handshake
	Acks      [NumAcks]Ack
}

// wireSize is sizeof(struct Packet) in the C implementation: a 28-byte
// header (24 bytes of uint32 fields, 2 bytes of type/index fields, and 2
// bytes of compiler-inserted padding to 4-byte-align the union that
// follows), plus the 512-byte union.
const wireSize = 28 + 512

// unionOffset is the byte offset of the Handshake/Acks union within the
// wire encoding.
const unionOffset = 28

// MarshalBinary encodes p in the same 540-byte, big-endian, on-the-wire
// format used by the original C implementation.
func (p *Packet) MarshalBinary() ([]byte, error) {
	buf := make([]byte, wireSize)
	binary.BigEndian.PutUint32(buf[0:], p.Magic)
	binary.BigEndian.PutUint32(buf[4:], p.ID)
	binary.BigEndian.PutUint32(buf[8:], p.TxTime)
	binary.BigEndian.PutUint32(buf[12:], p.ClockDiff)
	binary.BigEndian.PutUint32(buf[16:], p.UsecPerPkt)
	binary.BigEndian.PutUint32(buf[20:], p.NumLost)
	buf[24] = byte(p.PacketType)
	buf[25] = p.FirstAck
	// buf[26:28] is padding, left zero.

	switch p.PacketType {
	case PacketTypeHandshake:
		off := unionOffset
		binary.BigEndian.PutUint32(buf[off:], p.Handshake.Version)
		binary.BigEndian.PutUint32(buf[off+4:], p.Handshake.CookieEpoch)
		copy(buf[off+8:off+8+CookieSize], p.Handshake.Cookie[:])
	case PacketTypeAck:
		off := unionOffset
		for i := range p.Acks {
			binary.BigEndian.PutUint32(buf[off:], p.Acks[i].ID)
			binary.BigEndian.PutUint32(buf[off+4:], p.Acks[i].RxTime)
			off += 8
		}
	}
	return buf, nil
}

// UnmarshalBinary decodes a packet previously encoded with MarshalBinary (or
// received from a wire-compatible C implementation).
func (p *Packet) UnmarshalBinary(buf []byte) error {
	if len(buf) != wireSize {
		return fmt.Errorf("isoping: invalid packet length %d, want %d", len(buf), wireSize)
	}
	p.Magic = binary.BigEndian.Uint32(buf[0:])
	p.ID = binary.BigEndian.Uint32(buf[4:])
	p.TxTime = binary.BigEndian.Uint32(buf[8:])
	p.ClockDiff = binary.BigEndian.Uint32(buf[12:])
	p.UsecPerPkt = binary.BigEndian.Uint32(buf[16:])
	p.NumLost = binary.BigEndian.Uint32(buf[20:])
	p.PacketType = PacketType(buf[24])
	p.FirstAck = buf[25]

	switch p.PacketType {
	case PacketTypeHandshake:
		off := unionOffset
		p.Handshake.Version = binary.BigEndian.Uint32(buf[off:])
		p.Handshake.CookieEpoch = binary.BigEndian.Uint32(buf[off+4:])
		copy(p.Handshake.Cookie[:], buf[off+8:off+8+CookieSize])
	case PacketTypeAck:
		off := unionOffset
		for i := range p.Acks {
			p.Acks[i].ID = binary.BigEndian.Uint32(buf[off:])
			p.Acks[i].RxTime = binary.BigEndian.Uint32(buf[off+4:])
			off += 8
		}
	}
	return nil
}
