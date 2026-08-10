// Copyright 2016 Google Inc. All rights reserved.
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

package isoping

import (
	"bytes"
	"testing"
)

func TestWireSizeMatchesCImplementation(t *testing.T) {
	// The C implementation's sizeof(struct Packet) is 540 bytes: a 6xuint32
	// header (24) + packet_type/first_ack (2) + 2 bytes of compiler padding
	// to 4-byte-align the union, + a 512-byte union.
	if wireSize != 540 {
		t.Errorf("wireSize = %d, want 540", wireSize)
	}
}

func TestPacketRoundTripAck(t *testing.T) {
	p := &Packet{
		Magic:      Magic,
		ID:         42,
		TxTime:     123456,
		ClockDiff:  7,
		UsecPerPkt: 100000,
		NumLost:    3,
		PacketType: PacketTypeAck,
		FirstAck:   5,
	}
	p.Acks[5] = Ack{ID: 41, RxTime: 123400}
	p.Acks[6] = Ack{ID: 42, RxTime: 123450}

	buf, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != wireSize {
		t.Fatalf("len(buf) = %d, want %d", len(buf), wireSize)
	}

	var got Packet
	if err := got.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if got != *p {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", got, *p)
	}
}

func TestPacketRoundTripHandshake(t *testing.T) {
	p := &Packet{
		Magic:      Magic,
		ID:         1,
		TxTime:     100,
		PacketType: PacketTypeHandshake,
	}
	p.Handshake.Version = 1
	p.Handshake.CookieEpoch = 99
	copy(p.Handshake.Cookie[:], bytes.Repeat([]byte{0xab}, CookieSize))

	buf, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var got Packet
	if err := got.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if got != *p {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", got, *p)
	}
}

func TestMagicBytes(t *testing.T) {
	// Confirms the magic number reads as the ASCII string "BLIP" on the
	// wire, matching #define MAGIC 0x424c4950 in isoping.cc.
	p := &Packet{Magic: Magic, PacketType: PacketTypeAck}
	buf, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[0:4]); got != "BLIP" {
		t.Errorf("magic bytes = %q, want %q", got, "BLIP")
	}
}
