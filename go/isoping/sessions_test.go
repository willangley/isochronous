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
	"errors"
	"net/netip"
	"testing"
)

var testAddr = netip.MustParseAddrPort("[::1]:12345")

func TestCookieValidation(t *testing.T) {
	s := NewSessions()
	s.RotateCookieSecrets(1)

	p := &Packet{}
	if err := s.CalculateCookie(p, testAddr); err == nil {
		t.Fatal("CalculateCookie on a non-handshake packet: got nil error, want non-nil")
	}

	p.PacketType = PacketTypeHandshake
	p.UsecPerPkt = 100000
	if err := s.CalculateCookie(p, testAddr); err != nil {
		t.Fatalf("CalculateCookie: %v", err)
	}

	// We validate cookies we generate.
	if !s.ValidateCookie(p, testAddr) {
		t.Error("ValidateCookie on our own cookie: got false, want true")
	}

	// Validation fails after changing the IP port or address.
	changedPort := netip.AddrPortFrom(testAddr.Addr(), testAddr.Port()+1)
	if s.ValidateCookie(p, changedPort) {
		t.Error("ValidateCookie after changing port: got true, want false")
	}

	ip := testAddr.Addr().As16()
	ip[0]++
	changedAddr := netip.AddrPortFrom(netip.AddrFrom16(ip), testAddr.Port())
	if s.ValidateCookie(p, changedAddr) {
		t.Error("ValidateCookie after changing address: got true, want false")
	}

	// Validation fails after changing UsecPerPkt.
	p.UsecPerPkt++
	if s.ValidateCookie(p, testAddr) {
		t.Error("ValidateCookie after changing UsecPerPkt: got true, want false")
	}
	p.UsecPerPkt--

	// Validation fails after plain modifying the cookie.
	p.Handshake.Cookie[0]++
	if s.ValidateCookie(p, testAddr) {
		t.Error("ValidateCookie after modifying cookie: got true, want false")
	}
	p.Handshake.Cookie[0]--

	// Cookies generated with the previous secret still validate.
	s.RotateCookieSecrets(2)
	if !s.ValidateCookie(p, testAddr) {
		t.Error("ValidateCookie with previous epoch's secret: got false, want true")
	}

	// But secrets older than that don't validate.
	s.RotateCookieSecrets(3)
	if s.ValidateCookie(p, testAddr) {
		t.Error("ValidateCookie with obsolete epoch's secret: got true, want false")
	}
}

func TestExponentialHandshakeBackoff(t *testing.T) {
	const cbase uint64 = 400 * 1000
	const usecPerPkt = 100 * 1000
	c := NewSessions()
	c.NewSession(cbase, usecPerPkt, testAddr)
	cSession, _ := c.soleSession()
	if cSession.NextSend != cbase {
		t.Fatalf("NextSend = %d, want %d", cSession.NextSend, cbase)
	}

	// Test that we resend handshake packets on an exponential backoff
	// schedule, up until round 10.
	const isServer = false
	send := func() { _ = SendPacket(cSession, discardConn{}, isServer) }

	send()
	if cSession.HandshakeState != HandshakeRequested {
		t.Fatalf("HandshakeState = %v, want %v", cSession.HandshakeState, HandshakeRequested)
	}
	if cSession.HandshakeRetryCount != 0 {
		t.Fatalf("HandshakeRetryCount = %d, want 0", cSession.HandshakeRetryCount)
	}
	if want := cbase + HandshakeTimeoutUsec; cSession.NextSend != want {
		t.Fatalf("NextSend = %d, want %d", cSession.NextSend, want)
	}

	for round := 1; round <= 11; round++ {
		tPrev := cSession.NextSend
		send()
		if cSession.HandshakeRetryCount != round {
			t.Fatalf("round %d: HandshakeRetryCount = %d, want %d", round, cSession.HandshakeRetryCount, round)
		}
		shift := round
		if shift > 10 {
			shift = 10
		}
		want := tPrev + uint64(HandshakeTimeoutUsec)<<uint(shift)
		if cSession.NextSend != want {
			t.Fatalf("round %d: NextSend = %d, want %d", round, cSession.NextSend, want)
		}
	}
}

// discardConn is a Conn that silently accepts every write and errors on any
// read; the handshake-backoff test only exercises SendPacket's bookkeeping,
// not real I/O.
type discardConn struct{}

func (discardConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return len(b), nil
}
func (discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (discardConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, errors.New("discardConn: no reads expected")
}
func (discardConn) Read(b []byte) (int, error) {
	return 0, errors.New("discardConn: no reads expected")
}
