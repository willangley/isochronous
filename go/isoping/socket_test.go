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
	"net"
	"net/netip"
	"testing"
	"time"
)

// newLoopbackUDPServer opens a server-style (unconnected) UDP socket on
// loopback, closed automatically at the end of the test.
func newLoopbackUDPServer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// newLoopbackUDPClient opens a client-style (connected) UDP socket dialed
// at server, closed automatically at the end of the test.
func newLoopbackUDPClient(t *testing.T, server *net.UDPConn) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp6", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readDeadline is generous slack for loopback UDP delivery, which (unlike
// on Linux) isn't necessarily synchronous with the sending syscall on
// macOS; see the isoping_test.cc select()-timing fix this mirrors.
const readDeadline = 500 * time.Millisecond

// mustNotReadable asserts that conn has no packet waiting within
// readDeadline.
func mustNotReadable(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(readDeadline))
	buf := make([]byte, wireSize)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("unexpected packet available (%d bytes), want none", n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Read: %v, want a timeout", err)
	}
}

// drainOnePacket reads and discards exactly one packet, asserting its
// length, without decoding it. Mirrors a raw recv() in the C test used to
// "eat" a packet before the protocol layer would otherwise see it.
func drainOnePacket(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(readDeadline))
	buf := make([]byte, wireSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != wireSize {
		t.Fatalf("Read: got %d bytes, want %d", n, wireSize)
	}
}

// readIncoming sets a generous deadline and calls ReadIncomingPacket,
// requiring it to succeed.
func readIncoming(t *testing.T, sessions *Sessions, conn *net.UDPConn, now uint64, isServer bool) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(readDeadline))
	if err := ReadIncomingPacket(sessions, conn, now, isServer); err != nil {
		t.Fatalf("ReadIncomingPacket: %v", err)
	}
}

func TestSendAndReceiveOnSockets(t *testing.T) {
	const cbase uint64 = 1400 * 1000
	const sbase uint64 = 1600 * 1000
	const usecPerPkt = 100 * 1000
	const csLatency = 4000
	const scLatency = 5000

	server := newLoopbackUDPServer(t)
	client := newLoopbackUDPClient(t, server)

	c := NewSessions()
	s := NewSessions()
	const isServer = true
	const isClient = false

	s.MaybeRotateCookieSecrets(sbase, isServer)
	c.NewSession(cbase+1, usecPerPkt, netip.AddrPort{})
	cSession, _ := c.soleSession()

	// Send the initial handshake packet.
	tt := cSession.NextSend - cbase
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	if cSession.HandshakeRetryCount != 0 {
		t.Fatalf("HandshakeRetryCount = %d, want 0", cSession.HandshakeRetryCount)
	}

	readIncoming(t, s, server, sbase, isServer)

	// The server returns its handshake cookie immediately; eat it before
	// the client processes it, to exercise the resend-on-timeout path
	// below.
	drainOnePacket(t, client)

	// The client doesn't send more packets until the handshake timeout
	// expires.
	tt += HandshakeTimeoutUsec - 1
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	mustNotReadable(t, server)

	// Wait for the client to time out and resend the initial handshake
	// packet.
	tt++
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}

	// The server resends its cookie immediately.
	readIncoming(t, s, server, sbase, isServer)
	if len(s.SessionMap) != 0 {
		t.Fatalf("len(s.SessionMap) = %d, want 0 (server keeps no state for unverified clients)", len(s.SessionMap))
	}

	// Let the client read the cookie, establishing the connection.
	readIncoming(t, c, client, cbase+tt, isClient)
	if cSession.NextTxID != 1 {
		t.Fatalf("NextTxID = %d, want 1", cSession.NextTxID)
	}
	if cSession.NextSend != cbase+tt {
		t.Fatalf("NextSend = %d, want %d", cSession.NextSend, cbase+tt)
	}

	tt = cSession.NextSend - cbase - 1
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	// Verify we didn't send a packet before its time.
	mustNotReadable(t, server)

	// Send a packet in each direction. The server can now verify the
	// client.
	tt++
	if cSession.NextTxID != 1 {
		t.Fatalf("NextTxID = %d, want 1", cSession.NextTxID)
	}
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	if cSession.NextTxID != 2 {
		t.Fatalf("NextTxID = %d, want 2", cSession.NextTxID)
	}

	tt += csLatency
	readIncoming(t, s, server, sbase+tt, isServer)
	if len(s.SessionMap) != 1 {
		t.Fatalf("len(s.SessionMap) = %d, want 1", len(s.SessionMap))
	}
	if want := sbase + tt + 10*1000; s.NextSendTime() != want {
		t.Fatalf("NextSendTime() = %d, want %d", s.NextSendTime(), want)
	}

	sSession, ok := s.soleSession()
	if !ok {
		t.Fatal("no server session")
	}
	if !sSession.RemoteAddr.IsValid() {
		t.Fatal("sSession.RemoteAddr is not valid")
	}
	if sSession.NextTxID != 1 {
		t.Fatalf("sSession.NextTxID = %d, want 1", sSession.NextTxID)
	}
	if sSession.Rx.ID != 1 {
		t.Fatalf("sSession.Rx.ID = %d, want 1", sSession.Rx.ID)
	}

	tt = s.NextSendTime() - sbase
	if err := SendWaitingPackets(s, server, sbase+tt, isServer); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	if want := sbase + tt + uint64(sSession.UsecPerPkt); s.NextSendTime() != want {
		t.Fatalf("NextSendTime() = %d, want %d", s.NextSendTime(), want)
	}
	if sSession.NextTxID != 2 {
		t.Fatalf("sSession.NextTxID = %d, want 2", sSession.NextTxID)
	}

	tt += scLatency
	readIncoming(t, c, client, cbase+tt, isClient)
	if cSession.LatRxCount != 1 {
		t.Fatalf("LatRxCount = %d, want 1", cSession.LatRxCount)
	}

	// Verify we reject garbage data.
	garbage := make([]byte, wireSize)
	if n, err := client.Write(garbage); err != nil || n != wireSize {
		t.Fatalf("Write garbage: n=%d err=%v", n, err)
	}
	server.SetReadDeadline(time.Now().Add(readDeadline))
	if err := ReadIncomingPacket(s, server, sbase+tt, isServer); err == nil {
		t.Fatal("ReadIncomingPacket on garbage data: got nil error, want non-nil")
	}

	// Make a new client, who sends more frequently, getting a new source
	// port. Also establish an upper limit, to verify that the server
	// enforces it.
	c2 := NewSessions()
	s.PacketsPerSec = 4e6 / usecPerPkt
	c2.NewSession(cbase, usecPerPkt/10, netip.AddrPort{})
	c2Session, _ := c2.soleSession()
	c2conn := newLoopbackUDPClient(t, server)

	// Perform the handshake dance so the server knows c2 is legit.
	PrepareTxPacket(c2Session)
	if err := SendPacket(c2Session, c2conn, isClient); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	tt = csLatency
	readIncoming(t, s, server, sbase+tt, isServer)
	tt += scLatency
	readIncoming(t, c2, c2conn, cbase+tt, isClient)

	if want := int32(usecPerPkt / 4); c2Session.UsecPerPkt != want {
		t.Fatalf("c2Session.UsecPerPkt = %d, want %d (server-enforced rate ceiling)", c2Session.UsecPerPkt, want)
	}

	// Now we can send a validated packet to the server.
	tt = c2Session.NextSend - cbase
	if err := SendWaitingPackets(c2, c2conn, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	tt += csLatency

	// Check that the new client is added to the server's state, and it
	// will be sent next.
	readIncoming(t, s, server, sbase+tt, isServer)
	if len(s.SessionMap) != 2 {
		t.Fatalf("len(s.SessionMap) = %d, want 2", len(s.SessionMap))
	}
	if want := sbase + tt + 10*1000; s.NextSendTime() != want {
		t.Fatalf("NextSendTime() = %d, want %d", s.NextSendTime(), want)
	}

	// Let both clients time out on the server side, then have the original
	// client come back.
	tt += 65 * 1000 * 1000
	if err := SendWaitingPackets(s, server, sbase+tt, isServer); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	if len(s.SessionMap) != 0 {
		t.Fatalf("len(s.SessionMap) = %d, want 0", len(s.SessionMap))
	}

	// The now-evicted client still gets one last packet before eviction
	// (SendWaitingPackets always sends before deciding whether to evict).
	readIncoming(t, c, client, cbase+tt, isClient)
	// Hack so the client doesn't spam the server catching up.
	cSession.UsecPerPkt = 50 * 1000 * 1000
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	// The server no longer has any record of this client, so it treats the
	// ack packet as coming from an unknown client and replies with a fresh
	// handshake cookie instead of processing it as an ack.
	server.SetReadDeadline(time.Now().Add(readDeadline))
	if err := ReadIncomingPacket(s, server, sbase+tt, isServer); err != nil {
		t.Fatalf("ReadIncomingPacket (unknown client recovery): %v", err)
	}

	// The client will receive that handshake packet and can renegotiate.
	readIncoming(t, c, client, cbase+tt, isClient)
}

func TestTimeRolloverAt32Bits(t *testing.T) {
	// Have the server's time be close to rolling over the 32-bit
	// microsecond boundary.
	const usecPerPkt = 100 * 1000
	const cbase uint64 = 400 * 1000
	const wrap uint64 = 1 << 32
	// It takes one round-trip to establish the handshake.
	sbase := wrap - uint64(1.5*usecPerPkt)

	server := newLoopbackUDPServer(t)
	client := newLoopbackUDPClient(t, server)
	c2conn := newLoopbackUDPClient(t, server)

	c := NewSessions()
	c2 := NewSessions()
	s := NewSessions()
	const isServer = true
	const isClient = false

	s.MaybeRotateCookieSecrets(sbase, isServer)
	// The first session sends slowly, the second one sends more
	// frequently.
	c.NewSession(cbase, 4*usecPerPkt, netip.AddrPort{})
	c2.NewSession(cbase, usecPerPkt, netip.AddrPort{})
	cSession, _ := c.soleSession()
	c2Session, _ := c2.soleSession()

	// Send the initial handshake packets.
	tt := cSession.NextSend - cbase
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	if err := SendWaitingPackets(c2, c2conn, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}

	readIncoming(t, s, server, sbase+tt, isServer)
	readIncoming(t, s, server, sbase+tt, isServer)
	if len(s.SessionMap) != 0 {
		t.Fatalf("len(s.SessionMap) = %d, want 0 (server keeps no state for unverified clients)", len(s.SessionMap))
	}

	readIncoming(t, c, client, cbase+tt, isClient)
	readIncoming(t, c2, c2conn, cbase+tt, isClient)

	tt = cSession.NextSend - cbase
	if err := SendWaitingPackets(c, client, cbase+tt, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	tt2 := c2Session.NextSend - cbase
	if err := SendWaitingPackets(c2, c2conn, cbase+tt2, isClient); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}

	readIncoming(t, s, server, sbase+tt, isServer)
	readIncoming(t, s, server, sbase+tt2, isServer)
	if len(s.SessionMap) != 2 {
		t.Fatalf("len(s.SessionMap) = %d, want 2", len(s.SessionMap))
	}

	// Verify we can still send packets after crossing the 32-bit boundary.
	tt = s.NextSendTime() - sbase
	if err := SendWaitingPackets(s, server, sbase+tt, isServer); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	readIncoming(t, c2, c2conn, cbase+tt, isClient)

	tt = s.NextSendTime() - sbase
	if err := SendWaitingPackets(s, server, sbase+tt, isServer); err != nil {
		t.Fatalf("SendWaitingPackets: %v", err)
	}
	readIncoming(t, c2, c2conn, cbase+tt, isClient)
}
