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
	"container/heap"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"time"
)

// Sessions holds all active sessions for either a client or a server, plus
// the secrets and epoch bookkeeping needed to generate and validate
// handshake cookies.
//
// Unlike the C implementation, cookie derivation here does not need to be
// byte-identical to any other implementation: a handshake cookie is opaque
// to the client, which only ever echoes back whatever bytes the server
// issued it. So Sessions is free to use Go's standard crypto/sha256 and
// crypto/rand directly, with no need to reproduce OpenSSL's EVP API or the
// C sockaddr_storage memory layout.
type Sessions struct {
	// SessionMap holds all active sessions, indexed by remote address.
	SessionMap map[netip.AddrPort]*Session
	// nextSends is a min-heap of active sessions ordered by NextSend,
	// giving O(log n) access to the session that should send its next
	// packet soonest. It plays the same role as the C implementation's
	// priority_queue<SessionMap::iterator, ..., CompareNextSend>.
	//
	// As in the C implementation, a session must always be popped off
	// nextSends before any decision to evict it from SessionMap, and an
	// evicted session must never be pushed back onto nextSends: Pop only
	// ever removes the minimum element, so there is no operation to
	// remove an arbitrary session from the middle of the heap.
	nextSends sessionHeap

	// PacketsPerSec is the maximum accepted send rate a server will
	// negotiate with clients during the handshake (a client requesting a
	// higher rate is clamped down to this). Defaults to
	// DefaultPacketsPerSec.
	PacketsPerSec float64
	// UsecPerPrint, Quiet, and WantTimestamps are copied onto every Session
	// created via NewSession, including ones the server creates dynamically
	// as clients connect; see the Session field docs.
	UsecPerPrint   int32
	Quiet          bool
	WantTimestamps bool

	cookieEpoch          uint32
	lastSecretUpdateTime uint64
	cookieSecret         [CookieSecretSize]byte
	prevCookieEpoch      uint32
	prevCookieSecret     [CookieSecretSize]byte
}

// NewSessions constructs an empty Sessions with a freshly generated random
// cookie secret.
func NewSessions() *Sessions {
	s := &Sessions{
		SessionMap:    make(map[netip.AddrPort]*Session),
		PacketsPerSec: DefaultPacketsPerSec,
	}
	s.newRandomCookieSecret()
	return s
}

// NewSession creates and registers a new session for addr, scheduling its
// first packet to be sent at firstSend, and returns it.
func (s *Sessions) NewSession(firstSend uint64, usecPerPkt int32, addr netip.AddrPort) *Session {
	session := newSession(firstSend, usecPerPkt, addr, s.UsecPerPrint, s.Quiet, s.WantTimestamps)
	s.SessionMap[addr] = session
	heap.Push(&s.nextSends, session)
	return session
}

// NextSendTime returns the NextSend time of the session that should send
// next, or 0 if there are no active sessions.
func (s *Sessions) NextSendTime() uint64 {
	if len(s.nextSends) == 0 {
		return 0
	}
	return s.nextSends[0].NextSend
}

// soleSession returns the single active session, for use in client mode
// where exactly one session (the connection to the server) ever exists.
func (s *Sessions) soleSession() (*Session, bool) {
	for _, session := range s.SessionMap {
		return session, true
	}
	return nil, false
}

func (s *Sessions) newRandomCookieSecret() {
	if _, err := rand.Read(s.cookieSecret[:]); err != nil {
		// crypto/rand.Read only fails if the OS RNG is unavailable, an
		// unrecoverable environment failure.
		panic("isoping: failed to generate random cookie secret: " + err.Error())
	}
}

// RotateCookieSecrets replaces the current cookie secret with a freshly
// generated one under newEpoch, retaining the previous secret so cookies
// issued under it remain valid for one more rotation. Normally called only
// via MaybeRotateCookieSecrets; exported directly for use in tests.
func (s *Sessions) RotateCookieSecrets(newEpoch uint32) {
	s.prevCookieEpoch = s.cookieEpoch
	s.prevCookieSecret = s.cookieSecret
	s.cookieEpoch = newEpoch
	s.newRandomCookieSecret()
}

// MaybeRotateCookieSecrets rotates the cookie secrets if they haven't been
// changed in a while. Only meaningful for a server; a no-op for clients.
func (s *Sessions) MaybeRotateCookieSecrets(now uint64, isServer bool) {
	if isServer && now-s.lastSecretUpdateTime > 1000000 {
		// Round off the unix timestamp to 64 seconds as an epoch, so we
		// don't have to track which ones we've already used.
		newEpoch := uint32(time.Now().Unix() >> 6)
		if newEpoch != s.cookieEpoch {
			s.RotateCookieSecrets(newEpoch)
		}
		s.lastSecretUpdateTime = now
	}
}

// CalculateCookie computes a handshake cookie for the given remote address,
// using the current cookie secret and the relevant fields already set in p,
// and stores the result in p. p.PacketType must already be
// PacketTypeHandshake.
func (s *Sessions) CalculateCookie(p *Packet, addr netip.AddrPort) error {
	return s.calculateCookieWithSecret(p, addr, s.cookieSecret[:], s.cookieEpoch)
}

func (s *Sessions) calculateCookieWithSecret(p *Packet, addr netip.AddrPort, secret []byte, epoch uint32) error {
	if p.PacketType != PacketTypeHandshake {
		return fmt.Errorf("isoping: tried to create cookie for a non-handshake packet")
	}
	h := sha256.New()
	h.Write(secret)
	var usecPerPktBytes [4]byte
	binary.BigEndian.PutUint32(usecPerPktBytes[:], p.UsecPerPkt)
	h.Write(usecPerPktBytes[:])
	writeAddr(h, addr)
	copy(p.Handshake.Cookie[:], h.Sum(nil))
	p.Handshake.CookieEpoch = epoch
	return nil
}

// ValidateCookie reports whether p contains a handshake packet with a valid
// cookie for addr, generated by this Sessions under either its current or
// previous cookie epoch.
func (s *Sessions) ValidateCookie(p *Packet, addr netip.AddrPort) bool {
	if p.Handshake.CookieEpoch != s.cookieEpoch && p.Handshake.CookieEpoch != s.prevCookieEpoch {
		fmt.Fprintf(os.Stderr, "Obsolete cookie epoch: %d\n", p.Handshake.CookieEpoch)
		return false
	}
	secret := s.cookieSecret[:]
	epoch := s.cookieEpoch
	if p.Handshake.CookieEpoch == s.prevCookieEpoch {
		secret = s.prevCookieSecret[:]
		epoch = s.prevCookieEpoch
	}
	golden := Packet{PacketType: PacketTypeHandshake, UsecPerPkt: p.UsecPerPkt}
	if err := s.calculateCookieWithSecret(&golden, addr, secret, epoch); err != nil {
		return false
	}
	if golden.Handshake.Cookie != p.Handshake.Cookie {
		fmt.Fprintf(os.Stderr, "Invalid cookie in handshake packet from %s\n", addr)
		return false
	}
	return true
}

// writeAddr writes a stable byte representation of addr to h. It normalizes
// IPv4 and IPv4-mapped IPv6 addresses to the same 16-byte form, so cookies
// remain valid regardless of how the OS happens to represent a given peer's
// address.
func writeAddr(h interface{ Write([]byte) (int, error) }, addr netip.AddrPort) {
	ip16 := addr.Addr().As16()
	h.Write(ip16[:])
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], addr.Port())
	h.Write(portBytes[:])
}

// sessionHeap implements container/heap.Interface, ordering *Session values
// by NextSend ascending.
type sessionHeap []*Session

func (h sessionHeap) Len() int           { return len(h) }
func (h sessionHeap) Less(i, j int) bool { return h[i].NextSend < h[j].NextSend }
func (h sessionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *sessionHeap) Push(x any) {
	*h = append(*h, x.(*Session))
}

func (h *sessionHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return item
}
