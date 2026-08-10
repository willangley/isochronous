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
	"fmt"
	"net/netip"
)

// HandshakeState is the state of a Session's connection handshake.
type HandshakeState int

const (
	// NewSessionState: no packets exchanged yet.
	NewSessionState HandshakeState = iota
	// HandshakeRequested: client has sent its initial packet to the
	// server, i.e. SYN.
	HandshakeRequested
	// CookieGenerated: server has replied with a cookie, i.e. SYN|ACK.
	CookieGenerated
	// Established: client has echoed the cookie back, i.e. ACK.
	Established
)

func (s HandshakeState) String() string {
	switch s {
	case NewSessionState:
		return "NEW_SESSION"
	case HandshakeRequested:
		return "HANDSHAKE_REQUESTED"
	case CookieGenerated:
		return "COOKIE_GENERATED"
	case Established:
		return "ESTABLISHED"
	default:
		return fmt.Sprintf("HandshakeState(%d)", int(s))
	}
}

// HandshakeTimeoutUsec is the base timeout, in microseconds, before the
// client resends an unacknowledged handshake packet. Successive retries
// back off exponentially, capped at a factor of 2^10.
const HandshakeTimeoutUsec = 1000000

// Session tracks all state for one isoping connection, either from the
// client's or the server's point of view.
//
// WARNING: lots of math in this package relies on well-defined uint32/int32
// arithmetic overflow behavior, plus the fact that when we subtract two
// successive timestamps (for example) they will be less than 2^31
// microseconds apart. It would be safer to just use 64-bit values
// everywhere, but that would cut the number of acks per packet in half,
// which would be unfortunate. See diff and diff64 in clock.go.
type Session struct {
	UsecPerPkt   int32
	UsecPerPrint int32

	// Quiet suppresses the per-packet summary lines normally printed by
	// HandleAckPacket. WantTimestamps additionally prefixes those lines
	// with a wall-clock-style timestamp. Both are copied from the owning
	// Sessions at construction time (see Sessions.NewSession): the C
	// implementation reads its equivalent "quiet"/"want_timestamps"
	// variables as process-wide globals, which Go's package-level state
	// conventions make an awkward, test-hostile fit, so they're carried
	// per-Session here instead.
	Quiet          bool
	WantTimestamps bool

	// RemoteAddr is the peer's address.
	RemoteAddr netip.AddrPort

	HandshakeState      HandshakeState
	HandshakeRetryCount int

	NextTxID       uint32 // id field for next transmit
	NextRxID       uint32 // expected id field for next receive
	NextRxAckID    uint32 // expected ack.id field in next received ack
	StartRtxTime   uint32 // remote's txtime at startup
	StartRxTime    uint64 // local rxtime at startup
	LastRxTime     uint32 // local rxtime of last received packet
	MinCycleRxDiff int32  // smallest packet delay seen this cycle
	NextCycle      uint32 // time when next cycle begins
	NextSend       uint64 // time when we'll send next pkt
	NumLost        uint32 // number of rx packets not received
	NextTxAckIndex int    // next array item to fill in Tx.Acks

	Tx, Rx Packet // transmit and received packet buffers

	LastAckInfo string // human readable format of latest ack
	LastPrint   uint32 // time of last packet printout

	// Packet statistics counters for transmit and receive directions.
	LatTx, LatTxMin, LatTxMax, LatTxCount, LatTxSum, LatTxVarSum int64
	LatRx, LatRxMin, LatRxMax, LatRxCount, LatRxSum, LatRxVarSum int64
}

// newSession constructs a Session for a peer at addr, whose first packet
// will be sent at firstSend (a now64()-style timestamp). usecPerPrint
// controls how often received packets are printed (0 disables rate
// limiting, matching the -f flag being unset).
func newSession(firstSend uint64, usecPerPkt int32, addr netip.AddrPort, usecPerPrint int32, quiet, wantTimestamps bool) *Session {
	return &Session{
		UsecPerPkt:     usecPerPkt,
		UsecPerPrint:   usecPerPrint,
		Quiet:          quiet,
		WantTimestamps: wantTimestamps,
		RemoteAddr:     addr,
		HandshakeState: NewSessionState,
		NextTxID:       1,
		NextSend:       firstSend,
		LastPrint:      uint32(firstSend - uint64(usecPerPkt)),
		LatTxMin:       0x7fffffff,
		LatRxMin:       0x7fffffff,
	}
}
