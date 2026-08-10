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

package isoping

import (
	"container/heap"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// DefaultPacketsPerSec is the default rate a client requests, and the
// default rate ceiling a server enforces, absent a -r flag.
const DefaultPacketsPerSec = 10.0

// UsecPerCycle is the amount of time we can assume our calibration between
// the local and remote monotonic clocks is reasonably valid. It seems some
// devices have *very* fast clock skew (> 1 msec/minute) so this
// unfortunately has to be much shorter than one might like. This may
// reflect actual bugs in some ntpd and/or kernel adjtime() implementations:
// in principle this kind of periodic correction shouldn't be necessary,
// because that's what adjtime() is for. But empirically, results are way
// off without it.
const UsecPerCycle = 10 * 1000 * 1000

// ErrConnectionRefused is returned by SendPacket and ReadIncomingPacket when
// the OS reports that the remote end has actively refused the connection
// (e.g. via an ICMP port-unreachable observed on a connected client
// socket). It signals "the server is gone, stop retrying" the same way the
// C implementation's use of errno ECONNREFUSED does.
var ErrConnectionRefused = errors.New("isoping: connection refused")

// errInvalidPacket reports that a received packet was malformed: too short,
// missing the magic number, or an unrecognized packet type.
var errInvalidPacket = errors.New("isoping: invalid packet")

// Conn is the minimal socket interface the protocol functions need to send
// and receive packets. *net.UDPConn satisfies it: WriteToUDPAddrPort and
// ReadFromUDPAddrPort address an unconnected (server) socket, while Write
// and Read address a connected (client) socket's single peer.
type Conn interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Write(b []byte) (int, error)
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	Read(b []byte) (int, error)
}

func recvFrom(conn Conn, isServer bool, buf []byte) (int, netip.AddrPort, error) {
	if isServer {
		return conn.ReadFromUDPAddrPort(buf)
	}
	n, err := conn.Read(buf)
	return n, netip.AddrPort{}, err
}

// PrepareTxPacket fills in s.Tx as the next outgoing packet: sequence id,
// current handshake-or-ack packet type, and clock/loss bookkeeping. Note:
// Tx.Acks is filled in incrementally by HandleAckPacket; this only sets the
// header around whatever ack data is already there. Corresponds to
// prepare_tx_packet() in the C implementation.
func PrepareTxPacket(s *Session) {
	s.Tx.Magic = Magic
	s.Tx.ID = s.NextTxID
	s.NextTxID++
	s.Tx.UsecPerPkt = uint32(s.UsecPerPkt)
	s.Tx.TxTime = uint32(s.NextSend)
	if s.StartRtxTime != 0 {
		s.Tx.ClockDiff = uint32(s.StartRxTime - uint64(s.StartRtxTime))
	} else {
		s.Tx.ClockDiff = 0
	}
	s.Tx.NumLost = s.NumLost
	s.Tx.FirstAck = uint8(s.NextTxAckIndex)
	switch s.HandshakeState {
	case NewSessionState, HandshakeRequested, CookieGenerated:
		s.Tx.PacketType = PacketTypeHandshake
	case Established:
		s.Tx.PacketType = PacketTypeAck
	default:
		panic(fmt.Sprintf("isoping: unknown handshake state %v", s.HandshakeState))
	}
}

// prepareHandshakeReplyPacket builds the initial handshake reply a server
// sends before a Session exists for the client: it echoes the client's id
// and clamps the client's requested rate to no faster than packetsPerSec.
// Corresponds to prepare_handshake_reply_packet() in the C implementation.
func prepareHandshakeReplyPacket(rx *Packet, now uint64, packetsPerSec float64) Packet {
	minUsecPerPkt := uint32(1e6 / packetsPerSec)
	return Packet{
		Magic:      Magic,
		ID:         rx.ID,
		UsecPerPkt: max(rx.UsecPerPkt, minUsecPerPkt),
		TxTime:     uint32(now),
		ClockDiff:  uint32(now) - rx.TxTime,
		PacketType: PacketTypeHandshake,
	}
}

// sendInitialHandshakeReply sends a fresh cookie to a client that hasn't
// established a session yet. Corresponds to send_initial_handshake_reply()
// in the C implementation.
func (s *Sessions) sendInitialHandshakeReply(conn Conn, rx *Packet, remoteAddr netip.AddrPort, now uint64) error {
	tx := prepareHandshakeReplyPacket(rx, now, s.PacketsPerSec)
	if err := s.CalculateCookie(&tx, remoteAddr); err != nil {
		return err
	}
	buf, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDPAddrPort(buf, remoteAddr); err != nil {
		fmt.Fprintf(os.Stderr, "sendto: %v\n", err)
	}
	return nil
}

// SendPacket sends s.Tx (already populated, e.g. by PrepareTxPacket) and
// advances the session's schedule and handshake-retry/backoff state.
// Corresponds to send_packet() in the C implementation.
func SendPacket(s *Session, conn Conn, isServer bool) error {
	buf, err := s.Tx.MarshalBinary()
	if err != nil {
		return err
	}
	if isServer {
		if _, err := conn.WriteToUDPAddrPort(buf, s.RemoteAddr); err != nil {
			fmt.Fprintf(os.Stderr, "sendto: %v\n", err)
		}
	} else {
		if _, err := conn.Write(buf); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
			if errors.Is(err, syscall.ECONNREFUSED) {
				return ErrConnectionRefused
			}
		}
	}

	if isServer || s.HandshakeState == Established || s.HandshakeState == CookieGenerated {
		s.NextSend += uint64(s.UsecPerPkt)
	} else {
		// Handle resending handshake packets from the client. If they get
		// lost before we get a valid cookie from the server, the server
		// won't know about us, and our normal retry procedure would get us
		// out of sync.
		if s.HandshakeState == NewSessionState {
			s.HandshakeState = HandshakeRequested
			s.HandshakeRetryCount = 0
		} else {
			s.HandshakeRetryCount++
		}
		// Limit the backoff to a factor of 2^10.
		shift := s.HandshakeRetryCount
		if shift > 10 {
			shift = 10
		}
		timeout := uint32(HandshakeTimeoutUsec) << uint(shift)
		s.NextSend += uint64(timeout)
		// Don't count the handshake packet as part of the sequence.
		s.NextTxID--
	}
	return nil
}

// SendWaitingPackets sends a packet for every session whose scheduled
// NextSend time has arrived. On a server, sessions that haven't been heard
// from in over 60 seconds are dropped instead of rescheduled. Corresponds
// to send_waiting_packets() in the C implementation.
func SendWaitingPackets(sessions *Sessions, conn Conn, now uint64, isServer bool) error {
	for len(sessions.nextSends) > 0 && diff64(now, sessions.NextSendTime()) >= 0 {
		session := heap.Pop(&sessions.nextSends).(*Session)
		PrepareTxPacket(session)
		if err := SendPacket(session, conn, isServer); err != nil {
			return err
		}
		// TODO: Detect connection refused on a per-client basis, instead of
		// waiting for timeout.
		// TODO: Support very low packets-per-second values, e.g. one packet
		// per hour, without constantly disconnecting the client.
		// TODO: Instead of a fixed timeout, evict clients if they miss a
		// certain number of expected transmissions, scaling with how many
		// packets they've already sent.
		if isServer && diff(now, uint64(session.LastRxTime)) > 60*1000*1000 {
			fmt.Fprintf(os.Stderr, "client %s disconnected.\n", session.RemoteAddr)
			delete(sessions.SessionMap, session.RemoteAddr)
		} else {
			heap.Push(&sessions.nextSends, session)
		}
	}
	return nil
}

// ReadIncomingPacket reads one packet from conn and processes it, updating
// sessions and possibly sending a reply on conn. Assumes a packet is
// currently readable. Corresponds to read_incoming_packet() in the C
// implementation.
func ReadIncomingPacket(sessions *Sessions, conn Conn, now uint64, isServer bool) error {
	buf := make([]byte, wireSize)
	n, rxAddr, err := recvFrom(conn, isServer, buf)
	if err != nil {
		// A caller closing its own conn to unblock a goroutine parked here
		// (e.g. during shutdown) is an expected way to stop, not a real
		// I/O failure worth logging.
		if !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "recvfrom: %v\n", err)
		}
		return err
	}

	var rx Packet
	if n != wireSize {
		fmt.Fprintf(os.Stderr, "got invalid packet of length %d from %s\n", n, rxAddr)
		return errInvalidPacket
	}
	if err := rx.UnmarshalBinary(buf[:n]); err != nil || rx.Magic != Magic {
		fmt.Fprintf(os.Stderr, "got invalid packet of length %d, magic=%d from %s\n", n, rx.Magic, rxAddr)
		return errInvalidPacket
	}
	switch rx.PacketType {
	case PacketTypeHandshake, PacketTypeAck:
	default:
		fmt.Fprintf(os.Stderr, "received unknown packet type %d\n", rx.PacketType)
		return errInvalidPacket
	}

	var session *Session
	if isServer {
		if existing, ok := sessions.SessionMap[rxAddr]; ok {
			session = existing
		} else if rx.PacketType != PacketTypeHandshake {
			fmt.Fprintf(os.Stderr, "Received non-handshake packet from unknown client %s\n", rxAddr)
			// Reply with a new handshake packet, including a cookie; we may
			// have dropped a legit client and need to tell it to
			// renegotiate.
			return sessions.sendInitialHandshakeReply(conn, &rx, rxAddr, now)
		}
	} else {
		existing, ok := sessions.soleSession()
		if !ok {
			fmt.Fprintf(os.Stderr, "No session configured for %s when receiving packet\n", rxAddr)
			return errInvalidPacket
		}
		session = existing
	}
	return handlePacket(sessions, session, &rx, conn, rxAddr, now, isServer)
}

// handlePacket checks what kind of packet was received and processes it
// appropriately. session may be nil when handling a handshake packet for a
// connection that doesn't exist yet. Corresponds to handle_packet() in the
// C implementation.
func handlePacket(sessions *Sessions, session *Session, rx *Packet, conn Conn, rxAddr netip.AddrPort, now uint64, isServer bool) error {
	switch rx.PacketType {
	case PacketTypeHandshake:
		if isServer {
			return handleNewClientHandshakePacket(sessions, rx, conn, rxAddr, now)
		}
		handleServerHandshakePacket(sessions, rx, now)
		return nil
	case PacketTypeAck:
		if session != nil {
			session.Rx = *rx
			if !isServer && session.HandshakeState == CookieGenerated {
				// Now we know the server has accepted our connection. Clear
				// out the handshake data from the send buffer and prepare
				// to track acks.
				session.HandshakeState = Established
				session.Tx.Acks = [NumAcks]Ack{}
			}
		}
		HandleAckPacket(session, now)
		return nil
	default:
		return fmt.Errorf("isoping: handlePacket called for unknown packet type %d", rx.PacketType)
	}
}

// handleNewClientHandshakePacket processes a handshake packet from a new
// client: it replies with a cookie if none was provided, or validates a
// provided cookie and establishes a new Session. Corresponds to
// handle_new_client_handshake_packet() in the C implementation.
func handleNewClientHandshakePacket(sessions *Sessions, rx *Packet, conn Conn, remoteAddr netip.AddrPort, now uint64) error {
	if rx.Handshake.CookieEpoch == 0 {
		// New connection with no cookie. Return a cookie to validate the
		// client.
		delete(sessions.SessionMap, remoteAddr)
		fmt.Fprintf(os.Stderr, "New connection from %s, sending cookie\n", remoteAddr)
		return sessions.sendInitialHandshakeReply(conn, rx, remoteAddr, now)
		// The handshake state is conceptually COOKIE_GENERATED now, but the
		// whole point of the cookie is to avoid saving state in the server,
		// so we don't store a Session here.
	}
	// Cookie provided; validate it to accept or reject the connection.
	if !sessions.ValidateCookie(rx, remoteAddr) {
		return nil
	}
	fmt.Fprintf(os.Stderr, "New client connection: %s\n", remoteAddr)
	// Use the usec_per_pkt value provided by the client.
	session := sessions.NewSession(now+10*1000, int32(rx.UsecPerPkt), remoteAddr)
	session.HandshakeState = Established
	session.Rx = *rx
	// This is a new session we haven't sent any timing packets on, so the
	// client can't possibly have acknowledged any packets. Replace the
	// handshake data with a set of empty acks and process as normal.
	session.Rx.PacketType = PacketTypeAck
	session.Rx.Acks = [NumAcks]Ack{}
	HandleAckPacket(session, now)
	return nil
}

// handleServerHandshakePacket processes a handshake packet received from
// the server, configuring the (sole) client Session to echo the provided
// cookie back. Corresponds to handle_server_handshake_packet() in the C
// implementation.
func handleServerHandshakePacket(sessions *Sessions, rx *Packet, now uint64) {
	session, ok := sessions.soleSession()
	if !ok {
		return
	}
	// We don't need to resend the handshake packet any more.
	if len(sessions.nextSends) > 0 {
		heap.Pop(&sessions.nextSends)
	}

	session.NextTxID = 1
	session.NextRxID = 0
	session.Tx.PacketType = PacketTypeHandshake
	session.Tx.Handshake.CookieEpoch = rx.Handshake.CookieEpoch
	session.Tx.Handshake.Cookie = rx.Handshake.Cookie
	if usecPerPkt := int32(rx.UsecPerPkt); usecPerPkt != session.UsecPerPkt {
		fmt.Fprintf(os.Stderr, "Server overrode packets per second to %f\n", 1000000.0/float64(usecPerPkt))
		session.UsecPerPkt = usecPerPkt
	}
	session.HandshakeState = CookieGenerated
	session.NextSend = now
	heap.Push(&sessions.nextSends, session)
}

// HandleAckPacket processes an established Session's incoming ack packet,
// already stored in s.Rx: it updates loss counters and clock-skew/latency
// estimates in both directions, and prints a summary line if printing is
// due. Corresponds to handle_ack_packet() in the C implementation.
func HandleAckPacket(s *Session, now uint64) {
	// Most of the complexity here comes from the fact that the remote
	// system's clock will be skewed vs. ours. We use a monotonic clock
	// instead of wall-clock time, so unless we figure out the skew offset,
	// comparing the two values is essentially meaningless. We can however
	// assume both clocks tick at 1 microsecond per tick... except for
	// inevitable clock rate errors, which we have to account for
	// occasionally.

	txtime := s.Rx.TxTime
	rxtime := now
	id := s.Rx.ID

	if s.NextRxID == 0 {
		// The remote txtime is told to us by the sender, so it is always
		// perfectly correct... but it uses the sender's clock.
		s.StartRtxTime = txtime - id*uint32(s.UsecPerPkt)

		// The receive time uses our own clock and is estimated by us, so it
		// needs to be corrected over time because:
		//   a) the two clocks inevitably run at slightly different speeds;
		//   b) there's an unknown, variable, network delay between tx and
		//      rx.
		// Here, we're just assigning an initial estimate.
		s.StartRxTime = rxtime - uint64(id)*uint64(s.UsecPerPkt)

		s.MinCycleRxDiff = 0
		s.NextRxID = id
		s.NextCycle = uint32(now + UsecPerCycle)
	}

	// see if we missed receiving any previous packets.
	tmpdiff := diff(id, s.NextRxID)
	switch {
	case tmpdiff > 0:
		// arriving packet has id > expected, so something was lost. Note
		// that we don't use Rx.Acks to determine packet loss: the limited
		// size of that array means that, during a longer outage, we might
		// not see an ack for a packet *even if that packet arrived safely*
		// at the remote. So we count on the remote end to count its own
		// packet losses using sequence numbers and send that count back to
		// us, and do the same here for incoming packets, sending our error
		// count back to them next time we're ready to transmit.
		fmt.Fprintf(os.Stderr, "lost %d  expected=%d  got=%d\n", tmpdiff, s.NextRxID, id)
		s.NumLost += uint32(tmpdiff)
		s.NextRxID += uint32(tmpdiff) + 1
	case tmpdiff == 0:
		// exactly as expected; good.
		s.NextRxID++
	default:
		// packet before the expected one? weird.
		fmt.Fprintf(os.Stderr, "out-of-order packets? %d\n", tmpdiff)
	}

	// fix up the clock offset if there's any drift.
	predictedRxTime := s.StartRxTime + uint64(id)*uint64(s.UsecPerPkt)
	rxOffset := int32(diff64(rxtime, predictedRxTime))
	if rxOffset < -20 {
		// packet arrived before predicted time, so prediction was based on
		// a packet that was "slow" before, or else one of our clocks is
		// drifting. Use earliest legitimate start time.
		fmt.Fprintf(os.Stderr, "time paradox: backsliding start by %d usec\n", rxOffset)
		s.StartRxTime = rxtime - uint64(id)*uint64(s.UsecPerPkt)
		predictedRxTime = s.StartRxTime + uint64(id)*uint64(s.UsecPerPkt)
	}
	rxdiff := int32(diff64(rxtime, predictedRxTime))

	// Figure out the offset between our clock and the remote's clock, so we
	// can calculate the minimum round trip time (rtt). Then, because
	// consecutive packets sent in both directions are equally spaced in
	// time, we can figure out how much a particular packet was delayed in
	// transit - independently in each direction! This is an advantage over
	// the normal "ping" program, which has no way to tell which direction
	// caused the delay, or which direction dropped the packet.
	//
	// Our clockdiff is
	//   (our rx time) - (their tx time)
	//   == (their rx time + offset) - (their tx time)
	//   == (their tx time + offset + 1/2 rtt) - (their tx time)
	//   == offset + 1/2 rtt
	// and theirs (rx.clockdiff) is:
	//   (their rx time) - (our tx time)
	//   == (their rx time) - (their tx time + offset)
	//   == (their tx time + 1/2 rtt) - (their tx time + offset)
	//   == 1/2 rtt - offset
	// So add them together and we get:
	//   offset + 1/2 rtt + 1/2 rtt - offset  ==  rtt
	// Subtract them and we get:
	//   offset + 1/2 rtt - 1/2 rtt + offset  ==  2 * offset
	// ...but that last subtraction is dangerous because if we divide by 2
	// to get offset, it doesn't work with 32-bit math, which may have
	// discarded a high-order bit somewhere along the way. Instead, we can
	// extract offset once we have rtt by substituting it into
	//   clockdiff = offset + 1/2 rtt
	//   offset = clockdiff - 1/2 rtt
	// (Dividing rtt by 2 is safe since it's always small and positive.)
	//
	// (This example assumes 1/2 rtt in each direction. There's no way to
	// determine it more accurately than that.)
	clockdiff := diff(s.StartRxTime, uint64(s.StartRtxTime))
	rtt := clockdiff + int32(s.Rx.ClockDiff)
	offset := diff(clockdiff, rtt/2)

	if s.Rx.ClockDiff == 0 {
		// don't print the first packet: it has an invalid clockdiff since
		// the client can't calculate the clockdiff until it receives at
		// least one packet from us.
		s.LastPrint = uint32(now - uint64(s.UsecPerPrint) + 1)
	} else {
		// not the first packet, so statistics are valid.
		s.LatRxCount++
		s.LatRx = int64(rxdiff) + int64(rtt/2)
		s.LatRxMin = min(s.LatRxMin, s.LatRx)
		s.LatRxMax = max(s.LatRxMax, s.LatRx)
		s.LatRxSum += s.LatRx
		s.LatRxVarSum += s.LatRx * s.LatRx
	}

	// Note: the way okToPrint is structured, if there is a dropout in the
	// connection for more than UsecPerPrint, we will statistically end up
	// printing the first packet after the dropout ends. That one should
	// have the longest timeout, ie. a "worst case" packet, which is usually
	// the information you want to see.
	okToPrint := !s.Quiet && diff(now, uint64(s.LastPrint)) >= s.UsecPerPrint
	if okToPrint {
		if s.WantTimestamps {
			printTimestamp(os.Stdout, rxtime)
		}
		fmt.Printf("%12s  %6.1f ms rx  (min=%.1f)  loss: %d/%d tx  %d/%d rx\n",
			s.LastAckInfo,
			float64(rxdiff+rtt/2)/1000.0,
			float64(rtt/2)/1000.0,
			s.Rx.NumLost,
			s.NextTxID-1,
			s.NumLost,
			s.NextRxID-1)
		s.LastAckInfo = ""
		s.LastPrint = uint32(now)
	}

	if rxdiff < s.MinCycleRxDiff {
		s.MinCycleRxDiff = rxdiff
	}
	if diff(now, uint64(s.NextCycle)) >= 0 {
		if s.MinCycleRxDiff > 0 {
			fmt.Fprintf(os.Stderr, "clock skew: sliding start by %d usec\n", s.MinCycleRxDiff)
			s.StartRxTime += uint64(s.MinCycleRxDiff)
		}
		s.MinCycleRxDiff = 0x7fffffff
		s.NextCycle += UsecPerCycle
	}

	// schedule this for an ack next time we send the packet
	s.Tx.Acks[s.NextTxAckIndex] = Ack{ID: id, RxTime: uint32(rxtime)}
	s.NextTxAckIndex = (s.NextTxAckIndex + 1) % NumAcks

	// see which of our own transmitted packets have been acked
	firstAck := int(s.Rx.FirstAck)
	for i := 0; i < NumAcks; i++ {
		acki := (firstAck + i) % NumAcks
		ackID := s.Rx.Acks[acki].ID
		if ackID == 0 {
			continue // empty slot
		}
		if diff(ackID, s.NextRxAckID) < 0 {
			continue
		}
		// an expected ack
		startTxTime := uint32(s.NextSend) - s.NextTxID*uint32(s.UsecPerPkt)
		ackTxTime := startTxTime + ackID*uint32(s.UsecPerPkt)
		remoteRxTime := s.Rx.Acks[acki].RxTime
		// note: already contains 1/2 rtt, unlike rxdiff
		ackRxTime := remoteRxTime + uint32(offset)
		txdiff := diff(ackRxTime, ackTxTime)
		if !s.Quiet && s.UsecPerPrint <= 0 && s.LastAckInfo != "" {
			// only print multiple acks per rx if no UsecPerPrint limit
			if s.WantTimestamps {
				printTimestamp(os.Stdout, uint64(ackRxTime))
			}
			fmt.Printf("%12s\n", s.LastAckInfo)
			s.LastAckInfo = ""
		}
		if s.LastAckInfo == "" {
			s.LastAckInfo = fmt.Sprintf("%6.1f ms tx", float64(txdiff)/1000.0)
		}
		s.NextRxAckID = ackID + 1
		s.LatTxCount++
		s.LatTx = int64(txdiff)
		s.LatTxMin = min(s.LatTxMin, s.LatTx)
		s.LatTxMax = max(s.LatTxMax, s.LatTx)
		s.LatTxSum += s.LatTx
		s.LatTxVarSum += s.LatTx * s.LatTx
	}

	s.LastRxTime = uint32(rxtime)
}

// printTimestamp writes the wall-clock-style timestamp corresponding to
// when, deliberately in the same format tcpdump uses so isoping and tcpdump
// output can be sorted and correlated by hand.
//
// Note this reproduces the original's behavior of feeding a monotonic
// (not wall-clock) microsecond count through a wall-clock formatter, which
// does not produce a meaningful time of day; it's kept as-is for parity
// with the C implementation's print_timestamp().
func printTimestamp(w *os.File, when uint64) {
	t := time.Unix(int64(when/1000000), 0)
	fmt.Fprintf(w, "%02d:%02d:%02d.%06d ", t.Hour(), t.Minute(), t.Second(), when%1000000)
}
