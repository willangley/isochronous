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
	"math"
	"net/netip"
	"testing"
)

// assertEq mirrors wvtest's WVPASSEQ numeric-comparison semantics: WvTest's
// int/int overload of start_check_eq (wvtest.h) takes plain `int`
// parameters, so in the original C++ test suite every numeric WVPASSEQ
// comparison is implicitly truncated to a 32-bit signed int before
// comparing, regardless of the operands' original C++ types (uint32_t,
// uint64_t, ...). Both sides here are computed with plain Go int64
// arithmetic (wide enough to never overflow at these microsecond
// magnitudes) and truncated to int32 only at the comparison itself,
// reproducing that exact behavior without needing to replicate C's
// intermediate integer-promotion rules at every sub-expression.
func assertEq(t *testing.T, name string, got, want int64) {
	t.Helper()
	g, w := int32(got), int32(want)
	if g != w {
		t.Errorf("%s = %d, want %d", name, g, w)
	}
}

// sendNextAckPacket sends one packet from a synthetic latency of latency
// microseconds after from's current NextSend, and delivers it to to via
// HandleAckPacket, without any real socket. Corresponds to
// send_next_ack_packet() in the C test suite.
func sendNextAckPacket(from *Session, fromBase uint64, to *Session, toBase uint64, latency uint32) uint32 {
	tt := from.NextSend - fromBase
	PrepareTxPacket(from)
	to.Rx = from.Tx
	from.NextSend += uint64(from.UsecPerPkt)
	tt += uint64(latency)
	HandleAckPacket(to, toBase+tt)
	return uint32(tt)
}

func TestAlgorithmLogic(t *testing.T) {
	const cbase uint64 = 400 * 1000
	const sbase uint64 = 600 * 1000
	const realClockdiff = int64(sbase - cbase)
	const usecPerPkt = 100 * 1000

	c := newSession(cbase, usecPerPkt, netip.AddrPort{}, 0, false, false)
	s := newSession(sbase, usecPerPkt, netip.AddrPort{}, 0, false, false)
	c.HandshakeState = Established
	s.HandshakeState = Established

	const csLatency uint32 = 24 * 1000
	const scLatency uint32 = 25 * 1000
	halfRtt := int64((scLatency + csLatency) / 2)

	// Send the initial packet from client to server. This isn't enough to
	// let us draw any useful latency conclusions.
	tt := sendNextAckPacket(c, cbase, s, sbase, csLatency)
	rxtime := uint32(sbase + uint64(tt))
	s.NextSend = uint64(rxtime) + 10*1000

	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), 0)
	assertEq(t, "s.LastRxTime", int64(s.LastRxTime), int64(rxtime))
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), 0)
	assertEq(t, "s.Tx.Acks[0].ID", int64(s.Tx.Acks[0].ID), 1)
	assertEq(t, "s.NextTxAckIndex", int64(s.NextTxAckIndex), 1)
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].ID", int64(s.Tx.Acks[s.Tx.FirstAck].ID), 1)
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].RxTime", int64(s.Tx.Acks[s.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(rxtime)-int64(c.UsecPerPkt))
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.NextSend", int64(s.NextSend), int64(rxtime)+10*1000)

	// Reply to the client.
	tt = sendNextAckPacket(s, sbase, c, cbase, scLatency)

	// Now we have enough data to figure out latencies on the client.
	rxtime = uint32(cbase + uint64(tt))
	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), int64(rxtime)-int64(s.UsecPerPkt))
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+int64(csLatency)+10*1000-int64(s.UsecPerPkt))
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), 0)
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+int64(csLatency))
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].ID", int64(c.Tx.Acks[c.Tx.FirstAck].ID), 1)
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].RxTime", int64(c.Tx.Acks[c.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "c.NumLost", int64(c.NumLost), 0)
	assertEq(t, "c.LatTxCount", c.LatTxCount, 1)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt)
	assertEq(t, "c.LatRxCount", c.LatRxCount, 1)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt)
	assertEq(t, "c.NumLost", int64(c.NumLost), 0)

	// Round 2.
	tt = sendNextAckPacket(c, cbase, s, sbase, csLatency)
	rxtime = uint32(sbase + uint64(tt))

	// Now the server also knows latencies.
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(sbase)+int64(csLatency)-int64(s.UsecPerPkt))
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].ID", int64(s.Tx.Acks[s.Tx.FirstAck].ID), 2)
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].RxTime", int64(s.Tx.Acks[s.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)
	assertEq(t, "s.LatTxCount", s.LatTxCount, 1)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt)
	assertEq(t, "s.LatRxCount", s.LatRxCount, 1)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt)
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)

	// Increase the latencies in both directions, reply to client.
	latencyDiff := int64(10 * 1000)
	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(int64(scLatency)+latencyDiff))

	rxtime = uint32(cbase + uint64(tt))
	assertEq(t, "s.Tx.ClockDiff", int64(s.Tx.ClockDiff), realClockdiff+int64(csLatency))
	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), int64(rxtime)-int64(s.Tx.ID)*int64(s.UsecPerPkt)-latencyDiff)
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+int64(csLatency)+10*1000-int64(s.UsecPerPkt))
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].ID", int64(c.Tx.Acks[c.Tx.FirstAck].ID), 2)
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].RxTime", int64(c.Tx.Acks[c.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "c.NumLost", int64(c.NumLost), 0)
	assertEq(t, "c.LatTxCount", c.LatTxCount, 2)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt)
	assertEq(t, "c.LatRxCount", c.LatRxCount, 2)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt+latencyDiff)
	assertEq(t, "c.NumLost", int64(c.NumLost), 0)

	// Client replies with increased latency, server notices.
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(int64(csLatency)+latencyDiff))

	rxtime = uint32(sbase + uint64(tt))
	assertEq(t, "c.Tx.ClockDiff", int64(c.Tx.ClockDiff), -realClockdiff+int64(scLatency))
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(sbase)+int64(csLatency)-int64(s.UsecPerPkt))
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].ID", int64(s.Tx.Acks[s.Tx.FirstAck].ID), 3)
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].RxTime", int64(s.Tx.Acks[s.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)
	assertEq(t, "s.LatTxCount", s.LatTxCount, 2)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt+latencyDiff)
	assertEq(t, "s.LatRxCount", s.LatRxCount, 2)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+latencyDiff)
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)

	// Lose a server->client packet, send the next client->server packet,
	// verify only the received packets were acked.
	s.NextSend += uint64(s.UsecPerPkt)
	s.NextTxID++

	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(int64(csLatency)+latencyDiff))

	rxtime = uint32(sbase + uint64(tt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].ID", int64(s.Tx.Acks[s.Tx.FirstAck].ID), 3)
	assertEq(t, "s.Tx.Acks[s.Tx.FirstAck].RxTime", int64(s.Tx.Acks[s.Tx.FirstAck].RxTime), int64(rxtime)-int64(s.UsecPerPkt))
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)
	assertEq(t, "s.LatTxCount", s.LatTxCount, 2)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt+latencyDiff)
	assertEq(t, "s.LatRxCount", s.LatRxCount, 3)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+latencyDiff)
	assertEq(t, "s.NumLost", int64(s.NumLost), 0)

	// Remove the extra latency from server->client, send the next packet,
	// have the client receive it and notice the lost packet and reduced
	// latency.
	tt = sendNextAckPacket(s, sbase, c, cbase, scLatency)

	rxtime = uint32(cbase + uint64(tt))
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].ID", int64(c.Tx.Acks[c.Tx.FirstAck].ID), 4)
	assertEq(t, "c.Tx.Acks[c.Tx.FirstAck].RxTime", int64(c.Tx.Acks[c.Tx.FirstAck].RxTime), int64(rxtime))
	assertEq(t, "c.NumLost", int64(c.NumLost), 1)
	assertEq(t, "c.LatTxCount", c.LatTxCount, 4)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+latencyDiff)
	assertEq(t, "c.LatRxCount", c.LatRxCount, 3)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt)
	assertEq(t, "c.NumLost", int64(c.NumLost), 1)

	// A tiny reduction in latency shows up in MinCycleRxDiff.
	latencyDiff = 0
	latencyMiniDiff := int64(-15)
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(int64(csLatency)+latencyMiniDiff))

	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), latencyMiniDiff)
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(sbase)+int64(csLatency)-int64(s.UsecPerPkt))
	assertEq(t, "s.LatTx", s.LatTx, halfRtt)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+latencyMiniDiff)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(int64(scLatency)+latencyMiniDiff))

	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), latencyMiniDiff)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+latencyMiniDiff)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt+latencyMiniDiff)

	// Reduce the latency dramatically, verify that both sides see it, and
	// the start time is modified (not MinCycleRxDiff).
	latencyDiff = -22 * 1000
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(int64(csLatency)+latencyDiff))

	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), latencyMiniDiff)
	// We see half the latency diff applied to each side of the connection
	// because the reduction in latency creates a time paradox, rebasing the
	// start time and recalculating the RTT.
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(sbase)+int64(csLatency)+latencyDiff-int64(s.UsecPerPkt))
	assertEq(t, "s.LatTx", s.LatTx, halfRtt+latencyDiff/2+latencyMiniDiff)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+latencyDiff/2)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(int64(scLatency)+latencyDiff))

	// Now we see the new latency applied to both sides.
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency))
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), latencyMiniDiff)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+latencyDiff)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt+latencyDiff)

	// Restore latency on one side of the connection, verify that we track
	// it on only one side and we've improved our clock sync.
	tt = sendNextAckPacket(c, cbase, s, sbase, csLatency)

	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+int64(scLatency)+latencyDiff)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt+latencyDiff)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt)

	// And double-check that the other side also sees the improved clock
	// sync and one-sided latency on the correct side.
	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(int64(scLatency)+latencyDiff))

	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+int64(csLatency)+latencyDiff)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt+latencyDiff)
	_ = tt
}

// Verify that isoping handles clocks ticking at different rates.
func TestClockDrift(t *testing.T) {
	const cbase uint64 = 1400 * 1000
	const sbase uint64 = 1600 * 1000
	const usecPerPktInit = 100 * 1000

	c := newSession(cbase, usecPerPktInit, netip.AddrPort{}, 0, false, false)
	s := newSession(sbase, usecPerPktInit, netip.AddrPort{}, 0, false, false)
	c.HandshakeState = Established
	s.HandshakeState = Established
	// Send packets infrequently, to get new cycles more often.
	s.UsecPerPkt = 1 * 1000 * 1000
	c.UsecPerPkt = 1 * 1000 * 1000

	// One-way latencies: csLatency is the latency from client to server;
	// scLatency is from server to client.
	csLatency := int64(4 * 1000)
	scLatency := int64(5 * 1000)
	driftPerRound := int64(15)
	halfRtt := (scLatency + csLatency) / 2

	// Perform the initial setup.
	c.NextSend = cbase
	tt := sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency))
	s.NextSend = sbase + uint64(tt) + 10*1000

	origServerStartRxtime := int64(s.StartRxTime)
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), int64(sbase)+csLatency-int64(s.UsecPerPkt))
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), 0)
	assertEq(t, "s.LatRx", s.LatRx, 0)
	assertEq(t, "s.LatTx", s.LatTx, 0)
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), 0)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency))

	origClientStartRxtime := int64(c.StartRxTime)
	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), int64(cbase)+2*halfRtt+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+csLatency+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+csLatency)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt)
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), 0)

	// Clock drift shows up as symmetric changes in one-way latency.
	totalDrift := driftPerRound
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency+totalDrift))

	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), origServerStartRxtime)
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+scLatency)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+totalDrift)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt)
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), 0)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency-totalDrift))

	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), int64(cbase)+2*halfRtt+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+csLatency+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+csLatency)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt-totalDrift)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+totalDrift)
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), -driftPerRound)

	// Once we exceed -20us of drift, we adjust the client's StartRxTime.
	totalDrift += driftPerRound
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency+totalDrift))

	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), origServerStartRxtime)
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+scLatency)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+totalDrift)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt-driftPerRound)
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), 0)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency-totalDrift))

	clockAdj := totalDrift
	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), int64(cbase)+2*halfRtt+10*1000-int64(c.UsecPerPkt)-totalDrift)
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+csLatency+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+csLatency)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt-driftPerRound)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+driftPerRound)
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), -driftPerRound)

	// Skip ahead to the next cycle.
	packetsToSkip := int64(8)
	s.NextSend += uint64(packetsToSkip) * uint64(s.UsecPerPkt)
	s.NextRxID += uint32(packetsToSkip)
	s.NextTxID += uint32(packetsToSkip)
	c.NextSend += uint64(packetsToSkip) * uint64(c.UsecPerPkt)
	c.NextRxID += uint32(packetsToSkip)
	c.NextTxID += uint32(packetsToSkip)
	totalDrift += packetsToSkip * driftPerRound

	// At first we blame the rx latency for most of the drift.
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency+totalDrift))

	// StartRxTime doesn't change here, as the first cycle suppresses
	// positive MinCycleRxDiff values.
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), origServerStartRxtime)
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+scLatency-clockAdj)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+totalDrift-driftPerRound)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt-driftPerRound)
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), math.MaxInt32)

	// After one round-trip, we divide the blame for the latency diff
	// evenly.
	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency-totalDrift))

	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), origClientStartRxtime-totalDrift)
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+csLatency+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+csLatency)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt-totalDrift/2)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+totalDrift/2)
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), math.MaxInt32)

	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency+totalDrift))

	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), origServerStartRxtime)
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+scLatency-totalDrift)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+totalDrift/2)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt-totalDrift/2)
	// We also notice the difference in expected arrival times on the
	// server...
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), totalDrift)

	totalDrift += driftPerRound
	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency-totalDrift))
	// And on the client. The client doesn't notice the totalDrift rxdiff,
	// as it was swallowed by the new cycle.
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), -driftPerRound)

	// Skip ahead to the next cycle.
	packetsToSkip = 8
	s.NextSend += uint64(packetsToSkip) * uint64(s.UsecPerPkt)
	s.NextRxID += uint32(packetsToSkip)
	s.NextTxID += uint32(packetsToSkip)
	c.NextSend += uint64(packetsToSkip) * uint64(c.UsecPerPkt)
	c.NextRxID += uint32(packetsToSkip)
	c.NextTxID += uint32(packetsToSkip)
	totalDrift += packetsToSkip * driftPerRound
	driftPerCycle := 10 * driftPerRound
	tt = sendNextAckPacket(c, cbase, s, sbase, uint32(csLatency+totalDrift))

	// The clock drift has worked its way into the RTT calculation.
	halfRtt = (csLatency + scLatency - driftPerCycle) / 2

	// Now StartRxTime has updated.
	assertEq(t, "s.StartRxTime", int64(s.StartRxTime), origServerStartRxtime+driftPerCycle)
	assertEq(t, "s.StartRtxTime", int64(s.StartRtxTime), int64(cbase)-int64(c.UsecPerPkt))
	assertEq(t, "s.Rx.ClockDiff", int64(s.Rx.ClockDiff), int64(cbase)-int64(sbase)+scLatency-driftPerCycle)
	assertEq(t, "s.LatRx", s.LatRx, halfRtt+totalDrift)
	assertEq(t, "s.LatTx", s.LatTx, halfRtt-driftPerRound)
	assertEq(t, "s.MinCycleRxDiff", int64(s.MinCycleRxDiff), math.MaxInt32)

	tt = sendNextAckPacket(s, sbase, c, cbase, uint32(scLatency-totalDrift))

	assertEq(t, "c.StartRxTime", int64(c.StartRxTime), origClientStartRxtime-totalDrift)
	assertEq(t, "c.StartRtxTime", int64(c.StartRtxTime), int64(sbase)+csLatency+10*1000-int64(c.UsecPerPkt))
	assertEq(t, "c.Rx.ClockDiff", int64(c.Rx.ClockDiff), int64(sbase)-int64(cbase)+csLatency+driftPerCycle)
	assertEq(t, "c.LatRx", c.LatRx, halfRtt+driftPerRound/2)
	assertEq(t, "c.LatTx", c.LatTx, halfRtt+totalDrift/2+1)
	assertEq(t, "c.MinCycleRxDiff", int64(c.MinCycleRxDiff), math.MaxInt32)
	_ = tt
}
