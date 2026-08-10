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

// Command isoping is like ping, but sends packets isochronously (equally
// spaced in time) in each direction, to determine which direction of a
// noisy network is dropping or delaying packets and by how much.
//
// Unlike ping, this requires a server (i.e. another copy of this program,
// or the original C isoping) to be running on the remote end.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/willangley/isochronous/go/isoping"
)

// defaultTTL matches isoping.cc's DEFAULT_TTL.
const defaultTTL = 32

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("isoping", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "\n"+
			"Usage: %[1]s                          (server mode)\n"+
			"   or: %[1]s <server-hostname-or-ip>  (client mode)\n"+
			"\n"+
			"      -f <lines/sec>  max output lines per second\n"+
			"      -r <pps>        packets per second (default=%g)\n"+
			"                      in server mode: the highest accepted rate.\n"+
			"      -t <ttl>        packet ttl to use (default=%d)\n"+
			"      -q              quiet mode (don't print packets)\n"+
			"      -D <dscp>       dscp value\n"+
			"      -E              enable ecn\n"+
			"      -T              print timestamps\n",
			fs.Name(), isoping.DefaultPacketsPerSec, defaultTTL)
	}

	printsPerSec := fs.Float64("f", -1, "max output lines per second")
	packetsPerSec := fs.Float64("r", isoping.DefaultPacketsPerSec, "packets per second")
	ttl := fs.Int("t", defaultTTL, "packet ttl to use")
	quiet := fs.Bool("q", false, "quiet mode (don't print packets)")
	dscp := fs.Int("D", 0, "dscp value")
	ecn := fs.Bool("E", false, "enable ecn")
	wantTimestamps := fs.Bool("T", false, "print timestamps")

	if err := fs.Parse(args); err != nil {
		return 99
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if set["f"] && *printsPerSec <= 0 {
		fmt.Fprintf(stderr, "isoping: lines per second must be >= 0\n")
		return 99
	}
	if set["r"] && (*packetsPerSec < 0.001 || *packetsPerSec > 1e6) {
		fmt.Fprintf(stderr, "isoping: packets per sec (-r) must be 0.001..1000000\n")
		return 99
	}
	if set["t"] && *ttl < 1 {
		fmt.Fprintf(stderr, "isoping: ttl must be >= 1\n")
		return 99
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return 99
	}

	usecPerPrint := int32(0)
	if *printsPerSec > 0 {
		usecPerPrint = int32(1e6 / *printsPerSec)
	}

	sessions := isoping.NewSessions()
	sessions.PacketsPerSec = *packetsPerSec
	sessions.UsecPerPrint = usecPerPrint
	sessions.Quiet = *quiet
	sessions.WantTimestamps = *wantTimestamps

	var conn *net.UDPConn
	isServer := fs.NArg() == 0
	if isServer {
		var err error
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: isoping.ServerPort})
		if err != nil {
			fmt.Fprintf(stderr, "socket: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "server listening at %s\n", conn.LocalAddr())
	} else {
		remotename := fs.Arg(0)
		fmt.Fprintf(stderr, "connecting to %s...\n", remotename)
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(remotename, strconv.Itoa(isoping.ServerPort)))
		if err != nil {
			fmt.Fprintf(stderr, "resolve %s: %v\n", remotename, err)
			return 1
		}
		conn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			fmt.Fprintf(stderr, "connect: %v\n", err)
			return 1
		}
		now := isoping.Now()
		sessions.NewSession(now, int32(1e6 / *packetsPerSec), conn.RemoteAddr().(*net.UDPAddr).AddrPort())
	}
	defer conn.Close()

	fmt.Fprintf(stderr, "using ttl=%d\n", *ttl)
	// IPv6 is the only setting that reliably works cross-platform for an
	// AF_INET6 socket; the IPv4 setting below additionally covers the case
	// where the connection ends up routed over IPv4 despite the IPv6
	// socket, which happens on Linux but not macOS.
	p6 := ipv6.NewConn(conn)
	if err := p6.SetHopLimit(*ttl); err != nil {
		fmt.Fprintf(stderr, "setsockopt(TTLv6): %v\n", err)
		return 1
	}
	p4 := ipv4.NewConn(conn)
	if err := p4.SetTTL(*ttl); err != nil && !errors.Is(err, syscall.EINVAL) {
		fmt.Fprintf(stderr, "setsockopt(TTLv4): %v\n", err)
		return 1
	}

	dscpValue := *dscp
	if *ecn {
		dscpValue |= 2
	}
	if err := p6.SetTrafficClass(dscpValue); err != nil {
		fmt.Fprintf(stderr, "setsockopt IPv6 TCLASS: %v\n", err)
	}
	if err := p4.SetTOS(dscpValue); err != nil && !errors.Is(err, syscall.EINVAL) {
		fmt.Fprintf(stderr, "setsockopt TOS: %v\n", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	// A dedicated reader goroutine turns the blocking recvfrom() loop from
	// the C implementation's single-threaded select() into a channel the
	// main loop can select over alongside the next-send timer and signals.
	// Now() is deliberately captured after RecvPacket returns, not before:
	// RecvPacket blocks for an arbitrary amount of time waiting for the next
	// packet, so timestamping beforehand would record when the wait began
	// rather than when the packet actually arrived, corrupting the
	// clock-skew math in HandleAckPacket.
	readCh := make(chan error)
	go func() {
		for {
			rx, rxAddr, err := isoping.RecvPacket(conn, isServer)
			now := isoping.Now()
			if err != nil {
				readCh <- err
				continue
			}
			readCh <- isoping.ProcessReceivedPacket(sessions, conn, rx, rxAddr, now, isServer)
		}
	}()

loop:
	for {
		now := isoping.Now()
		sessions.MaybeRotateCookieSecrets(now, isServer)
		if err := isoping.SendWaitingPackets(sessions, conn, now, isServer); err != nil {
			if errors.Is(err, isoping.ErrConnectionRefused) {
				return 2
			}
		}

		var timer *time.Timer
		var timerCh <-chan time.Time
		if nextSend := sessions.NextSendTime(); nextSend != 0 {
			d := time.Duration(int64(nextSend)-int64(now)) * time.Microsecond
			if d < 0 {
				d = 0
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}

		select {
		case err := <-readCh:
			if timer != nil {
				timer.Stop()
			}
			if err != nil && !isServer && errors.Is(err, isoping.ErrConnectionRefused) {
				return 2
			}
		case <-timerCh:
		case <-sigCh:
			if timer != nil {
				timer.Stop()
			}
			break loop
		}
	}

	if !isServer {
		printClientSummary(stdout, sessions)
	}
	return 0
}

// printClientSummary prints the final tx/rx latency summary a client shows
// on exit. Corresponds to the tail of isoping_main() in the C
// implementation.
func printClientSummary(w io.Writer, sessions *isoping.Sessions) {
	var s *isoping.Session
	for _, session := range sessions.SessionMap {
		s = session
		break
	}
	if s == nil {
		return
	}
	fmt.Fprintf(w, "\n---\n")
	fmt.Fprintf(w, "tx: min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f ms\n",
		float64(s.LatTxMin)/1000.0,
		divide(float64(s.LatTxSum), float64(s.LatTxCount))/1000.0,
		float64(s.LatTxMax)/1000.0,
		stddev(s.LatTxVarSum, s.LatTxSum, s.LatTxCount)/1000.0)
	fmt.Fprintf(w, "rx: min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f ms\n",
		float64(s.LatRxMin)/1000.0,
		divide(float64(s.LatRxSum), float64(s.LatRxCount))/1000.0,
		float64(s.LatRxMax)/1000.0,
		stddev(s.LatRxVarSum, s.LatRxSum, s.LatRxCount)/1000.0)
	fmt.Fprintf(w, "\n")
}

func divide(x, y float64) float64 {
	if y == 0 {
		return 0
	}
	return x / y
}

// stddev is an incremental (one-pass) standard deviation calculation that
// doesn't need to know the mean in advance. Corresponds to
// onepass_stddev() in the C implementation. See:
// http://mathcentral.uregina.ca/QQ/database/QQ.09.02/carlos1.html
func stddev(sumSq, sum, count int64) float64 {
	numer := count*sumSq - sum*sum
	denom := count * (count - 1)
	return math.Sqrt(divide(float64(numer), float64(denom)))
}
