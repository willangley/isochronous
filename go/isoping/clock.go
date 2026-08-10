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

import "time"

var processStart = time.Now()

// now64 returns a monotonically increasing microsecond timestamp relative
// to an arbitrary reference point fixed at process start. It mirrors the C
// implementation's ustime64(): in particular it never returns 0 (0 is used
// as a magic "unset" value for Ack entries), relying on time.Since being
// based on the Go runtime's monotonic clock reading.
func now64() uint64 {
	d := uint64(time.Since(processStart).Microseconds())
	if d == 0 {
		return 1
	}
	return d
}

// Now returns a monotonically increasing microsecond timestamp suitable for
// passing as the `now` parameter throughout this package. Callers (notably
// cmd/isoping) are expected to call it once per event-loop iteration and
// thread the result through, the same way isoping_main() calls ustime64()
// in the C implementation rather than having each protocol function read
// the clock itself.
func Now() uint64 {
	return now64()
}

// integer is the set of types diff accepts.
type integer interface {
	~int32 | ~uint32 | ~uint64
}

// diff computes (x - y) truncated to 32 bits and interpreted as signed,
// matching the C implementation's DIFF() macro. Fields carried on the wire
// are 32-bit and intentionally wrap approximately every 71 minutes; as long
// as any two timestamps compared this way are known to be within about 35
// minutes of each other, this wraparound-safe subtraction produces the
// correct signed difference even across a wrap. x and y must be passed as
// the same type; widen the narrower operand at the call site (e.g.
// diff(now, uint64(s.LastPrint))).
func diff[T integer](x, y T) int32 {
	return int32(uint32(x) - uint32(y))
}

// diff64 computes (x - y) as a full-precision signed 64-bit difference,
// matching the C implementation's DIFF64() macro. Used for timestamps that
// are never truncated to 32 bits (e.g. Session.NextSend), where wraparound
// at 2^64 microseconds is not a practical concern.
func diff64(x, y uint64) int64 {
	return int64(x - y)
}
