// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"tailscale.com/types/logger"
)

// bypassRoute is the platform-independent view of one routing table entry,
// as needed by foreign tunnel bypass (see SetBypassForeignTunnels).
type bypassRoute struct {
	Prefix  netip.Prefix
	IfIndex uint32
	// Virtual reports whether the route's interface is a virtual one
	// (TUN, VPN, PPP...) rather than a physical NIC.
	Virtual bool
	// Scoped reports whether the route only applies to sockets already
	// bound to its interface (macOS RTF_IFSCOPE). Scoped routes take no part
	// in normal route selection, but a scoped default route on a physical
	// interface is exactly where we want to send bypassed traffic: macOS
	// scopes the physical default route once a VPN takes over the default.
	Scoped bool
	// Metric is the effective metric (lower wins among equal prefixes).
	Metric uint32
}

// foreignTunnelCoverage is the share of the IPv4 address space a virtual
// interface must route for it to count as a foreign tunnel: half of it.
//
// Proxy TUNs route (almost) everything: Clash on Windows adds a 0.0.0.0/0;
// on macOS it adds ~70 split routes covering everything but private ranges.
// Split-tunnel VPNs route a handful of private ranges (10/8 is 1/256 of the
// space), several orders of magnitude below this threshold.
const foreignTunnelCoverage = uint64(1) << 31

// foreignTunnels returns the set of interfaces that are foreign tunnels.
func foreignTunnels(routes []bypassRoute) map[uint32]bool {
	cover := map[uint32]uint64{}
	for _, r := range routes {
		if !r.Virtual || r.Scoped || !r.Prefix.Addr().Is4() {
			continue
		}
		// Overlapping routes are double counted; that only matters for
		// pathological tables and errs toward "foreign tunnel".
		cover[r.IfIndex] += uint64(1) << (32 - r.Prefix.Bits())
	}
	var out map[uint32]bool
	for idx, n := range cover {
		if n >= foreignTunnelCoverage {
			if out == nil {
				out = map[uint32]bool{}
			}
			out[idx] = true
		}
	}
	return out
}

// physicalDefault returns the best non-virtual interface holding an IPv4
// default route. Unscoped routes are preferred over scoped ones, then the
// lowest metric wins.
func physicalDefault(routes []bypassRoute) (idx uint32, ok bool) {
	var best bypassRoute
	for _, r := range routes {
		if r.Virtual || r.Prefix.Bits() != 0 || !r.Prefix.Addr().Is4() {
			continue
		}
		if !ok || better(r, best) {
			best, ok = r, true
		}
	}
	return best.IfIndex, ok
}

func better(a, b bypassRoute) bool {
	if a.Scoped != b.Scoped {
		return !a.Scoped
	}
	return a.Metric < b.Metric
}

// lookupRoute does a longest-prefix match of addr against the unscoped
// routes, breaking ties by the lowest metric, and returns the interface.
func lookupRoute(routes []bypassRoute, addr netip.Addr) (idx uint32, ok bool) {
	addr = addr.Unmap()
	var best bypassRoute
	for _, r := range routes {
		if r.Scoped || !r.Prefix.Contains(addr) {
			continue
		}
		if !ok || r.Prefix.Bits() > best.Prefix.Bits() ||
			(r.Prefix.Bits() == best.Prefix.Bits() && r.Metric < best.Metric) {
			best, ok = r, true
		}
	}
	return best.IfIndex, ok
}

// bypassAppliesTo reports whether a socket of the given network takes part
// in foreign tunnel bypass at all. Only UDP does.
//
// The bypass exists for NAT traversal: a proxy TUN re-sends UDP from its own
// socket, so STUN reports the proxy's mapping and hole punching fails. TCP
// (DERP, HTTPS) has no such problem, and binding it to the physical NIC
// takes away the one thing the proxy is good at: on some networks direct
// TLS connections to overseas relays get reset every 30-70s (observed on a
// Windows client in China, while the same connection through the proxy was
// stable). A flapping DERP connection then also drops the disco messages
// that set up the direct path, so binding TCP costs both paths.
func bypassAppliesTo(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	}
	return false
}

// bypassRoutedVia returns the interface a socket for address would be routed
// through, as input for bypassInterface: 0 for a listening socket (empty or
// unspecified host) and for IPv6 destinations, which are judged like a
// listening socket since only the IPv4 table is consulted. ok is false when
// an IPv4 destination has no route at all.
func bypassRoutedVia(routes []bypassRoute, address string) (via uint32, ok bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() || !addr.Unmap().Is4() {
		return 0, true
	}
	return lookupRoute(routes, addr)
}

// bypassInterface decides where a socket should be bound in bypass mode.
//
// routedVia is the interface the destination would be routed through, or 0
// for a listening socket (no destination; a single UDP socket talks to every
// peer). It returns bind=false when the socket should be left alone.
func bypassInterface(routes []bypassRoute, routedVia uint32) (idx uint32, bind bool) {
	tunnels := foreignTunnels(routes)
	if len(tunnels) == 0 {
		return 0, false
	}
	if routedVia != 0 && !tunnels[routedVia] {
		// Routed via a physical interface or a split-tunnel VPN: respect it.
		return 0, false
	}
	phys, ok := physicalDefault(routes)
	if !ok {
		// Only reachable through the tunnel; binding would cut us off.
		return 0, false
	}
	return phys, true
}

// bypassLogger logs bypass decisions only when they change, since sockets
// are created on every DERP reconnect and magicsock rebind.
type bypassLogger struct {
	mu   sync.Mutex
	last string
}

var bypassLog bypassLogger

func (l *bypassLogger) logf(logf logger.Logf, format string, args ...any) {
	if logf == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	if msg == l.last {
		return
	}
	l.last = msg
	logf("%s", msg)
}
