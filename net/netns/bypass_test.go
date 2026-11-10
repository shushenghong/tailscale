// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"net/netip"
	"testing"
)

const (
	ifWiFi  = 19 // physical
	ifTUN   = 60 // proxy TUN (Clash "Meta Tunnel")
	ifVPN   = 70 // split-tunnel corporate VPN
	ifFullV = 80 // full-tunnel corporate VPN
)

func r(prefix string, idx uint32, virtual bool, metric uint32) bypassRoute {
	return bypassRoute{Prefix: netip.MustParsePrefix(prefix), IfIndex: idx, Virtual: virtual, Metric: metric}
}

// windowsClash mirrors a real Windows routing table with Clash Verge in TUN
// mode: the TUN adds its own 0.0.0.0/0 with a lower metric than Wi-Fi.
func windowsClash() []bypassRoute {
	return []bypassRoute{
		r("0.0.0.0/0", ifWiFi, false, 35),
		r("0.0.0.0/0", ifTUN, true, 0),
		r("192.168.3.0/24", ifWiFi, false, 291),
		r("198.18.0.0/30", ifTUN, true, 256),
	}
}

// macClash mirrors a real macOS routing table with Clash Verge in TUN mode:
// the default route stays on en0, the TUN covers the public space with split
// routes that skip private ranges.
func macClash() []bypassRoute {
	rs := []bypassRoute{
		r("0.0.0.0/0", ifWiFi, false, 0),
		r("192.168.0.0/24", ifWiFi, false, 0),
	}
	for _, p := range []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6",
		"172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9",
		"173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "192.0.0.0/9", "200.0.0.0/5",
		"208.0.0.0/4", "224.0.0.0/3",
	} {
		rs = append(rs, r(p, ifTUN, true, 0))
	}
	return rs
}

func TestForeignTunnels(t *testing.T) {
	if got := foreignTunnels(windowsClash()); !got[ifTUN] || len(got) != 1 {
		t.Errorf("windows clash: got %v, want only TUN", got)
	}
	if got := foreignTunnels(macClash()); !got[ifTUN] || len(got) != 1 {
		t.Errorf("mac clash: got %v, want only TUN", got)
	}
	split := []bypassRoute{
		r("0.0.0.0/0", ifWiFi, false, 0),
		r("10.0.0.0/8", ifVPN, true, 0),
		r("172.16.0.0/12", ifVPN, true, 0),
		r("192.168.0.0/16", ifVPN, true, 0),
	}
	if got := foreignTunnels(split); len(got) != 0 {
		t.Errorf("split VPN: got %v, want none", got)
	}
}

func TestBypassInterface(t *testing.T) {
	split := append(windowsClash(), r("10.0.0.0/8", ifVPN, true, 0))
	scopedPhys := bypassRoute{Prefix: netip.MustParsePrefix("0.0.0.0/0"), IfIndex: ifWiFi, Scoped: true}

	tests := []struct {
		name     string
		routes   []bypassRoute
		dst      string // empty = listening socket
		wantIdx  uint32
		wantBind bool
	}{
		{"windows clash, listen", windowsClash(), "", ifWiFi, true},
		{"windows clash, public dst", windowsClash(), "220.191.62.229", ifWiFi, true},
		{"windows clash, LAN dst", windowsClash(), "192.168.3.7", 0, false},
		{"mac clash, listen", macClash(), "", ifWiFi, true},
		{"mac clash, public dst", macClash(), "208.111.39.38", ifWiFi, true},
		{"mac clash, LAN dst", macClash(), "192.168.0.9", 0, false},
		{"clash + split VPN, intranet relay", split, "10.1.2.3", 0, false},
		{"clash + split VPN, public dst", split, "8.8.8.8", ifWiFi, true},
		{"split VPN only, listen", []bypassRoute{
			r("0.0.0.0/0", ifWiFi, false, 0),
			r("10.0.0.0/8", ifVPN, true, 0),
		}, "", 0, false},
		{"no tunnel at all", []bypassRoute{r("0.0.0.0/0", ifWiFi, false, 0)}, "", 0, false},
		{"tunnel but no physical default", []bypassRoute{
			r("0.0.0.0/0", ifFullV, true, 0),
		}, "", 0, false},
		{"macOS full VPN scopes the physical default", []bypassRoute{
			r("0.0.0.0/0", ifFullV, true, 0),
			scopedPhys,
		}, "1.1.1.1", ifWiFi, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var via uint32
			if tc.dst != "" {
				via, _ = lookupRoute(tc.routes, netip.MustParseAddr(tc.dst))
			}
			idx, bind := bypassInterface(tc.routes, via)
			if idx != tc.wantIdx || bind != tc.wantBind {
				t.Errorf("got (%d, %v), want (%d, %v)", idx, bind, tc.wantIdx, tc.wantBind)
			}
		})
	}
}

func TestLookupRoute(t *testing.T) {
	rs := windowsClash()
	// Equal /0 prefixes: the lower metric (the TUN) wins, as on Windows.
	if idx, _ := lookupRoute(rs, netip.MustParseAddr("8.8.8.8")); idx != ifTUN {
		t.Errorf("public: got %d, want TUN", idx)
	}
	if idx, _ := lookupRoute(rs, netip.MustParseAddr("192.168.3.1")); idx != ifWiFi {
		t.Errorf("LAN: got %d, want Wi-Fi", idx)
	}
	if idx, _ := lookupRoute(rs, netip.MustParseAddr("::ffff:192.168.3.1")); idx != ifWiFi {
		t.Errorf("v4-mapped LAN: got %d, want Wi-Fi", idx)
	}
}

func TestBypassAppliesToUDPOnly(t *testing.T) {
	for _, n := range []string{"udp", "udp4", "udp6"} {
		if !bypassAppliesTo(n) {
			t.Errorf("bypassAppliesTo(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"tcp", "tcp4", "tcp6", "ip4:icmp", ""} {
		if bypassAppliesTo(n) {
			t.Errorf("bypassAppliesTo(%q) = true, want false", n)
		}
	}
}
