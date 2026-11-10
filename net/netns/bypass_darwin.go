// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

// rtfIfscope is RTF_IFSCOPE, which x/sys/unix does not define on all BSDs.
const rtfIfscope = 0x1000000

// bypassControlDarwin is controlLogf's replacement in foreign tunnel bypass
// mode; see SetBypassForeignTunnels.
func bypassControlDarwin(logf logger.Logf, network, address string, c syscall.RawConn) error {
	routes, err := darwinBypassRoutes()
	if err != nil {
		bypassLog.logf(logf, "netns: bypass: reading routes: %v; leaving sockets unbound", err)
		return nil
	}
	via, ok := bypassRoutedVia(routes, address)
	if !ok {
		return nil // no route; let the kernel report it
	}
	idx, bind := bypassInterface(routes, via)
	if !bind {
		bypassLog.logf(logf, "netns: bypass: no foreign tunnel in the way; not binding")
		return nil
	}
	bypassLog.logf(logf, "netns: bypass: foreign tunnel present; binding to if %d", idx)
	return bindConnToInterface(c, network, address, int(idx), logf)
}

// isVirtualDarwin reports whether a macOS interface name is a tunnel/VPN
// rather than a physical NIC.
func isVirtualDarwin(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "tun", "tap", "gif", "stf"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// darwinBypassRoutes reads the IPv4 routing table.
func darwinBypassRoutes() ([]bypassRoute, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("route.ParseRIB: %w", err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make(map[int]string, len(ifs))
	for _, ifc := range ifs {
		names[ifc.Index] = ifc.Name
	}

	var out []bypassRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
			continue
		}
		if len(rm.Addrs) <= unix.RTAX_DST {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		bits := 32
		if rm.Flags&unix.RTF_HOST == 0 {
			if len(rm.Addrs) <= unix.RTAX_NETMASK {
				continue
			}
			mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
			if !ok {
				continue
			}
			ones, total := net.IPMask(mask.IP[:]).Size()
			if total == 0 {
				continue // non-contiguous mask
			}
			bits = ones
		}
		prefix, err := netip.AddrFrom4(dst.IP).Prefix(bits)
		if err != nil {
			continue
		}
		out = append(out, bypassRoute{
			Prefix:  prefix,
			IfIndex: uint32(rm.Index),
			Virtual: isVirtualDarwin(names[rm.Index]),
			Scoped:  rm.Flags&rtfIfscope != 0,
		})
	}
	return out, nil
}
