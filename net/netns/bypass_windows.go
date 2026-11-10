// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/types/logger"
)

// bypassControlWindows is controlC's replacement in foreign tunnel bypass
// mode; see SetBypassForeignTunnels.
func bypassControlWindows(logf logger.Logf, network, address string, c syscall.RawConn) error {
	if !bypassAppliesTo(network) {
		return nil // TCP follows the system routes; see bypassAppliesTo
	}
	routes, err := windowsBypassRoutes()
	if err != nil {
		bypassLog.logf(logf, "netns: bypass: reading routes: %v; leaving sockets unbound", err)
		return nil
	}
	via, ok := bypassRoutedVia(routes, address)
	if !ok {
		return nil // no route; let the stack report it
	}
	idx, bind := bypassInterface(routes, via)
	if !bind {
		bypassLog.logf(logf, "netns: bypass: no foreign tunnel in the way; not binding")
		return nil
	}
	bypassLog.logf(logf, "netns: bypass: foreign tunnel present; binding to if %d", idx)

	canV4, canV6 := false, false
	switch network {
	case "tcp", "udp":
		canV4, canV6 = true, true
	case "tcp4", "udp4":
		canV4 = true
	case "tcp6", "udp6":
		canV6 = true
	}
	// The NDIS interface index is shared by both address families.
	if canV4 {
		if err := bindSocket4(c, idx); err != nil {
			return fmt.Errorf("bindSocket4(%d): %w", idx, err)
		}
	}
	if canV6 {
		if err := bindSocket6(c, idx); err != nil {
			return fmt.Errorf("bindSocket6(%d): %w", idx, err)
		}
	}
	return nil
}

// isVirtualIfType reports whether a Windows interface type is a tunnel/VPN
// rather than a physical NIC. Wintun-based TUNs (Clash Meta, sing-box,
// WireGuard, Tailscale) report IF_TYPE_PROP_VIRTUAL; the built-in VPN client
// uses PPP and tunnel types. TAP adapters report Ethernet and cannot be told
// apart from a real NIC, so they are not covered.
func isVirtualIfType(t winipcfg.IfType) bool {
	switch t {
	case winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel, winipcfg.IfTypePPP:
		return true
	}
	return false
}

// windowsBypassRoutes reads the IPv4 routing table of interfaces that are up.
func windowsBypassRoutes() ([]bypassRoute, error) {
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	byLUID := make(map[winipcfg.LUID]*winipcfg.IPAdapterAddresses, len(ifs))
	for _, ifc := range ifs {
		if ifc.OperStatus == winipcfg.IfOperStatusUp {
			byLUID[ifc.LUID] = ifc
		}
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("GetIPForwardTable2: %w", err)
	}
	out := make([]bypassRoute, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		ifc := byLUID[row.InterfaceLUID]
		if ifc == nil {
			continue
		}
		out = append(out, bypassRoute{
			Prefix:  row.DestinationPrefix.Prefix(),
			IfIndex: row.InterfaceIndex,
			Virtual: isVirtualIfType(ifc.IfType),
			// Windows sums the route and interface metrics.
			Metric: row.Metric + ifc.Ipv4Metric,
		})
	}
	return out, nil
}
