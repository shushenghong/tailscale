// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"net"
	"testing"
)

// TestDarwinBypassRoutes reads the live routing table and logs the bypass
// decision; it only fails if the table cannot be read or parsed.
func TestDarwinBypassRoutes(t *testing.T) {
	routes, err := darwinBypassRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	name := func(idx uint32) string {
		if ifc, err := net.InterfaceByIndex(int(idx)); err == nil {
			return ifc.Name
		}
		return "?"
	}
	for idx := range foreignTunnels(routes) {
		t.Logf("foreign tunnel: %s", name(idx))
	}
	if idx, ok := physicalDefault(routes); ok {
		t.Logf("physical default: %s", name(idx))
	}
	for _, addr := range []string{"", "8.8.8.8:443", "192.168.0.1:80"} {
		via, _ := bypassRoutedVia(routes, addr)
		idx, bind := bypassInterface(routes, via)
		t.Logf("%q: via=%s bind=%v to=%s", addr, name(via), bind, name(idx))
	}
}
