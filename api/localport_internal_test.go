package api

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDefaultGateways(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" + // default via 172.17.0.1
		"eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" + // the subnet, no gateway
		"eth1\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" + // a second network's default
		"eth1\t00000000\t010012AC\t0003\t0\t0\t9\t00000000\t0\t0\t0\n" // the same gateway again
	got := defaultGateways(table)
	want := []netip.Addr{netip.MustParseAddr("172.17.0.1"), netip.MustParseAddr("172.18.0.1")}
	if !slices.Equal(got, want) {
		t.Errorf("gateways = %v, want %v", got, want)
	}
	if g := defaultGateways("header only\n"); len(g) != 0 {
		t.Errorf("no routes = %v", g)
	}
}
