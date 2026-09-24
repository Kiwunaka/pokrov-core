package smartaccess

import "net/netip"

// Mirrors the owned Smart DNS public-address boundary. Mapped/translated
// addresses are not alternate ways to route a lease into a private network.
func publicRelayAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Is4In6() || addr.Zone() != "" ||
		!addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() {
		return false
	}
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) { return false }
	for _, prefix := range forbiddenRelayPrefixes {
		if prefix.Contains(addr) { return false }
	}
	return true
}

var forbiddenRelayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
