package urltest

import "testing"

func TestResolveURLTestLinkUsesOwnedProbeByDefault(t *testing.T) {
	const ownedProbe = "https://api.pokrov.space/api/public/authenticated-egress-probe"
	if actual := resolveURLTestLink(""); actual != ownedProbe {
		t.Fatalf("unexpected default URL-test target: %q", actual)
	}
	const explicit = "https://example.test/probe"
	if actual := resolveURLTestLink(explicit); actual != explicit {
		t.Fatalf("explicit URL-test target changed: %q", actual)
	}
}
