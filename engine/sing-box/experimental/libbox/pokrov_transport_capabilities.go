package libbox

import "github.com/sagernet/sing-box/include"

// Pure build inventory. No configuration, resolver, tunnel or probe is started.
func TransportCapabilities() string { return include.TransportCapabilities() }
