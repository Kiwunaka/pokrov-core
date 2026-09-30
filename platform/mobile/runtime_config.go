package mobile

import "github.com/Kiwunaka/POKROV-core/v2/config"

// NormalizeRuntimeConfig prepares a runtime copy for direct CommandServer startup.
func NormalizeRuntimeConfig(content string) (string, error) {
	normalized, err := config.NormalizeLegacyDNS([]byte(content))
	return string(normalized), err
}
