package mobile

import (
	"github.com/Kiwunaka/POKROV-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// NormalizeRuntimeConfig prepares a runtime copy for direct CommandServer startup.
func NormalizeRuntimeConfig(content string) (string, error) {
	normalized, err := config.NormalizeLegacyDNS([]byte(content))
	if err != nil {
		return "", err
	}
	var options option.Options
	if err := options.UnmarshalJSONContext(libbox.BaseContext(nil), normalized); err != nil {
		return "", err
	}
	if err := config.ValidateProxyInbounds(&options); err != nil {
		return "", err
	}
	return string(normalized), nil
}
