package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestOutboundMonitoringRequiresExplicitOption(t *testing.T) {
	options := &option.Options{}
	setExperimental(options, &PokrovOptions{EnableClashApi: true})
	if options.Experimental == nil || options.Experimental.Monitoring != nil {
		t.Fatal("Clash API must not enable outbound monitoring")
	}

	options = &option.Options{}
	setExperimental(options, &PokrovOptions{EnableOutboundMonitoring: true})
	if options.Experimental == nil || options.Experimental.Monitoring == nil {
		t.Fatal("explicit outbound monitoring option was ignored")
	}
}
