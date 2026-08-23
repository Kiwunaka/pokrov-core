package ray2sing

import (
	"errors"

	T "github.com/sagernet/sing-box/option"
)

var errLegacyAWGConverterDisabled = errors.New("legacy raw AWG conversion is disabled; use pokrov.awg2.endpoint.v1")

func rejectLegacyAWGConfig(string) (*T.Endpoint, error) {
	return nil, errLegacyAWGConverterDisabled
}

func rejectLegacyAWGTextConfig(string) (*T.Endpoint, error) {
	return nil, errLegacyAWGConverterDisabled
}
