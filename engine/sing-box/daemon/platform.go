package daemon

type PlatformHandler interface {
	ServiceStop() error
	ServiceReload() error
	SystemProxyStatus() (*SystemProxyStatus, error)
	SetSystemProxyEnabled(enabled bool) error
	WriteDebugMessage(message string)
}

// OperationalEventHandler is optional. It carries only contract-owned event
// identifiers and catalog codes; arbitrary log lines never enter this seam.
type OperationalEventHandler interface {
	WriteOperationalEvent(name string, subsystem string, stage string, outcome string, errorCode string, phase string)
}
