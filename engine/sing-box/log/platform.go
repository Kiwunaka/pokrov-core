package log

type PlatformWriter interface {
	WriteMessage(level Level, message string)
}

// PlatformMessageFilter runs before file, observable and platform log sinks.
// A filtered message does not inherit the upstream logger's arbitrary tag.
type PlatformMessageFilter interface {
	FilterMessage(level Level, message string) string
}
