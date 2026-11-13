package vk

import "context"

// CaptchaSolver is supplied by the owning native host. Challenge URLs and
// one-shot answers stay in memory and are never operational log messages.
type CaptchaSolver interface {
	SolveVkCaptcha(context.Context, string) (string, error)
}
