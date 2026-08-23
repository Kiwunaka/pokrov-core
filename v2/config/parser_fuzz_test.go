package config

import (
	"context"
	"testing"
)

func FuzzParseConfigDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		`{"outbounds":[{"type":"direct","tag":"direct"}]}`,
		`{"endpoints":[]}`,
		`proxies: []`,
		`not a profile`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseConfig(
			context.Background(),
			&ReadOptions{Content: content},
			false,
			DefaultPokrovOptions(),
			false,
		)
	})
}
