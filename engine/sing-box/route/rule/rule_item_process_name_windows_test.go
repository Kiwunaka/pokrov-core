package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessNameMatchesWindowsExecutableRegardlessOfCase(t *testing.T) {
	rule := NewProcessItem([]string{"discord.exe"})
	if !rule.Match(&adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{ProcessPath: `C:\Users\Tester\AppData\Local\Discord\app-1.0.0\Discord.exe`},
	}) {
		t.Fatal("Discord.exe did not match selected discord.exe")
	}
}
