//go:build pokrov_wintun_test

package wintun

import (
	"sync/atomic"
	"syscall"
)

// Test-only callbacks: these never load wintun.dll or call any driver API.
type PokrovFixtureProbe struct {
	Handle     uintptr
	closeCalls atomic.Int32
	lastHandle atomic.Uintptr
}

func (p *PokrovFixtureProbe) CloseCalls() int32   { return p.closeCalls.Load() }
func (p *PokrovFixtureProbe) LastHandle() uintptr { return p.lastHandle.Load() }
func (p *PokrovFixtureProbe) RealDLLLoaded() bool { return modwintun.module != nil }

func PokrovInstallFixtureProbe() *PokrovFixtureProbe {
	p := &PokrovFixtureProbe{Handle: 0x13572468}
	procWintunCreateAdapter = &lazyProc{addr: syscall.NewCallback(func(uintptr, uintptr, uintptr) uintptr { return p.Handle })}
	procWintunCloseAdapter = &lazyProc{addr: syscall.NewCallback(func(handle uintptr) uintptr {
		p.lastHandle.Store(handle)
		p.closeCalls.Add(1)
		return 1
	})}
	procWintunStartSession = &lazyProc{addr: syscall.NewCallback(func(uintptr, uintptr) uintptr { return 0 })}
	return p
}
