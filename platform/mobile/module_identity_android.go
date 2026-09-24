//go:build android && cgo

package mobile

import "github.com/Kiwunaka/POKROV-core/v2/hcore"

// CoreModuleSHA256 is optional metadata for the loaded Android ELF.
func CoreModuleSHA256() string { return hcore.AndroidModuleSHA256() }
