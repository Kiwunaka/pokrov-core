package libbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/byteformats"
)

var (
	sBasePath                string
	sWorkingPath             string
	sTempPath                string
	sSlipstreamClientPath    atomic.Pointer[string]
	sUserID                  int
	sGroupID                 int
	sFixAndroidStack         bool
	sCommandServerListenPort uint16
	sCommandServerSecret     string
	sLogMaxLines             int
	sDebug                   bool
)

func init() {
	debug.SetPanicOnFault(true)
	debug.SetTraceback("all")
}

type SetupOptions struct {
	BasePath                string
	WorkingPath             string
	TempPath                string
	SlipstreamClientPath    string
	FixAndroidStack         bool
	CommandServerListenPort int32
	CommandServerSecret     string
	LogMaxLines             int
	Debug                   bool
}

func Setup(options *SetupOptions) error {
	sBasePath = options.BasePath
	sWorkingPath = options.WorkingPath
	sTempPath = options.TempPath
	if err := SetSlipstreamClientPath(options.SlipstreamClientPath); err != nil {
		return err
	}

	sUserID = os.Getuid()
	sGroupID = os.Getgid()

	// TODO: remove after fixed
	// https://github.com/golang/go/issues/68760
	sFixAndroidStack = options.FixAndroidStack

	sCommandServerListenPort = uint16(options.CommandServerListenPort)
	sCommandServerSecret = options.CommandServerSecret
	sLogMaxLines = options.LogMaxLines
	sDebug = options.Debug

	os.MkdirAll(sWorkingPath, 0o777)
	os.MkdirAll(sTempPath, 0o777)
	return nil
}

// SetSlipstreamClientPath is a trusted host setup input. It affects only new
// runtime contexts; connection profiles cannot select or replace executables.
func SetSlipstreamClientPath(path string) error {
	if path != "" {
		if !filepath.IsAbs(path) {
			return errors.New("slipstream client path must be absolute")
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("slipstream bundled client is unavailable")
		}
		if !C.IsWindows && info.Mode().Perm()&0o111 == 0 {
			return errors.New("slipstream bundled client is not executable")
		}
	}
	sSlipstreamClientPath.Store(&path)
	return nil
}

func slipstreamClientPath() string {
	if path := sSlipstreamClientPath.Load(); path != nil {
		return *path
	}
	return ""
}

func SetLocale(localeId string) {
	locale.Set(localeId)
}

func Version() string {
	return C.Version
}

func FormatBytes(length int64) string {
	return byteformats.FormatKBytes(uint64(length))
}

func FormatMemoryBytes(length int64) string {
	return byteformats.FormatMemoryKBytes(uint64(length))
}

func FormatDuration(duration int64) string {
	return log.FormatDuration(time.Duration(duration) * time.Millisecond)
}

func ProxyDisplayType(proxyType string) string {
	return C.ProxyDisplayName(proxyType)
}
