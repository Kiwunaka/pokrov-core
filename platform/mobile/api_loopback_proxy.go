package mobile

import (
	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func StartApiLoopbackProxy(boardURL, publicKey string, platformInterface libbox.PlatformInterface) (int32, error) {
	return hcore.StartApiLoopbackProxy(boardURL, publicKey, platformInterface)
}
func StopApiLoopbackProxy() { hcore.StopApiLoopbackProxy() }
