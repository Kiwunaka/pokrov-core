package hcore

import (
	"github.com/Kiwunaka/POKROV-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
)

type pokrovMainServiceManager struct{}

var _ adapter.LifecycleService = (*pokrovMainServiceManager)(nil)

func (h *pokrovMainServiceManager) Name() string { return "pokrovMainServiceManager" }
func (h *pokrovMainServiceManager) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStarted {
		return service_manager.OnMainServiceStart()
	}
	return nil
}

func (h *pokrovMainServiceManager) Close() error {
	return service_manager.OnMainServiceClose()
}
