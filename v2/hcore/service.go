package hcore

import (
	"context"

	"github.com/Kiwunaka/POKROV-core/v2/config"
	box "github.com/sagernet/sing-box"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func NewService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	if err := config.ValidateProxyInbounds(&options); err != nil {
		return nil, err
	}
	if C.IsWindows {
		if trace := newOwnedDNSProbeTrace(); trace != nil {
			ctx = service.ContextWith[adapter.OwnedDNSProbeTrace](service.ExtendContext(ctx), trace)
		}
	}

	// ctx = filemanager.WithDefault(ctx, sWorkingPath, sTempPath, sUserID, sGroupID)
	logInterface := LogInterface{}
	bopts := daemon.ServiceOptions{
		Context:     ctx,
		Debug:       static.debug,
		LogMaxLines: 100,
		// Options:           *options,
		Handler: &logInterface,
		ExtraServices: []adapter.LifecycleService{
			&pokrovMainServiceManager{},
		},
	}
	err := libbox.CheckConfigOptions(&options)
	if err != nil {
		return nil, err
	}
	instance := daemon.NewStartedService(bopts)

	// for i := 0; i < 10; i++ {
	// 	if hutils.IsPortInUse(options.Inbounds[0].SocksOptions.ListenPort) {
	// 		<-time.After(100 * time.Millisecond)
	// 	}
	// }

	if err := instance.StartOrReloadServiceOptions(options); err != nil {
		_ = instance.Close()
		return nil, err
	}

	// instance.GetInstance().AddPostService("pokrovMainServiceManager", &pokrovMainServiceManager{})

	// if err := startCommandServer(instance); err != nil {
	// 	return errorWrapper(MessageType_START_COMMAND_SERVER, err)
	// }

	return instance, nil
}

func (h *PokrovInstance) UrlTestHistory() *urltest.HistoryStorage {

	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.UrlTestHistory()
}

func (h *PokrovInstance) Box() *box.Box {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Box()
}

func (h *PokrovInstance) Instance() *daemon.Instance {
	ss := h.StartedService
	if ss == nil {
		return nil
	}
	return ss.Instance()

}

func (h *PokrovInstance) Context() context.Context {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Context()
}

func (h *PokrovInstance) TrafficManager() *trafficcontrol.Manager {
	if ins := h.Instance(); ins != nil {
		return ins.TrafficManager()
	}
	return nil
}
