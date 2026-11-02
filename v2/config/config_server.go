package config

import (
	context "context"
	"errors"
	"fmt"
	"os"

	"github.com/Kiwunaka/POKROV-core/v2/hutils"
	"github.com/sagernet/sing-box/experimental/libbox"
)

type server struct {
	UnimplementedCoreServiceServer
}

func String(s string) *string {
	return &s
}

func (s *server) ParseConfig(ctx context.Context, in *ParseConfigRequest) (resp *ParseConfigResponse, err error) {
	defer DeferPanicToError("ParseConfig", func(recovered_err error) {
		resp = &ParseConfigResponse{Error: String(fmt.Sprintf("%v", recovered_err))}
		err = nil
	})
	ctx = libbox.BaseContext(nil)
	config, err := ParseConfig(ctx, &ReadOptions{Path: in.Path}, in.Debug, nil, false)
	if err != nil {
		return &ParseConfigResponse{Error: String(err.Error())}, nil
	}
	configStr, err := config.MarshalJSONContext(ctx)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(in.Path, []byte(configStr), 0o600)
	if err != nil {
		return nil, err
	}
	if err = hutils.Chmod(in.Path, 0o600); err != nil {
		return nil, err
	}
	return &ParseConfigResponse{Error: String("")}, nil
}

func (s *server) GenerateFullConfig(ctx context.Context, in *GenerateConfigRequest) (resp *GenerateConfigResponse, err error) {
	defer DeferPanicToError("GenerateFullConfig", func(recovered_err error) {
		resp = &GenerateConfigResponse{Error: String(fmt.Sprintf("%v", recovered_err))}
		err = nil
	})
	ctx = libbox.BaseContext(nil)
	config, err := BuildConfigJson(ctx, DefaultPokrovOptions(), &ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}
	return &GenerateConfigResponse{
		Config: string(config),
	}, nil
}

func StartGRPCServer(port uint16) error {
	return errors.New("unauthenticated configuration gRPC listener is disabled")
}
