package hcore

import (
	"context"
	"encoding/json"
	"os"

	"github.com/Kiwunaka/POKROV-core/v2/config"
	"github.com/Kiwunaka/POKROV-core/v2/db"
	hcommon "github.com/Kiwunaka/POKROV-core/v2/hcommon"
	hutils "github.com/Kiwunaka/POKROV-core/v2/hutils"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func BuildConfigJson(ctx context.Context, in *StartRequest) (string, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service ")

	parsedContent, err := BuildConfig(ctx, in)
	if err != nil {
		return "", err
	}
	res, err := parsedContent.MarshalJSONContext(ctx)
	return string(res), err
}

func BuildConfig(ctx context.Context, in *StartRequest) (*option.Options, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Building Config...")

	readOpt := &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath}
	if !in.EnableRawConfig {
		// hcontent, err := json.MarshalIndent(static.PokrovOptions, "", " ")
		// if err != nil {
		// 	return nil, err
		// }

		// Log(LogLevel_DEBUG, LogType_CORE, "Building config ", string(hcontent))
		// Log(LogLevel_DEBUG, LogType_CORE, "Building config ")
		return config.BuildConfig(ctx, static.PokrovOptions, readOpt)
	}
	return config.ReadSingOptions(ctx, readOpt)

}

func (s *CoreService) Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	return Parse(libbox.FromContext(ctx, nil), in)
}

func Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	defer config.DeferPanicToError("parse", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})

	path := in.TempPath
	if path == "" {
		path = in.ConfigPath
	}

	config, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: in.Content, Path: path}, true, static.PokrovOptions, false)
	if err != nil {
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_FAILED,
			Message:      err.Error(),
		}, err
	}
	if in.ConfigPath != "" {
		err = os.WriteFile(in.ConfigPath, config, 0o644)
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, err
		}
	}
	return &ParseResponse{
		ResponseCode: hcommon.ResponseCode_OK,
		Content:      string(config),
		Message:      "",
	}, err
}

func (s *CoreService) ChangePokrovSettings(ctx context.Context, in *ChangePokrovSettingsRequest) (*CoreInfoResponse, error) {
	return ChangePokrovSettings(in, true)
}

func ChangePokrovSettings(in *ChangePokrovSettingsRequest, insert bool) (*CoreInfoResponse, error) {
	static.PokrovOptions = config.DefaultPokrovOptions()
	defer func() {
		switch static.PokrovOptions.LogLevel {
		case "debug":
			static.logLevel = LogLevel_DEBUG
		case "info":
			static.logLevel = LogLevel_INFO
		case "warn":
			static.logLevel = LogLevel_WARNING
		case "error":
			static.logLevel = LogLevel_ERROR
		case "fatal":
			static.logLevel = LogLevel_FATAL
		case "trace":
			static.logLevel = LogLevel_TRACE
		default:
			static.logLevel = LogLevel_INFO
		}
		static.debug = static.debug || static.logLevel <= LogLevel_DEBUG
	}()

	if in.PokrovSettingsJson == "" {
		return &CoreInfoResponse{}, nil
	}
	if insert {
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "PokrovSettingsJson",
			Value: in.PokrovSettingsJson,
		})
	}

	err := json.Unmarshal([]byte(in.PokrovSettingsJson), static.PokrovOptions)
	if err != nil {
		return nil, err
	}

	if static.PokrovOptions.Warp.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.PokrovOptions.Warp.WireguardConfigStr), &static.PokrovOptions.Warp.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	if static.PokrovOptions.Warp2.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.PokrovOptions.Warp2.WireguardConfigStr), &static.PokrovOptions.Warp2.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	return &CoreInfoResponse{}, nil
}

func (s *CoreService) GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	return GenerateConfig(libbox.FromContext(ctx, nil), in)
}

func GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	defer config.DeferPanicToError("generateConfig", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	if static.PokrovOptions == nil {
		static.PokrovOptions = config.DefaultPokrovOptions()
	}
	config, err := config.ParseBuildConfigBytes(ctx, static.PokrovOptions, &config.ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}

	return &GenerateConfigResponse{
		ConfigContent: string(config),
	}, nil
}

func removeTunnelIfNeeded(options *option.Options) (tuninb *option.TunInboundOptions) {
	if hutils.TunAllowed() {
		return nil
	}

	// Create a new slice to hold the remaining inbounds
	newInbounds := make([]option.Inbound, 0, len(options.Inbounds))

	for _, inb := range options.Inbounds {
		if inb.Type == C.TypeTun {
			if d, ok := inb.Options.(option.TunInboundOptions); ok {
				tuninb = &d
			}

		} else {
			newInbounds = append(newInbounds, inb)
		}
	}

	options.Inbounds = newInbounds
	return tuninb
}
