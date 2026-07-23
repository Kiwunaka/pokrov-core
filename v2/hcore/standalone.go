package hcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/config"

	"github.com/sagernet/sing-box/option"
)

func RunStandalone(ctx context.Context, pokrovSettingPath string, configPath string, defaultConfig config.PokrovOptions) error {
	fmt.Println("Running in standalone mode")
	current, err := readAndBuildConfig(ctx, pokrovSettingPath, configPath, &defaultConfig)
	if err != nil {
		fmt.Printf("Error in read and build config %v", err)
		return err
	}

	_, err = StartService(ctx, &StartRequest{
		ConfigContent:          current.Config,
		EnableOldCommandServer: false,
		DelayStart:             false,
		EnableRawConfig:        true,
	})
	if err != nil {
		fmt.Printf("Error in start service %v", err)
		return err
	}
	go updateConfigInterval(ctx, current, pokrovSettingPath, configPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("Waiting for CTRL+C to stop\n")
	<-sigChan
	fmt.Printf("CTRL+C recived-->stopping\n")
	_, err = Stop()

	return err
}

type ConfigResult struct {
	Config              string
	RefreshInterval     int
	PokrovPokrovOptions *config.PokrovOptions
}

func readAndBuildConfig(ctx context.Context, pokrovSettingPath string, configPath string, defaultConfig *config.PokrovOptions) (ConfigResult, error) {
	var result ConfigResult

	result, err := readConfigContent(configPath)
	if err != nil {
		return result, err
	}

	pokrovconfig := config.DefaultPokrovOptions()

	if defaultConfig != nil {
		pokrovconfig = defaultConfig
	}

	if pokrovSettingPath != "" {
		pokrovconfig, err = ReadPokrovOptionsAt(pokrovSettingPath)
		if err != nil {
			return result, err
		}
	}

	result.PokrovPokrovOptions = pokrovconfig
	result.Config, err = buildStandaloneConfig(ctx, &config.ReadOptions{Content: result.Config}, result.PokrovPokrovOptions)
	if err != nil {
		return result, err
	}

	return result, nil
}

func readConfigContent(configPath string) (ConfigResult, error) {
	var content string
	var refreshInterval int

	if strings.HasPrefix(configPath, "http://") || strings.HasPrefix(configPath, "https://") {
		client := &http.Client{}

		// Create a new request
		req, err := http.NewRequest("GET", configPath, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return ConfigResult{}, err
		}
		req.Header.Set("User-Agent", "PokrovNext/4.0.0("+runtime.GOOS+") like ClashMeta v2ray sing-box")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making GET request:", err)
			return ConfigResult{}, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ConfigResult{}, fmt.Errorf("failed to read config body: %w", err)
		}
		content = string(body)
		refreshInterval, _ = extractRefreshInterval(resp.Header, content)
		fmt.Printf("Refresh interval: %d\n", refreshInterval)

	} else {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return ConfigResult{}, fmt.Errorf("failed to read config file: %w", err)
		}
		content = string(data)
	}

	return ConfigResult{
		Config:          content,
		RefreshInterval: refreshInterval,
	}, nil
}

func extractRefreshInterval(header http.Header, bodyStr string) (int, error) {
	refreshIntervalStr := header.Get("profile-update-interval")
	if refreshIntervalStr != "" {
		refreshInterval, err := strconv.Atoi(refreshIntervalStr)
		if err != nil {
			return 0, fmt.Errorf("failed to parse refresh interval from header: %w", err)
		}
		return refreshInterval, nil
	}

	lines := strings.Split(bodyStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//profile-update-interval:") || strings.HasPrefix(line, "#profile-update-interval:") {
			parts := strings.SplitN(line, ":", 2)
			str := strings.TrimSpace(parts[1])
			refreshInterval, err := strconv.Atoi(str)
			if err != nil {
				return 0, fmt.Errorf("failed to parse refresh interval from body: %w", err)
			}
			return refreshInterval, nil
		}
	}
	return 0, nil
}

func buildStandaloneConfig(ctx context.Context, ropt *config.ReadOptions, hopts *config.PokrovOptions) (string, error) {
	finalconfig, err := config.ParseBuildConfig(ctx, hopts, ropt)
	if err != nil {
		return "", fmt.Errorf("failed to parse config content: %w", err)
	}

	finalconfig.Log.Output = ""
	finalconfig.Experimental = &option.ExperimentalOptions{
		ClashAPI: &option.ClashAPIOptions{
			ExternalUI: "webui",
		},
	}
	// finalconfig.Experimental.ClashAPI.ExternalUI = "webui"
	if hopts.AllowConnectionFromLAN {
		finalconfig.Experimental.ClashAPI.ExternalController = "0.0.0.0:16756"
	} else {
		finalconfig.Experimental.ClashAPI.ExternalController = "127.0.0.1:16756"
	}

	fmt.Printf("Open http://localhost:6756/ui/?secret=%s in your browser\n", finalconfig.Experimental.ClashAPI.Secret)

	if err := Setup(
		&SetupRequest{
			BasePath:          "./",
			WorkingDir:        "./",
			TempDir:           "./tmp",
			FlutterStatusPort: 0,
			Debug:             false,
			Listen:            "127.0.0.1:17078",
			Mode:              SetupMode_GRPC_NORMAL_INSECURE,
		}, nil); err != nil {
		return "", fmt.Errorf("failed to set up global configuration: %w", err)
	}

	configStr, err := finalconfig.MarshalJSONContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to convert config to JSON: %w", err)
	}

	return string(configStr), nil
}

func updateConfigInterval(ctx context.Context, current ConfigResult, pokrovSettingPath string, configPath string) {
	if current.RefreshInterval <= 0 {
		return
	}

	for {
		<-time.After(time.Duration(current.RefreshInterval) * time.Hour)
		new, err := readAndBuildConfig(ctx, pokrovSettingPath, configPath, current.PokrovPokrovOptions)
		if err != nil {
			continue
		}
		if new.Config != current.Config {
			Stop()
			StartService(ctx, &StartRequest{
				ConfigContent:          new.Config,
				DelayStart:             false,
				EnableOldCommandServer: false,
				DisableMemoryLimit:     false,
				EnableRawConfig:        true,
			})
		}
		current = new
	}
}

func ReadPokrovOptionsAt(path string) (*config.PokrovOptions, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var options config.PokrovOptions
	err = json.Unmarshal(content, &options)
	if err != nil {
		return nil, err
	}
	if options.Warp.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(options.Warp.WireguardConfigStr), &options.Warp.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	if options.Warp2.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(options.Warp2.WireguardConfigStr), &options.Warp2.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	return &options, nil
}
