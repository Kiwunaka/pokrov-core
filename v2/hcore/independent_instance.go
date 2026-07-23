package hcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/config"
	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box/option"
)

func getRandomAvailblePort() uint16 {
	// TODO: implement it
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func RunInstanceString(ctx context.Context, pokrovSettings *config.PokrovOptions, proxiesInput string) (*PokrovInstance, error) {
	if pokrovSettings == nil {
		pokrovSettings = config.DefaultPokrovOptions()
	}

	singconfigs, err := config.ParseConfig(ctx, &config.ReadOptions{Content: proxiesInput}, true, pokrovSettings, false)
	if err != nil {
		return nil, err
	}
	return RunInstance(ctx, pokrovSettings, singconfigs)
}

func RunInstance(ctx context.Context, pokrovSettings *config.PokrovOptions, singconfig *option.Options) (*PokrovInstance, error) {
	if pokrovSettings == nil {
		pokrovSettings = config.DefaultPokrovOptions()
	}
	pokrovSettings.EnableClashApi = false
	pokrovSettings.InboundOptions.MixedPort = getRandomAvailblePort()
	pokrovSettings.InboundOptions.EnableTun = false
	pokrovSettings.InboundOptions.EnableTunService = false
	pokrovSettings.InboundOptions.SetSystemProxy = false
	pokrovSettings.InboundOptions.TProxyPort = 0
	pokrovSettings.InboundOptions.DirectPort = 0
	pokrovSettings.InboundOptions.RedirectPort = 0
	pokrovSettings.Region = "other"
	pokrovSettings.BlockAds = false
	pokrovSettings.LogFile = "/dev/null"

	finalConfigs, err := config.BuildConfig(ctx, pokrovSettings, &config.ReadOptions{Options: singconfig})
	if err != nil {
		return nil, err
	}

	instance, err := NewService(ctx, *finalConfigs)
	if err != nil {
		return nil, err
	}

	<-time.After(250 * time.Millisecond)
	hservice := &PokrovInstance{
		StartedService: instance,
		ListenPort:     pokrovSettings.InboundOptions.MixedPort}
	hservice.PingCloudflare()
	return hservice, nil
}

// dialer, err := s.libbox.GetInstance().Router().Dialer(context.Background())

func (s *PokrovInstance) Close() error {
	return s.StartedService.CloseService()
}

func (s *PokrovInstance) GetContent(url string) (string, error) {
	return s.ContentFromURL("GET", url, 10*time.Second)
}

func (s *PokrovInstance) ContentFromURL(method string, url string, timeout time.Duration) (string, error) {
	if method == "" {
		return "", fmt.Errorf("empty method")
	}
	if url == "" {
		return "", fmt.Errorf("empty url")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", s.ListenPort), nil, proxy.Direct)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if body == nil {
		return "", fmt.Errorf("empty body")
	}

	return string(body), nil
}

func (s *PokrovInstance) PingCloudflare() (time.Duration, error) {
	return s.Ping("http://cp.cloudflare.com")
}

// func (s *PokrovService) RawConnection(ctx context.Context, url string) (net.Conn, error) {
// 	return
// }

func (s *PokrovInstance) PingAverage(url string, count int) (time.Duration, error) {
	if count <= 0 {
		return -1, fmt.Errorf("count must be greater than 0")
	}

	var sum int
	real_count := 0
	for i := 0; i < count; i++ {
		delay, err := s.Ping(url)
		if err == nil {
			real_count++
			sum += int(delay.Milliseconds())
		} else if real_count == 0 && i > count/2 {
			return -1, fmt.Errorf("ping average failed")
		}

	}
	return time.Duration(sum / real_count * int(time.Millisecond)), nil
}

func (s *PokrovInstance) Ping(url string) (time.Duration, error) {
	startTime := time.Now()
	_, err := s.ContentFromURL("HEAD", url, 4*time.Second)
	if err != nil {
		return -1, err
	}
	duration := time.Since(startTime)
	return duration, nil
}
