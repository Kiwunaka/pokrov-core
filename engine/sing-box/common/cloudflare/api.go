package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/tidwall/gjson"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type CloudflareApi struct {
	client http.Client
}

const baseUrl = "https://api.cloudflareclient.com/v0i1909051800/"
const cloudflareAPIUserAgent = "okhttp/3.12.1"

func NewCloudflareApiDetour(detour N.Dialer) *CloudflareApi {
	opts := make([]CloudflareApiOption, 0, 1)
	if detour != nil {
		opts = append(opts, WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	return NewCloudflareApi(opts...)
}
func NewCloudflareApi(opts ...CloudflareApiOption) *CloudflareApi {
	api := &CloudflareApi{http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(api)
	}
	return api
}

func (api *CloudflareApi) CreateProfile(ctx context.Context, publicKey string) (*CloudflareProfile, error) {
	request, err := newCloudflareRequest(ctx, http.MethodPost, baseUrl+"reg", strings.NewReader(
		fmt.Sprintf(
			"{\"install_id\":\"\",\"tos\":\"%s\",\"key\":\"%s\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}",
			time.Now().Format("2006-01-02T15:04:05.000Z"),
			publicKey,
		),
	))
	if err != nil {
		return nil, err
	}
	response, err := api.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare registration returned status %d", response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	result := gjson.GetBytes(content, "result")
	if !result.Exists() || !result.IsObject() {
		return nil, fmt.Errorf("cloudflare registration response has no result")
	}
	profile := new(CloudflareProfile)
	return profile, json.Unmarshal([]byte(result.Raw), profile)
}

func (api *CloudflareApi) GetProfile(ctx context.Context, authToken string, id string) (*CloudflareProfile, error) {
	request, err := newCloudflareRequest(ctx, http.MethodGet, baseUrl+"reg/"+id, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	response, err := api.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare profile returned status %d", response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	profile := new(CloudflareProfile)
	return profile, json.NewDecoder(strings.NewReader(gjson.Get(string(content), "result").Raw)).Decode(profile)
}

func (api *CloudflareApi) UpdateAccount(ctx context.Context, profile *CloudflareProfile, license string) (*CloudflareProfile, error) {
	deviceId := profile.ID
	authToken := profile.Token
	request, err := newCloudflareRequest(ctx, http.MethodPost, fmt.Sprint(baseUrl, "reg/", deviceId, "/account"), strings.NewReader(
		fmt.Sprintf("{\"license\":\"%s\"}", license),
	))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	response, err := api.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare account update returned status %d", response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	ia := new(IdentityAccount)
	if err := json.Unmarshal([]byte(content), ia); err != nil {
		return nil, err
	}

	profile.Account = *ia
	return profile, nil
}

func (api *CloudflareApi) CreateProfileLicense(ctx context.Context, privateKey string, license string) (*CloudflareProfile, error) {
	var wgKey wgtypes.Key
	var err error
	if privateKey != "" {
		wgKey, err = wgtypes.ParseKey(privateKey)
		if err != nil {

			return nil, err
		}
	} else {
		wgKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {

			return nil, err
		}
	}
	profile, err := api.CreateProfile(ctx, wgKey.PublicKey().String())
	if err != nil {
		return nil, err
	}
	profile.Config.PrivateKey = wgKey.String()
	if license == "" {
		return profile, nil
	}
	return api.UpdateAccount(ctx, profile, license)
}

func (api *CloudflareApi) DeleteProfile(ctx context.Context, profile *CloudflareProfile) error {
	request, err := newCloudflareRequest(ctx, http.MethodDelete, fmt.Sprint(baseUrl, "reg/", profile.ID), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+profile.Token)
	response, err := api.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare profile deletion returned status %d", response.StatusCode)
	}
	return nil
}

func newCloudflareRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", cloudflareAPIUserAgent)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}
