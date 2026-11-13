// Adapted from cacggghp/vk-turn-proxy v1.8.3 (GPL-3.0).
package vk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	M "github.com/sagernet/sing/common/metadata"
)

type authResponse struct {
	Data struct {
		Token string `json:"access_token"`
	} `json:"data"`
	Response struct {
		Token string `json:"token"`
	} `json:"response"`
	SessionKey string `json:"session_key"`
	Turn       struct {
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
		URLs       []string `json:"urls"`
	} `json:"turn_server"`
	Error *struct {
		Code     int             `json:"error_code"`
		Redirect string          `json:"redirect_uri"`
		SID      json.RawMessage `json:"captcha_sid"`
		TS       json.RawMessage `json:"captcha_ts"`
	} `json:"error"`
}

type turnCredentials struct {
	username, password, address string
	expiresAt                   time.Time
}

func (h *Outbound) credentials(ctx context.Context) (string, string, string, error) {
	// Match the upstream ten-minute grant with its one-minute safety margin.
	// The owning outbound gate serializes this cache and connection setup.
	if c := h.credentialsCache; c != nil && time.Now().Before(c.expiresAt) {
		return c.username, c.password, c.address, nil
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return h.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
	}, TLSHandshakeTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(endpoint string, values url.Values) (*authResponse, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, errors.New("VK authentication request unavailable")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		response, err := client.Do(req)
		if err != nil {
			cause := "connection failed"
			switch text := strings.ToLower(err.Error()); {
			case strings.Contains(text, "certificate"):
				cause = "certificate verification failed"
			case strings.Contains(text, "timeout"), strings.Contains(text, "deadline"):
				cause = "connection timed out"
			case strings.Contains(text, "eof"):
				cause = "connection closed"
			case strings.Contains(text, "resolve"), strings.Contains(text, "lookup"):
				cause = "DNS resolution failed"
			}
			return nil, errors.New("VK authentication " + cause)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("VK authentication rejected the request")
		}
		var decoded authResponse
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
			return nil, errors.New("invalid VK authentication response")
		}
		return &decoded, nil
	}
	response, err := request("https://login.vk.ru/?act=get_anonym_token", url.Values{
		"client_id": {vkClientID}, "client_secret": {vkClientSecret}, "token_type": {"messages"}, "version": {"1"}, "app_id": {vkClientID},
	})
	if err != nil {
		return "", "", "", err
	}
	if response.Data.Token == "" {
		return "", "", "", errors.New("VK anonymous login failed")
	}
	accessToken := response.Data.Token
	base := url.Values{"vk_join_link": {"https://vk.com/call/join/" + h.call}, "access_token": {accessToken}}
	preview := maps.Clone(base)
	preview.Set("fields", "photo_200")
	if _, err = request("https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+vkClientID, preview); err != nil {
		return "", "", "", err
	}
	base.Set("name", "POKROV")
	endpoint := "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=" + vkClientID
	response, err = request(endpoint, base)
	if err != nil {
		return "", "", "", err
	}
	if response.Error != nil && response.Error.Code == 14 {
		if h.solver == nil {
			return "", "", "", errors.New("VK verification requires the POKROV app")
		}
		token, err := h.solver.SolveVkCaptcha(ctx, response.Error.Redirect)
		if err != nil || token == "" {
			return "", "", "", errors.New("VK verification was cancelled")
		}
		base.Set("success_token", token)
		base.Set("captcha_key", "")
		base.Set("captcha_sid", scalarString(response.Error.SID))
		base.Set("captcha_ts", scalarString(response.Error.TS))
		base.Set("captcha_attempt", "1")
		base.Set("is_sound_captcha", "0")
		response, err = request(endpoint, base)
		if err != nil {
			return "", "", "", err
		}
	}
	if response.Error != nil || response.Response.Token == "" {
		return "", "", "", errors.New("VK call verification failed")
	}
	anonymToken := response.Response.Token
	sessionData, _ := json.Marshal(map[string]any{"version": 2, "device_id": uuid.NewString(), "client_version": 1.1, "client_type": "SDK_JS"})
	response, err = request("https://calls.okcdn.ru/fb.do", url.Values{"session_data": {string(sessionData)}, "method": {"auth.anonymLogin"}, "format": {"JSON"}, "application_key": {"CGMMEJLGDIHBABABA"}})
	if err != nil {
		return "", "", "", err
	}
	if response.SessionKey == "" {
		return "", "", "", errors.New("VK call login failed")
	}
	response, err = request("https://calls.okcdn.ru/fb.do", url.Values{"joinLink": {h.call}, "isVideo": {"false"}, "protocolVersion": {"5"}, "capabilities": {"2F7F"}, "anonymToken": {anonymToken}, "method": {"vchat.joinConversationByLink"}, "format": {"JSON"}, "application_key": {"CGMMEJLGDIHBABABA"}, "session_key": {response.SessionKey}})
	if err != nil {
		return "", "", "", err
	}
	if response.Turn.Username == "" || response.Turn.Credential == "" || len(response.Turn.URLs) == 0 {
		return "", "", "", errors.New("VK TURN access unavailable")
	}
	address := strings.Split(response.Turn.URLs[0], "?")[0]
	if !strings.HasPrefix(address, "turn:") {
		return "", "", "", errors.New("unsupported VK TURN address")
	}
	address = strings.TrimPrefix(address, "turn:")
	if _, _, err := net.SplitHostPort(address); err != nil {
		return "", "", "", errors.New("invalid VK TURN address")
	}
	h.credentialsCache = &turnCredentials{response.Turn.Username, response.Turn.Credential, address, time.Now().Add(9 * time.Minute)}
	return response.Turn.Username, response.Turn.Credential, address, nil
}

func scalarString(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return string(number)
	}
	return ""
}
