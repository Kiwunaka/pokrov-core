package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// EnrollMASQUEKey switches a newly registered, client-owned device to MASQUE.
func (api *CloudflareApi) EnrollMASQUEKey(ctx context.Context, token, id, publicKey string) (*CloudflareProfile, error) {
	body, err := json.Marshal(map[string]string{"name": "POKROV", "key": publicKey, "key_type": "secp256r1", "tunnel_type": "masque"})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, "https://api.cloudflareclient.com/v0a4471/reg/"+id, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "WARP for Android")
	request.Header.Set("CF-Client-Version", "a-6.35-4471")
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := api.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WARP MASQUE registration returned status %d", response.StatusCode)
	}
	var profile CloudflareProfile
	if err = json.NewDecoder(response.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("WARP MASQUE registration response is invalid")
	}
	return &profile, nil
}
