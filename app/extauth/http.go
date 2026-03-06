package extauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type Request struct {
	Type         string `json:"type"`
	Protocol     string `json:"protocol,omitempty"`
	ConnectionID string `json:"connection_id"`
	InboundTag   string `json:"inbound_tag,omitempty"`
	Credential   string `json:"credential"`
	SourceIP     string `json:"ip,omitempty"`
	LocalIP      string `json:"local_ip,omitempty"`
}
type Response struct {
	User *UserInfo `json:"user,omitempty"`
}

type UserInfo struct {
	Email string `json:"email"`
	Level uint32 `json:"level"`
}

var (
	ErrAuthDenied    = errors.New("extauth: auth denied")
	ErrUpstreamError = errors.New("extauth: upstream error")
)

func (i *Instance) sendRequest(ctx context.Context, req Request) (*Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", i.url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if i.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+i.secret)
	}

	client := &http.Client{Timeout: i.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrAuthDenied
	}
	if resp.StatusCode >= 500 {
		return nil, ErrUpstreamError
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var authResp Response
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	return &authResp, nil
}
