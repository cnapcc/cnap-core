package conf

import (
	"github.com/xtls/xray-core/app/extauth"
	"google.golang.org/protobuf/proto"
)

type ExtAuthConfig struct {
	Url        string `json:"url"`
	Timeout    int32  `json:"timeout"`
	Ttl        int32  `json:"ttl"`
	Heartbeat  int32  `json:"heartbeat"`
	Disconnect bool   `json:"disconnect"`
	Secret     string `json:"secret"`
}

func (c *ExtAuthConfig) Build() proto.Message {
	return &extauth.Config{
		Url:        c.Url,
		Timeout:    c.Timeout,
		Ttl:        c.Ttl,
		Heartbeat:  c.Heartbeat,
		Disconnect: c.Disconnect,
		Secret:     c.Secret,
	}
}
