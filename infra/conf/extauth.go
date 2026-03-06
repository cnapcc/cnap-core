package conf

import (
	"github.com/xtls/xray-core/app/extauth"
	"google.golang.org/protobuf/proto"
)

type ExtAuthNotificationsConfig struct {
	Connect    bool  `json:"connect"`
	Heartbeat  int32 `json:"heartbeat"`
	Disconnect bool  `json:"disconnect"`
}

type ExtAuthConfig struct {
	Url           string                     `json:"url"`
	Secret        string                     `json:"secret"`
	Timeout       int32                      `json:"timeout"`
	Ttl           int32                      `json:"ttl"`
	Notifications ExtAuthNotificationsConfig `json:"notifications"`
}

func (c *ExtAuthConfig) Build() (proto.Message, error) {
	return &extauth.Config{
		Url:     c.Url,
		Timeout: c.Timeout,
		Ttl:     c.Ttl,
		Notifications: &extauth.Notifications{
			Connect:    c.Notifications.Connect,
			Heartbeat:  c.Notifications.Heartbeat,
			Disconnect: c.Notifications.Disconnect,
		},
		Secret: c.Secret,
	}, nil
}
