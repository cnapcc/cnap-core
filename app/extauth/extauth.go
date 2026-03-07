package extauth

import (
	"context"
	"errors"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

// ExtAuth module
type Instance struct {
	url              string
	secret           string
	timeout          time.Duration
	ttl              time.Duration
	notifyConnect    bool
	notifyHeartbeat  time.Duration
	notifyDisconnect bool
	cache            sync.Map
}

type cacheKey struct {
	credential string
	ip         string
}

type cacheEntry struct {
	user      *protocol.MemoryUser
	expiresAt time.Time
}

type connectionInfo struct {
	sourceIP     string
	localIP      string
	inboundTag   string
	protocolName string
}

func (i *Instance) getConnectionInfo(ctx context.Context) connectionInfo {
	info := connectionInfo{}
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		info.sourceIP = inbound.Source.Address.String()
		info.localIP = inbound.Local.Address.String()
		info.inboundTag = inbound.Tag
		info.protocolName = inbound.Name
	}
	return info
}

// New creates a new Instance
func New(ctx context.Context, config *Config) (*Instance, error) {
	if config == nil {
		return nil, errors.New("extauth: config is nil")
	}
	if config.Url == "" {
		return nil, errors.New("extauth: url is required")
	}

	notifications := config.Notifications
	if notifications == nil {
		notifications = &Notifications{}
	}

	instance := &Instance{
		url:              config.Url,
		secret:           config.Secret,
		timeout:          time.Duration(config.Timeout) * time.Second,
		ttl:              time.Duration(config.Ttl) * time.Second,
		notifyConnect:    notifications.Connect,
		notifyHeartbeat:  time.Duration(notifications.Heartbeat) * time.Second,
		notifyDisconnect: notifications.Disconnect,
	}

	if instance.ttl > 0 {
		go instance.janitor(ctx)
	}

	return instance, nil
}

func (i *Instance) janitor(ctx context.Context) {
	ticker := time.NewTicker(i.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			i.cache.Range(func(key, value any) bool {
				entry, ok := value.(*cacheEntry)
				if !ok || now.After(entry.expiresAt) {
					i.cache.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

// Type implements common.HasType
func (*Instance) Type() interface{} {
	return (*Instance)(nil)
}

// Start implements common.Runnable
func (i *Instance) Start() error {
	return nil
}

// Close implements common.Closable
func (i *Instance) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Connect validates credential via cache or external API
func (i *Instance) Connect(credential string, connectionID string, ctx context.Context) *protocol.MemoryUser {
	info := i.getConnectionInfo(ctx)

	var user *protocol.MemoryUser
	key := cacheKey{credential: credential, ip: info.sourceIP}

	// Check cache for authorization only
	if cached, ok := i.cache.Load(key); ok {
		entry := cached.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			user = entry.user
		} else {
			i.cache.Delete(key)
		}
	}

	// If not in cache, go to backend for authorization
	if user == nil {
		resp, err := i.sendRequest(ctx, Request{
			Type:         "authorization",
			Credential:   credential,
			ConnectionID: connectionID,
			Protocol:     info.protocolName,
			InboundTag:   info.inboundTag,
			SourceIP:     info.sourceIP,
			LocalIP:      info.localIP,
		})
		if err != nil || resp == nil || resp.User == nil {
			return nil
		}

		// Save user to cache
		user = &protocol.MemoryUser{
			Email: resp.User.Email,
			Level: resp.User.Level,
		}
		if i.ttl > 0 {
			i.cache.Store(key, &cacheEntry{
				user:      user,
				expiresAt: time.Now().Add(i.ttl),
			})
		}
	}

	if i.notifyConnect {
		req := Request{
			Type:         "connect",
			Credential:   credential,
			ConnectionID: connectionID,
			Protocol:     info.protocolName,
			InboundTag:   info.inboundTag,
			SourceIP:     info.sourceIP,
			LocalIP:      info.localIP,
		}

		// Creating new context in case of possible context close like in disconnect
		go func(r Request) {
			timeout := i.timeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			notifyCtx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, _ = i.sendRequest(notifyCtx, r)
		}(req)
	}

	if i.notifyHeartbeat > 0 || i.notifyDisconnect {
		go i.Watch(credential, connectionID, ctx)
	}

	return user
}

func (i *Instance) Watch(credential string, connectionID string, ctx context.Context) {
	if i.notifyHeartbeat <= 0 {
		<-ctx.Done()
		if i.notifyDisconnect {
			i.Disconnect(credential, connectionID, ctx)
		}
		return
	}

	ticker := time.NewTicker(i.notifyHeartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if i.notifyDisconnect {
				i.Disconnect(credential, connectionID, ctx)
			}
			return
		case <-ticker.C:
			i.Heartbeat(credential, connectionID, ctx)
		}
	}
}

func (i *Instance) Heartbeat(credential string, connectionID string, ctx context.Context) {
	info := i.getConnectionInfo(ctx)
	_, err := i.sendRequest(ctx, Request{
		Type:         "heartbeat",
		Credential:   credential,
		ConnectionID: connectionID,
		Protocol:     info.protocolName,
		InboundTag:   info.inboundTag,
		SourceIP:     info.sourceIP,
		LocalIP:      info.localIP,
	})

	if errors.Is(err, ErrAuthDenied) {
		key := cacheKey{credential: credential, ip: info.sourceIP}
		i.cache.Delete(key)
	}
}

func (i *Instance) Disconnect(credential string, connectionID string, ctx context.Context) {
	info := i.getConnectionInfo(ctx)

	// Using old context results in immediate cancellation, so create a new context with timeout
	timeout := i.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	disconnectCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	i.sendRequest(disconnectCtx, Request{
		Type:         "disconnect",
		Credential:   credential,
		ConnectionID: connectionID,
		Protocol:     info.protocolName,
		InboundTag:   info.inboundTag,
		SourceIP:     info.sourceIP,
		LocalIP:      info.localIP,
	})
}
