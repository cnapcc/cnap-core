package extauth

import (
	"context"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

// ExtAuth module
type Instance struct {
	url        string
	secret     string
	timeout    time.Duration
	heartbeat  time.Duration
	ttl        time.Duration
	disconnect bool
	cache      sync.Map
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
	return &Instance{
		url:        config.Url,
		secret:     config.Secret,
		timeout:    time.Duration(config.Timeout) * time.Second,
		heartbeat:  time.Duration(config.Heartbeat) * time.Second,
		ttl:        time.Duration(config.Ttl) * time.Second,
		disconnect: config.Disconnect,
	}, nil
}

// Type implements common.HasType
func (*Instance) Type() interface{} {
	return (*Instance)(nil)
}

// Start implements common.Runnable
func (i *Instance) Start() error { return nil }

// Close implements common.Closable
func (i *Instance) Close() error { return nil }

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Connect validates credential via cache or external API
func (i *Instance) Connect(credential string, connectionID string, ctx context.Context) *protocol.MemoryUser {
	info := i.getConnectionInfo(ctx)

	// Check User in cache
	key := cacheKey{credential: credential, ip: info.sourceIP}
	if cached, ok := i.cache.Load(key); ok {
		entry := cached.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			if i.heartbeat > 0 || i.disconnect {
				go i.Watch(credential, connectionID, ctx)
			}
			return entry.user
		}
		i.cache.Delete(key)
	}

	// Send request to external API
	resp, err := i.sendRequest(Request{
		Type:         "connect",
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

	// Save User to cache
	user := &protocol.MemoryUser{
		Email: resp.User.Email,
		Level: resp.User.Level,
	}
	if i.ttl > 0 {
		i.cache.Store(key, &cacheEntry{
			user:      user,
			expiresAt: time.Now().Add(i.ttl),
		})
	}

	// Run Watch only if there is heartbeat or disconnect enabled
	if i.heartbeat > 0 || i.disconnect {
		go i.Watch(credential, connectionID, ctx)
	}

	return user
}

func (i *Instance) Watch(credential string, connectionID string, ctx context.Context) {
	if i.heartbeat <= 0 {
		<-ctx.Done()
		i.Disconnect(credential, connectionID, ctx)
		return
	}

	ticker := time.NewTicker(i.heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if i.disconnect {
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
	resp, err := i.sendRequest(Request{
		Type:         "heartbeat",
		Credential:   credential,
		ConnectionID: connectionID,
		Protocol:     info.protocolName,
		InboundTag:   info.inboundTag,
		SourceIP:     info.sourceIP,
		LocalIP:      info.localIP,
	})

	// Remove User from cache if backend didn't respond with 200 OK
	// If err != nil, it's other type of error, don't touch cache
	if resp == nil && err == nil {
		key := cacheKey{credential: credential, ip: info.sourceIP}
		i.cache.Delete(key)
	}
}

func (i *Instance) Disconnect(credential string, connectionID string, ctx context.Context) {
	info := i.getConnectionInfo(ctx)

	i.sendRequest(Request{
		Type:         "disconnect",
		Credential:   credential,
		ConnectionID: connectionID,
		Protocol:     info.protocolName,
		InboundTag:   info.inboundTag,
		SourceIP:     info.sourceIP,
		LocalIP:      info.localIP,
	})
}
