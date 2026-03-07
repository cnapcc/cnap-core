package vless

import (
	"context"

	googleuuid "github.com/google/uuid"
	"github.com/xtls/xray-core/app/extauth"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

type ExtAuthValidator struct {
	authenticator *extauth.Instance
	ctx           context.Context
	connectionID  string
}

func NewExtAuthValidator(auth *extauth.Instance) *ExtAuthValidator {
	return &ExtAuthValidator{authenticator: auth}
}

func (v *ExtAuthValidator) WithContext(ctx context.Context) *ExtAuthValidator {
	return &ExtAuthValidator{
		authenticator: v.authenticator,
		ctx:           ctx,
		connectionID:  googleuuid.New().String(),
	}
}

func (v *ExtAuthValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	user := v.authenticator.Connect(id.String(), v.connectionID, v.ctx)
	if user == nil {
		return nil
	}
	user.Account = &MemoryAccount{
		ID: protocol.NewID(id),
	}
	return user
}

func (v *ExtAuthValidator) Add(u *protocol.MemoryUser) error             { return nil }
func (v *ExtAuthValidator) Del(email string) error                       { return nil }
func (v *ExtAuthValidator) GetByEmail(email string) *protocol.MemoryUser { return nil }
func (v *ExtAuthValidator) GetAll() []*protocol.MemoryUser               { return nil }
func (v *ExtAuthValidator) GetCount() int64                              { return 0 }
