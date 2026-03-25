package web

import (
	"context"
	"encoding/json"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/domain"
)

func (a *App) recordAudit(ctx context.Context, action string, target string, outcome string, metadata map[string]any) {
	if a.store == nil {
		return
	}

	actor := "anonymous"
	if identity, ok := auth.IdentityFromContext(ctx); ok {
		actor = identity.Username
	}

	encoded := "{}"
	if metadata != nil {
		if payload, err := json.Marshal(metadata); err == nil {
			encoded = string(payload)
		}
	}

	_ = a.store.CreateAuditLog(ctx, domain.AuditLog{
		Actor:    actor,
		Action:   action,
		Target:   target,
		Outcome:  outcome,
		Metadata: encoded,
	})
}
