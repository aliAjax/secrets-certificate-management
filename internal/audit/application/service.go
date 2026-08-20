package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
)

type Service struct {
	repo   auditdomain.Repository
	crypto *cryptoapplication.Service
}

func NewService(repo auditdomain.Repository, cryptoService *cryptoapplication.Service) *Service {
	return &Service{repo: repo, crypto: cryptoService}
}

func (s *Service) Record(ctx context.Context, input auditdomain.RecordInput) (auditdomain.Event, error) {
	for attempt := 0; attempt < 3; attempt++ {
		previous, err := s.repo.LastHash(ctx)
		if err != nil {
			return auditdomain.Event{}, err
		}
		event := auditdomain.Event{
			ID:           uuid.New(),
			PreviousHash: previous,
			Actor:        input.Actor,
			Namespace:    input.Namespace,
			Path:         input.Path,
			Action:       input.Action,
			Result:       input.Result,
			Metadata:     input.Metadata,
			CreatedAt:    time.Now().UTC(),
		}
		if event.Metadata == nil {
			event.Metadata = map[string]string{}
		}
		event.EventHash = s.hash(event)
		appended, err := s.repo.Append(ctx, event)
		if err == auditdomain.ErrChainConflict {
			continue
		}
		if err != nil {
			return auditdomain.Event{}, err
		}
		return appended, nil
	}
	return auditdomain.Event{}, fmt.Errorf("failed to append audit event after retries")
}

func (s *Service) List(ctx context.Context, filter auditdomain.ListFilter) ([]auditdomain.Event, error) {
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 100
	}
	return s.repo.List(ctx, filter)
}

func (s *Service) Verify(ctx context.Context) (bool, int, error) {
	events, err := s.repo.ListAll(ctx)
	if err != nil {
		return false, 0, err
	}
	previous := "genesis"
	for i, event := range events {
		if event.PreviousHash != previous {
			return false, i, fmt.Errorf("previous hash mismatch at sequence %d", event.Sequence)
		}
		if event.EventHash != s.hash(event) {
			return false, i, fmt.Errorf("event hash mismatch at sequence %d", event.Sequence)
		}
		previous = event.EventHash
	}
	return true, len(events), nil
}

func (s *Service) hash(event auditdomain.Event) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		event.PreviousHash,
		event.Actor,
		event.Namespace,
		event.Path,
		event.Action,
		event.Result,
		event.CreatedAt.UTC().Format(time.RFC3339Nano),
		canonicalMetadata(event.Metadata),
	)
	sig, err := s.crypto.Sign(context.Background(), cryptodomain.SignRequest{Data: []byte(payload)})
	if err != nil {
		return "invalid"
	}
	return hex.EncodeToString(sig.Signature)
}

func canonicalMetadata(metadata map[string]string) string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, key := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(metadata[key])
	}
	return b.String()
}
