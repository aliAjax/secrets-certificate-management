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

// maxChainConflictRetries bounds how many times Record will re-read the tip of
// the audit chain and retry the append after a concurrent writer committed
// first. Each retry observes a fresh previous hash, so legitimate concurrent
// writes converge instead of corrupting the chain. The advisory lock in the
// repository still serializes the critical section; retries here absorb the
// race between the non-locked LastHash read and the locked append.
const maxChainConflictRetries = 8

type Service struct {
	repo   auditdomain.Repository
	crypto *cryptoapplication.Service
}

func NewService(repo auditdomain.Repository, cryptoService *cryptoapplication.Service) *Service {
	return &Service{repo: repo, crypto: cryptoService}
}

func (s *Service) Record(ctx context.Context, input auditdomain.RecordInput) (auditdomain.Event, error) {
	// Build the invariant parts of the event once. Only the previous hash (and
	// therefore the event hash) changes across retries, so we rebuild those
	// per attempt after re-reading the chain tip.
	base := auditdomain.Event{
		ID:        uuid.New(),
		Actor:     input.Actor,
		Namespace: input.Namespace,
		Path:      input.Path,
		Action:    input.Action,
		Result:    input.Result,
		Metadata:  input.Metadata,
		CreatedAt: time.Now().UTC(),
	}
	if base.Metadata == nil {
		base.Metadata = map[string]string{}
	}

	var lastErr error
	for attempt := 0; attempt <= maxChainConflictRetries; attempt++ {
		previous, err := s.repo.LastHash(ctx)
		if err != nil {
			return auditdomain.Event{}, err
		}
		event := base
		event.PreviousHash = previous
		event.EventHash = s.hash(event)

		result, err := s.repo.Append(ctx, event)
		if err == nil {
			return result, nil
		}
		lastErr = err
		// Only a chain conflict is retriable: another writer committed first,
		// so re-read the tip and try again. Anything else (insert failure,
		// context cancelled, etc.) aborts immediately.
		if !auditdomain.IsChainConflict(err) {
			return auditdomain.Event{}, err
		}
	}
	return auditdomain.Event{}, fmt.Errorf("record audit event after %d retries: %w", maxChainConflictRetries, lastErr)
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
