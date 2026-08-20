package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrChainConflict = errors.New("audit chain conflict")

type Event struct {
	ID           uuid.UUID         `json:"id"`
	Sequence     int64             `json:"sequence"`
	EventHash    string            `json:"event_hash"`
	PreviousHash string            `json:"previous_hash"`
	Actor        string            `json:"actor"`
	Namespace    string            `json:"namespace"`
	Path         string            `json:"path"`
	Action       string            `json:"action"`
	Result       string            `json:"result"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"created_at"`
}

type RecordInput struct {
	Actor     string
	Namespace string
	Path      string
	Action    string
	Result    string
	Metadata  map[string]string
}

type ListFilter struct {
	Namespace string
	Path      string
	Actor     string
	Action    string
	Limit     int
}
