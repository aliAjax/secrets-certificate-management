package domain

import "context"

type Repository interface {
	Append(ctx context.Context, event Event) (Event, error)
	LastHash(ctx context.Context) (string, error)
	List(ctx context.Context, filter ListFilter) ([]Event, error)
	ListAll(ctx context.Context) ([]Event, error)
}
