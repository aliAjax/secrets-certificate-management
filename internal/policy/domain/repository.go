package domain

import "context"

type Repository interface {
	Create(ctx context.Context, policy Policy) error
	Get(ctx context.Context, name string) (Policy, error)
	List(ctx context.Context, namespace string) ([]Policy, error)
	Delete(ctx context.Context, id interface{}) error
}
