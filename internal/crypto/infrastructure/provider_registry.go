package infrastructure

import (
	"fmt"
	"sync"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
)

type Registry struct {
	mu        sync.RWMutex
	providers map[string]backenddomain.Provider
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]backenddomain.Provider)}
}

func (r *Registry) Register(provider backenddomain.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
}

func (r *Registry) Get(name string) (backenddomain.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q is not registered", name)
	}
	return provider, nil
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
