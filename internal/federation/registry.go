package federation

import "fmt"

// Registry holds the set of configured upstream providers indexed by slug.
// Built at startup from config; immutable after that.
type Registry struct {
	ordered   []Provider            // insertion order for UI rendering
	byName    map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Provider)}
}

// Register adds a provider. Panics on duplicate slugs — this is a
// programming error caught at startup.
func (r *Registry) Register(p Provider) {
	if _, exists := r.byName[p.Name()]; exists {
		panic(fmt.Sprintf("federation: provider %q registered twice", p.Name()))
	}
	r.byName[p.Name()] = p
	r.ordered = append(r.ordered, p)
}

// Get returns the provider for the given slug and whether it was found.
func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.byName[name]
	return p, ok
}

// All returns providers in registration order — used to render the login
// page buttons.
func (r *Registry) All() []Provider {
	return r.ordered
}

// Names returns the slug of each registered provider in order.
func (r *Registry) Names() []string {
	names := make([]string, len(r.ordered))
	for i, p := range r.ordered {
		names[i] = p.Name()
	}
	return names
}

// Empty returns true if no providers are registered.
func (r *Registry) Empty() bool {
	return len(r.ordered) == 0
}
