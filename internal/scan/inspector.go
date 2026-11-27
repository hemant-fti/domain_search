package scan

import (
	"context"

	"domain-search/pkg/models"
)

// Inspector discovers one kind of web server. pkg/nginx, pkg/apache and
// pkg/iis implement it.
//
// Discover may return domains together with an error: the domains are a
// usable partial result and the error explains what is missing. A nil slice
// with an error means discovery failed.
type Inspector interface {
	Name() string
	Detect(context.Context) (bool, error)
	Discover(context.Context) ([]models.Domain, error)
}

// statusInspector is implemented by inspectors that can tell whether the
// service is running.
type statusInspector interface {
	Running(context.Context) (bool, error)
}

// InspectOptions selects what Inspect collects.
type InspectOptions struct {
	Domains bool
	Config  bool
	Version bool
}
