package inspectors

import (
	"context"
	"domain-search/models"
)

type Inspector interface {
	Name() string
	Detect(context.Context) (bool, error)
	Discover(context.Context) ([]models.Domain, error)
}
