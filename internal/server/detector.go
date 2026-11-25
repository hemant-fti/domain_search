package server

import (
	"context"
	"domain-search/models"
	"domain-search/pkg/system"
)

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Detect(ctx context.Context) (models.Info, error) {
	var out models.Info

	if err := ctx.Err(); err != nil {
		return out, err
	}

	hostname, err := system.Hostname()
	if err == nil {
		out.Hostname = hostname
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}

	kernel, err := system.KernelVersion()
	if err == nil {
		out.Kernel = kernel
	}

	return out, nil
}
