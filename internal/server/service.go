package server

import (
	"context"

	osExec "domain-search/internal/os"
)

type Service struct {
	detector *Detector
}

func NewService() *Service {
	return &Service{
		detector: NewDetector(),
	}
}

func (s *Service) GetInfo(ctx context.Context, ex osExec.Executor) (Info, error) {
	return s.detector.Detect(ctx, ex)
}
