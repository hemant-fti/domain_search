package server

import (
	"context"
)

type Service struct {
	detector *Detector
}

func NewService() *Service {
	return &Service{
		detector: NewDetector(),
	}
}

func (s *Service) GetInfo(ctx context.Context) (Info, error) {
	return s.detector.Detect(ctx)
}
