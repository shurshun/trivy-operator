// Package reportstorage writes reports to alternate storage instead of Kubernetes CRDs.
package reportstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

// Store persists a report as a JSON document under a slash-separated key,
// for example "vulnerability_reports/ReplicaSet-nginx-nginx.json".
type Store interface {
	Put(ctx context.Context, key string, report any) error
}

// New returns the Store selected by the alternate report storage settings.
func New(ctx context.Context, config etc.Config) (Store, error) {
	switch config.AltReportStorageType {
	case "", etc.AltReportStorageFilesystem:
		if config.AltReportDir == "" {
			return nil, errors.New("alternate report storage directory must be set")
		}
		return NewFilesystem(config.AltReportDir), nil
	case etc.AltReportStorageS3:
		return NewS3(ctx, S3Options{
			Bucket:       config.AltReportS3Bucket,
			Prefix:       config.AltReportS3Prefix,
			Endpoint:     config.AltReportS3Endpoint,
			Region:       config.AltReportS3Region,
			UsePathStyle: config.AltReportS3UsePathStyle,
		})
	default:
		return nil, fmt.Errorf("unsupported alternate report storage type %q", config.AltReportStorageType)
	}
}

func encode(w io.Writer, report any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}
	return nil
}
