package reportstorage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/reportstorage"
)

func TestNew_RejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  etc.Config
		wantErr string
	}{
		{
			name:    "filesystem without directory",
			config:  etc.Config{AltReportStorageType: etc.AltReportStorageFilesystem},
			wantErr: "alternate report storage directory must be set",
		},
		{
			name:    "s3 without bucket",
			config:  etc.Config{AltReportStorageType: etc.AltReportStorageS3},
			wantErr: "alternate report storage S3 bucket must be set",
		},
		{
			name:    "unknown type",
			config:  etc.Config{AltReportStorageType: "gcs"},
			wantErr: `unsupported alternate report storage type "gcs"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reportstorage.New(context.Background(), tt.config)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
