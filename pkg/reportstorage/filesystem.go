package reportstorage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type filesystemStore struct {
	dir string
}

// NewFilesystem returns a Store that writes reports as files under dir.
func NewFilesystem(dir string) Store {
	return &filesystemStore{dir: dir}
}

func (s *filesystemStore) Put(_ context.Context, key string, report any) error {
	path := filepath.Join(s.dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("failed to make directory %s: %w", filepath.Dir(path), err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	if err := encode(file, report); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s: %w", path, err)
	}
	return nil
}
