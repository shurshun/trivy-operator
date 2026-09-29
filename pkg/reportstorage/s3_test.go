package reportstorage_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/reportstorage"
)

type recordedPut struct {
	path        string
	contentType string
	body        []byte
}

// fakeS3 serves HeadBucket for one bucket and records PutObject requests.
type fakeS3 struct {
	bucket string

	mu   sync.Mutex
	puts []recordedPut
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead:
		if r.URL.Path != "/"+f.bucket {
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.puts = append(f.puts, recordedPut{path: r.URL.Path, contentType: r.Header.Get("Content-Type"), body: body})
		f.mu.Unlock()
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newFakeS3(t *testing.T, bucket string) (*fakeS3, *httptest.Server) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")

	fake := &fakeS3{bucket: bucket}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, server
}

func TestS3Store_Put(t *testing.T) {
	fake, server := newFakeS3(t, "reports")
	store, err := reportstorage.NewS3(context.Background(), reportstorage.S3Options{
		Bucket:       "reports",
		Prefix:       "cluster-a",
		Endpoint:     server.URL,
		UsePathStyle: true,
	})
	require.NoError(t, err)

	report := map[string]string{"name": "nginx"}
	require.NoError(t, store.Put(context.Background(), "vulnerability_reports/ReplicaSet-nginx-nginx.json", report))

	require.Len(t, fake.puts, 1)
	put := fake.puts[0]
	assert.Equal(t, "/reports/cluster-a/vulnerability_reports/ReplicaSet-nginx-nginx.json", put.path)
	assert.Equal(t, "application/json", put.contentType)
	var got map[string]string
	require.NoError(t, json.Unmarshal(put.body, &got))
	assert.Equal(t, report, got)
}

func TestNewS3_FailsWhenBucketIsUnreachable(t *testing.T) {
	_, server := newFakeS3(t, "reports")

	_, err := reportstorage.NewS3(context.Background(), reportstorage.S3Options{
		Bucket:       "missing",
		Endpoint:     server.URL,
		UsePathStyle: true,
	})

	require.ErrorContains(t, err, `failed to access S3 bucket "missing"`)
}
