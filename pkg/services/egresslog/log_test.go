package egresslog

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestDenialsAreVisibleAndBounded(t *testing.T) {
	var out bytes.Buffer
	sink := log.New()
	sink.SetOutput(&out)
	sink.SetLevel(log.InfoLevel)
	sink.SetFormatter(&log.JSONFormatter{})
	now := time.Unix(100, 0)
	logger := New(sink, func() time.Time { return now })
	for i := 0; i < 100; i++ {
		logger.Denied(DNS, "blocked %q", "bad.example")
	}
	logger.Denied(SNIMismatch, "SNI mismatch")
	now = now.Add(time.Second)
	logger.Denied(DNS, "blocked %q", "another.example")
	dec := json.NewDecoder(&out)
	var rows []map[string]any
	for dec.More() {
		var row map[string]any
		require.NoError(t, dec.Decode(&row))
		rows = append(rows, row)
	}
	require.Len(t, rows, 3)
	require.Equal(t, "info", rows[0]["level"])
	require.Equal(t, "dns", rows[0]["reason"])
	require.Equal(t, float64(99), rows[2]["suppressed"])
}

func TestConcurrentDenials(t *testing.T) {
	var out bytes.Buffer
	sink := log.New()
	sink.SetOutput(&out)
	logger := New(sink, func() time.Time { return time.Unix(100, 0) })
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); logger.Denied(TCP, "blocked") }()
	}
	wg.Wait()
	require.Equal(t, 1, bytes.Count(out.Bytes(), []byte("\n")))
}
