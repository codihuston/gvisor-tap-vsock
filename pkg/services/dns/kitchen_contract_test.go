package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestKitchenRenderedDNSCorpus(t *testing.T) {
	dir := os.Getenv("KITCHEN_FORK_FIXTURES")
	if dir == "" {
		t.Skip("run Kitchen make fork-test for the cross-repository contract")
	}
	data, err := os.ReadFile(filepath.Join(dir, "stack-configs.json"))
	require.NoError(t, err)
	var configs map[string]types.Configuration
	require.NoError(t, json.Unmarshal(data, &configs))
	data, err = os.ReadFile(filepath.Join(dir, "corpus.json"))
	require.NoError(t, err)
	var corpus []struct {
		Name    string
		Host    string
		Allowed bool
	}
	require.NoError(t, json.Unmarshal(data, &corpus))
	for i, tc := range corpus {
		t.Run(tc.Name, func(t *testing.T) {
			config, ok := configs[fmt.Sprintf("kitchen-corpus-%d", i)]
			require.True(t, ok)
			var patterns []*regexp.Regexp
			for _, p := range config.OutboundAllow {
				re, err := regexp.Compile(p)
				require.NoError(t, err)
				patterns = append(patterns, re)
			}
			require.Equal(t, tc.Allowed, matchesAllowlist(tc.Host, patterns))
		})
	}
}
