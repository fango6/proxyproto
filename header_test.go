package proxyproto

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadHeader want success
func TestReadHeader(t *testing.T) {
	// version 1
	for _, tt := range readAndParseV1Tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			got, err := ReadHeader(reader)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
	// version 2
	for _, tt := range readAndParseV2Tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.Raw = []byte(tt.raw)
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			got, err := ReadHeader(reader)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
