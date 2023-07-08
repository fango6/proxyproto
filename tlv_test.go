package proxyproto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseTLVs(t *testing.T) {
	tests := []struct {
		name    string
		rawTLVs []byte
		want    TLVs
		wantErr error
	}{
		{
			name: "vpce id",
			rawTLVs: []byte("\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" + // type:234, length:34, value:vcpe-abcdefg-hijklmn-opqrst-uvwxyz
				"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"), // type:PP2_TYPE_NOOP, length:8, value:"\x00\x00\x00\x00\x00\x00\x00\x00"
			want: TLVs{
				{Type: 234, Length: 34, Value: []byte("vcpe-abcdefg-hijklmn-opqrst-uvwxyz")},
				{Type: 4, Length: 8, Value: []byte("\x00\x00\x00\x00\x00\x00\x00\x00")},
			},
			wantErr: nil,
		}, {
			name:    "length too short",
			rawTLVs: []byte("\xEA\x00"), // type:234, length:34, value:vcpe-abcdefg-hijklmn-opqrst-uvwxyz
			wantErr: ErrTlvLenTooShort,
		}, {
			name:    "value too short",
			rawTLVs: []byte("\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst"),
			wantErr: ErrTlvValTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTLVs(tt.rawTLVs)

			if tt.wantErr != nil {
				require.EqualError(t, err, tt.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
