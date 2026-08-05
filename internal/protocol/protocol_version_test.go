package protocol

import "testing"

func TestProtocolVersionStateless(t *testing.T) {
	tests := []struct {
		name    string
		version ProtocolVersion
		want    bool
	}{
		{name: "2026-07-28 is stateless", version: "2026-07-28", want: true},
		{name: "2025-11-25 is stateful", version: "2025-11-25", want: false},
		{name: "2025-06-18 is stateful", version: "2025-06-18", want: false},
		{name: "2025-03-26 is stateful", version: "2025-03-26", want: false},
		{name: "2024-11-05 is stateful", version: "2024-11-05", want: false},
		{name: "empty is stateful", version: "", want: false},
		{name: "later unknown date is stateless", version: "2027-01-01", want: true},
		{name: "garbage is stateful", version: "not-a-date", want: false},
		{name: "date-length garbage is stateful", version: "aaaa-bb-cc", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.version.Stateless(); got != tt.want {
				t.Errorf("ProtocolVersion(%q).Stateless() = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
