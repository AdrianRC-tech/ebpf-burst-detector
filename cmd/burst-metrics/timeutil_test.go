package main

import "testing"

func TestParseTimeOfDayNs(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{
			name: "hours minutes seconds and full 9-digit fraction",
			in:   "11:00:30.066000000",
			want: 39630*1_000_000_000 + 66_000_000,
		},
		{
			name: "end of the same burst",
			in:   "11:00:30.866000000",
			want: 39630*1_000_000_000 + 866_000_000,
		},
		{
			name: "midnight",
			in:   "00:00:00.000000000",
			want: 0,
		},
		{
			name: "no fractional part",
			in:   "10:00:11",
			want: 36011 * 1_000_000_000,
		},
		{
			name:    "wrong shape",
			in:      "not-a-time",
			wantErr: true,
		},
		{
			name:    "non-numeric hour",
			in:      "ab:00:30.066000000",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTimeOfDayNs(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTimeOfDayNs(%q) = %d, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTimeOfDayNs(%q) returned unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseTimeOfDayNs(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
