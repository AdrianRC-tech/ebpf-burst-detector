package main

import "testing"

func TestActiveCPUs(t *testing.T) {
	cases := []struct {
		name  string
		input []uint64
		want  int
	}{
		{"empty", nil, 0},
		{"all zero", []uint64{0, 0, 0, 0}, 0},
		{"one active", []uint64{0, 7, 0, 0}, 1},
		{"all active", []uint64{1, 2, 3, 4}, 4},
		{"mixed", []uint64{0, 1, 0, 2, 0, 3, 0, 4}, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := activeCPUs(tc.input); got != tc.want {
				t.Fatalf("activeCPUs(%v) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
