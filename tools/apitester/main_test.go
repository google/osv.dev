package main

import (
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

func Test(t *testing.T) {
	t.Parallel()

	cassettes := LoadCassettes(t)

	for _, cas := range cassettes {
		t.Run(determineCassetteName(cas), func(t *testing.T) {
			t.Parallel()
			for _, interaction := range cas.Interactions {
				t.Run(determineInteractionName(interaction), func(t *testing.T) {
					t.Parallel()

					resp := PlayInteraction(t, interaction)

					snaps.MatchSnapshot(t, readBody(t, resp))
				})
			}
		})
	}
}

func Test_Example(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name  string
		Cases []string
	}{
		{Name: "classic", Cases: []string{"world", "sunshine"}},
		{Name: "planets", Cases: []string{"earth", "mars"}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			for _, ttt := range tt.Cases {
				t.Run(ttt, func(t *testing.T) {
					t.Parallel()

					snaps.MatchSnapshot(t, "hello "+ttt)
				})
			}
		})
	}
}
