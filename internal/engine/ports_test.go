package engine

import (
	"encoding/json"
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bytezora/recon-x/internal/state"
	"github.com/bytezora/recon-x/internal/subdomain"
)

func TestRunResumeUsesSavedResultsForCompletedSteps(t *testing.T) {
	saved := Results{
		Subs: []subdomain.Result{
			{Subdomain: "www.example.test", IPs: []string{"127.0.0.1"}, Source: "seed"},
		},
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}

	st := &state.State{
		Target:         "example.test",
		Version:        "test",
		CompletedSteps: []int{1},
		Data:           data,
	}

	got := New(Config{Target: "example.test", Resume: true}).Run(func(tea.Msg) {}, st, "", map[int]bool{1: true})
	if len(got.Subs) != 1 {
		t.Fatalf("resumed subdomains len = %d, want 1", len(got.Subs))
	}
	if got.Subs[0].Subdomain != "www.example.test" {
		t.Fatalf("resumed subdomain = %q", got.Subs[0].Subdomain)
	}
}

func TestRunResumeIgnoresLegacyStateWithoutData(t *testing.T) {
	st := &state.State{
		Target:         "example.test",
		Version:        "test",
		CompletedSteps: []int{1},
	}

	got := New(Config{Target: "example.test", Resume: true}).Run(func(tea.Msg) {}, st, "", map[int]bool{})
	if len(got.Subs) != 0 {
		t.Fatalf("resumed subdomains len = %d, want 0", len(got.Subs))
	}
	if len(st.CompletedSteps) != 0 {
		t.Fatalf("legacy completed steps were not cleared: %v", st.CompletedSteps)
	}
}

func TestParsePortListSupportsRangesAndDedupe(t *testing.T) {
	got := parsePortList("80, 443, 8000-8002,443,0,65536,bad,9000-8999")
	want := []int{80, 443, 8000, 8001, 8002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePortList() = %v, want %v", got, want)
	}
}
