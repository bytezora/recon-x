package state

import (
	"encoding/json"
	"os"
)

type State struct {
	Target         string          `json:"target"`
	Version        string          `json:"version"`
	CompletedSteps []int           `json:"completed_steps"`
	Data           json.RawMessage `json:"data,omitempty"`
}

func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	return &s, json.Unmarshal(b, &s)
}

func Save(path string, s *State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func (s *State) Done(step int) bool {
	for _, n := range s.CompletedSteps {
		if n == step {
			return true
		}
	}
	return false
}

func (s *State) Mark(step int) {
	if !s.Done(step) {
		s.CompletedSteps = append(s.CompletedSteps, step)
	}
}
