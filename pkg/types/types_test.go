package types

import (
	"encoding/json"
	"testing"
)

func TestNormalizeStaticRules_NilMethodsBecomesEmptySlice(t *testing.T) {
	rules := []StaticRule{
		{Methods: nil, URLPattern: "https://example.com/", MatchType: "prefix", Action: "allow"},
		{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"},
	}
	NormalizeStaticRules(rules)

	if rules[0].Methods == nil {
		t.Error("expected Methods to be non-nil after normalization")
	}
	if len(rules[0].Methods) != 0 {
		t.Errorf("expected empty Methods, got %v", rules[0].Methods)
	}
	if len(rules[1].Methods) != 1 || rules[1].Methods[0] != "GET" {
		t.Errorf("expected Methods=[GET], got %v", rules[1].Methods)
	}
}

func TestNormalizeStaticRules_EmptyInput(t *testing.T) {
	NormalizeStaticRules(nil)
	NormalizeStaticRules([]StaticRule{})
}

func TestNormalizeStaticRules_JSONSerializesAsEmptyArray(t *testing.T) {
	rules := []StaticRule{
		{Methods: nil, URLPattern: "https://example.com/"},
	}
	NormalizeStaticRules(rules)

	b, err := json.Marshal(rules[0].Methods)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(b) != "[]" {
		t.Errorf("expected JSON [], got %s", string(b))
	}
}
