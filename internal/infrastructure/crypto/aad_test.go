package crypto

import (
	"strings"
	"testing"
)

func TestBuildAADFormat(t *testing.T) {
	aad := BuildAAD("POST", "/api/v1/test", "enc:v1", "sess-1", "req-1", "data.name", "default")
	aadStr := string(aad)
	expected := "POST:/api/v1/test:enc:v1:sess-1:req-1:default:data.name"
	if aadStr != expected {
		t.Errorf("expected AAD %q, got %q", expected, aadStr)
	}
}

func TestBuildAADMethodUppercase(t *testing.T) {
	aad := BuildAAD("get", "/path", "enc:v1", "s", "r", "f", "t")
	if !strings.HasPrefix(string(aad), "GET:") {
		t.Errorf("method should be uppercased, got: %s", string(aad))
	}
}

func TestBuildAADDeterministic(t *testing.T) {
	a := BuildAAD("POST", "/p", "enc:v1", "s1", "r1", "f.name", "t1")
	b := BuildAAD("POST", "/p", "enc:v1", "s1", "r1", "f.name", "t1")
	if string(a) != string(b) {
		t.Error("same inputs must produce same AAD")
	}
}

func TestBuildAADDifferentFieldPaths(t *testing.T) {
	a := BuildAAD("POST", "/p", "enc:v1", "s1", "r1", "f.name", "t1")
	b := BuildAAD("POST", "/p", "enc:v1", "s1", "r1", "f.phone", "t1")
	if string(a) == string(b) {
		t.Error("different field paths must produce different AAD")
	}
}
