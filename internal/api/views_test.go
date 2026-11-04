package api

import "testing"

// A check through a proxy resolves nothing in the Pod: older rows stored a nil
// slice as "null", and the API must still return a list.
func TestRawNeverReturnsNull(t *testing.T) {
	for _, s := range []string{"", "null", "not json"} {
		if got := string(raw(s, "[]")); got != "[]" {
			t.Errorf("raw(%q) = %s, want []", s, got)
		}
	}
	if got := raw("null", ""); got != nil {
		t.Errorf(`raw("null", "") = %s, want nil (omitted)`, got)
	}
	if got := string(raw(`["10.0.0.1"]`, "[]")); got != `["10.0.0.1"]` {
		t.Errorf("raw kept list = %s", got)
	}
}
