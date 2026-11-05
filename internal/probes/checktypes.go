package probes

import "slices"

// CheckTypeFirewall names the firewall ticket mode among the check types
// administrators can switch off; the others are the methods of the catalog.
const CheckTypeFirewall = ModeFirewall

// CheckTypes lists every check type in display order: the methods of the
// catalog, then the firewall ticket mode.
func CheckTypes() []string {
	out := make([]string, 0, len(Catalog)+1)
	for _, e := range Catalog {
		out = append(out, string(e.Method))
	}
	return append(out, CheckTypeFirewall)
}

// NormalizeDisabledChecks validates a list of disabled check types and
// returns it without duplicates, in display order (never nil).
func NormalizeDisabledChecks(in []string) ([]string, error) {
	all := CheckTypes()
	for _, t := range in {
		if !slices.Contains(all, t) {
			return nil, FieldError{Field: "disabled", Code: "unknown_check_type", Message: "unknown check type " + quoteName(t)}
		}
	}
	out := []string{}
	for _, t := range all {
		if slices.Contains(in, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

func quoteName(s string) string {
	if len(s) > 32 {
		s = s[:32] + "…"
	}
	return `"` + s + `"`
}
