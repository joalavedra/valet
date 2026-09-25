package handle

import "testing"

func TestNewAndParse(t *testing.T) {
	tests := []struct {
		kind, site, label, want string
		wantErr                 bool
	}{
		{"cred", "github.com", "joan", "cred://github.com/joan", false},
		{"card", "", "visa-4242", "card://visa-4242", false},
		{"cred", "", "x", "", true},
		{"card", "", "", "", true},
		{"oauth", "a", "b", "", true},
	}
	for _, tc := range tests {
		h, err := New(tc.kind, tc.site, tc.label)
		if tc.wantErr {
			if err == nil {
				t.Errorf("New(%q,%q,%q): want error", tc.kind, tc.site, tc.label)
			}
			continue
		}
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if h.String() != tc.want {
			t.Errorf("got %q want %q", h, tc.want)
		}
		kind, site, label, err := Parse(h.String())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if kind != tc.kind || site != tc.site || label != tc.label {
			t.Errorf("Parse(%q) = %q,%q,%q", h, kind, site, label)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := Validate("cred://github.com/joan"); err != nil {
		t.Error(err)
	}
	if err := Validate("card://visa-4242"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "cred://onlysite", "http://x", "card://"} {
		if err := Validate(bad); err == nil {
			t.Errorf("Validate(%q): want error", bad)
		}
	}
}
