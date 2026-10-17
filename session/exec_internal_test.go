package session

import "testing"

// TestParseExecRefusesANameWithANULOrAnEqualsSign pins what no argument of a process
// can carry to the helper's exec, a NUL, beside an equals sign: neither is a name.
func TestParseExecRefusesANameWithANULOrAnEqualsSign(t *testing.T) {
	for _, name := range []string{"A\x00B", "A=B", "A\x00"} {
		if _, _, err := parseExec([]string{"--unset", name, "--", "true"}); err == nil {
			t.Errorf("%q was taken as a name", name)
		}
	}
	names, argv, err := parseExec([]string{"--unset", "A", "--unset", "_B1", "--", "p", "--unset", "C"})
	if err != nil || len(names) != 2 || names[1] != "_B1" || len(argv) != 3 || argv[1] != "--unset" {
		t.Errorf("parseExec: %q, %q, %v", names, argv, err)
	}
}
