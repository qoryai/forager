package sealed

import "testing"

// TestSealWithoutASigningKeyStartsWithTheFix pins the refusal of Seal without the
// server's signing key: the step first, then the cause.
func TestSealWithoutASigningKeyStartsWithTheFix(t *testing.T) {
	const want = "pass the server's signing key to Seal; sealing needs it"
	if _, err := Seal(Sealing{}, nil); err == nil || err.Error() != want {
		t.Errorf("%v, want %q", err, want)
	}
}
