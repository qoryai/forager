package accesskey

// UserAgent is the User-Agent of every request Forager sends a server: qory-forager/
// and the version.
func UserAgent(version string) string { return "qory-forager/" + version }
