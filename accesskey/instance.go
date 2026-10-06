package accesskey

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// InstancePrefix starts every instance id qory generates.
const InstancePrefix = "i_"

// InstanceHashKey is the key of the hash of the machine's identity in the instance id
// file, so the file names the machine without containing its identity.
const InstanceHashKey = "qory instance-id v1"

// NewInstanceID returns a new instance id: "i_" and 16 bytes from the system's random
// source in base64url, 24 characters.
func NewInstanceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("the system's random source: %w", err)
	}
	return InstancePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// CheckInstanceID refuses an instance id outside ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$,
// which the server answers with a signed 400 bad_request, and one that contains an
// access key secret, since the id travels in clear.
func CheckInstanceID(id string) error {
	if !nameShape.MatchString(id) || ContainsSecret(id) {
		return fmt.Errorf("the instance id %s is not 1 to 64 of A-Z, a-z, 0-9, dot, underscore and dash, starting with a letter or digit", shown(id))
	}
	return nil
}

// MachineHash returns the lower-case hex HMAC-SHA256, keyed with [InstanceHashKey], of
// the machine's identity: /etc/machine-id on Linux, IOPlatformUUID on macOS, else the
// host name, as machine-id(5) recommends. White space around the identity, the line
// feed that ends /etc/machine-id say, is not part of it.
func MachineHash(machineID []byte) string {
	m := hmac.New(sha256.New, []byte(InstanceHashKey))
	m.Write(bytes.TrimSpace(machineID))
	return hex.EncodeToString(m.Sum(nil))
}

// InstanceFile returns the content of qory's instance-id file for an id on a machine:
// two lines, the id and [MachineHash] of the machine's identity.
func InstanceFile(id string, machineID []byte) []byte {
	return []byte(id + "\n" + MachineHash(machineID) + "\n")
}

// ReadInstanceFile reads qory's instance-id file on a machine and returns its id. ok
// is false when the file is not two such lines, its id fails [CheckInstanceID], or its
// hash is not this machine's, a file copied with a home directory say; qory then
// generates a new id with [NewInstanceID] and writes it with [InstanceFile].
func ReadInstanceFile(b []byte, machineID []byte) (id string, ok bool) {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 || CheckInstanceID(lines[0]) != nil {
		return "", false
	}
	if !hmac.Equal([]byte(lines[1]), []byte(MachineHash(machineID))) {
		return "", false
	}
	return lines[0], true
}

// The variables qory reads the access key's secret, its id and the pin from. They are
// the runner's alone: no tool, credential program or agent receives them.
const (
	EnvSecret = "QORY_ACCESS_KEY_SECRET"
	EnvID     = "QORY_ACCESS_KEY_ID"
	EnvPin    = "QORY_APIARY_PUBLIC_KEY"
)

// WithoutVariables returns an environment, NAME=value entries, without [EnvSecret],
// [EnvID] and [EnvPin]: the environment a program the runner starts receives.
func WithoutVariables(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name != EnvSecret && name != EnvID && name != EnvPin {
			out = append(out, kv)
		}
	}
	return out
}