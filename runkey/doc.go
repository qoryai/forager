// Package runkey is the run key of the Forager contract, contracts/forager/v1: the one
// string Qory Apiary answers a run's registration with when the registering node's or
// node pool's choice resolves to a gateway, and the only proof the run's edge presents
// to that gateway.
//
// A run key is "qrk_", the payload in base64url without padding, ".", and the
// signature in base64url without padding, at most [MaxLength] characters. The payload
// is the exact JSON bytes Qory Apiary signed, run-key.schema.json; the signature is 64
// bytes of Ed25519 under Qory Apiary's server key, over [Domain], a line feed and the
// payload bytes. Nobody re-serialises the payload.
//
// [Verify] is the gateway's and Qory Apiary's reading: it finds the pinned server key
// whose fingerprint the payload names as its signer, verifies the signature under it,
// and only then reads the payload against the schema. [Parse] is a runner's reading: a
// runner pins no server key, so it checks the form and the payload's schema and
// nothing else. Its [Key] reports false from [Key.Verified] and grants nothing; of it a
// runner takes the run's id, the gateway's URL, the one address the run key is ever
// sent to, and the gateway's keys, the pin for the gateway's answers. A runner never
// checks Issued or AttachBy: its clock decides nothing.
//
// [Key.Sign] makes a run key, as Qory Apiary does, under a server signing key.
//
// Errors name the part of the run key that is wrong and never contain the run key or
// any part of its value.
package runkey
