// Package accesskey is the access key of the runner contract, contracts/runner/v1: the
// one credential a machine holds for its server, and everything signed with it or for
// it. The runner signs its requests with this package, and the qory command enrols,
// creates and reads keys with it, so both hold one definition of each string.
//
// An access key is one Ed25519 key. Its secret is one line, "qak_" and the 32-byte seed
// in base64url without padding, 47 characters; [Generate] makes one from the system's
// random source and [ParseSecret] reads one. Everything comes from the seed: the
// Ed25519 public key, its fingerprint, and the X25519 key that opens what the server
// seals to the access key. The server assigns the access key its id, "ak_" and 16
// lower-case Crockford base32 characters, when the key enrols.
//
// Every request to the server is signed under the secret: [Request] builds the request
// string, "qory-request-ed25519-v1" and then the access key id, the instance id and
// the request, and [Key.SignRequest] signs it. Every answer of the server is signed
// under the server's own Ed25519 key and bound to the request by the request's
// signature: [Answer] builds the six lines, "qory-answer-ed25519-v1" first, and
// [Pin.VerifyAnswer] verifies them under the keys the machine pins. Every 401 is
// unsigned. An answer to an enrolment has its own domain line,
// "qory-enrol-answer-ed25519-v1", and the request's proof in place of its signature.
//
// Enrolment assigns a new key its id: [NewEnrolmentRequest] builds the request, with
// an enrolment code in its normalised form and a proof of possession under the new
// key, and [EnrolmentRequest.Post] sends it and verifies the answer under the server
// key the code's fingerprint selects.
//
// An instance is one running copy of qory with the access key. [NewInstanceID] makes
// its id, and [InstanceFile] and [ReadInstanceFile] are the two lines qory keeps it in,
// the id and a keyed hash of the machine's identity, so a file copied to another
// machine yields a new id there. Reading and writing that file is qory's.
//
// Errors name what is wrong with a value and never contain a secret. A [Key] formats as
// its fingerprint alone, whatever the verb.
package accesskey
