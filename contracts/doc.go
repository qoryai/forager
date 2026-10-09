// Package contracts embeds the Forager contract, contracts/forager/v1, and compiles its
// schemas.
//
// The contract is the set of documents Forager reads and writes: the policy, the
// server, the configuration and the run configuration a server answers, the events, a
// batch, a record and a runtime descriptor. Each has a JSON schema whose $id is [Base]
// followed by the file's path under forager/v1, so a $ref between schemas resolves
// without a network. [Compiler] returns a compiler that
// knows every schema of the contract under that $id, and [Compile] compiles one by its
// file name, "policy.schema.json" say.
//
// [Document] reads a YAML or JSON file into the JSON types a schema validates, and
// [Lines] reads a JSON lines file the same way, one value per line. The tests in this
// package validate every fixture under forager/v1/fixtures and every descriptor with its
// fixtures under forager/v1/runtimes, so the schemas, the fixtures and the readers cannot
// drift apart.
//
// The package reads the contract and nothing else. It does not run a session, map a
// record or post a batch; those are the session and receiver packages.
package contracts
