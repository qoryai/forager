package runcredential

// The known answers of the run credential, under the contract's fixtures, are written
// from a published seed by package knownanswers; the tests fail while they differ.
//go:generate go run ./internal/knownanswers/gen ../contracts/forager/v1/fixtures/known-answers/run-credentials
