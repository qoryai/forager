package runkey

// The known answers of a run through a gateway, under the contract's fixtures, are
// written from the published fixture keys by package knownanswers; the tests fail while
// they differ.
//go:generate go run ./internal/knownanswers/gen ../contracts/forager/v1/fixtures/known-answers
