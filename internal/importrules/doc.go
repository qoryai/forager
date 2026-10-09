// Package importrules holds the tests that keep the module's parts apart. The module is
// a core, the packages at its root and under internal/, and four parts over it: gateway,
// wall, session and e2e. One reads every package's imports, its tests' included,
// with go list and fails on an import the rules forbid:
//
//   - the core imports no part;
//   - the gateway and the wall import the core and themselves;
//   - the session imports the core, the wall and itself, and its tests package gateway
//     too;
//   - e2e imports every part;
//   - no part imports the core's internal packages, and nothing but e2e imports the
//     session.
//
// Beside the imports, the others read the source with go/parser and hold the session to
// the gateway's link: package gateway exports Start, Resend, what they take and give,
// and nothing else, a name each, listed in gatewaySurface; no file of session/ but a
// test imports a gateway package, under any build constraint; and a session test uses
// of package gateway only the names that list holds.
package importrules
