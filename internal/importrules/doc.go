// Package importrules holds the test that keeps the module's parts apart. The module is
// a core, the packages at its root and under internal/, and four parts over it: gateway,
// wall, session and e2e. The test reads every package's imports, its tests' included,
// with go list and fails on an import the rules forbid:
//
//   - the core imports no part;
//   - the gateway and the wall import the core and themselves;
//   - the session imports the core, the wall, package gateway and itself;
//   - e2e imports every part;
//   - no part imports the core's internal packages, and nothing but e2e imports the
//     session.
package importrules
