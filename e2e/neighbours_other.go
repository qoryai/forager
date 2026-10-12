//go:build !linux

package e2e

import "errors"

// linkLayer is the neighbour table, which is read on Linux alone.
func linkLayer() (map[string]string, error) {
	return nil, errors.New("the neighbour table is read on Linux alone")
}
