package session

import (
	"errors"
	"fmt"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/policy"
)

// Built is the result of a build of an image, as [Run.Built] writes it in
// dev.qory.run.built.
type Built struct {
	// Image is the image by its digest: NAME@sha256: and 64 lower-case hexadecimal
	// digits, with no tag, as a policy's image reference is.
	Image string
	// Size is the image's size in bytes, 1 or more.
	Size int64
	// Commit is the full commit id the image was built from: 40 or 64 hexadecimal
	// characters, in lower case.
	Commit string
	// EnvironmentRef is the reference to the environment the image is for, not empty.
	// Forager writes it as given and checks nothing else of its form.
	EnvironmentRef string
}

// Built writes the run's dev.qory.run.built with b's members as image, size, commit and
// environment_ref, once per run: before the first join, between joins or after the
// last, with no host step open. Write the build itself as a host step of kind
// event.StepBuild, and call Built after the step exits.
//
// An error means nothing is written: a member of b is not of its shape, a session of
// the run is running, a host step is open, the run is closed, or the run has its
// dev.qory.run.built already.
//
// EnvironmentRef must contain no credential: Forager writes it as given.
func (r *Run) Built(b Built) error {
	if err := checkBuilt(b); err != nil {
		return err
	}
	if !r.joining.TryLock() {
		return errors.New("write the build's result after Join returns: a session of the run is still running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return errors.New("open a new run for the build's result: the run is closed")
	}
	if r.hostStep != nil {
		return fmt.Errorf("exit step %d before the build's result: Built writes nothing while a host step is open", r.hostStep.n)
	}
	if r.built {
		return errors.New("write the build's result once per run: the run has its dev.qory.run.built already")
	}
	r.built = true
	r.post(event.RunBuilt, map[string]any{"image": b.Image, "size": b.Size, "commit": b.Commit, "environment_ref": b.EnvironmentRef})
	return nil
}

// checkBuilt refuses a build's result the schema of dev.qory.run.built would: an image
// not pinned by digest, a size below 1, a commit that is not a full commit id, or an
// empty environment reference. The image's error shows no value, since a reference
// may contain a registry's credentials.
func checkBuilt(b Built) error {
	switch {
	case !policy.ImageReference(b.Image):
		return errors.New("set the built image to NAME@sha256: and 64 lower-case hexadecimal digits, in lower case, with no tag")
	case b.Size < 1:
		return fmt.Errorf("set the built image's size to its bytes, 1 or more, not %d", b.Size)
	case !commitShape.MatchString(b.Commit):
		return errors.New("set the commit of the build to a full commit id, 40 or 64 hexadecimal characters in lower case")
	case b.EnvironmentRef == "":
		return errors.New("set the build's environment reference: dev.qory.run.built requires a non-empty environment_ref")
	}
	return nil
}
