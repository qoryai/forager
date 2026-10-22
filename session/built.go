package session

import (
	"errors"
	"fmt"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/policy"
)

// Built is the result of a build of an image, as [Run.Built] writes it in
// dev.qory.run.built.
type Built struct {
	// Image is the image by its digest: NAME@sha256: and 64 lower-case hexadecimal
	// digits, with no tag, as a policy's image reference is, and with no qak_, qrk_ or qecr_ in
	// any case.
	Image string
	// Size is the image's size in bytes, 1 or more.
	Size int64
	// Commit is the full commit id the image was built from: 40 or 64 hexadecimal
	// characters, in lower case.
	Commit string
	// EnvironmentRef is the reference to the environment the image is for, not empty.
	// The run's masker replaces each forwarder's password in it, and a reference that
	// contains qak_, qrk_ or qecr_ in any case is a phrase in its place, as in a step's name.
	EnvironmentRef string
	// EnvironmentImage is the environment image the build pushed, or the one it started
	// from, of the form of Image. Empty means not reported: Built then writes no
	// environment_image.
	EnvironmentImage string
	// Base is the base image the build pulled, of the form of Image. Empty means not
	// reported: Built then writes no base.
	Base string
}

// Built writes the run's dev.qory.run.built with b's members as image, size, commit and
// environment_ref, and as environment_image and base when they are set, once per run:
// before the first join or after a join returns, with no host step open. Write the
// build itself as a host step of kind event.StepBuild, and call Built after the step
// exits.
//
// An error means nothing is written: a member of b is not of its shape, Image,
// EnvironmentImage or Base contains qak_, qrk_ or qecr_, another call of the run is
// running, a host step is open, the run is closed, or Built wrote the run's
// dev.qory.run.built already.
//
// EnvironmentRef must contain no credential. The masker replaces only the forwarders'
// passwords, and accesskey.ShownValue replaces only a reference that contains qak_,
// qrk_ or qecr_; any other secret in EnvironmentRef is written as the caller passes it.
func (r *Run) Built(b Built) error {
	if err := checkBuilt(b); err != nil {
		return err
	}
	if !r.joining.TryLock() {
		return errors.New("write the build's result after the run's other call returns: another call of the run is running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return errors.New("open a new run for the build's result: the run is closed")
	}
	if r.hostStep != nil {
		return fmt.Errorf("exit step %d before you write the build's result: Built writes nothing while a host step is open", r.hostStep.n)
	}
	if r.built {
		return errors.New("write the build's result once per run: Built wrote this run's dev.qory.run.built already")
	}
	r.built = true
	data := map[string]any{"image": b.Image, "size": b.Size, "commit": b.Commit, "environment_ref": r.stepName(b.EnvironmentRef)}
	if b.EnvironmentImage != "" {
		data["environment_image"] = b.EnvironmentImage
	}
	if b.Base != "" {
		data["base"] = b.Base
	}
	r.post(event.RunBuilt, data)
	return nil
}

// checkBuilt refuses a build's result the schema of dev.qory.run.built would: an image
// not pinned by digest, a size below 1, a commit that is not a full commit id, or an
// empty environment reference, and an image, an environment image or a base image
// that contains qak_, qrk_ or qecr_ in any case, which no event contains. An empty
// environment image or base is not reported, and passes. The images' errors show no
// value, since a reference may contain a registry's credentials.
func checkBuilt(b Built) error {
	switch {
	case accesskey.ContainsSecret(b.Image):
		return errors.New("set the built image to a reference without qak_, qrk_ or qecr_: each starts a secret")
	case !policy.ImageReference(b.Image):
		return errors.New("set the built image to NAME@sha256: and 64 hexadecimal digits, all in lower case, with no tag")
	case b.Size < 1:
		return fmt.Errorf("set the built image's size to its size in bytes, 1 or more, not %d", b.Size)
	case !commitShape.MatchString(b.Commit):
		return errors.New("set the commit of the build to a full commit id, 40 or 64 hexadecimal characters in lower case")
	case b.EnvironmentRef == "":
		return errors.New("set the build's environment reference: dev.qory.run.built requires a non-empty environment_ref")
	case b.EnvironmentImage != "" && accesskey.ContainsSecret(b.EnvironmentImage):
		return errors.New("set the environment image to a reference without qak_, qrk_ or qecr_: each starts a secret")
	case b.EnvironmentImage != "" && !policy.ImageReference(b.EnvironmentImage):
		return errors.New("set the environment image to NAME@sha256: and 64 hexadecimal digits, all in lower case, with no tag")
	case b.Base != "" && accesskey.ContainsSecret(b.Base):
		return errors.New("set the base image to a reference without qak_, qrk_ or qecr_: each starts a secret")
	case b.Base != "" && !policy.ImageReference(b.Base):
		return errors.New("set the base image to NAME@sha256: and 64 hexadecimal digits, all in lower case, with no tag")
	}
	return nil
}
