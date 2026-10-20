package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// imageName is the machine's name for one of its images, policy.schema.json's
// $defs/image_name.
var imageName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// imageReference is a reference pinned by its digest, policy.schema.json's
// $defs/image_reference: a lower-case NAME, then @sha256: and 64 lower-case hexadecimal
// digits. NAME is at most [maxImageName] characters, which the pattern does not hold.
var imageReference = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@sha256:[0-9a-f]{64}$`)

// maxImageName is the most characters of a reference's NAME, the part before the @.
const maxImageName = 255

// ImageName reports whether s is the machine's name for an image: 1 to 64 of a-z, 0-9,
// underscore, dot and dash, starting with a letter or a digit.
func ImageName(s string) bool { return imageName.MatchString(s) }

// ImageReference reports whether s is an image's reference pinned by its digest, as a
// policy names one: NAME@sha256: and 64 lower-case hexadecimal digits, NAME a
// lower-case reference name of at most 255 characters, with no tag. Such a reference
// names one build and never moves.
func ImageReference(s string) bool {
	name, _, ok := strings.Cut(s, "@")
	return ok && len(name) <= maxImageName && imageReference.MatchString(s)
}

// referenceShaped reports whether s is written as a reference rather than a name: it
// holds a slash, an at sign or a colon, none of which a name holds.
func referenceShaped(s string) bool { return strings.ContainsAny(s, "/@:") }

// CheckImage refuses a policy's image written as a reference that is not pinned by
// digest, with a tag, in upper case or without a digest, with run_configuration_invalid:
// the code of the policy a node's file holds and of the one a server's run
// configuration holds. A name, a pinned reference and a value that is neither a name
// nor written as a reference pass: the last is the schema's to refuse. The refusal
// names no value, since a reference may carry a registry's credentials.
func CheckImage(image string) error {
	if ImageName(image) || !referenceShaped(image) || ImageReference(image) {
		return nil
	}
	return refusal.New(refusal.RunConfigurationInvalid, nil, "the policy names its image by a reference that is not "+
		"pinned by digest: a reference is NAME@sha256: and 64 lower-case hexadecimal digits, in lower case, with no tag")
}

// checkImage is [CheckImage] of a document's image, before the schema reads it.
func checkImage(doc any) error {
	m, _ := doc.(map[string]any)
	if image, ok := m["image"].(string); ok {
		return CheckImage(image)
	}
	return nil
}

// CheckImagePrefix refuses an entry of a machine's images.allow that cannot be one: an
// empty one, *, and one that is not the start of a pinned reference in lower case up to
// a whole part of it: a registry host, a NAME or a path of its, which may end in a
// slash, or a NAME followed by its @.
func CheckImagePrefix(entry string) error {
	const digest = "@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	switch {
	case entry == "":
		return errors.New("images.allow holds an empty entry, which would allow every image")
	case entry == "*":
		return errors.New("images.allow holds *, which would allow every image: list the prefixes of the references it allows")
	case strings.HasSuffix(entry, "@") && ImageReference(entry+digest[1:]),
		strings.HasSuffix(entry, "/") && ImageReference(entry+"x"+digest),
		!strings.HasSuffix(entry, "@") && !strings.HasSuffix(entry, "/") &&
			(ImageReference(entry+digest) || ImageReference(entry+"/x"+digest)):
		return nil
	}
	return fmt.Errorf("images.allow holds %s, which is not the start of a reference pinned by digest in lower case, "+
		"up to a whole part of it: a registry, a name or a path ending in a slash, or a name and its @", accesskey.ShownValue(entry, true))
}

// ImageAllowed returns the first entry of allow that covers ref, and whether one does.
// An entry covers a reference that starts with it, when the entry ends in / or @ or
// the reference's next character is / or @: registry.example/agents covers
// registry.example/agents/x@sha256:… and registry.example/agents@sha256:…, and neither
// registry.example/agents-other/x@sha256:… nor registry.example:5000/agents/x@sha256:….
// Nothing is normalised: an entry covers the references written under it alone.
func ImageAllowed(allow []string, ref string) (string, bool) {
	for _, entry := range allow {
		rest, ok := strings.CutPrefix(ref, entry)
		if !ok || entry == "" {
			continue
		}
		if strings.HasSuffix(entry, "/") || strings.HasSuffix(entry, "@") ||
			strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "@") {
			return entry, true
		}
	}
	return "", false
}
