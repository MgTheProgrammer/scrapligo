package cli

import (
	scrapligoconstants "github.com/scrapli/scrapligo/v2/constants"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
)

// GetHostKeyFingerprint returns the raw ssh host key digest (fingerprint) of the connected device
// for the given hash -- 16 bytes for md5, 20 for sha1, 32 for sha256. Fetched from the session on
// demand, so only available for the ssh2 transport while open, otherwise returns an error wrapping
// ErrOperation.
func (c *Cli) GetHostKeyFingerprint(hash scrapligoconstants.HostKeyHash) ([]byte, error) {
	if c.ptr == 0 {
		return nil, scrapligoerrors.NewFfiError("driver pointer nil", nil)
	}

	buf := make([]byte, scrapligoconstants.MaxHostKeyDigestLen)

	var digestSize uintptr

	err := c.ffiMap.Session.GetHostKeyFingerprint(c.ptr, uint8(hash), &buf, &digestSize)
	if err != nil {
		return nil, err
	}

	return buf[:digestSize], nil
}
