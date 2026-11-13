package constants

// HostKeyHash is an enum(ish) representing the hash algorithm used to fingerprint a host key.
type HostKeyHash uint8

// enumerations of HostKeyHash, values match the libscrapli (and libssh2) values.
const (
	HostKeyHashMD5 HostKeyHash = iota + 1
	HostKeyHashSHA1
	HostKeyHashSHA256
)

// MaxHostKeyDigestLen is the longest possible host key digest (sha256).
const MaxHostKeyDigestLen = 32
