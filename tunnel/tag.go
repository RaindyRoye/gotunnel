package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Routing handshakes run before stream encryption:
// request = legacy response (48 bytes) | version (1) | destination | HMAC (32)
// reply   = version (1) | status (1) | HMAC (32)
// Version 1 selects a tag; version 2 supplies a backend address.
// Legacy clients send only the legacy response and do not wait for a reply.
const (
	tagVersion      = 1
	targetVersion   = 2
	routeAccepted   = 0
	tagUnknown      = 1
	targetDisabled  = 2
	routeRequestMAC = 255
	maxTagLength    = 128
	maxTargetLength = 1024
)

type routingRequest struct {
	version     byte
	destination string
}

func validateTag(tag string) error {
	if len(tag) == 0 || len(tag) > maxTagLength {
		return fmt.Errorf("tag must contain 1..%d characters", maxTagLength)
	}
	for _, c := range tag {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return fmt.Errorf("tag %q must use letters, digits, '.', '_' or '-'", tag)
		}
	}
	return nil
}

func validateTarget(target string) error {
	if len(target) == 0 || len(target) > maxTargetLength {
		return fmt.Errorf("target must contain 1..%d characters", maxTargetLength)
	}
	return validateBackend(target)
}

func (r routingRequest) validate() error {
	switch r.version {
	case tagVersion:
		return validateTag(r.destination)
	case targetVersion:
		return validateTarget(r.destination)
	default:
		return fmt.Errorf("unsupported routing version %d", r.version)
	}
}

// Preserve the version-1 tag signature and use a separate domain for targets,
// so a signed target cannot be reinterpreted as a tag (or vice versa).
func (a *Taa) routingMAC(request routingRequest, status byte) []byte {
	domain := "gotunnel/tag/v1"
	if request.version == targetVersion {
		domain = "gotunnel/target/v2"
	}
	a.mac.Write([]byte(domain))
	a.mac.Write(a.token.toBytes())
	a.mac.Write([]byte{status})
	a.mac.Write([]byte(request.destination))
	sum := a.mac.Sum(nil)
	a.mac.Reset()
	return sum
}

func (a *Taa) routingResponse(token []byte, request routingRequest) []byte {
	buf := mpool.Get()[:TaaBlockSize+1+len(request.destination)+sha256.Size]
	copy(buf, token)
	buf[TaaBlockSize] = request.version
	copy(buf[TaaBlockSize+1:], request.destination)
	copy(buf[len(buf)-sha256.Size:], a.routingMAC(request, routeRequestMAC))
	return buf
}

func (a *Taa) verifyRoutingResponse(buf []byte) (routingRequest, error) {
	var request routingRequest
	if len(buf) < TaaBlockSize+2+sha256.Size || len(buf) > TaaBlockSize+1+maxTargetLength+sha256.Size {
		return request, fmt.Errorf("routing requires a client with -tag or -target")
	}
	if !a.VerifyCipherBlock(buf[:TaaBlockSize]) {
		return request, fmt.Errorf("invalid routing authentication response")
	}
	request = routingRequest{buf[TaaBlockSize], string(buf[TaaBlockSize+1 : len(buf)-sha256.Size])}
	if err := request.validate(); err != nil {
		return request, err
	}
	if !hmac.Equal(buf[len(buf)-sha256.Size:], a.routingMAC(request, routeRequestMAC)) {
		return request, fmt.Errorf("invalid routing signature")
	}
	return request, nil
}

func (a *Taa) routingAck(request routingRequest, status byte) []byte {
	buf := mpool.Get()[:2+sha256.Size]
	buf[0], buf[1] = request.version, status
	copy(buf[2:], a.routingMAC(request, status))
	return buf
}

func (a *Taa) verifyRoutingAck(request routingRequest, buf []byte) error {
	if len(buf) != 2+sha256.Size || buf[0] != request.version || !hmac.Equal(buf[2:], a.routingMAC(request, buf[1])) {
		return fmt.Errorf("invalid routing acknowledgement")
	}
	return request.statusError(buf[1])
}

func (r routingRequest) statusError(status byte) error {
	switch status {
	case routeAccepted:
		return nil
	case tagUnknown:
		return fmt.Errorf("unknown tag %q", r.destination)
	case targetDisabled:
		return fmt.Errorf("client-specified backend is disabled on server")
	default:
		return fmt.Errorf("unexpected routing acknowledgement status %d", status)
	}
}
