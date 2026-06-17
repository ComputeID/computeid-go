package computeid

import "errors"

var (
	ErrComputeID      = errors.New("computeid")
	ErrAuthentication = errors.Join(ErrComputeID, errors.New("authentication"))
	ErrRegistration   = errors.Join(ErrComputeID, errors.New("registration"))
	ErrRevocation     = errors.Join(ErrComputeID, errors.New("revocation"))
	ErrTrust          = errors.Join(ErrComputeID, errors.New("trust"))
	ErrCapability     = errors.Join(ErrComputeID, errors.New("capability"))
	ErrAPI            = errors.Join(ErrComputeID, errors.New("api"))
)

type APIError struct {
	StatusCode int
	Message    string
	Endpoint   string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return "computeid: API call to " + e.Endpoint + " failed"
	}
	return "computeid: " + e.Endpoint + ": " + e.Message
}

func (e *APIError) Unwrap() error { return ErrAPI }
