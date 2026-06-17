package computeid

import (
	"context"
	"fmt"
)

// IssueAgentPassportQuick mints a passport in one call using a trust-level
// preset, mirroring the Python issue_agent_passport quickstart.
func IssueAgentPassportQuick(agentName, ownerOrg, ownerEmail, model string, level TrustLevel) (*AgentPassport, error) {
	return IssueAgentPassport(IssueOptions{
		AgentName:    agentName,
		AgentType:    "general",
		OwnerOrg:     ownerOrg,
		OwnerEmail:   ownerEmail,
		Capabilities: CapabilitiesFor(level),
		Model:        model,
	})
}

// RegisterGPU is a one-liner over RegisterDevice with DeviceType="GPU".
func RegisterGPU(ctx context.Context, name, ipAddress, apiKey string) (*DevicePassport, error) {
	return RegisterDevice(ctx, RegisterDeviceRequest{
		Name:       name,
		DeviceType: "GPU",
		IPAddress:  ipAddress,
	}, apiKey)
}

// RequirePassport wraps a function with passport + capability checks.
// The wrapper returns an error matching ErrAuthentication / ErrTrust if the
// passport is nil, not trusted, or lacks the required capability. On success
// it logs the call as an action on the passport and invokes fn.
//
// Example:
//
//	search := computeid.RequirePassport(computeid.ActionBrowseWeb,
//	    func(passport *computeid.AgentPassport, query string) (string, error) {
//	        return doSearch(query), nil
//	    })
//	res, err := search(passport, "GPU rental prices")
func RequirePassport[A any, R any](capability Action, fn func(p *AgentPassport, arg A) (R, error)) func(p *AgentPassport, arg A) (R, error) {
	return func(p *AgentPassport, arg A) (R, error) {
		var zero R
		if p == nil {
			return zero, fmt.Errorf("%w: function requires an AgentPassport", ErrAuthentication)
		}
		if !p.IsTrusted() {
			return zero, fmt.Errorf("%w: passport for %s is not trusted", ErrAuthentication, p.AgentName)
		}
		if capability != "" && !p.VerifyAction(capability) {
			return zero, fmt.Errorf("%w: agent lacks %s capability", ErrTrust, capability)
		}
		r, err := fn(p, arg)
		outcome := OutcomeSuccess
		if err != nil {
			outcome = OutcomeFailure
		}
		p.LogAction(string(capability)+"_call", nil, outcome)
		return r, err
	}
}
