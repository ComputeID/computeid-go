package computeid

// TrustLevel describes the broad authority an agent operates under.
type TrustLevel string

const (
	TrustRestricted TrustLevel = "restricted"
	TrustStandard   TrustLevel = "standard"
	TrustElevated   TrustLevel = "elevated"
	TrustAutonomous TrustLevel = "autonomous"
)

// AgentCapabilities declares what an AI agent is permitted to do. Embed one
// in every AgentPassport. The zero value is safe but grants nothing useful;
// prefer one of the preset constructors.
type AgentCapabilities struct {
	CanBrowseWeb       bool           `json:"can_browse_web"`
	CanExecuteCode     bool           `json:"can_execute_code"`
	CanAccessFiles     bool           `json:"can_access_files"`
	CanCallAPIs        bool           `json:"can_call_apis"`
	CanSpawnAgents     bool           `json:"can_spawn_agents"`
	CanAccessDatabase  bool           `json:"can_access_database"`
	CanSendEmail       bool           `json:"can_send_email"`
	MaxActionsPerHour  int            `json:"max_actions_per_hour"`
	TrustLevel         TrustLevel     `json:"trust_level"`
	HumanInLoop        bool           `json:"human_in_loop"`
	AllowedDomains     []string       `json:"allowed_domains,omitempty"`
	AllowedTools       []string       `json:"allowed_tools,omitempty"`
	MaxTokenBudget     *int           `json:"max_token_budget,omitempty"`
	CustomPermissions  map[string]any `json:"custom_permissions,omitempty"`
}

// RestrictedCapabilities — minimal permissions, human oversight required.
func RestrictedCapabilities() AgentCapabilities {
	return AgentCapabilities{
		CanCallAPIs:       true,
		MaxActionsPerHour: 50,
		TrustLevel:        TrustRestricted,
		HumanInLoop:       true,
	}
}

// StandardCapabilities — web browsing, API calls, file read.
func StandardCapabilities() AgentCapabilities {
	return AgentCapabilities{
		CanBrowseWeb:      true,
		CanCallAPIs:       true,
		CanAccessFiles:    true,
		MaxActionsPerHour: 200,
		TrustLevel:        TrustStandard,
		HumanInLoop:       true,
	}
}

// ElevatedCapabilities — code execution, can spawn child agents.
func ElevatedCapabilities() AgentCapabilities {
	return AgentCapabilities{
		CanBrowseWeb:      true,
		CanExecuteCode:    true,
		CanCallAPIs:       true,
		CanAccessFiles:    true,
		CanSpawnAgents:    true,
		MaxActionsPerHour: 1000,
		TrustLevel:        TrustElevated,
		HumanInLoop:       false,
	}
}

// AutonomousCapabilities — full autonomy; use with care.
func AutonomousCapabilities() AgentCapabilities {
	return AgentCapabilities{
		CanBrowseWeb:      true,
		CanExecuteCode:    true,
		CanCallAPIs:       true,
		CanAccessFiles:    true,
		CanSpawnAgents:    true,
		CanAccessDatabase: true,
		CanSendEmail:      true,
		MaxActionsPerHour: 10000,
		TrustLevel:        TrustAutonomous,
		HumanInLoop:       false,
	}
}

// CapabilitiesFor returns the preset matching a trust level, defaulting to
// StandardCapabilities for any unknown level.
func CapabilitiesFor(level TrustLevel) AgentCapabilities {
	switch level {
	case TrustRestricted:
		return RestrictedCapabilities()
	case TrustElevated:
		return ElevatedCapabilities()
	case TrustAutonomous:
		return AutonomousCapabilities()
	default:
		return StandardCapabilities()
	}
}

// Action is the canonical name of an action that AgentPassport.VerifyAction
// gates on. Pass any of these to VerifyAction or check raw via the
// Can* fields directly.
type Action string

const (
	ActionBrowseWeb      Action = "browse_web"
	ActionExecuteCode    Action = "execute_code"
	ActionAccessFiles    Action = "access_files"
	ActionCallAPI        Action = "call_api"
	ActionSpawnAgent     Action = "spawn_agent"
	ActionAccessDatabase Action = "access_database"
	ActionSendEmail      Action = "send_email"
)

// Allows reports whether the capability set grants a given action.
func (c AgentCapabilities) Allows(a Action) bool {
	switch a {
	case ActionBrowseWeb:
		return c.CanBrowseWeb
	case ActionExecuteCode:
		return c.CanExecuteCode
	case ActionAccessFiles:
		return c.CanAccessFiles
	case ActionCallAPI:
		return c.CanCallAPIs
	case ActionSpawnAgent:
		return c.CanSpawnAgents
	case ActionAccessDatabase:
		return c.CanAccessDatabase
	case ActionSendEmail:
		return c.CanSendEmail
	}
	return false
}
