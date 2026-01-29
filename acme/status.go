package acme

// Status represents an ACME status.
type Status string

var (
	// StatusValid -- valid
	StatusValid = Status("valid")
	// StatusInvalid -- invalid
	StatusInvalid = Status("invalid")
	// StatusPending -- pending; e.g. an Order that is not ready to be finalized.
	StatusPending = Status("pending")
	// StatusDeactivated -- deactivated; e.g. for an Account that is not longer valid.
	StatusDeactivated = Status("deactivated")
	// StatusReady -- ready; e.g. for an Order that is ready to be finalized.
	StatusReady = Status("ready")
	// StatusProcessing -- processing e.g. a Challenge that is in the process of being validated.
	StatusProcessing = Status("processing")
	//statusExpired     = "expired"
	//statusActive      = "active"
)
